#!/usr/bin/env python3
"""
luadch smoke-test harness.

Starts a freshly-installed luadch hub on test ports, runs a small set of
protocol-level checks (plain ADC handshake, TLS ADC handshake, log scan
for plugin errors), and tears it down. Exits 0 on all-pass, non-zero on
any failure.

Usage:
    python3 tests/smoke/run.py <path-to-built-install-tree>

The argument is the directory that "cmake --install build" produced,
typically build/install/luadch. The harness copies it to a temp dir,
overrides ports to avoid collisions with a real hub on the same host,
and runs everything from there. The original install tree is untouched.

Exit codes:
    0   all tests passed
    1   one or more tests failed
    2   harness error (could not start hub, etc.)
"""

import argparse
import base64
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Vendored pure-Python Tiger-192 hash. Used to compute CIDs (Tiger(PID)) and
# password challenge responses (Tiger(password || salt)) for the login flow
# tests below. Self-tests on import; if it ever breaks the harness fails fast.
sys.path.insert(0, str(Path(__file__).parent))
import tiger as _tiger


# Test ports, deliberately offset from the upstream defaults (5000-5003)
# so a developer running the suite locally does not collide with their
# real hub. CI is isolated so the offset does not matter there.
TEST_PORT_PLAIN = 15500
TEST_PORT_TLS = 15501
TEST_PORT_PLAIN_V6 = 15502
TEST_PORT_TLS_V6 = 15503

HUB_HOST = "127.0.0.1"

# How long to wait for the hub to bind ports / shut down.
START_TIMEOUT_SEC = 20
STOP_TIMEOUT_SEC = 10
PROTOCOL_TIMEOUT_SEC = 5


class TestFailure(Exception):
    """Raised by individual tests on assertion failure."""


def log(msg):
    print(f"[smoke] {msg}", flush=True)


# -----------------------------------------------------------------------------
# Setup / teardown
# -----------------------------------------------------------------------------

def stage_install(source_install_dir: Path) -> Path:
    """
    Copy the install tree into a fresh temp dir so the test mutates a
    disposable copy (cfg.tbl rewrites, generated certs, log files).
    """
    staging = Path(tempfile.mkdtemp(prefix="luadch-smoke-"))
    log(f"staging install tree at {staging}")
    shutil.copytree(source_install_dir, staging / "luadch")
    return staging / "luadch"


def override_test_ports(staging_dir: Path):
    """
    Rewrite the four port arrays in cfg.tbl to our test values. Done as a
    targeted regex on the four canonical lines so we do not touch
    surrounding cfg structure or comments.
    """
    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")

    rewrites = [
        (r"tcp_ports\s*=\s*\{[^}]*\}", f"tcp_ports = {{ {TEST_PORT_PLAIN} }}"),
        (r"ssl_ports\s*=\s*\{[^}]*\}", f"ssl_ports = {{ {TEST_PORT_TLS} }}"),
        (r"tcp_ports_ipv6\s*=\s*\{[^}]*\}", f"tcp_ports_ipv6 = {{ {TEST_PORT_PLAIN_V6} }}"),
        (r"ssl_ports_ipv6\s*=\s*\{[^}]*\}", f"ssl_ports_ipv6 = {{ {TEST_PORT_TLS_V6} }}"),
    ]
    for pattern, replacement in rewrites:
        new_text, count = re.subn(pattern, replacement, text, count=1)
        if count != 1:
            raise RuntimeError(f"could not rewrite cfg.tbl pattern: {pattern}")
        text = new_text

    cfg_path.write_text(text, encoding="utf-8")
    log(f"rewrote ports: plain={TEST_PORT_PLAIN}, tls={TEST_PORT_TLS}, "
        f"plain_v6={TEST_PORT_PLAIN_V6}, tls_v6={TEST_PORT_TLS_V6}")


def generate_test_cert(staging_dir: Path):
    """
    Run the bundled make_cert.{sh,bat} to create a self-signed test cert.
    On Windows we always use the .bat: msys2 / Git Bash mangles the
    "/CN=..." subject name via POSIX-to-Windows path conversion, which
    breaks make_cert.sh even when bash is on PATH.
    """
    certs_dir = staging_dir / "certs"

    if sys.platform == "win32":
        # cmd.exe /c does not search the CWD by default; use an absolute
        # path so the call works regardless of how Python was invoked.
        cmd = ["cmd.exe", "/c", str(certs_dir / "make_cert.bat")]
    else:
        sh = shutil.which("bash")
        if not sh:
            raise RuntimeError("no bash available to run make_cert.sh")
        cmd = [sh, "make_cert.sh"]

    log(f"generating test cert via {cmd[0]}")
    # Capture as bytes; cmd.exe on Windows emits cp1252 / cp850 / OEM
    # depending on locale, and openssl's stderr can include non-ASCII
    # chars in error paths. Decoding with errors="replace" sidesteps
    # any locale fight just to surface a useful error message.
    result = subprocess.run(cmd, cwd=certs_dir, capture_output=True)
    if result.returncode != 0:
        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(
            f"cert generation failed (exit {result.returncode}):\n"
            f"stdout: {stdout}\n"
            f"stderr: {stderr}"
        )


def start_hub(staging_dir: Path):
    """
    Launch luadch from a CWD outside the staging tree. The hub anchors
    its own runtime paths to the binary's directory at startup
    (issue #12 / Phase 6b), so it must work regardless of the caller's
    CWD. Picking a foreign CWD here turns the smoke run into a positive
    proof of that anchoring; before #12 was fixed the hub would bail
    out looking for ./core/init.lua relative to the harness's CWD.
    """
    binary = staging_dir / ("Luadch.exe" if sys.platform == "win32" else "luadch")
    if not binary.exists():
        raise RuntimeError(f"hub binary not found at {binary}")

    foreign_cwd = staging_dir.parent  # the temp dir the staging lives inside
    log_file = open(staging_dir / "log" / "smoke-hub.log", "wb")
    log(f"starting {binary} (cwd={foreign_cwd})")
    proc = subprocess.Popen(
        [str(binary)],
        cwd=str(foreign_cwd),
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    return proc, log_file


def wait_for_port(host: str, port: int, timeout: float):
    """Poll TCP connect until success or timeout."""
    deadline = time.monotonic() + timeout
    last_err = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError as e:
            last_err = e
            time.sleep(0.2)
    raise TimeoutError(f"port {host}:{port} did not open within {timeout}s; last error: {last_err}")


def stop_hub(proc, log_file):
    if proc.poll() is None:
        log("stopping hub")
        proc.terminate()
        try:
            proc.wait(timeout=STOP_TIMEOUT_SEC)
        except subprocess.TimeoutExpired:
            log("hub did not exit cleanly, killing")
            proc.kill()
            proc.wait(timeout=STOP_TIMEOUT_SEC)
    log_file.close()


# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------

def test_hub_binds_ports():
    """The hub bound both plain and TLS ports within the start timeout."""
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)
    wait_for_port(HUB_HOST, TEST_PORT_TLS, START_TIMEOUT_SEC)


def adc_handshake(sock):
    """
    Send the canonical client SUP and read until we see ISUP, ISID and
    IINF in the response stream. ADC frames are newline-terminated.
    """
    sock.settimeout(PROTOCOL_TIMEOUT_SEC)
    sock.sendall(b"HSUP ADBASE ADTIGR\n")

    seen = {"ISUP": False, "ISID": False, "IINF": False}
    buffer = b""
    deadline = time.monotonic() + PROTOCOL_TIMEOUT_SEC

    while time.monotonic() < deadline and not all(seen.values()):
        chunk = sock.recv(4096)
        if not chunk:
            break
        buffer += chunk
        while b"\n" in buffer:
            line, _, buffer = buffer.partition(b"\n")
            for fourcc in seen:
                if line.startswith(fourcc.encode()):
                    seen[fourcc] = True

    missing = [k for k, v in seen.items() if not v]
    if missing:
        raise TestFailure(f"handshake response missing frames: {missing}")


def test_plain_handshake():
    """Plain ADC: send HSUP, expect ISUP/ISID/IINF."""
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        adc_handshake(sock)


def test_tls_handshake():
    """TLS ADC: same as plain but wrapped in TLS. Hub uses a self-signed cert."""
    ctx = ssl.create_default_context()
    # Self-signed test cert; we are not validating identity in the smoke
    # test, only that the TLS handshake completes and ADC frames flow.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((HUB_HOST, TEST_PORT_TLS), timeout=PROTOCOL_TIMEOUT_SEC) as raw:
        with ctx.wrap_socket(raw, server_hostname=HUB_HOST) as sock:
            adc_handshake(sock)


# -----------------------------------------------------------------------------
# ADC protocol helpers (used by the login flow tests below)
# -----------------------------------------------------------------------------

def _b32_encode(data: bytes) -> str:
    """ADC base32: standard RFC 4648 alphabet, no padding."""
    return base64.b32encode(data).decode("ascii").rstrip("=")


def _b32_decode(s: str) -> bytes:
    """ADC base32 decode: re-pad to a multiple of 8, then standard b32decode."""
    return base64.b32decode(s + "=" * (-len(s) % 8))


def _adc_escape(s: str) -> str:
    """Escape spaces, newlines and backslashes for an ADC named-parameter value."""
    return s.replace("\\", "\\\\").replace(" ", "\\s").replace("\n", "\\n")


class _ADCReader:
    """Buffered reader that yields complete newline-terminated ADC frames."""

    def __init__(self, sock):
        self._sock = sock
        self._buffer = b""

    def recv_until(self, predicate, timeout: float = PROTOCOL_TIMEOUT_SEC) -> str:
        """Read frames from the socket until predicate(frame) returns truthy.
        Returns the matching frame as a string (without the trailing \\n)."""
        deadline = time.monotonic() + timeout
        while True:
            while b"\n" in self._buffer:
                line, _, self._buffer = self._buffer.partition(b"\n")
                frame = line.decode("utf-8", errors="replace")
                if predicate(frame):
                    return frame
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TestFailure(f"timed out after {timeout}s waiting for matching ADC frame")
            self._sock.settimeout(remaining)
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise TestFailure("connection closed by hub before matching frame arrived")
            self._buffer += chunk


def _adc_login(sock, nick: str, password: str):
    """Run a full ADC client login as a registered user. On success returns
    (sid, reader) so the caller can keep using the same socket for further
    interactions (e.g. sending +help)."""
    reader = _ADCReader(sock)

    # 1. SUP exchange. Hub responds with ISUP (its supported features),
    #    ISID (the SID it has assigned us) and IINF (hub info).
    sock.sendall(b"HSUP ADBASE ADTIGR\n")
    reader.recv_until(lambda f: f.startswith("ISUP "))
    isid = reader.recv_until(lambda f: f.startswith("ISID "))
    sid = isid.split(" ", 1)[1].strip()
    reader.recv_until(lambda f: f.startswith("IINF "))

    # 2. Compute identity and send BINF. CID = Tiger(PID); the hub validates
    #    this match in core/hub.lua's BINF handler.
    pid_bytes = secrets.token_bytes(24)
    cid_b32 = _b32_encode(_tiger.tiger(pid_bytes))
    pid_b32 = _b32_encode(pid_bytes)
    # SU (supported features) needs a non-empty value or the ADC parser
    # rejects the BINF as malformed. TCP4 declares we accept active TCPv4
    # CTM connections - inert for the smoke test, but parser-valid.
    binf = (
        f"BINF {sid}"
        f" ID{cid_b32}"
        f" PD{pid_b32}"
        f" NI{_adc_escape(nick)}"
        f" I40.0.0.0"
        f" SUTCP4\n"
    )
    sock.sendall(binf.encode("utf-8"))

    # 3. Hub answers IGPA <salt> for a registered user. Decode salt, compute
    #    the response = Tiger(password || salt_bytes), send HPAS.
    gpa = reader.recv_until(lambda f: f.startswith("IGPA "))
    salt_b32 = gpa.split(" ", 1)[1].strip()
    salt_bytes = _b32_decode(salt_b32)
    response = _tiger.tiger(password.encode("utf-8") + salt_bytes)
    sock.sendall(f"HPAS {_b32_encode(response)}\n".encode("utf-8"))

    # 4. On success the hub transitions us to NORMAL state and starts
    #    streaming our own and other users' INFs. The first BINF that starts
    #    with our own SID is the canonical signal we are logged in. On a
    #    bad-password failure the hub instead emits ISTA 223 and disconnects.
    final = reader.recv_until(
        lambda f: f.startswith(f"BINF {sid}") or f.startswith("ISTA "),
        timeout=PROTOCOL_TIMEOUT_SEC,
    )
    if final.startswith("ISTA "):
        raise TestFailure(f"login failed: hub returned {final!r}")

    return sid, reader


# -----------------------------------------------------------------------------
# Tests (continued)
# -----------------------------------------------------------------------------

def _open_tls_socket():
    """Helper: return a connected TLS-wrapped socket to the hub's TLS port.
    Validation is disabled because the smoke harness uses a self-signed
    test cert generated by certs/make_cert.{sh,bat}."""
    raw = socket.create_connection((HUB_HOST, TEST_PORT_TLS), timeout=PROTOCOL_TIMEOUT_SEC)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(raw, server_hostname=HUB_HOST)


def test_full_login_plain():
    """Plain ADC: full login flow as dummy/test, BINF + HPAS to NORMAL state.
    Exercises createuser's user object, the BINF parser, IGPA / salt
    generation, HPAS verification, login() listener firing."""
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        sid, _reader = _adc_login(sock, "dummy", "test")
        if not sid or len(sid) != 4:
            raise TestFailure(f"unexpected SID format from hub: {sid!r}")


def test_full_login_tls():
    """Same as plain, but over the TLS port."""
    sock = _open_tls_socket()
    try:
        sid, _reader = _adc_login(sock, "dummy", "test")
        if not sid or len(sid) != 4:
            raise TestFailure(f"unexpected SID format from hub: {sid!r}")
    finally:
        sock.close()


def test_command_routing():
    """After a full login, send `+help` and expect any EMSG/DMSG response from
    the hubbot. Exercises onBroadcast listener chain + etc_hubcommands routing
    + cmd_help running and replying."""
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")
        sock.sendall(f"BMSG {sid} +help\n".encode("utf-8"))
        # cmd_help replies via user:reply(...) which goes out as a private
        # message frame (E or D type). We accept either kind.
        response = reader.recv_until(
            lambda f: f.startswith("EMSG ") or f.startswith("DMSG "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if len(response) < 20:
            raise TestFailure(f"+help response unexpectedly short: {response!r}")


def test_csprng_salt_uniqueness():
    """Open N sequential connections to a registered nick, drive each through
    SUP/BINF until the hub answers IGPA <salt>, capture the salt and disconnect
    before HPAS (so badpassword stays at 0). Assert all salts are distinct.

    Smoke-coverage for the F-AUTH-2 fix: the math.random() salt source was
    replaced with OpenSSL RAND_bytes via adclib.random_bytes. A regression to
    a deterministic / poorly-seeded PRNG would make this test fail on
    repeated salts."""
    salts = []
    N = 10
    for _ in range(N):
        with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
            reader = _ADCReader(sock)
            sock.sendall(b"HSUP ADBASE ADTIGR\n")
            reader.recv_until(lambda f: f.startswith("ISUP "))
            isid = reader.recv_until(lambda f: f.startswith("ISID "))
            sid = isid.split(" ", 1)[1].strip()
            reader.recv_until(lambda f: f.startswith("IINF "))

            pid_bytes = secrets.token_bytes(24)
            cid_b32 = _b32_encode(_tiger.tiger(pid_bytes))
            pid_b32 = _b32_encode(pid_bytes)
            binf = (
                f"BINF {sid}"
                f" ID{cid_b32}"
                f" PD{pid_b32}"
                f" NIdummy"
                f" I40.0.0.0"
                f" SUTCP4\n"
            )
            sock.sendall(binf.encode("utf-8"))

            gpa = reader.recv_until(lambda f: f.startswith("IGPA "))
            salts.append(gpa.split(" ", 1)[1].strip())
            # Drop the connection before HPAS - no badpassword increment.

    if len(set(salts)) != N:
        dupes = [s for s in salts if salts.count(s) > 1]
        raise TestFailure(f"salt collision in {N} draws: {dupes!r}")


def test_perip_connection_cap():
    """Open more parallel TCP connections from one IP than ratelimit_perip_max_conns
    (default 16). The N+1th accept must fail or get torn down by the hub before
    a SUP exchange completes. Smoke coverage for F-NET-1.

    We keep the first batch alive (don't close until end of test), then attempt
    one extra. If the hub honours the cap, the extra socket either errors at
    connect or the hub closes it before SUP can complete."""
    cap = 16
    keep = []
    try:
        for _ in range(cap):
            sock = socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC)
            keep.append(sock)
        # The cap+1 attempt: connect may succeed (kernel-level) but the hub must
        # not produce an ISUP. Give it ~1s; if we get nothing, the hub refused.
        try:
            extra = socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC)
        except OSError:
            return  # connect refused at OS level - that's also acceptable
        try:
            extra.settimeout(1.5)
            extra.sendall(b"HSUP ADBASE ADTIGR\n")
            data = b""
            try:
                data = extra.recv(4096)
            except (socket.timeout, OSError):
                pass
            if data:
                raise TestFailure(
                    f"hub accepted connection #{cap + 1} from one IP and answered "
                    f"with {data[:80]!r}; expected the per-IP cap to refuse"
                )
        finally:
            extra.close()
    finally:
        for s in keep:
            s.close()
        # Give the hub time to process disconnects and free per-IP slots
        # before the next test connects.
        time.sleep(0.6)


def test_no_script_errors(log_path: Path):
    """
    Plugin-load smoke: scan the captured hub stdout for "script error:"
    lines. core/scripts.lua emits exactly that prefix when a plugin
    fails to load or a listener throws.
    """
    if not log_path.exists():
        raise TestFailure(f"hub log not found at {log_path}")
    text = log_path.read_text(encoding="utf-8", errors="replace")
    bad_lines = [line for line in text.splitlines() if "script error:" in line]
    if bad_lines:
        sample = "\n  ".join(bad_lines[:5])
        raise TestFailure(f"hub emitted {len(bad_lines)} script error line(s):\n  {sample}")


# -----------------------------------------------------------------------------
# Test orchestration
# -----------------------------------------------------------------------------

TESTS = [
    ("hub binds plain + TLS ports", test_hub_binds_ports),
    ("plain ADC handshake", test_plain_handshake),
    ("TLS ADC handshake", test_tls_handshake),
    ("plain ADC full login (dummy/test)", test_full_login_plain),
    ("TLS ADC full login (dummy/test)", test_full_login_tls),
    ("+cmd routing (post-login +help)", test_command_routing),
    ("CSPRNG salts are unique across connections", test_csprng_salt_uniqueness),
    ("per-IP connection cap refuses overflow", test_perip_connection_cap),
]


def run_tests(log_path: Path):
    failed = []
    for name, fn in TESTS:
        try:
            fn()
        except Exception as e:
            log(f"FAIL  {name}: {e}")
            failed.append(name)
        else:
            log(f"PASS  {name}")

    # The plugin-load test reads the hub log, so it runs after all
    # protocol tests have had a chance to exercise the listeners.
    try:
        test_no_script_errors(log_path)
    except Exception as e:
        log(f"FAIL  no script errors in log: {e}")
        failed.append("no script errors in log")
    else:
        log("PASS  no script errors in log")

    return failed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "install_dir",
        type=Path,
        help="path to a built+installed luadch tree (e.g. build/install/luadch)",
    )
    parser.add_argument(
        "--keep-staging",
        action="store_true",
        help="leave the temp staging dir on disk for inspection after the run",
    )
    args = parser.parse_args()

    if not args.install_dir.is_dir():
        log(f"ERROR  install dir not found: {args.install_dir}")
        return 2

    staging_dir = stage_install(args.install_dir.resolve())
    proc = None
    log_file = None
    try:
        override_test_ports(staging_dir)
        generate_test_cert(staging_dir)
        proc, log_file = start_hub(staging_dir)
        failed = run_tests(staging_dir / "log" / "smoke-hub.log")
    finally:
        if proc is not None:
            stop_hub(proc, log_file)
        if not args.keep_staging:
            shutil.rmtree(staging_dir.parent, ignore_errors=True)
        else:
            log(f"staging kept at {staging_dir.parent}")

    if failed:
        log(f"FAILED  {len(failed)} test(s): {', '.join(failed)}")
        return 1
    log("OK  all tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
