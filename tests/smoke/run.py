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
    # Pin TLS 1.2 minimum (closes CodeQL py/insecure-protocol). The
    # default context still admits TLSv1 / TLSv1.1 negotiation paths
    # we never want even in test code.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

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
    # Pin TLS 1.2 minimum (closes CodeQL py/insecure-protocol).
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
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


# -----------------------------------------------------------------------------
# Phase 8a-2 - negative-test fuzz suite (issue #121)
# -----------------------------------------------------------------------------
# These tests feed malformed ADC input into the hub and assert that the hub
# handles it cleanly: no crash, no Lua error in error.log (caught by
# test_no_script_errors at end of run), and the hub stays available for
# further connections (caught by test_neg_canary at end of this section).
#
# Each test opens its own socket and closes it before the next one starts,
# so the per-IP connection cap (16) is not exhausted - sequential access
# stays well within the burst budget (30).
#
# Tests deliberately do NOT assert specific hub responses: any of "ISTA
# error frame", "clean disconnect", "silent ignore-and-keep-going" is an
# acceptable handling of a malformed input. The non-acceptable outcomes
# are "hub crash" and "Lua script error" - both caught by the canary +
# test_no_script_errors pair at the end of the run.

def _neg_handshake_get_sid(sock):
    """Drive HSUP -> ISUP/ISID/IINF on a freshly connected socket. Returns
    (reader, sid) so the caller can send a malformed BINF. Caller owns
    the socket lifetime."""
    reader = _ADCReader(sock)
    sock.sendall(b"HSUP ADBASE ADTIGR\n")
    reader.recv_until(lambda f: f.startswith("ISUP "))
    isid = reader.recv_until(lambda f: f.startswith("ISID "))
    sid = isid.split(" ", 1)[1].strip()
    reader.recv_until(lambda f: f.startswith("IINF "))
    return reader, sid


def _neg_drain_briefly(sock, timeout: float = 2.0):
    """Drain whatever the hub sends back, up to `timeout` seconds. Used
    after sending a malformed payload to give the hub time to react before
    the test exits and closes the socket. Never raises."""
    sock.settimeout(timeout)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return
    except (socket.timeout, OSError):
        return


def _neg_send_binf_extra(binf_extra: str):
    """Open a fresh plain socket, run the SUP exchange to acquire a SID,
    then send a single BINF with `binf_extra` appended after `BINF <sid>`.
    Drain briefly so the hub has a chance to react. The caller's intent is
    to verify that whatever malformed extra was sent does not crash the
    hub - the actual response is not asserted here."""
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        _reader, sid = _neg_handshake_get_sid(sock)
        binf = f"BINF {sid} {binf_extra}\n".encode("utf-8")
        try:
            sock.sendall(binf)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return  # hub already closed - acceptable
        _neg_drain_briefly(sock)
    finally:
        sock.close()


def _neg_random_pid_cid_pair():
    """A fresh PID + matching CID = Tiger(PID), both base32-encoded. Use
    these in BINF tests where the test is about a *different* malformed
    field - the hub still has to compute Tiger(PID) and compare to CID,
    so passing a valid pair avoids spurious early-rejection on
    CID/PID mismatch."""
    pid_bytes = secrets.token_bytes(24)
    cid_b32 = _b32_encode(_tiger.tiger(pid_bytes))
    pid_b32 = _b32_encode(pid_bytes)
    return cid_b32, pid_b32


def test_neg_inf_negative_numerics():
    """BINF with negative SS / SF / SL / DS / US. Hub should reject or
    ignore; should not propagate the negative value into ban / quota
    arithmetic where it could underflow."""
    cid_b32, pid_b32 = _neg_random_pid_cid_pair()
    extra = (
        f"ID{cid_b32} PD{pid_b32} NIneg-numerics I40.0.0.0 SUTCP4"
        f" SS-1 SF-1 SL-1 DS-1 US-1"
    )
    _neg_send_binf_extra(extra)


def test_neg_inf_oversize_numerics():
    """BINF with absurdly large SS / SF. Hub should reject or clamp; raw
    value must not blow up integer math anywhere downstream."""
    cid_b32, pid_b32 = _neg_random_pid_cid_pair()
    extra = (
        f"ID{cid_b32} PD{pid_b32} NIoversize-num I40.0.0.0 SUTCP4"
        f" SS999999999999999999999999999 SF999999999"
    )
    _neg_send_binf_extra(extra)


def test_neg_inf_invalid_ipv4():
    """BINF with syntactically-invalid I4. Parser/validator must reject
    cleanly; specifically must not try to resolve, normalize, or use the
    bogus value as a key."""
    cid_b32, pid_b32 = _neg_random_pid_cid_pair()
    extra = f"ID{cid_b32} PD{pid_b32} NIbad-ipv4 I4999.999.999.999 SUTCP4"
    _neg_send_binf_extra(extra)


def test_neg_inf_invalid_ipv6():
    """BINF with non-IPv6 garbage in I6."""
    cid_b32, pid_b32 = _neg_random_pid_cid_pair()
    extra = f"ID{cid_b32} PD{pid_b32} NIbad-ipv6 I40.0.0.0 I6not-an-ipv6 SUTCP4"
    _neg_send_binf_extra(extra)


def test_neg_inf_overlong_nick():
    """BINF with a 1000-character NI. Should hit the parser size limits or
    a per-field validator without trampling the buffer."""
    long_nick = "A" * 1000
    cid_b32, pid_b32 = _neg_random_pid_cid_pair()
    extra = f"ID{cid_b32} PD{pid_b32} NI{long_nick} I40.0.0.0 SUTCP4"
    _neg_send_binf_extra(extra)


def test_neg_inf_overlong_description():
    """BINF with a 10000-character DE. Stress test the per-field size
    handling on a large optional string."""
    long_desc = "X" * 10000
    cid_b32, pid_b32 = _neg_random_pid_cid_pair()
    extra = (
        f"ID{cid_b32} PD{pid_b32} NIlong-desc I40.0.0.0 SUTCP4"
        f" DE{long_desc}"
    )
    _neg_send_binf_extra(extra)


def test_neg_inf_malformed_utf8_nick():
    """BINF with raw bytes that are not valid UTF-8 in NI. Phase 7d's
    re-enabled UTF-8 entry check (#65) should reject; this test guards
    that behaviour as a regression net."""
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        _reader, sid = _neg_handshake_get_sid(sock)
        cid_b32, pid_b32 = _neg_random_pid_cid_pair()
        # 0xFF is a lone continuation byte - never valid UTF-8 by itself.
        binf = (
            f"BINF {sid} ID{cid_b32} PD{pid_b32} NIbad".encode("utf-8")
            + b"\xff\xfe"
            + f" I40.0.0.0 SUTCP4\n".encode("utf-8")
        )
        try:
            sock.sendall(binf)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
        _neg_drain_briefly(sock)
    finally:
        sock.close()


def test_neg_inf_missing_required_fields():
    """BINF with no ID / PID at all. Login flow expects both to validate
    the CID = Tiger(PID) constraint; missing fields must not crash the
    handler."""
    cid_b32, _pid_b32 = _neg_random_pid_cid_pair()
    # Send only a NI - no ID, no PD. Hub should either ISTA-reject or
    # silently drop the connection.
    extra = "NImissing-pid-id I40.0.0.0 SUTCP4"
    _neg_send_binf_extra(extra)


def test_neg_repeated_binf_burst():
    """Send 30 BINFs back-to-back on a single connection before any HPAS.
    Goal: stress the parse() reentrancy fix (Phase 7d, #65) and any
    per-connection state churn under burst INF traffic."""
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        _reader, sid = _neg_handshake_get_sid(sock)
        for i in range(30):
            cid_b32, pid_b32 = _neg_random_pid_cid_pair()
            binf = (
                f"BINF {sid} ID{cid_b32} PD{pid_b32}"
                f" NIburst{i} I40.0.0.0 SUTCP4\n"
            )
            try:
                sock.sendall(binf.encode("utf-8"))
            except (BrokenPipeError, ConnectionResetError, OSError):
                # Hub disconnected mid-burst; that is an acceptable
                # rate-limit response.
                return
        _neg_drain_briefly(sock)
    finally:
        sock.close()


def test_neg_command_before_handshake():
    """Send a BMSG before any HSUP. The hub's state-machine must reject
    the out-of-order command; specifically must not attribute the message
    to an uninitialised user record."""
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        try:
            sock.sendall(b"BMSG AAAA hello-from-pre-handshake-state\n")
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
        _neg_drain_briefly(sock)
    finally:
        sock.close()


def test_neg_hpas_before_binf():
    """Send HPAS immediately after HSUP, before any BINF. The hub does not
    have a salt for us yet - the password-state machine must reject."""
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        _reader, _sid = _neg_handshake_get_sid(sock)
        # 32 zero bytes b32-encoded - syntactically valid base32, but
        # there's no HPAS challenge in flight yet.
        bogus = _b32_encode(b"\x00" * 32)
        try:
            sock.sendall(f"HPAS {bogus}\n".encode("utf-8"))
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
        _neg_drain_briefly(sock)
    finally:
        sock.close()


def test_neg_post_login_oversized_msg():
    """After a clean login, send a 70 KiB BMSG. Phase 7d's 64 KiB
    command-size cap (#65) should engage; the hub must close the
    connection without throwing a Lua error."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        try:
            sid, _reader = _adc_login(sock, "dummy", "test")
        except TestFailure:
            return  # login failed before we even try the negative; not our bug
        oversized = "X" * 70000
        try:
            sock.sendall(f"BMSG {sid} {oversized}\n".encode("utf-8"))
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
        _neg_drain_briefly(sock)


def test_neg_post_login_oversized_search():
    """After a clean login, send an oversized BSCH (5 KiB token list).
    Search dispatch must not buffer the entire payload into a Lua string
    that overruns any per-field cap."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        try:
            sid, _reader = _adc_login(sock, "dummy", "test")
        except TestFailure:
            return
        # Each AN<token> is 12 bytes; 400 of them = ~5 KiB. Well under the
        # 64 KiB total cap, but a flood of named parameters in one frame.
        tokens = " ".join(f"AN{'q' * 8}{i:03d}" for i in range(400))
        try:
            sock.sendall(f"BSCH {sid} {tokens}\n".encode("utf-8"))
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
        _neg_drain_briefly(sock)


def test_neg_post_login_search_burst():
    """After a clean login, fire 50 BSCH commands back-to-back. Should be
    rate-limited (per-user search rate) or silently absorbed; must not
    produce a Lua error from churned listener state."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        try:
            sid, _reader = _adc_login(sock, "dummy", "test")
        except TestFailure:
            return
        for i in range(50):
            try:
                sock.sendall(f"BSCH {sid} ANqt{i}\n".encode("utf-8"))
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
        _neg_drain_briefly(sock)


def test_neg_post_login_inf_burst():
    """After a clean login, fire 50 BINF updates back-to-back. Tests that
    the INF bucket (#80) absorbs share-state-update floods without
    crashing the dispatcher. The first ~burst go through to onInf
    listeners, the rest are silently dropped by rl_inf_drop. Hub must
    stay alive."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        try:
            sid, _reader = _adc_login(sock, "dummy", "test")
        except TestFailure:
            return
        for i in range(50):
            try:
                # Vary SS (share size) to look like a watch-folder
                # churning files in / out - the legitimate-use case the
                # bucket is sized to tolerate up to its burst.
                sock.sendall(
                    f"BINF {sid} SS{1000 + i}\n".encode("utf-8")
                )
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
        _neg_drain_briefly(sock)


def test_neg_post_login_pm_burst():
    """After a clean login, fire 50 DMSG private messages back-to-back
    at our OWN sid (self-target). Self-target is accepted by incoming()
    (mysid == usersid check passes, targetuser is non-nil) so the
    dispatcher actually reaches the _normal.DMSG handler and the
    rl_pm_drop rate-limit gate. Targeting a non-existent SID like ZZZZ
    instead would short-circuit at hub.lua:1264 with ISTA 140 BEFORE
    dispatch, defeating the test's purpose. Tests that the PM bucket
    (#80 split from msg) rate-limits / absorbs without crashing the
    dispatcher."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        try:
            sid, _reader = _adc_login(sock, "dummy", "test")
        except TestFailure:
            return
        for i in range(50):
            try:
                sock.sendall(
                    f"DMSG {sid} {sid} hello{i}\n".encode("utf-8")
                )
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
        _neg_drain_briefly(sock)


def test_neg_post_login_ctm_burst():
    """After a clean login, fire 50 DCTM commands at our own SID
    (self-target). See PM burst test above for why we self-target
    instead of using a non-existent SID. Confirms the #80 CTM bucket
    absorbs a connection-setup flood without crashing the dispatcher
    and actually reaches the rl_ctm_drop gate."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        try:
            sid, _reader = _adc_login(sock, "dummy", "test")
        except TestFailure:
            return
        for i in range(50):
            try:
                sock.sendall(f"DCTM {sid} {sid} ADC/1.0 12345 tok{i}\n".encode("utf-8"))
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
        _neg_drain_briefly(sock)


def test_neg_post_login_rcm_burst():
    """After a clean login, fire 50 DRCM commands at our own SID.
    DRCM shares the CTM bucket since both are peer-connection
    initiation primitives. Tests the second code path through
    rl_ctm_drop."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        try:
            sid, _reader = _adc_login(sock, "dummy", "test")
        except TestFailure:
            return
        for i in range(50):
            try:
                sock.sendall(f"DRCM {sid} {sid} ADC/1.0\n".encode("utf-8"))
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
        _neg_drain_briefly(sock)


def test_hqui_from_client_honored():
    """ADC 6.3.10: client-initiated HQUI must be honored - hub closes
    the connection cleanly without replying ISTA 125 (unknown command).
    Before T1.7 of #147 the parser accepted HQUI but the dispatcher
    had no entry, so the hub answered with the catch-all unknown-
    command STA instead of treating QUI as a polite goodbye."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        sid, _reader = _adc_login(sock, "dummy", "test")
        try:
            sock.sendall(f"HQUI {sid}\n".encode("utf-8"))
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
        # Drain whatever the hub still has buffered for us before the
        # close. Should be empty or contain only normal logout
        # broadcasts, never ISTA 125.
        sock.settimeout(2.0)
        buf = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except (socket.timeout, TimeoutError):
            raise TestFailure(
                "hub did not close socket within 2s after HQUI; "
                "T1.7 dispatcher likely not wired correctly"
            )
        if b"ISTA 125" in buf:
            raise TestFailure(
                f"hub rejected client HQUI as unknown command "
                f"(ISTA 125 in tail): {buf[:200]!r}"
            )


def test_neg_post_login_natt_burst():
    """After a clean login, fire 50 mixed DNAT / DRNT commands (ADC-EXT
    NATT, T1.1 of #147) at our own SID. Both new dispatch routes
    share the CTM bucket (peer-connection setup); confirms NATT relay
    absorbs floods the same way DCTM / DRCM do without crashing and
    actually reaches the rl_ctm_drop gate."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        try:
            sid, _reader = _adc_login(sock, "dummy", "test")
        except TestFailure:
            return
        for i in range(50):
            # Alternate the two new commands so the test exercises both
            # dispatch paths through rl_ctm_drop, not just one.
            cmd = "DNAT" if i % 2 == 0 else "DRNT"
            try:
                sock.sendall(
                    f"{cmd} {sid} {sid} ADC/1.0 12345 tok{i}\n".encode("utf-8")
                )
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
        _neg_drain_briefly(sock)


def test_neg_canary_hub_alive():
    """After the negative-test battery, the hub must still accept a clean
    login. This is the canary that catches any of the above tests having
    crashed or destabilised the hub - if the canary fails, walk the
    failed-tests list above and re-run individually to find the offender.

    The negative-test battery burns through per-IP connection-rate budget
    (default ratelimit_perip_conn_burst = 30, refill 10/sec). Sleep up
    front so the bucket has time to refill - we want to test "hub still
    works", not "hub still rate-limits us". Retry the connect a couple
    of times in case the bucket needs a moment more."""
    time.sleep(3)
    last_err = None
    for attempt in range(5):
        try:
            with socket.create_connection(
                (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
            ) as sock:
                sid, _reader = _adc_login(sock, "dummy", "test")
                if not sid or len(sid) != 4:
                    raise TestFailure(
                        f"hub did not accept clean login after "
                        f"negative-test battery; got SID {sid!r}"
                    )
                return
        except (OSError, TestFailure) as e:
            last_err = e
            time.sleep(1.0)
    raise TestFailure(
        f"hub did not accept clean login after 5 retries spanning "
        f"~8 seconds post-fuzz-battery; last error: {last_err!r}"
    )


def test_setpass_preserves_encryption(staging_dir: Path):
    """#92 regression: cmd_setpass must persist user.tbl through the
    encrypted cfg.saveusers() path, not bypass it via util.savearray().
    Pre-fix, every +setpass invocation rewrote user.tbl as plaintext
    Lua source, silently undoing the Phase 7f F-AUTH-1 mitigation.

    Drive a real +setpass from the dummy login, verify the on-disk
    user.tbl still carries the LDC1 magic, and confirm by re-login
    that the new password actually took effect (catches silent no-ops
    that would leave LDC1 magic unchanged from the prior HPAS save).

    The new password must satisfy the default min_password_length=10
    so cmd_setpass does not bail out at the length check before saving.
    No subsequent test logs in as dummy, so we do not reset; staging
    is rebuilt per harness run anyway."""
    new_pass = "smoketestnew"  # 12 chars; passes min_password_length=10
    user_tbl = staging_dir / "cfg" / "user.tbl"

    # ADC BMSG body: spaces inside the message are escaped as `\s` so
    # the parser treats the whole thing as one positional parameter.
    # Without escaping, "+setpass nick myself smoketestnew" arrives at
    # the script as `parameters=""` (only the leading "+setpass" lands
    # in adccmd[6]) and the command silently no-ops.
    body = _adc_escape(f"+setpass nick myself {new_pass}")

    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")
        sock.sendall(f"BMSG {sid} {body}\n".encode("utf-8"))
        # cmd_setpass replies via user:reply(...), which goes out as
        # private chat (E or D type) from the hubbot. Wait for it so
        # we know the script's save path has executed.
        reader.recv_until(
            lambda f: f.startswith("EMSG ") or f.startswith("DMSG "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )

    head = user_tbl.read_bytes()[:4]
    if head != b"LDC1":
        raise TestFailure(
            f"user.tbl bypassed encryption after +setpass (head={head!r}); "
            f"#92 regression: cmd_setpass writes plaintext via util.savearray"
        )

    # Confirm cmd_setpass actually persisted the new password (the LDC1
    # magic alone is also produced by the prior HPAS save, so without
    # this the test could pass even with a silent no-op).
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        try:
            _adc_login(sock, "dummy", new_pass)
        except TestFailure as e:
            raise TestFailure(
                f"+setpass did not actually change the password (re-login "
                f"with new value rejected): {e}"
            )

    # Give the hub a moment to flush the disconnect-driven cfg.saveusers
    # so the next disk-state test does not race the io_open("wb") +
    # f:write cycle and observe a transiently empty user.tbl.
    time.sleep(0.5)


def test_usertbl_bak_atomic_refresh(staging_dir: Path):
    """Closes upstream luadch#189: previously user.tbl.bak only got
    refreshed at hub start / +reload, so a corrupted user.tbl would
    fall back to a weeks-old snapshot and silently lose recent regs.

    saveusers() now writes user.tbl atomically (.tmp + rename) and
    immediately mirrors the same on-disk bytes to user.tbl.bak. After
    every successful save the two files should be byte-identical and
    both carry the LDC1 encrypted-at-rest magic. The prior tests in
    this run have driven multiple saveusers calls (HPAS lastconnect
    updates + the +setpass test), so by the time this test runs both
    files exist and reflect the latest save."""
    cfg_dir = staging_dir / "cfg"
    user_tbl = cfg_dir / "user.tbl"
    user_tbl_bak = cfg_dir / "user.tbl.bak"

    if not user_tbl_bak.exists():
        raise TestFailure(f"user.tbl.bak missing at {user_tbl_bak}")
    if user_tbl_bak.read_bytes()[:4] != b"LDC1":
        raise TestFailure(f"user.tbl.bak is not encrypted at rest")

    # Same bytes -> same nonce -> same blob -> byte-equal files.
    # saveusers() builds the encrypted blob once and writes it to both
    # paths, so this is the strict equality check we want.
    if user_tbl.read_bytes() != user_tbl_bak.read_bytes():
        raise TestFailure(
            "user.tbl and user.tbl.bak diverged - .bak refresh after "
            "saveusers is not running atomically"
        )


def test_cert_autogen_first_boot(staging_dir: Path):
    """Closes #77: the hub auto-generates a self-signed P-256 ECDSA
    cert + key on first boot when none exist on disk. The smoke
    harness setup intentionally skips the legacy
    `make_cert.{sh,bat}` pre-gen step, so by the time the prior
    tests' TLS handshakes succeeded, the cert was generated by
    core/cert_bootstrap.lua.

    This test asserts the on-disk shape of the auto-generated
    artifacts: both files exist, both are PEM-formatted, the
    cert has plausible size (an ECDSA self-signed cert with a
    short CN is in the few-hundred-byte range), and the cert
    parses cleanly through Python's `ssl` module."""
    cert_path = staging_dir / "certs" / "servercert.pem"
    key_path = staging_dir / "certs" / "serverkey.pem"

    if not cert_path.exists():
        raise TestFailure(f"hub did not auto-generate cert at {cert_path}")
    if not key_path.exists():
        raise TestFailure(f"hub did not auto-generate key at {key_path}")

    cert_bytes = cert_path.read_bytes()
    key_bytes = key_path.read_bytes()

    if not cert_bytes.startswith(b"-----BEGIN CERTIFICATE-----"):
        raise TestFailure(
            f"servercert.pem is not PEM (head={cert_bytes[:40]!r})"
        )
    # OpenSSL 3.x's PEM_write_bio_PrivateKey emits PKCS#8 format with
    # a generic "PRIVATE KEY" header, regardless of the underlying
    # algorithm. Older PEM_write_bio_ECPrivateKey used "EC PRIVATE
    # KEY"; we accept either so a future API switch (or a build
    # against legacy OpenSSL) does not cause a false failure here.
    if not (
        key_bytes.startswith(b"-----BEGIN PRIVATE KEY-----")
        or key_bytes.startswith(b"-----BEGIN EC PRIVATE KEY-----")
    ):
        raise TestFailure(
            f"serverkey.pem is not PEM (head={key_bytes[:40]!r})"
        )

    # Sanity range: a P-256 self-signed cert is ~400-700 bytes.
    if not (200 < len(cert_bytes) < 4096):
        raise TestFailure(
            f"servercert.pem size out of plausible range: {len(cert_bytes)} bytes"
        )

    # Parse the cert - if it's malformed, ssl will raise and the test
    # fails with a useful traceback rather than just "looks like PEM."
    import ssl as _ssl_check
    try:
        ctx = _ssl_check.SSLContext(_ssl_check.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cadata=cert_bytes.decode("ascii"))
    except Exception as e:
        raise TestFailure(f"servercert.pem failed to parse via ssl module: {e}")


def test_usertbl_encrypted_at_rest(staging_dir: Path):
    """Phase 7f F-AUTH-1: user.tbl on disk must start with the LDC1 magic
    after the hub has had any reason to save it (HPAS lastconnect update
    runs every login). master.key must exist with the AES-256 key size.

    We rely on the prior tests having logged in dummy/test (forces a
    saveusers via the HPAS handler), so by the time this runs user.tbl
    is in the encrypted format."""
    cfg_dir = staging_dir / "cfg"
    user_tbl = cfg_dir / "user.tbl"
    master_key = cfg_dir / "master.key"
    if not master_key.exists():
        raise TestFailure(f"master.key missing at {master_key}")
    key_bytes = master_key.read_bytes()
    if len(key_bytes) != 32:
        raise TestFailure(f"master.key size {len(key_bytes)}; expected 32")
    if not user_tbl.exists():
        raise TestFailure(f"user.tbl missing at {user_tbl}")
    head = user_tbl.read_bytes()[:4]
    if head != b"LDC1":
        raise TestFailure(
            f"user.tbl is not encrypted at rest (head={head!r}); "
            f"expected LDC1 magic prefix"
        )


# Plaintext user.tbl with the bundled dummy/test reg. Used by the
# #128 plaintext-mode test setup to install a known-good baseline
# after wiping master.key (the existing encrypted user.tbl can no
# longer decrypt without the key). Format mirrors examples/cfg/user.tbl.
_DUMMY_USERTBL_PLAINTEXT = (
    b"\xef\xbb\xbfreturn {\n\n"
    b"    { badpassword = 0, lastconnect = 0, level = 100, "
    b'nick = "dummy", password = "test", rank = "2", },\n\n'
    b"}\n"
)


def _switch_to_plaintext_mode(staging_dir: Path, current_proc, current_log_file):
    """#128 setup: stop the encryption-enabled hub, flip encrypt_usertbl
    to false in cfg.tbl, install a fresh plaintext user.tbl baseline,
    wipe master.key, restart. Returns the new (proc, log_file) so
    main() can clean up regardless of whether the subsequent
    assertions pass."""
    stop_hub(current_proc, current_log_file)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    # Target the *setting line* specifically (trailing comma); a more
    # permissive pattern would also match the explanatory comment
    # text "encrypt_usertbl = true." inside the doc block above the
    # actual key.
    text, n = re.subn(
        r"^\s*encrypt_usertbl\s*=\s*true\s*,",
        "    encrypt_usertbl = false,",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if n != 1:
        raise TestFailure(
            "could not flip encrypt_usertbl to false in cfg.tbl - "
            "the toggle line was not found in the staging tree"
        )
    cfg_path.write_text(text, encoding="utf-8")

    # Sanity check that the *setting line* (not just the comment) now
    # reads false.
    after = cfg_path.read_text(encoding="utf-8")
    if not re.search(r"^\s*encrypt_usertbl\s*=\s*false\s*,",
                     after, flags=re.MULTILINE):
        raise TestFailure(
            "cfg.tbl edit did not persist - the encrypt_usertbl setting "
            "line is not false after the rewrite"
        )

    # Wipe master.key so cfg_secret.init() runs the no-key path on
    # the second start (and we can verify it does NOT regenerate).
    (staging_dir / "cfg" / "master.key").unlink(missing_ok=True)

    # Install a known-good plaintext user.tbl. The current staging
    # user.tbl is AES-encrypted (the first hub rewrote it during the
    # encrypted-mode tests) and master.key is now gone, so it can no
    # longer decrypt. Without a usable user.tbl the dummy/test login
    # below would fail.
    (staging_dir / "cfg" / "user.tbl").write_bytes(_DUMMY_USERTBL_PLAINTEXT)
    # Wipe .bak so saveusers writes both files fresh in the new
    # plaintext format.
    (staging_dir / "cfg" / "user.tbl.bak").unlink(missing_ok=True)

    # Linux kernels can hold the listening sockets in TIME_WAIT for a
    # moment after SIGTERM even with SO_REUSEADDR - the previous start
    # in this same staging tree was bound here. A short sleep avoids
    # racing the kernel cleanup.
    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    return proc, log_file


def test_usertbl_plaintext_when_disabled(staging_dir: Path, proc=None):
    """#128 assertions: with encrypt_usertbl=false in cfg.tbl and a
    fresh staging tree, completing a login must write user.tbl as
    plaintext Lua source (no LDC1 magic) and must NOT auto-generate
    a master.key. Caller is responsible for putting the hub into
    plaintext mode via _switch_to_plaintext_mode() first."""
    try:
        wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)
    except TimeoutError as e:
        # Hub never bound the port. Surface every diagnostic we can
        # pull so CI shows what the second instance was doing rather
        # than just "timed out".
        diag = ""
        if proc is not None:
            rc = proc.poll()
            diag += f"\nproc.poll() = {rc!r} (None == still running)"
        for fname in ("smoke-hub.log", "error.log"):
            path = staging_dir / "log" / fname
            try:
                size = path.stat().st_size if path.exists() else "missing"
                content = path.read_text(encoding="utf-8", errors="replace") \
                    if path.exists() else ""
                tail = "\n".join(content.splitlines()[-40:])
                diag += f"\n--- {fname} (size={size}, last 40 lines) ---\n{tail}"
            except OSError as oe:
                diag += f"\n--- {fname} (read failed: {oe}) ---"
        # cfg.tbl: check that the toggle edit landed.
        try:
            cfg = (staging_dir / "cfg" / "cfg.tbl").read_text(encoding="utf-8")
            for i, line in enumerate(cfg.splitlines(), 1):
                if "encrypt_usertbl" in line:
                    diag += f"\ncfg.tbl:{i}: {line!r}"
        except OSError:
            pass
        raise TestFailure(f"{e}{diag}")

    # Trigger a save by completing a login; the HPAS handler updates
    # lastconnect on the registered user record and that forces
    # saveusers.
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        _adc_login(sock, "dummy", "test")

    # Give the post-login save path a moment to flush.
    time.sleep(0.5)

    user_tbl = staging_dir / "cfg" / "user.tbl"
    if not user_tbl.exists():
        raise TestFailure(
            "user.tbl missing after login under encrypt_usertbl=false; "
            "save path should have written it as plaintext"
        )

    head = user_tbl.read_bytes()[:4]
    if head == b"LDC1":
        raise TestFailure(
            "user.tbl has LDC1 magic despite encrypt_usertbl=false; "
            "saveusers wrote an encrypted blob - the toggle is not "
            "wired through to the write path"
        )

    # cfg_secret should NOT have generated a master.key when
    # encryption is disabled.
    master_key = staging_dir / "cfg" / "master.key"
    if master_key.exists():
        raise TestFailure(
            "master.key was generated despite encrypt_usertbl=false; "
            "cfg_secret.init() bypass for the disabled path is broken"
        )


def _switch_to_tier_mode(staging_dir: Path, current_proc, current_log_file):
    """#80 PR4 setup: stop the hub, append a strict-tier definition for
    level 100 (dummy) to cfg.tbl, bump bypass_level above 100 so the
    op-bypass does not skip the check, restart. Returns the new
    (proc, log_file) so main() can clean up regardless of whether the
    subsequent assertions pass."""
    stop_hub(current_proc, current_log_file)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")

    # Append the three keys just before the final closing brace. The
    # bundled cfg.tbl has no ratelimit_* lines at all (it inherits the
    # defaults from core/cfg_defaults.lua), so this is purely additive
    # - we are not editing an existing setting line.
    tier_block = (
        "\n    -- inserted by smoke harness for the tier-overlay test\n"
        "    ratelimit_bypass_level = 200,\n"
        '    ratelimit_tier_for_level = { [100] = "strict" },\n'
        '    ratelimit_tiers = { strict = { msg_burst = 2, msg_rate = 0.1 } },\n'
    )
    new_text, n = re.subn(
        r"(\n)\}\s*$",
        tier_block + r"\1}\n",
        text,
        count=1,
    )
    if n != 1:
        raise TestFailure(
            "could not inject tier block into cfg.tbl - the final "
            "closing brace was not found at the end of the file"
        )
    cfg_path.write_text(new_text, encoding="utf-8")

    # Same TIME_WAIT consideration as the plaintext-mode switch above.
    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    return proc, log_file


def test_ratelimit_tier_msg_throttle(staging_dir: Path, proc=None):
    """#80 PR4 assertion: with bypass_level=200 and a tier mapping
    level 100 -> { msg_burst=2 }, dummy (level 100) sending 5 BMSGs in
    rapid succession should see exactly 2 broadcasts echoed back. The
    other 3 are dropped at the hub by rl_msg_drop because the bucket
    is exhausted and the rate is too low (0.1/s) for any refill in the
    test's wall-clock duration. Confirms the tier overlay actually
    replaces the global msg_burst=10 scalar instead of silently falling
    back to it. Caller is responsible for putting the hub into tier
    mode via _switch_to_tier_mode() first."""
    try:
        wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)
    except TimeoutError as e:
        diag = ""
        if proc is not None:
            rc = proc.poll()
            diag += f"\nproc.poll() = {rc!r} (None == still running)"
        for fname in ("smoke-hub.log", "error.log"):
            path = staging_dir / "log" / fname
            try:
                size = path.stat().st_size if path.exists() else "missing"
                content = path.read_text(encoding="utf-8", errors="replace") \
                    if path.exists() else ""
                tail = "\n".join(content.splitlines()[-40:])
                diag += f"\n--- {fname} (size={size}, last 40 lines) ---\n{tail}"
            except OSError as oe:
                diag += f"\n--- {fname} (read failed: {oe}) ---"
        raise TestFailure(f"{e}{diag}")

    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        sid, _reader = _adc_login(sock, "dummy", "test")
        # Unique per-test marker so we don't collide with anything else
        # the hub may be broadcasting on this connection.
        marker = "tiertest" + secrets.token_hex(4)
        for i in range(5):
            sock.sendall(f"BMSG {sid} {marker}{i}\n".encode("utf-8"))
        # Give the hub a moment to dispatch + echo whatever it accepts.
        time.sleep(0.5)
        sock.settimeout(0.5)
        buf = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except (socket.timeout, TimeoutError):
            pass
        echoes = sum(1 for i in range(5) if f"{marker}{i}".encode() in buf)
        if echoes != 2:
            raise TestFailure(
                f"tier overlay did not throttle BMSG as expected: "
                f"with msg_burst=2 in the strict tier for level 100, "
                f"5 BMSGs should produce exactly 2 echoes, got {echoes}. "
                f"Either the tier mapping never resolved (fallback to "
                f"global msg_burst=10 = all 5 echo) or the bypass-level "
                f"check let dummy through (level 100 should NOT bypass "
                f"with bypass_level=200). Buffer sample: {buf[:200]!r}"
            )


def test_canonical_socket_layout(staging_dir: Path):
    """Closes #88: LuaSocket and LuaSec install in the canonical layout
    so plugins can `require "socket.http"` / `require "ssl.https"` per
    the standard Lua convention.

    Static path-existence check - if the CMake install rules drift back
    to the flat luadch-2.x bundling, http.lua's own internal
    `require "socket.url"` would fail and any HTTP-using plugin breaks.
    """
    expected = [
        # LuaSocket entrypoint + top-level helpers
        "lib/luasocket/lua/socket.lua",
        "lib/luasocket/lua/mime.lua",
        "lib/luasocket/lua/ltn12.lua",
        # LuaSocket submodules (require "socket.X")
        "lib/luasocket/lua/socket/http.lua",
        "lib/luasocket/lua/socket/url.lua",
        "lib/luasocket/lua/socket/headers.lua",
        # LuaSec entrypoint + submodules
        "lib/luasec/lua/ssl.lua",
        "lib/luasec/lua/ssl/https.lua",
        "lib/luasec/lua/ssl/options.lua",
        # SLAXML XML parser (used by ptx_RSSFeedWatch and any future
        # XML-consuming plugin in luadch-ng/scripts)
        "lib/slaxml/slaxml.lua",
    ]
    missing = [p for p in expected if not (staging_dir / p).exists()]
    if missing:
        raise TestFailure(
            "canonical LuaSocket / LuaSec layout incomplete; missing:\n  "
            + "\n  ".join(missing)
        )


def test_no_script_errors(log_path: Path, error_log_path: Path = None):
    """
    Plugin-load smoke: scan the hub's stdout AND the on-disk error.log
    for "script error:" lines. core/scripts.lua emits exactly that
    prefix when a plugin fails to load or a listener throws.

    Phase 8a-2 (issue #121): error_log_path was added because the
    captured hub stdout in `log_path` only carries C-level prints from
    the hub binary - Lua-side `out.error()` writes to log/error.log on
    disk. Pre-fix, this test silently passed even when plugins were
    raising on every login because the negative-test fuzz suite did
    not surface those errors anywhere stdout could see them.
    """
    bad_lines = []

    if log_path.exists():
        text = log_path.read_text(encoding="utf-8", errors="replace")
        bad_lines.extend(
            (str(log_path), line)
            for line in text.splitlines()
            if "script error:" in line
        )
    else:
        raise TestFailure(f"hub log not found at {log_path}")

    if error_log_path is not None and error_log_path.exists():
        text = error_log_path.read_text(encoding="utf-8", errors="replace")
        bad_lines.extend(
            (str(error_log_path), line)
            for line in text.splitlines()
            if "script error:" in line
        )

    if bad_lines:
        sample = "\n  ".join(f"[{src}] {line}" for src, line in bad_lines[:5])
        raise TestFailure(
            f"hub emitted {len(bad_lines)} script error line(s):\n  {sample}"
        )


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
    # Phase 8a-2 negative-test fuzz suite (issue #121). Each test feeds
    # malformed input and checks the hub does not crash; the canary at
    # the end and test_no_script_errors at the end of the run together
    # detect any failure.
    ("neg: BINF with negative numerics", test_neg_inf_negative_numerics),
    ("neg: BINF with oversize numerics", test_neg_inf_oversize_numerics),
    ("neg: BINF with invalid IPv4", test_neg_inf_invalid_ipv4),
    ("neg: BINF with invalid IPv6", test_neg_inf_invalid_ipv6),
    ("neg: BINF with overlong nick", test_neg_inf_overlong_nick),
    ("neg: BINF with overlong description", test_neg_inf_overlong_description),
    ("neg: BINF with malformed UTF-8 nick", test_neg_inf_malformed_utf8_nick),
    ("neg: BINF missing required ID/PID", test_neg_inf_missing_required_fields),
    ("neg: 30 repeated BINFs in one connection", test_neg_repeated_binf_burst),
    ("neg: command before handshake", test_neg_command_before_handshake),
    ("neg: HPAS before BINF", test_neg_hpas_before_binf),
    ("neg: post-login oversized BMSG", test_neg_post_login_oversized_msg),
    ("neg: post-login oversized BSCH", test_neg_post_login_oversized_search),
    ("neg: post-login BSCH burst", test_neg_post_login_search_burst),
    ("neg: post-login DMSG burst (#80 PM bucket)", test_neg_post_login_pm_burst),
    ("neg: post-login BINF burst (#80 INF bucket)", test_neg_post_login_inf_burst),
    ("neg: post-login DCTM burst (#80 CTM bucket)", test_neg_post_login_ctm_burst),
    ("neg: post-login DRCM burst (#80 CTM bucket)", test_neg_post_login_rcm_burst),
    ("neg: post-login NATT burst (#147 T1.1)", test_neg_post_login_natt_burst),
    ("HQUI from client closes cleanly (#147 T1.7)", test_hqui_from_client_honored),
    ("neg: canary - hub still alive after fuzz battery", test_neg_canary_hub_alive),
]


def run_tests(staging_dir: Path):
    log_path = staging_dir / "log" / "smoke-hub.log"
    error_log_path = staging_dir / "log" / "error.log"
    failed = []
    for name, fn in TESTS:
        try:
            fn()
        except Exception as e:
            log(f"FAIL  {name}: {e}")
            failed.append(name)
        else:
            log(f"PASS  {name}")

    # State-of-disk tests run after the protocol tests so any post-login
    # save (HPAS lastconnect update) has had a chance to land.
    try:
        test_canonical_socket_layout(staging_dir)
    except Exception as e:
        log(f"FAIL  canonical LuaSocket / LuaSec layout: {e}")
        failed.append("canonical LuaSocket / LuaSec layout")
    else:
        log("PASS  canonical LuaSocket / LuaSec layout")

    try:
        test_cert_autogen_first_boot(staging_dir)
    except Exception as e:
        log(f"FAIL  cert auto-gen on first boot: {e}")
        failed.append("cert auto-gen on first boot")
    else:
        log("PASS  cert auto-gen on first boot")

    try:
        test_setpass_preserves_encryption(staging_dir)
    except Exception as e:
        log(f"FAIL  +setpass preserves encryption: {e}")
        failed.append("+setpass preserves encryption")
    else:
        log("PASS  +setpass preserves encryption")

    try:
        test_usertbl_encrypted_at_rest(staging_dir)
    except Exception as e:
        log(f"FAIL  user.tbl encrypted at rest: {e}")
        failed.append("user.tbl encrypted at rest")
    else:
        log("PASS  user.tbl encrypted at rest")

    try:
        test_usertbl_bak_atomic_refresh(staging_dir)
    except Exception as e:
        log(f"FAIL  user.tbl.bak atomic refresh: {e}")
        failed.append("user.tbl.bak atomic refresh")
    else:
        log("PASS  user.tbl.bak atomic refresh")

    # The plugin-load test reads the hub log, so it runs after all
    # protocol tests have had a chance to exercise the listeners.
    try:
        test_no_script_errors(log_path, error_log_path)
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
        # As of v3.1.6 the hub auto-generates a self-signed P-256
        # ECDSA cert on first boot via core/cert_bootstrap.lua when
        # no cert exists. Default cfg.tbl ships TLS-only (#77).
        #
        # Wipe any leftover cert/key the install tree may carry from
        # earlier manual testing - the staging copy needs to start
        # without certs so the auto-gen path actually runs and
        # test_cert_autogen_first_boot has something to assert.
        for stale in ("servercert.pem", "serverkey.pem",
                      "cacert.pem", "cakey.pem"):
            (staging_dir / "certs" / stale).unlink(missing_ok=True)
        proc, log_file = start_hub(staging_dir)
        failed = run_tests(staging_dir)

        # #128 plaintext-mode test runs AFTER the regular battery
        # because cfg_secret.init() reads encrypt_usertbl once at
        # startup, so we have to stop + restart with a flipped cfg.
        # The setup helper returns the new (proc, log_file) so the
        # finally block below stops the right hub regardless of
        # whether the assertions raise.
        try:
            proc, log_file = _switch_to_plaintext_mode(
                staging_dir, proc, log_file
            )
            test_usertbl_plaintext_when_disabled(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  user.tbl plaintext mode when disabled: {e}")
            failed.append("user.tbl plaintext mode when disabled")
        else:
            log("PASS  user.tbl plaintext mode when disabled")

        # #80 PR4 tier-overlay test: same restart pattern as plaintext
        # mode. We inject a strict tier for level 100 (dummy) so that
        # sending more than burst BMSGs gets throttled at the hub
        # before the broadcast fan-out, proving the overlay path
        # actually replaces the global msg_burst=10 scalar.
        try:
            proc, log_file = _switch_to_tier_mode(
                staging_dir, proc, log_file
            )
            test_ratelimit_tier_msg_throttle(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  ratelimit tier overlay throttles BMSG: {e}")
            failed.append("ratelimit tier overlay throttles BMSG")
        else:
            log("PASS  ratelimit tier overlay throttles BMSG")
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
