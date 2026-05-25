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
import contextlib
import json
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
import zlib
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
TEST_PORT_HTTP = 15510    # Phase 8 S3: local HTTP API listener (#82)

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


@contextlib.contextmanager
def _logged_in_user(nick: str = "dummy", password: str = "test"):
    """Context manager wrapping `_adc_login` for tests that need a
    short-lived live ADC session.

    Yields (sock, sid, reader). On exit, closes the socket (catching
    OSError so a hub-side kick that already half-closed the socket
    does not raise out of the `with` block - the kick is the
    expected outcome of HTTP write-endpoint smoke tests).

    Phase 2 (#82 / #198) of the HTTP API has ~8 call sites that need
    a logged-in ADC user; before this helper each one carried 5-7
    lines of `socket.create_connection` / try / finally / except
    OSError boilerplate. PR-3 (cmd_gag) and PR-4 (cmd_ban) will
    reuse this helper plus `_assert_adc_drops` / `_assert_adc_alive`
    extensively, so the trajectory is for the helper count to stay
    small and this file to stay readable rather than splitting into
    a `tests/smoke/helpers.py` (revisit only if the helper count
    grows past ~6 single-purpose functions).
    """
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        sid, reader = _adc_login(sock, nick, password)
        yield sock, sid, reader
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _assert_adc_drops(sock, timeout: float = 2.0, attempts: int = 10):
    """Assert that the hub closes the ADC socket within `timeout`
    seconds. After an HTTP-driven kick or redirect, the hub sends
    `ISTA 230 ...` (or `IQUI <sid> RD ...`) and then FINs the
    socket. The test side sees a series of recv() calls returning
    chunks of frames followed by an empty bytes object (EOF) or an
    OSError (RST). A `socket.timeout` is treated as **failure**:
    the kick is fast on healthy CI, a 2s budget is more than enough
    for the hub-side close to land on the wire, and silently
    passing on timeout (the pre-PR-C inline pattern did this) hides
    the very regression this assertion exists to detect - a
    handler that no-ops without actually invoking the kick.

    Raises TestFailure if the kick is not observable within budget.
    """
    sock.settimeout(timeout)
    try:
        for _ in range(attempts):
            chunk = sock.recv(4096)
            if not chunk:
                return    # clean FIN observed - dropped
    except OSError:
        return    # RST also means the conn is dead (good)
    raise TestFailure(
        "ADC connection did NOT drop within the timeout - "
        "the HTTP write-endpoint did not deliver the kick "
        "(or did so faster than recv could observe, which is "
        "unrealistic for a non-keepalive hub close)"
    )


def _assert_adc_alive(sock, timeout: float = 1.0):
    """Assert that the ADC socket is still alive. Used after a 400/
    403/404/409/415 from an HTTP write-endpoint to confirm the
    handler short-circuited BEFORE the kick fired.

    Drains the socket in a recv-loop for `timeout` seconds and
    fails if a FIN (empty bytes) ever lands. Hub-pushed frames
    (BINF / IINF / queued chat) are fine - the loop swallows them.
    A timeout means "no evidence of close" which is the alive
    signal. The single-recv pre-PR-C inline pattern had a
    false-pass window: a hub frame queued before the assertion
    would short-circuit the check before the FIN arrived; this
    loop addresses that.
    """
    deadline = time.monotonic() + timeout
    sock.settimeout(timeout)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return    # timeout = no FIN observed = alive
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            return    # idle = alive
        except OSError:
            raise TestFailure(
                "ADC connection unexpectedly dropped (OSError) - "
                "the HTTP handler ran the side-effect when it "
                "should have short-circuited"
            )
        if chunk == b"":
            raise TestFailure(
                "ADC connection unexpectedly dropped (FIN) - the "
                "HTTP handler ran the side-effect when it should "
                "have short-circuited"
            )
        # non-empty: hub pushed a frame (BINF / IINF / chat). The
        # socket is alive; keep draining until the deadline.


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


def test_s1_fragmented_frame_reassembled():
    """Phase 8 S1: an ADC frame split across two TCP segments must be
    reassembled and processed as one frame.

    Pre-S1 (`receive(socket, "*l")`) a plain-TCP partial line returned
    nil,"timeout",<partial>, which the old _readbuffer guard treated as
    fatal -> the hub dropped the connection. This test therefore FAILS
    on pre-S1 code (connection closed / no reply) and PASSES on S1 - a
    true pre/post differentiator (CLAUDE.md s1a.7), and it directly
    exercises the latent "unwanted disconnects in big hubs" bug the S1
    journal documents.
    """
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sid, reader = _adc_login(sock, "dummy", "test")
        # Send "+help" as two TCP segments with the frame boundary (\n)
        # only in the second write.
        sock.sendall(f"BMSG {sid} +he".encode("utf-8"))
        time.sleep(0.25)  # force a separate read event on the hub side
        sock.sendall(b"lp\n")
        response = reader.recv_until(
            lambda f: f.startswith("EMSG ") or f.startswith("DMSG "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if len(response) < 20:
            raise TestFailure(
                f"fragmented +help reply unexpectedly short: {response!r}"
            )


def test_s1_two_frames_one_segment():
    """Phase 8 S1: two ADC frames delivered in a single TCP segment must
    be processed as two independent frames (no over-merge into one
    unparseable blob, no desync of the trailing-byte buffer).

    Over-merge would make adc_parse choke on an embedded \\n and produce
    no reply at all; a desynced remainder buffer would break the next
    command. The test asserts a reply to the doubled send AND that a
    subsequent independent command still works."""
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sid, reader = _adc_login(sock, "dummy", "test")
        # Two complete frames, one write / one segment.
        sock.sendall(f"BMSG {sid} +help\nBMSG {sid} +help\n".encode("utf-8"))
        reader.recv_until(
            lambda f: f.startswith("EMSG ") or f.startswith("DMSG "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        # Stream must not be desynced by the framer's remainder handling:
        # an independent follow-up command still gets answered.
        sock.sendall(f"BMSG {sid} +help\n".encode("utf-8"))
        followup = reader.recv_until(
            lambda f: f.startswith("EMSG ") or f.startswith("DMSG "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if len(followup) < 20:
            raise TestFailure(
                f"stream desynced after pipelined frames; follow-up "
                f"reply too short: {followup!r}"
            )


def test_literal_bracket_command_hint():
    """#137 regression: a user who types `[+!#]<cmd>` (with literal
    square brackets, copying the doc-notation as if it were the
    actual syntax) gets a hint and the broadcast is swallowed.

    The hint MUST:
      - mention the correct prefix form (e.g. `+help`)
      - NOT echo the input args - args may contain a password
        (e.g. `[+!#]reg <user> <pw>` would leak credentials if
        the bot replied with the original line)

    The test sends `[+!#]help foo bar` where `foo bar` stands in
    for arbitrary "secret" args, then asserts the bot's EMSG/DMSG
    reply does NOT contain `foo` or `bar`.
    """
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")
        # ADC escape: spaces become \s. So `[+!#]help foo bar` ->
        # `[+!#]help\sfoo\sbar`.
        sock.sendall(f"BMSG {sid} [+!#]help\\sfoo\\sbar\n".encode("utf-8"))
        # Drain all frames the hub sends back within 3 seconds and
        # collect them ALL. Two independent assertions:
        #   1. the hint BMSG (with "pick one of") arrived
        #   2. NO BMSG frame contains the input args "foo"/"bar"
        # Matching only the hint frame and checking it for leakage
        # would miss a regression where the broadcast escapes the
        # PROCESSED swallow and is echoed back from the user's own
        # SID before the hint - that BMSG would contain foo/bar
        # and the privacy claim would silently regress (the hint
        # itself never echoes input, but the un-swallowed broadcast
        # would).
        all_frames = []
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                f = reader.recv_until(lambda x: True, timeout=0.5)
                all_frames.append(f)
            except TestFailure:
                break
        bmsg_frames = [f for f in all_frames if f.startswith("BMSG ")]
        hint_frames = [f for f in bmsg_frames if "pick\\sone\\sof" in f]
        if not hint_frames:
            raise TestFailure(
                f"did not receive the literal-bracket hint BMSG; "
                f"BMSG frames seen: {bmsg_frames!r}"
            )
        hint = hint_frames[0]
        if "help" not in hint:
            raise TestFailure(
                f"hint did not mention the command name 'help': {hint!r}"
            )
        # Privacy assertion across ALL BMSG frames (hint plus any
        # leaked broadcast). `foo` / `bar` are stand-ins for
        # hypothetical password tokens; either appearing in any
        # BMSG returned by the hub means the swallow regressed.
        for frame in bmsg_frames:
            if "foo" in frame or "bar" in frame:
                raise TestFailure(
                    f"hub leaked input args (privacy regression of "
                    f"#137 - either hint echoed them or the broadcast "
                    f"was not swallowed): {frame!r}"
                )


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


def test_binf_without_i4_or_i6_accepted():
    """#161 regression: a BINF that omits I4 AND I6 must NOT be rejected
    with ISTA 220 'No CID/PID/NICK/IP found in your INF.'. Per ADC 4.3.x
    the I4 / I6 fields are conditionally required (only when the client
    supports TCP4 / UDP4 / TCP6 / UDP6). Hublist pingers and any
    IP-agnostic probe omit them legitimately. The hub fills in the
    TCP-source IP, same canonical path as the 0.0.0.0 placeholder.

    Test uses the registered `dummy` account so the success path is
    `IGPA <salt>` (password challenge), which lets us distinguish the
    fix from the bug:
      - Pre-fix: ISTA 220 immediately after BINF
      - Post-fix: IGPA, meaning BINF was accepted and identify-state
        passed

    BINF intentionally omits TCP4 / UDP4 in SU - the real pinger profile
    advertises no TCP/UDP feature (see go-dcpp dcping in upstream
    luadch/luadch#176: `SUKEYP,OSNR,UCM0,UCMD,BAS0,BASE,TIGR`). This is
    the spec-defined case where I4/I6 are *not* required at all. A
    future hardening that adds "if SU has TCP4 then require I4" must
    not break this test (it wouldn't, since we don't claim TCP4).

    IPv6 coverage note: the `userip:find(":", 1, true) and "I6" or "I4"`
    fallback in core/hub_dispatch.lua only exercises the "I6" branch
    when the socket is IPv6. This test connects to TEST_PORT_PLAIN
    (IPv4 only) so the IPv6 branch is untested here - the logic is
    trivial fallback (colon-presence in TCP-source IP string), proven
    by inspection rather than test. Worth a dedicated IPv6 smoke run
    if/when we expand IPv6 feature coverage.
    """
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        reader, sid = _neg_handshake_get_sid(sock)
        cid_b32, pid_b32 = _neg_random_pid_cid_pair()
        # BINF with NO I4, NO I6, NO TCP4/UDP4 in SU - matches the real
        # hublist-pinger profile. The bug fix lets the hub fill the IP
        # slot with the TCP-source IP via setnp(ipver, userip).
        binf = (
            f"BINF {sid}"
            f" ID{cid_b32}"
            f" PD{pid_b32}"
            f" NIdummy"
            f" SUBAS0,BASE,TIGR\n"
        )
        sock.sendall(binf.encode("utf-8"))
        # Read the first frame the hub emits after BINF. With the fix
        # this is IGPA (the password challenge for a registered user).
        # Without the fix it is ISTA 220 + IQUI.
        try:
            frame = reader.recv_until(
                lambda f: f.startswith("IGPA ") or f.startswith("ISTA "),
                timeout=PROTOCOL_TIMEOUT_SEC,
            )
        except TestFailure as e:
            raise TestFailure(
                f"hub did not respond to no-I4/no-I6 BINF within "
                f"{PROTOCOL_TIMEOUT_SEC}s: {e}"
            ) from e
        if frame.startswith("ISTA 220 "):
            raise TestFailure(
                f"hub rejected BINF without I4/I6 with ISTA 220 "
                f"(regression of #161): {frame!r}. Per ADC 4.3.x the "
                f"I4/I6 fields are conditionally required, not absolutely "
                f"required - the hub must fill in the TCP-source IP."
            )
        if not frame.startswith("IGPA "):
            raise TestFailure(
                f"unexpected response to no-I4/no-I6 BINF: {frame!r}. "
                f"Expected IGPA (registered user password challenge)."
            )


def test_binf_with_both_i4_and_i6_accepted():
    """#147 T3.1 (HBRI): a BINF that carries BOTH I4 AND I6 must be
    accepted, with the hub validating ONLY the family matching the
    connecting TCP source against userip. The OTHER family is the
    "other-family-than-the-connection" and stays unverified-but-
    stored (the trade-off documented in docs/SECURITY.md).

    This test exercises the HBRI differentiator: it connects via
    **IPv6** (TEST_PORT_PLAIN_V6) and sends BINF with a wrong I4
    (8.8.8.8, definitely not the TCP source) AND a correct I6 (::1,
    matches the v6 TCP source).

    Pre-T3.1 the hub probed I4 FIRST and validated the I4 against
    userip - which is ::1 here, so 8.8.8.8 != ::1 trips
    kill_wrong_ips and the user gets ISTA 246 invalid_ip.

    Post-T3.1 the hub probes both families, picks the field matching
    the v6 connection (= I6), validates ::1 == ::1, passes. The wrong
    I4 stays unverified but is preserved in adccmd for downstream
    forwarding - peers can choose to ignore it.

    Test uses the registered `dummy` account so success advances to
    IGPA (password challenge), distinguishing the fix from the bug:
      - Pre-fix: ISTA 246 invalid_ip immediately after BINF
      - Post-fix: IGPA, BINF accepted, identify-state passed
    """
    sock = socket.create_connection(
        ("::1", TEST_PORT_PLAIN_V6), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        reader, sid = _neg_handshake_get_sid(sock)
        cid_b32, pid_b32 = _neg_random_pid_cid_pair()
        # I4 8.8.8.8 (wrong - we are connecting on v6 ::1) + correct I6.
        # The smoke harness's v6 listener accepts connections from ::1
        # and userip will resolve to "::1" inside the hub. Pre-T3.1 the
        # I4-first validation kicks with ISTA 246; post-T3.1 the I6
        # check (matching family) passes.
        binf = (
            f"BINF {sid}"
            f" ID{cid_b32}"
            f" PD{pid_b32}"
            f" NIdummy"
            f" I48.8.8.8"
            f" I6::1"
            f" SUTCP4,TCP6,BAS0,BASE,TIGR\n"
        )
        sock.sendall(binf.encode("utf-8"))
        try:
            frame = reader.recv_until(
                lambda f: f.startswith("IGPA ") or f.startswith("ISTA "),
                timeout=PROTOCOL_TIMEOUT_SEC,
            )
        except TestFailure as e:
            raise TestFailure(
                f"hub did not respond to dual-stack BINF within "
                f"{PROTOCOL_TIMEOUT_SEC}s: {e}"
            ) from e
        if frame.startswith("ISTA 246 "):
            raise TestFailure(
                f"hub rejected dual-stack BINF with ISTA 246 invalid_ip: "
                f"{frame!r}. T3.1 must validate ONLY the family matching "
                f"the TCP source (I6 here); the I4 is the 'other family' "
                f"and stays unverified-but-stored."
            )
        if frame.startswith("ISTA "):
            raise TestFailure(
                f"unexpected ISTA response to dual-stack BINF: {frame!r}. "
                f"Expected IGPA."
            )
        if not frame.startswith("IGPA "):
            raise TestFailure(
                f"unexpected response to dual-stack BINF: {frame!r}. "
                f"Expected IGPA (registered user password challenge)."
            )
    finally:
        sock.close()


def test_post_login_i4_silent_stripped():
    """#222: post-login BINF carrying `I4 <new_ip>` MUST be silent-
    stripped, not killed. Pre-fix the `forbidden.flags_on_inf` check
    in `scripts/hub_inf_manager.lua` killed the user with `ISTA 240`
    + TL300; legitimate DC++ clients refreshing INF (e.g. after NAT
    rebind) were repeatedly bounced.

    Post-fix the I4 field is silent-stripped (broadcast carries no
    I4 update, stored `_inf` IP stays at the verified original); the
    other INF fields in the same update (here `DEnew-desc`) still
    get applied.

    Falsifiable: on unpatched code the test sees ISTA 240 + socket
    close, the `final` predicate hits the ISTA branch.
    """
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")
        # Drain any post-login state (own-BINF echo already consumed
        # by _adc_login). Send a post-login BINF update containing
        # I4 (a wrong-IP claim) + DE (a legitimate field update).
        update = (
            f"BINF {sid}"
            f" I4203.0.113.1"
            f" DEpost-login-i4-strip-test\n"
        )
        sock.sendall(update.encode("utf-8"))

        # Expect the broadcast echo of OUR update (BINF starting with
        # our SID) OR an ISTA reject. ISTA = pre-fix regression.
        echo = reader.recv_until(
            lambda f: f.startswith(f"BINF {sid}") or f.startswith("ISTA "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if echo.startswith("ISTA "):
            raise TestFailure(
                f"#222 regression: post-login INF with I4 was rejected "
                f"with ISTA. The fix silent-strips I4/I6 instead of "
                f"killing the user. Got: {echo!r}"
            )
        # Broadcast must NOT contain the wrong-IP claim (stripped).
        if "I4203.0.113.1" in echo:
            raise TestFailure(
                f"#222 regression: post-login broadcast carries the "
                f"client's I4 claim. The fix strips I4 from the cmd "
                f"before broadcast. Echo: {echo!r}"
            )
        # The other field (DE update) MUST be in the broadcast,
        # proving the strip is targeted to I4/I6 only. Note that
        # the bundled `usr_desc_prefix` plugin prepends the user's
        # level label (e.g. `[\sHUBOWNER\s]\s`) to the DE value, so
        # we substring-match the unique marker instead of the
        # exact `DE...=value` form.
        if "post-login-i4-strip-test" not in echo:
            raise TestFailure(
                f"#222 regression: legitimate non-IP INF field (DE) "
                f"was not broadcast. The strip must be targeted to "
                f"I4/I6 only - other fields stay. Echo: {echo!r}"
            )


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


def test_post_login_search_result_listener_chain():
    """#160 defense-in-depth: send a small burst of DRES and FRES
    after login so the etc_trafficmanager onSearchResult listener
    runs end-to-end at least once. The listener bodies do
    `user:level() < masterlevel` guards plus need_block() checks;
    we exercise the path so any syntax/upvalue regression in the
    new listener (or a sibling plugin that hooks onSearchResult)
    surfaces here rather than in production.

    Assertion is indirect via the existing test_no_script_errors
    canary at end of run - a hub script-error during onSearchResult
    dispatch would land in error.log and fail that check.
    """
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        try:
            sid, _reader = _adc_login(sock, "dummy", "test")
        except TestFailure:
            return
        # Send 5 DRES (D-class single-target result) + 5 FRES
        # (F-class feature-filtered result). Targets are our own
        # SID for D-class; FRES has no explicit target SID.
        # TR is the TigerTree hash - ADC enforces exactly 39 chars
        # from [A-Z2-7] (core/adc.lua:155). Build the value as 38
        # fixed chars + one digit-suffix in 2..6 (range 2,7) to
        # stay inside the alphabet AND the length cap. A length
        # or alphabet mismatch makes the parser drop the frame
        # silently (event.log, not error.log) and the listener
        # would never fire - the test would pass for the wrong
        # reason without exercising the new onSearchResult path.
        for i in range(2, 7):
            try:
                sock.sendall(
                    f"DRES {sid} {sid} FNself.txt SI100 TR{'A'*38}{i}\n".encode("utf-8")
                )
                sock.sendall(
                    f"FRES {sid} +ADC0 FNself{i}.txt SI100 TR{'B'*38}{i}\n".encode("utf-8")
                )
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


def _switch_to_dual_stack_same_port_mode(staging_dir: Path, current_proc, current_log_file):
    """#107 setup: stop the hub, flip tcp_ports_ipv6 and ssl_ports_ipv6
    to the same port numbers as their v4 counterparts so the next test
    can verify the (port, family)-keyed _server registry binds both
    listeners without "already exist" errors. Returns the new
    (proc, log_file)."""
    stop_hub(current_proc, current_log_file)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")

    # Reuse the v4 ports for v6 - the whole point of the fix is that
    # this layout is now legal.
    rewrites = [
        (r"tcp_ports_ipv6\s*=\s*\{[^}]*\}",
         f"tcp_ports_ipv6 = {{ {TEST_PORT_PLAIN} }}"),
        (r"ssl_ports_ipv6\s*=\s*\{[^}]*\}",
         f"ssl_ports_ipv6 = {{ {TEST_PORT_TLS} }}"),
    ]
    for pattern, replacement in rewrites:
        new_text, n = re.subn(pattern, replacement, text, count=1)
        if n != 1:
            raise TestFailure(
                f"could not flip {pattern} to same-as-v4 in cfg.tbl"
            )
        text = new_text
    cfg_path.write_text(text, encoding="utf-8")

    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    return proc, log_file


def test_dual_stack_same_port_binds(staging_dir: Path, proc=None):
    """#107 regression: with tcp_ports_ipv6 set to the same port number
    as tcp_ports, both v4 and v6 listeners must bind successfully (the
    _server registry is now (port, family)-keyed). Pre-fix the second
    addserver() call hit the existence check on the port and refused
    to bind, leaving the hub v4-only.

    Assertions:
    1. The v4 listener is reachable on 127.0.0.1:TEST_PORT_PLAIN.
    2. The v6 listener is reachable on ::1:TEST_PORT_PLAIN (same port).
    3. A handshake on each completes - confirms the listeners are
       actually wired, not just bound. The v6 listener has its own
       _server registry entry under the composite (port, "ipv6") key.
    4. The hub log does not contain "listeners on port ... already
       exist" - which would mean the existence check fired and one
       of the two never bound.
    """
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)
    # Resolve ::1 explicitly so getaddrinfo on Windows + Linux both
    # use the IPv6 loopback path (not 127.0.0.1).
    deadline = time.monotonic() + START_TIMEOUT_SEC
    last_err = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("::1", TEST_PORT_PLAIN), timeout=0.5):
                break
        except OSError as e:
            last_err = e
            time.sleep(0.2)
    else:
        raise TestFailure(
            f"v6 listener did not open on [::1]:{TEST_PORT_PLAIN}; "
            f"last error: {last_err}"
        )

    # Quick handshake on both. The hub's HSUP handler is family-
    # agnostic so the assertions are identical; we just want to prove
    # the bytes flow.
    for host_label, host in (("v4", HUB_HOST), ("v6", "::1")):
        with socket.create_connection((host, TEST_PORT_PLAIN), timeout=2) as s:
            s.sendall(b"HSUP ADBASE ADTIGR\n")
            buf = b""
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and b"\nIINF " not in buf:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
            if b"ISUP " not in buf:
                raise TestFailure(
                    f"no ISUP frame received on {host_label} "
                    f"({host}:{TEST_PORT_PLAIN}); buf={buf[:200]!r}"
                )

    # Belt-and-suspenders: scan the hub log for the existence-check
    # error string. If either of the two addserver() calls had hit
    # the check, the hub would have logged it during startup.
    log_path = staging_dir / "log" / "smoke-hub.log"
    if log_path.exists():
        text = log_path.read_text(encoding="utf-8", errors="replace")
        if "already exist" in text:
            # Filter to lines from THIS run's startup
            offending = [
                line for line in text.splitlines()
                if "already exist" in line
            ]
            raise TestFailure(
                f"hub log contains 'already exist' line(s) - the "
                f"existence check fired:\n  " +
                "\n  ".join(offending[:3])
            )


def _switch_to_hub_listen_loopback_mode(staging_dir: Path, current_proc, current_log_file):
    """#186 setup: stop the hub, set hub_listen to loopback-only and
    blank the IPv6 port arrays (a v4-only bind address yields no IPv6
    listener by design - blanking them keeps the test about the v4
    bind-restriction and avoids a noisy expected v6 bind failure).
    Returns the new (proc, log_file)."""
    stop_hub(current_proc, current_log_file)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    rewrites = [
        (r'hub_listen\s*=\s*\{[^}]*\}', 'hub_listen = { "127.0.0.1" }'),
        (r"tcp_ports_ipv6\s*=\s*\{[^}]*\}", "tcp_ports_ipv6 = { }"),
        (r"ssl_ports_ipv6\s*=\s*\{[^}]*\}", "ssl_ports_ipv6 = { }"),
    ]
    for pattern, replacement in rewrites:
        new_text, n = re.subn(pattern, replacement, text, count=1)
        if n != 1:
            raise TestFailure(
                f"could not apply {pattern!r} in cfg.tbl (is hub_listen "
                f"present in examples/cfg/cfg.tbl?)"
            )
        text = new_text
    cfg_path.write_text(text, encoding="utf-8")

    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    return proc, log_file


def test_hub_listen_honored(staging_dir: Path, proc=None):
    """#186 regression: with hub_listen = { "127.0.0.1" } the ADC
    listener MUST bind loopback only. Pre-fix, server.addserver bound
    p.addr (never p.ip) so hub_listen was silently ignored and the hub
    bound 0.0.0.0 regardless - an exposure for any operator who set a
    bind restriction. This test FAILS pre-fix (reachable off-loopback)
    and PASSES post-fix.

    1. ADC handshake on 127.0.0.1:<plain> still works.
    2. The same port is NOT reachable on this host's non-loopback
       IPv4 (skipped only if the env has no routable non-loopback
       address - never failed spuriously).
    """
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)

    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as s:
        s.sendall(b"HSUP ADBASE ADTIGR\n")
        reader = _ADCReader(s)
        reader.recv_until(lambda f: f.startswith("ISUP "))

    nonloop = None
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 80))  # no packets; resolves local addr
            cand = probe.getsockname()[0]
        finally:
            probe.close()
        if cand and not cand.startswith("127.") and cand != "0.0.0.0":
            nonloop = cand
    except OSError:
        nonloop = None
    if nonloop:
        try:
            c = socket.create_connection((nonloop, TEST_PORT_PLAIN), timeout=2)
            c.close()
            raise TestFailure(
                f"SECURITY: ADC listener reachable on non-loopback "
                f"{nonloop}:{TEST_PORT_PLAIN} despite hub_listen = "
                f'{{ "127.0.0.1" }} (#186: hub_listen ignored).'
            )
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass  # expected: refused/unreachable off-loopback
    else:
        log("  (skip non-loopback check: no non-loopback IPv4)")


def _read_first_token_from_file(token_path: Path) -> str:
    """Parse the bootstrap-sample file (`cfg/api_token.first`) written
    by `bootstrap_first_token`. The file starts with comment lines
    (prefix `#`); the first non-comment non-blank line is the token.
    Raises TestFailure if the file is missing or empty."""
    if not token_path.exists():
        raise TestFailure(f"expected sample token file at {token_path}, not present")
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return line
    raise TestFailure(f"sample token file {token_path} has no non-comment line")


def _switch_to_http_no_tokens_mode(staging_dir: Path, current_proc, current_log_file):
    """#231 setup step 1: flip `http_port = false` to a test port but
    leave `http_api_tokens` empty (the cfg.tbl default). Start the
    hub. Expected outcome:
    - The hub writes a sample token to `cfg/api_token.first` and
      logs a warning.
    - The HTTP listener is NOT bound (TCP connect to TEST_PORT_HTTP
      is refused).
    Returns (proc, log_file) so the asserting test can run against
    the live hub before `_switch_to_http_mode` takes over.

    Also applies the burst-bump cfg overrides that
    `_switch_to_http_mode` previously owned. This pre-emptive bump
    avoids re-writing cfg.tbl a third time once the token is
    injected; both cfg flips end up in place before the listener
    binds."""
    stop_hub(current_proc, current_log_file)

    # Remove a stale sample-token file from a previous test run on
    # the same staging dir so the assertion "file was created on
    # this boot" is meaningful. Production deployments do not
    # delete it - operator does, per docs.
    sample_path = staging_dir / "cfg" / "api_token.first"
    sample_path.unlink(missing_ok=True)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    new_text, n = re.subn(
        r"http_port\s*=\s*false",
        f"http_port = {TEST_PORT_HTTP}",
        text,
        count=1,
    )
    if n != 1:
        raise TestFailure(
            "could not flip http_port = false to a test port in cfg.tbl "
            "(is the http_port key present in examples/cfg/cfg.tbl?)"
        )
    new_text, nb = re.subn(
        r"http_api_burst\s*=\s*\d+",
        "http_api_burst = 100",
        new_text,
        count=1,
    )
    if nb != 1:
        raise TestFailure(
            "could not bump http_api_burst in cfg.tbl - missing default key?"
        )
    # Also bump the per-minute admin / read rates: the registered-
    # users family (#236) added dozens of admin-scope tests
    # (cmd_reg POST + PATCH, cmd_setpass PUT, cmd_nickchange PUT,
    # cmd_upgrade PUT, cmd_delreg DELETE) that exhaust the
    # production default of 60/min on Linux CI even after the
    # burst-100 bump. Staging is single-token + single-client, so
    # the production-grade DoS defence is moot here.
    new_text, nra = re.subn(
        r"http_api_rate_admin\s*=\s*\d+",
        "http_api_rate_admin = 600",
        new_text,
        count=1,
    )
    if nra != 1:
        raise TestFailure(
            "could not bump http_api_rate_admin in cfg.tbl - missing default key?"
        )
    new_text, nrr = re.subn(
        r"http_api_rate_read\s*=\s*\d+",
        "http_api_rate_read = 600",
        new_text,
        count=1,
    )
    if nrr != 1:
        raise TestFailure(
            "could not bump http_api_rate_read in cfg.tbl - missing default key?"
        )
    # Also bump the per-IP TCP-connection-rate BURST (NOT the
    # parallel-conn cap _max_conns, which `test_perip_connection_cap`
    # asserts is exactly 16). The Phase 1c bad-prefix flood (15
    # quick HTTP conns) followed by cmd_disconnect's 4-5 ADC logins
    # plus cmd_redirect's 5 more burns through the production-default
    # burst of 30 on Linux CI (faster than Windows MinGW); the next
    # connection from 127.0.0.1 then RSTs in `accept_ip`. Bumping
    # the burst gives headroom for the sequential HTTP test
    # battery without weakening any of the ADC-side limiter tests.
    # The key is NOT in examples/cfg/cfg.tbl by default (only in
    # cfg_defaults.lua at 30), so use a regex that matches the key
    # if present, otherwise append it.
    if re.search(r"ratelimit_perip_conn_burst\s*=", new_text):
        new_text = re.sub(
            r"ratelimit_perip_conn_burst\s*=\s*\d+",
            "ratelimit_perip_conn_burst = 200",
            new_text,
            count=1,
        )
    else:
        # Inject before the closing brace of the cfg.tbl table. The
        # file's last non-blank line is the `}` that terminates the
        # outer table; insert just above it.
        new_text = re.sub(
            r"^\}\s*$",
            "    ratelimit_perip_conn_burst = 200,  -- smoke override (#82 Phase 2)\n}",
            new_text,
            count=1,
            flags=re.MULTILINE,
        )
    cfg_path.write_text(new_text, encoding="utf-8")

    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    # Wait until the ADC port is bound to ensure the hub finished
    # the boot sequence (incl. the bootstrap_first_token write).
    # Without this, the test below might race the hub's startup.
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, 5.0)
    return proc, log_file


def test_http_no_tokens_means_no_listener(staging_dir: Path, proc=None):
    """#231 regression test: `http_port` set + `http_api_tokens` empty
    must NOT bind the HTTP listener. Sample token must be written to
    `cfg/api_token.first` instead, so the operator has a value to
    copy into cfg.tbl.

    Runs against the hub started by `_switch_to_http_no_tokens_mode`
    immediately above. Verifies:
    - cfg/api_token.first exists and has a non-comment token line.
    - TCP connect to TEST_PORT_HTTP is refused (listener never bound).
    - ADC ports are still up (no collateral damage).
    """
    sample_path = staging_dir / "cfg" / "api_token.first"
    token = _read_first_token_from_file(sample_path)
    # Token format sanity: base32 (A-Z2-7), ~52 chars from 32 bytes.
    if len(token) < 40:
        raise TestFailure(
            f"sample token at {sample_path} is suspiciously short ({len(token)} chars): {token!r}"
        )

    # TCP connect to the HTTP test port must NOT succeed. The hub did
    # NOT bind the listener because cfg.tbl http_api_tokens is empty.
    # Accepted "not listening" signals across platforms:
    #   - ConnectionRefusedError (Linux + Windows WSAECONNREFUSED=10061):
    #     OS responded with TCP RST. Fast.
    #   - socket.timeout / TimeoutError: OS dropped / filtered the SYN.
    #     Slower but still proves nothing is accepting.
    # The only failure mode we care about is a SUCCESSFUL connect (which
    # would mean the listener bound despite the empty token table).
    try:
        with socket.create_connection((HUB_HOST, TEST_PORT_HTTP), timeout=2.0) as s:
            s.close()
        raise TestFailure(
            f"HTTP listener bound on port {TEST_PORT_HTTP} despite empty "
            f"http_api_tokens; #231 regression"
        )
    except (ConnectionRefusedError, socket.timeout, TimeoutError):
        # All three are the expected outcome - no listener accepting.
        pass
    except OSError as e:
        # Some other OSError - investigate. WinError 10061 on Windows
        # is ConnectionRefused-equivalent and already caught above; any
        # other code is surprising.
        if hasattr(e, "winerror") and e.winerror == 10061:
            pass
        else:
            raise TestFailure(
                f"HTTP connect to {TEST_PORT_HTTP} failed with unexpected error: "
                f"{type(e).__name__}: {e}"
            )

    # ADC handshake still works (no collateral damage). Reuse the
    # plain-handshake assertion.
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as s:
        s.sendall(b"HSUP ADBASE\n")
        data = b""
        s.settimeout(PROTOCOL_TIMEOUT_SEC)
        try:
            data = s.recv(1024)
        except socket.timeout:
            pass
    if b"ISUP" not in data:
        raise TestFailure(
            f"ADC handshake degraded by HTTP no-listener path; got: {data!r}"
        )


def _switch_to_http_mode(staging_dir: Path, current_proc, current_log_file):
    """#231 setup step 2: after `_switch_to_http_no_tokens_mode`
    proved that empty http_api_tokens means no listener, copy the
    sample token from `cfg/api_token.first` into cfg.tbl
    http_api_tokens (the documented activation step) and restart
    the hub. Returns (proc, log_file) for the running hub with the
    HTTP listener now bound.

    The pre-#231 design auto-activated a bootstrap token in-memory;
    smoke tests just read `api_token.first` and used it directly.
    Now cfg.tbl is the single source of truth, so smoke must
    perform the operator's copy step explicitly before the listener
    will bind."""
    stop_hub(current_proc, current_log_file)

    sample_path = staging_dir / "cfg" / "api_token.first"
    token = _read_first_token_from_file(sample_path)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    # Rewrite `http_api_tokens = { }` to embed the sample token
    # with admin scope. The trailing comma on the cfg.tbl line is
    # preserved by the replacement.
    new_tokens_value = (
        '{ ["' + token + '"] = { scope = "admin", comment = "smoke-bootstrap" } }'
    )
    new_text, n = re.subn(
        r"http_api_tokens\s*=\s*\{\s*\}",
        f"http_api_tokens = {new_tokens_value}",
        text,
        count=1,
    )
    if n != 1:
        raise TestFailure(
            "could not inject sample token into cfg.tbl http_api_tokens (regex did not match)"
        )
    cfg_path.write_text(new_text, encoding="utf-8")

    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    # Wait for ADC port first (proves hub booted), then HTTP port
    # (proves the listener actually bound on this run, i.e. the
    # token injection worked).
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, 5.0)
    wait_for_port(HUB_HOST, TEST_PORT_HTTP, 5.0)
    return proc, log_file


def _http_roundtrip(raw_request: bytes) -> str:
    """Open a fresh connection to the HTTP listener, send a raw
    request, read until the server closes (the hub always answers
    Connection: close - one request per connection), return the
    decoded response."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_HTTP), timeout=PROTOCOL_TIMEOUT_SEC
    ) as s:
        s.sendall(raw_request)
        chunks = []
        s.settimeout(PROTOCOL_TIMEOUT_SEC)
        while True:
            try:
                c = s.recv(4096)
            except socket.timeout:
                break
            if not c:
                break
            chunks.append(c)
    return b"".join(chunks).decode("latin-1", errors="replace")


def test_http_health_roundtrip(staging_dir: Path, proc=None):
    """Phase 1b of #82: the hardened HTTP framer + router answer
    correctly and the security posture holds.

    - GET /health -> 200, body "ok" (plain text, no auth, special-case)
    - HEAD /health -> 200, empty body
    - NO Server header (no version fingerprint pre-auth)
    - unknown path WITHOUT auth -> 401 (auth-first; do not leak
      endpoint existence to anonymous callers)
    - DELETE /health WITHOUT auth -> 401 (same; /health is GET/HEAD-
      only as a special case, anything else falls into normal routing)
    - malformed request-line -> 400 (framer-level, pre-auth)
    - bad HTTP version -> 505 (framer-level)
    - Transfer-Encoding (smuggling vector) -> 400 (framer-level)
    - the ADC listener still handshakes (per-listener pipeline
      selection did not regress the ADC path)
    """
    wait_for_port(HUB_HOST, TEST_PORT_HTTP, START_TIMEOUT_SEC)

    def status(resp):
        return resp.split("\r\n", 1)[0]

    # 1. happy path
    r = _http_roundtrip(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /health: expected 200, got {status(r)!r}")
    if "\r\n\r\nok" not in r:
        raise TestFailure(f"GET /health: body 'ok' missing; resp={r!r}")
    if "Connection: close" not in r:
        raise TestFailure("GET /health: missing Connection: close")
    if "server:" in r.lower():
        raise TestFailure(f"Server header leaked (fingerprint): {r!r}")

    # 2. HEAD: same status, empty body
    r = _http_roundtrip(b"HEAD /health HTTP/1.1\r\n\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(f"HEAD /health: expected 200, got {status(r)!r}")
    if r.split("\r\n\r\n", 1)[1] != "":
        raise TestFailure(f"HEAD /health: body must be empty; resp={r!r}")

    # 3..7 hard-status table
    for label, req, want in [
        # Phase 1b: unknown path without auth -> 401, NOT 404. The
        # router enforces auth before route lookup so anonymous
        # callers cannot enumerate endpoints.
        ("unknown path no auth", b"GET /nope HTTP/1.1\r\n\r\n", "401"),
        # /health is registered (GET, scope="none") but DELETE on
        # it without auth -> 401 (don't leak path existence to
        # anonymous callers; admin API posture). An authenticated
        # client gets 405 + Allow header instead.
        ("bad method on /health no auth", b"DELETE /health HTTP/1.1\r\n\r\n", "401"),
        # framer-level rejections still fire before the router
        ("malformed reqline", b"GET/health HTTP/1.1\r\n\r\n", "400"),
        ("bad version", b"GET /health HTTP/2.0\r\n\r\n", "505"),
        ("TE smuggling", b"GET /health HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", "400"),
    ]:
        r = _http_roundtrip(req)
        if want not in status(r):
            raise TestFailure(
                f"HTTP {label}: expected {want}, got {status(r)!r}"
            )

    # 8. /v1/endpoints: requires auth; without it -> 401.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"GET /v1/endpoints no-auth: expected 401, got {status(r)!r}"
        )
    if "application/json" not in r.lower():
        raise TestFailure(
            f"401 must use JSON envelope (Content-Type); got {r!r}"
        )
    if '"E_UNAUTHENTICATED"' not in r:
        raise TestFailure(f"401: expected E_UNAUTHENTICATED in body; got {r!r}")

    # 9. /v1/endpoints with the bootstrap token -> 200 + envelope
    #    listing at least /health and /v1/endpoints.
    token_path = staging_dir / "cfg" / "api_token.first"
    if not token_path.exists():
        raise TestFailure(
            f"bootstrap file missing at {token_path}; the hub should "
            f"have generated it on first boot with http_port set"
        )
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")

    req_with_auth = (
        b"GET /v1/endpoints HTTP/1.1\r\n"
        b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"
        b"\r\n"
    )
    r = _http_roundtrip(req_with_auth)
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/endpoints with bootstrap token: expected 200, "
            f"got {status(r)!r}; resp={r!r}"
        )
    body = r.split("\r\n\r\n", 1)[1]
    if '"ok":true' not in body.replace(" ", ""):
        raise TestFailure(f"envelope missing ok:true; body={body!r}")
    # The catalog lists ALL registered routes including /health
    # (scope="none", anonymous-accessible) and itself
    # (scope="read", self-describing).
    if '"/v1/endpoints"' not in body:
        raise TestFailure(
            f"endpoint catalog missing /v1/endpoints (self-listing); body={body!r}"
        )
    if '"/health"' not in body:
        raise TestFailure(
            f"endpoint catalog missing /health (scope=none route); body={body!r}"
        )

    # 10. /v1/endpoints with a BOGUS token -> 401.
    bad_req = (
        b"GET /v1/endpoints HTTP/1.1\r\n"
        b"Authorization: Bearer not-a-real-token\r\n"
        b"\r\n"
    )
    r = _http_roundtrip(bad_req)
    if "401" not in status(r):
        raise TestFailure(
            f"GET /v1/endpoints with bad token: expected 401, got {status(r)!r}"
        )

    # 11. OPTIONS introspection per §6.6 - 204 + Allow header, no
    # auth required. /health is GET-only so OPTIONS yields the
    # auto-added HEAD + OPTIONS.
    r = _http_roundtrip(b"OPTIONS /health HTTP/1.1\r\n\r\n")
    if "204" not in status(r):
        raise TestFailure(
            f"OPTIONS /health: expected 204, got {status(r)!r}"
        )
    if "Allow:" not in r:
        raise TestFailure(f"OPTIONS /health: missing Allow header; resp={r!r}")
    # The Allow header MUST list GET (registered) + HEAD (auto-
    # added for GET routes) + OPTIONS (self).
    for must_have in ("GET", "HEAD", "OPTIONS"):
        if must_have not in r:
            raise TestFailure(
                f"OPTIONS /health: Allow must list {must_have}; resp={r!r}"
            )

    # 12. OPTIONS on an unknown path with auth -> 404 (anonymous
    # would get 401 first, but introspection does not bypass auth
    # for paths that simply do not exist).
    r = _http_roundtrip(
        b"OPTIONS /v1/nope HTTP/1.1\r\n"
        b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"
        b"\r\n"
    )
    if "404" not in status(r):
        raise TestFailure(
            f"OPTIONS /v1/nope authed: expected 404, got {status(r)!r}"
        )

    # 13. Authenticated method-mismatch on /health -> 405 + Allow.
    r = _http_roundtrip(
        b"DELETE /health HTTP/1.1\r\n"
        b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"
        b"\r\n"
    )
    if "405" not in status(r):
        raise TestFailure(
            f"DELETE /health authed: expected 405, got {status(r)!r}"
        )
    if "Allow:" not in r or "GET" not in r:
        raise TestFailure(f"DELETE /health authed: missing Allow: GET; resp={r!r}")

    # SECURITY: the HTTP listener MUST be loopback-only (no TLS / no
    # auth is only acceptable because it is 127.0.0.1-bound). Prove it
    # is NOT reachable on this host's non-loopback address. Skipped
    # only if the environment has no usable non-loopback IPv4 (some
    # locked-down CI net namespaces) - never failed spuriously.
    nonloop = None
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 80))  # no packets sent; just resolves the local addr
            cand = probe.getsockname()[0]
        finally:
            probe.close()
        if cand and not cand.startswith("127.") and cand != "0.0.0.0":
            nonloop = cand
    except OSError:
        nonloop = None
    if nonloop:
        try:
            c = socket.create_connection((nonloop, TEST_PORT_HTTP), timeout=2)
            c.close()
            raise TestFailure(
                f"SECURITY: HTTP listener reachable on non-loopback "
                f"{nonloop}:{TEST_PORT_HTTP} - it must bind 127.0.0.1 "
                f"only (regression of B1: addr vs ip)."
            )
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass  # expected: refused/unreachable off-loopback
    else:
        log("  (skip non-loopback bind check: no non-loopback IPv4)")

    # ADC path still works alongside the HTTP listener
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as s:
        s.sendall(b"HSUP ADBASE ADTIGR\n")
        reader = _ADCReader(s)
        reader.recv_until(lambda f: f.startswith("ISUP "))


def test_http_phase1c_endpoints(staging_dir: Path, proc=None):
    """Phase 1c of #82: the 4 core read endpoints answer; rate-limit
    + per-prefix failed-auth + idempotency wiring is alive on the
    dispatch path.

    Smoke-scope (full semantics live in tests/unit/http_router_test.lua):
    - GET /v1/version with bootstrap token -> 200 + envelope with name
    - GET /v1/stats                        -> 200 + envelope w/ online_count
    - GET /v1/users?limit=50               -> 200 + envelope w/ pagination block
    - GET /v1/users/AAAA                   -> 404 (no such SID online)
    - GET /v1/log/api?lines=5              -> 200 + envelope w/ lines array
    - /v1/endpoints catalog now lists all five (plus /health + self)
    - Hammer with wrong-prefix bearer -> 429 from prefix bucket after burst
    - Hammer /v1/version with right token -> 429 from per-token bucket
      eventually (read budget = 120/min, burst = 10 by default)
    """
    # Re-discover the bootstrap token; the hub re-generated it on this
    # boot (every fresh staging run overwrites api_token.first).
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # 1. /v1/version
    r = _http_roundtrip(b"GET /v1/version HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/version: expected 200, got {status(r)!r}")
    b = body_of(r)
    if '"ok":true' not in b.replace(" ", ""):
        raise TestFailure(f"GET /v1/version: envelope ok:true missing; body={b!r}")
    if '"name"' not in b or "Luadch" not in b:
        raise TestFailure(f"GET /v1/version: missing name/Luadch in body={b!r}")
    if '"uptime_seconds"' not in b:
        raise TestFailure(f"GET /v1/version: missing uptime_seconds; body={b!r}")

    # 2. /v1/stats
    r = _http_roundtrip(b"GET /v1/stats HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/stats: expected 200, got {status(r)!r}")
    b = body_of(r)
    if '"online_count"' not in b:
        raise TestFailure(f"GET /v1/stats: missing online_count; body={b!r}")
    if '"share_total_bytes"' not in b:
        raise TestFailure(f"GET /v1/stats: missing share_total_bytes; body={b!r}")
    if '"by_level"' not in b:
        raise TestFailure(f"GET /v1/stats: missing by_level; body={b!r}")

    # 3. /v1/users with explicit pagination
    r = _http_roundtrip(b"GET /v1/users?limit=50&offset=0 HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/users: expected 200, got {status(r)!r}")
    b = body_of(r)
    if '"pagination"' not in b:
        raise TestFailure(f"GET /v1/users: missing pagination block; body={b!r}")
    for need in ('"users"', '"total"', '"limit"', '"offset"'):
        if need not in b:
            raise TestFailure(f"GET /v1/users: missing {need}; body={b!r}")

    # 4. /v1/users/{sid} for a SID that cannot be online (AAAA is the
    #    spec-reserved sentinel value the SID-assigner skips).
    r = _http_roundtrip(b"GET /v1/users/AAAA HTTP/1.1\r\n" + auth + b"\r\n")
    if "404" not in status(r):
        raise TestFailure(
            f"GET /v1/users/AAAA: expected 404, got {status(r)!r}"
        )
    b = body_of(r)
    if '"E_NOT_FOUND"' not in b:
        raise TestFailure(f"GET /v1/users/AAAA: missing E_NOT_FOUND code; body={b!r}")

    # 5. /v1/log/api (admin scope; bootstrap token is admin)
    r = _http_roundtrip(b"GET /v1/log/api?lines=5 HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/log/api: expected 200, got {status(r)!r}")
    b = body_of(r)
    if '"lines"' not in b:
        raise TestFailure(f"GET /v1/log/api: missing lines array; body={b!r}")

    # 6. /v1/endpoints catalog now lists all Phase 1c endpoints.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/endpoints: expected 200, got {status(r)!r}")
    b = body_of(r)
    for path_must_have in (
        '"/v1/version"', '"/v1/stats"', '"/v1/users"',
        '"/v1/users/{sid}"', '"/v1/log/api"',
    ):
        if path_must_have not in b:
            raise TestFailure(
                f"catalog missing {path_must_have}; body={b!r}"
            )

    # 7. Per-prefix failed-auth bucket (§4.8). Burst is 5 by default;
    #    six wrong-token-same-prefix requests should reach the 429
    #    rate-limit response. Use a Bearer with a distinct 4-char
    #    prefix so this test does not exhaust other tests' budget if
    #    re-ordered.
    bad_prefix = b"PRFX-bogus-token-value-xx"
    bad_auth = b"Authorization: Bearer " + bad_prefix + b"\r\n"
    saw_429 = False
    for i in range(15):
        r = _http_roundtrip(b"GET /v1/version HTTP/1.1\r\n" + bad_auth + b"\r\n")
        st = status(r)
        if "429" in st:
            saw_429 = True
            # Retry-After header MUST be present per §4.8
            if "Retry-After:" not in r:
                raise TestFailure(
                    f"per-prefix 429: missing Retry-After; resp={r!r}"
                )
            break
        if "401" not in st:
            raise TestFailure(
                f"per-prefix flood: expected 401 then 429, got {st!r}"
            )
    if not saw_429:
        raise TestFailure(
            "per-prefix failed-auth bucket never tripped after 15 attempts"
        )

    # The right-prefix-bucket SHOULD be unrelated. The valid bootstrap
    # token has its own prefix; a single subsequent request must still
    # succeed (proves the bucket is keyed by prefix not by source IP).
    r = _http_roundtrip(b"GET /v1/version HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"valid token after wrong-prefix flood: expected 200, "
            f"got {status(r)!r}; resp={r!r}"
        )


def test_http_phase2_cmd_disconnect(staging_dir: Path, proc=None):
    """Phase 2 PR-1 of #82: cmd_disconnect plugin migrates to HTTP.

    The plugin keeps the existing +disconnect ADC chat-cmd unchanged
    AND additionally registers DELETE /v1/users/{sid}. Both call into
    a shared do_disconnect helper. This test exercises the HTTP path
    only - the ADC +disconnect cmd is covered by its own test history.

    Coverage:
    - Login a real ADC user (dummy/test), capture SID.
    - DELETE /v1/users/{sid} with admin token + reason body -> 200 +
      envelope { ok:true, data:{ action:"disconnect", sid, nick, reason } }
      (Phase-2 normalised shape per #200 / HTTP_API.md §7.1.1).
    - ADC connection drops shortly after (the kick is asynchronous to
      the HTTP response but happens within the request handler tick).
    - Subsequent DELETE on the same SID -> 404 E_NOT_FOUND.
    - DELETE on a never-online SID (AAAA sentinel) -> 404.
    - Idempotency: a second DELETE with the SAME X-Idempotency-Key
      within TTL replays the cached 200 (handler not re-invoked,
      audit log not re-emitted - the cache is the audit-deduplication
      mechanism).
    - /v1/endpoints catalog now lists DELETE /v1/users/{sid}.
    """
    # Re-discover the admin token from the bootstrap file (fresh each run).
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # 1. Log in an ADC user, grab their SID, kick via DELETE.
    with _logged_in_user() as (adc, sid, _reader):
        if len(sid) != 4:
            raise TestFailure(f"unexpected SID length: {sid!r}")

        # 2. DELETE /v1/users/{sid} with reason body.
        body = b'{"reason":"smoke test kick"}'
        req = (
            b"DELETE /v1/users/" + sid.encode("ascii") + b" HTTP/1.1\r\n"
            + auth +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )
        r = _http_roundtrip(req)
        if "200 OK" not in status(r):
            raise TestFailure(f"DELETE /v1/users/{sid}: expected 200, got {status(r)!r}; resp={r!r}")
        b = body_of(r)
        # Phase-2 envelope normalisation (#200): write-endpoint
        # responses carry `action:"<verb>"` instead of a per-
        # endpoint verb-boolean (pre-#200 was {disconnected:true,...}).
        if '"action":"disconnect"' not in b.replace(" ", ""):
            raise TestFailure(f"DELETE /v1/users/{{sid}}: expected action:disconnect; body={b!r}")
        # The nick may be auto-prefixed by the level tag (e.g.
        # "[HUBOWNER]dummy"); substring-match is enough.
        if '"nick":"' not in b or "dummy" not in b:
            raise TestFailure(f"DELETE /v1/users/{{sid}}: expected nick containing 'dummy'; body={b!r}")
        if '"reason":"smoketestkick"' not in b.replace(" ", ""):
            raise TestFailure(f"DELETE /v1/users/{{sid}}: reason missing or wrong; body={b!r}")

        # 3. ADC connection drops. The hub sends ISTA 230 then closes.
        _assert_adc_drops(adc)

    # 4. Subsequent DELETE on the same SID -> 404 (user offline now).
    req2 = (
        b"DELETE /v1/users/" + sid.encode("ascii") + b" HTTP/1.1\r\n"
        + auth +
        b"\r\n"
    )
    r = _http_roundtrip(req2)
    if "404" not in status(r):
        raise TestFailure(
            f"second DELETE /v1/users/{sid} (user offline): expected 404, got {status(r)!r}"
        )
    if '"E_NOT_FOUND"' not in body_of(r):
        raise TestFailure(f"second DELETE: expected E_NOT_FOUND; resp={r!r}")

    # 5. DELETE on a never-online SID -> 404 (sanity).
    r = _http_roundtrip(b"DELETE /v1/users/AAAA HTTP/1.1\r\n" + auth + b"\r\n")
    if "404" not in status(r):
        raise TestFailure(f"DELETE /v1/users/AAAA: expected 404, got {status(r)!r}")

    # 6. Idempotency: log in a fresh user, kick once with idem-key,
    # second DELETE with SAME key replays the cached 200 (not 404)
    # even though the user is offline now.
    with _logged_in_user() as (adc2, sid2, _reader):
        idem_key = b"smoke-idem-" + sid2.encode("ascii")
        body = b'{"reason":"idem cached"}'
        req3 = (
            b"DELETE /v1/users/" + sid2.encode("ascii") + b" HTTP/1.1\r\n"
            + auth +
            b"Content-Type: application/json\r\n"
            b"X-Idempotency-Key: " + idem_key + b"\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )
        r = _http_roundtrip(req3)
        if "200 OK" not in status(r):
            raise TestFailure(f"idem DELETE first call: expected 200, got {status(r)!r}")
        first_body = body_of(r)

        # Wait for the ADC drop so the second call is unambiguously
        # a cache replay (not a coincidental race).
        _assert_adc_drops(adc2)

        # Second call with SAME idem key: user is offline now. Without
        # the cache this would be 404. With the cache it MUST replay
        # the original 200.
        r = _http_roundtrip(req3)
        if "200 OK" not in status(r):
            raise TestFailure(
                f"idem DELETE replay: expected cached 200, got {status(r)!r}; "
                f"the idempotency cache did not replay"
            )
        if body_of(r) != first_body:
            raise TestFailure(
                "idem DELETE replay body differs from first call - cache stored wrong payload"
            )

    # 7. /v1/endpoints catalog includes DELETE /v1/users/{sid}
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"DELETE"' not in b or '"/v1/users/{sid}"' not in b:
        raise TestFailure(
            f"catalog missing DELETE /v1/users/{{sid}} after Phase 2 PR-1; body={b!r}"
        )

    # 8. Schema validation: reason > 256 chars -> 400 E_BAD_INPUT.
    #    Confirms the request_schema declared on the route is
    #    actually wired into dispatch. User must STILL be online -
    #    the validation failed before the handler ran.
    with _logged_in_user() as (adc3, sid3, _reader):
        long_reason = "x" * 300
        bigbody = ('{"reason":"' + long_reason + '"}').encode("ascii")
        req4 = (
            b"DELETE /v1/users/" + sid3.encode("ascii") + b" HTTP/1.1\r\n"
            + auth +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(bigbody)).encode("ascii") + b"\r\n"
            b"\r\n" + bigbody
        )
        r = _http_roundtrip(req4)
        if "400" not in status(r):
            raise TestFailure(
                f"reason >256 chars: expected 400, got {status(r)!r}"
            )
        if '"E_BAD_INPUT"' not in body_of(r):
            raise TestFailure(
                f"reason >256 chars: expected E_BAD_INPUT code; body={body_of(r)!r}"
            )
        _assert_adc_alive(adc3)


def test_http_phase2_cmd_redirect(staging_dir: Path, proc=None):
    """Phase 2 PR-2 of #82: cmd_redirect plugin migrates to HTTP.

    Coexist with the +redirect ADC chat-cmd via a shared do_redirect
    helper, same pattern as PR-1. The HTTP body carries an optional
    `url` field; missing/empty falls back to cfg `cmd_redirect_url`.

    Coverage:
    - POST /v1/users/{sid}/redirect with explicit URL -> 200 +
      { action:"redirect", sid, nick, url } envelope. ADC drops.
      (Phase-2 normalised shape per #200 / HTTP_API.md §7.1.1.)
    - POST without url -> 200 (falls back to cfg default).
    - POST on offline SID -> 404 E_NOT_FOUND.
    - POST without auth -> 401.
    - URL > 1024 chars -> 400 E_BAD_INPUT.
    - /v1/endpoints catalog lists POST /v1/users/{sid}/redirect.
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # 1. Login + redirect with explicit url.
    with _logged_in_user() as (adc, sid, _reader):
        body = b'{"url":"adc://newhub.example:5000"}'
        req = (
            b"POST /v1/users/" + sid.encode("ascii") + b"/redirect HTTP/1.1\r\n"
            + auth +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )
        r = _http_roundtrip(req)
        if "200 OK" not in status(r):
            raise TestFailure(
                f"POST /v1/users/{sid}/redirect: expected 200, got {status(r)!r}; resp={r!r}"
            )
        b = body_of(r)
        # Phase-2 envelope normalisation (#200): see cmd_disconnect
        # smoke for context.
        if '"action":"redirect"' not in b.replace(" ", ""):
            raise TestFailure(f"redirect: expected action:redirect; body={b!r}")
        if '"url":"adc://newhub.example:5000"' not in b.replace(" ", ""):
            raise TestFailure(f"redirect: url not echoed; body={b!r}")
        # ADC should drop (IQUI RD + kill).
        _assert_adc_drops(adc)

    # 2. Login + redirect WITHOUT url body -> falls back to cfg
    #    default. The cfg default in examples/cfg/cfg.tbl is non-
    #    empty so this MUST succeed (200) rather than 400.
    with _logged_in_user() as (_adc2, sid2, _reader):
        req2 = (
            b"POST /v1/users/" + sid2.encode("ascii") + b"/redirect HTTP/1.1\r\n"
            + auth +
            b"Content-Length: 0\r\n"
            b"\r\n"
        )
        r = _http_roundtrip(req2)
        if "200 OK" not in status(r):
            raise TestFailure(
                f"POST .../redirect (no body, cfg default): expected 200, got {status(r)!r}; resp={r!r}"
            )

    # 3. POST on offline SID -> 404.
    body3 = b'{"url":"adc://x:1"}'
    req3 = (
        b"POST /v1/users/AAAA/redirect HTTP/1.1\r\n"
        + auth +
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body3)).encode("ascii") + b"\r\n"
        b"\r\n" + body3
    )
    r = _http_roundtrip(req3)
    if "404" not in status(r):
        raise TestFailure(f"POST .../AAAA/redirect: expected 404, got {status(r)!r}; resp={r!r}")

    # 4. No auth -> 401.
    r = _http_roundtrip(
        b"POST /v1/users/AAAA/redirect HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
    )
    if "401" not in status(r):
        raise TestFailure(f"POST .../redirect no-auth: expected 401, got {status(r)!r}")

    # 5. Overlong url -> 400 (schema reject; user must NOT be kicked).
    with _logged_in_user() as (adc3, sid3, _reader):
        long_url = "adc://" + ("x" * 1100) + ":5000"
        bigbody = ('{"url":"' + long_url + '"}').encode("ascii")
        req5 = (
            b"POST /v1/users/" + sid3.encode("ascii") + b"/redirect HTTP/1.1\r\n"
            + auth +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(bigbody)).encode("ascii") + b"\r\n"
            b"\r\n" + bigbody
        )
        r = _http_roundtrip(req5)
        if "400" not in status(r):
            raise TestFailure(
                f"overlong url: expected 400, got {status(r)!r}"
            )
        if '"E_BAD_INPUT"' not in body_of(r):
            raise TestFailure(f"overlong url: expected E_BAD_INPUT; body={body_of(r)!r}")
        _assert_adc_alive(adc3)

    # 6. Catalog now lists POST /v1/users/{sid}/redirect.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"POST"' not in b or '"/v1/users/{sid}/redirect"' not in b:
        raise TestFailure(
            f"catalog missing POST /v1/users/{{sid}}/redirect; body={b!r}"
        )

    # 7. Non-ADC URL scheme -> 400 (schema pattern reject). Defence-
    #    in-depth against an admin token redirecting users to a
    #    non-hub URL (javascript:, http://evil/, file:///).
    with _logged_in_user() as (adc4, sid4, _reader):
        badbody = b'{"url":"http://evil.example/"}'
        req7 = (
            b"POST /v1/users/" + sid4.encode("ascii") + b"/redirect HTTP/1.1\r\n"
            + auth +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(badbody)).encode("ascii") + b"\r\n"
            b"\r\n" + badbody
        )
        r = _http_roundtrip(req7)
        if "400" not in status(r):
            raise TestFailure(
                f"non-ADC scheme: expected 400 (pattern reject), got {status(r)!r}"
            )
        _assert_adc_alive(adc4)

    # 8. Idempotency replay: send the same POST twice with the same
    #    X-Idempotency-Key. First call kicks. Second call MUST replay
    #    the cached 200 even though the user is offline now (would
    #    otherwise be 404).
    with _logged_in_user() as (adc5, sid5, _reader):
        idem_key = b"redirect-idem-" + sid5.encode("ascii")
        body8 = b'{"url":"adc://idem.test:5000"}'
        req8 = (
            b"POST /v1/users/" + sid5.encode("ascii") + b"/redirect HTTP/1.1\r\n"
            + auth +
            b"Content-Type: application/json\r\n"
            b"X-Idempotency-Key: " + idem_key + b"\r\n"
            b"Content-Length: " + str(len(body8)).encode("ascii") + b"\r\n"
            b"\r\n" + body8
        )
        r = _http_roundtrip(req8)
        if "200 OK" not in status(r):
            raise TestFailure(
                f"idem POST first call: expected 200, got {status(r)!r}"
            )
        first_body = body_of(r)
        # Wait for ADC drop so the second call cannot coincidentally
        # see the user still online.
        _assert_adc_drops(adc5)
        # Second call with same idem-key: user offline, but cache MUST
        # replay the original 200.
        r = _http_roundtrip(req8)
        if "200 OK" not in status(r):
            raise TestFailure(
                f"idem POST replay: expected cached 200, got {status(r)!r}; "
                f"the idempotency cache did not replay"
            )
        if body_of(r) != first_body:
            raise TestFailure(
                "idem POST replay body differs from first call - cache stored wrong payload"
            )


def test_http_phase2_cmd_gag(staging_dir: Path, proc=None):
    """Phase 2 PR-3 of #82: cmd_gag plugin migrates to HTTP.

    First Phase-2 plugin with persistent state (gag list survives
    +reload via scripts/data/cmd_gag.tbl). Two endpoints:

    - POST /v1/users/{sid}/gag (body { mode, duration_minutes? })
    - DELETE /v1/users/{sid}/gag

    Same coexist pattern as PR-1 / PR-2: ADC `+gag` cmd unchanged,
    HTTP endpoints registered via util_http.http_register_user_action.
    The ADC user is NOT kicked (gag suppresses outbound chat, not the
    session) so the smoke uses _assert_adc_alive between phases.

    Coverage:
    - POST mute with no duration -> 200 + envelope w/ action:"gag",
      mode:"mute", no expires_at; user stays online (gag does not kick).
    - POST again on same user -> 409 E_CONFLICT.
    - POST invalid mode -> 400 (schema enum reject).
    - DELETE -> 200 + envelope w/ action:"ungag", previous_mode.
    - DELETE again -> 404 E_NOT_FOUND.
    - POST kennylize with duration_minutes=30 -> 200 + expires_at
      field set, ISO 8601 format.
    - POST shadowmute on fresh user -> 200.
    - Catalog lists POST + DELETE /v1/users/{sid}/gag.
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def post_gag(sid: str, body: bytes) -> str:
        req = (
            b"POST /v1/users/" + sid.encode("ascii") + b"/gag HTTP/1.1\r\n"
            + auth +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )
        return _http_roundtrip(req)

    def delete_gag(sid: str) -> str:
        req = (
            b"DELETE /v1/users/" + sid.encode("ascii") + b"/gag HTTP/1.1\r\n"
            + auth +
            b"\r\n"
        )
        return _http_roundtrip(req)

    # 1. POST mute (no duration) + 200 + user stays alive + DELETE flow.
    with _logged_in_user() as (adc, sid, _reader):
        # 1a. Fresh POST -> 200 + correct envelope.
        r = post_gag(sid, b'{"mode":"mute"}')
        if "200 OK" not in status(r):
            raise TestFailure(f"POST .../gag mute: expected 200, got {status(r)!r}; resp={r!r}")
        b = body_of(r)
        if '"action":"gag"' not in b.replace(" ", ""):
            raise TestFailure(f"gag: expected action:gag; body={b!r}")
        if '"mode":"mute"' not in b.replace(" ", ""):
            raise TestFailure(f"gag: expected mode:mute; body={b!r}")
        if '"expires_at"' in b:
            raise TestFailure(f"gag (no duration): expires_at must be absent; body={b!r}")

        # 1b. Gag does NOT kick - user must still be online.
        _assert_adc_alive(adc)

        # 1c. Re-POST -> 409 Conflict (already gagged).
        r = post_gag(sid, b'{"mode":"mute"}')
        if "409" not in status(r):
            raise TestFailure(f"re-POST .../gag: expected 409, got {status(r)!r}")
        if '"E_CONFLICT"' not in body_of(r):
            raise TestFailure(f"re-POST .../gag: expected E_CONFLICT; resp={r!r}")

        # 1d. Invalid mode -> 400 (schema enum reject).
        r = post_gag(sid, b'{"mode":"flaschenpost"}')
        if "400" not in status(r):
            raise TestFailure(f"invalid mode: expected 400, got {status(r)!r}")
        if '"E_BAD_INPUT"' not in body_of(r):
            raise TestFailure(f"invalid mode: expected E_BAD_INPUT; resp={r!r}")

        # 1e. DELETE -> 200 with previous_mode.
        r = delete_gag(sid)
        if "200 OK" not in status(r):
            raise TestFailure(f"DELETE .../gag: expected 200, got {status(r)!r}; resp={r!r}")
        b = body_of(r)
        if '"action":"ungag"' not in b.replace(" ", ""):
            raise TestFailure(f"ungag: expected action:ungag; body={b!r}")
        if '"previous_mode":"mute"' not in b.replace(" ", ""):
            raise TestFailure(f"ungag: expected previous_mode:mute; body={b!r}")

        # 1f. DELETE again -> 404.
        r = delete_gag(sid)
        if "404" not in status(r):
            raise TestFailure(f"re-DELETE .../gag: expected 404, got {status(r)!r}")
        if '"E_NOT_FOUND"' not in body_of(r):
            raise TestFailure(f"re-DELETE .../gag: expected E_NOT_FOUND; resp={r!r}")

        # 1g. Sanity: user still alive after the whole flow.
        _assert_adc_alive(adc)

    # 2. POST kennylize with duration_minutes=30 -> envelope carries
    #    duration_minutes + expires_at (ISO 8601). Verify the
    #    timestamp format roughly (YYYY-MM-DDTHH:MM:SSZ).
    with _logged_in_user() as (adc2, sid2, _reader):
        r = post_gag(sid2, b'{"mode":"kennylize","duration_minutes":30}')
        if "200 OK" not in status(r):
            raise TestFailure(f"POST .../gag kennylize+30min: expected 200, got {status(r)!r}; resp={r!r}")
        b = body_of(r)
        if '"duration_minutes":30' not in b.replace(" ", ""):
            raise TestFailure(f"gag w/ duration: expected duration_minutes:30; body={b!r}")
        m = re.search(r'"expires_at":"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"', b)
        if not m:
            raise TestFailure(f"gag w/ duration: expires_at not in ISO 8601 form; body={b!r}")
        _assert_adc_alive(adc2)
        # Cleanup (otherwise the gag persists in cmd_gag.tbl across
        # later harness invocations on the same staging dir).
        r = delete_gag(sid2)
        if "200 OK" not in status(r):
            raise TestFailure(f"cleanup DELETE: expected 200, got {status(r)!r}")

    # 3. POST shadowmute on fresh user -> 200 + clean up.
    with _logged_in_user() as (adc3, sid3, _reader):
        r = post_gag(sid3, b'{"mode":"shadowmute"}')
        if "200 OK" not in status(r):
            raise TestFailure(f"POST .../gag shadowmute: expected 200, got {status(r)!r}")
        if '"mode":"shadowmute"' not in body_of(r).replace(" ", ""):
            raise TestFailure(f"shadowmute: mode missing in envelope; resp={r!r}")
        _assert_adc_alive(adc3)
        r = delete_gag(sid3)
        if "200 OK" not in status(r):
            raise TestFailure(f"cleanup shadowmute DELETE: expected 200, got {status(r)!r}")

    # 4. Catalog now lists POST + DELETE /v1/users/{sid}/gag.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/users/{sid}/gag"' not in b:
        raise TestFailure(f"catalog missing /v1/users/{{sid}}/gag; body={b!r}")
    # Catalog includes both POST and DELETE entries on the same path.
    if b.count('"/v1/users/{sid}/gag"') < 2:
        raise TestFailure(f"catalog should list BOTH POST and DELETE /v1/users/{{sid}}/gag; body={b!r}")

    # 5. Persistence: POST creates a gag entry, and the on-disk
    #    scripts/data/cmd_gag.tbl must contain the user's firstnick.
    #    A subsequent DELETE removes it. This verifies the disk-
    #    write side of persistence; the re-load path
    #    (util.loadtable(gag_path) at plugin onStart) is unchanged
    #    from pre-PR-3 and shared with every other persist-on-disk
    #    plugin in the codebase, so a full restart cycle here would
    #    only cover surface already covered by Phase-7 user.tbl
    #    persistence tests. A dedicated hub-restart-and-survive
    #    test is a worthwhile Phase-2 polish item but deferred to
    #    keep PR-3 small.
    gag_tbl_path = staging_dir / "scripts" / "data" / "cmd_gag.tbl"
    with _logged_in_user() as (adc, sid, _reader):
        r = post_gag(sid, b'{"mode":"mute"}')
        if "200 OK" not in status(r):
            raise TestFailure(f"persistence POST: expected 200, got {status(r)!r}")
        if not gag_tbl_path.exists():
            raise TestFailure(f"persistence: cmd_gag.tbl not written at {gag_tbl_path}")
        # The serialised entry must include the user's firstnick.
        # dummy may be auto-prefixed by level (e.g. "[HUBOWNER]dummy"),
        # but the firstnick is the registered nick which IS plain "dummy".
        contents = gag_tbl_path.read_text(encoding="utf-8")
        if 'user_nick = "dummy"' not in contents:
            raise TestFailure(
                f"persistence: cmd_gag.tbl after POST missing user_nick "
                f"entry; contents={contents!r}"
            )
        # Clean up + verify the disk-write of removal too.
        r = delete_gag(sid)
        if "200 OK" not in status(r):
            raise TestFailure(f"persistence cleanup DELETE: expected 200, got {status(r)!r}")
        contents = gag_tbl_path.read_text(encoding="utf-8")
        if 'user_nick = "dummy"' in contents:
            raise TestFailure(
                f"persistence: cmd_gag.tbl after DELETE still has entry; "
                f"contents={contents!r}"
            )


def test_http_phase2_cmd_ban(staging_dir: Path, proc=None):
    """Phase 2 PR-4 of #82: cmd_ban plugin migrates to HTTP.

    Last bundled-plugin migration of Phase 2. Largest plugin (779 LoC)
    with the most complex target shape: bans key by nick / cid / ip
    (and a transient `sid` resolve-then-store-by-nick path), not a
    single {sid}. Hence raw `hub.http_register` registrations rather
    than the util_http SID helper.

    Four endpoints:
    - GET    /v1/bans                 (= +ban show)
    - GET    /v1/bans/history[?nick=] (= +ban showhis)
    - POST   /v1/bans                 (= +ban ...)
    - DELETE /v1/bans/{id}            (= +unban; index from GET /v1/bans)

    Coverage:
    - POST sid + duration + reason -> 200 envelope w/ action:"ban",
      target_nick, expires_at, id. ADC user dropped (ISTA 232 + TL).
    - GET /v1/bans lists the entry with the same id + remaining_seconds.
    - GET /v1/bans/history?nick=dummy returns the history entry.
    - POST cid blind-add (target not online) -> 200 (no offline lookup).
    - POST nick unknown (not online, not registered) -> 404.
    - POST invalid target_type -> 400 (schema enum reject).
    - DELETE /v1/bans/{id} -> 200 envelope w/ action:"unban", removed.
    - DELETE /v1/bans/99 -> 404 E_NOT_FOUND.
    - DELETE /v1/bans/foo -> 400 E_BAD_INPUT (not an integer).
    - Persistence: scripts/data/cmd_ban_bans.tbl + cmd_ban_history.tbl
      reflect POST + DELETE.
    - /v1/endpoints catalog lists all four routes.
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def post_ban(body: bytes) -> str:
        req = (
            b"POST /v1/bans HTTP/1.1\r\n"
            + auth +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )
        return _http_roundtrip(req)

    def delete_ban(id_str: str) -> str:
        req = (
            b"DELETE /v1/bans/" + id_str.encode("ascii") + b" HTTP/1.1\r\n"
            + auth +
            b"\r\n"
        )
        return _http_roundtrip(req)

    def get_bans() -> str:
        return _http_roundtrip(b"GET /v1/bans HTTP/1.1\r\n" + auth + b"\r\n")

    def get_history(nick: str = "") -> str:
        path = b"/v1/bans/history"
        if nick:
            path += b"?nick=" + nick.encode("ascii")
        return _http_roundtrip(b"GET " + path + b" HTTP/1.1\r\n" + auth + b"\r\n")

    # Pre-flight: ban list empty on a fresh staging dir.
    r = get_bans()
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/bans pre-flight: expected 200, got {status(r)!r}")
    if '"bans":[]' not in body_of(r).replace(" ", ""):
        raise TestFailure(
            f"GET /v1/bans pre-flight: expected empty list, got {body_of(r)!r}"
        )

    bans_tbl = staging_dir / "scripts" / "data" / "cmd_ban_bans.tbl"
    history_tbl = staging_dir / "scripts" / "data" / "cmd_ban_history.tbl"

    # 1. POST sid + duration + reason. The ADC user should be dropped.
    with _logged_in_user() as (adc, sid, _reader):
        body = (
            b'{"target_type":"sid","target":"' + sid.encode("ascii")
            + b'","duration_minutes":60,"reason":"smoke ban test"}'
        )
        r = post_ban(body)
        if "200 OK" not in status(r):
            raise TestFailure(f"POST /v1/bans (sid): expected 200, got {status(r)!r}; resp={r!r}")
        b = body_of(r)
        # Strengthening over the PR-1/2/3 string-contains pattern: also
        # assert the success-envelope `"ok":true` is present, so a 200
        # status with a malformed body (e.g. an error envelope leaked
        # via a router bug) is caught instead of false-passing on the
        # action substring alone.
        if '"ok":true' not in b.replace(" ", ""):
            raise TestFailure(f"POST /v1/bans: success envelope missing 'ok:true'; body={b!r}")
        if '"action":"ban"' not in b.replace(" ", ""):
            raise TestFailure(f"POST /v1/bans: action missing; body={b!r}")
        if '"id":1' not in b.replace(" ", ""):
            raise TestFailure(f"POST /v1/bans: expected id:1; body={b!r}")
        if '"duration_minutes":60' not in b.replace(" ", ""):
            raise TestFailure(f"POST /v1/bans: duration mismatch; body={b!r}")
        if '"reason":"smokebantest"' not in b.replace(" ", ""):
            raise TestFailure(f"POST /v1/bans: reason missing/wrong; body={b!r}")
        m = re.search(r'"expires_at":"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"', b)
        if not m:
            raise TestFailure(f"POST /v1/bans: expires_at not ISO 8601; body={b!r}")
        # target_nick should be the registered firstnick ("dummy").
        if '"target_nick":"dummy"' not in b.replace(" ", ""):
            raise TestFailure(f"POST /v1/bans: target_nick should be 'dummy'; body={b!r}")

        # ADC drops (ISTA 232 + TL3600). The kick happens within the
        # same hub tick as the HTTP handler return.
        _assert_adc_drops(adc)

    # 2. GET /v1/bans now lists the entry at id=1.
    r = get_bans()
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/bans after add: expected 200, got {status(r)!r}")
    b = body_of(r)
    if '"id":1' not in b.replace(" ", ""):
        raise TestFailure(f"GET /v1/bans: id=1 missing; body={b!r}")
    if '"nick":"dummy"' not in b.replace(" ", ""):
        raise TestFailure(f"GET /v1/bans: nick=dummy missing; body={b!r}")
    if '"remaining_seconds":' not in b.replace(" ", ""):
        raise TestFailure(f"GET /v1/bans: remaining_seconds missing; body={b!r}")

    # 3. GET /v1/bans/history?nick=dummy lists the history entry.
    r = get_history("dummy")
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/bans/history?nick=dummy: expected 200, got {status(r)!r}")
    b = body_of(r)
    if '"dummy"' not in b:
        raise TestFailure(f"GET history: dummy not in body; body={b!r}")
    if '"state":"active"' not in b.replace(" ", ""):
        raise TestFailure(f"GET history: expected state:active; body={b!r}")

    # 3b. Unfiltered history returns the same nick.
    r = get_history()
    if '"dummy"' not in body_of(r):
        raise TestFailure(f"GET history (no filter): missing dummy; body={body_of(r)!r}")

    # 4. Persistence: bans.tbl + history.tbl on disk reflect the POST.
    if not bans_tbl.exists():
        raise TestFailure(f"persistence: {bans_tbl} not written")
    if not history_tbl.exists():
        raise TestFailure(f"persistence: {history_tbl} not written")
    contents_bans = bans_tbl.read_text(encoding="utf-8")
    if 'nick = "dummy"' not in contents_bans:
        raise TestFailure(
            f"persistence: cmd_ban_bans.tbl missing dummy entry; contents={contents_bans!r}"
        )

    # 5. DELETE /v1/bans/1 -> 200 + envelope w/ action:"unban", removed.
    r = delete_ban("1")
    if "200 OK" not in status(r):
        raise TestFailure(f"DELETE /v1/bans/1: expected 200, got {status(r)!r}; resp={r!r}")
    b = body_of(r)
    if '"ok":true' not in b.replace(" ", ""):
        raise TestFailure(f"DELETE /v1/bans/1: success envelope missing 'ok:true'; body={b!r}")
    if '"action":"unban"' not in b.replace(" ", ""):
        raise TestFailure(f"DELETE /v1/bans/1: action missing; body={b!r}")
    if '"removed":' not in b.replace(" ", ""):
        raise TestFailure(f"DELETE /v1/bans/1: removed snapshot missing; body={b!r}")
    if '"nick":"dummy"' not in b.replace(" ", ""):
        raise TestFailure(f"DELETE /v1/bans/1: removed.nick=dummy missing; body={b!r}")

    # 5b. Persistence: bans.tbl no longer contains dummy after the DELETE.
    contents_bans = bans_tbl.read_text(encoding="utf-8")
    if 'nick = "dummy"' in contents_bans:
        raise TestFailure(
            f"persistence: cmd_ban_bans.tbl still has dummy after DELETE; contents={contents_bans!r}"
        )

    # 6. DELETE /v1/bans/1 again -> 404 (no entry at index).
    r = delete_ban("1")
    if "404" not in status(r):
        raise TestFailure(f"DELETE /v1/bans/1 (empty list): expected 404, got {status(r)!r}")
    if '"E_NOT_FOUND"' not in body_of(r):
        raise TestFailure(f"DELETE second: expected E_NOT_FOUND; resp={r!r}")

    # 7. DELETE /v1/bans/foo -> 400 (not an integer).
    r = delete_ban("foo")
    if "400" not in status(r):
        raise TestFailure(f"DELETE /v1/bans/foo: expected 400, got {status(r)!r}")
    if '"E_BAD_INPUT"' not in body_of(r):
        raise TestFailure(f"DELETE foo: expected E_BAD_INPUT; resp={r!r}")

    # 8. POST cid blind-add. cid lookup hits no online user; cmd_ban
    #    writes the ban entry anyway (matches ADC behaviour). Use a
    #    plausible 39-char base32 CID-looking string; the hub does not
    #    validate the format on input.
    cid_blind = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    body = (
        b'{"target_type":"cid","target":"' + cid_blind.encode("ascii")
        + b'","duration_minutes":5,"reason":"blind add"}'
    )
    r = post_ban(body)
    if "200 OK" not in status(r):
        raise TestFailure(f"POST /v1/bans (cid blind): expected 200, got {status(r)!r}; resp={r!r}")
    b = body_of(r)
    # target_nick should be absent (no online resolve), but the entry
    # still lands at id=1 since the bans list was empty after step 5.
    if '"id":1' not in b.replace(" ", ""):
        raise TestFailure(f"POST cid blind: expected id:1; body={b!r}")
    if '"target_nick"' in b:
        raise TestFailure(f"POST cid blind: target_nick should be absent; body={b!r}")

    # Cleanup blind-add so subsequent tests start clean.
    r = delete_ban("1")
    if "200 OK" not in status(r):
        raise TestFailure(f"cleanup DELETE cid blind: expected 200, got {status(r)!r}")

    # 9. POST nick unknown -> 404 (not online, not registered).
    body = b'{"target_type":"nick","target":"nobody-known-nick","duration_minutes":5}'
    r = post_ban(body)
    if "404" not in status(r):
        raise TestFailure(f"POST nick unknown: expected 404, got {status(r)!r}")
    if '"E_NOT_FOUND"' not in body_of(r):
        raise TestFailure(f"POST nick unknown: expected E_NOT_FOUND; resp={r!r}")

    # 10. POST invalid target_type -> 400 (schema enum reject).
    body = b'{"target_type":"frob","target":"x","duration_minutes":5}'
    r = post_ban(body)
    if "400" not in status(r):
        raise TestFailure(f"POST invalid target_type: expected 400, got {status(r)!r}")
    if '"E_BAD_INPUT"' not in body_of(r):
        raise TestFailure(f"POST invalid type: expected E_BAD_INPUT; resp={r!r}")

    # 11. POST reason > 256 chars -> 400 (schema max_length reject).
    long_reason = "x" * 300
    body = (
        b'{"target_type":"ip","target":"10.0.0.1","duration_minutes":5,"reason":"'
        + long_reason.encode("ascii") + b'"}'
    )
    r = post_ban(body)
    if "400" not in status(r):
        raise TestFailure(f"POST reason >256: expected 400, got {status(r)!r}")

    # 12. /v1/endpoints catalog lists all four cmd_ban routes.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    for needed in ('"/v1/bans"', '"/v1/bans/history"', '"/v1/bans/{id}"'):
        if needed not in b:
            raise TestFailure(f"catalog missing {needed!r}; body={b!r}")


def test_http_phase3_cmd_restart(staging_dir: Path, proc=None):
    """Phase 3 PR-1 of #82 / #225: cmd_restart plugin migrates to HTTP.

    Coexist pattern (same as Phase 2): the existing ADC +restart cmd
    is unchanged, the new POST /v1/restart endpoint is added in
    onStart. Both call the shared `do_restart()` helper.

    This test covers ONLY the rejection paths. The success path
    (X-Confirm: yes + valid body) is deliberately NOT exercised,
    because firing the restart would arm the exit timer and tear
    down the smoke hub before subsequent tests
    (test_inf_integer_clamps, BLOM / ZLIF / etc.) can run. The
    success-path code is exercised in production every time an
    operator types +restart.

    Coverage:
    - POST /v1/restart without X-Confirm header -> 400
      E_CONFIRMATION_REQUIRED (router-side gate per §4.6).
    - POST /v1/restart with X-Confirm: no -> 400 (router rejects
      anything that is not the literal "yes").
    - POST /v1/restart with oversized `message` field
      (>1024 chars) -> 400 E_BAD_INPUT (request_schema validator).
      X-Confirm IS set on this case to prove the schema check
      runs even after the X-Confirm gate clears.
    - /v1/endpoints catalog now lists POST /v1/restart.

    The hub MUST stay alive after every assertion: `in_progress`
    is only set when do_restart actually runs, which never happens
    on the reject paths.
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # 1. Missing X-Confirm -> 400 E_CONFIRMATION_REQUIRED.
    req = (
        b"POST /v1/restart HTTP/1.1\r\n"
        + auth +
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    r = _http_roundtrip(req)
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/restart without X-Confirm: expected 400, got {status(r)!r}"
        )
    if '"E_CONFIRMATION_REQUIRED"' not in body_of(r):
        raise TestFailure(
            f"POST /v1/restart without X-Confirm: expected "
            f"E_CONFIRMATION_REQUIRED; body={body_of(r)!r}"
        )

    # 2. X-Confirm with non-"yes" value -> still 400.
    req = (
        b"POST /v1/restart HTTP/1.1\r\n"
        + auth +
        b"X-Confirm: no\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    r = _http_roundtrip(req)
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/restart with X-Confirm: no: expected 400, got {status(r)!r}"
        )

    # 3. Oversized `message` field with X-Confirm: yes -> 400 E_BAD_INPUT.
    # Confirms the request_schema is wired (max_length=1024).
    long_msg = "x" * 1100
    body = ('{"message":"' + long_msg + '"}').encode("ascii")
    req = (
        b"POST /v1/restart HTTP/1.1\r\n"
        + auth +
        b"X-Confirm: yes\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"\r\n" + body
    )
    r = _http_roundtrip(req)
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/restart oversized message: expected 400, got {status(r)!r}"
        )
    if '"E_BAD_INPUT"' not in body_of(r):
        raise TestFailure(
            f"POST /v1/restart oversized message: expected E_BAD_INPUT; "
            f"body={body_of(r)!r}"
        )

    # 4. /v1/endpoints catalog lists POST /v1/restart.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/restart"' not in b:
        raise TestFailure(f"catalog missing /v1/restart; body={b!r}")


def test_http_phase3_cmd_shutdown(staging_dir: Path, proc=None):
    """Phase 3 PR-2 of #82 / #225: cmd_shutdown plugin migrates to HTTP.

    Mirror of test_http_phase3_cmd_restart. Same rejection-only
    coverage rationale: firing the shutdown would tear down the
    smoke hub before downstream tests can run, so the success path
    is exercised in production every time an operator types
    `+shutdown`.

    Coverage:
    - POST /v1/shutdown without X-Confirm header -> 400
      E_CONFIRMATION_REQUIRED (router-side gate per §4.6).
    - POST /v1/shutdown with X-Confirm: no -> 400.
    - POST /v1/shutdown with oversized `message` field
      (>1024 chars) + X-Confirm: yes -> 400 E_BAD_INPUT
      (request_schema validator).
    - /v1/endpoints catalog now lists POST /v1/shutdown.
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # 1. Missing X-Confirm -> 400 E_CONFIRMATION_REQUIRED.
    req = (
        b"POST /v1/shutdown HTTP/1.1\r\n"
        + auth +
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    r = _http_roundtrip(req)
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/shutdown without X-Confirm: expected 400, got {status(r)!r}"
        )
    if '"E_CONFIRMATION_REQUIRED"' not in body_of(r):
        raise TestFailure(
            f"POST /v1/shutdown without X-Confirm: expected "
            f"E_CONFIRMATION_REQUIRED; body={body_of(r)!r}"
        )

    # 2. X-Confirm with non-"yes" value -> still 400.
    req = (
        b"POST /v1/shutdown HTTP/1.1\r\n"
        + auth +
        b"X-Confirm: no\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    r = _http_roundtrip(req)
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/shutdown with X-Confirm: no: expected 400, got {status(r)!r}"
        )

    # 3. Oversized `message` field with X-Confirm: yes -> 400 E_BAD_INPUT.
    long_msg = "x" * 1100
    body = ('{"message":"' + long_msg + '"}').encode("ascii")
    req = (
        b"POST /v1/shutdown HTTP/1.1\r\n"
        + auth +
        b"X-Confirm: yes\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"\r\n" + body
    )
    r = _http_roundtrip(req)
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/shutdown oversized message: expected 400, got {status(r)!r}"
        )
    if '"E_BAD_INPUT"' not in body_of(r):
        raise TestFailure(
            f"POST /v1/shutdown oversized message: expected E_BAD_INPUT; "
            f"body={body_of(r)!r}"
        )

    # 4. /v1/endpoints catalog lists POST /v1/shutdown.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/shutdown"' not in b:
        raise TestFailure(f"catalog missing /v1/shutdown; body={b!r}")


def test_http_phase3_cmd_errors(staging_dir: Path, proc=None):
    """Phase 3 PR-3 of #82 / #225: cmd_errors plugin migrates to HTTP.

    Read-only endpoint, admin scope. Pattern-setter for log-tail
    endpoints (Phase 3 PR-4 etc_cmdlog mirrors).

    Coverage:
    - Pre-seed log/error.log with known lines.
    - GET /v1/log/error -> 200 + envelope { ok:true, data:{ lines:
      [<all_lines>], returned, total_lines } }.
    - GET /v1/log/error?lines=2 -> 200 + last 2 lines only,
      returned=2, total_lines=N.
    - GET /v1/log/error?lines=invalid -> 200, falls back to default
      (no rejection per §6.4 clamping rule).
    - GET /v1/log/error?lines=99999 -> 200, clamped to 1000.
    - Anonymous GET (no Authorization header) -> 401.
    - /v1/endpoints catalog lists GET /v1/log/error.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # Seed log/error.log with 5 distinct lines. The hub may also
    # write to this file independently; assertions below check
    # SHAPE not exact content beyond "our seeded lines are visible".
    log_path = staging_dir / "log" / "error.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    seed = [
        "smoke seed line 1",
        "smoke seed line 2",
        "smoke seed line 3",
        "smoke seed line 4",
        "smoke seed line 5",
    ]
    with log_path.open("a", encoding="utf-8") as f:
        for line in seed:
            f.write(line + "\n")

    # 1. Anonymous GET -> 401.
    r = _http_roundtrip(b"GET /v1/log/error HTTP/1.1\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous GET /v1/log/error: expected 401, got {status(r)!r}"
        )

    # 2. Authenticated GET default lines -> 200, lines array includes
    # all our seeded lines.
    r = _http_roundtrip(b"GET /v1/log/error HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/log/error: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(f"GET /v1/log/error: ok=false; body={body_of(r)!r}")
    data = parsed.get("data") or {}
    lines = data.get("lines") or []
    total = data.get("total_lines")
    returned = data.get("returned")
    if not isinstance(lines, list) or not isinstance(total, int) or not isinstance(returned, int):
        raise TestFailure(
            f"GET /v1/log/error: malformed data shape; body={body_of(r)!r}"
        )
    if returned != len(lines):
        raise TestFailure(
            f"GET /v1/log/error: returned ({returned}) != len(lines) ({len(lines)})"
        )
    for needle in seed:
        if needle not in lines:
            raise TestFailure(
                f"GET /v1/log/error: seeded line {needle!r} missing; "
                f"got {lines!r}"
            )

    # 3. ?lines=2 -> returned=2, last two lines.
    r = _http_roundtrip(b"GET /v1/log/error?lines=2 HTTP/1.1\r\n" + auth + b"\r\n")
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("returned") != 2 or len(data.get("lines") or []) != 2:
        raise TestFailure(
            f"GET /v1/log/error?lines=2: expected returned=2; body={body_of(r)!r}"
        )

    # 4. ?lines=invalid -> falls back to default, returns 200.
    r = _http_roundtrip(b"GET /v1/log/error?lines=notanumber HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/log/error?lines=invalid: expected 200, got {status(r)!r}"
        )

    # 5. ?lines=99999 -> clamped to 1000 internally; returned <= 1000.
    r = _http_roundtrip(b"GET /v1/log/error?lines=99999 HTTP/1.1\r\n" + auth + b"\r\n")
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    returned = data.get("returned")
    if returned is None or returned > 1000:
        raise TestFailure(
            f"GET /v1/log/error?lines=99999: returned={returned} not clamped; "
            f"body={body_of(r)!r}"
        )

    # 6. /v1/endpoints catalog lists GET /v1/log/error.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/log/error"' not in b:
        raise TestFailure(f"catalog missing /v1/log/error; body={b!r}")


def test_http_phase3_etc_cmdlog(staging_dir: Path, proc=None):
    """Phase 3 PR-4 of #82 / #225: etc_cmdlog plugin migrates to HTTP.

    Mirror of Phase 3 PR-3 (cmd_errors). Read-only endpoint, admin
    scope. Same shape: lines / returned / total_lines.

    Coverage:
    - Pre-seed log/cmd.log with known lines.
    - GET /v1/log/cmd -> 200, seeded lines visible.
    - GET /v1/log/cmd?lines=2 -> 200, returned=2.
    - Anonymous -> 401.
    - /v1/endpoints catalog lists GET /v1/log/cmd.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    log_path = staging_dir / "log" / "cmd.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    seed = [
        "cmdlog seed line A",
        "cmdlog seed line B",
        "cmdlog seed line C",
    ]
    with log_path.open("a", encoding="utf-8") as f:
        for line in seed:
            f.write(line + "\n")

    # 1. Anonymous -> 401.
    r = _http_roundtrip(b"GET /v1/log/cmd HTTP/1.1\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous GET /v1/log/cmd: expected 401, got {status(r)!r}"
        )

    # 2. Default lines -> 200, all seeded lines visible.
    r = _http_roundtrip(b"GET /v1/log/cmd HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/log/cmd: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    lines = data.get("lines") or []
    for needle in seed:
        if needle not in lines:
            raise TestFailure(
                f"GET /v1/log/cmd: seeded line {needle!r} missing; got {lines!r}"
            )
    if data.get("returned") != len(lines):
        raise TestFailure(
            f"GET /v1/log/cmd: returned != len(lines); body={body_of(r)!r}"
        )

    # 3. ?lines=2 -> exactly 2 returned (last two of file's tail).
    r = _http_roundtrip(b"GET /v1/log/cmd?lines=2 HTTP/1.1\r\n" + auth + b"\r\n")
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("returned") != 2 or len(data.get("lines") or []) != 2:
        raise TestFailure(
            f"GET /v1/log/cmd?lines=2: expected returned=2; body={body_of(r)!r}"
        )

    # 4. /v1/endpoints catalog lists GET /v1/log/cmd.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/log/cmd"' not in b:
        raise TestFailure(f"catalog missing /v1/log/cmd; body={b!r}")


def test_http_phase3_etc_log_cleaner(staging_dir: Path, proc=None):
    """Phase 3 PR-5 of #82 / #225: etc_log_cleaner plugin migrates
    to HTTP.

    Write endpoint (DELETE), admin scope. Truncates a known log
    file via the API and asserts the file shrinks to 0 bytes.

    Coverage:
    - Pre-seed log/error.log with known content.
    - DELETE /v1/log/error -> 200, action:"log-cleared",
      bytes_before > 0.
    - Verify file on disk is now 0 bytes.
    - DELETE /v1/log/unknown -> 400 E_BAD_INPUT.
    - DELETE /v1/log/error AGAIN -> 200, bytes_before=0 (already
      truncated, idempotent).
    - Anonymous DELETE -> 401.
    - /v1/endpoints catalog lists DELETE /v1/log/{name}.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    log_path = staging_dir / "log" / "error.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        f.write("log-cleaner-smoke marker line\n")
    size_before = log_path.stat().st_size
    if size_before == 0:
        raise TestFailure(f"failed to seed {log_path}: still 0 bytes")

    # 1. Anonymous -> 401.
    r = _http_roundtrip(b"DELETE /v1/log/error HTTP/1.1\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous DELETE /v1/log/error: expected 401, got {status(r)!r}"
        )

    # 2. DELETE /v1/log/error -> 200, action + bytes_before > 0.
    r = _http_roundtrip(b"DELETE /v1/log/error HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"DELETE /v1/log/error: expected 200, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(f"DELETE /v1/log/error: ok=false; body={body_of(r)!r}")
    data = parsed.get("data") or {}
    if data.get("action") != "log-cleared":
        raise TestFailure(
            f"DELETE /v1/log/error: expected action=log-cleared; "
            f"body={body_of(r)!r}"
        )
    if data.get("name") != "error":
        raise TestFailure(
            f"DELETE /v1/log/error: expected name=error; body={body_of(r)!r}"
        )
    if not isinstance(data.get("bytes_before"), int) or data["bytes_before"] <= 0:
        raise TestFailure(
            f"DELETE /v1/log/error: expected bytes_before > 0; "
            f"body={body_of(r)!r}"
        )

    # 3. File on disk is now 0 bytes.
    size_after = log_path.stat().st_size if log_path.exists() else 0
    if size_after != 0:
        raise TestFailure(
            f"DELETE /v1/log/error: file still has {size_after} bytes "
            f"after truncate (path={log_path})"
        )

    # 4. Unknown name -> 400 E_BAD_INPUT.
    r = _http_roundtrip(b"DELETE /v1/log/notalog HTTP/1.1\r\n" + auth + b"\r\n")
    if "400" not in status(r):
        raise TestFailure(
            f"DELETE /v1/log/notalog: expected 400, got {status(r)!r}"
        )
    if '"E_BAD_INPUT"' not in body_of(r):
        raise TestFailure(
            f"DELETE /v1/log/notalog: expected E_BAD_INPUT; "
            f"body={body_of(r)!r}"
        )

    # 5. Idempotent re-clean -> 200, bytes_before=0.
    r = _http_roundtrip(b"DELETE /v1/log/error HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"DELETE /v1/log/error (idempotent): expected 200, got {status(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("bytes_before") != 0:
        raise TestFailure(
            f"DELETE /v1/log/error (idempotent): expected bytes_before=0; "
            f"body={body_of(r)!r}"
        )

    # 6. /v1/endpoints catalog lists DELETE /v1/log/{name}.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/log/{name}"' not in b:
        raise TestFailure(f"catalog missing /v1/log/{{name}}; body={b!r}")


def test_http_phase4_etc_chatlog(staging_dir: Path, proc=None):
    """Phase 4 PR-1 of #82 / #249: etc_chatlog plugin migrates to HTTP.

    Read scope. Mirror of Phase 3 PR-3 (cmd_errors) for the
    tail-style shape, but read on the chat-history buffer instead
    of an on-disk log file.

    Coverage:
    - Anonymous GET (no Authorization header) -> 401.
    - Authenticated GET -> 200 with envelope { ok:true, data:{
      lines:[{timestamp, nick, message}, ...], returned, total_lines } }.
    - GET ?lines=2 -> returned <= 2 (the in-memory buffer may have
      fewer entries on a fresh hub; clamp upward, not exact).
    - GET ?lines=invalid -> 200, falls back to default per §6.4.
    - GET ?lines=99999 -> 200, clamped to min(cfg max_lines, 1000).
      On a fresh-staging hub cfg ships max_lines=200, so the
      effective bound is 200 AND `returned <= total_lines` (clamp-
      to-buffer-size invariant).
    - /v1/endpoints catalog lists GET /v1/chatlog.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # 1. Anonymous GET -> 401.
    r = _http_roundtrip(b"GET /v1/chatlog HTTP/1.1\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous GET /v1/chatlog: expected 401, got {status(r)!r}"
        )

    # 2. Authenticated GET -> 200 + valid envelope shape.
    r = _http_roundtrip(b"GET /v1/chatlog HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/chatlog: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(f"GET /v1/chatlog: ok=false; body={body_of(r)!r}")
    data = parsed.get("data") or {}
    lines = data.get("lines")
    total = data.get("total_lines")
    returned = data.get("returned")
    if not isinstance(lines, list) or not isinstance(total, int) or not isinstance(returned, int):
        raise TestFailure(
            f"GET /v1/chatlog: malformed data shape; body={body_of(r)!r}"
        )
    if returned != len(lines):
        raise TestFailure(
            f"GET /v1/chatlog: returned ({returned}) != len(lines) ({len(lines)})"
        )
    # Each entry (if any) must carry the structured shape.
    for entry in lines:
        if not isinstance(entry, dict):
            raise TestFailure(
                f"GET /v1/chatlog: entry not an object; got {entry!r}"
            )
        for key in ("timestamp", "nick", "message"):
            if key not in entry:
                raise TestFailure(
                    f"GET /v1/chatlog: entry missing {key!r}; got {entry!r}"
                )

    # 3. ?lines=2 -> returned <= 2 (buffer may have fewer entries).
    r = _http_roundtrip(b"GET /v1/chatlog?lines=2 HTTP/1.1\r\n" + auth + b"\r\n")
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    returned = data.get("returned")
    if returned is None or returned > 2:
        raise TestFailure(
            f"GET /v1/chatlog?lines=2: expected returned<=2; body={body_of(r)!r}"
        )

    # 4. ?lines=invalid -> falls back to default, returns 200.
    r = _http_roundtrip(b"GET /v1/chatlog?lines=notanumber HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/chatlog?lines=invalid: expected 200, got {status(r)!r}"
        )

    # 5. ?lines=99999 -> clamped to min(cfg etc_chatlog_max_lines,
    # HTTP_MAX_LINES=1000). The default cfg ships max_lines=200,
    # so on a fresh-staging hub `returned` must be <= 200 AND <=
    # data['total_lines'] (clamp-to-buffer-size invariant). The
    # weaker `<= 1000` assertion would pass trivially on a stock
    # cfg and not exercise the cap, so anchor against both bounds.
    r = _http_roundtrip(b"GET /v1/chatlog?lines=99999 HTTP/1.1\r\n" + auth + b"\r\n")
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    returned = data.get("returned")
    total = data.get("total_lines")
    if returned is None or returned > 200:
        raise TestFailure(
            f"GET /v1/chatlog?lines=99999: returned={returned} not clamped "
            f"to cfg max_lines=200; body={body_of(r)!r}"
        )
    if total is not None and returned > total:
        raise TestFailure(
            f"GET /v1/chatlog?lines=99999: returned={returned} > "
            f"total_lines={total}; body={body_of(r)!r}"
        )

    # 6. /v1/endpoints catalog lists GET /v1/chatlog.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/chatlog"' not in b:
        raise TestFailure(f"catalog missing /v1/chatlog; body={b!r}")


def test_http_announce(staging_dir: Path, proc=None):
    """#82 deferred Phase-2-spec item: cmd_mass plugin migrates to
    POST /v1/announce. Coexists with the three ADC chat-cmds
    (`+mass`, `+masshub`, `+masslvl`) - the structured body's
    `scope` field dispatches to the right helper.

    Coverage:
    - Anonymous POST -> 401.
    - POST {message, scope:"all"} -> 200 + envelope.
    - POST {message, scope:"hub"} -> 200 + envelope (no sender in
      banner, sender field still in response).
    - POST {message, scope:"level", level:N} where N is a valid
      level -> 200 + envelope with recipients field.
    - POST {message, scope:"level"} without level -> 400 E_BAD_INPUT.
    - POST {message, scope:"level", level:99999} (unknown) -> 400.
    - POST {message:"", scope:"all"} -> 400 (empty message).
    - POST {scope:"all"} missing message -> 400 (schema required).
    - POST {message, scope:"unknown"} -> 400 (schema enum reject).
    - /v1/endpoints catalog lists POST /v1/announce.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def post(body: bytes, with_auth: bool = True):
        h = auth if with_auth else b""
        return _http_roundtrip(
            b"POST /v1/announce HTTP/1.1\r\n" + h +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )

    # 1. Anonymous -> 401.
    r = post(b'{"message":"hi","scope":"all"}', with_auth=False)
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous POST /v1/announce: expected 401, got {status(r)!r}"
        )

    # 2. scope=all success.
    r = post(b'{"message":"Smoke announce all","scope":"all"}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"POST /v1/announce scope=all: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "announce" or data.get("scope") != "all":
        raise TestFailure(
            f"POST /v1/announce scope=all: envelope mismatch; body={body_of(r)!r}"
        )
    if data.get("message") != "Smoke announce all":
        raise TestFailure(
            f"POST /v1/announce scope=all: message echoed wrong; body={body_of(r)!r}"
        )

    # 3. scope=hub success (no sender in banner; sender still in
    # response data for audit).
    r = post(b'{"message":"Smoke announce hub","scope":"hub"}')
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("scope") != "hub":
        raise TestFailure(
            f"POST /v1/announce scope=hub: envelope mismatch; body={body_of(r)!r}"
        )

    # 4. scope=level with a valid level (10 is the default
    # registered level per the examples cfg).
    r = post(b'{"message":"Smoke level","scope":"level","level":10}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"POST /v1/announce scope=level: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("scope") != "level" or data.get("level") != 10:
        raise TestFailure(
            f"POST /v1/announce scope=level: envelope mismatch; body={body_of(r)!r}"
        )
    if not isinstance(data.get("recipients"), int):
        raise TestFailure(
            f"POST /v1/announce scope=level: expected integer recipients; body={body_of(r)!r}"
        )

    # 5. scope=level WITHOUT level -> 400.
    r = post(b'{"message":"x","scope":"level"}')
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/announce scope=level no level: expected 400, got {status(r)!r}"
        )
    if '"E_BAD_INPUT"' not in body_of(r):
        raise TestFailure(
            f"POST /v1/announce scope=level no level: expected E_BAD_INPUT; body={body_of(r)!r}"
        )

    # 6. scope=level with unknown level -> 400.
    r = post(b'{"message":"x","scope":"level","level":99999}')
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/announce scope=level unknown: expected 400, got {status(r)!r}"
        )

    # 7. Empty message -> 400.
    r = post(b'{"message":"","scope":"all"}')
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/announce empty message: expected 400, got {status(r)!r}"
        )

    # 8. Missing message (schema required) -> 400.
    r = post(b'{"scope":"all"}')
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/announce missing message: expected 400, got {status(r)!r}"
        )

    # 9. Unknown scope (schema enum reject) -> 400.
    r = post(b'{"message":"x","scope":"world"}')
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/announce unknown scope: expected 400, got {status(r)!r}"
        )

    # 10. /v1/endpoints catalog lists POST /v1/announce.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/announce"' not in b:
        raise TestFailure(f"catalog missing /v1/announce; body={b!r}")


def test_http_topic(staging_dir: Path, proc=None):
    """#82 deferred Phase-2-spec item: cmd_topic plugin migrates to
    POST /v1/topic. Coexists with the ADC `+topic` chat-cmd.

    Coverage:
    - Anonymous POST -> 401.
    - POST {topic: "Smoke set"} -> 200 + action:topic-set + topic +
      previous.
    - POST {topic: ""} -> 200 + action:topic-reset + topic=default
      (the previous set above is "previous").
    - POST {} -> 200 + action:topic-reset (missing field = reset).
    - POST {topic: "default"} -> action:topic-set (literal value, NOT
      magic-keyword reset - HTTP path documented to differ from ADC).
    - Schema: {topic: 12345} (non-string) -> 400 E_BAD_INPUT.
    - /v1/endpoints catalog lists POST /v1/topic.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def post(body: bytes, with_auth: bool = True):
        h = auth if with_auth else b""
        return _http_roundtrip(
            b"POST /v1/topic HTTP/1.1\r\n" + h +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )

    # 1. Anonymous -> 401.
    r = post(b"{}", with_auth=False)
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous POST /v1/topic: expected 401, got {status(r)!r}"
        )

    # 2. Set topic to a known value.
    r = post(b'{"topic":"Smoke set"}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"POST /v1/topic set: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "topic-set" or data.get("topic") != "Smoke set":
        raise TestFailure(
            f"POST /v1/topic set: unexpected envelope; body={body_of(r)!r}"
        )

    # 3. Reset via empty topic field.
    r = post(b'{"topic":""}')
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "topic-reset":
        raise TestFailure(
            f"POST /v1/topic reset (empty): expected action=topic-reset; "
            f"body={body_of(r)!r}"
        )
    if data.get("previous") != "Smoke set":
        raise TestFailure(
            f"POST /v1/topic reset: expected previous='Smoke set' (the "
            f"value set in step 2); body={body_of(r)!r}"
        )

    # 4. Reset via missing topic field (empty body).
    r = post(b'{}')
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "topic-reset":
        raise TestFailure(
            f"POST /v1/topic reset (missing field): expected "
            f"action=topic-reset; body={body_of(r)!r}"
        )

    # 5. Literal "default" sets the topic to the WORD "default" on
    # the HTTP path (NOT magic-keyword reset). Documented difference
    # from the ADC `+topic default` cmd.
    r = post(b'{"topic":"default"}')
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "topic-set" or data.get("topic") != "default":
        raise TestFailure(
            f"POST /v1/topic literal default: expected action=topic-set "
            f"+ topic='default' (HTTP path differs from ADC magic-keyword); "
            f"body={body_of(r)!r}"
        )

    # 6. Schema reject: non-string topic.
    r = post(b'{"topic":12345}')
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/topic with non-string: expected 400, got {status(r)!r}"
        )
    if '"E_BAD_INPUT"' not in body_of(r):
        raise TestFailure(
            f"POST /v1/topic non-string: expected E_BAD_INPUT; body={body_of(r)!r}"
        )

    # 7. /v1/endpoints catalog lists POST /v1/topic.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/topic"' not in b:
        raise TestFailure(f"catalog missing /v1/topic; body={b!r}")


def test_http_registered_users_pr1(staging_dir: Path, proc=None):
    """#82 registered-users family PR-1 (#236): cmd_reg plugin migrates
    GET /v1/registered (paginated, read), POST /v1/registered (admin),
    PATCH /v1/registered/{nick} (admin). Coexists with the ADC `+reg`
    chat-cmd.

    Coverage:
    - Anonymous GET -> 401.
    - GET /v1/registered -> 200 + envelope.data.registered[] +
      pagination sibling per §6.4.
    - GET ?limit=1 -> respects limit clamp.
    - POST missing nick -> 400 E_BAD_INPUT.
    - POST with valid body (no password) -> 200 + action:register +
      password echoed back, comment empty by default.
    - POST same nick again -> 409 E_CONFLICT (nick already regged).
    - POST with caller-supplied password -> 200 + password matches.
    - PATCH /v1/registered/{nick} {comment: "smoke"} -> 200 + action:
      patch-registered + comment="smoke".
    - PATCH with empty body -> 400 (no patchable fields).
    - PATCH unknown nick -> 404 E_NOT_FOUND.
    - GET shows the patched comment in the entry.
    - /v1/endpoints catalog lists all three routes.

    Placement note: runs BEFORE test_http_reload so the test's persisted
    users are still in-memory + on-disk when the reload tests fire. The
    reload test asserts route-table survival, not data survival.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def req(method: bytes, path: bytes, body: bytes = b"", with_auth: bool = True):
        h = auth if with_auth else b""
        if body:
            return _http_roundtrip(
                method + b" " + path + b" HTTP/1.1\r\n" + h +
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                b"\r\n" + body
            )
        return _http_roundtrip(
            method + b" " + path + b" HTTP/1.1\r\n" + h + b"\r\n"
        )

    # 1. Anonymous GET -> 401.
    r = req(b"GET", b"/v1/registered", with_auth=False)
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous GET /v1/registered: expected 401, got {status(r)!r}"
        )

    # 2. GET list -> 200 with envelope + pagination.
    r = req(b"GET", b"/v1/registered")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/registered: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(f"GET /v1/registered: ok!=true; body={body_of(r)!r}")
    if "registered" not in (parsed.get("data") or {}):
        raise TestFailure(
            f"GET /v1/registered: data.registered missing; body={body_of(r)!r}"
        )
    pag = parsed.get("pagination") or {}
    for key in ("total", "limit", "offset"):
        if key not in pag:
            raise TestFailure(
                f"GET /v1/registered: pagination missing {key!r}; body={body_of(r)!r}"
            )

    # 3. limit=1 respected.
    r = req(b"GET", b"/v1/registered?limit=1")
    parsed = _json.loads(body_of(r))
    page = parsed.get("data", {}).get("registered", [])
    if len(page) > 1:
        raise TestFailure(
            f"GET /v1/registered?limit=1: expected <=1 entries, got {len(page)}"
        )
    if parsed.get("pagination", {}).get("limit") != 1:
        raise TestFailure(
            f"GET /v1/registered?limit=1: pagination.limit != 1; body={body_of(r)!r}"
        )

    # 4. POST missing nick -> 400.
    r = req(b"POST", b"/v1/registered", b'{"level":20}')
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/registered missing nick: expected 400, got {status(r)!r}"
        )
    if '"E_BAD_INPUT"' not in body_of(r):
        raise TestFailure(
            f"POST /v1/registered missing nick: expected E_BAD_INPUT; body={body_of(r)!r}"
        )

    # 5. POST create -> 200 + password echoed back.
    r = req(b"POST", b"/v1/registered",
            b'{"nick":"smoke_pr1_a","level":20}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"POST /v1/registered create: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "register" or data.get("nick") != "smoke_pr1_a":
        raise TestFailure(
            f"POST /v1/registered create: unexpected envelope; body={body_of(r)!r}"
        )
    if not data.get("password"):
        raise TestFailure(
            f"POST /v1/registered create: expected non-empty password; body={body_of(r)!r}"
        )

    # 6. POST same nick again -> 409.
    r = req(b"POST", b"/v1/registered",
            b'{"nick":"smoke_pr1_a","level":20}')
    if "409" not in status(r):
        raise TestFailure(
            f"POST /v1/registered duplicate: expected 409, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 7. POST with caller-supplied password.
    r = req(b"POST", b"/v1/registered",
            b'{"nick":"smoke_pr1_b","level":20,"password":"supplied_pw_xyz"}')
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("password") != "supplied_pw_xyz":
        raise TestFailure(
            f"POST /v1/registered with password: expected echo back; body={body_of(r)!r}"
        )

    # 8. PATCH comment -> 200.
    r = req(b"PATCH", b"/v1/registered/smoke_pr1_a",
            b'{"comment":"smoke test note"}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PATCH /v1/registered/smoke_pr1_a: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "patch-registered" or data.get("comment") != "smoke test note":
        raise TestFailure(
            f"PATCH /v1/registered/smoke_pr1_a: unexpected envelope; body={body_of(r)!r}"
        )

    # 9. PATCH empty body -> 400 (no patchable fields).
    r = req(b"PATCH", b"/v1/registered/smoke_pr1_a", b'{}')
    if "400" not in status(r):
        raise TestFailure(
            f"PATCH empty body: expected 400, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 10. PATCH unknown nick -> 404.
    r = req(b"PATCH", b"/v1/registered/nonexistent_smoke_user",
            b'{"comment":"x"}')
    if "404" not in status(r):
        raise TestFailure(
            f"PATCH unknown nick: expected 404, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 11. GET shows the patched comment in the entry.
    r = req(b"GET", b"/v1/registered?limit=1000")
    parsed = _json.loads(body_of(r))
    page = parsed.get("data", {}).get("registered", [])
    found = None
    for entry in page:
        if entry.get("nick") == "smoke_pr1_a":
            found = entry
            break
    if not found:
        raise TestFailure(
            f"GET /v1/registered: smoke_pr1_a missing from list; body={body_of(r)!r}"
        )
    if found.get("comment") != "smoke test note":
        raise TestFailure(
            f"GET /v1/registered: smoke_pr1_a comment mismatch; got {found!r}"
        )
    if found.get("level") != 20:
        raise TestFailure(
            f"GET /v1/registered: smoke_pr1_a level != 20; got {found!r}"
        )
    if "password" in found:
        raise TestFailure(
            f"GET /v1/registered: password leaked in list view; got {found!r}"
        )

    # 12. Empty-string comment clears the description entirely:
    # a follow-up GET must show comment="" for that nick (no
    # stale empty-reason record left behind).
    r = req(b"PATCH", b"/v1/registered/smoke_pr1_a", b'{"comment":""}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PATCH empty comment (clear): expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    r = req(b"GET", b"/v1/registered?limit=1000")
    parsed = _json.loads(body_of(r))
    for entry in parsed.get("data", {}).get("registered", []):
        if entry.get("nick") == "smoke_pr1_a":
            if entry.get("comment") != "":
                raise TestFailure(
                    f"GET after PATCH-empty: expected comment=''; got {entry!r}"
                )
            break

    # 13. PATCH on a bot nick -> 404 (bots are excluded from
    # /v1/registered surface; PATCH must mirror GET).
    r = req(b"PATCH", b"/v1/registered/luadch-NG",
            b'{"comment":"should not stick"}')
    # The bot's actual nick depends on cfg `hub_bot_nick`; the
    # smoke staging uses "luadch-NG" (see cfg_defaults). If the
    # name happens to differ we get 404 anyway via the
    # not-registered branch - either way the contract holds:
    # PATCH on the bot's nick must NOT return 200.
    if "200" in status(r):
        raise TestFailure(
            f"PATCH on hubbot nick must not return 200; got {status(r)!r}"
        )

    # 14. /v1/endpoints catalog lists all three routes - precise
    # match on the PATCH /v1/registered/{nick} combination, not
    # just the path string + method letters in isolation.
    r = req(b"GET", b"/v1/endpoints")
    cat = body_of(r)
    for needle in (
        '"/v1/registered"',
        '"/v1/registered/{nick}"',
        '"register a new user',
        '"update free-form fields',
    ):
        if needle not in cat:
            raise TestFailure(f"catalog missing {needle!r}; body={cat!r}")


def test_http_registered_get_pr2(staging_dir: Path, proc=None):
    """#82 registered-users family PR-2 (#236): cmd_accinfo plugin
    migrates GET /v1/registered/{nick} (read scope). Returns the
    expanded view (= ADC `+accinfoop`) for a single registered user.
    Depends on PR-1 having created smoke_pr1_a + smoke_pr1_b in the
    same hub session.

    Coverage:
    - Anonymous GET -> 401.
    - GET /v1/registered/smoke_pr1_a -> 200 + expanded envelope
      (nick + level + level_name + by + regged_at + lastseen +
      is_online + comment + traffic_blocked + msg_blocked + ban),
      no password leak.
    - GET unknown nick -> 404 E_NOT_FOUND.
    - GET on hubbot nick -> not 200 (humans-only filter).
    - /v1/endpoints catalog lists GET /v1/registered/{nick}.

    Runs AFTER test_http_registered_users_pr1 so the created users
    exist; BEFORE test_http_reload for the same reason.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def get(path: bytes, with_auth: bool = True):
        h = auth if with_auth else b""
        return _http_roundtrip(
            b"GET " + path + b" HTTP/1.1\r\n" + h + b"\r\n"
        )

    # 1. Anonymous -> 401.
    r = get(b"/v1/registered/smoke_pr1_a", with_auth=False)
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous GET /v1/registered/<nick>: expected 401, got {status(r)!r}"
        )

    # 2. Existing user -> 200 + expanded envelope.
    r = get(b"/v1/registered/smoke_pr1_a")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/registered/smoke_pr1_a: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    for field in (
        "nick", "level", "level_name", "by", "regged_at",
        "lastseen", "is_online", "comment", "traffic_blocked",
    ):
        if field not in data:
            raise TestFailure(
                f"GET /v1/registered/smoke_pr1_a: missing {field!r}; body={body_of(r)!r}"
            )
    if data.get("nick") != "smoke_pr1_a":
        raise TestFailure(
            f"GET /v1/registered/smoke_pr1_a: wrong nick echoed; body={body_of(r)!r}"
        )
    if data.get("level") != 20:
        raise TestFailure(
            f"GET /v1/registered/smoke_pr1_a: expected level=20; got {data!r}"
        )
    if "password" in data:
        raise TestFailure(
            f"GET /v1/registered/smoke_pr1_a: password leaked; body={body_of(r)!r}"
        )
    if data.get("is_online") is not False:
        raise TestFailure(
            f"GET /v1/registered/smoke_pr1_a: expected is_online=false; got {data!r}"
        )

    # 3. Unknown nick -> 404.
    r = get(b"/v1/registered/never_registered_smoke")
    if "404" not in status(r):
        raise TestFailure(
            f"GET unknown nick: expected 404, got {status(r)!r}; body={body_of(r)!r}"
        )
    if '"E_NOT_FOUND"' not in body_of(r):
        raise TestFailure(
            f"GET unknown nick: expected E_NOT_FOUND; body={body_of(r)!r}"
        )

    # 4. Hubbot nick -> must not return 200 (humans-only filter).
    # The actual bot nick varies with cfg `hub_bot_nick`; we try the
    # default and fall through if it's not registered (also 404 by
    # the not-registered branch, which is the contract).
    r = get(b"/v1/registered/luadch-NG")
    if "200" in status(r):
        raise TestFailure(
            f"GET on hubbot nick must not return 200; got {status(r)!r}"
        )

    # 5. /v1/endpoints catalog lists GET /v1/registered/{nick} with
    # the new description string (proves PR-2 registered the route).
    r = _http_roundtrip(
        b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n"
    )
    cat = body_of(r)
    if '"expanded account info' not in cat:
        raise TestFailure(
            f"catalog missing /v1/registered/{{nick}} GET description; body={cat!r}"
        )


def test_http_setpass_pr3(staging_dir: Path, proc=None):
    """#82 registered-users family PR-3 (#236): cmd_setpass plugin
    migrates PUT /v1/registered/{nick}/password (admin scope).
    Coexists with the ADC `+setpass nick` chat-cmd.

    Depends on PR-1 having created smoke_pr1_a + smoke_pr1_b in the
    same hub session.

    Coverage:
    - Anonymous PUT -> 401.
    - PUT missing password -> 400 E_BAD_INPUT.
    - PUT empty password -> 400.
    - PUT password with whitespace -> 400.
    - PUT happy path -> 200 + action:password-set +
      online_notified=false (smoke_pr1_a is not online).
    - PUT same password again -> 200 (idempotent; ADC msg_nochange
      semantics intentionally NOT applied on HTTP).
    - PUT unknown nick -> 404 E_NOT_FOUND.
    - PUT on hubbot nick -> not 200 (humans-only).
    - /v1/endpoints catalog lists PUT /v1/registered/{nick}/password.

    Runs AFTER test_http_registered_get_pr2 and BEFORE
    test_http_reload.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def put(path: bytes, body: bytes, with_auth: bool = True):
        h = auth if with_auth else b""
        return _http_roundtrip(
            b"PUT " + path + b" HTTP/1.1\r\n" + h +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )

    # 1. Anonymous -> 401.
    r = put(b"/v1/registered/smoke_pr1_a/password",
            b'{"password":"newpw_smoke_42"}', with_auth=False)
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous PUT password: expected 401, got {status(r)!r}"
        )

    # 2. Missing password field -> 400.
    r = put(b"/v1/registered/smoke_pr1_a/password", b'{}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT missing password: expected 400, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 3. Empty password -> 400.
    r = put(b"/v1/registered/smoke_pr1_a/password",
            b'{"password":""}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT empty password: expected 400, got {status(r)!r}"
        )

    # 4. Whitespace in password -> 400.
    r = put(b"/v1/registered/smoke_pr1_a/password",
            b'{"password":"bad password"}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT password with whitespace: expected 400, got {status(r)!r}"
        )

    # 5. Happy path.
    r = put(b"/v1/registered/smoke_pr1_a/password",
            b'{"password":"newpw_smoke_42"}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PUT password: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "password-set" or data.get("nick") != "smoke_pr1_a":
        raise TestFailure(
            f"PUT password: unexpected envelope; body={body_of(r)!r}"
        )
    if data.get("online_notified") is not False:
        raise TestFailure(
            f"PUT password: expected online_notified=false (target offline); got {data!r}"
        )

    # 6. Same password again -> 200 (idempotent).
    r = put(b"/v1/registered/smoke_pr1_a/password",
            b'{"password":"newpw_smoke_42"}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PUT idempotent retry: expected 200, got {status(r)!r}"
        )

    # 7. Unknown nick -> 404. Password is well above
    # cfg.min_password_length (default 10) to ensure the body
    # passes validation before the nick lookup runs.
    r = put(b"/v1/registered/never_registered_smoke/password",
            b'{"password":"newpw_smoke_zz"}')
    if "404" not in status(r):
        raise TestFailure(
            f"PUT unknown nick: expected 404, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 8. Hubbot nick -> not 200.
    r = put(b"/v1/registered/luadch-NG/password",
            b'{"password":"should_not_stick"}')
    if "200" in status(r):
        raise TestFailure(
            f"PUT on hubbot nick must not return 200; got {status(r)!r}"
        )

    # 9. Catalog discovery.
    r = _http_roundtrip(
        b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n"
    )
    cat = body_of(r)
    if '"/v1/registered/{nick}/password"' not in cat:
        raise TestFailure(
            f"catalog missing /v1/registered/{{nick}}/password; body={cat!r}"
        )
    if '"rotate the password' not in cat:
        raise TestFailure(
            f"catalog missing PUT password description; body={cat!r}"
        )


def test_http_nickchange_pr4(staging_dir: Path, proc=None):
    """#82 registered-users family PR-4 (#236): cmd_nickchange plugin
    migrates PUT /v1/registered/{nick}/nick (admin scope). Coexists
    with the ADC `+nickchange` chat-cmd.

    Depends on PR-1 having created smoke_pr1_b in the same hub
    session - we rename smoke_pr1_b so we don't disturb
    smoke_pr1_a (referenced by PR-3's password test if smoke
    ordering ever shuffles).

    Coverage:
    - Anonymous PUT -> 401.
    - PUT missing new_nick -> 400.
    - PUT whitespace in new_nick -> 400.
    - PUT happy path -> 200 + action:nick-changed + previous_nick +
      online_kicked=false (target offline).
    - PUT same -> 200 (idempotent).
    - PUT to a name that's already registered -> 409 E_CONFLICT.
    - PUT unknown nick -> 404 E_NOT_FOUND.
    - GET /v1/registered confirms the renamed entry shows up under
      the new name and not the old.
    - /v1/endpoints catalog lists PUT /v1/registered/{nick}/nick.

    Runs AFTER PR-3 and BEFORE reload.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def put(path: bytes, body: bytes, with_auth: bool = True):
        h = auth if with_auth else b""
        return _http_roundtrip(
            b"PUT " + path + b" HTTP/1.1\r\n" + h +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )

    # 1. Anonymous -> 401.
    r = put(b"/v1/registered/smoke_pr1_b/nick",
            b'{"new_nick":"smoke_pr4_renamed"}', with_auth=False)
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous PUT nick: expected 401, got {status(r)!r}"
        )

    # 2. Missing new_nick -> 400.
    r = put(b"/v1/registered/smoke_pr1_b/nick", b'{}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT missing new_nick: expected 400, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 3. Whitespace in new_nick -> 400.
    r = put(b"/v1/registered/smoke_pr1_b/nick",
            b'{"new_nick":"bad nick"}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT whitespace nick: expected 400, got {status(r)!r}"
        )

    # 4. Happy path.
    r = put(b"/v1/registered/smoke_pr1_b/nick",
            b'{"new_nick":"smoke_pr4_renamed"}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PUT nick: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "nick-changed":
        raise TestFailure(
            f"PUT nick: unexpected action; body={body_of(r)!r}"
        )
    if data.get("nick") != "smoke_pr4_renamed" or data.get("previous_nick") != "smoke_pr1_b":
        raise TestFailure(
            f"PUT nick: wrong nick/previous_nick; got {data!r}"
        )
    if data.get("online_kicked") is not False:
        raise TestFailure(
            f"PUT nick: expected online_kicked=false (target offline); got {data!r}"
        )

    # 5. Idempotent retry: rename smoke_pr4_renamed -> smoke_pr4_renamed.
    r = put(b"/v1/registered/smoke_pr4_renamed/nick",
            b'{"new_nick":"smoke_pr4_renamed"}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PUT idempotent retry: expected 200, got {status(r)!r}"
        )

    # 6. Conflict: rename to smoke_pr1_a which still exists from PR-1.
    r = put(b"/v1/registered/smoke_pr4_renamed/nick",
            b'{"new_nick":"smoke_pr1_a"}')
    if "409" not in status(r):
        raise TestFailure(
            f"PUT conflict: expected 409, got {status(r)!r}; body={body_of(r)!r}"
        )
    if '"E_CONFLICT"' not in body_of(r):
        raise TestFailure(
            f"PUT conflict: expected E_CONFLICT; body={body_of(r)!r}"
        )

    # 7. Unknown nick -> 404.
    r = put(b"/v1/registered/never_registered_smoke/nick",
            b'{"new_nick":"foo_smoke_42"}')
    if "404" not in status(r):
        raise TestFailure(
            f"PUT unknown nick: expected 404, got {status(r)!r}"
        )

    # 8. GET list shows the new name and not the old.
    r = _http_roundtrip(
        b"GET /v1/registered?limit=1000 HTTP/1.1\r\n" + auth + b"\r\n"
    )
    parsed = _json.loads(body_of(r))
    nicks = [
        entry.get("nick")
        for entry in parsed.get("data", {}).get("registered", [])
    ]
    if "smoke_pr4_renamed" not in nicks:
        raise TestFailure(
            f"GET list missing renamed nick smoke_pr4_renamed; got {nicks!r}"
        )
    if "smoke_pr1_b" in nicks:
        raise TestFailure(
            f"GET list still contains old nick smoke_pr1_b after rename; got {nicks!r}"
        )

    # 9. Catalog discovery.
    r = _http_roundtrip(
        b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n"
    )
    cat = body_of(r)
    if '"/v1/registered/{nick}/nick"' not in cat:
        raise TestFailure(
            f"catalog missing /v1/registered/{{nick}}/nick; body={cat!r}"
        )


def test_http_upgrade_pr5(staging_dir: Path, proc=None):
    """#82 registered-users family PR-5 (#236): cmd_upgrade plugin
    migrates PUT /v1/registered/{nick}/level (admin scope). Coexists
    with the ADC `+upgrade` chat-cmd.

    Depends on PR-1 having created smoke_pr1_a in the same hub
    session. (PR-4 renamed smoke_pr1_b -> smoke_pr4_renamed, but
    smoke_pr1_a stays at level 20.)

    Coverage:
    - Anonymous PUT -> 401.
    - PUT missing level -> 400.
    - PUT non-integer level -> 400.
    - PUT unknown level (999 not in cfg.levels) -> 400.
    - PUT happy path (level 30) -> 200 + action:level-changed +
      previous_level=20 + online_kicked=false.
    - PUT same level again -> 200 (idempotent).
    - PUT unknown nick -> 404.
    - GET /v1/registered/{nick} confirms the new level.
    - /v1/endpoints catalog lists PUT /v1/registered/{nick}/level.

    Runs AFTER PR-4 and BEFORE reload.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def put(path: bytes, body: bytes, with_auth: bool = True):
        h = auth if with_auth else b""
        return _http_roundtrip(
            b"PUT " + path + b" HTTP/1.1\r\n" + h +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )

    # 1. Anonymous -> 401.
    r = put(b"/v1/registered/smoke_pr1_a/level", b'{"level":30}',
            with_auth=False)
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous PUT level: expected 401, got {status(r)!r}"
        )

    # 2. Missing level -> 400.
    r = put(b"/v1/registered/smoke_pr1_a/level", b'{}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT missing level: expected 400, got {status(r)!r}"
        )

    # 3. Non-integer level -> 400.
    r = put(b"/v1/registered/smoke_pr1_a/level", b'{"level":"twenty"}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT non-integer level: expected 400, got {status(r)!r}"
        )

    # 4. Unknown level (999 not in cfg.levels) -> 400.
    r = put(b"/v1/registered/smoke_pr1_a/level", b'{"level":999}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT unknown level: expected 400, got {status(r)!r}"
        )

    # 5. Happy path: smoke_pr1_a is level 20 (from PR-1). Bump to 30.
    r = put(b"/v1/registered/smoke_pr1_a/level", b'{"level":30}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PUT level: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "level-changed":
        raise TestFailure(
            f"PUT level: unexpected action; body={body_of(r)!r}"
        )
    if data.get("level") != 30 or data.get("previous_level") != 20:
        raise TestFailure(
            f"PUT level: expected level=30 previous=20; got {data!r}"
        )
    if data.get("online_kicked") is not False:
        raise TestFailure(
            f"PUT level: expected online_kicked=false (target offline); got {data!r}"
        )

    # 6. Same level again -> 200 (idempotent).
    r = put(b"/v1/registered/smoke_pr1_a/level", b'{"level":30}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PUT idempotent retry: expected 200, got {status(r)!r}"
        )

    # 7. Unknown nick -> 404.
    r = put(b"/v1/registered/never_registered_smoke/level",
            b'{"level":30}')
    if "404" not in status(r):
        raise TestFailure(
            f"PUT unknown nick: expected 404, got {status(r)!r}"
        )

    # 8. GET /v1/registered/{nick} reflects the new level.
    r = _http_roundtrip(
        b"GET /v1/registered/smoke_pr1_a HTTP/1.1\r\n" + auth + b"\r\n"
    )
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET after PUT level: expected 200, got {status(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if parsed.get("data", {}).get("level") != 30:
        raise TestFailure(
            f"GET after PUT level: expected level=30; got {parsed!r}"
        )

    # 9. Catalog discovery.
    r = _http_roundtrip(
        b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n"
    )
    cat = body_of(r)
    if '"/v1/registered/{nick}/level"' not in cat:
        raise TestFailure(
            f"catalog missing /v1/registered/{{nick}}/level; body={cat!r}"
        )


def test_http_delreg_pr6(staging_dir: Path, proc=None):
    """#82 registered-users family PR-6 (#236): cmd_delreg plugin
    migrates DELETE /v1/registered/{nick} (admin scope, X-Confirm
    required). Coexists with the ADC `+delreg` chat-cmd.

    Depends on PR-1 having created smoke_pr4_renamed (renamed from
    smoke_pr1_b by PR-4) in the same hub session. We use that user
    to avoid disturbing smoke_pr1_a (referenced by PR-5's level
    test for the GET-reflect assertion).

    Coverage:
    - Anonymous DELETE -> 401.
    - DELETE without X-Confirm header -> 400 E_CONFIRMATION_REQUIRED.
    - DELETE with X-Confirm + reason -> 200 + action:delreg +
      blacklisted=true + online_kicked=false.
    - Post-DELETE GET /v1/registered/{nick} -> 404 (user gone).
    - Post-DELETE POST /v1/registered with same nick -> 409
      E_CONFLICT (blacklist entry blocks re-reg until explicit clear).
    - DELETE on unknown nick -> 404.
    - DELETE on hubbot -> not 200.
    - /v1/endpoints catalog lists DELETE /v1/registered/{nick}.

    Runs AFTER PR-5 and BEFORE reload. This is the last PR of the
    registered-users family - tracker #236 closes after merge.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"
    confirm = b"X-Confirm: yes\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def delete(path: bytes, body: bytes = b"", with_auth: bool = True,
               with_confirm: bool = True):
        h = auth if with_auth else b""
        h += confirm if with_confirm else b""
        if body:
            return _http_roundtrip(
                b"DELETE " + path + b" HTTP/1.1\r\n" + h +
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                b"\r\n" + body
            )
        return _http_roundtrip(
            b"DELETE " + path + b" HTTP/1.1\r\n" + h + b"\r\n"
        )

    # 1. Anonymous -> 401.
    r = delete(b"/v1/registered/smoke_pr4_renamed",
               b'{"reason":"smoke test"}', with_auth=False)
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous DELETE: expected 401, got {status(r)!r}"
        )

    # 2. No X-Confirm header -> 400 E_CONFIRMATION_REQUIRED.
    r = delete(b"/v1/registered/smoke_pr4_renamed",
               b'{"reason":"smoke test"}', with_confirm=False)
    if "400" not in status(r):
        raise TestFailure(
            f"DELETE without X-Confirm: expected 400, got {status(r)!r}"
        )
    if '"E_CONFIRMATION_REQUIRED"' not in body_of(r):
        raise TestFailure(
            f"DELETE without X-Confirm: expected E_CONFIRMATION_REQUIRED; "
            f"body={body_of(r)!r}"
        )

    # 3. Happy path with reason -> 200 + blacklist entry.
    r = delete(b"/v1/registered/smoke_pr4_renamed",
               b'{"reason":"smoke delreg with reason"}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"DELETE: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "delreg" or data.get("nick") != "smoke_pr4_renamed":
        raise TestFailure(
            f"DELETE: unexpected envelope; body={body_of(r)!r}"
        )
    if data.get("blacklisted") is not True:
        raise TestFailure(
            f"DELETE with reason: expected blacklisted=true; got {data!r}"
        )
    if data.get("online_kicked") is not False:
        raise TestFailure(
            f"DELETE: expected online_kicked=false (target offline); got {data!r}"
        )

    # 4. Post-DELETE GET -> 404.
    r = _http_roundtrip(
        b"GET /v1/registered/smoke_pr4_renamed HTTP/1.1\r\n" + auth + b"\r\n"
    )
    if "404" not in status(r):
        raise TestFailure(
            f"GET after DELETE: expected 404, got {status(r)!r}"
        )

    # 5. Post-DELETE POST same nick -> 409 (blacklisted).
    create_body = b'{"nick":"smoke_pr4_renamed","level":20}'
    r = _http_roundtrip(
        b"POST /v1/registered HTTP/1.1\r\n" + auth +
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(create_body)).encode("ascii") + b"\r\n"
        b"\r\n" + create_body
    )
    if "409" not in status(r):
        raise TestFailure(
            f"POST after blacklist-delreg: expected 409, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )

    # 6. DELETE unknown nick -> 404.
    r = delete(b"/v1/registered/never_registered_smoke")
    if "404" not in status(r):
        raise TestFailure(
            f"DELETE unknown nick: expected 404, got {status(r)!r}"
        )

    # 7. DELETE hubbot -> not 200.
    r = delete(b"/v1/registered/luadch-NG")
    if "200" in status(r):
        raise TestFailure(
            f"DELETE on hubbot must not return 200; got {status(r)!r}"
        )

    # 8. Catalog discovery.
    r = _http_roundtrip(
        b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n"
    )
    cat = body_of(r)
    if '"delreg a registered user' not in cat:
        raise TestFailure(
            f"catalog missing DELETE /v1/registered/{{nick}} description; "
            f"body={cat!r}"
        )


def test_239_cmd_ban_stale_bans_ref(staging_dir: Path, proc=None):
    """#239 regression: cmd_ban exported `bans` table goes stale
    after `+ban clear` rebinds the local `bans = {}`. cmd_accinfo's
    file-scope `local bans_tbl = ban.bans` (captured at module
    import time) holds the OLD reference, so any subsequent ban-
    status lookup (`+accinfoop` AND the new `GET /v1/registered/
    {nick}` ban field) returns a stale snapshot.

    Pre-fix repro:
    1. POST /v1/bans to ban smoke_pr1_a (regged from PR-1, offline).
    2. GET /v1/registered/smoke_pr1_a -> ban != null.
    3. ADC `+ban clear` via dummy (level 100) -> triggers cleanbans.
    4. GET /v1/registered/smoke_pr1_a -> ban != null (BUG; should
       be null because the persisted bans table is now empty).

    Post-fix (cleanbans mutates in place): step 4 returns ban=null.

    Runs LAST in the HTTP suite before reload so the family's
    persisted users / bans state is still intact.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # Step 1: POST /v1/bans on the offline-regged nick.
    create_body = (
        b'{"target_type":"nick","target":"smoke_pr1_a",'
        b'"duration_minutes":60,"reason":"#239 regression test"}'
    )
    r = _http_roundtrip(
        b"POST /v1/bans HTTP/1.1\r\n" + auth +
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(create_body)).encode("ascii") + b"\r\n"
        b"\r\n" + create_body
    )
    if "200 OK" not in status(r):
        raise TestFailure(
            f"#239 setup: POST /v1/bans expected 200, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )

    # Step 2: ban shows up in GET /v1/registered/{nick}.
    r = _http_roundtrip(
        b"GET /v1/registered/smoke_pr1_a HTTP/1.1\r\n" + auth + b"\r\n"
    )
    parsed = _json.loads(body_of(r))
    pre_ban = parsed.get("data", {}).get("ban")
    if not pre_ban:
        raise TestFailure(
            f"#239 setup: GET expected ban != null after POST /v1/bans; "
            f"got {parsed!r}"
        )

    # Step 3: trigger cleanbans via ADC `+ban clear` (level 100).
    # ADC BMSG escapes spaces as `\s` (matches the existing pattern
    # at the `[+!#]help` literal-prefix test); a literal space would
    # otherwise terminate the message field early. The 3s sleep is
    # the safer synchronisation than recv-on-pattern because the
    # hub-bot reply can arrive AS a BMSG (the test sees it via the
    # initial socket buffer if drained too early on a fast machine),
    # so we just let the dispatch tick complete before the next GET.
    with _logged_in_user() as (sock, sid, _reader):
        sock.sendall(f"BMSG {sid} +ban\\sclear\n".encode("utf-8"))
        time.sleep(3.0)

    # Step 4: ban should be null after cleanbans. Pre-fix, the
    # cmd_accinfo-held stale reference would still surface the
    # ban entry here.
    r = _http_roundtrip(
        b"GET /v1/registered/smoke_pr1_a HTTP/1.1\r\n" + auth + b"\r\n"
    )
    parsed = _json.loads(body_of(r))
    post_ban = parsed.get("data", {}).get("ban")
    if post_ban is not None:
        raise TestFailure(
            f"#239 regression: GET after `+ban clear` expected ban=null; "
            f"got {post_ban!r} - cmd_accinfo's bans_tbl is stale "
            f"(cleanbans rebound the local, the import reference is now orphan)"
        )


def _switch_to_partial_prefix_table_mode(staging_dir: Path, current_proc, current_log_file):
    """#243 setup: remove ONE entry from cfg.tbl
    `usr_nick_prefix_prefix_table` while leaving the rest intact -
    targets level 30, the post-PR-5 level of smoke_pr1_a. The
    surrounding entries (0/10/20/40/.../100) survive so the
    dummy user (level 100) can still log in cleanly; subsequent
    smoke tests (kill_wrong_ips / BLOM / ZLIF / hub_listen) are
    unaffected because they don't exercise level-30 users.

    Pre-fix the ADC `+setpass nick smoke_pr1_a <pw>` path then
    crashes on `prefix_table[30]` returning nil and concatenating
    with the nick. Post-fix the `or ""` guard absorbs the missing
    entry.

    Restart the hub against the mangled cfg and return the new
    (proc, log_file)."""
    stop_hub(current_proc, current_log_file)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    # Surgical removal: delete the `[ 30 ] = "[VIP]",` line.
    new_text, n = re.subn(
        r'^\s*\[\s*30\s*\]\s*=\s*"\[VIP\]"\s*,\s*\n',
        "",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if n != 1:
        raise TestFailure(
            "could not remove `[ 30 ] = \"[VIP]\"` entry from "
            "usr_nick_prefix_prefix_table in cfg.tbl (regex did not "
            "match - did the default cfg.tbl shape change?)"
        )
    cfg_path.write_text(new_text, encoding="utf-8")
    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, 5.0)
    wait_for_port(HUB_HOST, TEST_PORT_HTTP, 5.0)
    return proc, log_file


def test_243_prefix_table_nil_no_adc_crash(staging_dir: Path, proc=None):
    """#243 regression: ADC `+setpass`, `+nickchange`, `+upgrade`,
    `+delreg` all index `prefix_table[level]` without a nil-guard
    inside `if activate then`. When the prefix table has no entry
    for the target user's level (cfg drift OR an ad-hoc level the
    operator forgot to add), the index returns nil and the
    downstream concat (`nil .. nick`) crashes the handler. The
    HTTP path was always defensive (`prefix_table[level] or ""`).

    The crash is caught by the dispatcher (it does not kill the
    hub) but the trace lands in `error.log`. This test runs the
    ADC `+setpass` chat-cmd under the mangled cfg (level 30 entry
    removed) and asserts `error.log` carries no
    `attempt to concatenate a nil` / `attempt to index a nil`
    entry for any of the four family plugins.

    Uses smoke_pr1_a (created by #236 PR-1, level 30 after PR-5)
    as the regged target. The user is regged in user.tbl which
    survives the mode switch (only cfg.tbl is rewritten).
    """
    error_log = staging_dir / "log" / "error.log"
    size_before = error_log.stat().st_size if error_log.exists() else 0

    with _logged_in_user() as (sock, sid, _reader):
        # ADC BMSG escapes spaces as `\s` (see #239 / cmd_help
        # literal-bracket smoke). Target cmd: `+upgrade nick
        # smoke_pr1_a 40`. Of the four family plugins,
        # cmd_setpass / cmd_nickchange / cmd_delreg all wrap
        # the prefix lookup in `hub.escapeto( prefix_table[...] )`
        # and `hub.escapeto` is a C function that `luaL_optstring`s
        # a nil arg to `""` - no crash. cmd_upgrade's ADC path
        # (line ~244 pre-fix) uses `prefix = prefix_table[ level ]`
        # then `target_nick = prefix .. target_firstnick` without
        # the escapeto wrapper, so `nil .. <nick>` crashes the
        # handler. This is the only crash-site in the family,
        # but the `or ""` guard goes onto all four plugins for
        # consistency.
        sock.sendall(f"BMSG {sid} +upgrade\\snick\\ssmoke_pr1_a\\s40\n".encode("utf-8"))
        time.sleep(3.0)

    size_after = error_log.stat().st_size if error_log.exists() else 0
    if size_after <= size_before:
        return  # No new error.log lines - the handler ran cleanly.

    with open(error_log, "rb") as f:
        f.seek(size_before)
        new_text = f.read()
    bad_patterns = [
        b"attempt to concatenate a nil",
        b"attempt to index a nil",
    ]
    plugin_markers = [
        b"cmd_setpass",
        b"cmd_nickchange",
        b"cmd_upgrade",
        b"cmd_delreg",
    ]
    for bp in bad_patterns:
        if bp in new_text:
            # Surface which plugin to make the failure self-debugging.
            for pm in plugin_markers:
                if pm in new_text:
                    raise TestFailure(
                        f"#243 regression: error.log shows {bp!r} from "
                        f"{pm.decode()!r} under cfg drift "
                        f"(prefix_table = {{}}). New error.log section: "
                        f"{new_text[:512]!r}"
                    )
            raise TestFailure(
                f"#243 regression: error.log shows {bp!r} under cfg "
                f"drift (prefix_table = {{}}). New error.log section: "
                f"{new_text[:512]!r}"
            )


def test_http_reload(staging_dir: Path, proc=None):
    """#82 deferred Phase-2-spec item: cmd_reload plugin migrates to
    POST /v1/reload (X-Confirm). Coexists with the ADC `+reload`
    chat-cmd.

    Coverage:
    - Anonymous POST -> 401.
    - POST without X-Confirm -> 400 E_CONFIRMATION_REQUIRED.
    - POST with X-Confirm: yes -> 200 + action:"reload" +
      reloaded:["cfg","scripts"].
    - Post-reload: /v1/endpoints catalog still lists POST /v1/reload
      (proves restartscripts re-registered the route).
    - Post-reload: dummy ADC login still works (proves plugins
      re-init'd cleanly).

    Placement note: this test runs BEFORE test_inf_integer_clamps,
    which itself queries /v1/users via HTTP. inf_integer_clamps
    thus acts as a natural sanity check that reload did not break
    the HTTP route table.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # 1. Anonymous POST -> 401.
    r = _http_roundtrip(b"POST /v1/reload HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous POST /v1/reload: expected 401, got {status(r)!r}"
        )

    # 2. Without X-Confirm -> 400 E_CONFIRMATION_REQUIRED.
    r = _http_roundtrip(
        b"POST /v1/reload HTTP/1.1\r\n" + auth +
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/reload without X-Confirm: expected 400, got {status(r)!r}"
        )
    if '"E_CONFIRMATION_REQUIRED"' not in body_of(r):
        raise TestFailure(
            f"POST /v1/reload without X-Confirm: expected "
            f"E_CONFIRMATION_REQUIRED; body={body_of(r)!r}"
        )

    # 3. With X-Confirm: yes -> 200 + envelope.
    r = _http_roundtrip(
        b"POST /v1/reload HTTP/1.1\r\n" + auth +
        b"X-Confirm: yes\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    if "200 OK" not in status(r):
        raise TestFailure(
            f"POST /v1/reload with X-Confirm: expected 200, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(f"POST /v1/reload: ok=false; body={body_of(r)!r}")
    data = parsed.get("data") or {}
    if data.get("action") != "reload":
        raise TestFailure(
            f"POST /v1/reload: expected action=reload; body={body_of(r)!r}"
        )
    reloaded = data.get("reloaded") or []
    if "cfg" not in reloaded or "scripts" not in reloaded:
        raise TestFailure(
            f"POST /v1/reload: expected reloaded array containing cfg + scripts; "
            f"body={body_of(r)!r}"
        )

    # 4. Post-reload: /v1/endpoints catalog still lists POST /v1/reload.
    # If restartscripts() did not re-register the route, this fails.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/reload"' not in b:
        raise TestFailure(
            f"catalog missing /v1/reload after reload; "
            f"restartscripts did not re-register? body={b!r}"
        )


def test_inf_integer_clamps(staging_dir: Path, proc=None):
    """Phase 8a F-INF-2 (#219): per-field integer clamps on the user
    accessors `user:share()` / `user:files()` / `user:slots()` /
    `user:hubs()`.

    The ADC parser is deliberately permissive (`^%-?%d+$`) on integer
    fields so DC++ builds that emit the `DS-1` sentinel can still log
    in (Phase 7d / #65 / upstream luadch/luadch#241). The clamp lives
    at the accessor layer in `core/hub_user_object.lua`: negatives
    normalise to 0 and oversize values cap at a float-safe / spec-
    realistic boundary so hub-stat aggregates and the HTTP API JSON
    output cannot be poisoned.

    Test:
    1. Login dummy/test with a BINF carrying poison numerics:
       SS=-1, SF=10^18, SL=-1, HN=99999999, HR=-1, HO=10^18.
    2. The login MUST succeed (parser stays permissive - Phase 7d
       contract regression guard).
    3. Query /v1/users via HTTP and find dummy's entry by SID.
    4. Assert: share_bytes=0, share_files=2^32, slots=0,
       hubs_normal=2^16, hubs_regged=0, hubs_op=2^16.
    """
    # Re-discover bootstrap token (same pattern as phase1c).
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    # 1. Login dummy with custom poison BINF.
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
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
            f" ID{cid_b32} PD{pid_b32} NIdummy I40.0.0.0 SUTCP4"
            f" SS-1 SF999999999999999999 SL-1"
            f" HN99999999 HR-1 HO999999999999999999\n"
        )
        sock.sendall(binf.encode("utf-8"))

        gpa = reader.recv_until(lambda f: f.startswith("IGPA "))
        salt_b32 = gpa.split(" ", 1)[1].strip()
        salt_bytes = _b32_decode(salt_b32)
        response = _tiger.tiger("test".encode("utf-8") + salt_bytes)
        sock.sendall(f"HPAS {_b32_encode(response)}\n".encode("utf-8"))

        # Login must succeed. ISTA = parser-level reject -> Phase 7d
        # regression.
        final = reader.recv_until(
            lambda f: f.startswith(f"BINF {sid}") or f.startswith("ISTA "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if final.startswith("ISTA "):
            raise TestFailure(
                f"Phase 7d (#65) regression: hub rejected BINF carrying "
                f"negative / oversize integer fields. The clamp must "
                f"live at the accessor layer, not the parser. Got: {final!r}"
            )

        # 2. Query /v1/users with the bootstrap token. Find dummy by
        #    SID.
        r = _http_roundtrip(
            b"GET /v1/users?limit=50 HTTP/1.1\r\n" + auth + b"\r\n"
        )
        status_line = r.split("\r\n", 1)[0]
        if "200 OK" not in status_line:
            raise TestFailure(
                f"/v1/users: expected 200, got {status_line!r}"
            )
        body = r.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in r else ""
        # Parse JSON properly - dkjson does not preserve key insertion
        # order so a substring slice around `"sid":"<our-sid>"` would
        # only see fields that happen to follow sid in this run's hash
        # iteration.
        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            raise TestFailure(f"/v1/users: response not JSON: {e}; body={body!r}")
        users = data.get("data", {}).get("users", [])
        entry = next((u for u in users if u.get("sid") == sid), None)
        if entry is None:
            raise TestFailure(
                f"/v1/users: dummy entry (sid={sid!r}) not in users[]; "
                f"users={users!r}"
            )

        # 3. Per-field clamp assertions. Caps come from
        #    core/hub_user_object.lua _CAP_*.
        for key, want, label in (
            ("share_bytes",   0,           "SS=-1 -> 0"),
            ("share_files",   1 << 32,     "SF=10^18 -> 2^32"),
            ("slots",         0,           "SL=-1 -> 0"),
            ("hubs_normal",   1 << 16,     "HN=99999999 -> 2^16"),
            ("hubs_regged",   0,           "HR=-1 -> 0"),
            ("hubs_op",       1 << 16,     "HO=10^18 -> 2^16"),
        ):
            got = entry.get(key)
            if got != want:
                raise TestFailure(
                    f"F-INF-2 clamp not applied: {key}={got!r} "
                    f"(want={want}, {label}); full entry={entry!r}"
                )
    finally:
        sock.close()


def _switch_to_kill_wrong_ips_off_mode(staging_dir, current_proc, current_log_file):
    """#214 Gap 2 regression setup: stop the hub, set `kill_wrong_ips
    = false` in cfg.tbl so the next test exercises the NAT-weird-
    deployment opt-out path. The key is not in `examples/cfg/cfg.tbl`
    by default (only in `core/cfg_defaults.lua` at true), so we inject
    it before the closing brace of the cfg.tbl table. Mirrors the
    `_switch_to_http_mode` `ratelimit_perip_conn_burst` injection
    pattern (same #82 lesson: cfg keys not always present in the
    example - regex must handle both)."""
    stop_hub(current_proc, current_log_file)
    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    if re.search(r"kill_wrong_ips\s*=", text):
        new_text, n = re.subn(
            r"kill_wrong_ips\s*=\s*\w+",
            "kill_wrong_ips = false",
            text,
            count=1,
        )
    else:
        new_text, n = re.subn(
            r"^\}\s*$",
            "    kill_wrong_ips = false,  -- smoke override (#214 Gap 2 test)\n}",
            text,
            count=1,
            flags=re.MULTILINE,
        )
    if n != 1:
        raise TestFailure(
            "could not set kill_wrong_ips=false in cfg.tbl - neither "
            "the in-place substitution nor the inject-before-} pattern "
            "matched. Did the cfg.tbl format change?"
        )
    cfg_path.write_text(new_text, encoding="utf-8")
    time.sleep(1.0)
    return start_hub(staging_dir)


def test_kill_wrong_ips_off_stamps_userip(staging_dir: Path, proc=None):
    """#214 Gap 2 regression. With `kill_wrong_ips = false` (the NAT-
    weird-deployment opt-out), a BINF claiming a different IP than the
    TCP source MUST NOT broadcast the lie - the hub MUST stamp the
    verified `userip` over the wrong claim before the BINF goes out to
    other clients. Pre-fix the wrong claim was forwarded as-is, which
    let a hostile client redirect other users' CTM / RCM frames at an
    arbitrary victim address (DDoS-amplification, see #214 body +
    Wikipedia DC++ DDoS history).

    Test:
      1. Login dummy/test with `I4203.0.113.1` (RFC 5737 documentation
         range - syntactically valid IPv4, definitely not 127.0.0.1).
      2. Login MUST succeed (kill_wrong_ips=false preserves the
         user's connection - that is the whole point of the opt-out).
      3. Read the own-BINF echo. It MUST carry `I4127.0.0.1` (verified
         userip), NOT `I4203.0.113.1` (the claim).

    Falsifiable: on unpatched code the echo carries the lie, the
    final `I4203.0.113.1 in final` check raises.
    """
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
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
            f" ID{cid_b32} PD{pid_b32} NIdummy"
            f" I4203.0.113.1 SUTCP4\n"
        )
        sock.sendall(binf.encode("utf-8"))

        gpa = reader.recv_until(lambda f: f.startswith("IGPA "))
        salt_b32 = gpa.split(" ", 1)[1].strip()
        salt_bytes = _b32_decode(salt_b32)
        response = _tiger.tiger("test".encode("utf-8") + salt_bytes)
        sock.sendall(f"HPAS {_b32_encode(response)}\n".encode("utf-8"))

        final = reader.recv_until(
            lambda f: f.startswith(f"BINF {sid}") or f.startswith("ISTA "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if final.startswith("ISTA "):
            raise TestFailure(
                f"#214 Gap 2: kill_wrong_ips=false should preserve the "
                f"user's connection on IP mismatch (the whole point of "
                f"the opt-out). Got ISTA: {final!r}"
            )

        # The broadcast BINF echo MUST carry the verified userip
        # (127.0.0.1), not the lie (203.0.113.1).
        if "I4127.0.0.1" not in final:
            raise TestFailure(
                f"#214 Gap 2: broadcast BINF should carry "
                f"I4127.0.0.1 (verified userip stamped over the claim) "
                f"but does not. Frame: {final!r}"
            )
        if "I4203.0.113.1" in final:
            raise TestFailure(
                f"#214 Gap 2 regression: broadcast BINF carries the "
                f"claimed wrong IP `I4203.0.113.1` (DDoS-amplification "
                f"vector - other clients would direct CTM / RCM at the "
                f"spoofed address). The unverified claim MUST be "
                f"stamped over with userip before broadcast. "
                f"Frame: {final!r}"
            )
    finally:
        sock.close()


def _switch_to_blom_mode(staging_dir: Path, current_proc, current_log_file):
    """Phase 8 S5 (#147 T2.2) setup: stop the hub, flip
    `blom_enabled = false` to `true` in cfg.tbl so the next test
    exercises ADC-EXT BLOM hash-search routing. Keeps default k=6,
    h=16, m=32768 (4 KiB filter). Returns the new (proc, log_file)."""
    stop_hub(current_proc, current_log_file)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    new_text, n = re.subn(
        r"blom_enabled\s*=\s*false",
        "blom_enabled = true",
        text,
        count=1,
    )
    if n != 1:
        raise TestFailure(
            "could not flip blom_enabled in cfg.tbl"
        )
    cfg_path.write_text(new_text, encoding="utf-8")

    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    return proc, log_file


# BLOM bloom-filter parameters that must match the cfg defaults
# (cfg_defaults.lua blom_k / blom_h / blom_m). The smoke harness
# does not parse the live cfg back out; if the hub's defaults
# change, update these constants alongside.
BLOM_K = 6
BLOM_H = 16
BLOM_M = 32768


def _blom_insert(filter_bytes: bytes, tth: bytes,
                 k: int = BLOM_K, h: int = BLOM_H, m: int = BLOM_M) -> bytes:
    """Insert a single 24-byte TTH into a bloom filter byte array.
    Mirrors the bit-extraction in core/bloom.lua / the spec
    (section 3.20): per-iteration read h bits starting at bit i*h
    from the TTH as little-endian unsigned int, modulo m, set that
    bit (LSB-first per byte). Returns the updated filter bytes."""
    if len(tth) != 24:
        raise ValueError(f"TTH must be 24 bytes, got {len(tth)}")
    bps = h // 8
    out = bytearray(filter_bytes)
    for i in range(k):
        pos = 0
        for j in range(bps):
            pos |= tth[i * bps + j] << (8 * j)
        pos %= m
        out[pos // 8] |= 1 << (pos % 8)
    return bytes(out)


def test_blom_roundtrip(staging_dir: Path, proc=None):
    """Phase 8 S5 (#147 T2.2) BLOM hash-search routing roundtrip.

    Single-user scenario (the hub's broadcast routing iterates ALL
    NORMAL-state humans including the sender, so a search the
    sender issues is echoed back if-and-only-if the bloom filter
    permits - the perfect oracle for filter routing without
    needing a second logged-in user, which is non-trivial in the
    pre-seeded smoke harness):

      A logs in as dummy advertising ADBLOM in HSUP, receives the
      hub's HGET, uploads HSND + a binary filter with ONE known
      TTH inserted. Then:
        - hash-search BSCH for the inserted TTH -> A receives echo
        - hash-search BSCH for a DIFFERENT TTH  -> no echo (filter
          stripped it)
        - keyword-search BSCH (no TR)           -> A receives echo
          regardless of the filter (load-bearing spec-trap regression)

    Validates: SUP advertise of ADBLOM, hub-initiated HGET, the
    counted-binary capture stage in iostream + the HSND handler,
    per-user filter storage on the user object, the hash-vs-keyword
    routing decision in core/hub.lua's incoming() B-class branch.
    """
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)

    in_filter_tth = secrets.token_bytes(24)
    not_in_filter_tth = secrets.token_bytes(24)
    filter_blob = bytes(BLOM_M // 8)
    filter_blob = _blom_insert(filter_blob, in_filter_tth)

    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        # ---- HSUP advertising ADBLOM
        sock.sendall(b"HSUP ADBASE ADTIGR ADBLOM\n")
        reader = _ADCReader(sock)
        isup = reader.recv_until(lambda f: f.startswith("ISUP "))
        if "ADBLOM" not in isup:
            raise TestFailure(
                f"hub did not advertise ADBLOM in plain SUP; got {isup!r}"
            )
        isid = reader.recv_until(lambda f: f.startswith("ISID "))
        sid = isid.split(" ", 1)[1].strip()
        reader.recv_until(lambda f: f.startswith("IINF "))

        # ---- full login as dummy
        pid = secrets.token_bytes(24)
        cid = _b32_encode(_tiger.tiger(pid))
        sock.sendall((
            f"BINF {sid} ID{cid} PD{_b32_encode(pid)}"
            f" NIdummy I40.0.0.0 SUTCP4\n"
        ).encode("utf-8"))
        gpa = reader.recv_until(lambda f: f.startswith("IGPA "))
        salt = _b32_decode(gpa.split(" ", 1)[1].strip())
        resp = _tiger.tiger(b"test" + salt)
        sock.sendall(f"HPAS {_b32_encode(resp)}\n".encode("utf-8"))
        reader.recv_until(lambda f: f.startswith(f"BINF {sid}"))

        # ---- hub now sends HGET. Read + validate.
        hget = reader.recv_until(lambda f: f.startswith("HGET "),
                                  timeout=PROTOCOL_TIMEOUT_SEC)
        if " blom " not in hget or f" {BLOM_M // 8} " not in hget:
            raise TestFailure(
                f"hub HGET does not match BLOM defaults; got {hget!r}"
            )
        if f"BK{BLOM_K}" not in hget or f"BH{BLOM_H}" not in hget:
            raise TestFailure(
                f"hub HGET missing BK/BH params; got {hget!r}"
            )

        # ---- reply with HSND header + binary filter blob
        sock.sendall(
            f"HSND blom / 0 {BLOM_M // 8}\n".encode("utf-8") + filter_blob
        )
        # Brief settle: the counted-binary stage's callback installs
        # the filter object on the user object. Sub-tick latency.
        time.sleep(0.5)

        # ---- hash-search for TTH IN the filter; expect echo back.
        tr_in = _b32_encode(in_filter_tth)
        sock.sendall(f"BSCH {sid} TR{tr_in}\n".encode("utf-8"))
        reader.recv_until(
            lambda f: f.startswith(f"BSCH {sid} ") and f"TR{tr_in}" in f,
            timeout=PROTOCOL_TIMEOUT_SEC * 2,
        )

        # ---- hash-search for TTH NOT in the filter; expect NO echo.
        tr_out = _b32_encode(not_in_filter_tth)
        sock.sendall(f"BSCH {sid} TR{tr_out}\n".encode("utf-8"))
        try:
            unwanted = reader.recv_until(
                lambda f: f.startswith(f"BSCH {sid} ") and f"TR{tr_out}" in f,
                timeout=1.5,
            )
            raise TestFailure(
                "hash-search for TTH not in filter still reached the user "
                f"(bloom filter not consulted?); got {unwanted!r}"
            )
        except TestFailure as tf:
            if "not consulted" in str(tf):
                raise
            # else: the timeout TestFailure is the expected outcome.

        # ---- keyword-search (no TR); expect echo regardless of filter.
        # This is the LOAD-BEARING spec-trap regression: the filter
        # must NOT be consulted on keyword searches because the bits
        # for a plain-text keyword are by definition not set.
        sock.sendall(f"BSCH {sid} ANbloomkeywordtest\n".encode("utf-8"))
        reader.recv_until(
            lambda f: f.startswith(f"BSCH {sid} ") and "ANbloomkeywordtest" in f,
            timeout=PROTOCOL_TIMEOUT_SEC * 2,
        )

    finally:
        sock.close()


def _switch_to_zlif_mode(staging_dir: Path, current_proc, current_log_file):
    """Phase 8 S4b (#147 T3.2) setup: stop the hub, flip
    `zlif_enabled = false` to `true` in cfg.tbl so the next test
    exercises ADC-EXT ZLIF stream compression. `zlif_over_tls` stays
    false - we test the plain-ADC path only (the TLS gate is a
    separate flag, and TLS+ZLIF has a documented CRIME-class
    concern). Returns the new (proc, log_file)."""
    stop_hub(current_proc, current_log_file)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    new_text, n = re.subn(
        r"zlif_enabled\s*=\s*false",
        "zlif_enabled = true",
        text,
        count=1,
    )
    if n != 1:
        raise TestFailure(
            "could not flip zlif_enabled in cfg.tbl - is the key present in "
            "examples/cfg/cfg.tbl with default false?"
        )
    cfg_path.write_text(new_text, encoding="utf-8")

    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    return proc, log_file


def test_zlif_roundtrip(staging_dir: Path, proc=None):
    """Phase 8 S4b: ADC-EXT ZLIF full roundtrip. With zlif_enabled =
    true and the client advertising ADZLIF in HSUP, the hub:

      - advertises ADZLIF in its ISUP response (plain frames)
      - sends `IZON\\n` as the last plain frame
      - deflate(Z_SYNC_FLUSH)s every subsequent outbound byte

    The test client decompresses inbound after the IZON boundary
    using Python's stdlib zlib (incremental, matches the Z_SYNC_FLUSH
    cadence). It does NOT send its own BZON, so its outbound stays
    plain - this exercises the asymmetric per-direction nature of
    ZLIF (hub compresses outbound; client outbound is plain).
    Validates: SUP advertise, IZON emission, outbound deflate stage
    installation, full ADC login flow over compression, +help reply
    routed back through deflate."""
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)

    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        sock.sendall(b"HSUP ADBASE ADTIGR ADZLIF\n")

        # Read uncompressed bytes until the IZON\n boundary. Anything
        # before IZON is plain ADC; the moment we see IZON, the hub
        # has switched its outbound to deflate.
        buf = b""
        deadline = time.monotonic() + PROTOCOL_TIMEOUT_SEC
        while b"IZON\n" not in buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TestFailure(
                    f"timed out waiting for IZON; got {buf!r}"
                )
            sock.settimeout(remaining)
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise TestFailure(
                    f"connection closed before IZON arrived; got {buf!r}"
                )
            buf += chunk

        plain, compressed_tail = buf.split(b"IZON\n", 1)

        # 1. SUP advertise check.
        if b"ADZLIF" not in plain:
            raise TestFailure(
                f"hub did not advertise ADZLIF in plain SUP; got {plain!r}"
            )

        # 2. ISID parse out of plain frames.
        sid = None
        for f in plain.split(b"\n"):
            if f.startswith(b"ISID "):
                sid = f.split(b" ", 1)[1].decode("ascii")
                break
        if not sid:
            raise TestFailure(f"no ISID in plain SUP frames; got {plain!r}")

        # 3. From here on the hub's stream is zlib (Z_SYNC_FLUSH).
        decomp = zlib.decompressobj()
        decoded = bytearray()
        comp_buf = bytearray(compressed_tail)

        def pump_recv(needle: bytes, timeout=PROTOCOL_TIMEOUT_SEC):
            """Read+decompress until `needle` (bytes) appears in
            `decoded`, or timeout."""
            end = time.monotonic() + timeout
            while needle not in decoded:
                if comp_buf:
                    decoded.extend(decomp.decompress(bytes(comp_buf)))
                    del comp_buf[:]
                    if needle in decoded:
                        return
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise TestFailure(
                        f"ZLIF timed out waiting for {needle!r}; "
                        f"decoded so far: {bytes(decoded)!r}"
                    )
                sock.settimeout(remaining)
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    raise TestFailure(
                        f"connection closed mid-ZLIF; decoded "
                        f"{bytes(decoded)!r}"
                    )
                comp_buf.extend(chunk)

        # 4. Send BINF for dummy/test (client outbound stays plain -
        # we did not BZON the hub).
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

        # 5. Hub responds IGPA <salt>, compressed.
        pump_recv(b"IGPA ")
        idx = decoded.index(b"IGPA ")
        nl = decoded.index(b"\n", idx)
        gpa = decoded[idx:nl].decode("ascii")
        salt_b32 = gpa.split(" ", 1)[1]
        salt_bytes = _b32_decode(salt_b32)
        response = _tiger.tiger(b"test" + salt_bytes)
        sock.sendall(f"HPAS {_b32_encode(response)}\n".encode("utf-8"))

        # 6. Login completes when the hub echoes our own BINF.
        pump_recv(f"BINF {sid}".encode("ascii"))

        # 7. Send +help BMSG and expect a chat reply (hubbot E/IMSG).
        sock.sendall(f"BMSG {sid} +help\n".encode("utf-8"))
        pump_recv(b"MSG ", timeout=PROTOCOL_TIMEOUT_SEC * 2)

        # 8. Now flip the CLIENT outbound to compression too so the
        # hub's inbound inflate stage gets exercised end-to-end
        # against real zlib (the unit test only mocks zlib). The
        # security review correctly flagged that the unit test
        # cannot catch a real-zlib Z_SYNC_FLUSH boundary / buffering
        # bug; this assertion covers the hub-inbound inflate path in
        # CI.
        #
        # Drain all pending hub bytes first (the +help reply from
        # step 7 may still be arriving in MSG fragments) so the
        # post-BZON marker check below cannot match a stale frame.
        sock.settimeout(0.5)
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            comp_buf.extend(chunk)
        if comp_buf:
            decoded.extend(decomp.decompress(bytes(comp_buf)))
            del comp_buf[:]
        boundary = len(decoded)

        # Send `BZON <sid>` uncompressed (last plain client frame),
        # then a single TCP write that bundles the compressed BMSG
        # right after the ZON `\n` - this is the same-TCP-segment
        # case S4a's pipeline reshape exists to handle. If the hub
        # mis-frames the post-ZON tail (i.e. pre-S4a behaviour), the
        # +zlif_compose-test command never reaches the hub command
        # dispatcher and the assertion below times out.
        comp = zlib.compressobj()
        compressed = (
            comp.compress(f"BMSG {sid} +help\n".encode("utf-8"))
            + comp.flush(zlib.Z_SYNC_FLUSH)
        )
        zon_then_compressed = f"BZON {sid}\n".encode("utf-8") + compressed
        sock.sendall(zon_then_compressed)

        # Wait for a NEW MSG to appear AFTER the drain boundary. With
        # the boundary anchored on a true zero-pending state, any
        # MSG past it must be the reply to our compressed +help.
        end = time.monotonic() + PROTOCOL_TIMEOUT_SEC * 2
        while True:
            if comp_buf:
                decoded.extend(decomp.decompress(bytes(comp_buf)))
                del comp_buf[:]
            if decoded.find(b"MSG ", boundary) != -1:
                break
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TestFailure(
                    "ZLIF inbound inflate: client compressed BZON + BMSG "
                    "+help did not produce a new hub reply; possible "
                    "mid-segment reshape regression or adc_parse rejecting "
                    "BZON. "
                    f"Decoded after boundary: "
                    f"{bytes(decoded[boundary:])!r}"
                )
            sock.settimeout(remaining)
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise TestFailure(
                    "ZLIF inbound: hub closed during compressed "
                    "BMSG roundtrip"
                )
            comp_buf.extend(chunk)

    finally:
        sock.close()


def test_zlif_pre_hsup_zon_rejected(staging_dir: Path, proc=None):
    """Phase 8 S4b security gate (security review BLOCKER B1): a
    `BZON` arriving BEFORE the HSUP handshake completes must be
    rejected with ISTA 240 + connection close, NOT silently install
    an inflate stage on a connection whose peer identity has not yet
    been negotiated. Runs under zlif_enabled = true to prove the
    state gate fires regardless of the operator cfg.

    Pre-fix (no `userstate == "protocol"` check): the hub installed
    inflate inbound, the client's plain follow-up bytes triggered a
    zlib Z_DATA_ERROR, the connection closed without any ISTA. This
    test specifically asserts the ISTA 240 marker which only the
    fix emits."""
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)

    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        sock.sendall(b"BZON AAAA\n")    # pre-HSUP - sid is bogus, irrelevant
        buf = b""
        end = time.monotonic() + PROTOCOL_TIMEOUT_SEC
        while b"\n" not in buf and time.monotonic() < end:
            sock.settimeout(end - time.monotonic())
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
        if b"ISTA 240" not in buf:
            raise TestFailure(
                f"pre-HSUP BZON: expected ISTA 240 close marker; got {buf!r}"
            )
    finally:
        sock.close()


def test_blom_zlif_combined(staging_dir: Path, proc=None):
    """#192 combined-mode regression: with BOTH `blom_enabled = true`
    AND `zlif_enabled = true` the hub MUST advertise ADBLOM + ADZLIF,
    install inflate on the inbound pipeline when the client BZONs,
    splice the BLOM counted-binary capture BEFORE the ADC-line framer
    (i.e. AFTER inflate) when HSND arrives, and build the bloom
    filter from the DECOMPRESSED filter bytes. Pre-fix (Phase-8 S5
    inframer_prepend semantic) this test FAILS: counted sits in
    front of inflate, captures raw deflated noise, the bloom filter
    bits are random -> hash-search for an inserted TTH gets dropped
    (false negative).

    Runs in the same dual-flag hub state the preceding ZLIF tests
    set up (`blom_enabled = true` persisted from the BLOM mode
    switch, `zlif_enabled = true` from the ZLIF switch; the cfg
    mutex from Phase-8 S5 has been removed)."""
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)

    in_filter_tth = secrets.token_bytes(24)
    not_in_filter_tth = secrets.token_bytes(24)
    filter_blob = bytes(BLOM_M // 8)
    filter_blob = _blom_insert(filter_blob, in_filter_tth)

    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        # ---- HSUP advertising BOTH ADBLOM + ADZLIF
        sock.sendall(b"HSUP ADBASE ADTIGR ADBLOM ADZLIF\n")

        # Read uncompressed bytes until IZON\n - the hub switches its
        # OUTBOUND to deflate after IZON. ADBLOM / ADZLIF / ISID /
        # IINF all arrive in the plain prefix.
        buf = b""
        deadline = time.monotonic() + PROTOCOL_TIMEOUT_SEC
        while b"IZON\n" not in buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TestFailure(
                    f"combined: timed out waiting for IZON; got {buf!r}"
                )
            sock.settimeout(remaining)
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise TestFailure(
                    f"combined: connection closed before IZON; got {buf!r}"
                )
            buf += chunk

        plain, compressed_tail = buf.split(b"IZON\n", 1)
        if b"ADBLOM" not in plain:
            raise TestFailure(
                f"combined: hub did not advertise ADBLOM; got {plain!r}"
            )
        if b"ADZLIF" not in plain:
            raise TestFailure(
                f"combined: hub did not advertise ADZLIF; got {plain!r}"
            )
        sid = None
        for f in plain.split(b"\n"):
            if f.startswith(b"ISID "):
                sid = f.split(b" ", 1)[1].decode("ascii")
                break
        if not sid:
            raise TestFailure(
                f"combined: no ISID in plain SUP frames; got {plain!r}"
            )

        decomp = zlib.decompressobj()
        decoded = bytearray()
        comp_buf = bytearray(compressed_tail)

        def pump_recv(needle: bytes, timeout=PROTOCOL_TIMEOUT_SEC):
            end = time.monotonic() + timeout
            while needle not in decoded:
                if comp_buf:
                    decoded.extend(decomp.decompress(bytes(comp_buf)))
                    del comp_buf[:]
                    if needle in decoded:
                        return
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise TestFailure(
                        f"combined: timed out waiting for {needle!r}; "
                        f"decoded so far: {bytes(decoded)!r}"
                    )
                sock.settimeout(remaining)
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    raise TestFailure(
                        f"combined: connection closed mid-stream; "
                        f"decoded {bytes(decoded)!r}"
                    )
                comp_buf.extend(chunk)

        # ---- BINF (plain client outbound; client has not BZON'd yet)
        pid = secrets.token_bytes(24)
        cid = _b32_encode(_tiger.tiger(pid))
        sock.sendall((
            f"BINF {sid} ID{cid} PD{_b32_encode(pid)}"
            f" NIdummy I40.0.0.0 SUTCP4\n"
        ).encode("utf-8"))

        # IGPA arrives compressed (hub outbound is now deflated).
        pump_recv(b"IGPA ")
        idx = decoded.index(b"IGPA ")
        nl = decoded.index(b"\n", idx)
        gpa = decoded[idx:nl].decode("ascii")
        salt = _b32_decode(gpa.split(" ", 1)[1])
        resp = _tiger.tiger(b"test" + salt)
        sock.sendall(f"HPAS {_b32_encode(resp)}\n".encode("utf-8"))

        # Login completes when the hub echoes our BINF.
        pump_recv(f"BINF {sid}".encode("ascii"))

        # Hub sends HGET after login (compressed).
        pump_recv(b"HGET ")
        idx = decoded.index(b"HGET ")
        nl = decoded.index(b"\n", idx)
        hget = decoded[idx:nl].decode("ascii")
        if " blom " not in hget:
            raise TestFailure(
                f"combined: HGET shape wrong (expected blom); got {hget!r}"
            )

        # ---- Switch CLIENT outbound to compression: BZON plain, then
        # all subsequent client bytes are deflate(Z_SYNC_FLUSH). The
        # hub installs inflate on inbound when BZON arrives. After
        # that, the next HSND header + binary blob both pass through
        # the hub's inflate stage. The BLOM HSND handler calls
        # insert_before_terminal(counted), splicing counted BETWEEN
        # inflate and adcline so the binary blob is captured
        # POST-INFLATE (decompressed) - the #192 fix point.
        sock.sendall(f"BZON {sid}\n".encode("utf-8"))

        # SINGLE compressobj for the whole post-BZON client-to-hub
        # stream. The hub's inflate stage holds one zlib state across
        # pushes - a fresh compressobj per message would insert a new
        # zlib prefix mid-stream and crash the inflate state.
        comp = zlib.compressobj()

        # HSND header + filter blob: both compressed together so the
        # hub's inflate sees them as one stream. The hub's HSND
        # dispatch will surface the header, splice counted, and the
        # binary tail (already in adcline's residual post-inflate)
        # gets routed through counted via insert_before_terminal's
        # residual transfer.
        hsnd = f"HSND blom / 0 {BLOM_M // 8}\n".encode("utf-8")
        payload = hsnd + filter_blob
        sock.sendall(
            comp.compress(payload) + comp.flush(zlib.Z_SYNC_FLUSH)
        )

        # Brief settle for the counted-stage callback to install the
        # filter on the user object.
        time.sleep(0.5)

        # ---- hash-search for TTH IN the filter; expect echo.
        # Same compressobj continues the stream.
        tr_in = _b32_encode(in_filter_tth)
        bsch = f"BSCH {sid} TR{tr_in}\n".encode("utf-8")
        sock.sendall(comp.compress(bsch) + comp.flush(zlib.Z_SYNC_FLUSH))
        pump_recv(f"BSCH {sid} TR{tr_in}".encode("ascii"),
                  timeout=PROTOCOL_TIMEOUT_SEC * 2)

        # ---- hash-search for TTH NOT in filter; expect NO echo.
        # If the #192 fix is wrong (counted captured deflated noise),
        # the bloom filter bits are random and the "inserted" TTH
        # search above usually MISSES the filter -> the test fails
        # there. This second assert covers the path where the random
        # bits happen to set the in_filter bit pattern.
        tr_out = _b32_encode(not_in_filter_tth)
        bsch_out = f"BSCH {sid} TR{tr_out}\n".encode("utf-8")
        sock.sendall(comp.compress(bsch_out) + comp.flush(zlib.Z_SYNC_FLUSH))

        # Drain any pending bytes, then wait briefly and assert no
        # echo arrives for tr_out.
        end_drain = time.monotonic() + 1.5
        before = bytes(decoded)
        echo_marker = f"BSCH {sid} ".encode("ascii") + f"TR{tr_out}".encode("ascii")
        while time.monotonic() < end_drain:
            if comp_buf:
                decoded.extend(decomp.decompress(bytes(comp_buf)))
                del comp_buf[:]
            if echo_marker in bytes(decoded):
                raise TestFailure(
                    "combined: hash-search for not-in-filter TTH still "
                    "reached the user; the BLOM filter was not built "
                    "from decompressed bytes (insert_before_terminal "
                    "regression)."
                )
            sock.settimeout(0.3)
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                break
            comp_buf.extend(chunk)
        if comp_buf:
            decoded.extend(decomp.decompress(bytes(comp_buf)))
            del comp_buf[:]
        if echo_marker in bytes(decoded):
            raise TestFailure(
                "combined: not-in-filter TTH was echoed (filter built "
                "from garbage bytes - #192 regression)."
            )

    finally:
        sock.close()


def _switch_to_public_hub_mode(staging_dir: Path, current_proc, current_log_file):
    """#162 setup: stop the hub, flip reg_only to false in cfg.tbl,
    restart. Required so the next test exercises the
    `(not _cfg_reg_only) and adccmd:hasparam "ADPING"` branch in
    core/hub_dispatch.lua's HSUP handler - the branch that ADC pingers
    (hublist scrapers) actually hit. Returns the new (proc, log_file)."""
    stop_hub(current_proc, current_log_file)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    text, n = re.subn(
        r"^\s*reg_only\s*=\s*true\s*,",
        "    reg_only = false,",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if n != 1:
        raise TestFailure(
            "could not flip reg_only to false in cfg.tbl - the setting "
            "line was not found in the staging tree"
        )
    cfg_path.write_text(text, encoding="utf-8")

    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    return proc, log_file


def test_ping_hsup_branch_emits_pingsup_response(staging_dir: Path, proc=None):
    """#162 regression: an ADC pinger sending HSUP with the ADPING flag
    against a public (reg_only=false) hub must receive the PING-IINF
    response from core/hub_dispatch.lua's _protocol.HSUP. Pre-fix the
    HSUP handler hit `pairs( _normalstatesids )` with `pairs` not
    imported into the module locals, raising the sandbox guard and
    silently failing the incoming() function - the pinger saw zero
    frames and timed out.

    Three assertions:
    1. ISUP from the hub advertises ADPING (proves the pinger branch
       at hub_dispatch.lua:220 fired, not the regular non-PING branch).
    2. IINF carries the T1.3 aggregate fields (SS, SF) that are only
       computed inside the buggy pairs() loop.
    3. The hub's error.log gained no `attempt to read undeclared var`
       entries during this connection (would catch the regression even
       if some future change made the pingsup string format-tolerate
       a missing field).
    """
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)

    error_log = staging_dir / "log" / "error.log"
    before = error_log.read_text(encoding="utf-8", errors="replace") if error_log.exists() else ""

    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        sock.sendall(b"HSUP ADBASE ADTIGR ADPING\n")
        reader = _ADCReader(sock)
        try:
            isup = reader.recv_until(lambda f: f.startswith("ISUP "))
            reader.recv_until(lambda f: f.startswith("ISID "))
            iinf = reader.recv_until(lambda f: f.startswith("IINF "))
        except TestFailure as e:
            raise TestFailure(
                f"public hub did not respond to HSUP ADPING (regression "
                f"of #162 'pairs undeclared'); error: {e}"
            ) from e

    if "ADPING" not in isup:
        raise TestFailure(
            f"ISUP did not advertise ADPING - the pinger branch in "
            f"hub_dispatch.lua:220 did not fire. Got: {isup!r}"
        )

    # T1.3 (#147) added SS / SF aggregate fields to the PING-IINF. The
    # SS field on a freshly-started empty hub will be SS0; the
    # regular non-PING IINF does not carry SS at all. Presence of SS
    # is the smoking-gun signal that the aggregator loop ran.
    if " SS" not in iinf:
        raise TestFailure(
            f"PING-IINF did not include the SS aggregate from T1.3 - the "
            f"aggregator loop at hub_dispatch.lua:233 did not run. "
            f"Got: {iinf!r}"
        )

    after = error_log.read_text(encoding="utf-8", errors="replace") if error_log.exists() else ""
    new_lines = after[len(before):]
    if "attempt to read undeclared var" in new_lines:
        raise TestFailure(
            f"hub emitted a sandbox-undeclared-var error during the "
            f"PING handshake (regression of #162). New error.log "
            f"content: {new_lines!r}"
        )


def _ping_uc(host: str, port: int) -> int:
    """Open a fresh connection, run the hublist-pinger HSUP handshake
    (ADPING flag), read the PING-IINF and return its UC field as an int.

    Requires the hub to be in public mode (reg_only=false) - the PING
    branch in hub_dispatch.lua's HSUP handler only fires there. The
    _pingsup template (core/hub.lua) is `... UC%s SS%s SF%s ...`, so UC
    is a space-delimited named param. Capture an optional leading
    minus too, so a #179-style _user_count underflow surfaces as a
    clear "UC=-N" assertion failure rather than a no-match error."""
    with socket.create_connection(
        (host, port), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        sock.sendall(b"HSUP ADBASE ADTIGR ADPING\n")
        reader = _ADCReader(sock)
        reader.recv_until(lambda f: f.startswith("ISUP "))
        reader.recv_until(lambda f: f.startswith("ISID "))
        iinf = reader.recv_until(lambda f: f.startswith("IINF "))
    m = re.search(r"\bUC(-?\d+)\b", iinf)
    if not m:
        raise TestFailure(
            f"PING-IINF carried no UC field; got: {iinf!r}"
        )
    return int(m.group(1))


def test_ping_uc_excludes_bots_empty_hub(staging_dir: Path, proc=None):
    """#179 tier 1: on a freshly-started public hub with zero humans
    connected, PING UC must be 0.

    The hub always runs at least the mandatory hubbot (created via
    regbot -> _normalstatesids) plus the example-cfg RegChat/OpChat
    bots. Pre-fix UC = tablesize(_normalstatesids) counted those bots,
    so an empty hub advertised UC>=1 to hublist scrapers. Post-fix UC =
    _get_user_count() (humans-only) = 0."""
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)
    uc = _ping_uc(HUB_HOST, TEST_PORT_PLAIN)
    if uc != 0:
        raise TestFailure(
            f"empty hub advertised UC={uc} to a hublist pinger; expected "
            f"0. Bots are leaking into the PING user count (#179)."
        )


def test_ping_uc_excludes_bots_one_human(staging_dir: Path, proc=None):
    """#179 tier 2 (the strong one): with exactly one human logged in
    and N bots online, PING UC must be 1, not 1+N.

    Differentiates all three wrong behaviours at once: counts bots
    (UC=1+N), is hard-wired 0 (UC=0), or counts everything. Only the
    correct humans-only counter yields exactly 1."""
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as human:
        sid, _reader = _adc_login(human, "dummy", "test")
        if not sid:
            raise TestFailure("setup login failed; cannot assert UC")
        # Second, independent connection performs the pinger handshake
        # while the human above stays in NORMAL state.
        uc = _ping_uc(HUB_HOST, TEST_PORT_PLAIN)
    if uc != 1:
        raise TestFailure(
            f"one human + bots online but PING UC={uc}; expected exactly "
            f"1. Bots are still inflating the hublist user count (#179)."
        )


def test_ping_uc_survives_reload(staging_dir: Path, proc=None):
    """#179 tier 3: PING UC must stay correct across a +reload.

    +reload -> hub.restartscripts() -> killscripts(), which bot.kill()s
    every bot. Each bot.kill() reaches disconnect()'s
    `if userstate == "normal"` block (bot.state() hard-returns
    "normal") and, without the symmetry guard in core/hub.lua, runs
    `_user_count = _user_count - 1` for an entity that never
    incremented it. Re-created bots take login()'s if-bot branch and
    never re-increment. So pre-guard, one +reload underflows
    _user_count by the bot count and the externally advertised UC goes
    negative/garbage.

    One human (dummy, level 100) stays connected across the reload, so
    the correct post-reload UC is exactly 1."""
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as human:
        sid, reader = _adc_login(human, "dummy", "test")
        if not sid:
            raise TestFailure("setup login failed; cannot assert UC")
        human.sendall(f"BMSG {sid} +reload\n".encode("utf-8"))
        # cmd_reload sends its "Configuration reloaded." confirmation
        # only AFTER hub.restartscripts() has run, so receiving any
        # private reply means killscripts() (the underflow path) is
        # already done.
        reader.recv_until(
            lambda f: f.startswith("EMSG ") or f.startswith("DMSG "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        uc = _ping_uc(HUB_HOST, TEST_PORT_PLAIN)
    if uc != 1:
        raise TestFailure(
            f"after +reload with one human online PING UC={uc}; "
            f"expected exactly 1. _user_count underflowed on bot "
            f"teardown during killscripts() (#179)."
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
    ("S1: fragmented frame reassembled (phase8-io)", test_s1_fragmented_frame_reassembled),
    ("S1: two frames in one segment (phase8-io)", test_s1_two_frames_one_segment),
    ("literal [+!#] bracket hint + no-arg-echo (#137)", test_literal_bracket_command_hint),
    ("BINF without I4/I6 accepted (#161)", test_binf_without_i4_or_i6_accepted),
    ("BINF with both I4 and I6 accepted (#147 T3.1 HBRI)", test_binf_with_both_i4_and_i6_accepted),
    ("post-login INF with I4 silent-stripped (#222)", test_post_login_i4_silent_stripped),
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
    ("post-login DRES/FRES listener chain (#160)", test_post_login_search_result_listener_chain),
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

        # #162 regression test: switch to a public (reg_only=false) hub
        # and verify the ADC PING HSUP branch in hub_dispatch.lua emits
        # ISUP+ADPING and the T1.3 PING-IINF without sandbox errors.
        # Pre-fix, `pairs` was not imported into the dispatcher module
        # so the aggregator loop crashed and pingers saw silent
        # timeouts.
        try:
            proc, log_file = _switch_to_public_hub_mode(
                staging_dir, proc, log_file
            )
            test_ping_hsup_branch_emits_pingsup_response(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  ADC PING HSUP emits pingsup response (#162): {e}")
            failed.append("ADC PING HSUP emits pingsup response (#162)")
        else:
            log("PASS  ADC PING HSUP emits pingsup response (#162)")

        # #179: hublist PING UC must exclude bots. Reuses the public-hub
        # mode left active by the #162 test (no extra restart). Tier 1
        # MUST run first - it asserts an empty hub (no humans connected
        # yet) advertises UC0.
        try:
            test_ping_uc_excludes_bots_empty_hub(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  PING UC excludes bots, empty hub (#179): {e}")
            failed.append("PING UC excludes bots, empty hub (#179)")
        else:
            log("PASS  PING UC excludes bots, empty hub (#179)")

        try:
            test_ping_uc_excludes_bots_one_human(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  PING UC excludes bots, one human (#179): {e}")
            failed.append("PING UC excludes bots, one human (#179)")
        else:
            log("PASS  PING UC excludes bots, one human (#179)")

        try:
            test_ping_uc_survives_reload(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  PING UC survives +reload (#179): {e}")
            failed.append("PING UC survives +reload (#179)")
        else:
            log("PASS  PING UC survives +reload (#179)")

        # #107 dual-stack same-port: flip the v6 ports in cfg.tbl to
        # the same number as the v4 ports and confirm both listeners
        # bind under the new (port, family)-keyed _server registry.
        # Pre-fix the second addserver() call hit the existence check
        # on the port and refused to bind.
        try:
            proc, log_file = _switch_to_dual_stack_same_port_mode(
                staging_dir, proc, log_file
            )
            test_dual_stack_same_port_binds(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  dual-stack same-port binding (#107): {e}")
            failed.append("dual-stack same-port binding (#107)")
        else:
            log("PASS  dual-stack same-port binding (#107)")

        # #231: regression test that the HTTP listener does NOT bind
        # when cfg.tbl http_api_tokens is empty. Flips http_port to
        # the test port, leaves tokens empty, starts hub. Hub writes
        # cfg/api_token.first sample but refuses to bind the listener.
        # This setup also leaves the cfg.tbl in the state expected by
        # _switch_to_http_mode below (http_port + bursts already set).
        try:
            proc, log_file = _switch_to_http_no_tokens_mode(
                staging_dir, proc, log_file
            )
            test_http_no_tokens_means_no_listener(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  http_port set + tokens empty = no listener (#231): {e}")
            failed.append("http_port set + tokens empty = no listener (#231)")
        else:
            log("PASS  http_port set + tokens empty = no listener (#231)")

        # Phase 8 S3 (#82): enable the local HTTP API and exercise the
        # hardened framer + /health router. _switch_to_http_mode now
        # injects the sample token from api_token.first into cfg.tbl
        # http_api_tokens (the operator's documented activation step
        # per #231) before restarting the hub.
        try:
            proc, log_file = _switch_to_http_mode(
                staging_dir, proc, log_file
            )
            test_http_health_roundtrip(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP /health roundtrip + hardening (#82 S3): {e}")
            failed.append("HTTP /health roundtrip + hardening (#82 S3)")
        else:
            log("PASS  HTTP /health roundtrip + hardening (#82 S3)")

        # Phase 1c of #82: the four core read endpoints + rate-limit
        # + per-prefix failed-auth wiring. Shares the same hub
        # instance as the /health roundtrip above (HTTP listener is
        # already up). Idempotency cache semantics are exercised by
        # the unit test (no write endpoint yet to cover smoke-side).
        try:
            test_http_phase1c_endpoints(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 1c endpoints + limits (#82): {e}")
            failed.append("HTTP API Phase 1c endpoints + limits (#82)")
        else:
            log("PASS  HTTP API Phase 1c endpoints + limits (#82)")

        # Phase 2 PR-1 of #82 / #198: cmd_disconnect plugin migrated
        # to DELETE /v1/users/{sid}. Logs in a real ADC user, kicks
        # via HTTP, asserts the ADC connection drops + idempotency
        # cache replays the kick response.
        try:
            test_http_phase2_cmd_disconnect(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 2 cmd_disconnect (#82 / #198): {e}")
            failed.append("HTTP API Phase 2 cmd_disconnect (#82 / #198)")
        else:
            log("PASS  HTTP API Phase 2 cmd_disconnect (#82 / #198)")

        # Phase 2 PR-2 of #82 / #198: cmd_redirect plugin migrated
        # to POST /v1/users/{sid}/redirect. Same hub instance.
        try:
            test_http_phase2_cmd_redirect(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 2 cmd_redirect (#82 / #198): {e}")
            failed.append("HTTP API Phase 2 cmd_redirect (#82 / #198)")
        else:
            log("PASS  HTTP API Phase 2 cmd_redirect (#82 / #198)")

        # Phase 2 PR-3 of #82 / #198: cmd_gag plugin migrated to
        # POST + DELETE /v1/users/{sid}/gag. First plugin migration
        # with persistent state (scripts/data/cmd_gag.tbl).
        try:
            test_http_phase2_cmd_gag(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 2 cmd_gag (#82 / #198): {e}")
            failed.append("HTTP API Phase 2 cmd_gag (#82 / #198)")
        else:
            log("PASS  HTTP API Phase 2 cmd_gag (#82 / #198)")

        # Phase 2 PR-4 of #82 / #198: cmd_ban plugin migrated to
        # /v1/bans, /v1/bans/history, /v1/bans/{id}. Last bundled-
        # plugin migration of Phase 2. Raw hub.http_register (not
        # util_http SID helper) since cmd_ban targets are
        # nick / cid / ip, not a single {sid}.
        try:
            test_http_phase2_cmd_ban(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 2 cmd_ban (#82 / #198): {e}")
            failed.append("HTTP API Phase 2 cmd_ban (#82 / #198)")
        else:
            log("PASS  HTTP API Phase 2 cmd_ban (#82 / #198)")

        # Phase 3 PR-1 of #82 / #225: cmd_restart plugin migrated to
        # POST /v1/restart (X-Confirm required). Rejection-only
        # coverage - firing the restart would tear down the smoke hub
        # before downstream tests can run, so the success path is left
        # to production usage. Shares the HTTP listener that's already
        # up.
        try:
            test_http_phase3_cmd_restart(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 3 cmd_restart (#82 / #225): {e}")
            failed.append("HTTP API Phase 3 cmd_restart (#82 / #225)")
        else:
            log("PASS  HTTP API Phase 3 cmd_restart (#82 / #225)")

        # Phase 3 PR-2 of #82 / #225: cmd_shutdown plugin migrated to
        # POST /v1/shutdown (X-Confirm required). Rejection-only
        # coverage - firing the shutdown would tear down the smoke
        # hub before downstream tests can run. Shares the HTTP
        # listener.
        try:
            test_http_phase3_cmd_shutdown(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 3 cmd_shutdown (#82 / #225): {e}")
            failed.append("HTTP API Phase 3 cmd_shutdown (#82 / #225)")
        else:
            log("PASS  HTTP API Phase 3 cmd_shutdown (#82 / #225)")

        # Phase 3 PR-3 of #82 / #225: cmd_errors plugin migrated to
        # GET /v1/log/error?lines=N. Read-only log-tail endpoint;
        # pattern-setter for PR-4 etc_cmdlog. Shares the HTTP
        # listener.
        try:
            test_http_phase3_cmd_errors(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 3 cmd_errors (#82 / #225): {e}")
            failed.append("HTTP API Phase 3 cmd_errors (#82 / #225)")
        else:
            log("PASS  HTTP API Phase 3 cmd_errors (#82 / #225)")

        # Phase 3 PR-4 of #82 / #225: etc_cmdlog plugin migrated to
        # GET /v1/log/cmd?lines=N. Mirror of PR-3 (cmd_errors).
        try:
            test_http_phase3_etc_cmdlog(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 3 etc_cmdlog (#82 / #225): {e}")
            failed.append("HTTP API Phase 3 etc_cmdlog (#82 / #225)")
        else:
            log("PASS  HTTP API Phase 3 etc_cmdlog (#82 / #225)")

        # Phase 3 PR-5 of #82 / #225: etc_log_cleaner plugin migrated
        # to DELETE /v1/log/{name}. Truncates a log file via the API
        # and verifies the on-disk size. Shares the HTTP listener.
        try:
            test_http_phase3_etc_log_cleaner(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 3 etc_log_cleaner (#82 / #225): {e}")
            failed.append("HTTP API Phase 3 etc_log_cleaner (#82 / #225)")
        else:
            log("PASS  HTTP API Phase 3 etc_log_cleaner (#82 / #225)")

        # Phase 4 PR-1 of #82 / #249: etc_chatlog plugin migrated to
        # GET /v1/chatlog?lines=N. Read scope, tail-style mirror of
        # Phase 3 PR-3 (cmd_errors) over the in-memory chat-history
        # buffer.
        try:
            test_http_phase4_etc_chatlog(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 4 etc_chatlog (#82 / #249): {e}")
            failed.append("HTTP API Phase 4 etc_chatlog (#82 / #249)")
        else:
            log("PASS  HTTP API Phase 4 etc_chatlog (#82 / #249)")

        # #82 deferred Phase-2-spec: cmd_mass migrated to
        # POST /v1/announce. All three scope variants + schema /
        # validator rejects + catalog.
        try:
            test_http_announce(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API cmd_mass (#82): {e}")
            failed.append("HTTP API cmd_mass (#82)")
        else:
            log("PASS  HTTP API cmd_mass (#82)")

        # #82 deferred Phase-2-spec: cmd_topic migrated to
        # POST /v1/topic. Set + reset + schema-reject + catalog.
        # Runs before reload (which clears the topic_tbl state via
        # restartscripts).
        try:
            test_http_topic(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API cmd_topic (#82): {e}")
            failed.append("HTTP API cmd_topic (#82)")
        else:
            log("PASS  HTTP API cmd_topic (#82)")

        # #82 registered-users family PR-1 (#236): cmd_reg migrated to
        # GET / POST /v1/registered + PATCH /v1/registered/{nick}.
        # Pagination + create + duplicate-409 + caller-pw + patch +
        # password-not-leaked + catalog. Runs BEFORE reload so the
        # created users are still in-memory when reload fires (reload
        # asserts route-table survival, not data survival).
        try:
            test_http_registered_users_pr1(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API cmd_reg (#82 / #236 PR-1): {e}")
            failed.append("HTTP API cmd_reg (#82 / #236 PR-1)")
        else:
            log("PASS  HTTP API cmd_reg (#82 / #236 PR-1)")

        # #82 registered-users family PR-2 (#236): cmd_accinfo
        # migrated to GET /v1/registered/{nick}. Requires PR-1's
        # smoke_pr1_a + smoke_pr1_b reg-users to exist in this hub
        # session, so this slot must follow PR-1's test.
        try:
            test_http_registered_get_pr2(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API cmd_accinfo (#82 / #236 PR-2): {e}")
            failed.append("HTTP API cmd_accinfo (#82 / #236 PR-2)")
        else:
            log("PASS  HTTP API cmd_accinfo (#82 / #236 PR-2)")

        # #82 registered-users family PR-3 (#236): cmd_setpass
        # migrated to PUT /v1/registered/{nick}/password.
        try:
            test_http_setpass_pr3(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API cmd_setpass (#82 / #236 PR-3): {e}")
            failed.append("HTTP API cmd_setpass (#82 / #236 PR-3)")
        else:
            log("PASS  HTTP API cmd_setpass (#82 / #236 PR-3)")

        # #82 registered-users family PR-4 (#236): cmd_nickchange
        # migrated to PUT /v1/registered/{nick}/nick. Renames
        # smoke_pr1_b (created by PR-1) so PR-3's smoke_pr1_a is
        # unaffected.
        try:
            test_http_nickchange_pr4(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API cmd_nickchange (#82 / #236 PR-4): {e}")
            failed.append("HTTP API cmd_nickchange (#82 / #236 PR-4)")
        else:
            log("PASS  HTTP API cmd_nickchange (#82 / #236 PR-4)")

        # #82 registered-users family PR-5 (#236): cmd_upgrade
        # migrated to PUT /v1/registered/{nick}/level.
        try:
            test_http_upgrade_pr5(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API cmd_upgrade (#82 / #236 PR-5): {e}")
            failed.append("HTTP API cmd_upgrade (#82 / #236 PR-5)")
        else:
            log("PASS  HTTP API cmd_upgrade (#82 / #236 PR-5)")

        # #82 registered-users family PR-6 (#236): cmd_delreg
        # migrated to DELETE /v1/registered/{nick} with X-Confirm.
        # Targets smoke_pr4_renamed (PR-4 renamed smoke_pr1_b ->
        # smoke_pr4_renamed) so PR-5's smoke_pr1_a stays intact.
        # Last PR of the family; tracker #236 closes after merge.
        try:
            test_http_delreg_pr6(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API cmd_delreg (#82 / #236 PR-6): {e}")
            failed.append("HTTP API cmd_delreg (#82 / #236 PR-6)")
        else:
            log("PASS  HTTP API cmd_delreg (#82 / #236 PR-6)")

        # #239: cmd_ban exported bans table goes stale after the
        # `+ban clear` rebind; cmd_accinfo's import-time bans_tbl
        # snapshot keeps surfacing the old ban entry. Repros via
        # ADC `+ban clear` + GET /v1/registered/{nick}. Runs after
        # the family so smoke_pr1_a still exists.
        try:
            test_239_cmd_ban_stale_bans_ref(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  cmd_ban stale bans ref (#239): {e}")
            failed.append("cmd_ban stale bans ref (#239)")
        else:
            log("PASS  cmd_ban stale bans ref (#239)")

        # #82 deferred Phase-2-spec: cmd_reload migrated to
        # POST /v1/reload (X-Confirm). Exercises both reject + success
        # paths. Placed last in the HTTP suite so reload-fires
        # naturally followed by inf_integer_clamps (which queries
        # /v1/users) acting as a route-survival sanity check.
        try:
            test_http_reload(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API cmd_reload (#82): {e}")
            failed.append("HTTP API cmd_reload (#82)")
        else:
            log("PASS  HTTP API cmd_reload (#82)")

        # Phase 8a F-INF-2 (#219): per-field integer clamps on user
        # accessors. Logs in with poison BINF (SS-1 / SF=10^18 / SL-1
        # / HN/HR/HO out-of-range) and asserts the /v1/users JSON
        # serialisation shows clamped values. Doubles as a Phase 7d
        # (#65) regression guard: login MUST succeed (parser stays
        # permissive). Shares the HTTP listener that's already up.
        try:
            test_inf_integer_clamps(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  F-INF-2 integer clamps on user accessors (#219): {e}")
            failed.append("F-INF-2 integer clamps on user accessors (#219)")
        else:
            log("PASS  F-INF-2 integer clamps on user accessors (#219)")

        # #243: cfg drift - `usr_nick_prefix_activate=true` AND
        # `usr_nick_prefix_prefix_table={}` previously crashed the
        # ADC `+setpass / +nickchange / +upgrade / +delreg` paths
        # on `prefix_table[level]` nil-concat. Family-wide sweep
        # added `or ""` index guards. Runs as a mode-switch since
        # cfg.tbl gets rewritten; subsequent kill_wrong_ips /
        # BLOM / ZLIF tests don't depend on prefix_table content,
        # so they compose fine on top of the cleared table.
        try:
            proc, log_file = _switch_to_partial_prefix_table_mode(
                staging_dir, proc, log_file
            )
            test_243_prefix_table_nil_no_adc_crash(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  prefix_table nil cfg-drift no ADC crash (#243): {e}")
            failed.append("prefix_table nil cfg-drift no ADC crash (#243)")
        else:
            log("PASS  prefix_table nil cfg-drift no ADC crash (#243)")

        # #214 Gap 2: flip kill_wrong_ips=false (the NAT-weird opt-out)
        # and verify the hub stamps the verified userip over a
        # mismatched primary-IP claim before broadcasting the BINF.
        # Falsifiable: pre-#214 the lie was forwarded as-is. The
        # cfg flip persists for subsequent tests, which is fine -
        # no currently-registered downstream test sends a mismatching
        # primary-IP claim from 127.0.0.1, so the opt-out has no
        # observable effect on BLOM / ZLIF / combined / hub_listen.
        try:
            proc, log_file = _switch_to_kill_wrong_ips_off_mode(
                staging_dir, proc, log_file
            )
            test_kill_wrong_ips_off_stamps_userip(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  kill_wrong_ips=false stamps userip (#214 Gap 2): {e}")
            failed.append("kill_wrong_ips=false stamps userip (#214 Gap 2)")
        else:
            log("PASS  kill_wrong_ips=false stamps userip (#214 Gap 2)")

        # Phase 8 S5 (#147 T2.2): enable BLOM and exercise hash-search
        # routing + the keyword-search broadcast regression. Runs
        # BEFORE the ZLIF tests so BLOM does not have to coexist
        # with hub-side outbound deflate (which would force the test
        # client to inflate the HGET frame).
        try:
            proc, log_file = _switch_to_blom_mode(
                staging_dir, proc, log_file
            )
            test_blom_roundtrip(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  BLOM hash-search routing roundtrip (#147 T2.2): {e}")
            failed.append("BLOM hash-search routing roundtrip (#147 T2.2)")
        else:
            log("PASS  BLOM hash-search routing roundtrip (#147 T2.2)")

        # Phase 8 S4b (#147 T3.2): flip zlif_enabled on, run a full
        # ADC login + +help reply over zlib-compressed inbound. Last
        # test because the cfg mutation is non-trivial and no later
        # test should depend on the post-ZLIF hub state.
        try:
            proc, log_file = _switch_to_zlif_mode(
                staging_dir, proc, log_file
            )
            test_zlif_roundtrip(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  ZLIF stream compression roundtrip (#147 T3.2): {e}")
            failed.append("ZLIF stream compression roundtrip (#147 T3.2)")
        else:
            log("PASS  ZLIF stream compression roundtrip (#147 T3.2)")

        # Security review B1 follow-up: pre-HSUP BZON must be rejected
        # with ISTA 240, not silently install the inflate stage on an
        # un-identified peer.
        try:
            test_zlif_pre_hsup_zon_rejected(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  ZLIF pre-HSUP ZON rejected (S4b B1): {e}")
            failed.append("ZLIF pre-HSUP ZON rejected (S4b B1)")
        else:
            log("PASS  ZLIF pre-HSUP ZON rejected (S4b B1)")

        # #192 combined-mode regression: with both blom_enabled=true
        # and zlif_enabled=true (the persistent post-ZLIF cfg state)
        # the hub MUST splice the BLOM counted-binary capture BEFORE
        # the ADC-line framer (i.e. AFTER inflate). Pre-fix the
        # counted stage was prepended and saw raw deflated bytes,
        # producing a corrupt filter -> false-negative routing.
        try:
            test_blom_zlif_combined(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  BLOM+ZLIF combined-mode routing (#192): {e}")
            failed.append("BLOM+ZLIF combined-mode routing (#192)")
        else:
            log("PASS  BLOM+ZLIF combined-mode routing (#192)")

        # #186: hub_listen must actually restrict the bind address
        # (last test - mutates hub_listen + blanks v6; nothing after).
        try:
            proc, log_file = _switch_to_hub_listen_loopback_mode(
                staging_dir, proc, log_file
            )
            test_hub_listen_honored(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  hub_listen honored / loopback-only (#186): {e}")
            failed.append("hub_listen honored / loopback-only (#186)")
        else:
            log("PASS  hub_listen honored / loopback-only (#186)")
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
