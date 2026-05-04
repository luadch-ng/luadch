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
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path


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
