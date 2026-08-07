#!/usr/bin/env python3
"""Decrypt / re-encrypt the at-rest-encrypted ``cfg/user.tbl`` offline.

Since Phase 7f (F-AUTH-1) luadch writes ``cfg/user.tbl`` as an AES-256-GCM
blob under the host-bound key ``cfg/master.key`` (see docs/SECURITY.md). The
file is NOT a SQLite database - it never was; it is a Lua table
(``return { ... }``) that used to be plain text and is now encrypted. So a
SQLite GUI (DB Browser) cannot open it, and there is no "password" - the
secret is the 32-byte key file.

This standalone tool lets an operator inspect or edit that database offline,
without running the hub, given the matching ``master.key``:

    # look at it / recover an account
    python tools/usertbl.py decrypt cfg/user.tbl cfg/master.key -o user.plain.lua

    # ... edit user.plain.lua in any text editor (it is plain Lua) ...

    # write it back
    python tools/usertbl.py encrypt user.plain.lua cfg/master.key -o cfg/user.tbl

IMPORTANT
  - STOP THE HUB FIRST. A running hub holds user.tbl in RAM and rewrites it
    from that copy on the next save, silently clobbering your offline edit.
  - The plaintext contains password-equivalent secrets (ADC BASE stores
    Tiger(pw+salt); cleartext-equivalent at rest is protocol-mandated - see
    docs/SECURITY.md). Treat user.plain.lua and master.key like the TLS
    private key: 0600, delete the plaintext when done.
  - master.key and the user.tbl it sealed are a MATCHED PAIR. Back them up
    TOGETHER. An old user.tbl snapshot without its contemporaneous key is
    unrecoverable by design (that is the whole point of the scheme).
  - If you would rather not use encryption at all, set ``encrypt_usertbl =
    false`` in cfg/cfg.tbl and reload - the hub then writes plaintext Lua and
    no key is needed (docs/SECURITY.md, "Operator opt-out"). This tool is for
    operators who keep encryption ON.

Wire format (must match core/cfg_secret.lua):

    offset  bytes
      0     4    magic "LDC1"
      4    12    nonce (96-bit, fresh per write)
     16    N    ciphertext
   16+N   16    GCM authentication tag (appended AFTER the ciphertext)

The 32-byte master.key is used DIRECTLY as the AES-256 key (no KDF, no salt,
no AAD).

Dependency: the ``cryptography`` package (``pip install cryptography``); the
Python standard library ships no AES. Exit code 0 = success, 1 = failure.
"""

import argparse
import os
import sys

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.stderr.write(
        "error: the 'cryptography' package is required.\n"
        "       install it with:  pip install cryptography\n"
    )
    sys.exit(1)

MAGIC = b"LDC1"
KEY_SIZE = 32     # AES-256
NONCE_SIZE = 12   # GCM 96-bit nonce
TAG_SIZE = 16     # GCM 128-bit tag
MIN_BLOB = len(MAGIC) + NONCE_SIZE + TAG_SIZE


def _die(msg):
    sys.stderr.write("error: " + msg + "\n")
    sys.exit(1)


def _read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        _die("cannot read %s: %s" % (path, e))


def _load_key(path):
    key = _read(path)
    if len(key) != KEY_SIZE:
        _die(
            "%s is %d bytes, expected exactly %d. This is not a valid "
            "master.key." % (path, len(key), KEY_SIZE)
        )
    return key


def _write_out(data, out_path, default_stream, binary):
    """Write to out_path, or to default_stream when out_path is None."""
    if out_path is None:
        if binary:
            default_stream.buffer.write(data)
        else:
            default_stream.write(data.decode("utf-8", "replace"))
        return
    # Overwriting the canonical user.tbl is the operator's deliberate call,
    # so we allow it - but never clobber silently; warn on stderr first.
    if os.path.exists(out_path):
        sys.stderr.write("note: overwriting existing %s\n" % out_path)
    # Create the output at 0600 on POSIX. The decrypted plaintext is
    # password-equivalent (and a re-sealed user.tbl the hub keeps at 0600), so
    # it must not be group/world-readable even for the brief edit window - this
    # matches cfg_secret's chmod-600 discipline for exactly these files.
    # os.open honors the mode on create; fchmod also tightens an existing
    # looser target. Windows ignores the POSIX mode (no fchmod) - rely on the
    # icacls guidance in docs/SECURITY.md there.
    try:
        fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except OSError as e:
        _die("cannot write %s: %s" % (out_path, e))


def cmd_decrypt(args):
    key = _load_key(args.keyfile)
    blob = _read(args.infile)
    if len(blob) < MIN_BLOB or blob[:len(MAGIC)] != MAGIC:
        _die(
            "%s is not an LDC1 encrypted blob. If it already starts with "
            "'return {' it is plaintext already - just open it in an editor."
            % args.infile
        )
    nonce = blob[len(MAGIC):len(MAGIC) + NONCE_SIZE]
    ct = blob[len(MAGIC) + NONCE_SIZE:]
    try:
        plaintext = AESGCM(key).decrypt(nonce, ct, None)
    except InvalidTag:
        _die(
            "decryption failed (InvalidTag): this master.key does not match "
            "%s (wrong key or corrupt file). A key file NEWER than the "
            "user.tbl it should open cannot have sealed it." % args.infile
        )
    _write_out(plaintext, args.output, sys.stdout, binary=False)
    if args.output:
        sys.stderr.write("decrypted %s -> %s (%d bytes)\n"
                         % (args.infile, args.output, len(plaintext)))


def cmd_encrypt(args):
    key = _load_key(args.keyfile)
    plaintext = _read(args.infile)
    if args.output is None:
        _die("encrypt needs -o/--output (won't dump a binary blob to the "
             "terminal). Point it at cfg/user.tbl.")
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)  # ct||tag
    blob = MAGIC + nonce + ct
    _write_out(blob, args.output, sys.stdout, binary=True)
    sys.stderr.write("encrypted %s -> %s (%d bytes)\n"
                     % (args.infile, args.output, len(blob)))


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="usertbl.py",
        description="Decrypt / re-encrypt luadch's at-rest user.tbl offline.",
        epilog="STOP THE HUB before editing; treat the plaintext and "
               "master.key like the TLS private key. See the module docstring "
               "and docs/SECURITY.md.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decrypt", help="LDC1 blob -> plaintext Lua")
    d.add_argument("infile", help="encrypted user.tbl (LDC1 blob)")
    d.add_argument("keyfile", help="matching master.key (32 raw bytes)")
    d.add_argument("-o", "--output",
                   help="write plaintext here (default: stdout)")
    d.set_defaults(func=cmd_decrypt)

    e = sub.add_parser("encrypt", help="plaintext Lua -> LDC1 blob")
    e.add_argument("infile", help="plaintext user.tbl (Lua source)")
    e.add_argument("keyfile", help="master.key to seal under (32 raw bytes)")
    e.add_argument("-o", "--output", help="write the LDC1 blob here (required)")
    e.set_defaults(func=cmd_encrypt)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
