# Security model

This document describes the security boundaries luadch enforces, the
trust assumptions it makes about its operating environment, and the
design rationale behind the at-rest data protections introduced in
the Phase 7 security audit.

It is the authoritative reference for operators deciding how to deploy
luadch and for contributors reviewing security-relevant changes. The
detailed audit findings live in
[`docs/phases/PHASE_7_FINDINGS.md`](phases/PHASE_7_FINDINGS.md).

---

## 1. Threat model

The hub serves untrusted ADC clients on the public internet. The
classes of attacker we defend against:

| Attacker | Capability | Defended against? |
|---|---|---|
| Network attacker | Can send arbitrary bytes to the listening ports | yes |
| Authenticated user | Has valid credentials, opens a normal session | yes |
| Backup thief | Reads `cfg/`, `certs/` from a snapshot or unprotected backup, no host access | yes |
| World-readable share | Hub data ends up on a misconfigured Samba / NFS / Dropbox mount | yes |
| Local file-write | Has filesystem write to `cfg/` but no shell on the host | partially (RCE eliminated; file-tamper still causes load-fail) |
| Host-level RCE / shell | Can read process memory, exec arbitrary code | **no** |
| Plugin author | Writes a malicious script and the operator installs it | **no** (see §2) |

The "host-level RCE" row is the one that matters most: ADC's password
challenge protocol forces the hub to keep a password-equivalent secret
in process memory while the hub runs (see §3). Anyone who breaks out
of the host's OS-level isolation can read it. The same trade-off
applies to Firefox's primary password, Telegram's local DB, and Apple
Keychain in its unlocked state. We accept it as a protocol constraint.

---

## 2. Plugin trust contract

Plugins under [`scripts/`](../scripts/) are **trusted by design**.

[`core/scripts.lua`](../core/scripts.lua) builds each plugin's `_ENV`
by copying every entry of the global table. Plugins have direct
access to `os`, `io`, `debug`, `package`, `load*`, `require`, the
file system, and the ability to spawn subprocesses. The
`cfg.no_global_scripting` setting only adds an
error-on-undeclared-globals metatable; it does **not** restrict the
library surface.

This is intentional. Plugins are part of the hub's privileged code
base; the boundary is between "operator-installed plugin" and
"untrusted ADC client", not between "plugin" and "core".

**Operator responsibilities:**

1. Audit every plugin you install. Read the source. Do not pull
   plugins from random forums.
2. Treat the `scripts/` directory like the rest of the hub binary:
   write-protect it from non-admin users on the host.
3. A compromised plugin trivially exfiltrates `cfg/master.key`,
   `certs/serverkey.pem`, and the in-RAM cleartext of `user.tbl`. No
   in-hub mechanism prevents that.

The corresponding audit finding is
[F-SAND-1](phases/PHASE_7_FINDINGS.md) (info-level; documented, not
"fixed" because tightening the sandbox would break the existing
plugin ecosystem).

---

## 3. Password storage and the ADC `BASE` constraint

luadch implements the ADC `BASE` extension's HPAS challenge-response:

```
Server: IGPA <fresh_per_login_salt>
Client: HPAS base32(Tiger(password || salt))
Server: must compute Tiger(stored, salt) and match
```

For the server's hash to match the client's, **the stored value must
equal the client's password input**. Any one-way KDF (Argon2id,
bcrypt, scrypt, PBKDF2) makes the server unable to produce the same
Tiger output, so login breaks. This constraint is shared by the
entire ADC ecosystem (ADCH++ stores cleartext in XML, uHub in
`users.conf`, …) and there is no published ADC extension that lifts
it. The audit research is recorded in issue
[#52](https://github.com/luadch-ng/luadch/issues/52).

### What luadch actually does

1. **In RAM, while the hub runs:** plaintext passwords are present as
   field values on each registered user's profile object. There is
   no way around this within standard ADC.
2. **On disk:** `cfg/user.tbl` is AES-256-GCM encrypted under a
   host-bound master key (Phase 7f, [F-AUTH-1](phases/PHASE_7_FINDINGS.md)).

### Wire format on disk

```
offset  bytes
  0     4    magic "LDC1"
  4    12    nonce (96-bit, fresh per write via OpenSSL RAND_bytes)
 16    N     ciphertext
16+N   16    GCM authentication tag
```

GCM authentication is the security-critical signal: a tampered file
fails the tag check and `loadusers` returns an error. The hub does
not silently accept tampered input.

### Master key

- **Default path:** `cfg/master.key` (set the `master_key_path` cfg
  key to override; see "Backup separation" below)
- **Size:** 32 raw bytes (AES-256)
- **Generation:** automatic on first boot via OpenSSL `RAND_bytes`
- **POSIX permissions:** `chmod 600`. The hub **refuses to start** if
  the existing key file has any other mode (modeled on OpenSSH's
  `~/.ssh/id_rsa` strict-mode check).
- **Windows permissions:** see §4 below.

### Backup separation - **required for the encryption to be meaningful**

The default `cfg/master.key` location was chosen for first-boot
convenience and backwards compatibility, **not** for production
security. With the default, a routine
`tar czf backup.tar.gz cfg/` bundles **both** the encrypted
`user.tbl` AND its decryption key into one archive. An attacker who
exfiltrates that backup decrypts everything offline; the at-rest
encryption provides zero protection in that scenario.

For production deployments, set the `master_key_path` cfg key in
`cfg/cfg.tbl` to an absolute path **outside** the install directory:

```lua
master_key_path = "/etc/luadch/master.key"            -- POSIX
master_key_path = "C:/ProgramData/luadch/master.key"  -- Windows
```

Then handle that path the same way you handle
`certs/serverkey.pem`:

- exclude it from the routine `cfg/` backup, or
- back it up to a separate destination (different host, different
  storage tier, or pass-phrase-encrypted archive).

The hub still enforces 0600 on the configured path on POSIX. On
Windows, apply `icacls` to the new path - see §4.

### What the on-disk encryption protects against

- Backup / snapshot exfiltration of `cfg/` without the host - **only
  if `master_key_path` points outside `cfg/` per the section above**
- World-readable `cfg/user.tbl` from a default umask
- File-system-only read primitive (read-only mount, share, lost
  laptop, …)

### What it does NOT protect against

- On-host RCE / Lua-sandbox escape (see §1, §2)
- Plugin compromise (see §2)
- Master-key file theft. If the attacker exfiltrates both
  `cfg/master.key` and `cfg/user.tbl`, they have all the credentials.

OS-bound key wrapping (TPM, DPAPI machine-scope, libsecret, macOS
Keychain) would harden the master-key-theft case and is tracked as a
Phase 8+ candidate in
[#48](https://github.com/luadch-ng/luadch/issues/48).

---

## 4. File-permission baseline

The hub automatically `chmod 600`s every secret file it writes on
POSIX (Phase 7b,
[F-SEC-1](phases/PHASE_7_FINDINGS.md)). That covers:

- `cfg/user.tbl` (registered-user database, encrypted blob)
- `cfg/user.tbl.bak`
- `cfg/master.key`
- `certs/serverkey.pem` and `certs/cakey.pem` are 0600'd by
  `examples/certs/make_cert.sh` at generation time.

### Linux / BSD - one-time migration

Existing deployments that pre-date Phase 7b should run once:

```sh
chmod 600 cfg/user.tbl cfg/user.tbl.bak certs/serverkey.pem certs/cakey.pem
# master.key is created by Phase 7f and ships pre-chmod'd. If you
# moved it via master_key_path, chmod that path too.
```

### Windows - manual ACL setup

NTFS does not have POSIX permission bits, so the hub does not
attempt to enforce permissions automatically. After install, run:

```cmd
icacls "cfg\user.tbl"           /inheritance:r /grant:r "%USERNAME%:F"
icacls "cfg\user.tbl.bak"       /inheritance:r /grant:r "%USERNAME%:F"
icacls "cfg\master.key"         /inheritance:r /grant:r "%USERNAME%:F"
icacls "certs\serverkey.pem"    /inheritance:r /grant:r "%USERNAME%:F"
icacls "certs\cakey.pem"        /inheritance:r /grant:r "%USERNAME%:F"
```

Replace `%USERNAME%` with the dedicated service account if the hub
runs as `LocalService` or similar. If `master_key_path` points to a
different location (e.g. `C:\ProgramData\luadch\master.key`), apply
the same `icacls` line there. The same recipe lives in
[`docs/BUILDING.md`](BUILDING.md).

---

## 5. Network-level defenses

| Defense | Where | Tunable via cfg |
|---|---|---|
| Per-IP parallel-socket cap | [`core/server.lua` accept](../core/server.lua) | `ratelimit_perip_max_conns` (default 16) |
| Per-IP accept-rate cap | same | `ratelimit_perip_conn_rate` / `_burst` |
| TLS handshake wallclock deadline | same | `ratelimit_handshake_timeout` (default 10s) |
| Per-IP failed-auth tracking + sticky lockout | [`core/hub_dispatch.lua` HPAS](../core/hub_dispatch.lua) | `ratelimit_perip_authfail_*`, `ratelimit_authfail_lockout` |
| Per-account bad-password lockout (independent of per-IP) | same | `max_bad_password`, `bad_pass_timeout` |
| Per-user chat / search rate-limit | [`core/hub_dispatch.lua` BMSG/BSCH](../core/hub_dispatch.lua) | `ratelimit_user_msg_*`, `ratelimit_user_search_*` |
| Op-level bypass of per-user limits | same | `ratelimit_bypass_level` (default 60) |
| Parser-side message-size cap | [`core/adc.lua` parse](../core/adc.lua) | hardcoded 64 KiB |
| Connection read-buffer cap | [`core/server.lua`](../core/server.lua) | hardcoded 1 MiB |
| INF-IP consistency check (kick on TCP-source vs INF-claim mismatch) | [`core/hub_dispatch.lua` BINF](../core/hub_dispatch.lua) + [`scripts/hub_inf_manager.lua`](../scripts/hub_inf_manager.lua) | `kill_wrong_ips` (default **true** since v3.1.4) |

The full DoS-hardening rationale is in Phase 7c
([#56](https://github.com/luadch-ng/luadch/issues/56)).

### `kill_wrong_ips` operator note ([#97](https://github.com/luadch-ng/luadch/issues/97))

The `kill_wrong_ips` default flipped from `false` to `true` in v3.1.4:
a connecting client whose INF advertises an `I4` / `I6` value
different from the TCP source IP is now disconnected. Same check
fires on `onInf` updates in normal state via
[`scripts/hub_inf_manager.lua`](../scripts/hub_inf_manager.lua) -
post-login a user cannot re-stamp their advertised IP either.

The legitimate **passive-mode `I40.0.0.0`** case is handled before
the kill check (the hub fills in the real IP at
[`core/hub_dispatch.lua`](../core/hub_dispatch.lua)), so passive
clients are unaffected.

**When to opt out (`kill_wrong_ips = false`):** deployments where
clients legitimately advertise an IP different from the TCP source.
Mostly:

- users behind symmetric NAT or carrier-grade NAT (CGNAT) where the
  client cannot determine its public IP and falls back to a stale
  cached value
- bridged / dual-stack setups where the user's own selection of
  `I4` vs `I6` does not match what the kernel chose for the
  outbound TCP connection
- corporate proxies / TLS-terminating reverse proxies in front of
  the hub that rewrite the source IP

The cost of opting out: per-IP rate limits, GeoIP / unified
blocklist matches, abuse logs, and any plugin reading
`user:ip()` operate on the **TCP source IP** anyway, so the check
is purely defence-in-depth against IP-spoofing INFs - the rest of
the stack stays sound.

---

## 6. TLS configuration

luadch supports plain ADC and TLS-wrapped ADCS in parallel. Default
TLS configuration in [`core/cfg_defaults.lua`](../core/cfg_defaults.lua):

- Protocol: TLS 1.3 (`tlsv1_3`)
- Cipher list: `"HIGH"`
- Disabled: SSLv2, SSLv3
- Peer-cert verify: off (correct for the server-side ADC role -
  clients are unauthenticated at the TLS layer; auth happens at the
  ADC HPAS layer)

The ADC `KEYP` extension lets clients pin the hub's TLS certificate
fingerprint; operators can publish their fingerprint via the
`+hubinfo` command and clients that support `KEYP` will reject
mismatching certs.

---

## 7. CVE / dependency tracking

luadch bundles all native dependencies as source. Operators should
subscribe to upstream releases:

- [Lua](https://www.lua.org/versions.html) - currently 5.4.8
- [LuaSec](https://github.com/lunarmodules/luasec) - currently 1.3.2
- [LuaSocket](https://github.com/lunarmodules/luasocket) - currently 3.1.0
- [aiq/basexx](https://github.com/aiq/basexx) - vendored from
  v0.4.1, upstream essentially abandoned
- [OpenSSL](https://github.com/openssl/openssl) - linked dynamically;
  `find_package(OpenSSL 3.0 REQUIRED)` enforces the floor

Quarterly checklist: query
[osv.dev](https://osv.dev) and the GitHub Advisory Database for each
of the above. Record the bundled SHA / version of every dep in
[`docs/BUILDING.md`](BUILDING.md) so audits compare to a written
truth, not to greps.

---

## 8. Reporting a security issue

Open a private security advisory at
<https://github.com/luadch-ng/luadch/security/advisories/new> rather
than a public issue, especially for issues that:

- enable RCE without prior authentication
- bypass auth or login throttling
- leak `master.key`, plaintext credentials, or TLS keys

Public issues are fine for findings that are already documented in
[`docs/phases/PHASE_7_FINDINGS.md`](phases/PHASE_7_FINDINGS.md) or
that require operator misconfiguration to exploit (e.g. a
world-readable `master.key` because the operator skipped §4).

---

## 9. Audit history

| Phase | Scope | Doc |
|---|---|---|
| Phase 7a | Read-only audit of every surface listed in [`CLAUDE.md`](../CLAUDE.md) §5 Phase 7 | [`docs/phases/PHASE_7_FINDINGS.md`](phases/PHASE_7_FINDINGS.md) |
| Phase 7b - 7g | Each finding either fixed or filed with a documented disposition | [`docs/phases/PHASE_7_FINDINGS.md`](phases/PHASE_7_FINDINGS.md) §5 |

A future phase may re-audit. Until then, this file plus
`PHASE_7_FINDINGS.md` is the security baseline for v3.0.x.
