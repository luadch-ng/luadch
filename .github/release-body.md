# Luadch v3.1.0

Phase 6 (refactor + smoke harness) and Phase 7 (security audit + hardening)
of the modernisation programme. Drop-in upgrade from v3.0.0.

## Highlights

- **AES-256-GCM at-rest encryption** of `cfg/user.tbl` with auto-managed
  master key + configurable `master_key_path` for backup separation
- **DoS hardening**: per-IP / per-user rate limits, TLS handshake deadline,
  per-IP failed-auth lockout (new `core/ratelimit.lua`)
- **Sandboxed config / state loaders**: tampered `.tbl` files cannot
  achieve RCE
- **ADC parser hardening**: control-byte rejection, reentrant `parse()`,
  64 KiB command-size cap
- **POSIX file-permission enforcement** on every secret file;
  chmod-or-die boot check on `master.key`
- **CSPRNG salts** via OpenSSL `RAND_bytes`; bundled Lua **5.4.7 → 5.4.8**
- **`core/cfg.lua` and `core/hub.lua` decomposed** into focused modules
  under a 1500-line ceiling (Phase 6c-d)
- **Comprehensive security audit** (Phase 7): 24 findings filed, 22 fixed;
  see [`docs/SECURITY.md`](https://github.com/luadch-ng/luadch/blob/v3.1.0/docs/SECURITY.md)
  and [`docs/phases/PHASE_7_FINDINGS.md`](https://github.com/luadch-ng/luadch/blob/v3.1.0/docs/phases/PHASE_7_FINDINGS.md)
- **CI smoke harness** extended from 7 to 10 protocol-level tests
  (handshake, login, +cmd routing, CSPRNG-salt-uniqueness, per-IP cap,
  encryption-at-rest, no-script-errors), green on Linux + Windows

## Downloads

| File | Platform |
|---|---|
| `luadch-v3.1.0-linux-x86_64.tar.gz` | Linux glibc x86_64 |
| `luadch-v3.1.0-windows-x86_64.zip`  | Windows x86_64 (MinGW UCRT64) |

Extract anywhere and run `./luadch` (Linux) or `Luadch.exe` (Windows). The
trees are self-contained: Lua interpreter, all bundled libs (LuaSec,
LuaSocket, basexx, adclib), default configs, scripts, certs helpers.

Default plain ADC port `5000`, TLS port `5001` after running
`certs/make_cert.{sh,bat}` once. First login: nick `dummy`, password
`test` - **delete that account immediately** after registering yourself,
see [`docs/CONFIGURATION.md`](https://github.com/luadch-ng/luadch/blob/v3.1.0/docs/CONFIGURATION.md).

## Migration from v3.0.0

No breaking changes for operators on default cfg. Existing `cfg/user.tbl`
is transparently migrated to the encrypted-at-rest format on the first
post-login save after upgrade.

**Strongly recommended** before putting real users into `user.tbl`:

1. Read [`docs/SECURITY.md`](https://github.com/luadch-ng/luadch/blob/v3.1.0/docs/SECURITY.md)
   §3 "Backup separation".
2. Set `master_key_path` in `cfg/cfg.tbl` to an absolute path **outside**
   the install directory:

   ```lua
   master_key_path = "/etc/luadch/master.key"            -- POSIX
   master_key_path = "C:/ProgramData/luadch/master.key"  -- Windows
   ```

   Otherwise a routine `tar czf backup.tar.gz cfg/` bundles the
   encrypted user database AND its decryption key into the same
   archive, and the at-rest encryption provides zero protection
   against backup theft.
3. Move the existing `cfg/master.key` (if first-boot already generated
   one) to the new path, ensure mode 0600 on POSIX (or `icacls` on
   Windows), and restart.

Existing world-readable secrets - one-time fix on POSIX:

```sh
chmod 600 cfg/user.tbl cfg/user.tbl.bak certs/serverkey.pem certs/cakey.pem
```

Windows `icacls` recipe in [`docs/BUILDING.md`](https://github.com/luadch-ng/luadch/blob/v3.1.0/docs/BUILDING.md)
and [`docs/SECURITY.md`](https://github.com/luadch-ng/luadch/blob/v3.1.0/docs/SECURITY.md) §4.

## Full changelog

See [`CHANGELOG.md`](https://github.com/luadch-ng/luadch/blob/v3.1.0/CHANGELOG.md)
for the complete categorised list. Phase journals in
[`docs/phases/PHASE_6.md`](https://github.com/luadch-ng/luadch/blob/v3.1.0/docs/phases/PHASE_6.md)
and [`docs/phases/PHASE_7.md`](https://github.com/luadch-ng/luadch/blob/v3.1.0/docs/phases/PHASE_7.md).

## Build from source

The pipeline is identical on every supported platform:

```sh
git clone --branch v3.1.0 https://github.com/luadch-ng/luadch.git
cd luadch
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
cmake --install build
```

Output lands in `build/install/luadch/` ready to run. Windows needs
`-G "MinGW Makefiles" -DOPENSSL_ROOT_DIR=...` extra, see
[`docs/BUILDING.md`](https://github.com/luadch-ng/luadch/blob/v3.1.0/docs/BUILDING.md).

## Credits

All conceptual credit to **blastbeat** and **pulsar**, original authors of
luadch. This fork modernises and extends their excellent foundation.
