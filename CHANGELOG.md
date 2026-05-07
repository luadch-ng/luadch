# Changelog

All notable changes to the `luadch-ng/luadch` fork are documented here.
The repo lived at `Aybook/luadch` before the v3.1.x line; auto-redirects
handle historic links.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The upstream project (`luadch/luadch`) is a separate codebase; its release
history is at https://github.com/luadch/luadch/releases.

## [v3.1.3] - 2026-05-07

Security patch on top of v3.1.2. Drop-in upgrade; no cfg / on-disk-format changes. Smoke 12/12 PASS on Linux + Windows.

### Bugfixes

- [#91](https://github.com/luadch-ng/luadch/issues/91) - Pre-auth DoS via reg_only nick collision (HPAS-gated takeover)
- [#92](https://github.com/luadch-ng/luadch/issues/92) - Encrypted `user.tbl` bypass in `cmd_setpass` / `cmd_nickchange` / `cmd_upgrade`
- [#93](https://github.com/luadch-ng/luadch/issues/93) - `master_key_path` POSIX shell-quoting in `cfg_secret`
- [#94](https://github.com/luadch-ng/luadch/issues/94) - Failed-auth state pollution in HPAS handler
- [#96](https://github.com/luadch-ng/luadch/issues/96) - `etc_cmdlog` redacts password-bearing arguments via new `etc_cmdlog_redact_args` cfg key

### Notes

- Smoke regression test added for #92 (`test_setpass_preserves_encryption`)
- Deferred to Phase-8 hardening: [#95](https://github.com/luadch-ng/luadch/issues/95), [#97](https://github.com/luadch-ng/luadch/issues/97)
- Audit meta tracker: [#98](https://github.com/luadch-ng/luadch/issues/98)

[v3.1.3]: https://github.com/luadch-ng/luadch/releases/tag/v3.1.3


## [v3.1.2] - 2026-05-06

Patch release. Drop-in upgrade from v3.1.1; no cfg / on-disk-format
changes, no Lua API changes. Single fix: bundled LuaSocket / LuaSec
now install in the canonical layout so plugins doing
`require "socket.http"` / `require "ssl.https"` load drop-in.

### Fixed

- **Canonical LuaSocket / LuaSec install layout** (closes
  [#88](https://github.com/luadch-ng/luadch/issues/88)). The Lua-side
  helpers were installed flat under `lib/luasocket/lua/` and
  `lib/luasec/lua/`, which broke `require "socket.http"` and
  `require "ssl.https"` for plugins. Even calling `require "http"`
  directly didn't help because `http.lua`'s own internal
  `require "socket.url"` and `require "socket.headers"` hit the same
  wall. Split the CMake `install(FILES ...)` rules so entrypoints
  (`socket.lua`, `mime.lua`, `ltn12.lua`, `mbox.lua`, `ssl.lua`) stay
  top-level and `socket.X` / `ssl.X` submodules go into nested
  subdirectories. Source files unchanged; hub-internal usage
  (`use "socket"`, `use "ssl"` only) unaffected. Unblocks the
  [`luadch-ng/scripts ptx_RSSFeedWatch`](https://github.com/luadch-ng/scripts)
  plugin and any future HTTP-using plugin.

### Added

- **Smoke regression test** for the canonical layout
  (`tests/smoke/run.py:test_canonical_socket_layout`). Static
  path-exists check on the LuaSocket / LuaSec submodule paths; if a
  future CMake change drifts back to the flat bundling, the smoke
  gate fires. Smoke harness now runs 11 protocol-level + state-of-disk
  tests (was 10).

[v3.1.2]: https://github.com/luadch-ng/luadch/releases/tag/v3.1.2


## [v3.1.1] - 2026-05-05

Patch release. Drop-in upgrade from v3.1.0; no cfg / on-disk-format changes,
no Lua API changes, smoke harness still 10 / 10. Two upstream-issue triage
rounds plus a small post-modernisation cleanup landed since v3.1.0.

### Fixed

- **DSCH search fanout** (closes upstream
  [luadch#200](https://github.com/luadch/luadch/issues/200), security).
  `etc_trafficmanager.lua` `onSearch` was fanning out direct (D / E type)
  searches to every user; receivers logged a `SECURITY WARNING: received
  a DSCH message that should have been sent to a different user.` for
  every cross-addressed message. The hub's default direct-routing path
  already delivers correctly to the single intended SID; the fan-out was
  redundant and protocol-violating. Same root cause as upstream
  [luadch#226](https://github.com/luadch/luadch/issues/226) (AirDC++ 4.21
  "search spam detected (severe)" disconnects).
- **Negative DS in INF blocked login** (closes upstream
  [luadch#241](https://github.com/luadch/luadch/issues/241)).
  `_regex.integer` now accepts signed decimals (`^%-?%d+$`) so a single
  buggy field doesn't cause the parser to drop the entire BINF and
  reject the login.
- **`etc_trafficmanager.lua` no message / no `[BLOCKED]` flag with
  custom prefix scripts** (closes upstream
  [luadch#240](https://github.com/luadch/luadch/issues/240)). Resolve
  blocked target via firstnick iteration instead of computing
  `prefix + firstnick` and looking up `hub.isnickonline()`. Robust
  against any nick-prefix scheme.
- **`+delreg <blacklisted-nick>` failed** (closes upstream
  [luadch#228](https://github.com/luadch/luadch/issues/228)). Extend
  the command to remove a blacklist entry when the target is not (or
  no longer) registered. New `blacklist_del()` helper +
  `msg_deblacklist` lang string.
- **Forgot-prefix commands leaked into main chat** (closes upstream
  [luadch#223](https://github.com/luadch/luadch/issues/223)). New
  `onBroadcast` fallback in `etc_hubcommands.lua`: if a message starts
  with a known command name as a whole word and is shaped like a
  forgotten command, swallow the broadcast and reply with a prefix
  hint.
- **`+help cmd_mass` showed misleading min-level** (closes upstream
  [luadch#217](https://github.com/luadch/luadch/issues/217)).
  `util.getlowestlevel()` returns just the lowest TRUE-keyed level,
  hiding gaps in the permission table. Append the actual permitted-level
  list to `help_desc` at script-load time, formatted with level names
  where available.
- **Cryptic "wrong sslctx parameters" on first Windows run** (closes
  upstream [luadch#177](https://github.com/luadch/luadch/issues/177)).
  `core/server.lua` `wrapserver` now `io.open`-pre-checks
  `sslctx.{key,certificate,cafile}` and surfaces a human-readable hint
  pointing at `certs/make_cert.{sh,bat}` or `use_ssl = false`.
- **Multi-byte nicks rejected at lower codepoint counts than ASCII**
  (refs [#48](https://github.com/luadch-ng/luadch/issues/48)).
  `usr_nick_length.lua` switched from `#nick` (byte length) to
  `utf.len(nick)` (codepoint length). `min/max_nickname_length` is
  documented in codepoints; Cyrillic / multi-byte nicks were tripping
  the threshold sooner than intended.
- **`hub_inf_manager.lua` failure reason hardcoded English**
  (refs [#48](https://github.com/luadch-ng/luadch/issues/48)). Routed
  through the existing per-script lang file as `msg_failedauth_reason`.
- **Smoke harness Windows-only hang** (refs
  [#48](https://github.com/luadch-ng/luadch/issues/48)).
  `subprocess.run(..., capture_output=True)` lets `cmd.exe` inherit
  the parent console; `make_cert.bat` ends with `pause` and blocked
  forever waiting for a keypress when the harness was invoked from an
  interactive shell. Pass `stdin=subprocess.DEVNULL` so `pause` sees
  EOF and exits cleanly. CI was unaffected (Linux uses
  `make_cert.sh`, no pause).

### Audited as already addressed by an earlier fix

Documented in [`docs/phases/INTERLUDE_UPSTREAM_TRIAGE_2.md`](docs/phases/INTERLUDE_UPSTREAM_TRIAGE_2.md)
so the next triage round doesn't re-discover them.

- Upstream [luadch#214](https://github.com/luadch/luadch/issues/214)
  (failed-auth hammering): handled by Phase 7c F-AUTH-3 (per-IP
  failed-auth lockout).
- Upstream [luadch#221](https://github.com/luadch/luadch/issues/221)
  (search protection): handled by Phase 7c F-RL-2 (per-user search
  rate cap).
- Upstream [luadch#226](https://github.com/luadch/luadch/issues/226)
  (AirDC++ 4.21 search-spam disconnect): same root cause as #200,
  fixed there.
- Upstream [luadch#230](https://github.com/luadch/luadch/issues/230)
  (sporadic invalid-password): symptom matches the unresolved
  data-loss [luadch#189](https://github.com/luadch/luadch/issues/189);
  same workaround (`+reload`).
- Upstream [luadch#236](https://github.com/luadch/luadch/issues/236),
  [luadch#237](https://github.com/luadch/luadch/issues/237),
  [luadch#238](https://github.com/luadch/luadch/issues/238),
  [luadch#242](https://github.com/luadch/luadch/issues/242):
  resolved or made unreachable by Phase 6 / Phase 7 work.

### Other

- Repo transferred from `Aybook/luadch` to `luadch-ng/luadch`
  (auto-redirects keep historic links working). Project page:
  <https://luadch-ng.github.io/>. Doc references and release notes
  updated to point at the new path; existing operator install trees
  need no action.

[v3.1.1]: https://github.com/luadch-ng/luadch/releases/tag/v3.1.1


## [v3.1.0] - 2026-05-04

Phase 6 (refactor + smoke harness) and Phase 7 (security audit + hardening)
of the modernisation programme. No breaking changes for operators on
default cfg; existing `cfg/user.tbl` is transparently migrated to the
new encrypted-at-rest format on first save after upgrade. Phase journals
in [`docs/phases/PHASE_6.md`](docs/phases/PHASE_6.md) and
[`docs/phases/PHASE_7.md`](docs/phases/PHASE_7.md).

### Added

#### Phase 7 - security features

- **AES-256-GCM at-rest encryption of `cfg/user.tbl`** (Phase 7f, F-AUTH-1).
  New module `core/cfg_secret.lua`; auto-managed master key at
  `cfg/master.key` with chmod 600 enforcement (refuse-to-start on POSIX
  if mode != 0600). New cfg key `master_key_path` (Phase 7h) lets
  operators move the key outside the install directory for backup
  separation - strongly recommended for production. See
  [`docs/SECURITY.md`](docs/SECURITY.md) §3.
- **DoS hardening** (Phase 7c, F-NET-1 / F-NET-2 / F-AUTH-3 / F-RL-1 /
  F-RL-2). New module `core/ratelimit.lua` with token-bucket counters:
  per-IP parallel-socket cap (default 16, NAT-friendly), per-IP accept
  rate, TLS handshake wallclock deadline (default 10 s, slowloris cut),
  per-IP failed-auth lockout (independent of per-account
  bad_pass_timeout), per-user chat / search rate limits with op-level
  bypass. All cfg-tunable.
- **Sandboxed config / state loaders** (Phase 7e, F-FIO-1, **critical**).
  `util.loadtable()` runs chunks with empty `_ENV` so a tampered `.tbl`
  file cannot reach `os` / `io` / `debug` / `package` / `require`.
  Eliminates the universal RCE-on-tampered-file class for `cfg.tbl`,
  `user.tbl`, language files, and the 20+ plugin state files. Format
  on disk unchanged - zero migration.
- **POSIX file-permission enforcement on secret files** (Phase 7b, F-SEC-1).
  Hub `chmod 600`s `user.tbl` and `user.tbl.bak` after every write;
  `make_cert.sh` 0600s the generated TLS private keys. Windows: `icacls`
  recipe in [`docs/BUILDING.md`](docs/BUILDING.md) and
  [`docs/SECURITY.md`](docs/SECURITY.md) §4.
- **Secure salt generation** (Phase 7b, F-AUTH-2). HPAS challenge salts and
  SIDs now drawn from OpenSSL `RAND_bytes` via the new
  `adclib.random_bytes` C function instead of `math.random` reseeded
  with `os.time()`. New `adclib.aes_gcm_seal` / `aes_gcm_open` C
  functions wrap OpenSSL EVP_CIPHER for the at-rest encryption.
- **ADC parser hardening** (Phase 7d, F-PRS-1..5).
  - `_regex.default` and `_regex.nowhitespace` now reject raw control
    bytes (`%c`); the previous validators were a no-op and a literal
    `\\n`/`\\s` substring search respectively.
  - `parse()` is reentrant: `_buffer` / `_clone` / `_eol` are
    parse-locals instead of module-globals.
  - `MAX_COMMAND_SIZE = 64 KiB` cap at parser entry; UTF-8 check
    re-enabled at parse entry.
  - Unknown two-letter named parameters now go through the same
    control-byte-rejecting default validator as known fields.
- **adclib hardening** (Phase 7b, F-C-1 + F-C-3).
  - `hash_pas` / `hash_pas_oldschool` no longer use VLAs sized by
    Lua-side input; salt length is bounded against
    `MAX_SALT_BYTES = 64`.
  - `luaL_checklstring` everywhere binary-safe Lua strings are
    expected, so an embedded NUL in a password no longer silently
    truncates the input.
- **Tiger hash hygiene** (Phase 7g, F-C-2 + F-C-5). Explicit parens on
  `pos & ( BLOCK_SIZE - 1 )`; `tigerCompress` receives memcpy'd
  aligned `unsigned long long[]` instead of an aliased `tmp` cast;
  bit-length finalize uses memcpy at offset 56.

#### Phase 7 - documentation

- **`docs/SECURITY.md`** (new top-level doc): threat model, plugin trust
  contract, F-AUTH-1 protocol-mandated cleartext disclosure, file-
  permission baseline (Linux + Windows `icacls`), network-defense map,
  TLS configuration, CVE-tracking process, security-issue reporting
  channel, audit history.
- **`docs/phases/PHASE_7_FINDINGS.md`**: full security-audit findings
  document (24 findings with severity + evidence + fix direction); each
  finding linked to its closing PR.
- **`docs/phases/PHASE_7.md`**: phase journal with the 12-PR list,
  recurring techniques, module-state shapes, review-gate findings.

#### Phase 6 - refactor + tests

- **CI smoke harness**: 10 protocol-level tests (plain + TLS handshake,
  full ADC login, +cmd routing, CSPRNG-salt-uniqueness, per-IP
  connection cap, encrypted-at-rest user.tbl, no-script-errors-in-log)
  on every push and PR via `.github/workflows/smoke.yml`. Both Linux
  (ubuntu-latest) and Windows (windows-latest with msys2 UCRT64).
- Vendored Tiger-192 implementation as `tests/smoke/tiger.py` so the
  smoke client and the hub agree on the hash by construction.
- **`docs/phases/PHASE_6.md`** journal.

### Changed

#### Phase 7

- Bundled Lua **5.4.7 → 5.4.8** (Phase 7b, F-DEP-1). Drop-in upstream
  patch-version sync; ABI-stable.
- `find_package(OpenSSL 3.0 REQUIRED)` in CMakeLists.txt - refuse to
  link against EOL'd OpenSSL 1.1.1 (Phase 7g, F-DEP-4).
- `basexx/basexx.lua` carries a provenance header (upstream tag,
  retrieval date, license, MIT) for future auditability (Phase 7g,
  F-DEP-3).
- `hub/hub.c` `restart()` checks the `atexit()` return value and exits
  loudly when the registration limit is hit, instead of silently
  exiting cleanly without re-entering Lua (Phase 7g, F-C-4).
- `core/util.lua` gains `chmod_secret`, `arraytostring`, and
  `loadtable_string` helpers used by the encryption path.

#### Phase 6

- **`core/cfg.lua` 3688 → 668 lines** (Phase 6c). Decomposed into:
  - `core/cfg_defaults.lua` (~3000-line data table, ceiling-exempt)
  - `core/cfg_users.lua` (user.tbl I/O)
  - `core/cfg_lang.lua` (language file loader)
- **`core/hub.lua` 2245 → 1497 lines** (Phase 6d). Decomposed into:
  - `core/hub_user_object.lua` (`createuser` factory)
  - `core/hub_bot_object.lua` (`createbot` factory)
  - `core/hub_dispatch.lua` (ADC state-machine handler tables)
- All code modules now under the 1500-line ceiling, with
  `cfg_defaults.lua` exempt as a flat data table.

### Fixed

- **Path anchoring** (Phase 6b, closes #12): hub `chdir`s to its binary
  directory at startup so `log/exception.txt` and other relative paths
  resolve correctly regardless of how the hub is launched.
- TODO/FIXME audit (Phase 6e) and dead-file removal (`core/test.lua`,
  `slnunicode/.travis.yml`).

### Security

Full audit findings in
[`docs/phases/PHASE_7_FINDINGS.md`](docs/phases/PHASE_7_FINDINGS.md).
Severity rollup: 24 findings filed; 22 fixed; 1 deferred-by-design
(F-AUTH-1 transparent KDF migration is ADC-protocol-immanent and
mitigated via at-rest encryption + chmod 600 + configurable
`master_key_path`); 1 stays `upstream-blocked` (F-DEP-2 LuaSec
OpenSSL-3 deprecated APIs, tracked as #3).

### Migration

- **Operators on v3.0.0**: upgrade is in-place. First boot generates
  `cfg/master.key`; first post-login save migrates `user.tbl` from
  plaintext to AES-256-GCM-encrypted. **Strongly recommended**: set
  `master_key_path = "/etc/luadch/master.key"` (or your preferred
  external path) in `cfg/cfg.tbl` and move the key file before
  putting real users into `user.tbl`. See
  [`docs/SECURITY.md`](docs/SECURITY.md) §3 "Backup separation".
- **Existing world-readable secrets**: run once on POSIX after upgrade:

  ```sh
  chmod 600 cfg/user.tbl cfg/user.tbl.bak certs/serverkey.pem certs/cakey.pem
  ```

  On Windows, see the `icacls` recipe in
  [`docs/SECURITY.md`](docs/SECURITY.md) §4.

[v3.1.0]: https://github.com/luadch-ng/luadch/releases/tag/v3.1.0


## [v3.0.0] - 2026-05-03

First release of the modernised `Aybook/luadch` fork. Forked from upstream
`luadch/luadch` source `v2.24 [RC4]`; upstream's last public release was
`v2.23` (2022-04-02).

This release lifts the project off Lua 5.1 (EOL since 2012), replaces the
ad-hoc Linux/Windows shell+batch build pipeline with a single CMake build,
and ships several pre-existing-bug fixes on top.

### Breaking changes

- **Lua runtime upgraded from 5.1.5 to 5.4.7.** Plugins relying on
  `setfenv`, `getfenv`, `loadstring`, `unpack`, `module(...)`, `math.atan2`,
  `math.pow`, `math.log10`, `LUA_MAXCAPTURES`, etc. will not load - update
  to 5.4 idioms (`load`, `table.unpack`, explicit `_ENV`, `math.atan` two-arg
  form).
- **Build system replaced with CMake.** The old `compile` shell script and
  `compile_with_mingw.bat` are gone (including the `*.c.not` source-rename
  hack). The new build is `cmake -B build && cmake --build build && cmake --install build`
  on every supported platform.
- **`slnunicode` C module replaced by a 40-line pure-Lua shim** built on
  Lua 5.4's builtin `utf8` library. Same surface API as the old `unicode`
  table; pattern-matching call sites confirmed ASCII-only by audit. Plugins
  using non-trivial Unicode-class patterns (`%l` against German umlauts,
  etc.) would need a dedicated function added to the shim.

### Added

- CMake build system covering Linux x86_64, Windows x86_64 (MinGW UCRT),
  and ARM aarch64 (cross-compile from Linux). Same three-step pipeline
  on every platform.
- GitHub Actions release workflow that builds Linux + Windows binaries
  and attaches them to the GitHub release on tag push.
- `.gitattributes` enforcing platform-correct line endings (CRLF for
  `.bat` / `.cmd`; LF everywhere else).
- `docs/BUILDING.md` rewritten with platform-specific Linux / Windows /
  ARM sections, OpenSSL cross-compile recipe, ARM cross-toolchain setup.
- `docs/INSTALLING.md`: deployment guide (Linux service-user pattern,
  systemd unit, Windows NSSM service, backups, update procedure).
- `docs/CONFIGURATION.md`: post-install configuration reference (first-run
  checklist, cfg.tbl tour, plugin categories, troubleshooting).
- `docs/phases/PHASE_{1..5}.md` and `INTERLUDE_UPSTREAM_TRIAGE.md`:
  per-phase modernisation journals.
- New `msg_del_reason` template in `cmd_delreg.lua` so deleted users see
  the reason on disconnect (en + de language files updated).

### Changed

- Hub launcher `hub/hub.c`: `lua_open()` -> `luaL_newstate()` (5.4 API).
- `adclib/adclib.cpp`: `luaL_reg` -> `luaL_Reg`,
  `luaL_register` -> `luaL_newlib + return 1`.
- Windows build: `wmic` calls in `cmd_hubinfo.lua` replaced with
  PowerShell `Get-CimInstance` (Windows 11 24H2+ removed `wmic`).
- CMake's Windows OpenSSL DLL bundling now searches both flat
  (`$ROOT/`) and bin-subdir (`$ROOT/bin/`) layouts so msys2 UCRT64 and
  WinLibs / ShiningLight Win64 both work without manual flattening.

### Fixed

- `os.difftime` 1-arg call pattern (silently tolerated in 5.1, errors in
  5.4): 12 scripts updated to `os.time() - x`.
- `cmd_hubinfo.lua` crash on missing certificate file (`get_certinfos`
  missing return).
- `+!#` server commands sent as PMs to the hubbot now route through the
  command pipeline again
  ([PR #13](https://github.com/Aybook/luadch/pull/13)).
- `make_cert.sh`: `UID` variable collision with bash's read-only builtin -
  renamed to `RAND_ID`.
- `make_cert.bat`: silently produced certs with an empty CN on
  OpenSSL 3.5+ because `openssl rand -hex 16 -out X` requires the
  positional `<num>` last; reordered. Also dropped OpenSSL-1.0.x-era
  `RANDFILE` legacy.
- `register` keyword warnings in `adclib/tiger.cpp` (C++17 deprecation).
- `cmd_delreg.lua` help-text fallback corrected: "delregs an existing
  user".
- `cmd_usercleaner.lua`: `+usercleaner showghosts` crashed when any
  registered user lacked a `date` attribute - guard `reg_date` before
  comparison.
- `usr_uptime.lua`: crashed on first user login after the database file
  was missing or unparseable - removed the `else` branch that returned
  early with an empty table before the entry-setup ran.
- `+delreg <nick> <reason>` now relays the reason to the deleted user
  before kicking, instead of the silent generic "You were delregged."
- `+shutdown` and `+restart` countdowns now block main-chat broadcasts so
  users cannot type during the countdown.

### Removed

- Legacy build scripts: `compile`, `compile_with_mingw.bat`, `cleanall`.
- The `*.c.not` rename trick the Windows build used to skip Unix-only
  LuaSocket sources.
- Unmaintained `slnunicode` C module (1366 lines of C, replaced by the
  40-line Lua shim).

### Security

- TLS 1.3 + AES-256-GCM verified end-to-end after the modernisation.
- `cfg/cfg.tbl` and `cfg/user.tbl` documented as 0600 by deployment
  guide (they hold the default-account password and the registered-user
  hashes respectively).

### Phase journals

For the full per-phase narrative (activities, design decisions, build
output specs, review-gate checklists), see [`docs/phases/`](docs/phases/).

[v3.0.0]: https://github.com/luadch-ng/luadch/releases/tag/v3.0.0
