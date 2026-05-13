# Changelog

All notable changes to the `luadch-ng/luadch` fork are documented here.
The repo lived at `Aybook/luadch` before the v3.1.x line; auto-redirects
handle historic links.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The upstream project (`luadch/luadch`) is a separate codebase; its release
history is at https://github.com/luadch/luadch/releases.

## [Unreleased] - 3.2.x line

Phase-8 feature work in progress. See open issues for the planned
scope: [#82](https://github.com/luadch-ng/luadch/issues/82) HTTP API,
[#83](https://github.com/luadch-ng/luadch/issues/83) Prometheus
metrics, [#84](https://github.com/luadch-ng/luadch/issues/84) audit
log, [#100](https://github.com/luadch-ng/luadch/issues/100)
self-registration, plus the deferred items in
[#147](https://github.com/luadch-ng/luadch/issues/147) (T2 HUBI,
T2 BLOM, T3 HBRI, T3 ZLIF). Security-fixes-only for the v3.1.x line
land on `release/3.1.x` per
[`CLAUDE.md` §8](CLAUDE.md#8-release-lines-and-support-policy).

### Bugfixes

- [#161](https://github.com/luadch-ng/luadch/issues/161) - BINF without `I4` / `I6` fields was rejected with `ISTA 220 No CID/PID/NICK/IP found in your INF.` Per ADC 4.3.x the `I4` / `I6` fields are *conditionally* required (only when the client advertises TCP4 / UDP4 / TCP6 / UDP6 in `SU`); hublist pingers and any IP-agnostic probe legitimately omit them. The hub now treats a missing `I4` / `I6` like the spec-defined `0.0.0.0` placeholder - fills in the TCP-source IP under the connection's address family, no special-case "no-IP user" shape downstream. `kill_wrong_ips` spoof-detection is unchanged for actually-mismatched claims. Mirrors upstream [luadch/luadch#176](https://github.com/luadch/luadch/issues/176). Backport target: `release/3.1.x` as v3.1.9.
- [#162](https://github.com/luadch-ng/luadch/issues/162) - ADC PING HSUP handler errored out (sandbox-undeclared `pairs`) on public (`reg_only = false`) hubs, returning zero frames to the pinger. Hublist scrapers timed out and dropped the hub from listings. Regression introduced by T1.3 of [#147](https://github.com/luadch-ng/luadch/issues/147) in v3.1.8. Backport target: `release/3.1.x` as v3.1.9 (self-introduced functional regression breaking the public-hub deployment mode - judgement call outside CLAUDE.md §8 table's listed categories).
- Latent crash in `core/server.lua` `changesettings()`: `tonumber()` was called seven times without `local tonumber = use "tonumber"` import. Function is currently dead code (no caller in hub or plugins) so no production impact; surfaced by the #162 sandbox-locals audit. Fix is a one-line `use` declaration alongside the existing locals.


## [v3.1.8] - 2026-05-12

Modernisation-complete patch release. Concludes the
[#80](https://github.com/luadch-ng/luadch/issues/80) ratelimit v2 work
(four buckets + per-userlevel tiers) and the
[#147](https://github.com/luadch-ng/luadch/issues/147) ADC protocol
coverage T1 line (eight items). After this release, `master` opens
the 3.2.x line; security fixes for 3.1.x go to the
`release/3.1.x` branch per [`CLAUDE.md`](CLAUDE.md#8-release-lines-and-support-policy)
§8.

Smoke 37/37 PASS on Linux + Windows.

### Features

- **Per-userlevel rate-limit tiers** ([#80](https://github.com/luadch-ng/luadch/issues/80), closed) -
  the PM, BINF, and CTM/RCM dispatch paths each get their own
  independent rate-limit bucket on top of the existing chat / search
  buckets ([#138](https://github.com/luadch-ng/luadch/pull/138)
  / [#139](https://github.com/luadch-ng/luadch/pull/139)
  / [#140](https://github.com/luadch-ng/luadch/pull/140)). All five
  buckets become optionally tier-mappable per user level via the new
  `ratelimit_tiers` + `ratelimit_tier_for_level` cfg keys
  ([#141](https://github.com/luadch-ng/luadch/pull/141)) - operators
  can give unreg / guest strict tiers and bots headroom without
  touching the global scalars. Strict-positive validators reject the
  silent-mute failure modes
  ([#142](https://github.com/luadch-ng/luadch/pull/142)
  / [#143](https://github.com/luadch-ng/luadch/pull/143)).
- **ADC protocol coverage** ([#147](https://github.com/luadch-ng/luadch/issues/147), T1 closed)
  - eight protocol-completeness items:
  - **NATT relay** ([#148](https://github.com/luadch-ng/luadch/pull/148)) -
    DNAT / DRNT handlers, hub-relay-only NAT-traversal per ADC-EXT 3.9.
  - **RDEX rich redirect** ([#149](https://github.com/luadch-ng/luadch/pull/149)) -
    `IINF.RP` advertisement + `IQUI.RX` (alternative URLs) / `IQUI.PT`
    (permanent flag) NPs, cfg-driven via `hub_redirect_protocols` /
    `hub_redirect_alternatives` / `hub_redirect_permanent`.
  - **PING completeness** ([#150](https://github.com/luadch-ng/luadch/pull/150)
    / [#146](https://github.com/luadch-ng/luadch/pull/146)) - `SS` /
    `SF` (total share / files), `HE` (email), `MU` / `MR` / `MO`
    (min hubs) added to the `ADPING` reply. `MU/MR/MO` cfg-tunable
    via new `min_user_hubs` / `min_reg_hubs` / `min_op_hubs` keys.
  - **STA emission codes** ([#151](https://github.com/luadch-ng/luadch/pull/151)) -
    `cmd_shutdown` / `cmd_restart` emit `ISTA 212` ("Hub disabled")
    before close; `cmd_ban` switches from 230 / 231 to spec-correct
    `ISTA 232` for finite-TL temporary bans.
  - **FRES routing** ([#152](https://github.com/luadch-ng/luadch/pull/152)) -
    feature-filtered search-result delivery (F-class RES) now
    dispatches alongside DRES.
  - **HQUI from client honored** ([#153](https://github.com/luadch-ng/luadch/pull/153)
    + [#156](https://github.com/luadch-ng/luadch/pull/156)) - clean
    close on client-initiated quit in any state, instead of `ISTA 125`
    unknown-command.
  - **ECTM / ERCM dispatch** ([#146](https://github.com/luadch-ng/luadch/pull/146)) -
    modern E-class CTM / RCM variants now routed.
- **Operator-facing docs** -
  new [`docs/SCRIPTS.md`](docs/SCRIPTS.md)
  ([#144](https://github.com/luadch-ng/luadch/pull/144)) lists every
  bundled plugin with its commands and cfg keys plus the full
  rate-limit configuration guide. README cleaned up
  ([#145](https://github.com/luadch-ng/luadch/pull/145)). Passthrough
  ADC-EXT extensions ([#154](https://github.com/luadch-ng/luadch/pull/154)),
  release-line / support policy ([#155](https://github.com/luadch-ng/luadch/pull/155))
  documented.

### Bugfixes

- **`user.sendsta` typo** ([#151](https://github.com/luadch-ng/luadch/pull/151)) -
  the long-standing `type( flags == "table" )` typo made
  `pairs(nil)` crash whenever a caller omitted the optional flags
  arg. Now `type( flags ) == "table"` matches the docstring contract.
- **`cmd_ban` STA code spec compliance** ([#151](https://github.com/luadch-ng/luadch/pull/151)) -
  three call sites now use 232 (temporary ban with TL) instead of
  231 (permanent ban, no TL) for finite-duration bans.
- **`user.redirect` quitmsg escape**
  ([#156](https://github.com/luadch-ng/luadch/pull/156)) -
  `MS<quitmsg>` was emitted raw; multi-word reasons produced
  malformed ADC. Now `adclib_escape`'d.
- **Ratelimit cfg validator strict-positive**
  ([#142](https://github.com/luadch-ng/luadch/pull/142)) - rate /
  burst / period values must be > 0; pre-fix an operator typo like
  `msg_burst = -1` would silent-mute every non-op user.
- **Smoke battery exercises rate-limit gates correctly**
  ([#156](https://github.com/luadch-ng/luadch/pull/156)) - the PM /
  CTM / RCM / NATT burst tests were short-circuiting at the
  target-lookup before reaching the dispatcher; now self-target so
  the rate-limit code path is genuinely covered.

### Notes

- **No breaking changes at defaults.** All new cfg keys are
  additive with conservative defaults that preserve v3.1.7
  behaviour.
- **ERES (Echo-class search result) is no longer parsed.** ADC 5.3.6
  defines only `D` and `F` classes for RES; previously the parser
  accepted ERES via the broader `[DE]` context and the hub forwarded
  it as E-class. The parser context tightened to `[FD]` as part of
  FRES routing ([#152](https://github.com/luadch-ng/luadch/pull/152)).
  No known client emits ERES; if an exotic NMDC bridge does, it is
  now rejected at parse instead of routed.
- `scripts/lang/cmd_shutdown.lang.{en,de}` and
  `scripts/lang/cmd_restart.lang.{en,de}` add a new `msg_hub_disabled`
  key for the STA 212 message. Operators with custom translations
  for these files need a one-time additive merge; missing keys fall
  back to the hardcoded English string.
- **Release-line model takes effect.** Starting after this release,
  `master` is the 3.2.x active-development line; security-only
  patches for 3.1.x land on `release/3.1.x`. See
  [`CLAUDE.md` §8](CLAUDE.md#8-release-lines-and-support-policy) for
  the full policy including the cherry-pick workflow and the
  "when to backport" decision table.

[v3.1.8]: https://github.com/luadch-ng/luadch/releases/tag/v3.1.8


## [v3.1.7] - 2026-05-11

Plugin data-integrity patch release. `util.savearray` / `util.savetable` are atomic-by-default, defensive `or {}` swept across bundled plugins that load tables, cross-month uptime accounting bug fixed, and `cmd_gag` gains shadowmute mode + duration syntax. Smoke 31/31 PASS on Linux + Windows.

### Features

- [#85](https://github.com/luadch-ng/luadch/issues/85) - `cmd_gag` adds **shadowmute** as a 4th mode plus optional duration on all modes ([#132](https://github.com/luadch-ng/luadch/pull/132)). Shadowmute = target sees their own messages echo but nobody else does. Duration accepts `30s` / `10m` / `2h` / `1d` / `1w` (combinable as `1h30m`); empty = permanent. Auto-expire walks the gag table every 60s. Offline ungag now works via `hub.getregusers()` lookup. Right-click menu gets a "Shadowmute User" entry.
- [#128](https://github.com/luadch-ng/luadch/issues/128) - `encrypt_usertbl` opt-out toggle in `cfg/cfg.tbl` ([#129](https://github.com/luadch-ng/luadch/pull/129)). Default `true` preserves the Phase-7f AES-256-GCM at-rest encryption. `false` writes plaintext `user.tbl` for single-user / home hubs where direct operator read access matters more than disk confidentiality. Auto-detected on read via LDC1 magic prefix - migration is transparent in both directions, master.key auto-generated only when encryption is on.

### Bugfixes

- [#127](https://github.com/luadch-ng/luadch/issues/127) - `usr_uptime` cross-month accounting fix ([#131](https://github.com/luadch-ng/luadch/pull/131)). Sessions spanning month boundaries no longer accumulate as "years" of uptime. New per-tick credit pattern attributes each 60s tick to the calendar month that contains it.
- [#133](https://github.com/luadch-ng/luadch/issues/133) F-PLG-1 / F-PLG-2 - bundled plugin data-integrity sweep:
  - `util.savearray` / `util.savetable` are **atomic-by-default** ([#134](https://github.com/luadch-ng/luadch/pull/134)) via the new public `util.atomic_write(path, content)` helper (tmp + rename, Windows fallback). 21 plugin save sites in the bundled tree get crash-safe writes with zero call-site changes. `cfg_users.lua` delegates to the shared helper for a single source of truth.
  - Defensive `or {}` on 22 `util.loadtable` consumer sites across 12 bundled plugins ([#135](https://github.com/luadch-ng/luadch/pull/135)). Missing / unreadable / parse-fail `.tbl` files no longer crash listeners on first `pairs()` / `ipairs()` / field access. Sites with the existing init-pattern (`check_hci` style) intentionally left as-is - they handle nil correctly and auto-create with defaults.
  - F-PLG-3 (silent no-op on incomplete `+cmd`) audited across 24 bundled scripts - no actionable bugs found, all command handlers already have explicit `msg_usage` fallbacks.

### Notes

- `scripts/lang/cmd_gag.lang.{en,de}` modified: 5 new keys (`msg_invalid_duration`, `msg_add_user_with_duration`, `msg_expired`, `ucmd_duration`, `ucmd_menu_ct1b`); rewritten: `msg_usage`, `help_usage`, `help_desc`, `msg_show_users`. Operators with custom `cmd_gag.lang.*` translations need a one-time merge.
- `examples/cfg/cfg.tbl` gains `encrypt_usertbl = true`. Existing `cfg/cfg.tbl` files without the key default to encrypted (preserves v3.1.6 behaviour). To opt out, add `encrypt_usertbl = false`.
- New public `util.atomic_write` + `util.tabletostring` helpers in `core/util.lua`. Plugins that roll their own save path can route through them for crash-safe writes; companion `luadch-ng/scripts` PRs already use them in `ptx_poll_bot`, `ptx_freshstuff`, `etc_requests`, and `etc_mainecho` (min hub version: v3.1.7).
- Smoke harness: 31/31 PASS unchanged - no new tests this release (audit-discussion outcome was "don't grow the testbench for refactors that don't change the protocol surface").

[v3.1.7]: https://github.com/luadch-ng/luadch/releases/tag/v3.1.7


## [v3.1.6] - 2026-05-09

Security-themed patch release. Hub now defaults to TLS-only with auto-generated self-signed certs on first boot, the password leakage in admin reply paths is closed for `+setpass` / `+accinfo` / `+usersearch`, and Docker deployments pick up new bundled language files automatically. Smoke 14/14 PASS on Linux + Windows.

### Breaking

- Default `cfg/cfg.tbl` ships TLS-only on **both stacks** ([#77](https://github.com/luadch-ng/luadch/issues/77) / [#113](https://github.com/luadch-ng/luadch/pull/113)): IPv4 (`tcp_ports = { }`, `ssl_ports = { 5001 }`) and IPv6 (`tcp_ports_ipv6 = { }`, `ssl_ports_ipv6 = { 5003 }`), with `use_ssl = true`. Existing `cfg/cfg.tbl` files are not migrated - operators upgrading from v3.1.5 keep their plain-port settings on both stacks unless they choose to flip. Fresh installs and Docker first-boot are TLS-only.

### Features

- Auto-generated self-signed P-256 ECDSA cert on first boot when no `servercert.pem` / `serverkey.pem` exists ([#113](https://github.com/luadch-ng/luadch/pull/113)). Pure-Lua + adclib OpenSSL bindings, no `make_cert.{sh,bat}` needed. Keyprint logged to stdout so `docker compose logs` shows it for the operator to share as `adcs://host:port/?kp=SHA256/<base32>`.
- Bundled `slaxml` XML parser at `lib/slaxml/` ([#112](https://github.com/luadch-ng/luadch/pull/112)). Plugins that need to parse XML (e.g. RSS feeds) can now `use "slaxml"` without a separate dep install.
- Docker entrypoint now also adds new bundled `scripts/lang/*.lang.*` files on container start ([#118](https://github.com/luadch-ng/luadch/pull/118)). Strictly add-only - existing translations are never overwritten. Same `LUADCH_AUTOSYNC_SCRIPTS=0` toggle covers both the `*.lua` overwrite-on-diff sync and the new lang add-only sync.

### Bugfixes

- [#95](https://github.com/luadch-ng/luadch/issues/95) - password no longer echoed in admin reply paths ([#119](https://github.com/luadch-ng/luadch/pull/119)). `+setpass` drops the password from the caller's reply (target still receives it via PM, needed for first login); `+accinfo` and `+usersearch` show `<REDACTED>` in the password column. The `+reg` auto-generated password delivery is intentionally unchanged - target needs the value to log in. Three of four sub-tasks of #95 closed.
- [#48](https://github.com/luadch-ng/luadch/issues/48) - `usr_nick_length` now routes its `onFailedAuth` reason and the `ISTA 221` kill message through `scripts/lang/usr_nick_length.lang.{en,de}` instead of hardcoded English ([#117](https://github.com/luadch-ng/luadch/pull/117)). Operator-facing string lands localised in `cmd.log` and any blacklist plugin listening on `onFailedAuth`.
- [#114](https://github.com/luadch-ng/luadch/issues/114) - grammar fix `'an user'` -> `'a user'` in nine plugin headers across `scripts/` and `examples/etc/other_available_scripts/` ([#116](https://github.com/luadch-ng/luadch/pull/116)). Comment-only.

### Notes

- New bundled lang files: `scripts/lang/usr_nick_length.lang.{en,de}`. New lang keys: `msg_redacted` in `cmd_accinfo.lang.{en,de}` and `cmd_usersearch.lang.{en,de}`. Modified key: `msg_ok` in `cmd_setpass.lang.{en,de}` (reads as a complete sentence after the password drop). Operators with custom lang files for these scripts: see release-body for the per-script delta.
- Bug-report and feature-request issue templates added under `.github/ISSUE_TEMPLATE/`.

[v3.1.6]: https://github.com/luadch-ng/luadch/releases/tag/v3.1.6


## [v3.1.5] - 2026-05-07

Patch release on top of v3.1.4. Drop-in upgrade. Closes upstream `luadch/luadch#189` (registered users disappearing) and adds image-side auto-sync of bundled plugin code. Smoke 13/13 PASS on Linux + Windows.

### Bugfixes

- [#108](https://github.com/luadch-ng/luadch/issues/108) / [upstream luadch#189](https://github.com/luadch/luadch/issues/189) - registered users no longer disappear from `user.tbl`. Two root causes: stale file-scope `hub.getregusers()` cache in `cmd_nickchange.lua` (saved snapshots over later `+reg` writes), and non-atomic `cfg_users.saveusers` (truncate-during-write left `user.tbl` partial; `checkusers()` then fell back to a weeks-old `.bak`). Now: `cmd_nickchange.lua` fetches `hub.getregusers()` per call; `saveusers()` writes via `.tmp` + `rename(2)`; `user.tbl.bak` refreshes on every successful save and is byte-identical to `user.tbl`.

### Features

- Docker entrypoint auto-syncs bundled `scripts/*.lua` from the image to the mounted `scripts/` directory on every container start. Plugin bug-fixes now reach existing deployments on `docker compose pull` without manual file copies. Operator-owned state (`scripts/lang/`, `scripts/data/`, `scripts/cfg/`, custom `*.lua`, `cfg/`, `certs/`, `secrets/`) is never touched. Opt-out via `LUADCH_AUTOSYNC_SCRIPTS=0`. See [`docs/DOCKER.md`](docs/DOCKER.md).

### Notes

- `user.tbl.bak` is now refreshed on every successful save (was: only at `+reload`). Operators relying on `.bak` as a stale-rollback should adjust workflows.
- New smoke test: `test_usertbl_bak_atomic_refresh` verifies `.bak` byte-equality with `user.tbl` after writes (12 -> 13 tests).

[v3.1.5]: https://github.com/luadch-ng/luadch/releases/tag/v3.1.5


## [v3.1.4] - 2026-05-07

Patch release on top of v3.1.3. Drop-in upgrade; no cfg / on-disk-format changes. Smoke 12/12 PASS on Linux + Windows. First release with an official container image.

### Features

- [#87](https://github.com/luadch-ng/luadch/issues/87) - Pure-rootless container image on `ghcr.io/luadch-ng/luadch` (linux/amd64 + linux/arm64). Compose-file at repo root, operator guide at [`docs/DOCKER.md`](docs/DOCKER.md).

### Bugfixes

- [#97](https://github.com/luadch-ng/luadch/issues/97) - `kill_wrong_ips` defaults to `true`; `I4` / `I6` added to `hub_inf_manager` forbidden-on-INF flags (closes IP-spoof on post-login INF). Operator opt-out for NAT-weird deployments documented in `docs/SECURITY.md` § 5.
- [#103](https://github.com/luadch-ng/luadch/issues/103) - `etc_motd`: multi-placeholder MOTDs no longer crash on login; new `{nick}` template form, `%s` kept for backwards compat.

### Notes

- `docker.yml` workflow build/push status badge added to README.
- Audit meta tracker [#98](https://github.com/luadch-ng/luadch/issues/98) closed; remaining deferral [#95](https://github.com/luadch-ng/luadch/issues/95) (admin reply paths) stays Phase-8.

[v3.1.4]: https://github.com/luadch-ng/luadch/releases/tag/v3.1.4


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
