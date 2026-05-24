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
[#147](https://github.com/luadch-ng/luadch/issues/147) (T2 BLOM,
T3 ZLIF). Security-fixes-only for the v3.1.x line
land on `release/3.1.x` per
[`CLAUDE.md` §8](CLAUDE.md#8-release-lines-and-support-policy).

> **Note:** The **Bugfixes** entries for `#161`, `#162`, the latent
> `server.lua tonumber` crash, and `#160`, plus the `#159` aarch64
> entry under **Features**, were cherry-picked to `release/3.1.x`
> and shipped as **[v3.1.9](https://github.com/luadch-ng/luadch/releases/tag/v3.1.9)**
> (2026-05-13). They stay listed here because they are part of the
> 3.2.x line as well - merged on master first per the §8 workflow.
> The `#159` aarch64 follow-up under **Bugfixes** is a v3.1.10
> backport candidate (regression-fix on a v3.1.9 feature). The
> `#137` literal-bracket hint and the **Luadch-NG identifier
> rename** under **Features**, the entries in **Refactors**, and
> **Documentation** are 3.2.x-only and not part of v3.1.9.

### Breaking

- [#231](https://github.com/luadch-ng/luadch/issues/231) - HTTP API now requires an **explicit token in cfg.tbl** before binding the listener. Previously the first-boot bootstrap generated a token AND auto-activated it in-memory, so the API "just worked" on first boot. That mechanism had a footgun: `+reload` reads `cfg.tbl` fresh and silently wiped the in-memory token, locking the operator out until a process restart (which then generated a NEW token, overwriting `api_token.first`). Post-#231: hub writes a sample token to `cfg/api_token.first` (chmod 600) when `http_port` is set but `http_api_tokens` is empty, logs a warning, and does NOT bind the listener. Operator must copy the value into `cfg.tbl http_api_tokens` and restart (or `+reload`) to activate. `cfg.tbl` is now the single source of truth. **Action required for operators:** if you upgrade with `http_port` set but no token in `cfg.tbl`, the HTTP API will not be reachable until you copy the sample value over. Details in [`docs/HTTP_API.md` §4.7](docs/HTTP_API.md). 3.2.x only, not backported.

### Bugfixes

- [#207](https://github.com/luadch-ng/luadch/issues/207) - TLS-handshake CPU-exhaustion hardening: (a) reduced the stuck-handshake retry loop in `core/server.lua` `wrapconnection()` from 20 to 10 iterations - the loop only ever iterates on the SSL wantread/wantwrite I/O dance, not new ECDH work (which happens once on the first flight); 10 yields are plenty for TLS 1.3, the configured default protocol. (b) Extracted `ratelimit_expired_handshakes()` from the 120s `_checkinterval` sweep into a dedicated faster sweep gated by a new cfg key `ratelimit_handshake_sweep_interval` (default 10s). Worst-case lifetime of a stuck handshake's handler + coroutine drops from `handshake_timeout + 120s` (~130s under defaults) to `handshake_timeout + 10s` (~20s under defaults). The per-IP rate-limit aspect of the original issue is already covered by the existing `ratelimit_perip_conn_rate` / `_burst` / `_max_conns` (defaults 10/s, burst 30, max 16 parallel) which fires on TCP-accept - which IS the TLS-handshake-start point - so no new code path was added for per-IP rate enforcement. Documented in code comments. 3.2.x only, not backported.
- [#208](https://github.com/luadch-ng/luadch/issues/208) - integer overflow in `adclib.gen_self_signed_cert()` on any platform where `long` is 32-bit. The input bound of `36500` days (~100 years) combined with `long days * 86400` overflowed (LONG_MAX = 2,147,483,647; `36500 * 86400 = 3,153,600,000`), producing a negative-seconds value that `X509_gmtime_adj` interpreted as "seconds before the epoch" - the generated cert's `notAfter` landed in ~1933 and TLS clients got `certificate has expired`. Affected platforms: 32-bit ILP32 (i686 / ARMv7 / MIPS32) AND Windows x64 LLP64 (MinGW UCRT64, MSVC; `long` is 32-bit by Windows ABI regardless of process width). Unaffected: Linux LP64 (x86_64, aarch64). Fix: lower the input bound from 36500 to **24855** days (~68 years = `LONG_MAX / 86400` on a 32-bit long), making the arithmetic safe on every supported platform without platform-conditional code. The new ceiling is well above any realistic deployment; `cert_bootstrap.lua` uses 3650 days = 10 years by default and was always in-bounds. The issue only surfaced if an operator or sandboxed Lua passed `days > 24855` on a long-is-32-bit host. 3.2.x only, not backported.
- [#161](https://github.com/luadch-ng/luadch/issues/161) - BINF without `I4` / `I6` fields was rejected with `ISTA 220 No CID/PID/NICK/IP found in your INF.` Per ADC 4.3.x the `I4` / `I6` fields are *conditionally* required (only when the client advertises TCP4 / UDP4 / TCP6 / UDP6 in `SU`); hublist pingers and any IP-agnostic probe legitimately omit them. The hub now treats a missing `I4` / `I6` like the spec-defined `0.0.0.0` placeholder - fills in the TCP-source IP under the connection's address family, no special-case "no-IP user" shape downstream. `kill_wrong_ips` spoof-detection is unchanged for actually-mismatched claims. Mirrors upstream [luadch/luadch#176](https://github.com/luadch/luadch/issues/176). Backported to `release/3.1.x` as v3.1.9.
- [#162](https://github.com/luadch-ng/luadch/issues/162) - ADC PING HSUP handler errored out (sandbox-undeclared `pairs`) on public (`reg_only = false`) hubs, returning zero frames to the pinger. Hublist scrapers timed out and dropped the hub from listings. Regression introduced by T1.3 of [#147](https://github.com/luadch-ng/luadch/issues/147) in v3.1.8. Backported to `release/3.1.x` as v3.1.9 (self-introduced functional regression breaking the public-hub deployment mode - judgement call outside CLAUDE.md §8 table's listed categories).
- Latent crash in `core/server.lua` `changesettings()`: `tonumber()` was called seven times without `local tonumber = use "tonumber"` import. Function is currently dead code (no caller in hub or plugins) so no production impact; surfaced by the #162 sandbox-locals audit. Fix is a one-line `use` declaration alongside the existing locals. Backported to v3.1.9 alongside #162.
- [#159](https://github.com/luadch-ng/luadch/issues/159) follow-up (Sopor / Boro) - the v3.1.9 `linux-aarch64` artifact was unusable on Bullseye-based Pi systems (DietPi v9.x, glibc 2.31) AND on fresh Pi OS Bookworm (glibc 2.36) because it was built on `ubuntu-24.04-arm` (glibc 2.39) and inherited `GLIBC_2.34` / `GLIBC_2.38` symbol requirements. The aarch64 build now runs inside a Debian Bullseye container on the same native-arm runner, with OpenSSL 3.x built from source and bundled (`libssl.so.3` + `libcrypto.so.3` alongside the binary, same pattern as the Windows `libssl-3-x64.dll`). `rpath` is patched to `$ORIGIN` on the main binary and `$ORIGIN/../../..` on `luasec/ssl.so` so the bundled libs resolve without depending on the system OpenSSL version. The workflow has an explicit `objdump -T | grep GLIBC` step that fails the build if any required symbol exceeds GLIBC_2.31 (Bullseye baseline) - catches a future regression where someone bumps the container away from Bullseye without thinking. Backport candidate for v3.1.10.
- Phase 8a F-INF-1f cosmetic fix in `scripts/etc_userlogininfo.lua`: the `or "<unknown>"` fallback on a nil `user_version` never fired because `hub.escapefrom(nil)` returns `""` and `"" or "<unknown>"` evaluates to `""` in Lua (`""` is truthy). Operators saw an empty client-version field in the login-info message instead of `<unknown>`. Fix: explicit `nil`-check before calling `hub.escapefrom`. Deferred from Phase 8a closeout. 3.2.x only, not backported.
- [#219](https://github.com/luadch-ng/luadch/issues/219) - Phase 8a F-INF-2: per-field integer clamps on the user accessors `user:share()` / `user:files()` / `user:slots()` / `user:hubs()` in `core/hub_user_object.lua`. Caps: `SS=[0, 2^53]`, `SF=[0, 2^32]`, `SL`/`HN`/`HR`/`HO=[0, 2^16]`; negatives floor to 0. Defends hub-stat aggregates, PING reply totals (#147 T1.3/T1.4), and HTTP API JSON output against a client claiming `SS=-1` or `SS=10^18` (would otherwise pollute `etc_records` persistence permanently). Phase 7d (#65) parser contract preserved: parser still accepts negative integers (DC++ `DS-1` sentinel), stored `_inf` untouched, only accessor reads normalised. See `docs/PLUGIN_API.md` user accessor section for the clamp contract. 3.2.x only, not backported.
- [#214](https://github.com/luadch-ng/luadch/issues/214) Gap 2 - DDoS-amplification hardening on the `kill_wrong_ips = false` opt-out path in `core/hub_dispatch.lua`. The NAT-weird-deployment opt-out preserves the user's connection on a primary-IP claim mismatch (default `kill_wrong_ips = true` kills) but pre-fix the wrong claim STAYED in the BINF and was broadcast to other clients - they would then direct CTM / RCM frames at the spoofed address (Maksis-confirmed DDoS-amplification vector, see [Wikipedia DC++ DDoS history](https://en.wikipedia.org/wiki/Direct_Connect_(protocol)#Direct_Connect_used_for_DDoS_attacks)). Fix: the mismatch + opt-out branch now stamps the verified `userip` over the lie via `adccmd:setnp( userfam, userip )`, so the broadcast INF carries the authenticated TCP-source IP. Opt-out intent (don't kill the user) preserved AND legitimate NAT-deployments now broadcast a routable IP (strictly better UX than pre-fix). Default `kill_wrong_ips = true` deployments unaffected. The remaining vector (Gap 1: secondary-family unverified broadcast) is closed by the upcoming HBRI implementation. **Backport candidate for v3.1.10** (DDoS-amplification fix; the opt-out users are precisely the NAT-weird operators most likely to enable it without realising the broadcast hole).
- [#222](https://github.com/luadch-ng/luadch/issues/222) (HadesDCH) - post-login INF updates carrying `I4` / `I6` are now silent-stripped from `scripts/hub_inf_manager.lua` instead of killing the user with `ISTA 240` + `TL300`. Real DC++ clients refresh INF (incl. `I4`) on routine triggers (NAT rebind, ISP-IP change, plain refresh); the existing kill-on-flag logic disconnected those legitimate users, producing the FAILED-AUTH log spam HadesDCH reported. The `flags_on_inf` table split into `flags_on_inf_kill` (`PD` / `ID`, identity spoofing = kill) and `flags_on_inf_strip` (`I4` / `I6`, IP mutation attempt or routine refresh = silent strip). Anti-spoofing (#97) intent preserved: stored `_inf` IP fields are NEVER mutated, the stripped fields never reach the broadcast - other clients keep seeing the original verified IP. Other INF fields in the same post-login update (e.g. `DE` description change, `SS` share size update) still get applied. Plugin bumped to v0.07. **Backport candidate for v3.1.10**.
- [#160](https://github.com/luadch-ng/luadch/issues/160) (Sopor) - defense-in-depth for `etc_trafficmanager.lua` search blocking. The `onSearch` listener already swallows searches in both directions for blocked users, so they normally have no search to reply to. The new `onSearchResult` listener catches the protocol-violating edge case where a blocked user sends an unsolicited DRES / FRES (or a DRES targets a blocked user). Plugin bumped to v2.2. Backported to `release/3.1.x` as v3.1.9.

### Features

- [#82](https://github.com/luadch-ng/luadch/issues/82) - HTTP API `POST /v1/topic` (admin scope). `cmd_topic` plugin v0.04 coexists ADC `+topic` and the new HTTP endpoint via shared `do_set_topic()` / `do_reset_topic()` helpers. Body `{topic?: string}`: missing / empty resets to `cfg.hub_description`, non-empty sets. HTTP callers can literally set topic to the word `"default"` (the ADC `+topic default` magic-keyword does NOT apply because the body expresses reset via absence). Closes the deferred Phase-2-spec entry. 3.2.x only, not backported.
- [#82](https://github.com/luadch-ng/luadch/issues/82) - HTTP API `POST /v1/reload` (X-Confirm required). `cmd_reload` plugin v0.04 coexists ADC `+reload` and the new HTTP endpoint. Body / response shape documented in [`docs/HTTP_API.md` §10.2](docs/HTTP_API.md). Idempotency cache replays a successful reload-retry without double-reloading. Closes the deferred Phase-2-spec entry. 3.2.x only, not backported.
- [#82](https://github.com/luadch-ng/luadch/issues/82) Phase 3 PR-1 (#225) - HTTP API `POST /v1/restart` (X-Confirm required). `cmd_restart` plugin v0.12 coexists ADC `+restart` and the new HTTP endpoint via a shared `do_restart()` helper. ADC-side `cmd_restart_permission` level table is bypassed on the HTTP path - the bearer token's `admin` scope IS the authorisation gate. Body / response shape documented in [`docs/HTTP_API.md` §10.2](docs/HTTP_API.md). 3.2.x only, not backported.
- [#82](https://github.com/luadch-ng/luadch/issues/82) Phase 3 PR-2 (#225) - HTTP API `POST /v1/shutdown` (X-Confirm required). `cmd_shutdown` plugin v0.11 coexists ADC `+shutdown` and the new HTTP endpoint via a shared `do_shutdown()` helper. ADC-side `cmd_shutdown_permission` level table is bypassed on the HTTP path - the bearer token's `admin` scope IS the authorisation gate. Mirror of Phase 3 PR-1 (`POST /v1/restart`). Drive-by ADC fix: `+shutdown` with no comment no longer broadcasts an empty banner (matches `+restart`). Body / response shape documented in [`docs/HTTP_API.md` §10.2](docs/HTTP_API.md). 3.2.x only, not backported.
- [#82](https://github.com/luadch-ng/luadch/issues/82) Phase 3 PR-3 (#225) - HTTP API `GET /v1/log/error?lines=N` (admin scope). `cmd_errors` plugin v0.13 coexists ADC `+errors` and the new HTTP endpoint via a shared `read_log_tail()` helper. Pattern-setter for log-read endpoints (Phase 3 PR-4 `/v1/log/cmd` will mirror). Drive-by ADC fix: `+errors` tail off-by-one corrected (now returns exactly maxlines=200 lines instead of an approximation). Body / response shape documented in [`docs/HTTP_API.md` §10.2](docs/HTTP_API.md). 3.2.x only, not backported.
- [#82](https://github.com/luadch-ng/luadch/issues/82) Phase 3 PR-4 (#225) - HTTP API `GET /v1/log/cmd?lines=N` (admin scope). `etc_cmdlog` plugin v1.3 coexists ADC `+cmdlog show` and the new HTTP endpoint. ADC path unchanged (whole-file dump to chat banner); HTTP path is line-tail per §6.4, same shape as Phase 3 PR-3 (`/v1/log/error`). Body / response shape documented in [`docs/HTTP_API.md` §10.2](docs/HTTP_API.md). 3.2.x only, not backported.
- [#82](https://github.com/luadch-ng/luadch/issues/82) Phase 3 PR-5 (#225) - HTTP API `DELETE /v1/log/{name}` (admin scope). `etc_log_cleaner` plugin v0.9 coexists ADC `+cleanlog <name>` and the new HTTP endpoint. `{name}` is one of `error` / `cmd` (matching the plugin's supported set; spec was originally aspirational about `event` / `script`, now corrected). Bypasses the ADC-side `activate_X` cfg gates consistent with the rest of Phase 3 - admin token IS the auth gate. Body / response shape documented in [`docs/HTTP_API.md` §10.2](docs/HTTP_API.md). 3.2.x only, not backported.
- [#159](https://github.com/luadch-ng/luadch/issues/159) (Sopor) - pre-compiled `linux-aarch64` release artifact. The `release.yml` workflow gains a `build-linux-aarch64` job on GitHub's native `ubuntu-24.04-arm` runner (Cobalt 100, public-repo-free since 2025). Produces `luadch-vX.Y.Z-linux-aarch64.tar.gz` alongside the existing x86_64 / Windows artifacts on every tag push. Covers Raspberry Pi 3+ / 4 / 5 / Zero 2W with a 64-bit OS (>95% of the installed Pi base in 2026). Backported to `release/3.1.x` as v3.1.9 - the workflow lives in `.github/`, which is mirrored from master for every backport release, so the cherry-pick is purely the workflow file.
- (Boro, [forum thread](https://forum.dchublist.org/viewtopic.php?f=25&t=1195)) - the hub now identifies itself as **Luadch-NG** rather than Luadch on the wire and in user-visible defaults. The ADC `AP` (application) field in `IINF` changes from `APLUADCH` to `APLUADCH-NG` for normal-client, reg-only, and pinger SUP paths; the `IINF` `NI` placeholder in the reg-only pre-auth handshake template changes from `Luadch` to `Luadch-NG`; the `core/const.lua` `PROGRAM_NAME` constant becomes `Luadch-NG` (used in the boot banner and `cmd_hubinfo`); the `FORK` constant shortens to `fork by Aybo` so the banner reads `Luadch-NG vX.Y.Z by blastbeat and pulsar (2007-YYYY), fork by Aybo`. Default `cfg_defaults.hub_name` and `etc_usercommands_toplevelmenu` follow suit ("Luadch-NG Hub" / "Luadch-NG Commands"); existing installations with persisted cfg are unaffected. Rationale: the fork has diverged enough from upstream (Lua 5.4, security-hardening, full build-system rewrite) that hublist scrapers like dchublist.org should track it as distinct software, not as legacy Luadch. 3.2.x only, not backported.
- [#147](https://github.com/luadch-ng/luadch/issues/147) T3.1 (HBRI) - the hub now accepts a BINF carrying BOTH `I4` and `I6` in one frame, so dual-stack peers can advertise both addresses on login. The hub validates the field matching the connecting TCP source's family against `userip` under `kill_wrong_ips`; the OTHER family is forwarded to other clients as-is (unverified). That trade-off is unavoidable - a peer connecting on v4 has no v6 socket through which we could authenticate their v6 address. Documented in [`docs/SECURITY.md`](docs/SECURITY.md). Post-login INF updates still cannot mutate either I4 or I6 (the #97 closeout in `scripts/hub_inf_manager.lua` stays in force; the comment expanded to mention HBRI explicitly so a future contributor does not relax the asymmetry). Spec verification on 2026-05-14: CTM and RCM carry no IP (ADC §6.3.8 / §6.3.9 - confirmed via [adc.sourceforge.io](https://adc.sourceforge.io/ADC.html) and the luadch parser at `core/adc.lua:388-414`), so the original plan-doc claim of an "IP-spoof check at DCTM/ECTM/DRCM/ERCM" was retracted - those handlers stay as pure relays. New positive smoke test `test_binf_with_both_i4_and_i6_accepted`. Second item under Phase 8b (see [`docs/phases/PHASE_8B_DUAL_STACK.md`](docs/phases/PHASE_8B_DUAL_STACK.md)). 3.2.x only, not backported.
- [#107](https://github.com/luadch-ng/luadch/issues/107) - dual-stack listening on the same port (HTTP/80-style). `core/server.lua` `_server` registry switches from `port`-keyed to `(port, family)`-keyed; the second `addserver()` call with the same port number on the other family no longer hits the existence check. Operators can now use `tcp_ports = { 5000 }, tcp_ports_ipv6 = { 5000 }` and let one URL serve both stacks instead of publishing two URLs or running an external proxy. The historical `5000` / `5002` split still works unchanged for operators who prefer it. The bundled luasocket forces `IPV6_V6ONLY = 1` on AF_INET6 sockets at creation (`luasocket/src/inet.c` `inet_trycreate`), so the v6 listener does not accidentally also accept v4-mapped traffic - a comment in `core/server.lua` documents this implicit dependency. `docs/CONFIGURATION.md` / `docs/DOCKER.md` updated to reflect the new layout. New smoke test asserts both listeners bind on the same port. First item under Phase 8b (see [`docs/phases/PHASE_8B_DUAL_STACK.md`](docs/phases/PHASE_8B_DUAL_STACK.md)). 3.2.x only, not backported.
- [#137](https://github.com/luadch-ng/luadch/issues/137) (Sopor) - `etc_hubcommands.lua` now catches the literal-bracket mistake. Users who type `[+!#]command` (with the square brackets, reading the doc notation as if it were the actual syntax) get a hint and the broadcast is swallowed - same swallow-and-hint mechanism as the bare-word case (#223). Critical: the hint never echoes the input args, because the args can carry a password when the user typed e.g. `[+!#]reg <user> <pw>`. Matches the literal-bracket form with one or more of `+`, `!`, `#` inside the brackets. Plugin bumped to v0.05. 3.2.x only, not backported.

### Notes

- ⚠️ **Default change** - `ssl_ports_ipv6` default flipped from `{ 5003 }` to `{ 5001 }` to align with `ssl_ports` now that same-port dual-stack is supported since v3.2.x (post-#107). Operators upgrading **without an explicit `ssl_ports_ipv6` in their `cfg/cfg.tbl`** will see the v6 TLS listener move from port 5003 to port 5001 (same as v4). Operators who previously published `adcs://hub.example.com:5003` to v6 clients must EITHER add `ssl_ports_ipv6 = { 5003 }` to their `cfg/cfg.tbl` to keep the historical port OR update their published URLs. The historical 5000/5001/5002/5003 split still works for operators who set it explicitly. Deferred cosmetic flip from Phase 8b (#107). 3.2.x only, not backported.

### Refactors

- [#166](https://github.com/luadch-ng/luadch/issues/166) - cosmetic refactor: unified `return nil` exit pattern in `etc_trafficmanager.lua` `onConnectToMe` / `onRevConnectToMe` / `onSearchResult` listeners. Three listeners had two `return nil` paths (inside-gate "allow" + outside-gate "exempt") that were functionally identical. Replaced with a single explicit `return nil` after the gate block. Behaviour unchanged. Bytecode is two instructions shorter per listener (a deduplicated `LOADNIL` / `RETURN1` pair), verified with `luac -l`. `onSearch` is not part of this refactor because its control-flow shape is different (no masterlevel gate, returns `PROCESSED` after manual fan-out). Plugin bumped to v2.3. 3.2.x only, not backported.

- Phase-journal housekeeping sweep: removed dead `local doc = use "doc"` imports in `core/server.lua` and `core/util.lua` (the `core/doc.lua` auto-doc generator is disabled since Phase 6 but the dead imports lingered; `core/doc.lua` itself stays on disk for potential future re-enable). Surfaced by a phase-doc audit. 3.2.x only, not backported.

### Documentation

- New [`docs/PLUGIN_SANDBOX_MIGRATION.md`](docs/PLUGIN_SANDBOX_MIGRATION.md) for third-party plugin authors whose plugins worked pre-2026-05-23 (pre-#206). Lists every primitive that became unreachable across Tier-1 + Tier-2 sub-PRs (#210, #211, #212, #213) with copy-paste old-API → new-API mappings. Driven by a post-#206 audit of the companion `luadch-ng/scripts` repo that found 2 of 30 third-party plugins broken (`ptx_freshstuff` uses `loadfile/dofile`, `ptx_RSSFeedWatch` uses `require`); the doc covers their patterns + every other case in the bundled-plugin audit. [`docs/PLUGIN_API.md`](docs/PLUGIN_API.md) §2 also updated to reflect the post-#206 whitelist as the live spec; it no longer claims "full os/io libraries are available". 3.2.x only, not backported.

- [#167](https://github.com/luadch-ng/luadch/issues/167) - documented the `etc_trafficmanager.lua` admin escape valve as intentional. Operators at level >= `masterlevel` (60 by default) bypass the block filter on **three** event types (`onConnectToMe`, `onRevConnectToMe`, `onSearchResult`) even when on `block_tbl`; the `[BLOCKED]` description flag still applies. Two reasons: (1) admin self-soft-lock protection (typo-resistance on `+trafficmanager block <yournick>`), (2) the threat-model assumes ops are trusted. The fourth listener (`onSearch`) has no exempt gate by design - blocked ops cannot send searches, but the block does not lock them out of PM / main-chat. Hard-block-everyone is not implemented because no operator has reported needing it; design options (global toggle, per-block flag, separate filter-min-level cfg) are sketched in the issue body for future revisits. Code-comment-only change next to the `masterlevel` definition. 3.2.x only, not backported.


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
