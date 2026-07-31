# Luadch v3.1.8

**Modernisation-complete patch release.** Closes the [#80](https://github.com/luadch-ng/luadch-ng/issues/80) ratelimit v2 and [#147](https://github.com/luadch-ng/luadch-ng/issues/147) ADC protocol coverage tracks. After this release the 3.1.x line is **stable, security-fixes-only**; new feature work moves to the 3.2.x line on `master`. See [`CLAUDE.md` §8](https://github.com/luadch-ng/luadch-ng/blob/master/CLAUDE.md#8-release-lines-and-support-policy) for the full release-line policy.

## ⚠️ Before upgrading

Back up your `cfg/`, `scripts/lang/`, `scripts/data/`, `scripts/cfg/`, `certs/`, and `secrets/` directories. This release adds new keys to several lang files (additive, see below) and introduces several new optional cfg keys for the ratelimit / RDEX / PING extensions.

```sh
tar -czf "luadch-backup-$(date +%F).tar.gz" cfg scripts certs secrets
```

## Lang file changes

Operators with stock bundled lang files get the new keys automatically via the Docker autosync from [#118](https://github.com/luadch-ng/luadch-ng/pull/118) or `cmake --install build` for source builds. Operators with **custom** translations have a small one-time additive merge:

| File | New key |
|---|---|
| `cmd_shutdown.lang.{en,de}` | `msg_hub_disabled` |
| `cmd_restart.lang.{en,de}` | `msg_hub_disabled` |

Missing keys fall back to the hardcoded English string ("Hub is shutting down." / "Hub is restarting.") so the hub stays functional.

## Cfg additions

All new keys are additive with defaults that preserve v3.1.7 behaviour. No `cfg/cfg.tbl` migration is required.

### Ratelimit v2 ([#80](https://github.com/luadch-ng/luadch-ng/issues/80))

```lua
-- Per-bucket rate / burst, each independently tunable
ratelimit_user_pm_rate  = 5,   ratelimit_user_pm_burst  = 10,
ratelimit_user_inf_rate = 2,   ratelimit_user_inf_burst = 20,
ratelimit_user_ctm_rate = 2,   ratelimit_user_ctm_burst = 30,

-- Per-userlevel tier overlay - any subset of fields per tier,
-- missing fields fall back to the global scalars above
ratelimit_tiers = { },
ratelimit_tier_for_level = { },
```

Worked example for the tier overlay is in [`docs/SCRIPTS.md`](https://github.com/luadch-ng/luadch-ng/blob/master/docs/SCRIPTS.md#rate-limit-configuration). At defaults (empty tier tables) behaviour is identical to v3.1.7.

### ADC protocol coverage ([#147](https://github.com/luadch-ng/luadch-ng/issues/147))

```lua
-- ADC-EXT RDEX rich redirect
hub_redirect_protocols = 3,         -- bitmask (ADC=1, ADCS=2, NEODC=4)
hub_redirect_alternatives = { },    -- list of alternative URLs as RX fields
hub_redirect_permanent = false,     -- PT1 flag on redirects

-- ADC-EXT PING min-hubs federation policy (also from #146)
min_user_hubs = 0,                  -- min OTHER hubs (federation requirement)
min_reg_hubs = 0,
min_op_hubs = 0,
```

## Highlights

### Ratelimit v2 ([#80](https://github.com/luadch-ng/luadch-ng/issues/80), 4 PRs + 2 review followups)

The hub's per-user rate-limit machinery split BMSG / DMSG / EMSG / BINF / DCTM / DRCM into five independent buckets. Each bucket has its own rate + burst cfg keys, and **all five become optionally tier-mappable per user level** via the new `ratelimit_tiers` + `ratelimit_tier_for_level` overlay. Op-level bypass preserved. Worked tier-overlay example in [`docs/SCRIPTS.md`](https://github.com/luadch-ng/luadch-ng/blob/master/docs/SCRIPTS.md#rate-limit-configuration).

A strict-positive validator rejects `rate = 0` / `burst = -1` / NaN at cfg-load time, with a clear `out_error` log entry; the previous silent-mute failure mode under operator typo is gone.

### ADC protocol coverage ([#147](https://github.com/luadch-ng/luadch-ng/issues/147), 8 PRs)

Eight protocol-completeness items shipped as small, additive PRs:

- **NATT relay** (DNAT / DRNT, ADC-EXT 3.9) - hub-relay-only NAT-traversal for passive-passive transfers.
- **RDEX rich redirect** - `IINF.RP` advertisement + `IQUI.RX` / `PT` NPs on every kick / redirect.
- **PING completeness** - `SS` / `SF` aggregate share + file count, `HE` email, `MU` / `MR` / `MO` min-hubs federation policy now emitted in the ADPING reply. Hublist scrapers see the full spec-defined data.
- **STA emission codes** - `cmd_shutdown` / `cmd_restart` emit `ISTA 212` ("Hub disabled") before close so clients distinguish a graceful shutdown from a network glitch. `cmd_ban` switches from incorrect 230 / 231 to spec-correct `ISTA 232` for finite-TL temporary bans.
- **FRES routing** - feature-filtered search-result delivery (F-class) now dispatched.
- **HQUI from client honored** - client-initiated quit triggers a clean close in any state instead of `ISTA 125` unknown-command.
- **ECTM / ERCM dispatch** - modern E-class CTM / RCM variants accepted (was: silently dropped).
- **Passthrough extensions documented** - `TYPE` / `ONID` / `DFAV` / `FEED` and friends are explicitly transparent passthrough (no SUP advertisement needed, hub relays the commands without inspection).

Per the audit the hub is now at **~90% ADC + ADC-EXT coverage** for hub-relevant features. Remaining 10% is BLOM (Tier 2, demand-driven) and HBRI / ZLIF (Tier 3, deferred to 3.2.x).

### Operator documentation

- New [`docs/SCRIPTS.md`](https://github.com/luadch-ng/luadch-ng/blob/master/docs/SCRIPTS.md) lists every bundled plugin (commands + cfg keys) with a full rate-limit configuration guide.
- README cleaned up - dropped the "what's different in this fork" section now that the modernisation programme is done; added a release-line status table near the top.
- [`CLAUDE.md` §8](https://github.com/luadch-ng/luadch-ng/blob/master/CLAUDE.md#8-release-lines-and-support-policy) documents the post-3.1.8 maintenance-branch model.

## Bugfixes

- `user.sendsta` typo ([#151](https://github.com/luadch-ng/luadch-ng/pull/151)) - `pairs(nil)` crash on callers that omitted the optional flags arg, present since the API was added.
- `user.redirect` `MS<quitmsg>` was emitted raw; multi-word reasons produced malformed ADC. Now escaped.
- Smoke battery's PM / CTM / RCM / NATT burst tests previously short-circuited at the target-lookup before reaching the rate-limit gate; they now self-target and exercise the actual code paths.

## Notes

- **No breaking changes at defaults.** Every new cfg key has a default that preserves v3.1.7 behaviour. Operators upgrading without touching cfg get the new features behind unchanged knobs.
- **ERES no longer accepted by the parser.** ADC 5.3.6 defines only D and F classes for RES; the parser context tightened to `[FD]` as part of FRES routing. No known client emits ERES; exotic NMDC bridges that did would now see parse-time rejection instead of forward-as-E-class.
- **3.1.x maintenance from this release on.** New feature work goes to `master` (3.2.x line); security fixes for 3.1.x go to a `release/3.1.x` branch created from this tag. See [`CLAUDE.md` §8](https://github.com/luadch-ng/luadch-ng/blob/master/CLAUDE.md#8-release-lines-and-support-policy).

## Downloads

| File | Platform |
|---|---|
| `luadch-v3.1.8-linux-x86_64.tar.gz` | Linux glibc x86_64 |
| `luadch-v3.1.8-windows-x86_64.zip`  | Windows x86_64 (MinGW UCRT64) |
| `ghcr.io/luadch-ng/luadch:v3.1.8`   | Container, linux/amd64 + linux/arm64 |

## Migration from v3.1.7

Drop the new install tree in place of the old one (or `git pull && cmake --build build && cmake --install build` from source). Container users get both the bundled `*.lua` sync and the lang add-only sync on the next `docker compose up -d` after `pull`.

No `cfg/cfg.tbl` migration is needed - all new keys are additive with defaults. To opt into the tier-overlay rate-limit, see the worked example in [`docs/SCRIPTS.md` Rate-limit configuration](https://github.com/luadch-ng/luadch-ng/blob/master/docs/SCRIPTS.md#rate-limit-configuration).

## Build from source

```sh
git clone --branch v3.1.8 https://github.com/luadch-ng/luadch-ng.git
cd luadch
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
cmake --install build
```
