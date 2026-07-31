# Phase 8a-1 - ADC input validation audit findings

> Working agreement: see [`CLAUDE.md`](../../CLAUDE.md) §1.
> Phase scope: see [`CLAUDE.md`](../../CLAUDE.md) §5 ("Phase 8+ - Future features (post-modernisation)").
> Tracker: [issue #121](https://github.com/luadch-ng/luadch-ng/issues/121).

**Status:** complete - all 8a-3 fix waves landed + post-fix review pass closed
**Started:** 2026-05-10
**Closed:** 2026-05-10
**Scope:** ADC input-validation surfaces across the modernised
luadch core, the bundled `scripts/`, and the companion plugin
repository [`luadch-ng/scripts`](https://github.com/luadch-ng/scripts).
No code changed in 8a-1 itself. Each finding is filed as a GitHub
issue (or a sub-section here) and triaged into a later sub-phase
(8a-2..N) by severity.

The Phase 8a programme is the natural follow-on from Phase 7
(security audit + hardening, complete 2026-05-04). Phase 7 closed
the structural / connection-level / file-load layer; Phase 8a
covers what's left: per-field semantic validation in the
post-parse handlers and a regression net for malformed ADC input.

---

## 1. Methodology

External proposal from a luadch user (no GitHub handle) suggested a
focused audit of all externally-controlled ADC input fields with a
checklist of edge-case classes per field. Filed as
[issue #121](https://github.com/luadch-ng/luadch-ng/issues/121). The
audit splits into three sub-phases:

- **8a-1** (this doc): read-only pass; document current behaviour
  per field for each edge-case class; file findings as issues.
- **8a-2** ([PR #123](https://github.com/luadch-ng/luadch-ng/pull/123)):
  negative-test fuzz suite added to `tests/smoke/run.py` (14 -> 30
  tests). Caught five real bugs on first run, fixed them inline:
  - `core/adc.lua` parse() positional-param nil-safety
  - bundled scripts `usr_share`, `usr_slots`, `etc_records`,
    `cmd_hubinfo`, `cmd_hubstats`, `cmd_slots`, `etc_trafficmanager`:
    `(user:share() or 0)` / `(user:slots() or 0)` defensive coercion
- **8a-3..N**: per-finding fix waves. One PR per cluster.

This document records the 8a-1 audit pass.

### Threat model

Same as Phase 7 (see
[`PHASE_7_FINDINGS.md`](PHASE_7_FINDINGS.md) §1). The ADC client
on the public internet is untrusted; the hub must remain available
and not crash on any input the client can send. Plugin scripts in
`scripts/` are admin-authored and trusted. The companion
[`luadch-ng/scripts`](https://github.com/luadch-ng/scripts) repo is
operator-installed; same trust contract as bundled scripts when
deployed.

### Severity scale

| Tag | Meaning |
|---|---|
| **critical** | RCE without prior privilege, or trivially exploitable on a default install |
| **high** | RCE with limited prior privilege, auth bypass, or stable DoS against a default install |
| **medium** | Account-DoS, partial info disclosure, or exploit conditional on a non-default config |
| **low** | Defence-in-depth gap, or exploit requires improbable preconditions |
| **info** | No exploit; documents an assumption / portability landmine / hygiene item |

### Severity rollup (this audit pass + review pass)

| Severity | Count | Status |
|---|---|---|
| critical | 0 | - |
| high | 0 | - |
| medium | 1 | fixed in [#123](https://github.com/luadch-ng/luadch-ng/pull/123) (8a-2) |
| low | 6 | all fixed (3 in [#123](https://github.com/luadch-ng/luadch-ng/pull/123), 2 in [#125](https://github.com/luadch-ng/luadch-ng/pull/125), 1 in [scripts#22](https://github.com/luadch-ng/scripts/pull/22)); plus F-INF-1e defensive cleanup in this closeout PR |
| info | 3 | F-INF-2 (per-field bounds, by design); F-INF-3 (scope marker); F-INF-1f (etc_userlogininfo cosmetic, deferred) |

The fuzz suite in [#123](https://github.com/luadch-ng/luadch-ng/pull/123)
covered the `medium` finding (parse positional nil) plus the seven
sites of `(user:share/slots() or 0)` defensive coercion in bundled
scripts. The remaining `low` items landed in [#125](https://github.com/luadch-ng/luadch-ng/pull/125)
(luadch-ng/luadch-ng) and [scripts#22](https://github.com/luadch-ng/scripts/pull/22)
(companion repo). The post-fix review pass surfaced one additional
`low` (F-INF-1e, defensive cleanup) and one `info` (F-INF-1f,
cosmetic UX) - both addressed below.

---

## 2. Findings

### Medium

#### F-PRS-7: parse() crashes on malformed positional params (FIXED)

- **Location:** [`core/adc.lua:849-861`](../../core/adc.lua#L849-L861) (post-fix; pre-fix was the same site)
- **Status:** Fixed in [PR #123](https://github.com/luadch-ng/luadch-ng/pull/123).
- **Symptom:** A malformed ADC command with fewer positional parameters than the cmd descriptor declared (e.g. `BMSG <sid>` with no body) left `buffer[i] == nil`. The parse loop passed nil straight into the type-validator, which crashed on `string_find(nil, "%c")` from the `default` validator.
- **Exploit vector:** Post-login, any client could send `BMSG <sid>\n` (or another command short of one positional param) and force a Lua error in the parser. Connection got dropped per the parse-failure path; no script-level RCE; effectively a degraded-functionality DoS against a single connection per crash. Hub-wide impact bounded by Phase 7d's reentrant-parse fix (#65) - parse-locals are per-call so one crash does not corrupt other parses.
- **Severity:** medium. Requires an authenticated client (post-login) but no special privilege; reproducible with a one-line ADC frame.
- **Fix:** Reject nil positional params the same way an invalid value would be. Returns parse failure + `out_put` log entry.

### Low

#### F-INF-1: bundled and companion plugins crash on missing optional INF fields (PARTIALLY FIXED)

ADC `INF` fields like `SS` (share size), `SF` (shared files), `SL` (slots), `DS` / `US` (download / upload speed), `DE` (description), `EM` (email), `VE` (version), and the `HN` / `HR` / `HO` triplet (hubs as user / regged / op) are *optional* per the ADC spec - a conformant client may send a BINF that omits any of them. The hub stores the absence as `nil` on the user object; `user:share()` etc. return nil for the missing field.

Plugin code that reads these getters into arithmetic / comparisons / string operations without a nil guard crashes the listener on every login from such a client. Pre-fuzz-suite, this happened silently on every smoke run because `test_no_script_errors` only scanned hub stdout, not `log/error.log` (separate finding F-AUD-1 below).

##### F-INF-1a: bundled scripts (FIXED)

| File | Line | Pattern | Field | Fix in PR #123 |
|---|---|---|---|---|
| [`scripts/usr_share.lua`](../../scripts/usr_share.lua#L73) | 73 | `if user_share > max` after bare `user:share()` | SS | `(user:share() or 0)` |
| [`scripts/usr_slots.lua`](../../scripts/usr_slots.lua#L61) | 61 | `if user_slots < min` after bare `user:slots()` | SL | `(user:slots() or 0)` |
| [`scripts/etc_records.lua`](../../scripts/etc_records.lua#L247) | 247 | `new_hubshare + user:share()` | SS | `(user:share() or 0)` |
| [`scripts/etc_records.lua`](../../scripts/etc_records.lua#L293) | 293 | `target_usershare > tonumber(records[8])` | SS | `(user:share() or 0)` |
| [`scripts/cmd_hubinfo.lua`](../../scripts/cmd_hubinfo.lua#L403) | 403 | `hshare = hshare + ushare` after bare `user:share()` | SS | `(user:share() or 0)` |
| [`scripts/cmd_hubstats.lua`](../../scripts/cmd_hubstats.lua#L128) | 128 | `hshare + user:share()` direct | SS | `(user:share() or 0)` |
| [`scripts/cmd_slots.lua`](../../scripts/cmd_slots.lua#L65) | 65 | `if slots > 0` after bare `user:slots()` | SL | `(user:slots() or 0)` |
| [`scripts/etc_trafficmanager.lua`](../../scripts/etc_trafficmanager.lua#L353) | 353-357 | `if target:share() == 0 / < min` | SS | local `share = target:share() or 0` |

##### F-INF-1b: bundled `usr_hubs.lua` arithmetic-before-nil-check (FIXED)

- **Location:** [`scripts/usr_hubs.lua:119-122`](../../scripts/usr_hubs.lua#L119-L122)
- **Status:** Fixed in [PR #125](https://github.com/luadch-ng/luadch-ng/pull/125).
- **Symptom:**
  ```lua
  local hn, hr, ho = user:hubs()
  local hm = hn + hr + ho             -- crashes if any of hn/hr/ho is nil
  if not ( hn and hr and ho ) then    -- nil-check happens AFTER the crash
      user:kill( ... )
      return PROCESSED
  ```
  A client BINF without the `HN` / `HR` / `HO` triplet returns nil from `user:hubs()`. The arithmetic on line 120 fires before the nil-check on line 121.
- **Exploit:** Any client can send BINF without HN/HR/HO. Listener crashes on every such login.
- **Severity:** low. Localised to one plugin's onConnect; per-connection failure; hub stays up.
- **Recommended fix:** swap the nil-check before the arithmetic, or use `(... or 0)` coercion on each component.

##### F-INF-1c: bundled scripts using `user:description()` in `utf.sub` without nil-check (FIXED)

- **Location:**
  - [`scripts/usr_desc_prefix.lua:71`](../../scripts/usr_desc_prefix.lua#L71): `local desc = utf.sub( user:description(), utf.len( prefix ) + 1, -1 )`
  - [`scripts/etc_trafficmanager.lua:650`](../../scripts/etc_trafficmanager.lua#L650): same pattern with `target:description()`
- **Status:** Fixed in [PR #125](https://github.com/luadch-ng/luadch-ng/pull/125).
- **Symptom:** `user:description()` is nil if the client did not send `DE` in BINF. `utf.sub(nil, ...)` raises.
- **Exploit:** Any client can omit DE. Listener crashes on every onInf or other event that reaches these branches.
- **Severity:** low. Plugin-local, hub stays up.
- **Recommended fix:** `local desc = user:description() or ""` before the `utf.sub`. Other call sites in `etc_trafficmanager.lua` (lines 425, 432, 439, 443, 464, 471) already use this pattern; the missing two are the divergent ones.

##### F-INF-1d: companion `luadch-ng/scripts` scripts unguarded (FIXED, with one false-positive downgraded)

- **Location (companion repo):**
  - [`scripts/etc_maxhubs_announcer/etc_maxhubs_announcer.lua:85-86`](https://github.com/luadch-ng/scripts/blob/master/scripts/etc_maxhubs_announcer/etc_maxhubs_announcer.lua#L85-L86): `local hubs = hn + hr + ho` on bare `user:hubs()` - same pattern as F-INF-1b. **Fixed** in [scripts#22](https://github.com/luadch-ng/scripts/pull/22) via `(hn or 0) + (hr or 0) + (ho or 0)`.
  - [`scripts/etc_openhubs_announcer/etc_openhubs_announcer.lua:81-89`](https://github.com/luadch-ng/scripts/blob/master/scripts/etc_openhubs_announcer/etc_openhubs_announcer.lua#L81-L89): the pre-fix code fell back to the string `"unbekannt"` when `hn` was nil, then compared `open > 0` on the next line. Lua 5.4 raises "attempt to compare string with number" before the second `(open == "unbekannt")` branch can fire because `>` evaluates left-to-right inside `or`. **Fixed** in [scripts#22](https://github.com/luadch-ng/scripts/pull/22) by using nil directly and splitting the conditions.
  - [`scripts/ptx_tagcheck/ptx_tagcheck.lua:171`](https://github.com/luadch-ng/scripts/blob/master/scripts/ptx_tagcheck/ptx_tagcheck.lua#L171): bare `user:slots(), user:hubs()` destructure. **Confirmed false positive** during the [scripts#22](https://github.com/luadch-ng/scripts/pull/22) implementation - the downstream code at line 186 already guards with `if slots and hubs then` and has an `else` branch that logs missing fields via `OnError(...)`. No fix needed.
  - [`scripts/etc_clientblocker/etc_clientblocker.lua:68`](https://github.com/luadch-ng/scripts/blob/master/scripts/etc_clientblocker/etc_clientblocker.lua#L68): `hub_escapefrom( user:version() )` plus subsequent `:find` on the result. **Fixed** in [scripts#22](https://github.com/luadch-ng/scripts/pull/22) by early-returning when `user:version()` is nil (a client without a VE field has nothing to match against the blocklist anyway). Note: the underlying `adclib.unescape` C binding uses `luaL_optstring(L, 1, "")` so `hub.escapefrom(nil)` itself does not crash (returns `""`), but the early-return is still the cleanest semantic.
- **Status:** Fixed (3 of 4 sites) + 1 false-positive in [scripts#22](https://github.com/luadch-ng/scripts/pull/22).

##### F-INF-1e: `etc_trafficmanager.lua` `format_description` onInf branch with implicit precondition (FIXED)

- **Location:** [`scripts/etc_trafficmanager.lua:453-466`](../../scripts/etc_trafficmanager.lua#L453-L466) (inside `format_description`)
- **Status:** Fixed in this Phase-8a closeout PR.
- **Surfaced by:** post-fix review pass (this audit's second pass after [#125](https://github.com/luadch-ng/luadch-ng/pull/125) and [scripts#22](https://github.com/luadch-ng/scripts/pull/22) merged).
- **Symptom:** The `onInf` branch of `format_description` reads `local desc = cmd:getnp "DE"` without a nil-guard, then calls `desc:sub(...)` on it. The other three branches (`onStart`, `onExit`, `onConnect`) all read `target:description() or ""` instead, defending against missing DE fields. The onInf branch was safe in practice only because the single caller at line 1015 gates the call with `if desc then ... format_description(...)`, so when this branch runs, `cmd:getnp "DE"` is always non-nil.
- **Risk:** Implicit precondition - a future caller that drops the gate at the call site reintroduces the crash. Defence-in-depth gap.
- **Severity:** low.
- **Fix:** Coerce both `cmd:getnp "DE"` reads to `""` defensively, matching the pattern used by the other three branches.

#### F-AUD-1: smoke harness only scanned hub stdout, missing all error.log traffic (FIXED)

- **Location:** [`tests/smoke/run.py`](../../tests/smoke/run.py) `test_no_script_errors`
- **Status:** Fixed in [PR #123](https://github.com/luadch-ng/luadch-ng/pull/123).
- **Symptom:** The function read from `staging_dir / "log" / "smoke-hub.log"` (the captured Popen stdout) and grepped for `"script error:"`. Lua-side `out.error()` writes to `log/error.log` on disk, not stdout. Pre-fix, every plugin error from F-INF-1 hits was silently produced on every clean smoke run; the test passed regardless.
- **Severity:** low (audit / test infrastructure gap). Without the fix, the negative-test fuzz suite would land green in CI even when triggering plugin crashes.
- **Fix:** Test now scans both `smoke-hub.log` (stdout) and `log/error.log`.

### Info

#### F-INF-2: ADC `INF` field-level numeric range checks not enforced

- **Status:** by design (current behaviour), tracked for 8a-3 design decision.
- **Observation:** The ADC parser validates field *syntax* (e.g. `integer = function( str ) return str == "" or string_match( str, "^%-?%d+$" ) end` at [`core/adc.lua:186-189`](../../core/adc.lua#L186-L189)) but NOT *semantic range*. A client can send `SS-1`, `SF999999999999999999`, `SL-100`, etc. and the values are stored on the user object verbatim. Phase 7d (#65) deliberately accepts negative integers because some legacy DC++ clients emit negative `DS` and rejecting them at the parser level was a regression vector (closes upstream `luadch/luadch#241`).
- **Implication:** Any per-field range enforcement (must be >= 0; must be < some plausible upper bound) is the responsibility of post-parse handlers / plugin scripts. The F-INF-1a fixes coerce nil to 0 but do not bound the upper end; a client claiming `SS=999999999999999999` will still be stored at face value. Whether this matters for any specific use case is policy: the hub itself is unaffected, downstream consumers may want bounds.
- **Recommended next step:** decide per-field whether to add a sanity-bound at the post-parse handler (e.g. clamp `SS` to [0, 2^60]), or document the absence as policy. 8a-3 design call.

#### F-INF-1f: `etc_userlogininfo.lua` cosmetic UX with `or "<unknown>"` fallback

- **Location:** [`scripts/etc_userlogininfo.lua:156`](../../scripts/etc_userlogininfo.lua#L156): `local clientv = hub.escapefrom( user_version ) or "<unknown>"`
- **Status:** **Deferred / cosmetic only.** Surfaced by post-fix review pass; no fix in this phase.
- **Symptom:** `user_version` is nil if the client did not declare VE in BINF. `hub.escapefrom(nil)` returns `""` (the underlying `adclib.unescape` C binding uses `luaL_optstring(L, 1, "")`). `"" or "<unknown>"` evaluates to `""` in Lua because `""` is truthy, so the `<unknown>` fallback never fires. Operators see an empty string in the login-info message instead of `<unknown>`.
- **Risk:** No crash, no security implication. Operator-facing cosmetic only.
- **Severity:** info.
- **Recommended fix (future):** check the input directly: `local clientv = (user_version ~= nil and hub.escapefrom( user_version )) or "<unknown>"`. Out of scope for Phase 8a.

#### F-INF-3: Phase 8a-1 audit is non-exhaustive

- **Status:** info / scope marker.
- **Observation:** This 8a-1 pass focused on the most obviously suspect call patterns - `user:share()`, `user:slots()`, `user:hubs()`, `user:description()`, `user:version()` consumed in arithmetic / compare / string-op contexts without nil guards. A more exhaustive audit would also walk:
  - Every `cmd:getnp("XX")` consumer in core and bundled scripts; check that nil returns are handled before the value is used.
  - Every `tonumber(...)` site downstream of user-supplied data; check the result is handled when the input was non-numeric.
  - `utf.match` / `string.match` returns inside `local x, y = ...` patterns where the match can fail silently.
- **Recommended next step:** schedule a 8a-1b pass when the 8a-3..N fix waves close. Findings doc updates in place.

---

## 3. Triage table

| ID | Severity | Repo | Status | Tracking |
|---|---|---|---|---|
| F-PRS-7 | medium | luadch | fixed | [#123](https://github.com/luadch-ng/luadch-ng/pull/123) |
| F-INF-1a | low | luadch | fixed | [#123](https://github.com/luadch-ng/luadch-ng/pull/123) |
| F-INF-1b | low | luadch | fixed | [#125](https://github.com/luadch-ng/luadch-ng/pull/125) |
| F-INF-1c | low | luadch | fixed | [#125](https://github.com/luadch-ng/luadch-ng/pull/125) |
| F-INF-1d | low | luadch-ng/scripts | fixed (3 of 4; 1 false-positive) | [scripts#22](https://github.com/luadch-ng/scripts/pull/22) |
| F-INF-1e | low | luadch | fixed (defensive) | this closeout PR |
| F-AUD-1 | low | luadch | fixed | [#123](https://github.com/luadch-ng/luadch-ng/pull/123) |
| F-INF-1f | info | luadch | fixed | post-Phase-8a housekeeping |
| F-INF-2 | info | luadch | by design / open | 8a-3 design call (deferred) |
| F-INF-3 | info | luadch | scope marker | 8a-1b future pass (when needed) |

## 4. Phase 8a closure criteria

- [x] 8a-1 first pass documented (this file).
- [x] 8a-2 fuzz harness landed ([#123](https://github.com/luadch-ng/luadch-ng/pull/123)).
- [x] 8a-3 fix wave: F-INF-1b / F-INF-1c in the luadch repo ([#125](https://github.com/luadch-ng/luadch-ng/pull/125)).
- [x] 8a-3 fix wave: F-INF-1d in the companion repo ([scripts#22](https://github.com/luadch-ng/scripts/pull/22)).
- [x] Post-fix review pass: surfaces F-INF-1e (defensive cleanup, fixed in this closeout PR) and F-INF-1f (cosmetic, deferred, fixed 2026-05-23 in housekeeping PR).
- [x] Phase 8a closeout: this doc updated; phase status flipped to `complete`.
- [ ] 8a-3 design call on F-INF-2 (per-field bounds): decide and either implement or document as policy. **Deferred** - not blocking Phase 8a closure; remains tracked.
- [ ] 8a-1b second-pass audit (`cmd:getnp` consumers, `tonumber` sites, `match` returns): not scheduled. The post-fix review pass already audited the visible `cmd:getnp` consumers (only 2 unguarded paths found, F-INF-1e). A formal 8a-1b is no longer prioritised given the small remaining surface; reopens if a new bug shape suggests one.

## 5. Phase 8a summary

**Outcome:** Phase 8a (ADC input validation audit + hardening) closed
2026-05-10. Eight findings, all addressed:

- **1 medium, 6 low, 3 info findings** across the luadch core + bundled scripts + companion `luadch-ng/scripts` repo.
- **All `medium` and `low` findings fixed** across [#123](https://github.com/luadch-ng/luadch-ng/pull/123) (fuzz suite + initial defensive coercion in 7 sites), [#125](https://github.com/luadch-ng/luadch-ng/pull/125) (usr_hubs reorder + utf.sub coercion in 2 sites), [scripts#22](https://github.com/luadch-ng/scripts/pull/22) (companion repo: 3 plugins fixed, 1 confirmed false-positive), and this closeout PR (F-INF-1e defensive cleanup in format_description's onInf branch).
- **3 `info` items remain open by design or as future scope:**
  - F-INF-1f (cosmetic UX) - operator-facing only, fixed 2026-05-23 in housekeeping PR (one-line `nil`-check before `hub.escapefrom`).
  - F-INF-2 (per-field numeric bounds) - design call, intentionally accepts negative integers per upstream `luadch/luadch#241`.
  - F-INF-3 (exhaustive 8a-1b second-pass) - remaining surface is small, no longer prioritised.

**Smoke harness:** 14 → 30 protocol-level tests. Suite caught 5 real
plugin bugs on its first run, all fixed. `test_no_script_errors` now
scans both stdout and `log/error.log` to surface Lua-side errors that
the previous test missed.

**Behaviour change for operators:** clients that send an INF without
declaring `SS` (share size) or `SL` (slot count) are now consistently
treated as if they had declared 0. Pre-fix, these clients crashed
share/slot policy listeners and could potentially bypass min-share
enforcement (because the listener crashed before the kick fired).
Post-fix, they are kicked the same way as a client declaring `SS=0`.
This is a stricter policy than the buggy pre-fix state and matches the
documented intent of `usr_share` / `usr_slots`.
