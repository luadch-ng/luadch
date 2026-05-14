# Phase 8b - ADC dual-stack: #107 listening + T3.1 HBRI

> Working agreement: see [`CLAUDE.md`](../../CLAUDE.md) §1.
> Phase scope: see [`CLAUDE.md`](../../CLAUDE.md) §5 ("Phase 8+ - Future features").
> Tracker: [issue #147](https://github.com/luadch-ng/luadch/issues/147) (ADC-protocol coverage roadmap),
> [issue #107](https://github.com/luadch-ng/luadch/issues/107) (dual-stack listening).

**Status:** in flight - PR 1 (#107) merged via #176; PR 2 (T3.1 HBRI) implementation underway
**Target line:** 3.2.x on master
**Scope:** Two coupled ADC dual-stack items - the listener-registry change unblocks the dual-family INF work that depends on it:

- **#107 dual-stack listening** - `core/server.lua` `_server` registry currently port-keyed; second `addserver()` on the same port (different family) is refused. Switch to `(port, family)` key.
- **T3.1 HBRI** - dual-stack INF with both `I4` and `I6`, family-aware CTM/RCM forwarding. Sequenced after #107 because clean dual-stack smoke depends on same-port v4 + v6.

## Items deferred from the original sweep

**T2.2 BLOM (Bloom Filter SCH)** - still demand-driven, only worth it for hubs with 100+ users. Out of scope.

**T3.2 ZLIF (full-stream zlib)** - architectural, depends on a Phase 8 IO refactor for HTTP API (#82) / Prometheus (#83). Stays in Phase 8 backlog.

## 1. Items at a glance

| Item | LoC (est) | Touched files | Smoke add | Issue |
|---|---|---|---|---|
| #107 dual-stack listening | ~30-50 | `core/server.lua`, `docs/CONFIGURATION.md`, `tests/smoke/run.py` | 1 test | #107 |
| T3.1 HBRI | ~150 | `core/hub_dispatch.lua`, `core/types.lua`, `scripts/hub_inf_manager.lua`, `tests/smoke/run.py` | 2-3 tests | #147 (T3.1 row) |

---

## 2. #107 dual-stack listening

### 2.1 Current state

[`core/server.lua`](../../core/server.lua) lines:

- [`core/server.lua:134`](../../core/server.lua#L134) - `local _server`
- [`core/server.lua:174`](../../core/server.lua#L174) - `_server = { }    -- key = port, value = table; list of listening servers`
- [`core/server.lua:346`](../../core/server.lua#L346) - `_server[ serverport ] = nil` in `handler.kill()`
- [`core/server.lua:847`](../../core/server.lua#L847) - `elseif _server[ p.port ] then` - existence check
- [`core/server.lua:858-862`](../../core/server.lua#L858-L862) - family branch: `if p.family == "ipv6" then ... luasocket.tcp6() else luasocket.tcp4()`
- [`core/server.lua:905`](../../core/server.lua#L905) - `_server[ port ] = handler` - registry store
- [`core/server.lua:912-928`](../../core/server.lua#L912-L928) - `killall = function( ) ... _server = { } ...`

`_server` is read in exactly one place beyond the existence check (the `killall` reset). No external consumers (verified via grep).

### 2.2 The fix

Compose key as `(port, family)`:

```lua
local function _key( port, family )
    return tostring( port ) .. "/" .. ( family or "ipv4" )
end
```

Four sites change:
- L174 comment update
- L346 in `handler.kill`: thread `p.family` through `wrapserver` so the family is in scope, then `_server[ _key(serverport, serverfamily) ] = nil`
- L847: `elseif _server[ _key( p.port, p.family ) ] then`
- L905: `_server[ _key( port, p.family ) ] = handler`

`killall` at L923 is a full-table reset, unchanged.

`wrapserver()` arity grows by one (`family`). Single caller (`addserver` itself), so the arity change is internal.

### 2.3 IPV6_V6ONLY

The bundled luasocket already forces `IPV6_V6ONLY = 1` on every `AF_INET6` socket at creation time: [`luasocket/src/inet.c:349-356`](../../luasocket/src/inet.c#L349-L356), `inet_trycreate`. This is **already correct** under the bundled luasocket and **does not need a Lua-side `setoption("ipv6-v6only", true)` call**.

**Document the implicit dependency in a comment near the family branch** so a future luasocket fork that drops the default does not silently re-introduce the dual-stack-leak bug.

### 2.4 Backwards-compat

Operators using the historical `tcp_ports = { 5000 }, tcp_ports_ipv6 = { 5002 }` split continue to work unchanged - different ports never collided in either pre- or post-fix registry. After the fix, operators can pick same-port `{ 5000 }, { 5000 }`. **No cfg-defaults change in this PR.**

The cfg-defaults flip (e.g. `ssl_ports_ipv6 = { 5001 }` to align with `ssl_ports`) is **deferred to a trailing cosmetic PR** with its own CHANGELOG and operator notice.

### 2.5 Documentation flip

[`docs/CONFIGURATION.md`](../../docs/CONFIGURATION.md) currently has a paragraph noting "luadch's listener registry is currently port-keyed - same port number on v4 and v6 is not supported, see #107." Remove on fix; add a "supported since v3.2.x" note.

### 2.6 Smoke test (`test_dual_stack_same_port_binds`)

**Setup:**
1. Override `cfg.tbl` to use `tcp_ports = { TEST_PORT_PLAIN }, tcp_ports_ipv6 = { TEST_PORT_PLAIN }`.
2. Start hub.
3. `wait_for_port(HUB_HOST, TEST_PORT_PLAIN, ...)` for IPv4.
4. `wait_for_port("::1", TEST_PORT_PLAIN, ...)` for IPv6.

**Asserts:**
- Both v4 and v6 listeners bind without `address already in use`.
- A plain ADC handshake succeeds on each.
- A v4 connection does NOT see v6-only traffic (catches a regression where IPV6_V6ONLY gets dropped).

**Approximate LoC:** ~60 Python.

### 2.7 Risk register for #107

| Risk | Likelihood | Mitigation |
|---|---|---|
| Existing operators with `5002`/`5003` configs break | None | Different ports never collided. Fully backwards-compat. |
| `IPV6_V6ONLY` portability across luasocket forks | Medium | Bundled luasocket auto-sets it. Comment-of-record near the `tcp6()` call mitigates. Do not add a Lua-side `setoption` call - silent fail on older luasocket would be worse than the C default. |
| `wrapserver` arity break for external consumer | None | Module-local function. |
| `_server` registry consumer beyond addserver / killall | None | Verified via grep. |
| Address-already-in-use loop in `add_server_handler` retry path | Negligible | The pre-fix error string does not match the retry path's match condition. Post-fix the error stops happening. |

---

## 3. T3.1 HBRI - dual-stack INF (next PR after #107)

### 3.1 Where BINF is parsed

[`core/hub_dispatch.lua:308-424`](../../core/hub_dispatch.lua#L308-L424) - `_identify.BINF`. Current single-family probe at [`core/hub_dispatch.lua:317-324`](../../core/hub_dispatch.lua#L317-L324):

```lua
local ipver
local infip = adccmd:getnp "I4"
if infip then
    ipver = "I4"
else
    infip = adccmd:getnp "I6"
    if infip then ipver = "I6" end
end
```

For HBRI, probe both fields independently. Validate the family that matches the TCP source against `userip`; leave the other family unverified-but-stored.

### 3.2 Where `kill_wrong_ips` enforces

1. **Initial BINF (identify state)** - [`core/hub_dispatch.lua:342-348`](../../core/hub_dispatch.lua#L342-L348). HBRI change: compare only the family that matches the TCP source.
2. **Post-login BINF (normal state)** - [`scripts/hub_inf_manager.lua:101-106`](../../scripts/hub_inf_manager.lua#L101-L106). **HBRI keeps this restriction**: both I4 and I6 stay forbidden on post-login INF (re-affirms #97 closeout). Comment the asymmetry so a future contributor does not "fix" it.

### 3.3 CTM and RCM carry NO IP (correction)

The original planning version of this doc claimed CTM/RCM carry an
IP that the hub should validate per-family. **Spec verification on
2026-05-14 contradicts that claim.** Per
[ADC.html §6.3.8](https://adc.sourceforge.io/ADC.html) (CTM) and
[§6.3.9](https://adc.sourceforge.io/ADC.html) (RCM):

```
CTM <protocol> <separator> <port> <separator> <token>
RCM <protocol> <separator> <token>
```

Neither carries an address. The target client uses the sender's INF
(I4 / I6) to find the IP. The luadch parser confirms this at
[`core/adc.lua:388-414`](../../core/adc.lua#L388-L414) - CTM has
three positional params (protocol, port, token), no I4/I6 named
params.

**Consequence:** the family-aware routing happens entirely at the
BINF level (which IPs the hub stores and forwards). The dispatcher
handlers at [`core/hub_dispatch.lua:567-588`](../../core/hub_dispatch.lua#L567-L588)
stay as pure relays. **No CTM/RCM code changes** under HBRI.

### 3.4 Address-family classification

Single-line idiom already used in the existing fallback at
[`core/hub_dispatch.lua:340`](../../core/hub_dispatch.lua#L340):

```lua
userip:find( ":", 1, true ) and "I6" or "I4"
```

No factored `types.classify_ip` helper - one-line pattern reused
in-place keeps the diff small. If a future feature needs the
classification in a third place, factor then.

### 3.5 Landmines

- **3.5.L1:** [`scripts/hub_inf_manager.lua:58-59`](../../scripts/hub_inf_manager.lua#L58-L59) must keep BOTH I4 AND I6 on the forbidden-on-INF list. Document why so a future contributor does not relax the asymmetry between BINF (dual-stack allowed) and INF (both banned).
- **3.5.L2:** [`core/hub_dispatch.lua:332-341`](../../core/hub_dispatch.lua#L332-L341) "hub fills in nil IP" logic gets subtler. Client may legitimately advertise only I4 or only I6 (v4-only or v6-only host). Hub stamps the connecting family only if it was missing; the other field stays as-sent if the client provided it.
- **3.5.L3:** Smoke harness's `_adc_login()` at [`tests/smoke/run.py:294-301`](../../tests/smoke/run.py#L294-L301) currently sends `I40.0.0.0` (wildcard). Keep at least one test path that exercises this no-IP branch even after dual-stack smoke is added.

### 3.6 Smoke test for HBRI

One new positive test:

- **`test_binf_with_both_i4_and_i6_accepted`** (~50 LoC) - BINF with both I4 (matching TCP source) and I6 (non-matching, e.g. `fe80::1`) accepted, advances to IGPA. Validates that the hub probes both fields independently and validates only the family matching the TCP source.

Test count after this PR: 42 -> 43.

### 3.7 Risk register for HBRI

| Risk | Likelihood | Mitigation |
|---|---|---|
| Malformed dual-stack INF | Medium | Wire-level parser at [`core/adc.lua`](../../core/adc.lua) accepts I4/I6 as any string and stamps the connecting family with the TCP-source IP. The HBRI change does NOT add IP-syntax validation (none existed before, none added). Operator-facing impact = same as today: a syntactically invalid string in I4/I6 just won't match the TCP-source IP and trips `kill_wrong_ips` (if enabled). |
| IP-spoof protection regressed for the connecting family | High if mishandled | The implementation validates `inf_i4` against `userip` ONLY when the connection is v4, `inf_i6` ONLY when v6. The "other family" stays unverified. Documented in `docs/SECURITY.md`. |
| Operator confusion: "the other family is unverified" | Low-medium | The HBRI trade-off is unavoidable (no socket through which to authenticate the non-connecting family). Document explicitly in `docs/SECURITY.md`. |
| Existing single-family clients regress | None | A BINF carrying only I4 (the #161 case) stays exactly as today: the field is validated against userip, no I6 path consulted. |
| #97 post-login I4/I6 ban relaxed accidentally | Medium-high if mishandled | [`scripts/hub_inf_manager.lua`](../../scripts/hub_inf_manager.lua) keeps both flags forbidden on post-login INF. Comment expanded to mention HBRI explicitly so a future contributor does not "fix" the asymmetry. |

---

## 4. PR breakdown

CLAUDE.md §1.6 = one logical change per PR.

### PR 1: #107 dual-stack listening (merged via [#176](https://github.com/luadch-ng/luadch/pull/176), 2026-05-14)

| File | Change |
|---|---|
| `core/server.lua:134,174,346,847,858-862,905,923` | `_server` registry composite key `(port, family)`; thread `p.family` into `wrapserver` |
| `core/server.lua` (new comment) | Document the implicit `IPV6_V6ONLY` dependency on luasocket |
| `docs/CONFIGURATION.md` | Remove the port-keyed limitation paragraph; add a supported-since note |
| `CHANGELOG.md` | "Bugfixes" or "Features": dual-stack same-port listening; closes #107 |
| `tests/smoke/run.py` | 1 new test (`test_dual_stack_same_port_binds`) |
| `docs/phases/PHASE_8B_DUAL_STACK.md` | This file - bundled as the phase setup |

**Closes:** #107.

**Reviewers / risk:** Low-medium. Registry change is mechanical but touches a hot path. The `IPV6_V6ONLY` assumption is the portability landmine.

### PR 2: T3.1 HBRI dual-stack INF (this PR)

Sequenced after PR 1. Scope contracted vs the original planning notes
after the 2026-05-14 spec verification (see §3.3) - CTM and RCM carry
no IP, so this PR touches only the BINF parser, not the four CTM/RCM
dispatcher entries.

| File | Change |
|---|---|
| `core/hub_dispatch.lua:317-348` | Probe I4 and I6 independently; family-aware `kill_wrong_ips` validation against TCP-source IP. Stamp the connecting family with userip when missing / placeholder. |
| `scripts/hub_inf_manager.lua:49-61` | Comment-of-record explaining why I4/I6 stay forbidden on post-login INF |
| `CHANGELOG.md` | "Features": HBRI dual-stack INF (family-aware BINF validation, no CTM/RCM change because those frames carry no IP) |
| `tests/smoke/run.py` | 1 new test (`test_binf_with_both_i4_and_i6_accepted`) |

**Closes:** Tier-3.1 of #147.

**Reviewers / risk:** Medium-high. New security check at the CTM/RCM relay path. Pre-merge review will need to confirm the family-classification logic across all four handlers and that the post-login I4/I6 ban stays intact.

---

## 5. Closure criteria

- [ ] PR 1 (#107) merged. Smoke green on Linux + Windows. CHANGELOG entry. `docs/CONFIGURATION.md` paragraph removed. Comment-of-record in `core/server.lua` near `tcp6()` call.
- [ ] PR 2 (HBRI) merged. Smoke green on Linux + Windows. CHANGELOG entry. `docs/SECURITY.md` §5 updated with the I4-vs-I6 trade-off note. Three new smoke tests pass.
- [ ] This doc updated with PR numbers and status flipped to `complete`.
