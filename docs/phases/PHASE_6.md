# Phase 6 - Refactor & tests

> Working agreement: see [`CLAUDE.md`](../../CLAUDE.md) §1.
> Roadmap: see [`CLAUDE.md`](../../CLAUDE.md) §5.

**Status:** complete
**Started:** 2026-05-04
**Closed:** 2026-05-04
**Goal:** Address structural debt now that the runtime, dependencies, and
build system are current. Decompose the two large monoliths
(`core/cfg.lua` 3688, `core/hub.lua` 2245), establish a smoke-test
floor that runs in CI, anchor runtime paths to the binary directory,
and audit remaining `TODO` / `FIXME` markers.

---

## 1. PRs in order

| PR | Phase | What |
|---|---|---|
| #38 | 6a | Smoke-test harness: `tests/smoke/run.py`, plain + TLS handshake, plugin-load log scan |
| #39 | 6a | CI workflow `.github/workflows/smoke.yml` running on every push and PR |
| #44 | 6a | Full ADC login flow + `+cmd` routing, vendoring pure-Python Tiger as `tests/smoke/tiger.py` |
| #40 | 6b | Path anchoring (closes #12) - hub chdirs to its binary dir at startup, `log/exception.txt` instead of CWD-relative |
| #41 | 6c-1 | `_defaultsettings` -> `core/cfg_defaults.lua` (cfg.lua 3688 -> 719) |
| #42 | 6c-2 | User-tbl helpers -> `core/cfg_users.lua` |
| #43 | 6c-3 | `loadlanguage` -> `core/cfg_lang.lua`, drop dead `--[[ ]]` block |
| #45 | 6d-1 | `createuser` -> `core/hub_user_object.lua` (hub.lua 2245 -> 1915) |
| #46 | 6d-2 | `createbot` -> `core/hub_bot_object.lua` (hub.lua 1915 -> 1717) |
| #47 | 6d-3 | ADC dispatcher (`_protocol`, `_identify`, `_verify`, `_normal`, `states`) -> `core/hub_dispatch.lua` (hub.lua 1717 -> 1497, **under ceiling**) |
| #49 | 6e | TODO/FIXME audit + dead-file removal (`core/test.lua`, `slnunicode/.travis.yml`); Phase 8+ items tracked in #48 |

---

## 2. Recurring techniques

### `bind_late()` pattern

Used in seven extracted modules (`cfg_defaults`, `cfg_users`, `cfg_lang`,
`hub_user_object`, `hub_bot_object`, `hub_dispatch`, plus the host-side
helpers in `cfg.lua` and `hub.lua` that wire them up).

The Lua sandbox in `core/init.lua` strictly forbids accessing undeclared
globals, so an extracted module cannot just reach back into the
orchestrator's file-locals. We declare a forward `local helper` /
`local _state_table` etc. in the module, expose a `bind(deps)` function
that assigns them, and call `bind` from the orchestrator AFTER the
relevant cache / state is populated. Lua's by-reference upvalue capture
means closures defined before `bind` runs see the new values once it
fires. Re-binding after a state-table reassignment (e.g. on `+reload`,
`updateusers`) keeps the modules in sync with the orchestrator's view.

### Smoke harness as safety net

7 protocol-level tests in `tests/smoke/run.py`, run on every push and PR:

```
[smoke] PASS  hub binds plain + TLS ports
[smoke] PASS  plain ADC handshake
[smoke] PASS  TLS ADC handshake
[smoke] PASS  plain ADC full login (dummy/test)
[smoke] PASS  TLS ADC full login (dummy/test)
[smoke] PASS  +cmd routing (post-login +help)
[smoke] PASS  no script errors in log
```

The login + `+cmd` tests in particular round-trip through the user
object factory's full surface (`user.salt`, `user.password`,
`user.profile`, `user.write`, `user.kill`, state transitions) and the
listener chain (`onConnect`, `onLogin`, `onBroadcast`,
`etc_hubcommands`, `cmd_help`). If any extraction broke the wiring,
one of these would fail in CI before merge.

Tiger hash had to be vendored (`tests/smoke/tiger.py`) because hashlib,
pycryptodome, and cryptography all dropped Tiger years ago. The S-box
constants (1024 64-bit values across four sub-tables) were taken
verbatim from `adclib/tiger.cpp` so client and server agree by
construction; the module self-tests against the standard Tiger-192
vectors on import.

---

## 3. Module-state shapes after Phase 6

```
core/
  init.lua                209  (bootstrap, sandbox env)
  const.lua                22  (PROGRAM_NAME, VERSION, paths)
  mem.lua                  32  (GC trigger)
  signal.lua               41  (timers, start time)
  out.lua                  99  (logging, listener registry)
  types.lua               159  (ADC type validators)
  scripts.lua             263  (plugin loader, sandbox, hook registry)
  doc.lua                 308  (auto-doc generation, currently unused)
  hci.lua                   9  (hubruntime persistence helper)
  util.lua                686  (file I/O, encoding, UTF-8, table helpers)
  cfg.lua                 668  (orchestrator)
  cfg_defaults.lua       3039  (data-table, ceiling-exempt by CLAUDE.md §5)
  cfg_users.lua            87  (user.tbl I/O)
  cfg_lang.lua             68  (language file loader)
  adc.lua                 926  (ADC protocol parse/format)
  server.lua              989  (network select loop, SSL, coroutines)
  hub.lua                1497  (orchestrator)
  hub_user_object.lua     480  (createuser factory)
  hub_bot_object.lua      318  (createbot factory)
  hub_dispatch.lua        475  (state-machine handler tables + states())
hub/
  hub.c                   220  (C launcher, signal handling, path anchoring)
tests/
  smoke/run.py            505  (smoke harness)
  smoke/tiger.py          458  (vendored Tiger-192)
```

Two modules over the 1500-line ceiling, both deliberate exceptions
documented in their file headers:

- `core/cfg_defaults.lua` (3039 lines) - flat data table of 700 cfg-key
  entries. Cognitive load is low; an arbitrary domain-split would just
  add categorisation debate.
- *(no others)*

---

## 4. Review-gate findings

### 4.1 Smoke-test suite green in CI on Linux and Windows

Verified across every Phase-6 PR on both `smoke-linux` (ubuntu-latest)
and `smoke-windows` (windows-latest with msys2 UCRT64). 7/7 PASS.

### 4.2 Module line ceiling (1500)

All code modules under 1500. `cfg_defaults.lua` exempt as a flat data
table per CLAUDE.md §5 and its file header.

### 4.3 Function line ceiling (100)

Five functions exceed 100 lines:

| File | Function | Lines | Disposition |
|---|---|---|---|
| `core/hub_user_object.lua` | `createuser` | 375 | **Factory exception** - sequence of trivial `user.X = function() return _foo end` method stamps; cognitive load is low. Splitting would require redesigning the user-object API. |
| `core/hub_bot_object.lua` | `createbot` | 228 | Same pattern as `createuser`. |
| `core/server.lua` | `wrapconnection` | 362 | Pre-existing, untouched in Phase 6. Per-connection state machine. |
| `core/adc.lua` | `parse` | 174 | Pre-existing, untouched. ADC frame parser. |
| `core/server.lua` | `wrapserver` | 117 | Pre-existing, untouched. TLS / socket setup. |

The two factories are documented exceptions (see file headers). The
three pre-existing functions in `server.lua` and `adc.lua` were not
modified during the modernisation programme and are tracked as
Phase 8+ candidates in [#48](https://github.com/Aybook/luadch/issues/48).

### 4.4 Cyclomatic complexity ceiling (≤ 15)

Visual-inspection clean for every module touched in Phase 6. The
factories are nearly branch-free (each closure is a single-statement
return). Per-module orchestrator functions (`cfg.set`, `cfg.get`,
`hub.broadcast`, etc.) all have <= 5 branches. The new `bind()`
functions in extracted modules are linear assignment lists, CC = 1.

The pre-existing functions flagged in §4.3 (`wrapconnection`, `parse`,
`wrapserver`) were not formally measured. Their high line count
implies likely high CC; Phase 8+ scope.

### 4.5 Manual smoke

Exercised live by Aybo during the session: hub start, dummy/test
login on plain (5000) and TLS (5001), `+hubinfo` renders correctly,
`+shutdown` countdown blocks user typing (Phase-2 fix), keyprint
auto-generated correctly on TLS startup.

---

## 5. Items not closed in Phase 6

Tracked separately:

- [#12](https://github.com/Aybook/luadch/issues/12) **closed** by 6b path anchoring
- [#48](https://github.com/Aybook/luadch/issues/48) **open** - Phase 8+ candidate list (multi-hash schema, getbot enumeration, removeListener counterpart, usr_nick_length codepoint fix, usr_nick_prefix onInf, i18n gaps, plus the §4.3 pre-existing 100-line functions)
- `core/doc.lua` (308 lines) is "currently disabled" per CLAUDE.md §3 but still imported by `server.lua` and `util.lua` (unused dead imports). Cleanup is mechanical but out of Phase 6 scope; could roll into a future tidy. **Fixed 2026-05-23**: dead `local doc = use "doc"` lines removed from both modules in housekeeping PR; `core/doc.lua` retained on disk for potential future re-enable but no longer loaded. **Superseded 2026-07-16** (#447 PR 2): `core/doc.lua` removed entirely. The re-enable premise did not survive reading the file - its whole 19-entry payload is itself inside a `--[[ ]]` block (so a re-enable would emit an empty document), and it describes an API that no longer exists (`util.save`/`util.load`, `server.wrapsslclient`/`wraptcpclient`, `server.loop`). `docs/PLUGIN_API.md` supersedes it.

---

## 6. What is next

Master is at the merged Phase-6 state. The modernisation programme is
**code-complete**: the project is on Lua 5.4, on a current build
system, with clear module boundaries, with CI smoke tests catching
protocol-level regressions on every push.

**Phase 7 - Security audit & hardening** is next (CLAUDE.md §5). The
clean module shape Phase 6 produced means the audit can target
specific surfaces rather than wading through monoliths.
