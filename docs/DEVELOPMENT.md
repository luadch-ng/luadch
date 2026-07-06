# Developing luadch

Engineering how-to for anyone (human or AI assistant) writing code in this
repo. `CLAUDE.md` holds the working agreement, architecture map, and roadmap;
this file holds the mechanics: how to author a core module, write a plugin,
test, harden untrusted-input code, and what "done" means.

Written in English so every contributor can read it (project convention). No
point-in-time numbers here either - link the source of truth, don't transcribe
it.

---

## 1. Orientation - which doc for which task

| You want to... | Read |
|---|---|
| Know the rules / architecture / roadmap | `CLAUDE.md` |
| Build from source (Linux / Windows / ARM) | [`BUILDING.md`](BUILDING.md) |
| Deploy / operate a built hub | [`INSTALLING.md`](INSTALLING.md), [`CONFIGURATION.md`](CONFIGURATION.md), [`DOCKER.md`](DOCKER.md) |
| Write or extend a plugin | [`PLUGIN_API.md`](PLUGIN_API.md) (primary) + §3 here |
| Migrate a pre-sandbox plugin | [`PLUGIN_SANDBOX_MIGRATION.md`](PLUGIN_SANDBOX_MIGRATION.md) |
| Add an HTTP API endpoint | [`HTTP_API.md`](HTTP_API.md) §5 + §3 here |
| Understand the threat model / harden code | [`SECURITY.md`](SECURITY.md) + §5 here |
| Author a **core** module | §2 here |
| Write / run tests | [`../tests/README.md`](../tests/README.md) (harness) + §4 here |
| Know what a finished PR contains | §6 here (Definition of Done) |
| Read the history of a past phase | [`phases/`](phases/) |

---

## 2. Authoring a core module (`core/*.lua`)

Core modules run under `core/init.lua`'s **restricted environment**: the
module's `_ENV` has no standard globals. Every stdlib name and every other
module must be pulled in explicitly through `use`.

```lua
local use = use            -- the ONE global the restricted env grants

local type   = use "type"  -- capture every global you touch, as a local
local pairs  = use "pairs"
local string = use "string"
local ipmatch = use "ipmatch"   -- other core modules load the same way
```

### The `use`-trap (burned twice: #353, #358)

```lua
local type = type          -- WRONG. `type` is not in the restricted _ENV.
```

This is the single most common core-module mistake and it is **invisible in
unit tests**: a unit test loads the module with `loadfile(...)` into the test's
own `_G` (which does have `type`), so the bare global resolves and the test
passes. At real hub boot the module loads under the restricted `_ENV` and dies
with `attempt to read undeclared var: 'type'`. Same for a naked `pairs(...)`
call, `os.time()`, `math.floor()` - anything you did not capture via `use`.

**Local self-check before pushing** - load the module under a strict env that
mimics `init.lua` (this is exactly what caught a clean run in the mmdb reader):

```lua
-- strict_load.lua - run: lua5.4 strict_load.lua
local real = { type=type, pairs=pairs, ipairs=ipairs, string=string,
               table=table, tonumber=tonumber, tostring=tostring, error=error,
               pcall=pcall, io=io, math=math }
local function use(name)
  local v = real[name]; if v ~= nil then return v end
  error("use: unregistered dep '"..name.."'")   -- add real deps as needed
end
local env = setmetatable({ use = use }, {
  __index = function(_, k) error("UNDECLARED GLOBAL: '"..tostring(k).."'", 2) end })
assert(loadfile("core/yourmodule.lua", "t", env))()   -- errors on any bare global
```

### Registration + load order

Add the module name to the `_core` array in `core/init.lua`, **with a comment
explaining any ordering constraint** (init.lua calls each module's optional
`init()` in array order after loading them all). A module that does `use "X"`
at load time must appear after `X` in the array. Read the existing `_core`
comments before inserting - they document real ordering dependencies (e.g.
`secrets` after `cfg`, `ipmatch` before `blocklist`, `mmdb` after `ipmatch`).
Not every module belongs in `_core`: some are pulled in on demand via `use`
from another module (e.g. `cfg_secret`, whose `init()` needs `cfg` to be up).

### Rules

- **Passive at load.** A core module must only define functions and return its
  table at load time. No file I/O, no socket, no boot-time work in the module
  body - put that in an optional `init()` that init.lua calls after all modules
  are loaded (cfg + out are available by then).
- **1500-line ceiling** per module (Phase 6). Over that, split it.
- **`core/hub.lua` main chunk is AT Lua's 200-local cap.** A new file-scope
  `local` in hub.lua fails the build. Use lazy `use "X"` at the call site, or
  reuse an existing function with a flag parameter. Treat hub.lua's file-scope
  locals as frozen.
- **Security-sensitive surfaces** (network I/O, auth, ADC parsing, config, any
  untrusted-byte parser) get the §5 treatment and are flagged for extra review
  per `CLAUDE.md` §1a.1.

---

## 3. Plugin authoring - deltas on top of PLUGIN_API.md

[`PLUGIN_API.md`](PLUGIN_API.md) is the primary reference (sandbox contents,
listener registration + return semantics, `hub.import`, objects, pitfalls).
The conventions below are either not in it or are easy to get wrong:

- **Plugin state path:** persistent tables go to `scripts/data/<plugin>.tbl`
  (via `util.savetable` / `util.loadtable`). Operator-facing artifacts
  (exports, backups) go to `cfg/`. This matches `cmd_ban`, `etc_clientblocker`,
  `etc_blocklist` (all under `scripts/data/`).
- **Never export a mutable table across `+reload` (getter idiom).** `hub.import`
  shallow-copies the export table, so any consumer holding a direct reference
  goes stale the moment your plugin rebinds the local (e.g. `bans = {}` in a
  clean handler, or `state = loadtable()` in `onStart` on reload). Burned in
  #238 / #239. Fix: either mutate the table in place (never rebind the local),
  or export a **getter function** `function() return state end` so callers
  always read the live table. See the `scripts/etc_aliases.lua` header.
- **i18n: all-or-nothing, en + de.** If a plugin uses `cfg.loadlanguage`, every
  operator-visible string goes through it, and both `scripts/lang/<name>.lang.en`
  and `.lang.de` ship. Keep DC jargon (Hub, Slot, Share, OP, Kick, Ban, Nick,
  PM) in English in both files. Do not half-translate.
- **Operator *policy* text goes in cfg, not lang.** A kick/ban reason the
  operator is meant to customise (e.g. `etc_geoip_kick_reason`) belongs in a cfg
  key, not a `.lang` key - a lang key with the same fallback silently *shadows*
  the cfg key (`local r = lang.x or cfg.get("x")` makes the cfg lever dead), and
  the operator's edit has no effect. Lang files are for the hub-language UI; a
  per-hub policy message is cfg (matches `etc_clientblocker`'s `default_reason`).
- **A plugin that needs a core module must whitelist it.** Plugins have no
  `use`; a core module (e.g. `mmdb`, `blocklist`) is only reachable if its name
  is in `SANDBOX_GLOBALS` in [`core/scripts.lua`](../core/scripts.lua). Forgetting
  this loads fine in a unit test (which sets `_G`) but the plugin cannot see the
  module on the real hub. `os`/`io` reach plugins only through the curated
  `_os_safe`/`_io_safe` shims (no file-stat; use a file's own embedded timestamp,
  not mtime, for staleness).
- **`scriptversion` bump on any semantic change** (behaviour, cfg keys, wire
  surface) - the companion `luadch-ng/scripts` repo syncs by version.
- **Config defaults + validator go in `core/cfg_defaults.lua`.** Add the key
  with a type/range validator closure (see the `ratelimit_pos_number` /
  `_RATELIMIT_TIER_FIELDS` precedents) so an operator typo becomes a clear
  cfg-load error and default-fallback, not silent misbehaviour. Use
  `types_utf8` (not `types_string`) for text keys.
- **Activation gate:** a plugin only runs if it is whitelisted in `cfg.scripts`
  (drop-in is not enough), and `examples/cfg/cfg.tbl` should list it (enabled or
  disabled per its default policy). Array order in `cfg.scripts` = listener-chain
  order; structural plugins (e.g. `hub_inf_manager`) must precede plugins that
  depend on their effect.
- **Audit fire-sites:** state-changing actions emit `audit.build` / `audit.fire`
  with the firstnick-canonical actor. See [`SECURITY.md`](SECURITY.md) and the
  `#84` audit-log conventions.

### HTTP endpoints

- **`util_http.http_register_user_action`** (from `core/util_http.lua`) for
  actions whose target is a **SID** (kick, redirect, gag, ...): it does the SID
  extraction + online-check + non-bot preflight and builds the standard response
  envelope, so the plugin owns only the action body. Reference call sites:
  `scripts/cmd_disconnect.lua`, `scripts/cmd_redirect.lua`.
- **Raw `hub.http_register`** for read endpoints, non-SID target keys (CIDR,
  numeric id, nick/cid/ip like `cmd_ban`), or a non-standard envelope.
- Request schema uses `min`/`max` (not `minimum`/`maximum`); `enum` is
  supported. Filter/sort via `core/http_filter.lua` - pick the right field
  bucket (`string_fields` = substring, `boolean_fields` = strict true/false,
  `integer_fields` = exact + `_min`/`_max`). Full contract:
  [`HTTP_API.md`](HTTP_API.md) §5-§7.
- `dkjson` encodes an empty Lua table as JSON `[]`. For an object-shaped empty
  value, `setmetatable(t, { __jsontype = "object" })`.

---

## 4. Testing

Harness details (running the smoke suite, ports, `--keep-staging`, adding a
wire test) live in [`../tests/README.md`](../tests/README.md). This section is
the authoring contract + the gotchas that are only learned by getting burned.

### Unit tests (`tests/unit/<name>_test.lua`)

Pure-Lua, no sockets. They stub the `use` shim, `loadfile` the module under
test from the repo root, and count assertions with a tiny harness. Canonical
shape (see `tests/unit/blocklist_test.lua`, `mmdb_test.lua`):

```lua
_G.use = function(name)                    -- stub the restricted-env shim
  local real = { type=type, string=string, table=table, --[[ ... ]] }
  if name == "ipmatch" then return _loaded_ipmatch end   -- real deps too
  return real[name] or error("shim: missing dep " .. name)
end
local mod = assert(loadfile("core/yourmodule.lua"))()

local pass, fail = 0, 0
local function eq(what, got, want) --[[ increment + print FAIL ]] end
-- ... assertions ...
os.exit(fail == 0 and 0 or 1)
```

Run from the repo root before pushing (CI is one iteration too slow - #277):

```sh
lua5.4 tests/unit/yourmodule_test.lua      # exit 0 = pass, 1 = fail
```

**Register every new unit test in `.github/workflows/smoke.yml` on BOTH legs**
- the Linux job runs `lua5.4 tests/unit/X_test.lua`, the Windows job runs the
same under `shell: msys2 {0}` with `lua`. An unregistered test is silent
non-coverage.

### Regression tests must fail pre-fix (`CLAUDE.md` §1a.7)

A test that is green on both old and new code proves nothing. For a bug fix,
prove the new test **fails on the unpatched code** and passes patched:

```sh
cp core/yourmodule.lua /tmp/patched.lua
git checkout HEAD -- core/yourmodule.lua          # restore pre-fix version
lua5.4 tests/unit/yourmodule_test.lua             # expect the new case to FAIL
cp /tmp/patched.lua core/yourmodule.lua           # restore the fix
lua5.4 tests/unit/yourmodule_test.lua             # all green
```

Exception (`CLAUDE.md`-validated): a fix whose diff IS the proof (e.g. an
index that provably can never reach the out-of-range value) may skip the
ceremony - but the default is strict.

### Smoke harness gotchas (`tests/smoke/run.py`)

- **`TESTS`-list vs staging-runner ordering.** The staging-runner block runs
  under a level-100 identity that gets a strict `ratelimit_tiers` overlay
  (`msg_burst` as low as 2). A BMSG-heavy test placed there starves the token
  bucket and times out. Put BMSG-heavy tests in the initial `TESTS` list
  (before the mode switch).
- **ADC `\s` escaping.** Spaces on the wire are `\s`. A predicate like
  `"0 entries total" in frame` never matches (`"0\sentries\stotal"` on the
  wire) - decode with a helper, and when you *send* a multi-word BMSG body use
  `\\s` in the Python literal (a raw space terminates the body and the rest
  becomes ADC flags).
- **Dynamic `Content-Length`.** For an HTTP body, compute
  `str(len(body)).encode("ascii")` - a hardcoded length that mismatches hangs
  the server.
- **`wait_for_file` for the API token.** The first-boot token is written
  asynchronously; poll for the file instead of racing it.
- **Deadlines use `socket.gettime()`, not `os.time()`** - integer-second
  precision creates flakes at fractional boundaries.

---

## 5. Security checklists

`SECURITY.md` is the threat model. These are the code-review checklists.

### Untrusted-input parser checklist

Any code reading operator-supplied or network-supplied bytes (config/table
files, `.mmdb`, ADC frames, HTTP bodies, external feeds) runs on paths where a
crash / hang / OOM takes down the single-threaded hub. Required:

- **Bounds-check every read.** `string.sub` silently truncates past the end
  (no error) - guard length before slicing. `string.byte` past the end returns
  nil and the next arithmetic throws - catch it.
- **Bound total WORK, not just recursion depth.** A depth guard does not stop a
  wide-shallow amplification (N pointers each re-expanding one shared M-element
  structure = N*M work at constant depth). Add a per-operation budget. This was
  a runtime-proven CRITICAL DoS in the mmdb reader (#365).
- **`pcall`-wrap the parse** so corrupt/hostile input degrades to `(nil, err)`,
  never a thrown error on a boot / refresh path. Remember `pcall` catches
  throws, NOT hangs or OOM - the work budget is what protects those.
- **Cap size before reading into RAM.** Check the file/response size against a
  ceiling before slurping it.
- **Validate before trusting derived arithmetic.** e.g. reject a claimed
  `node_count` that would overflow when multiplied, before you multiply.

### Privilege / hierarchy checklist

- **Online vs offline hierarchy divergence (#320).** Online code reads
  `target:level()` (object); offline code reads `target.level` (profile table).
  A privilege check (can actor act on target?) MUST cover BOTH paths - fixing
  only one leaves an escalation hole. Grep both when touching any
  kick/ban/reg/level-change surface.
- **HTTP admin token is total-trust.** It maps to a synthetic level-100 actor
  and bypasses the ADC hierarchy guard by design - the token IS the trust
  surface. Document it at the call site; never treat a token request as a
  lower-privilege actor.

### Fail-safe checklist

- **Periodic file re-reads must RETAIN the last-good handle on failure.** A
  plugin that re-reads a file on a timer (a GeoIP `.mmdb`, an external feed
  file) MUST keep the previously-loaded reader if the reopen fails - never
  null-it-on-failure. A non-atomic `cp new over old` has a truncation window, a
  permission blip is transient; null-on-failure silently turns enforcement OFF
  until the next successful reload (a fail-*open*). Pattern: `reopen(path,
  current)` returns `current` on open failure and only swaps on success (closing
  the old handle then). Reviewer-caught in #78 D2.

---

## 6. Definition of Done (per PR)

A change is not done until all of the following hold. This is the concrete
expansion of `CLAUDE.md` §1 for a single PR.

- [ ] **Code** matches the surrounding style; no new file-scope local in
      `core/hub.lua`; core modules use `use "X"` for every global.
- [ ] **Tests**: unit and/or smoke coverage added; for a bug fix, the
      regression **provably fails pre-fix** (§4); ran locally with `lua5.4`
      before pushing.
- [ ] **CI registration**: any new unit test is wired into `smoke.yml` on both
      the Linux and Windows legs.
- [ ] **Docs**: `CLAUDE.md` and affected `docs/*.md` updated in the SAME PR
      when architecture, conventions, module layout, defaults, or an
      engineering rule changed. No stale numbers introduced.
- [ ] **Plugin extras** (if a plugin): `.lang.en` + `.lang.de`, cfg default +
      validator in `cfg_defaults.lua`, `examples/cfg/cfg.tbl` entry,
      `scriptversion` bumped, audit fire-site where a state change happens.
- [ ] **CHANGELOG.md** `[Unreleased]` entry (Breaking / Features / Bugfixes /
      Notes, breaking-first, short bullets).
- [ ] **Two-pass review** (§1a.6): independent reviewer + maintainer
      spot-check; ALL findings addressed (concerns and nits), not just
      blockers, or each skip justified in writing.
- [ ] **GitFlow A**: branched off `dev`, PR to `dev`; `Part of #N` (not
      `Closes #N`) for multi-tier trackers; `gh` pinned to `--repo
      luadch-ng/luadch`.
