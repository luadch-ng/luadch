# Phase 3 — Lua 5.1 → 5.4 migration

> Working agreement: see [`CLAUDE.md`](../../CLAUDE.md) §1.
> Roadmap: see [`CLAUDE.md`](../../CLAUDE.md) §5.

**Status:** complete
**Started:** 2026-05-03
**Closed:** 2026-05-03
**Goal:** Move the embedded Lua interpreter from 5.1.5 (EOL since 2012)
to 5.4.7. Touch the C modules and the Lua-side bootstrap as needed to
keep the hub building and behaving identically to before.

---

## 1. Lua version choice

Latest upstream when this phase started was Lua 5.5.0. Decision: **target
Lua 5.4** instead.

Reasons:

- LuaSec 1.3.2 and LuaSocket 3.1.0 (the bundled deps we have to live with
  until Phase 4) are tested against 5.4 in the wild but have not been
  exercised against 5.5 yet. Migrating straight to 5.5 would risk a
  Phase-4 dead-end before we have the Phase-3 baseline secured.
- The hard breaks (`setfenv`, `loadstring`, `unpack`, `LUA_QL`, …) all
  happened between 5.1 and 5.4. Going to 5.5 instead of 5.4 adds almost
  no extra work to bypass — but it changes which dependency
  combinations are even reachable.
- 5.4 → 5.5 is a small later upgrade, not a fundamental retarget.

A future Phase 4.5 / 5.5 micro-bump can take us to 5.5 once Phase 4 has
LuaSec / LuaSocket on confirmed-modern versions.

---

## 2. Activities

The full migration landed as one PR with three logical commits on the
`phase-3/lua-5.4-migration` branch — Lua-version migration cannot be
chunked into separately mergeable PRs because each intermediate state
leaves master broken.

### 2.1 Source drop (commit `e66cdae`)

Replaced `lua/src/` with the upstream Lua 5.4.7 release tarball
(`https://lua.org/ftp/lua-5.4.7.tar.gz`). Project conventions preserved:

- Custom luadch `Makefile` retained.
- Upstream's own Makefile (which 5.4 ships in `src/`) renamed to
  `LuaMakefile` per the existing convention used for 5.1.
- `print.c` (5.1 standalone bytecode dumper, replaced by `luac` in 5.2+)
  removed.
- 8 new files appeared in 5.4.x: `lcorolib.c`, `lctype.c`, `lctype.h`,
  `ljumptab.h`, `lopnames.h`, `lprefix.h`, `lua.hpp`, `lutf8lib.c`.

This commit alone leaves the build broken on purpose; the next one
fixes it.

### 2.2 Build infrastructure + adclib + slnunicode + setfenv (commit `f8f9b8c`)

#### Build infrastructure

- `lua/src/Makefile` (the custom luadch one): added `lcorolib.o`,
  `lctype.o`, `lutf8lib.o` to `OBJS`. Without `lctype.o` the link fails
  with `undefined reference to luai_ctype_` from `llex.c`.
- `compile_with_mingw.bat`: same three new modules added to the explicit
  `gcc -shared -o lua.dll` link list. Plus the new `unicode.lua` shim
  install replaces the old C-compile of `slnunico.c`/`slnudata.c`.
- `compile` (the Linux build script): replaced the slnunicode build
  block with a one-line `cp slnunicode/unicode.lua` install.

#### adclib C-API migration

`adclib/adclib.cpp` had the standard 5.1 → 5.2 idioms:

```cpp
// before
static const luaL_reg adclib[] = { ... };
extern "C" int luaopen_adclib(lua_State* L) {
    luaL_register(L, "adclib", adclib);
    return 0;
}

// after
static const luaL_Reg adclib[] = { ... };           // case fix
extern "C" int luaopen_adclib(lua_State* L) {
    luaL_newlib(L, adclib);                          // 5.2+ canonical
    return 1;                                        // module table is on the stack
}
```

`luaL_newlib` is the standard pattern for a require()-loadable C module
since 5.2.

#### slnunicode replaced with a Lua shim

The bundled slnunicode C module had not seen a real upstream update
since around 2008. It used Lua-5.1 internals removed in 5.2/5.3:
`LUA_QL`, `LUA_GLOBALSINDEX`, `luaL_register`, `LUA_INTFRMLEN`,
`LUA_INTFRM_T`, `LUA_MAXCAPTURES`, plus the 3-arg `lua_dump` signature.

Hand-porting ~1366 lines of unmaintained C to Lua 5.4 means we own that
code as our own ongoing maintenance burden. So before doing it, we did a
**usage audit** instead.

**Pattern audit.** Every `utf.match` / `find` / `gsub` / `gmatch` call
site in `core/` and `scripts/` was extracted and the distinct pattern
strings collected. The result: **40+ patterns, all ASCII-only**. No
Unicode character classes (`%l`, `%u`, etc. matching multibyte
characters); only protocol-level structure parsers like `^%S+ (.*)`,
`^[+!#](%a+)`, `^[012]%d%d$`. So byte-level `string.X` is bit-identical
in behaviour for these.

**Char-aware audit.** `utf.len` / `utf.sub` are used in only **7 sites**,
all of the form `utf.sub(s, utf.len(prefix) + 1, -1)` — "strip a known
prefix". Multibyte prefixes (e.g. `Über:`) need char-precise indices
here, so this needed real char awareness, not byte indices.

**Result:** a ~40-line Lua shim at `slnunicode/unicode.lua` that:

- Delegates byte-safe ops (`format`, `match`, `find`, `gsub`, `gmatch`,
  `rep`, `upper`, `lower`, `reverse`, `byte`, `char`) to `string.X`.
- Uses Lua 5.4's builtin `utf8` library for char-aware ops:
  `utf.len(s)` → `utf8.len(s)`, `utf.sub(s, i, j)` → byte-precise
  slicing via `utf8.offset`.
- Exposes `unicode.utf8` and `unicode.ascii` tables — the same names
  the rest of luadch already requires. **No call-site changes.**

The `slnunicode/` directory is kept on disk for reference; the C
sources are no longer compiled or copied.

**Net effect: 1366 lines of unmaintained C dropped, replaced by 40 lines of pure Lua we own and understand.**

#### Lua-side migration

A pre-flight grep confirmed that `setfenv` is the **only** active
Lua-5.1 idiom in luadch's own code — no `unpack`, no `loadstring`, no
`getfenv`, no `module()`. Two files, four lines:

- `core/init.lua`:
  ```lua
  -- before
  local script, err = loadfile( _path .. name .. ".lua" )
  setfenv( script, _env )
  _global[ name ] = script( )

  -- after
  local script, err = loadfile( _path .. name .. ".lua", "t", _env )
  _global[ name ] = script( )
  ```

- `core/scripts.lua`: the `env` table (which becomes the script's
  `_ENV`) is now built **before** the `loadfile` call so it can be
  passed in as the third argument. Behaviour is identical; just a small
  reorder of unrelated setup code.

The upvalue caches `local setfenv = ...` were removed from both files.

### 2.3 Script fixes surfaced by smoketests

Three script-level bugs were discovered while exercising the hub end-to-end
on Lua 5.4 and addressed in this branch rather than deferred — the first two
were pre-existing bugs that 5.1 had been silently tolerating, the third was
the previously-tracked Windows-platform issue (#16).

**`os.difftime` 1-arg call (commit `d10ea40`).** Twelve script call sites
called `os.difftime( os.time() - start )` — the author already computed the
difference inside the parens, then wrapped it in `os.difftime` (which takes
two arguments). Lua 5.1 silently tolerated the 1-arg form; Lua 5.4 errors
with `bad argument #2 to 'difftime' (number expected, got no value)`. Eleven
scripts touched (cmd_hubstats, cmd_restart, cmd_shutdown, etc_banner,
etc_records, etc_trafficmanager, hub_bot_cleaner, hub_runtime,
hub_user_lastseen, usr_uptime, plus internal call sites). Fix: drop the
redundant `os.difftime` wrapper. The arithmetic `os.time() - start` is
already in seconds.

**`cmd_hubinfo.get_certinfos` missing return (commit `8d80801`).** A
long-standing bug independent of the Lua migration: when the configured
certificate file did not exist (e.g. `make_cert.{sh,bat}` had not been run
for the current build dir), `io.open` returned nil, the `if fd then ... end`
block was skipped, and the function fell through with no return value.
Caller chain `"\t" .. select(1, get_certinfos())` then crashed with
`attempt to concatenate a nil value`. Restructured to a flat early-return
style where every error path explicitly returns three `msg_unknown`
strings; defensive against nil `ssl_params` from cfg as well.

**`cmd_hubinfo` wmic → PowerShell (commit `2e858c0`, closes #16).**
`wmic.exe` was deprecated in Windows 10 21H1 and removed by default in
Windows 11 24H2 / Server 2025+. On those systems the hub launched with
three "Der Befehl wmic..." stderr noises and `+hubinfo` returned
`<UNKNOWN>` for OS / CPU / RAM. Replaced the four `io.popen("wmic …")`
calls with `Get-CimInstance` invocations via PowerShell. Output is the
bare value (no `Caption=` prefix), so the prior `split` parsing is gone;
a `trim` is sufficient. Linux code paths unchanged — the win/unix branch
in each `check_*` function decides which command runs.

### 2.4 Phase journal (this document, final commit)

Documentation of the migration, captured live as it ran. Includes the
audit reasoning so a future maintainer understands why slnunicode is now
40 lines of Lua instead of 1366 lines of C, and why three additional
script fixes landed in the same PR.

---

## 3. Findings

### Filed during Phase 3

None. Three additional bugs surfaced during smoketest (see §2.3) but
all three were small enough and contextually related to the migration
(in `scripts/cmd_hubinfo.lua` and the timer scripts) to fix in this PR
rather than file separately.

### Closed by Phase 3

- **#16** — `cmd_hubinfo.lua` uses wmic which is removed in Windows 11
  24H2+. Closed by commit `2e858c0` (PowerShell `Get-CimInstance`
  replacement).

### Decided "no follow-up" in Phase 3

- Removing the `slnunicode/` directory itself. Kept on disk because
  rename / delete is cosmetic; can ship in a Phase 6 cleanup.
- Auditing for subtle Lua 5.3+ semantic changes (integer vs float,
  removed `math.atan2`/`pow`/etc.). The pre-flight grep showed luadch
  uses none of the removed math helpers, and the AirDC++ end-to-end
  smoketest exercised the integer-vs-float surface area without
  problems.
- The 1-arg `os.difftime` pattern audit was complete after the 12
  occurrences fixed in commit `d10ea40` — a follow-up grep confirmed
  no other instances anywhere in the codebase.

---

## 4. Build statistics

| Configuration                  | Errors | Warnings | Notes |
|--------------------------------|--------|----------|-------|
| Phase 2 baseline (Linux gcc 13)| 0      | 5        | OpenSSL 3.0 deprecation only |
| End of Phase 3 (Linux gcc 13)  | 0      | 5        | unchanged: same OpenSSL warnings |
| Phase 2 baseline (Windows gcc 16) | 0   | 7        | gcc-16 stylistic warnings |
| End of Phase 3 (Windows gcc 16) | 0     | 2        | only `tiger.cpp` parentheses; the others surfaced from the now-removed `slnunicode` C build |

Windows warnings dropped from 7 to 2 — the slnunicode shim eliminated
the gcc-16-stricter warnings that came from compiling the unmaintained
C module.

---

## 5. Smoketest summary

| Test                                                 | Linux | Windows |
|------------------------------------------------------|-------|---------|
| Clean build from scratch                             | ✅    | ✅      |
| Build time                                           | ~25s  | ~37s    |
| Hub binary launches, all 14 core modules load       | ✅    | ✅      |
| All 5 native libs load (incl. the new Lua shim)     | ✅    | ✅      |
| All 70+ scripts in `scripts/` load                   | ✅    | ✅      |
| Version banner prints, port 5000 binds              | ✅    | ✅      |
| Hub responds to ADC `HSUP` handshake                 | ✅    | (n/a) |
| AirDC++ end-to-end (login, `+help`, deflection)     | ✅    | ✅      |
| Clean shutdown on `SIGINT`/`Ctrl+C`                 | ✅    | ✅      |

Note: Lua's `print` is fully buffered when stdout is not a terminal,
so the boot trace appears in chunks rather than line-by-line. The
banner only flushes on shutdown. This is normal Lua/POSIX behaviour
and was already present in the 5.1 era; no migration regression.

---

## 6. Phase 4 entry criteria

Phase 4 is the **dependency updates** phase: bundled libraries get bumped
to current upstream where they are compatible with the now-current Lua
5.4 runtime.

Recommended preconditions before starting:

1. Master is at the merged Phase 3 PR; no uncommitted work; no
   long-running branches.
2. Read each library's CHANGELOG between bundled-version and HEAD —
   cheap reality check on what behaviour might shift.
3. Plan the sequence (suggested order, smallest blast radius first):
   - **basexx** (pure-Lua, zero risk): bump and forget.
   - **LuaSocket** 3.1.0 → current. 3.x line is stable; main thing to
     watch is the `socket.serial` and unix-socket handling that the
     Windows build excludes via the `*.c.not` rename trick.
   - **LuaSec** 1.3.2 → current (1.4.x). Drives the OpenSSL deprecation
     warnings in issue #3; the bump should make those go away.
   - **adclib**, **slnunicode**: in-tree, no upstream — skip in Phase 4.
4. Each library bump is its own commit / PR within Phase 4. Build green
   on both platforms after each one. AirDC++ TLS smoketest after the
   LuaSec bump in particular.
5. **Do not** bundle Phase 5 (CMake migration) into Phase 4. They are
   separate phases for the reason captured in CLAUDE.md §5.

---

## 7. Phase 3 review-gate checklist

- [x] Lua 5.4 source dropped in cleanly
- [x] Linux build green from clean checkout
- [x] Windows build green from clean checkout
- [x] All native libs (including the new Lua shim) load on both platforms
- [x] All 70+ scripts in `scripts/` load on both platforms
- [x] Hub responds to ADC handshake on Linux
- [x] AirDC++ end-to-end smoketest passes on both platforms
      (login, `+myip`, `+help`, `+uptime`, `+hubinfo`, plain PM deflection)
- [x] No script errors during steady-state run (timer listeners, etc.)
- [x] `+hubinfo` shows real OS/CPU/RAM on Windows 11 24H2+ (no wmic fallout)
- [x] Plain PM-to-bot deflection still applies (regression check from PR #13)
- [x] No new compiler errors; warnings count not regressed
- [x] One existing GitHub issue closed during this phase (#16, wmic)
- [x] No new GitHub issues opened (smoketest discoveries fixed in-branch)
- [x] CLAUDE.md §2 bundled-deps table updated to reflect Lua 5.4.7 + slnunicode shim

Phase 3 is closed. Phase 4 (dependency updates) may begin.
