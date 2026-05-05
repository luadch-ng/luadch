# CLAUDE.md

Context for Claude Code (and any AI assistant) working on luadch. Read this before
making changes — it captures the working agreement, architecture, and modernization plan
that span sessions.

User communication is in **German**; all written artifacts (this file, code, comments,
commits, PRs, issues) stay in **English** so other contributors can read them.

---

## 1. Working agreement (non-negotiable)

These rules are set by the maintainer and apply to every change.

1. **Security and consistency come first.** Treat any change touching network I/O,
   authentication, ADC protocol parsing, or configuration as security-sensitive. When
   fixing a pattern in one place, grep for the same pattern across the repo and fix it
   everywhere — divergent code paths are a defect.
2. **No spaghetti code.** Prefer small, focused functions and modules. Don't grow
   `core/cfg.lua` or `core/hub.lua` further; if new logic doesn't have an obvious home,
   propose a new module before writing the code.
3. **One phase at a time.** Work proceeds strictly phase by phase (see §5 Roadmap). Do
   not pull tickets forward from a later phase, even if they look trivial.
4. **Review gate between phases.** After every phase, run an explicit review covering:
   - **Security** — input validation, auth boundaries, network surface, file I/O.
   - **Consistency** — did similar code paths drift apart? Did naming get inconsistent?
   - **Code quality** — readability, dead code, duplication, function length.
   - **Build & smoke test** — both Linux and Windows builds succeed, hub starts, a
     test client (`adc://127.0.0.1:5000`) can connect.
5. **Fix-then-advance.** Anything found in the review must be fixed before the next
   phase begins. No "we'll get back to it." If something is genuinely out of scope,
   open a tracking issue and link it from the phase summary.
6. **Small reviewable PRs.** One logical change per PR. Reference the GitHub issue it
   closes. Never bundle modernization work with unrelated fixes.

When uncertain whether a change fits the current phase, **stop and ask the maintainer**.

---

## 2. Project overview

luadch is a DC++ **ADC** hub server written in Lua with a thin C launcher
(`hub/hub.c`, 209 lines) that embeds the Lua interpreter and hands off to
`core/init.lua`.

- **Current source version:** `v2.24 [RC4]` (see `core/const.lua`)
- **Latest release:** `v2.23` (2022-04-02) — the source is ahead of the last release
- **Open issues:** 47 (as of 2026-05-02)
- **License:** GPLv3.0

The repo bundles all runtime dependencies as source — there is no external package
manager. This is intentional (the project ships as a self-contained build) but means
dependency updates are manual.

### Bundled dependencies (verified 2026-05-03)

| Component   | Bundled version | Path           | Notes                                |
|-------------|-----------------|----------------|--------------------------------------|
| Lua         | **5.4.7**       | `lua/`         | bumped from 5.1.5 in Phase 3         |
| LuaSec      | **1.3.2**       | `luasec/`      | TLS support, links against OpenSSL — Phase 4 bump candidate |
| LuaSocket   | **3.1.0**       | `luasocket/`   | TCP/UDP, IPv6 capable — Phase 4 bump candidate |
| basexx      | (no version)    | `basexx/`      | Pure Lua, base32/64 encoding         |
| unicode     | shim            | `slnunicode/unicode.lua` | ~40-line Lua shim that replaces the unmaintained slnunicode C module; uses `string.X` and Lua 5.4 builtin `utf8` |
| adclib      | (no version)    | `adclib/`      | C module: ADC hashing & escaping     |

---

## 3. Architecture

### Boot sequence

```
hub/hub.c           ── lua_open(), register C functions, load core/init.lua
  └─ core/init.lua  ── sandboxed env, load libs + core modules in order
       └─ core/hub.lua      ── hub.loop() — main event loop
            └─ core/server.lua ── select() loop over sockets, SSL wrap
```

### Core modules (line counts)

| Module               | LOC  | Responsibility                                       |
|----------------------|------|------------------------------------------------------|
| `core/const.lua`     |   21 | Program name, version, config paths                  |
| `core/hci.lua`       |    9 | Stub (purpose unclear — flag for review)             |
| `core/test.lua`      |   14 | Stubbed; **no active test suite**                    |
| `core/mem.lua`       |   32 | GC trigger                                           |
| `core/signal.lua`    |   41 | Timers / start time                                  |
| `core/out.lua`       |   99 | Logging, error output, listener registry             |
| `core/types.lua`     |  159 | ADC protocol type validation                         |
| `core/init.lua`      |  209 | Bootstrap: env, module load order, restart loop      |
| `core/scripts.lua`   |  263 | Plugin loader, sandbox, hook registry                |
| `core/doc.lua`       |  308 | Auto-doc generation (currently disabled)             |
| `core/util.lua`      |  686 | File I/O, encoding, UTF-8, table helpers             |
| `core/adc.lua`       |  926 | ADC protocol: parse, escape, format                  |
| `core/server.lua`    |  989 | Network: select loop, SSL, coroutines                |
| `core/hub.lua`       | 2239 | **Hot path** — login, messaging, commands, listeners |
| `core/cfg.lua`       | 3688 | **Largest** — config + user.tbl + language           |
| `hub/hub.c`          |  209 | C launcher, signal handling                          |

### Plugin / hook model

Plugin scripts live in `scripts/` and are loaded via `core/scripts.lua` into a
sandboxed environment. They register listeners on lifecycle events:

- `onStart` — script init
- `onLogin` — user finished login
- `onFailedAuth` — auth failure
- `onBroadcast` — main-chat message
- `onReg` / `onDelreg` — registration changes
- `onError` — script error
- `onExit` — hub shutdown

Plugins use the `hub` table API: `hub.getuser(nick)`, `hub.broadcast(msg)`,
`hub.setlistener(event, id, func)`, plus `cfg.get(key)`, `utf.sub()`, etc.

---

## 4. Build & run

luadch uses CMake (≥ 3.20). Same three-step pipeline on every platform:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release [-DOPENSSL_ROOT_DIR=...]
cmake --build build -j
cmake --install build
```

Output lands in `build/install/luadch/`. Run `./luadch` (Linux) or
`Luadch.exe` (Windows) from there.

Linux defaults work without options. Windows needs `-G "MinGW Makefiles"`
and an OpenSSL location, e.g. `-DOPENSSL_ROOT_DIR=C:/OpenSSL`. ARM
(native or cross-compile) is supported and verified up to aarch64.

**Full prerequisites, OpenSSL cross-compile recipe, ARM cross-toolchain
setup, first-time login walkthrough:** see [`docs/BUILDING.md`](docs/BUILDING.md).

### First-time login

```
Nick:     dummy
Password: test
Address:  adc://127.0.0.1:5000      (plain)
          adcs://127.0.0.1:5001     (TLS, after running certs/make_cert.{sh,bat})
```

After login: `+reg <yournick> 100`, then `+delreg dummy`, then `+reload`.

---

## 5. Modernization roadmap

Each phase ends with the §1.4 review gate. We do not start Phase N+1 until Phase N
is reviewed and clean.

### Phase 1 — Foundation (current)

**Goal:** Reproducible builds on Linux and Windows, smoke test passes, baseline
documented.

- [ ] Verify Linux build from clean checkout
- [ ] Verify Windows MinGW build from clean checkout (note: hardcoded paths)
- [ ] Smoke-test: hub starts, dummy login works on plain + TLS
- [ ] Document any deviations from this CLAUDE.md
- [ ] Capture exact toolchain versions used

**Out of scope for Phase 1:** changing any `.lua` or `.c` file. This phase is
"observe and document," not "modify."

**Review gate:** Both builds produce a working hub. Build instructions in this file
match reality. No code changed yet.

### Phase 2 — Quick wins (no breaking changes)

**Goal:** Pick off small, low-risk issues that improve consistency without changing
behavior. Includes a minimal Windows-build hardening (ENV-var paths) so the existing
toolchain is reproducible. **Full Windows-build modernization (CMake) is its own
phase — see Phase 5 below.**

Candidates (planned at start of phase; actual progress tracked via merged PRs):
- Repo line-ending policy (`.gitattributes`)
- Replace deprecated `lua_open()` with `luaL_newstate()` in `hub/hub.c`
- C++17 `register`-keyword warnings in `adclib/tiger.cpp`
- `make_cert.sh` `UID`-variable collision with bash builtin
- Route `+!#` server commands from PM-to-hubbot through the command pipeline
- Audit hardcoded `"././"` relative paths in `core/init.lua` (audit only;
  full fix deferred to Phase 6)
- **Make Windows build reproducible:** replace hardcoded `C:\MinGW` and
  `C:\OpenSSL` paths in `compile_with_mingw.bat` with ENV variables, sanity
  check toolchain, document prereqs in `docs/BUILDING.md`

**Review gate:** Build still green on both platforms. Smoke test passes. No new
warnings. Each change has a PR + closed issue.

### Phase 3 — Lua 5.1 → 5.4 migration

**Goal:** Move embedded interpreter from Lua 5.1.5 (EOL 2012) to Lua 5.4.

This is the biggest single change in the modernization. Scope it carefully:
- Replace `setfenv` / `getfenv` (used in `core/init.lua`, `core/scripts.lua`) with
  `_ENV` and explicit closures
- `loadstring` → `load`
- `unpack` → `table.unpack`
- `module(...)` if used anywhere
- C API changes in `hub/hub.c` and the C modules (`adclib`, `slnunicode`)
- Compatibility re-check of all bundled libs against Lua 5.4

**Review gate:** All 70+ scripts in `scripts/` load and run. ADC protocol smoke tests
pass. Plugin sandbox still isolates globals. Performance not visibly worse.

### Phase 4 — Dependency audit (closed as audit-only)

**Outcome (2026-05-03):** every bundled dep is already on its latest
meaningful upstream tag. Issue #3 (OpenSSL 3.0 deprecation warnings in
LuaSec 1.3.2) reclassified as `upstream-blocked` + `wontfix` — fix
requires upstream LuaSec to migrate to the EVP / provider API, which
has not happened. Switching to a different TLS-binding library
(`lua-openssl`, etc.) is a network-stack-renewal scope, deliberately
not pursued.

Full reasoning in [`docs/phases/PHASE_4.md`](docs/phases/PHASE_4.md).

### Phase 5 — Cross-platform build system (CMake migration, closed)

**Outcome (2026-05-03):** Single CMake pipeline replaces the ad-hoc
`compile` shell script and `compile_with_mingw.bat` (whose `*.c.not`
rename hack is gone for good). Same three-step `cmake -B build` →
`--build` → `--install` works on Linux, Windows, and ARM aarch64
(cross-compile verified). Output sizes match the legacy build within
±10 %; the legacy scripts are deleted.

Full details in [`docs/phases/PHASE_5.md`](docs/phases/PHASE_5.md).

### Interlude - Upstream issue triage (closed)

**Outcome (2026-05-03):** One-off detour between Phase 5 and Phase 6.
Six small bugs from the upstream `luadch/luadch` tracker fixed in
single-PR patches; three further upstream bugs audited and confirmed
already fixed by the 5.4 / OpenSSL-3.x modernisation. Not part of
the modernisation roadmap (no review gate of its own); recorded so
future triage rounds do not re-discover the same audit results.

Full details in [`docs/phases/INTERLUDE_UPSTREAM_TRIAGE.md`](docs/phases/INTERLUDE_UPSTREAM_TRIAGE.md).

### Phase 6 - Refactor & tests (closed)

**Outcome (2026-05-04):** Modernisation refactor complete. `core/cfg.lua`
3688 -> 668, `core/hub.lua` 2245 -> 1497, all code modules under the
1500-line ceiling. Smoke harness with seven protocol-level tests
(plain + TLS handshake / login / +cmd routing / no-script-errors)
runs on every push and PR via `.github/workflows/smoke.yml`. Path
anchoring closes issue #12. Tiger hash vendored as
`tests/smoke/tiger.py` so the test client and hub agree by
construction. Surviving 100-line functions are documented exceptions
(factories, sequence-of-stamps) or pre-existing untouched code
tracked as Phase 8+ in #48.

Full details in [`docs/phases/PHASE_6.md`](docs/phases/PHASE_6.md).

### Phase 7 - Security audit & hardening (closed)

**Outcome (2026-05-04):** Systematic security audit (7a) produced 24
findings across 8 surfaces; sub-phases 7b-7h closed 22 of them. Two
remain by design: F-AUTH-1 transparent KDF migration is
protocol-immanent (mitigated via at-rest AES-256-GCM + chmod 600 +
configurable master-key path); F-DEP-2 LuaSec OpenSSL-3 deprecated
APIs stays `upstream-blocked` per Phase 4. Six concrete hardening
deliverables landed:

- DoS hardening: per-IP / per-user rate limits, TLS handshake
  deadline, per-IP failed-auth lockout in new `core/ratelimit.lua`
- AES-256-GCM at-rest encryption of `cfg/user.tbl` in new
  `core/cfg_secret.lua`, with chmod-or-die and configurable
  `master_key_path` for backup separation
- Sandbox `loadfile()` for all `.tbl` files (eliminates RCE on
  tampered config / user / language / plugin-state files)
- ADC parser hardening: control-byte rejection, reentrant `parse()`,
  64 KiB command-size cap, re-enabled UTF-8 entry check
- CSPRNG-driven password salt + SID via OpenSSL `RAND_bytes`
- New top-level `docs/SECURITY.md` documenting threat model, plugin
  trust contract, F-AUTH-1 disclosure, file-permission baseline,
  CVE-tracking process, and reporting channel

Smoke harness now runs 10 protocol-level tests (up from 7) covering
the new security mechanisms.

Full details in [`docs/phases/PHASE_7.md`](docs/phases/PHASE_7.md).

After Phase 7 the **modernisation programme is content-complete** -
the project is on a current Lua runtime, current bundled deps
(within upstream constraints), a unified modern build system,
structural code health, a smoke-test floor catching protocol-level
regressions, and defence-in-depth security around the
ADC-protocol-mandated cleartext.

### Phase 8+ - Future features (post-modernisation)

Reserved for new capability work that depends on the modernised + audited
foundation. Not modernisation work - these are deliberate feature additions,
scoped and prioritised when we get there. Examples held in the maintainer's
notes:

- External read-only API (HTTP/JSON status, user list, share stats)
- Web-based registration / admin panel
- IPv6 listening (issue #105 upstream - not adopted yet)
- NAT-traversal helpers

Each Phase-8+ item gets its own discrete phase or issue with its own scope
and review gate. The strict "one phase at a time" discipline still applies.

---

## 6. External state & memory

- **Phase journals** — [`docs/phases/`](docs/phases/) holds one Markdown file per
  modernization phase: activities, findings, build-output specs, and the review-gate
  checklist. Entry point for "what happened in phase N" is `docs/phases/PHASE_N.md`.
  These are the narrative — issues and code are the actionable state.
- **GitHub issues** — https://github.com/luadch-ng/luadch/issues — the actionable backlog.
  Each finding from a phase journal that needs work is an issue here, labeled with the
  target phase (`phase-2`, `phase-3`, …). Use `gh issue list --label phase-2` to scope
  upcoming work. Upstream `luadch/luadch` issues are referenced selectively when we
  adopt one (no bulk import — see §6 *Upstream policy* below).
- **Auto-memory** — Claude's per-user auto-memory directory for this project — holds
  user profile and high-level context. Architecture / build / roadmap details live in
  **this file**, not in memory, because they belong with the code.
- **Releases** — last public release is v2.23 (2022-04-02). Source is at v2.24 RC4.

### Upstream policy

The repo at `luadch-ng/luadch` is a fork of `luadch/luadch`. The upstream is
not actively released (last release 2022-04-02) but still receives occasional commits.
We do **not** plan to push modernization work back upstream and do **not** bulk-import
upstream's open issues. When a phase touches an area covered by an upstream issue, we
open a fresh issue here that references the upstream one in its body.

---

## 7. Conventions for changes

- **Commit style:** match `git log` — concise, imperative, optional `fix #NNN` trailer.
- **PR scope:** one issue per PR, except for tightly coupled changes.
- **Lua style:** match the file you're editing. Don't reformat unrelated lines.
- **Comments:** explain *why*, not *what*. Don't add a comment that just restates code.
- **No drive-by refactors.** If you spot something during an unrelated change, open
  an issue instead of fixing it inline.
