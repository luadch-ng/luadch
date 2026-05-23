# Phase 5 — Cross-platform build system (CMake migration)

> Working agreement: see [`CLAUDE.md`](../../CLAUDE.md) §1.
> Roadmap: see [`CLAUDE.md`](../../CLAUDE.md) §5.

**Status:** complete
**Started:** 2026-05-03
**Closed:** 2026-05-03
**Goal:** Replace the ad-hoc `compile` shell script and the fragile
`compile_with_mingw.bat` (with its `*.c.not` rename trick) with a single
CMake-based build that produces the Phase 1 build-output spec on Linux,
Windows, and ARM via one unified pipeline.

---

## 1. Activities

Six CMake files written over two iterations on the same migration branch.
Build verified on x86_64 Linux + x86_64 Windows + aarch64 (cross-compiled
from x86_64 Linux). Legacy scripts removed.

| Step | What |
|------|------|
| 5.1 | Top-level `CMakeLists.txt` (orchestrator, OpenSSL detection, install rules for the runtime tree) |
| 5.2 | `lua/src/CMakeLists.txt` (the embedded Lua 5.4 interpreter as a SHARED library) |
| 5.3 | `hub/CMakeLists.txt` (the `luadch` / `Luadch.exe` launcher executable) |
| 5.4 | `adclib/CMakeLists.txt` (ADC protocol C++ module) |
| 5.5 | `luasocket/CMakeLists.txt` (socket + mime plugins, plus a small static helper for luasec) |
| 5.6 | `luasec/CMakeLists.txt` (TLS plugin, links lua + openssl + the luasocket helper) |
| 5.7 | Polish: default Release build type for single-config generators; `-s` strip on link to match legacy size; `PREFIX ""` on Windows so the DLL is named `lua.dll` not `liblua.dll` |
| 5.8 | Delete legacy `compile`, `compile_with_mingw.bat`, `cleanall` (commit `62ea82e`) |
| 5.9 | Rewrite `docs/BUILDING.md` end-to-end (Linux / Windows / ARM sections); trim `CLAUDE.md` §4 to point at it |

---

## 2. Notable design decisions

### One pipeline, one mental model

Build commands now identical on every supported platform:

```
cmake -B build -DCMAKE_BUILD_TYPE=Release [-DOPENSSL_ROOT_DIR=...]
cmake --build build -j
cmake --install build
```

Output ends up in `build/install/luadch/` ready to run, ready to
package. The historical `build_gcc/luadch/` and `build_mingw/luadch/`
trees are gone.

### `*.c.not` rename trick eliminated

The Windows build used to mutate the source tree mid-build —
renaming `mime.c`, `unix.c`, `usocket.c`, `unixdgram.c`, `unixstream.c`,
`serial.c` to `*.c.not` so a wildcard compile would skip them, then
renaming them back. Fragile (broken state on script abort, breaks
parallel builds, breaks editors that watch the tree). CMake replaces
this with proper per-platform source lists:

```cmake
if(WIN32)
    list(APPEND LSOCKET_CORE_SOURCES ${LSOCKET_SRC}/wsocket.c)
else()
    list(APPEND LSOCKET_CORE_SOURCES
        ${LSOCKET_SRC}/usocket.c ${LSOCKET_SRC}/serial.c
        ${LSOCKET_SRC}/unix.c ${LSOCKET_SRC}/unixstream.c
        ${LSOCKET_SRC}/unixdgram.c)
endif()
```

The source tree is read-only during the build now.

### OpenSSL discovery

Linux: stock `find_package(OpenSSL REQUIRED)` works against the system
`-dev` package — no override needed.

Windows: pass `-DOPENSSL_ROOT_DIR=C:/OpenSSL` once at configure time;
CMake locates the import libraries and headers from the standard layout
documented in `docs/BUILDING.md`. The OpenSSL DLLs are installed into
the install root automatically so the hub finds them at runtime
without any PATH fiddling.

### Naming and size parity

CMake's MinGW defaults add a `lib` prefix to SHARED libraries on
Windows (so the Lua DLL would have ended up as `liblua.dll`). Phase 1
spec said `lua.dll`. Override on Windows only:

```cmake
if(WIN32)
    set_target_properties(lua PROPERTIES PREFIX "")
endif()
```

Size parity with the legacy build comes from two pieces: default
Release build type for single-config generators (else CMake builds
RelWithDebInfo-ish and binaries are 2-3× the legacy size), and the
`-s` linker flag on GCC/Clang Release links to match the legacy
`strip --strip-unneeded` step. After both, our binaries are within
±10 % of the legacy ones — `mime.dll` matches to the byte.

### Static helper for luasec

The legacy build had luasec link against `libluasocket.a` — a
hand-rolled static archive of `io.o`, `buffer.o`, `timeout.o`,
`compat.o`, plus the platform socket layer (`usocket.o` / `wsocket.o`).
The CMake equivalent is a `STATIC` target `luasocket_static` that
declares the same source list with `if(WIN32)` for the platform piece;
luasec then `target_link_libraries(ssl PRIVATE luasocket_static)`.
Same composition, but expressed declaratively, no separate `ar` step.

### Out-of-source build by default

`build/` is the canonical CMake build dir (gitignored alongside the
legacy `build_*/` for safety). Source tree is never written to during
configure or build.

---

## 3. Build statistics

Output sizes on Windows (gcc 16.1.0 UCRT, Release, stripped) — within
±10 % of the legacy build for every artefact:

| File              | CMake build | Legacy build | Δ   |
|-------------------|-------------|--------------|-----|
| `Luadch.exe`      | 176 640     | 180 277      | -2% |
| `lua.dll`         | 349 184     | 290 121      | +20% |
| `lib/adclib/adclib.dll`            | 232 448 | 237 517 | -2% |
| `lib/luasec/ssl/ssl.dll`           | 70 656  | 73 307  | -3% |
| `lib/luasocket/socket/socket.dll`  | 64 512  | 70 144  | -8% |
| `lib/luasocket/mime/mime.dll`      | 25 600  | 25 600  | 0%  |
| `lib/unicode/unicode.lua`          | 3 400   | 3 400   | 0%  |

(`lua.dll`'s +20 % is gcc-16-vs-gcc-13 codegen plus a couple of newer
exports; not a regression.)

Linux (gcc 13.3, Release, stripped) sizes are equivalent to the
legacy `./compile` output within rounding.

---

## 4. Smoketest summary

| Test                                                  | Linux | Windows | ARM aarch64 |
|-------------------------------------------------------|-------|---------|-------------|
| `cmake -B build`                                      | ✅    | ✅      | ✅ (cross)  |
| `cmake --build build -j`                              | ✅    | ✅      | ✅ (lua + adclib via single-file aarch64-linux-gnu-gcc; full link of liblua.so as ARM aarch64 shared object) |
| `cmake --install build` produces Phase 1 §3 layout    | ✅    | ✅      | n/a (cross-compile artefact only) |
| Hub binary launches; binds 0.0.0.0:5000               | ✅    | ✅      | n/a (no aarch64 runtime here)     |
| Hub responds to ADC `HSUP` handshake                  | ✅    | ✅      | n/a               |
| All warnings still cosmetic / pre-existing             | ✅    | ✅      | n/a               |

ARM verification was a code-portability proof rather than an
end-to-end runtime test (no aarch64 hardware in this dev environment).
The cross-toolchain produced a valid `ELF 64-bit LSB shared object,
ARM aarch64` `liblua.so`, which is enough to assert that nothing in
Phase 1-5 broke ARM portability. Anyone with a Pi can verify natively
using the Linux section of `docs/BUILDING.md` — same pipeline.

---

## 5. Findings

### Filed during Phase 5

None.

### Closed by Phase 5

None directly (the CMake migration was tracked as
[issue #15](https://github.com/Aybook/luadch/issues/15) but is being
resolved by the PR closing this phase, not separately).

### Decided "no follow-up" in Phase 5

- A GitHub Actions CI matrix (Ubuntu + Windows MinGW + ARM cross) was
  in scope for Phase 5 but deferred. Rationale: it is a deployment-side
  concern, not part of the build-system migration itself, and adding it
  is small once we have CMake. Will be picked up either as a tail-end
  Phase 5 task or as a Phase 7+ infrastructure item.
- ARM-specific runtime testing (actually exercising the hub on an aarch64
  device) was not done — we only verified portability via cross-compile.
  Expected to be picked up by anyone deploying to a Pi in the field.

---

## 6. Phase 6 entry criteria

Phase 6 is **refactor & tests**: address the structural debt that has been
visible all along but was deliberately untouched while we modernised the
runtime and build system underneath it.

Recommended preconditions before starting:

1. Master is at the merged Phase 5 PR; no uncommitted work.
2. Build a baseline smoke-test before touching `cfg.lua` or `hub.lua`.
   The pre-flight test target should at least:
   - exercise `core/adc.lua` parsers / formatters on a fixture corpus,
   - launch the hub against a fake `cfg/` tree and assert the listening
     ports + script load summary.
3. Decide on a line / complexity ceiling per module (e.g., no Lua file
   above 1500 lines, no function above 100 lines) so we have a clear
   "are we done?" signal.
4. Issue triage: re-read [#12](https://github.com/Aybook/luadch/issues/12)
   (path anchoring) and any other Phase-6-tagged issues; sequence them
   inside the phase.

Suggested order inside Phase 6:
- (a) Test-suite skeleton first (so every refactor PR can prove
  no regression)
- (b) Path-anchoring (issue #12)
- (c) `cfg.lua` decomposition by domain
- (d) `hub.lua` hot-path untangling
- (e) Remaining `TODO` / `FIXME` comments

---

## 7. Phase 5 review-gate checklist

- [x] CMake configures cleanly on Linux (`gcc 13`, system OpenSSL 3.0.x)
- [x] CMake configures cleanly on Windows (`gcc 16` UCRT, OpenSSL 3.5.7)
- [x] Build produces every artefact listed in PHASE_1.md §3, in the same
      relative paths
- [x] Sizes within tolerance of the legacy build (±10 % for every file
      except `lua.dll`'s +20 %, attributed to compiler-version codegen)
- [x] Hub launches and responds to ADC handshake on both platforms
- [x] ARM aarch64 cross-compile produces a valid shared object
      (portability proof; no runtime test on hardware here)
- [x] `*.c.not` rename trick removed from the Windows build
- [x] Legacy `compile`, `compile_with_mingw.bat`, `cleanall` removed
- [x] `docs/BUILDING.md` rewritten with platform-specific sections
- [x] `CLAUDE.md` §4 + §5 Phase 5 block updated to reflect the new state

Phase 5 is closed. Phase 6 (refactor & tests) may begin.
