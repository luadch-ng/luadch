# luadch tests

Two test layers: a protocol-level **smoke** harness that proves a
freshly-built hub starts, binds its ports, speaks ADC over plain and TLS,
and loads all bundled plugins without errors; and a pure-Lua **unit**
suite for modules that can be exercised standalone.

The smoke harness started as Phase 6 modernisation work and is now the
permanent regression floor: it runs on every push and PR, and both layers
run in CI on Linux AND Windows (`.github/workflows/smoke.yml`). Authoring
guidance (unit-harness contract, the regression-fail-pre-fix recipe, smoke
gotchas) lives in [`../docs/DEVELOPMENT.md`](../docs/DEVELOPMENT.md) §4.

## Layout

```
tests/
  smoke/
    run.py        Python harness: stages a temp install, generates a
                  test cert, starts the hub on test ports, runs the
                  protocol checks, tears down.
    tiger.py      Vendored pure-Python Tiger-192 hash. Used to compute
                  CIDs and password challenge responses for the login
                  flow tests. Self-tests on import.
  unit/
    *_test.lua    Pure-Lua unit tests (one per module/plugin) - stub the
                  `use` sandbox shim / plugin globals, load the target
                  standalone, assert its contract. Exit 0/1. Run
                  `ls tests/unit/*.lua` for the current set.
  README.md       (this file)
```

## What is tested

- **Hub binds plain + TLS ports.** The hub successfully starts and
  accepts TCP connections on both the plain and TLS test ports within
  the start timeout. Implicit coverage: `core/init.lua` runs to
  completion, the listener setup in `core/hub.lua` works, all
  bundled scripts load (a script error during start would either
  prevent listener registration or surface in the log).
- **Plain ADC handshake.** The harness opens a TCP socket to the
  plain port, sends `HSUP ADBASE ADTIGR`, and asserts that the hub
  responds with at least `ISUP`, `ISID`, and `IINF` frames. Covers
  the `core/adc.lua` parser/formatter on the protocol path users
  actually hit.
- **TLS ADC handshake.** Same as plain but wrapped in TLS against the
  hub's self-signed test cert. Covers the LuaSec / OpenSSL path
  end-to-end and protects against TLS regressions during refactor.
- **Plain ADC full login (dummy/test).** Performs a complete client
  login: SUP exchange, BINF with a freshly generated PID and the
  matching `CID = Tiger(PID)`, GPA salt receipt, HPAS response
  computed as `Tiger(password || salt)`. Asserts the hub transitions
  the client to NORMAL state by emitting our own BINF echo. Exercises
  `createuser`'s user object end-to-end (the user object factory in
  `core/hub_user_object.lua`), the BINF parser, salt generation, and
  password verification.
- **TLS ADC full login (dummy/test).** Same login flow over TLS.
- **`+cmd` routing (post-login `+help`).** After a successful login,
  sends `BMSG <sid> +help` and expects an EMSG/DMSG response from the
  hubbot. Exercises the onBroadcast listener chain,
  `etc_hubcommands` parser, and a real bundled command's reply path.
- **No script errors in log.** Scans the captured hub stdout for
  `script error:` lines (the prefix `core/scripts.lua` emits when a
  plugin fails to load or a listener throws). Catches plugin-level
  Lua-5.4 migration bugs and listener-registration mistakes.

## Running locally

You need a built+installed hub (the directory `cmake --install build`
produces) and Python 3.10+.

```sh
# from repo root, after a successful build+install:
python3 tests/smoke/run.py build/install/luadch
```

Exit code: `0` all pass, `1` test failures, `2` harness error (could
not start hub, etc.).

The harness copies the install tree to a temporary directory before
mutating it (cfg port overrides, generated cert). Pass
`--keep-staging` to leave the staging dir on disk for inspection
afterwards:

```sh
python3 tests/smoke/run.py build/install/luadch --keep-staging
```

The hub log of the run lives at `<staging>/luadch/log/smoke-hub.log`.

## Test ports

The harness rewrites `cfg.tbl` to use `15500` (plain), `15501` (TLS),
`15502` (plain IPv6), `15503` (TLS IPv6). Deliberately offset from the
upstream defaults (5000-5003) so a developer running the suite locally
does not collide with their real hub. CI is isolated so the offset
does not matter there.

## Unit tests (`tests/unit/`)

Pure-Lua modules (and plugins) with no socket dependency are exercised
standalone by stubbing the `use "X"` sandbox shim, `loadfile`-ing the
module from the repo root, and counting assertions with a tiny
`eq`/`truthy` harness. Each `tests/unit/<name>_test.lua` runs on its own:

```sh
# any Lua 5.4 interpreter, from repo root:
lua tests/unit/iostream_test.lua      # exit 0 = all pass, 1 = a failure
```

**These run in CI on BOTH platforms.** `.github/workflows/smoke.yml` runs
the whole `tests/unit/*_test.lua` set on the Linux leg (`lua5.4`) and the
Windows leg (msys2 `lua5.4`, the versioned `lua54` package - the unversioned
`lua` rolled to Lua 5.5 and broke the suite, #388) before the build+smoke
step. When you add a unit test you MUST add a step for it to both legs, or
it is silent non-coverage. (The exceptions are the C-module tests -
`adclib_unescape_test.lua` and `zlib_stream_test.lua` - which need the built
C module and so run on the Linux leg only, after install, with
`LD_LIBRARY_PATH=.`.)

The unit-test authoring contract + the regression-fail-pre-fix recipe are
in [`../docs/DEVELOPMENT.md`](../docs/DEVELOPMENT.md) §4.

## Limitations

- **Sandboxed core modules.** `core/adc.lua` and similar could be
  exercised with fixtures, but the `use "X"` sandbox in
  `core/init.lua` makes loading most core modules standalone clunky
  (the `iostream` shim works because that module is pure byte logic
  with no hub deps). We test the parser via the running hub instead,
  which is more accurate but slower per assertion.
- **Tiger hash is vendored.** ADC's CID and password-challenge use
  Tiger-192, which has been removed from `hashlib`, `pycryptodome`
  and other modern Python crypto libraries. `tiger.py` is a
  pure-Python port of `adclib/tiger.cpp` (S-box constants taken
  verbatim from the C source); it self-tests against the standard
  Tiger-192 test vectors on import.

## Adding a test

1. Pick a name. If it speaks the wire, add it to the `TESTS` list in
   `run.py`. If it parses the hub log, fold it into
   `test_no_script_errors` or add a sibling `test_<topic>(log_path)`.
2. Use `socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), ...)`
   for plain ADC, or wrap with the existing `ctx` block for TLS.
3. Raise `TestFailure(reason)` on assertion failure - the runner
   catches it and reports per-test pass / fail.
4. Run locally before pushing.
