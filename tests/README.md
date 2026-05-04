# luadch tests

Smoke tests that prove a freshly-built hub starts, binds its ports,
speaks ADC over plain and TLS, and loads all bundled plugins without
errors.

The suite is part of the **Phase 6** modernisation work
(see [`docs/phases/`](../docs/phases/) and CLAUDE.md §5). It exists to
catch regressions when we refactor `core/cfg.lua`, `core/hub.lua`, and
the path-anchoring logic later in Phase 6.

## Layout

```
tests/
  smoke/
    run.py        Python harness: stages a temp install, generates a
                  test cert, starts the hub on test ports, runs the
                  protocol checks, tears down.
  README.md       (this file)
```

## What is tested

- **Hub binds plain + TLS ports.** The hub successfully starts and
  accepts TCP connections on both the plain and TLS test ports within
  the start timeout. Implicit coverage: `core/init.lua` runs to
  completion, the listener setup in `core/hub.lua` works, all 66
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

## Limitations

- **No full login flow yet.** The handshake tests stop at the SUP/SID/
  INF exchange. Full BINF + GPA + BPAS auth as the `dummy` user is
  planned but adds non-trivial protocol code; it will land in a
  follow-up PR alongside `+cmd`-routing tests once login is in.
- **No internal unit tests.** `core/adc.lua` could be exercised
  directly with parser fixtures, but the `use "X"` sandbox in
  `core/init.lua` makes loading core modules standalone clunky. We
  test the parser via the running hub instead, which is more accurate
  but slower per assertion.
- **CI integration is a separate step.** The harness runs locally
  here; wiring it into `.github/workflows/` is the next Phase-6a
  ticket.

## Adding a test

1. Pick a name. If it speaks the wire, add it to the `TESTS` list in
   `run.py`. If it parses the hub log, fold it into
   `test_no_script_errors` or add a sibling `test_<topic>(log_path)`.
2. Use `socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), ...)`
   for plain ADC, or wrap with the existing `ctx` block for TLS.
3. Raise `TestFailure(reason)` on assertion failure - the runner
   catches it and reports per-test pass / fail.
4. Run locally before pushing.
