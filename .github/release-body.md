# Luadch v3.1.3

Security patch on top of v3.1.2. Drop-in upgrade: no cfg / on-disk-format changes, no Lua API changes. Smoke harness now 12 / 12 PASS on Linux + Windows.

## Highlights

- **Pre-auth DoS gone** (closes [#91](https://github.com/luadch-ng/luadch/issues/91)). In `reg_only` mode, an unauthenticated BINF claiming a registered user's nick used to kill that user before HPAS proved the new connection held the password. Attacker only needed the target nick. Now: defer the takeover, run HPAS, and only swap if the new connection's password verifies. Race-guarded and safe against pre-HPAS disconnects.
- **`user.tbl` encryption-bypass closed** (closes [#92](https://github.com/luadch-ng/luadch/issues/92)). `+setpass`, `+nickchange` and `+upgrade` were writing the user database directly via `util.savearray`, silently undoing the Phase 7f AES-256-GCM at-rest encryption. All nine call sites now route through `cfg.saveusers()` so the encryption layer holds.
- **Audit-trail leak fixed** (closes [#96](https://github.com/luadch-ng/luadch/issues/96)). `etc_cmdlog` no longer writes `+setpass` / `+newpw` arguments verbatim to `log/cmd.log`. New `etc_cmdlog_redact_args` cfg key (default `{ setpass, newpw }`) replaces them with `<redacted>`.
- Two more low-impact tightenings: HPAS state-pollution on failed auth ([#94](https://github.com/luadch-ng/luadch/issues/94)) and POSIX shell-quoting for the `master_key_path` perms check ([#93](https://github.com/luadch-ng/luadch/issues/93)).

## What this unblocks

- Operators running `reg_only` hubs are no longer one-packet away from a pre-auth DoS against any registered user.
- Phase 7f at-rest encryption is now end-to-end correct: every code path that mutates `user.tbl` goes through the encryption layer.

## Downloads

| File | Platform |
|---|---|
| `luadch-v3.1.3-linux-x86_64.tar.gz` | Linux glibc x86_64 |
| `luadch-v3.1.3-windows-x86_64.zip`  | Windows x86_64 (MinGW UCRT64) |

Extract anywhere and run `./luadch` (Linux) or `Luadch.exe` (Windows). The trees are self-contained: Lua interpreter, all bundled libs (LuaSec, LuaSocket, basexx, adclib), default configs, scripts, certs helpers.

Default plain ADC port `5000`, TLS port `5001` after running `certs/make_cert.{sh,bat}` once. First login: nick `dummy`, password `test` - **delete that account immediately** after registering yourself, see [`docs/CONFIGURATION.md`](https://github.com/luadch-ng/luadch/blob/v3.1.3/docs/CONFIGURATION.md).

## Migration from v3.1.2

None required. Drop the new install tree in place of the old one (or `git pull && cmake --build build && cmake --install build` from source). `cfg/`, `certs/`, `master.key`, encrypted `user.tbl` carry over without change.

The new `etc_cmdlog_redact_args` cfg key gets a sensible default (`{ setpass, newpw }`) on fresh installs; existing `cfg/cfg.tbl` files without the key fall back to the same default automatically (cfg defaults are merged, not required).

If you're still on v3.1.1 or earlier, follow the v3.1.1 / v3.1.2 migration notes:
<https://github.com/luadch-ng/luadch/releases>

## Deferred to Phase-8

Two findings from the same audit are intentionally not in this patch:
- [#95](https://github.com/luadch-ng/luadch/issues/95) - password disclosure in admin reply paths (broader UX call)
- [#97](https://github.com/luadch-ng/luadch/issues/97) - `kill_wrong_ips` default flip (will bundle with the unified blocklist track in [#78](https://github.com/luadch-ng/luadch/issues/78))

## Full changelog

See [`CHANGELOG.md`](https://github.com/luadch-ng/luadch/blob/v3.1.3/CHANGELOG.md) for the categorised list.

## Build from source

```sh
git clone --branch v3.1.3 https://github.com/luadch-ng/luadch.git
cd luadch
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
cmake --install build
```

Output lands in `build/install/luadch/` ready to run. Windows needs `-G "MinGW Makefiles" -DOPENSSL_ROOT_DIR=...` extra, see [`docs/BUILDING.md`](https://github.com/luadch-ng/luadch/blob/v3.1.3/docs/BUILDING.md).

## Credits

All conceptual credit to **blastbeat** and **pulsar**, original authors of luadch. This fork modernises and extends their excellent foundation.
