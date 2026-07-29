# Luadch v3.1.15

**Security patch** on the `release/3.1.x` line. One fix: a **remote, unauthenticated hub-crash on all platforms** - a single malformed ADC frame from an unauthenticated peer takes the whole hub down. No breaking changes; no cfg / lang-file changes; drop-in upgrade from v3.1.14. **All operators should upgrade.**

## ⚠️ Before upgrading

Back up your `cfg/`, `scripts/lang/`, `scripts/data/`, `scripts/cfg/`, `certs/`, and `secrets/` directories before any upgrade, on principle. **This release has no required cfg or lang-file changes** - the upgrade is a pure binary / script tree swap, but the backup discipline is worth keeping.

```sh
tar -czf "luadch-backup-$(date +%F).tar.gz" cfg scripts certs secrets
```

## Why upgrade

**Every operator should upgrade.** Before this fix, a single malformed ADC frame sent by an unauthenticated peer - no login, no registration - crashed the entire hub, dropping every connected user with no reconnect until a manual restart. It is trivially remote-triggerable and reproducible against any hub on any platform (Linux, Windows, ARM), independent of configuration.

## Bugfixes

### remote, unauthenticated hub-crash on a malformed ADC header ([#526](https://github.com/luadch-ng/luadch/pull/526))

In `core/adc.lua`'s `parse()`, a 2-field-header message class (F / D / E, `header.len == 2`) carrying the fourcc plus only **one** header field passed the length gate:

```lua
if eol < len then   -- accepts eol == len, i.e. fourcc + one field short
```

and reached the header-validation loop, which read the missing `buffer[3]` as `nil` and passed it to `_regex.sid` / `_regex.feature`:

```lua
sid     = function( str ) return string_match( str, _sid ) end   -- string_match(nil,...) -> throws
feature = function( str ) for i = 1, #str, 5 do ... end          -- #nil -> throws
```

The throw is **uncaught** all the way up the receive path (`server.tick` -> `readbuffer` -> `dispatch` -> `incoming` -> `adc.parse`, no `pcall`), so a single frame such as `FSCH AAAA` sent **before login** terminates the hub process.

The positional-parameter loop already carried a `param == nil` guard (Phase 8a F-PRS-7); the identical header-loop path was left unguarded - the asymmetry that made it reachable.

**Fix:** require the fourcc plus `len` header params (`eol >= len + 1`) and add the same `param == nil` guard to the header loop. No valid frame is affected (the minimum valid frame already has `eol == len + 1`).

**Live-validated:** a fresh `ghcr.io/luadch-ng/luadch:3.1.14` container **exits** on one pre-login `FSCH AAAA`; an image built from this fix **survives** `FSCH` / `DCTM` / `ECTM` / `DMSG AAAA` and still logs in. The 3.2.x line (`master`, PR [#525](https://github.com/luadch-ng/luadch/pull/525)) carries the identical fix plus a RED->GREEN unit regression on both smoke legs; 3.1.x has no unit-test harness, so the code here is identical and reviewer-verified, validated RED->GREEN against the 3.1.x `adc.lua` and live on the built image.

## Build / runtime

No toolchain changes. Same Lua 5.4.8, same LuaSec 1.3.2, same LuaSocket 3.1.0, same build toolchain as v3.1.14. The `linux-aarch64` artifact continues with the Bullseye-container pipeline (glibc 2.31 baseline, works on Pi OS Bullseye / Bookworm / DietPi v9.x).

## Upgrade

```sh
# Linux x86_64 / aarch64
wget https://github.com/luadch-ng/luadch/releases/download/v3.1.15/luadch-v3.1.15-linux-x86_64.tar.gz
tar xzf luadch-v3.1.15-linux-x86_64.tar.gz
# move your cfg/, scripts/data/, etc into the new tree, restart hub

# Windows
# Download luadch-v3.1.15-windows-x86_64.zip, extract, copy cfg+data over, restart.
```

3.2.x is the active development line on `master`; security backports continue to land on `release/3.1.x` per [`CLAUDE.md` §8](https://github.com/luadch-ng/luadch/blob/master/CLAUDE.md#8-release-lines-and-support-policy).
