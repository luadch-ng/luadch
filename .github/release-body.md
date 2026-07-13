# Luadch v3.1.14

**Maintenance patch** on the `release/3.1.x` line. One fix: a **Windows-only** hub-crash once the hub holds ~64 concurrent sockets. No breaking changes; no cfg / lang-file changes; drop-in upgrade from v3.1.13. **Linux operators are unaffected** (no functional change).

## ⚠️ Before upgrading

Back up your `cfg/`, `scripts/lang/`, `scripts/data/`, `scripts/cfg/`, `certs/`, and `secrets/` directories before any upgrade, on principle. **This release has no required cfg or lang-file changes** - the upgrade is a pure binary / script tree swap, but the backup discipline is worth keeping.

```sh
tar -czf "luadch-backup-$(date +%F).tar.gz" cfg scripts certs secrets
```

## Why upgrade

**Windows operators should upgrade**, especially busier hubs. Before this fix, a Windows hub crashed with `bad argument #1 to 'socket_select' (too many sockets)` and dropped every user once it held about **64 concurrent sockets** - a ceiling a moderately busy hub reaches organically (it can also be pushed there by a distributed connect flood; a single IP stays capped by `ratelimit_perip_max_conns`). Reported on Windows Server 2008 R2 running 3.1.13, but it affects any Windows version.

**Linux is unaffected** - its glibc select ceiling is already 1024, so this release makes no functional change on Linux beyond one informational boot-log line.

## Bugfixes

### [#416](https://github.com/luadch-ng/luadch/issues/416) (Sopor) - Windows hub-crash at ~64 concurrent sockets

The symptom in the log, immediately followed by the hub dropping every user:

```
/core/server.lua:...: bad argument #1 to 'socket_select' (too many sockets)
```

The hub event loop (`core/server.lua`'s `tick()`) calls `socket.select` over **every** connected socket at once. On Windows, luasocket's `select.c` hard-caps that at `FD_SETSIZE`:

```c
#ifdef _WIN32
    if (n >= FD_SETSIZE)
        luaL_argerror(L, tab, "too many sockets");
```

The bundled Windows build never defined `FD_SETSIZE`, so it inherited the Winsock default of **64** (`luasocket/CMakeLists.txt` set only `WINVER`). Once the hub held ~64 sockets (logged-in users + v4/v6 listeners + HBRI + HTTP), the unguarded `select` raised and the main loop died.

**Fix:** define `FD_SETSIZE=1024` for the Windows luasocket build (`socket` module + `luasocket_static`) - parity with the Linux glibc `fd_set`. On Windows `fd_set` is a `SOCKET` array sized by this macro, so raising it genuinely enlarges the set. This is **Windows-only**: on Linux, glibc's `fd_set` is a fixed 1024-bit buffer that redefining `FD_SETSIZE` would overflow.

Watching **more than ~1024** concurrent sockets needs replacing `select()` with `poll()` on both platforms, tracked in [#310](https://github.com/luadch-ng/luadch/issues/310) on the 3.2.x line. `max_users` (default 3000) counts logged-in users, not sockets, and is not reached on either platform before this ~1024 socket ceiling.

The hub now logs its compile-time select capacity (`socket._SETSIZE`) once at boot (`hub.loop`, to `event.log`) so you can confirm the raised cap. The identical fix is on the 3.2.x line (`master`, PR [#417](https://github.com/luadch-ng/luadch/pull/417)) with a smoke regression that provably fails pre-fix on the Windows CI leg.

## Build / runtime

No toolchain changes. Same Lua 5.4.8, same LuaSec 1.3.2, same LuaSocket 3.1.0, same build toolchain as v3.1.13. The Windows build simply compiles luasocket with `-DFD_SETSIZE=1024`.

The `linux-aarch64` artifact continues with the Bullseye-container pipeline (glibc 2.31 baseline, works on Pi OS Bullseye / Bookworm / DietPi v9.x).

## Upgrade

```sh
# Windows (the platform this fix targets)
# Download luadch-v3.1.14-windows-x86_64.zip, extract, copy cfg+data over, restart.

# Linux x86_64 / aarch64 (no functional change; upgrade at leisure)
wget https://github.com/luadch-ng/luadch/releases/download/v3.1.14/luadch-v3.1.14-linux-x86_64.tar.gz
tar xzf luadch-v3.1.14-linux-x86_64.tar.gz
# move your cfg/, scripts/data/, etc into the new tree, restart hub
```

3.2.x is the active development line on `master`; security backports continue to land on `release/3.1.x` per [`CLAUDE.md` §8](https://github.com/luadch-ng/luadch/blob/master/CLAUDE.md#8-release-lines-and-support-policy).
