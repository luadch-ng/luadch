# Luadch v3.1.13

**Security maintenance patch** on the `release/3.1.x` line. One fix: a remote, unauthenticated hub-crash. No breaking changes; no cfg / lang-file changes; drop-in upgrade from v3.1.12.

## ⚠️ Before upgrading

Back up your `cfg/`, `scripts/lang/`, `scripts/data/`, `scripts/cfg/`, `certs/`, and `secrets/` directories before any upgrade, on principle. **This release has no required cfg or lang-file changes** - the upgrade is a pure binary / script tree swap, but the backup discipline is worth keeping.

```sh
tar -czf "luadch-backup-$(date +%F).tar.gz" cfg scripts certs secrets
```

## Why upgrade

**Every operator should upgrade.** This is a remote, unauthenticated denial of service that takes the **whole hub** down - all users dropped, no reconnections possible until you manually restart the process. It is trivially triggerable (a single TCP connect followed by an immediate reset) and reproducible against any hub regardless of configuration.

## Bugfixes

### [#401](https://github.com/luadch-ng/luadch/issues/401) (Sopor) - remote hub-crash on a peer reset right after accept

The symptom in the error log, immediately followed by the hub dropping every user:

```
././core/ratelimit.lua:176: attempt to concatenate a nil value (local 'ip')
*** TLS error: Connection closed
```

`core/server.lua`'s accept path reads the connecting client's IP via `client:getpeername()` and hands it to the per-IP rate-limit guard. When a peer resets the TCP connection in the split second between `accept()` and `getpeername()` (connect + immediate RST - anyone can do it), `getpeername()` returns `nil`. That `nil` reached `ratelimit.accept_ip`, which builds its token-bucket key as `"ip:" .. ip` - raising `attempt to concatenate a nil value (local 'ip')`. The error was **uncaught inside the listener's accept loop**, so the hub stopped accepting connections and dropped everyone online.

`ratelimit.release_ip` already guarded a `nil` IP; `accept_ip` did not - the asymmetry that made this reachable.

**Fix (defence in depth):**

```lua
-- core/server.lua, accept path
 local clientip, clientport = client:getpeername( )
+if not clientip then
+    -- peer reset between accept() and getpeername(); socket is dead,
+    -- and we cannot rate-limit an unknown IP. Drop it before the guard.
+    client:close( )
+    return false
+end
```

```lua
-- core/ratelimit.lua, accept_ip
 if not _activate then return true end
+if not ip then return true end   -- mirror release_ip's nil guard
```

`core/server.lua` now closes a just-accepted socket whose peer address cannot be read *before* the rate-limit guard runs, and `accept_ip` guards `nil` directly.

The 3.2.x line (`master`) additionally guards `core/blocklist.lua`, which does not exist on 3.1.x, and carries a regression unit test (`tests/unit/ratelimit_test.lua`) that reproduces the exact crash and provably fails pre-fix. The 3.1.x fix is the same server + ratelimit guard, reviewer-verified, and validated by running that same test against this line's `ratelimit.lua`.

## Build / runtime

No changes. Same Lua 5.4, same LuaSec 1.3.2, same LuaSocket 3.1.0, same build toolchain as v3.1.12.

The `linux-aarch64` artifact continues with the Bullseye-container pipeline (glibc 2.31 baseline, works on Pi OS Bullseye / Bookworm / DietPi v9.x).

## Upgrade

```sh
# Linux x86_64 / aarch64
wget https://github.com/luadch-ng/luadch/releases/download/v3.1.13/luadch-v3.1.13-linux-x86_64.tar.gz
tar xzf luadch-v3.1.13-linux-x86_64.tar.gz
# move your cfg/, scripts/data/, etc into the new tree, restart hub

# Windows
# Download luadch-v3.1.13-windows-x86_64.zip, extract, copy cfg+data over, restart.
```

3.2.x is the active development line on `master`; security backports continue to land on `release/3.1.x` per [`CLAUDE.md` §8](https://github.com/luadch-ng/luadch/blob/master/CLAUDE.md#8-release-lines-and-support-policy).
