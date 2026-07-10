# Luadch v3.1.12

**Maintenance patch release** on the `release/3.1.x` line. One bugfix for a backport slip introduced in v3.1.10. No breaking changes; no cfg / lang-file changes; drop-in upgrade from v3.1.11.

## ⚠️ Before upgrading

Back up your `cfg/`, `scripts/lang/`, `scripts/data/`, `scripts/cfg/`, `certs/`, and `secrets/` directories before any upgrade, on principle. **This release has no required cfg or lang-file changes** - the upgrade is a pure binary / script tree swap, but the backup discipline is worth keeping.

```sh
tar -czf "luadch-backup-$(date +%F).tar.gz" cfg scripts certs secrets
```

## Why upgrade

**Only deployments that explicitly set `kill_wrong_ips = false`** are affected (the 3.1.x default is `true`). Operators run that opt-out specifically to admit NAT / CGNAT users whose client advertises a different IP than the one they connect from - and this bug defeats exactly that opt-out: instead of stamping the real IP and letting the user in, the hub raised a Lua error in `incoming` and the affected user could not complete login. If you set `kill_wrong_ips = false` (or plan to), upgrade. If you run the default, you are not affected and can upgrade at leisure.

## Bugfixes

### [#393](https://github.com/luadch-ng/luadch/issues/393) (Sopor) - `kill_wrong_ips = false` path errored with `attempt to read undeclared var: 'userfam'`

The symptom, once an operator set `kill_wrong_ips = false` and a mismatched-IP user connected:

```
hub.lua: function 'incoming': lua error: ././core/hub_dispatch.lua:356: attempt to read undeclared var: 'userfam'
```

The [#214](https://github.com/luadch-ng/luadch/issues/214) Gap 2 fix (shipped to 3.1.x in v3.1.10) stamps the authenticated TCP-source IP over a mismatched INF claim so the wrong IP is never broadcast. The v3.1.10 cherry-pick wrote that stamp as `adccmd:setnp( userfam, userip )` - but `userfam` is the **master** branch's variable name. The 3.1.x `incoming` function calls its address-family variable `ipver` (declared at the top of the function, used correctly by the first `setnp` on the no-IP path ~15 lines above). Under luadch's restricted core environment, reading the undeclared `userfam` raises an error - so for every user whose claimed INF IP differed from their real TCP-source IP while `kill_wrong_ips = false` was set, the stamp branch threw and the user (typically the very NAT/CGNAT client the opt-out exists to admit) could not log in.

**Fix:** use the in-scope `ipver` at that call site, matching the sibling `setnp`:

```lua
-               adccmd:setnp( userfam, userip )
+               adccmd:setnp( ipver, userip )
```

Default `kill_wrong_ips = true` deployments are unaffected - they take the kill branch and never reach the stamp branch. Master is unaffected; it uses `userfam` consistently throughout its renamed `incoming`. This was a partial-rename slip in the v3.1.10 backport only, so the fix is applied directly on `release/3.1.x` (nothing to cherry-pick from master).

The `kill_wrong_ips = false` stamp path had no smoke coverage, which is how the slip shipped in v3.1.10; a behavioural regression test needs a `kill_wrong_ips = false` hub config and is tracked as a follow-up.

## Build / runtime

No changes. Same Lua 5.4, same LuaSec 1.3.2, same LuaSocket 3.1.0, same build toolchain as v3.1.11.

The `linux-aarch64` artifact continues with the Bullseye-container pipeline (glibc 2.31 baseline, works on Pi OS Bullseye / Bookworm / DietPi v9.x).

## Upgrade

```sh
# Linux x86_64 / aarch64
wget https://github.com/luadch-ng/luadch/releases/download/v3.1.12/luadch-v3.1.12-linux-x86_64.tar.gz
tar xzf luadch-v3.1.12-linux-x86_64.tar.gz
# move your cfg/, scripts/data/, etc into the new tree, restart hub

# Windows
# Download luadch-v3.1.12-windows-x86_64.zip, extract, copy cfg+data over, restart.
```

3.2.x is the active development line on `master`; security backports continue to land on `release/3.1.x` per [`CLAUDE.md` §8](https://github.com/luadch-ng/luadch/blob/master/CLAUDE.md#8-release-lines-and-support-policy).
