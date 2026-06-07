# Luadch v3.1.11

**Maintenance patch release** on the `release/3.1.x` line. One privilege-escalation bugfix cherry-picked from master. No breaking changes; no cfg / lang-file changes; drop-in upgrade from v3.1.10.

## ⚠️ Before upgrading

Back up your `cfg/`, `scripts/lang/`, `scripts/data/`, `scripts/cfg/`, `certs/`, and `secrets/` directories before any upgrade, on principle. **This release has no required cfg or lang-file changes** - the upgrade is a pure binary / script tree swap, but the backup discipline is worth keeping.

```sh
tar -czf "luadch-backup-$(date +%F).tar.gz" cfg scripts certs secrets
```

## Why upgrade

**If your hub has more than one operator-level account and only one hubowner**, the bug fixed here is exploitable: any account with `+ban` permission (typically op-level and above) could ban the hubowner while the hubowner was offline, locking them out on the next login attempt. With a single hubowner this becomes denial-of-administration on the hub - the hubowner cannot remove their own ban because they cannot log in. With multiple hubowner-level accounts the impact is reduced to a removable nuisance.

Default-config hubs are affected. The fix applies to every operator from level 60 upward (default `cmd_ban_permission` ladder).

## Bugfixes

### [#320](https://github.com/luadch-ng/luadch/issues/320) (Kcchouette) - `cmd_ban` offline-by-nick path silently bypassed the hierarchy check

`scripts/cmd_ban.lua` had two divergent target-resolution paths converging on `addban()`:

- **Online branch** resolves `target` to a user OBJECT (has `:level()` method), falls through to the existing check at line 594: `if permission[level] < target:level() then ... msg_god`
- **Offline-by-nick branch** resolves `target` to a profile TABLE from `regnicks[]` (has `.level` field, no `:level()` method), then returns at `addban()` two lines BEFORE the check could run

Effect: a level-60 operator could send `+ban nick hubowner_offline 60 reason`, the offline branch ran `addban()` directly without checking that the operator outranked the target, and the hubowner was banned. On their next login attempt the ban hit, kicking them with `ISTA 232 ... TL<reconnect-seconds>`.

**Fix:** explicit hierarchy guard inside the offline-by-nick branch using `target.level`, mirroring the online-path semantics with the table-shape accessor:

```lua
elseif by == "nick" then
    local _, regnicks, _ = hub.getregusers()
    target = regnicks[ id ]
    if not target then
        user:reply( msg_off, hub.getbot() )
        return PROCESSED
    end
    if permission[ level ] < ( target.level or 0 ) then    -- new
        user:reply( msg_god, hub.getbot() )
        return PROCESSED
    end
end
```

cid / ip offline branches keep no profile lookup and stay unchecked by design (no hierarchy info available - the hub doesn't know whose IP a given IP is).

Plugin v0.36 → v0.37. Cherry-picked from master ([PR #322](https://github.com/luadch-ng/luadch/pull/322), commit `30c8809`); the new HTTP-API-based regression smoke test stays master-only because the HTTP API ships on 3.2.x only - the fix logic is identical and reviewer-verified.

A pattern sweep over the related command-and-profile plugins (`cmd_gag`, `cmd_setpass`, `cmd_upgrade`, `cmd_delreg`, `cmd_nickchange`, `cmd_redirect`, `cmd_disconnect`, `etc_trafficmanager`, `etc_msgmanager`) for the same online-vs-offline-hierarchy-check divergence came back clean - either properly guarded on both paths or online-only by design. cmd_ban was the only affected plugin in the family.

## Build / runtime

No changes. Same Lua 5.4.7, same LuaSec 1.3.2, same LuaSocket 3.1.0, same build toolchain as v3.1.10.

The `linux-aarch64` artifact continues with the Bullseye-container pipeline (glibc 2.31 baseline, works on Pi OS Bullseye / Bookworm / DietPi v9.x).

## Upgrade

```sh
# Linux x86_64 / aarch64
wget https://github.com/luadch-ng/luadch/releases/download/v3.1.11/luadch-v3.1.11-linux-x86_64.tar.gz
tar xzf luadch-v3.1.11-linux-x86_64.tar.gz
# move your cfg/, scripts/data/, etc into the new tree, restart hub

# Windows
# Download luadch-v3.1.11-windows-x86_64.zip, extract, copy cfg+data over, restart.
```

3.2.x is the active development line on `master`; security backports continue to land on `release/3.1.x` per [`CLAUDE.md` §8](https://github.com/luadch-ng/luadch/blob/master/CLAUDE.md#8-release-lines-and-support-policy).
