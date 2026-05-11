# Luadch v3.1.7

Plugin data-integrity patch release. `util.savearray` / `util.savetable` are now atomic-by-default across the bundled scripts tree, defensive `or {}` was swept onto `util.loadtable` consumers, the cross-month accounting bug in `usr_uptime` is fixed, and `cmd_gag` gains a shadowmute mode plus duration syntax.

## ⚠️ Before upgrading

Back up your `cfg/`, `scripts/lang/`, `scripts/data/`, `scripts/cfg/`, `certs/`, and `secrets/` directories. This release modifies `scripts/lang/cmd_gag.lang.{en,de}` (5 new keys + 4 rewritten strings for shadowmute / duration support) and adds `encrypt_usertbl` to `examples/cfg/cfg.tbl`. If you have customised `cmd_gag` translations, see the **Lang file changes** section below before letting the autosync run.

```sh
tar -czf "luadch-backup-$(date +%F).tar.gz" cfg scripts certs secrets
```

## Lang file changes

Operators with stock bundled lang files get the new keys automatically via the Docker autosync from [#118](https://github.com/luadch-ng/luadch/pull/118), or via `cmake --install build` for source builds. Operators with **custom** `cmd_gag.lang.*` files have a small one-time merge:

| File | What changed |
|---|---|
| `cmd_gag.lang.{en,de}` | New keys: `msg_invalid_duration`, `msg_add_user_with_duration`, `msg_expired`, `ucmd_duration`, `ucmd_menu_ct1b`. Rewritten: `msg_usage`, `help_usage`, `help_desc` (now reference shadowmute + `<DURATION>`), `msg_show_users` (adds the "Shadowmuted users" block). Missing keys fall back to the hardcoded English defaults; behaviour stays correct, the chat output just sits in mixed languages until the merge happens. |

## Features

- **`cmd_gag` shadowmute mode + duration** ([#85](https://github.com/luadch-ng/luadch/issues/85) / [#132](https://github.com/luadch-ng/luadch/pull/132)) - the gag bot gets a 4th mode where the target sees their own messages echo back as if everything works, but nobody else on the hub receives them. Combined with this, all three restriction modes (mute, kennylize, shadowmute) now take an optional duration: `30s`, `10m`, `2h`, `1d`, `1w` and combinations like `1h30m`. Empty duration = permanent. Restrictions auto-expire as the gag table is walked every 60s. Offline ungag works through `hub.getregusers()` so admins can lift restrictions even after the user disconnects. Right-click menu gets a "Shadowmute User" entry alongside the existing mute / kennylize ones.
- **`encrypt_usertbl` opt-out toggle** ([#128](https://github.com/luadch-ng/luadch/issues/128) / [#129](https://github.com/luadch-ng/luadch/pull/129)) - the Phase-7f AES-256-GCM at-rest encryption of `cfg/user.tbl` is now optional. Default `true` preserves the v3.1.3+ behaviour. Setting `encrypt_usertbl = false` writes plaintext Lua for single-user / home-hub deployments where disk-level confidentiality isn't part of the threat model and operator tooling needs direct read access to the file. Auto-detected on read via the LDC1 magic prefix, so migration is transparent in both directions; `master.key` is loaded if present (legacy decrypt) but only auto-generated when encryption is on.

## Bugfixes

- **`usr_uptime` cross-month accounting** ([#127](https://github.com/luadch-ng/luadch/issues/127) / [#131](https://github.com/luadch-ng/luadch/pull/131)) - sessions that span month boundaries no longer accumulate as "years" of uptime. The pre-fix code bracketed sessions on `login` and credited the whole span to the login month on `logout`, so a session starting on the 31st and ending on the 1st saw the end-month-minus-start-month delta arithmetic wrap into multi-year totals. The fix walks the user list on a 60-second timer and credits each tick to the calendar month it falls into, so cross-month sessions land in both months correctly.
- **Plugin save crash-safety - F-PLG-1** ([#133](https://github.com/luadch-ng/luadch/issues/133) / [#134](https://github.com/luadch-ng/luadch/pull/134)) - `util.savearray` and `util.savetable` previously opened the target file in `"w+"` (truncate) and wrote serialised content directly, so a hub crash mid-write left the `.tbl` partial. Both helpers now route through a new public `util.atomic_write(path, content)` helper that does tmp + rename (Windows fallback: remove then rename). 21 plugin save sites across the bundled tree get crash-safe writes with zero call-site changes; `core/cfg_users.lua` keeps its `chmod 600` for `user.tbl` separately via `util.chmod_secret`.
- **Plugin load nil-handling - F-PLG-2** ([#133](https://github.com/luadch-ng/luadch/issues/133) / [#135](https://github.com/luadch-ng/luadch/pull/135)) - `util.loadtable` returns `nil` on missing / unreadable / parse-fail. Defensive `or {}` added at 22 consumer sites across 12 bundled plugins (`bot_session_chat`, `cmd_accinfo`, `cmd_delreg`, `cmd_nickchange`, `cmd_reg`, `cmd_usercleaner`, `etc_msgmanager`, `etc_trafficmanager`, `usr_hide_share`, plus field-read defence in `cmd_hubinfo`, `cmd_uptime`, `hub_runtime`). Sites with the existing init-pattern (`check_hci` style: type-check + savetable + opchat warning) intentionally left alone - they handle nil correctly and auto-create the file.
- **F-PLG-3 audit** ([#133](https://github.com/luadch-ng/luadch/issues/133)) - silent no-op on incomplete `+cmd` audited across 24 bundled scripts and 53 `utf.match`-on-parameters sites. **No actionable bugs found.** Every command handler already has either an explicit pre-check guard or a final `msg_usage` fallback. Audit closeout on the tracker.

## Notes

- New public helpers in `core/util.lua`: `util.atomic_write(path, content)` and `util.tabletostring(tbl, name)`. Plugins that roll their own save logic can route through them for crash-safe writes. The companion `luadch-ng/scripts` repo already uses them in `ptx_poll_bot`, `ptx_freshstuff`, `etc_requests`, and `etc_mainecho` (min hub version: **v3.1.7**).
- Smoke harness: 31/31 PASS on Linux + Windows. No test count change in this release; the existing tests already cover the new behaviour (atomic-write path validated by `test_usertbl_bak_atomic_refresh` from v3.1.5).
- Companion plugin updates landed in [`luadch-ng/scripts#24`](https://github.com/luadch-ng/scripts/issues/24) (closed) with two PRs adding atomic save + nil-handling to the curated plugin tree - operators running those plugins should also pull the latest from that repo.

## Downloads

| File | Platform |
|---|---|
| `luadch-v3.1.7-linux-x86_64.tar.gz` | Linux glibc x86_64 |
| `luadch-v3.1.7-windows-x86_64.zip`  | Windows x86_64 (MinGW UCRT64) |
| `ghcr.io/luadch-ng/luadch:v3.1.7`   | Container, linux/amd64 + linux/arm64 |

## Migration from v3.1.6

Drop the new install tree in place of the old one (or `git pull && cmake --build build && cmake --install build` from source). Container users get both the bundled `*.lua` sync and the lang add-only sync on the next `docker compose up -d` after `pull`.

No `cfg.tbl` migration is needed. The new `encrypt_usertbl` key in `examples/cfg/cfg.tbl` is purely additive - existing `cfg/cfg.tbl` files without the key default to encrypted, which matches v3.1.6 behaviour. To opt out, add `encrypt_usertbl = false` and `+reload` (or restart the container).

## Build from source

```sh
git clone --branch v3.1.7 https://github.com/luadch-ng/luadch.git
cd luadch
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
cmake --install build
```
