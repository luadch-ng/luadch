# Bundled scripts

This document lists every plugin shipped with luadch under
[`scripts/`](../scripts/), with a one-line description, the operator
commands it registers, and the cfg keys it reads. It is the operator-
facing reference for "what's running on my hub and how do I tune it".

Each plugin's full docstring + version history lives in the file header
itself. The cfg keys listed here are documented in
[`core/cfg_defaults.lua`](../core/cfg_defaults.lua) (defaults + inline
explanation) and editable in `cfg/cfg.tbl`.

The rate-limit section at the end is the most invasive operator-facing
knob the hub exposes - dedicated section because it has more moving
parts than a single cfg key.

---

## Bot plugins

### bot_opchat

Internal op-chat bot for operator coordination. Broadcasts staff
messages to all logged-in ops at or above the configured level.

**Commands:** `+opchat help|history|historyall|historyclear`

**Config:** `bot_opchat_activate`, `bot_opchat_nick`, `bot_opchat_desc`,
`bot_opchat_history`, `bot_opchat_max_entrys`, `bot_opchat_permission`,
`bot_opchat_oplevel`

### bot_pm2ops

Routes operator private messages to the opchat bot. Forwards messages
with sender name and level to the operator coordination chat.

**Config:** `bot_pm2ops_activate`, `bot_pm2ops_nick`,
`bot_pm2ops_desc`, `bot_pm2ops_permission`

### bot_regchat

Registered-user chat with optional message history. Similar to opchat
but restricted to registered users instead of operators.

**Commands:** `+regchat help|history|historyall|historyclear`

**Config:** `bot_regchat_activate`, `bot_regchat_nick`,
`bot_regchat_desc`, `bot_regchat_history`, `bot_regchat_max_entrys`,
`bot_regchat_permission`, `bot_regchat_oplevel`

### bot_session_chat

Temporary per-session chats for user collaboration. Chat owners can
add/remove members; membership revokes on disconnect.

**Commands:** `+sessionchat <chatname>`

**Config:** `bot_session_chat_minlevel`,
`bot_session_chat_masterlevel`, `bot_session_chat_chatprefix`

---

## Command plugins

### cmd_accinfo

Display extended account details for registered users (nick, level,
registration date, last seen, ban status). Operator version shows
description and timestamps.

**Commands:** `+accinfo sid|nick|cid <target>` / `+accinfoop sid|nick|cid <target>`

**Config:** `cmd_accinfo_permission`, `cmd_accinfo_advanced_rc`,
`etc_msgmanager_activate`, `etc_trafficmanager_activate`,
`etc_trafficmanager_flag_blocked`

### cmd_ascii

Send ASCII art pictures to main chat. List of available art defined
in language files.

**Commands:** `+ascii <artname>`

**Config:** `cmd_ascii_minlevel`

### cmd_ban

Ban / unban users by nick, CID, or IP with optional duration and
reason. Maintains ban records with history and state tracking.

**Commands:** `+ban nick|cid|ip <target> [<duration_minutes>] [<reason>]` /
`+ban show|showhis [<nick>]|clear|clearhis` /
`+unban nick|cid|ip <target>`

**Config:** `cmd_ban_permission`, `cmd_ban_default_time`,
`cmd_ban_report`, `cmd_ban_report_hubbot`, `cmd_ban_report_opchat`,
`cmd_ban_llevel`, `cmd_unban_permission`

### cmd_delreg

Delete registrations by nick. Optionally blacklist with reason to
prevent re-registration.

**Commands:** `+delreg nick <nick> [<reason>]`

**Config:** `cmd_delreg_permission`, `cmd_delreg_report`,
`cmd_delreg_report_hubbot`, `cmd_delreg_report_opchat`,
`cmd_delreg_llevel`

### cmd_disconnect

Forcefully disconnect a user with optional reason message.

**Commands:** `+disconnect <nick> <reason>`

**Config:** `cmd_disconnect_minlevel`, `cmd_disconnect_sendmainmsg`,
`cmd_disconnect_report`, `cmd_disconnect_report_hubbot`,
`cmd_disconnect_report_opchat`, `cmd_disconnect_llevel`

### cmd_errors

Display the hub error log to users with sufficient permissions.

**Commands:** `+errors`

**Config:** `cmd_errors_permission`

### cmd_gag

Mute, kennylize (garble), or shadowmute users with optional duration.
Tracks restrictions and auto-expires.

**Commands:** `+gag mute|kennylize|shadowmute|ungag|show <nick> [<duration>]`

**Config:** `cmd_gag_permission`, `cmd_gag_user_notifiy`,
`cmd_gag_report`, `cmd_gag_report_hubbot`, `cmd_gag_report_opchat`,
`cmd_gag_llevel`

### cmd_help

Central help registry for all operator commands. Displays all
available commands filtered by user level.

**Commands:** `+help`

### cmd_hubinfo

Display comprehensive hub information including version, uptime, user
counts, ports, SSL/TLS mode, system info, and user level breakdown.

**Commands:** `+hubinfo`

**Config:** `cmd_hubinfo_minlevel`, `cmd_hubinfo_onlogin`

### cmd_hubstats

Track hub statistics over time (user averages, share, registrations,
bans). Data aggregated daily / weekly / monthly / yearly.

**Commands:** `+hubstats`

**Config:** `cmd_hubstats_oplevel`

### cmd_mass

Broadcast mass messages to all users or specific user levels. Optional
sender anonymity (`+masshub`).

**Commands:** `+mass <message>` / `+masslvl <level> <message>` /
`+masshub <message>`

**Config:** `cmd_mass_permission`, `cmd_mass_oplevel`

### cmd_myinf

Display own or target user's raw INF command output (client
information).

**Commands:** `+myinf [<nick>]`

**Config:** `cmd_myinf_permission`

### cmd_myip

Display own or target user's IP address. Unrestricted command.

**Commands:** `+myip [<nick>]`

### cmd_nickchange

Change registered user nicknames. Owner can change own; operators can
change others' subject to level hierarchy.

**Commands:** `+nickchange mynick <newnick>` /
`+nickchange othernick <oldnick> <newnick>`

**Config:** `cmd_nickchange_minlevel`, `cmd_nickchange_oplevel`,
`cmd_nickchange_advanced_rc`, `cmd_nickchange_report`,
`cmd_nickchange_report_hubbot`, `cmd_nickchange_report_opchat`

### cmd_redirect

Redirect users to an alternate hub URL based on level or manual
command.

**Commands:** `+redirect <nick> <url>`

**Config:** `cmd_redirect_activate`, `cmd_redirect_permission`,
`cmd_redirect_level`, `cmd_redirect_url`, `cmd_redirect_report`,
`cmd_redirect_report_hubbot`, `cmd_redirect_report_opchat`,
`cmd_redirect_llevel`

### cmd_reg

Register new users or add / modify registration descriptions. Generates
initial passwords and enforces level hierarchies.

**Commands:** `+reg nick <nick> <level> [<comment>]` /
`+reg desc <nick> <comment>`

**Config:** `cmd_reg_permission`, `cmd_reg_report`,
`cmd_reg_report_hubbot`, `cmd_reg_report_opchat`, `cmd_reg_llevel`

### cmd_reload

Reload hub configuration, user database, and restart scripts without
full hub restart.

**Commands:** `+reload`

**Config:** `cmd_reload_permission`

### cmd_restart

Gracefully restart the hub with optional broadcast message to users.
Optional countdown timer.

**Commands:** `+restart [<message>]`

**Config:** `cmd_restart_permission`, `cmd_restart_broadcast_countdown`

### cmd_rules

Display hub rules to users (sent at login or on command). Supports
placeholder substitution.

**Commands:** `+rules`

**Config:** `cmd_rules_target`

### cmd_setpass

Set or change passwords for registered users. Operators can reset
other users' passwords.

**Commands:** `+setpass myself <password>` /
`+setpass nick <nick> <password>`

**Config:** `cmd_setpass_permission`, `cmd_setpass_advanced_rc`,
`cmd_setpass_report`, `cmd_setpass_report_hubbot`,
`cmd_setpass_report_opchat`

### cmd_shutdown

Gracefully shut down the hub with optional broadcast message. Optional
countdown timer.

**Commands:** `+shutdown [<message>]`

**Config:** `cmd_shutdown_permission`,
`cmd_shutdown_broadcast_countdown`

### cmd_slots

Display list of all currently connected users with available upload
slots.

**Commands:** `+slots`

**Config:** `cmd_slots_minlevel`

### cmd_sslinfo

Display TLS / SSL connection information for user's client (protocol
version, cipher, certificate details).

**Commands:** `+sslinfo [<nick>]`

**Config:** `cmd_sslinfo_minlevel`

### cmd_talk

Broadcast messages anonymously without nickname prefix.

**Commands:** `+talk <message>`

**Config:** `cmd_talk_permission`

### cmd_topic

Set or reset the hub topic string. Broadcasts topic changes to all
users.

**Commands:** `+topic <newtopic>` / `+topic default`

**Config:** `cmd_topic_permission`, `hub_topic`

### cmd_uptime

Display hub uptime (session and cumulative since first start) and the
calling user's personal session duration.

**Commands:** `+uptime [<nick>]`

**Config:** `cmd_uptime_minlevel`

### cmd_usercleaner

Show and remove inactive or never-used accounts. Supports time-based
expiry and exception lists.

**Commands:** `+usercleaner showall|showexpired|showghosts|delexpired|delghosts|addexception|delexception|delexceptionall|showexceptions|setdays`

**Config:** `cmd_usercleaner_permission`, `cmd_usercleaner_days`,
`cmd_usercleaner_nick_protection`,
`cmd_usercleaner_level_protection`

### cmd_userinfo

Display user information (nick, level, IP, features, share, slots).
Filters by online / offline status.

**Commands:** `+userinfo [sid|nick|cid <target>]`

**Config:** `cmd_userinfo_permission`

### cmd_userlist

List all registered users sorted by level or registration date.
Useful for administration.

**Commands:** `+userlist [bydate]`

**Config:** `cmd_userlist_permission`

### cmd_usersearch

Search registered users by partial nick match. Results include share
and registration date (password column is redacted since v3.1.6 / #95).

**Commands:** `+usersearch <searchstring>`

**Config:** `cmd_usersearch_permission`, `cmd_usersearch_advanced_rc`

---

## Etc (utility) plugins

### etc_banner

Broadcast periodic banner messages to main chat at configurable
intervals.

**Config:** `etc_banner_activate`, `etc_banner_interval`

### etc_blacklist

Maintain and display the blacklist of delreg'd users to prevent
re-registration.

### etc_chatlog

Log main chat messages with timestamps, user nicks, and message
content. Display on user login.

**Config:** `etc_chatlog_activate`

### etc_cmdlog

Audit log of all operator `+cmd` invocations (who, what, when).

**Commands:** `+cmdlog show`

**Config:** `etc_cmdlog_activate`

### etc_dhtblocker

Disconnect users with DHT (Distributed Hash Table) search enabled.
Prevents unwanted network search participation.

**Config:** `etc_dhtblocker_activate`, `etc_dhtblocker_report`,
`etc_dhtblocker_report_hubbot`, `etc_dhtblocker_report_opchat`

### etc_dummy_warning

Warn level-100 admin on login if the default "dummy" account is still
registered.

### etc_hubcommands

Internal registry module for `+cmd` handlers. Exported library used by
every command plugin via `hub.import("etc_hubcommands")`. Also emits
the "Did you mean +X?" reminder on bare-word typos. Exports `add(cmd, fn)`
plus `has(cmd)` (predicate, used by etc_aliases at `+addalias` time) and
`list()` (enumeration helper used by `+aliases` to show built-in
command names).

### etc_aliases

Operator-defined command aliases. Lets the hub admin map short or
memorable alias names to existing commands (e.g. `+us` -> `+usersearch`,
`+tm` -> `+trafficmanager`). Closes [#327](https://github.com/luadch-ng/luadch/issues/327).

**Commands:**
- `+addalias <alias> <target>` - create a new alias
- `+delalias <alias>` - remove an alias
- `+aliases` - list configured aliases AND built-in command names

**Storage:** `cfg/aliases.tbl`, grouped by target for human readability:

```lua
return {
    usersearch     = { "us" },
    trafficmanager = { "tm", "trma" },
}
```

The plugin inverts to a flat `{ [alias] = target }` map in memory.
`+addalias` / `+delalias` rewrite the file atomically; `+reload` re-reads.

**Validation at `+addalias`** rejects with a distinct error string:
- alias not matching `^%a+$` (the hub dispatcher's regex constraint)
- alias name is already a real command (real commands always win,
  cannot be aliased)
- alias already mapped (use `+delalias` first - no silent overwrite)
- target command does not exist

**Resolver fallback** runs in `etc_hubcommands` on direct-lookup miss:
the typed token is resolved through `etc_aliases.resolve(name)` and
the real command's handler dispatches, receiving the resolved command
name as its `command` argument (so help-text generation matches). The
`[command] +<typed>` echo line shows the user's original input
verbatim - it's a chat acknowledgement, not a routing trace. Both
fall-through hints ("Did you mean +X?" and the literal-bracket hint)
DO surface the resolved target, since those messages exist to teach
the operator the correct command name.

**HTTP API:** `GET /v1/aliases`, `POST /v1/aliases` (admin),
`DELETE /v1/aliases/{alias}` (admin). See [HTTP_API.md](HTTP_API.md).

**Config:** `etc_aliases_minlevel` (default 80 = admin),
`etc_aliases_report` / `_report_hubbot` / `_report_opchat` / `_llevel`
(opchat audit trail toggles, matching the cmd_topic / etc_msgmanager
pattern).

### etc_auditlog

Persistent JSONL audit trail for staff actions. Subscribes to
`onAudit` events fired by every staff-action plugin via the
core/audit.lua helper (`audit.fire(audit.build(action, actor,
target, reason, meta))`). Closes [#84](https://github.com/luadch-ng/luadch/issues/84).

**Commands:** `+auditlog show` (today's file as chat banner).

**Storage:** `log/audit-YYYY-MM-DD.jsonl`, one JSON object per
line. UTC daily rollover; on the first write past midnight the
plugin opens a new file and unlinks any `audit-*.jsonl` older than
`etc_auditlog_retention_days`. POSIX chmod 0600 on every file
(no-op on Windows; see SECURITY.md §4 for the NTFS ACL recipe).

**Append-only.** The plugin opens `io.open(path, "ab")` exclusively;
no code path truncates the active file. The `DELETE /v1/log/audit`
endpoint deliberately does NOT exist (audit-trail philosophy:
clearing must be a filesystem-level operation with explicit
chain-of-custody).

**Per-line shape:**

```json
{
    "ts":     "2026-06-23T15:42:11Z",
    "action": "ban.add",
    "actor":  { "nick": "op", "level": 80, "sid": "ABCD",
                "cid": "...", "ip": "1.2.3.4" },
    "target": { "nick": "baduser", "ip": "5.6.7.8" },
    "reason": "spam",
    "meta":   { "by": "ip", "duration_sec": 86400, "online": true }
}
```

`actor.nick` is the canonical firstnick (prefix-less); the visible
form (e.g. `[OP]op`) lands in optional `display_nick` when it
differs. `actor.sid = "<http>"` for events fired via the HTTP API
(actor_label = the bearer token's `comment`). Optional fields
(`target`, `reason`, `meta`, `display_nick`) are dropped when
empty so the on-disk shape stays compact.

**Action vocabulary (25 names across 20 plugins):**
`ban.add`, `ban.remove`, `ban.clear`, `ban.history.clear`,
`gag.add`, `gag.remove`, `user.kick`, `user.redirect`,
`user.mass.kick`, `reg.add`, `reg.remove`, `reg.update`,
`reg.desc.set`, `reg.level.set`, `reg.nickchange`,
`reg.password.change`, `hub.topic.set`, `hub.topic.reset`,
`hub.reload`, `hub.restart`, `hub.shutdown`,
`hub.announce.{all,hub,level}`,
`alias.{add,remove}`, `msgmanager.{block,unblock}`,
`blacklist.remove`, `log.clear`, `records.reset`,
`user.cleanup`, `user.cleanup.exception.{add,remove,clear}`,
`user.cleanup.setdays`, `user.cleanup.orphan_comments`.

**HTTP API:** `GET /v1/log/audit?lines=N` (admin). Same envelope
(`{lines, returned, total_lines}`) as `/v1/log/cmd` and
`/v1/errors`. The audit stream also surfaces as
`GET /v1/events?types=audit` (admin scope only, see HTTP_API.md
§10.1 footnote).

**Config:** `etc_auditlog_activate` (master kill-switch, default
true), `etc_auditlog_dir` (`log/`), `etc_auditlog_prefix`
(`audit-`), `etc_auditlog_retention_days` (90, `0` disables the
sweep), `etc_auditlog_http_lines_default` (200),
`etc_auditlog_http_lines_max` (1000). Cap keys live on the core
side: `audit_log_max_reason_chars` (1000),
`audit_log_max_meta_value_chars` (1000) - applied at `audit.build`
time so both disk and `/v1/events` payloads stay bounded.

### etc_clientblocker

Block clients by Lua-pattern match against the BINF `AP+VE` field
(`user:version()` returns the concatenated `<AP> <VE>` form). Closes
[#81](https://github.com/luadch-ng/luadch/issues/81). Promoted into
core from the `luadch-ng/scripts` companion repo (basis: pulsar
v0.2, GPLv3).

**Commands:**
- `+addblocker <pattern> [reason]` - add a pattern. First whitespace-
  token is the pattern; everything after it is the kick reason
  (defaults to `etc_clientblocker_default_reason`).
- `+delblocker <pattern>` - remove a pattern.
- `+blocker` - list configured patterns.

**Storage:** `scripts/data/etc_clientblocker.tbl`, flat
`{ [pattern] = reason }`. The plugin auto-creates an empty file at
onStart if the file is missing.

**Listener-chain placement:** MUST sit AFTER `hub_inf_manager.lua`
in `cfg.scripts`. The structural BINF validator (forbidden flags /
identity-spoof kill / I4/I6 strip) is a hard precondition for the
client-policy match; running the policy filter on un-validated INFs
would be a layering inversion. `examples/cfg/cfg.tbl` ships them in
the right order.

**Operator self-lockout footgun.** The default
`etc_clientblocker_check_levels` table exempts OPERATOR (60),
SUPERVISOR (70) and ADMIN (80); HUBOWNER (100) stays in scope
deliberately. If you add a pattern that matches your own client
from a HUBOWNER session, flip `[100]` to `false` first, otherwise
the next `+reload` will kick you on the next connect.

**Pattern validation at edit time.** `+addblocker` / `POST
/v1/clientblocker` reject patterns that are empty, exceed
`etc_clientblocker_max_pattern_len` (default 200), contain
URL-unsafe `/`, `?`, `#` or `&` (the DELETE endpoint uses the
pattern as a path-var and the router does not percent-decode -
those four chars would silently 404), or fail a
`pcall(string.find, "", pat)` compile probe. This fails loud at
add time rather than silently at the next onConnect (the pcall
guard around the actual match call is belt-and-suspenders).
All other Lua-pattern punctuation (`%`, `+`, `.`, `(`, `)`,
`[`, `]`, `*`, `-`, `^`, `$`) is allowed.

**Audit events:** `client.block.add`, `client.block.remove`,
`client.block.kick`. The kick event's `meta` carries `{pattern,
version}` so post-mortem can reconstruct which rule fired and what
the offending VE actually was.

**Op-chat / hubbot report on kick.** When
`etc_clientblocker_report=true` (default) the plugin fires
`etc_report.send` with a human-readable banner
`[ CLIENT BLOCKER ]--> The user <nick> with IP <ip> is running
<version> and is not allowed in this hub. Matching pattern: <pat>`
so staff see kicks live in op-chat without tailing the audit log.
The audit log carries the same fields structured for forensics;
the report is for operational awareness. Sub-toggles
`etc_clientblocker_report_opchat` (default true) and
`etc_clientblocker_report_hubbot` (default false) match the
sibling-plugin convention.

**Default blocklist** (`scripts/data/etc_clientblocker.tbl`):
ships with 6 well-known cheat/mod clients pre-blocked
(`CleanDC++`, `RSX++`, `CrZ++`, `SmVDC++`, `DC@fe++`,
`FearDC`). These are universally-malicious clients across DC
hubs - operators almost never want them. Remove individual
entries via `+delblocker <pattern>` or edit the .tbl directly
and `+reload`.

**Extended example list** (`examples/data/etc_clientblocker.tbl.example`):
~40 additional patterns curated by Sopor over years of hub
operation - blocks outdated stable releases of DC++ (0.0xx-0.8xx),
AirDC++ (1.0-4.29 + Web Client 0.x-2.14b + nano), EiskaltDC++ (<2.4.1),
ApexDC++ (<1.6.4), ncdc (<1.18), Jucy (<0.86), plus legacy mods
(StrgDC++, IceDC++, PDC++, PWDC++). Copy this file to
`scripts/data/etc_clientblocker.tbl` and `+reload` to adopt the
broader policy.

**HTTP API:**
- `GET /v1/clientblocker` (read scope) - list patterns
- `POST /v1/clientblocker` (admin scope) - add pattern; body
  `{pattern, reason?}`
- `DELETE /v1/clientblocker/{pattern}` (admin scope) - remove
  pattern (path-encoded; the router decodes the path var)

**F-INF-1d nil-VE guard** (Phase 8a): a client that did not send
a `VE` field at BINF has nothing to match against. The check
skips silently rather than crashing; matches the "no rule
applies" semantic for any other missing input.

**Config:** `etc_clientblocker_oplevel` (write floor for the ADC
cmd; default 80), `etc_clientblocker_check_levels` (per-level
boolean table; level 55 (SBOT) + 60/70/80 exempt by default),
`etc_clientblocker_default_reason`
(`"Your client is not allowed"`),
`etc_clientblocker_max_pattern_len` (200),
`etc_clientblocker_report` (true), `etc_clientblocker_report_opchat`
(true), `etc_clientblocker_report_hubbot` (false),
`etc_clientblocker_llevel` (60).

### etc_keyprint

Automatically extract and cache hub certificate keyprint (SHA256) for
client validation. Sets `keyprint_hash` / `use_keyprint` in cfg.

### etc_log_cleaner

Clean error.log and cmd.log files. Keeps last N lines and supports
manual or scheduled cleanup.

**Commands:** `+cleanlog error|cmd`

**Config:** `etc_log_cleaner_permission`, `etc_log_cleaner_lines`

### etc_motd

Send message-of-the-day to users on login. Supports placeholder
substitution.

**Config:** `etc_motd_activate`, `etc_motd_target`

### etc_msgmanager

Block main chat and / or PM for specific user levels. Useful for spam
or abuse prevention.

**Commands:** `+msgmanager blockmain|blockpm|blockboth|unblock <nick>` /
`+msgmanager showusers|showsettings`

**Config:** `etc_msgmanager_activate`, `etc_msgmanager_permission`,
`etc_msgmanager_permission_main`, `etc_msgmanager_permission_pm`,
`etc_msgmanager_blocked_levels_main`,
`etc_msgmanager_blocked_levels_pm`, `etc_msgmanager_report`,
`etc_msgmanager_report_hubbot`, `etc_msgmanager_report_opchat`,
`etc_msgmanager_llevel`

### etc_onfailedauth

Send report when user fails authentication (bad password, IP ban,
etc).

**Config:** `etc_onfailedauth_report`

### etc_records

Track and display hub records (peak users, largest user share, etc).
Reset capability for admins.

**Commands:** `+records` / `+records reset`

**Config:** `etc_records_permission`, `etc_records_report`,
`etc_records_report_hubbot`, `etc_records_report_opchat`

### etc_report

Internal library for sending operator reports to hub bot and / or
opchat. Exported by other scripts.

### etc_trafficmanager

Block downloads, uploads, and searches for specific users. Useful for
spam or abuse control.

**Commands:** `+trafficmanager block|unblock <nick> [<reason>]` /
`+trafficmanager show settings|blocks`

**Config:** `etc_trafficmanager_activate`,
`etc_trafficmanager_permission`,
`etc_trafficmanager_blocked_levels`,
`etc_trafficmanager_check_minshare`,
`etc_trafficmanager_flag_blocked`, `etc_trafficmanager_report`,
`etc_trafficmanager_report_hubbot`,
`etc_trafficmanager_report_opchat`, `etc_trafficmanager_llevel`

> **CCPM side effect:** ADC uses the same `CTM` / `RCM` commands for
> file-transfer connection setup AND for CCPM (encrypted client-to-
> client PM) channel setup. The plugin blocks both at the hub level
> for blocked users, so adding a level to `etc_trafficmanager_blocked_levels`
> ALSO disables CCPM for that level. Affected users can still chat
> through the hub via regular `EMSG` / `DMSG`; only the direct
> end-to-end encrypted channel is unreachable. There is no clean
> wire-level differentiator between the two uses; operators who want
> CCPM available for a level must remove that level from the block
> list and accept the corresponding file-transfer permission. The
> source-level rationale is in the [`etc_trafficmanager.lua` header](../scripts/etc_trafficmanager.lua).

### etc_unknown_command

Reject mistyped or malformed commands in main chat with helpful error
message.

### etc_usercommands

Internal registry module for client right-click context menus.
Exported library used by command plugins via
`hub.import("etc_usercommands")`.

### etc_userlogininfo

Display detailed user connection info on login (client type, tag,
feature list, TLS cipher, upload / download speeds).

**Config:** `etc_userlogininfo_activate`

---

## Hub management plugins

### hub_bot_cleaner

Remove unused bot accounts from user database on timer. Prevents
clutter from disabled scripts.

**Config:** `hub_bot_cleaner_days`

### hub_cmd_manager

Enforce permission levels on direct ADC commands (EMSG, DMSG, SCH,
etc). Blacklist / whitelist support.

### hub_inf_manager

Validate user INF flags on connect and broadcast. Kill users whose
TCP source IP and BINF-advertised IP disagree (`kill_wrong_ips`).

**Config:** `kill_wrong_ips`

### hub_runtime

Track cumulative hub runtime (survives restarts) and provide show /
reset commands. Persists to `core/hci.lua`.

**Commands:** `+runtime show|reset`

### hub_user_lastseen

Update `lastseen` timestamp in user database on periodic timer (every
minute).

---

## User restriction plugins

### usr_desc_prefix

Prepend level-based prefix to user descriptions (e.g. `[VIP]`,
`[MOD]`). Configurable per level.

**Config:** `usr_desc_prefix_activate`, `usr_desc_prefix_levels`,
`usr_desc_prefix_prefix_table`

### usr_hide_share

Hide share size for specified user levels. Manual toggle via command.
Prevents share-based discrimination.

**Commands:** `+hideshare <nick>`

**Config:** `usr_hide_share_activate`,
`usr_hide_share_restrictions`, `usr_hide_share_permission`

### usr_hubs

Enforce minimum / maximum hub count per level. Redirect or disconnect
violators. Anti-multi-hub enforcement.

**Config:** `usr_hubs_minmax_table`, `usr_hubs_permission`,
`usr_hubs_redirect`

### usr_nick_length

Enforce min / max nickname length on connect and INF updates (multi-
byte codepoint-aware since v3.1.6).

**Config:** `min_nickname_length`, `max_nickname_length`

### usr_nick_prefix

Prepend level-based prefix to user nicknames (e.g. `[Op]Bob`,
`[VIP]Alice`). Configurable per level.

**Config:** `usr_nick_prefix_activate`, `usr_nick_prefix_levels`,
`usr_nick_prefix_prefix_table`

### usr_share

Enforce minimum / maximum share per user level. Redirect or disconnect
violators with optional blocking.

**Config:** `usr_share_minmax_table`, `usr_share_redirect`

### usr_slots

Enforce minimum / maximum upload slots per user level. Redirect or
disconnect violators.

**Config:** `usr_slots_minmax_table`, `usr_slots_redirect`

### usr_uptime

Track per-user session and cumulative online time. Aggregates by
month and displays totals.

**Commands:** `+useruptime [<nick>]`

**Config:** `usr_uptime_permission`

---

## Rate-limit configuration

The hub-level rate limiter lives in
[`core/ratelimit.lua`](../core/ratelimit.lua) and runs **before** any
plugin listener. It is a core feature, not a plugin, but operators
tune it the same way - via `cfg/cfg.tbl`. The full design rationale
is in [`docs/SECURITY.md` §5](SECURITY.md).

### What it protects

| Bucket | Limits | Default |
|---|---|---|
| Per-IP parallel sockets | Concurrent connections from one IP | 16 |
| Per-IP new-conn rate | Tokens / s with burst | 10 / s, burst 30 |
| Per-IP failed-auth | Bad-password rate before sticky lockout | 10 / min, burst 5 |
| TLS-handshake deadline | Wallclock seconds before a half-open TLS is killed | 10 s |
| Per-user **mainchat** (BMSG) | Tokens / s with burst | 5 / s, burst 10 |
| Per-user **PM** (DMSG / EMSG) | Tokens / s with burst | 5 / s, burst 10 |
| Per-user **BINF** (post-login updates) | Tokens / s with burst | 2 / s, burst 20 |
| Per-user **CTM / RCM** (peer-connection setup) | Tokens / s with burst | 2 / s, burst 30 |
| Per-user **search** (BSCH / FSCH / DSCH) | One token every N seconds with burst | 1 / 2 s, burst 3 |

The five per-user buckets (mainchat, PM, BINF, CTM/RCM, search) each
have their own rate-and-burst config; operators can dial each
independently. The defaults are sized so a normal user never hits
them - the limits only fire for floods.

### Op-level bypass

```lua
ratelimit_bypass_level = 60,
```

Users at or above this level skip **all per-user** checks. Per-IP
checks always apply regardless of level. Default 60 = "operator and
above bypass". Set higher (e.g. 80) to also rate-limit operators.

### Tier overlay (per-userlevel limits)

By default every non-op user uses the same scalar bucket settings
above. To set different limits per user level, define one or more
named **tiers** and map levels to them. Tiers are layered on top of
the scalars - any field a tier omits falls back to the scalar default,
and levels not in the map use the scalars unchanged.

```lua
-- unreg + guest get a stricter chat budget; bots get headroom on the
-- connection-setup bucket; everyone else stays on the defaults
ratelimit_tiers = {
    strict = {
        msg_rate    = 2,
        msg_burst   = 5,
        pm_rate     = 2,
        pm_burst    = 5,
    },
    bot = {
        ctm_rate    = 5,
        ctm_burst   = 60,
    },
},

ratelimit_tier_for_level = {
    [0]  = "strict",   -- unreg
    [10] = "strict",   -- guest
    [55] = "bot",      -- sbot
},
```

The 10 known tier fields are:

```
msg_rate     pm_rate     inf_rate     ctm_rate     search_period
msg_burst    pm_burst    inf_burst    ctm_burst    search_burst
```

Typo'd field names (e.g. `msg_brust = 5`) are rejected at cfg load
with an `out_error` log entry, so the operator notices the typo
instead of silently falling back to the global scalar.

### Default tuning rationale

- **chat (BMSG) 5 / s burst 10** - well above normal chat cadence (a
  user typing fast still trips at maybe 1 / s sustained); covers a
  ten-line paste without dropping.
- **PM (DMSG / EMSG) 5 / s burst 10** - same as chat (split out from
  the shared bucket in #80 so operators can tighten PM independently
  if abuse arises; PMs are harder to observe publicly).
- **BINF 2 / s burst 20** - tolerates watch-folder churn (one BINF
  per file added / removed during a sync) and parallel-download
  startup (ten slot-count updates in one second). Sustained 2 / s
  caps any flood at 120 / min after the burst.
- **CTM / RCM 2 / s burst 30** - covers "download all from this
  search results page" with up to 30 peers in the burst; same flood
  cap after.
- **Search 1 / 2 s burst 3** - search is server-side expensive
  (every connected client gets the query), so the cooldown is
  tighter. Burst 3 lets a user fire three quick refinements before
  the next 2 s.

### Throttle behaviour - important plugin contract note

When a bucket is exhausted the dispatcher returns `true` from the
handler, which **suppresses both the message fan-out AND the plugin
listener chain**. Throttled BINFs do not reach `onInf`, throttled
CTMs do not reach `onConnectToMe`, throttled DMSGs do not reach
`onPrivateMessage`. The full discussion is in
[`docs/SECURITY.md` §5 "Rate-limit and plugin contract"](SECURITY.md#rate-limit-and-plugin-contract-80).

For most operators this is the right behaviour. If you write a
plugin that does count-based heuristics on per-user messages, be
aware that the hub-level drop hides the post-burst tail from you.

### Bucket disable

To disable a single bucket, raise its limit very high - there's no
explicit off-switch per bucket. To disable the entire rate-limit
machinery:

```lua
ratelimit_activate = false,
```

This skips every check (per-IP, per-user, handshake-deadline). Not
recommended for public-facing deployments.

---

## ADC-EXT passthrough extensions

ADC defines a number of optional extensions where the hub's role is
purely transparent: clients negotiate the extension between
themselves (typically via `INF.SU` advertisement) and the hub just
relays the resulting commands like any other D-class / B-class
message. luadch supports these by simply not blocking them - no
SUP advertisement, no validation, no special parsing beyond the
already-existing default-validator path on unknown named
parameters (Phase 7d hardening).

Extensions in this category that the audit catches as
\"spec-defined, hub-passthrough\":

| Ext | What it does | Hub-side |
|---|---|---|
| **TYPE** | Typing notifications (\"user X is composing...\"), like instant-messenger clients show | passthrough |
| **ONID** | Per-user metadata about external services (email, ICQ, etc.); informational relay only | passthrough |
| **DFAV** | Decentralised hub-list: clients exchange their public hub favourites via `GFA` / `RFA` to build a community hublist | passthrough |
| **FEED** | RSS feed broadcasts inside the hub chat | passthrough |
| **ASCH** | Extended search NPs (file/folder filter, depth limit, etc.) | passthrough |
| **SEGA** | File-extension grouping in SCH | passthrough |
| **SUDP** | Encrypted UDP search-result delivery (`KY` key NP) | passthrough |
| **CCPM** | Client-to-client private messaging (`MSG.PM`) - hub detects support on login but stays out of the actual PM session | detect + passthrough |
| **BZIP** | bzip2-compressed filelist transport (client-pair) | passthrough |

luadch doesn't advertise any of these in its own ISUP because the
hub itself doesn't speak them - the client signals support per-user
in `INF.SU` and peers negotiate accordingly. If you write a plugin
that wants to gate one of these (e.g. forbid TYPE for level-0
unregistered users), it's a standard `onBroadcast` / `onPrivateMessage`
listener on the relevant command 4cc.

If a future ADC-EXT extension appears that the hub MUST validate
or transform (rather than just relay), it gets a first-class entry
in this doc and full \`core/hub_dispatch.lua\` plumbing - same way
NATT (#147 T1.1) and FRES (#147 T1.6) landed. The four extensions
above were filed as #147 T1.8 and explicitly do not need that.

---

## Optional plugins (companion repo)

The bundled tree above ships with luadch and is install-and-go. For
extra functionality - download bots, info commands, share-policy
plugins, RSS feeds, custom commands - see the curated companion
repository:

**[luadch-ng/scripts](https://github.com/luadch-ng/scripts)**

Each companion plugin lives in its own subdirectory under `scripts/`.
Drop the subdirectory into your `scripts/` tree, whitelist the plugin
in the `cfg.scripts` array in `cfg/cfg.tbl`, then `+reload`. Each
plugin folder contains its own README describing its commands and
cfg keys.

Note that the companion repo has a separate maintenance state - some
plugins there require luadch v3.1.7+ for features like
`util.atomic_write` (see the plugin header for the minimum hub
version).
