# Blocklist and GeoIP (operator guide)

luadch blocks unwanted connections in two complementary layers:

| Layer | Fires | Handles | Managed by |
|---|---|---|---|
| **Pre-handshake IP/CIDR blocklist** | TCP accept, before ADC/TLS | known-bad IPs and CIDR ranges (manual + future feeds) | `+blocklist` ([`SCRIPTS.md`](SCRIPTS.md) etc_blocklist) |
| **Post-handshake bans** | after login | nick / CID / short-term IP bans | `+ban` (cmd_ban) |
| **GeoIP policy** | on connect, post-handshake | country / ASN policy | `etc_geoip` (this doc) |

The pre-handshake blocklist is your DoS/scanner shield (a hostile IP is
dropped before it costs you a TLS handshake). GeoIP is *policy*: it
decides whether users from a given country or network are welcome, and
kicks them post-handshake with a reason they can read - the same layer
`+ban` and the client blocker use. This is deliberate; see the design
note at the end.

---

## GeoIP: country / ASN blocking (`etc_geoip`, #78 Phase D2)

`etc_geoip` resolves each connecting IP to its country (and optionally
its autonomous-system number) using a MaxMind GeoLite2 database, and
either logs or kicks connections matching your policy.

- **Per-connection lookup**, bounded to a few tens of microseconds, run
  after the handshake. It adds nothing to the pre-handshake accept path
  and never bloats the IP blocklist with the thousands of CIDRs a single
  country spans.
- **Operators are exempt by default** (`etc_geoip_check_levels`) so a
  wrong country code cannot lock your staff out.
- **The hub runs fine without a database.** A missing / outdated `.mmdb`
  logs one warning and leaves the checks inert.

### 1. Get a MaxMind GeoLite2 database

The database is **not bundled** (MaxMind's licence forbids
redistribution, and it ships only as a `.tar.gz`). It is free:

1. Create a free account at <https://www.maxmind.com/en/geolite2/signup>.
2. Generate a **licence key** (Account -> Manage License Keys).
3. Install MaxMind's `geoipupdate` tool and let it pull + refresh the
   `.mmdb` files. MaxMind releases updates twice weekly.

Editions you want: `GeoLite2-Country` (required for country blocking),
`GeoLite2-ASN` (optional, for ASN blocking).

#### Linux (bare metal)

```sh
apt install geoipupdate          # or: dnf install geoipupdate
```

`/etc/GeoIP.conf`:

```
AccountID 123456
LicenseKey YOUR_LICENSE_KEY
EditionIDs GeoLite2-Country GeoLite2-ASN
DatabaseDirectory /opt/luadch/cfg/geoip
```

```sh
chmod 600 /etc/GeoIP.conf         # the licence key is a secret
mkdir -p /opt/luadch/cfg/geoip
geoipupdate                       # first pull
# refresh Wed + Sat 04:00 (MaxMind releases Tue + Fri):
echo '0 4 * * 3,6 root geoipupdate' > /etc/cron.d/geoipupdate
```

#### Windows (bare metal)

Download `geoipupdate.exe` from
<https://github.com/maxmind/geoipupdate/releases>, put a `GeoIP.conf`
next to it (`DatabaseDirectory C:\Luadch\cfg\geoip`), then:

```bat
schtasks /create /tn geoipupdate /tr "C:\path\geoipupdate.exe" /sc weekly /d WED,SAT /st 04:00 /ru SYSTEM
```

#### Docker (recommended)

Run MaxMind's official updater as a sidecar sharing a volume with the
hub:

```yaml
services:
  luadch:
    volumes:
      - ./cfg:/luadch/cfg
      - geoip_data:/luadch/cfg/geoip
  geoipupdate:
    image: maxmindinc/geoipupdate
    restart: unless-stopped
    environment:
      - GEOIPUPDATE_ACCOUNT_ID=123456
      - GEOIPUPDATE_LICENSE_KEY=YOUR_LICENSE_KEY
      - GEOIPUPDATE_EDITION_IDS=GeoLite2-Country GeoLite2-ASN
      - GEOIPUPDATE_FREQUENCY=72          # hours
    volumes:
      - geoip_data:/usr/share/GeoIP
volumes:
  geoip_data:
```

The hub reads `.mmdb` files from `cfg/geoip/`; point
`etc_geoip_country_db_path` at wherever `geoipupdate` writes them.

### 2. Enable the plugin

In `cfg/cfg.tbl`, flip the plugin on in `cfg.scripts` and set the
feature toggle:

```lua
{ "etc_geoip.lua", enabled = true },   -- in the cfg.scripts list
```

```lua
etc_geoip_enabled = true,
etc_geoip_country_db_path = "cfg/geoip/GeoLite2-Country.mmdb",
etc_geoip_blocked_countries = { "CN", "RU", "KP" },   -- ISO-3166-1 alpha-2
etc_geoip_action = "log_only",                        -- start here, see below
```

Then `+reload`.

### 3. Verify with `log_only`, then enforce

`etc_geoip_action` defaults to **`log_only`**: every match is audited
(`geoip.block` with `action=log_only`) and reported to op-chat, but the
user is let in. Run this for a while and watch which real users your
policy would drop. When you are confident, switch to:

```lua
etc_geoip_action = "block",
```

and `+reload`. Now matches are kicked with `etc_geoip_kick_reason`.

`+geoip` (operator command) shows live status: DB load state + build
date, action mode, and the blocked country / ASN lists. The same
snapshot is available read-only at `GET /v1/geoip`.

### 4. Config reference

| Key | Default | Meaning |
|---|---|---|
| `etc_geoip_enabled` | `false` | master toggle (plugin loads either way) |
| `etc_geoip_country_db_path` | `cfg/geoip/GeoLite2-Country.mmdb` | Country `.mmdb` path |
| `etc_geoip_asn_db_path` | `cfg/geoip/GeoLite2-ASN.mmdb` | ASN `.mmdb` path (optional) |
| `etc_geoip_blocked_countries` | `{ }` | ISO-3166-1 alpha-2 codes (case-insensitive) |
| `etc_geoip_blocked_asns` | `{ }` | AS numbers (needs the ASN DB) |
| `etc_geoip_action` | `"log_only"` | `"log_only"` or `"block"` |
| `etc_geoip_check_levels` | ops exempt | which user levels are checked |
| `etc_geoip_recheck_interval_sec` | `3600` | how often the `.mmdb` is re-read (picks up geoipupdate writes) |
| `etc_geoip_kick_reason` | "Your region is not permitted..." | kick message (block mode); operator policy text, set it here |
| `etc_geoip_oplevel` | `80` | min level for `+geoip` |
| `etc_geoip_report` | `true` | fire an op-chat / hubbot report on every match |
| `etc_geoip_report_hubbot` | `false` | send the report as a hubbot PM to ops >= `etc_geoip_llevel` |
| `etc_geoip_report_opchat` | `true` | send the report into op-chat |
| `etc_geoip_llevel` | `60` | min level for the hubbot-PM report |

### Troubleshooting

- **`... database not found ...` in the log.** The `.mmdb` is not at the
  configured path yet. Run `geoipupdate`; check `etc_geoip_country_db_path`.
- **`... database is older than 30 days ...`.** `geoipupdate` has not
  refreshed. Country data drifts; refresh it (and check your cron /
  sidecar). Also emitted as a `geoip.db.stale` audit.
- **A user from an allowed country is blocked / vice versa.** GeoIP is
  approximate and changes over time. Verify with `+geoip` and the audit
  log; keep the DB fresh.
- **Dual-stack hubs.** On a `::` listener, IPv4 clients arrive as
  `::ffff:a.b.c.d` and resolve correctly - MaxMind's GeoLite2 databases
  are IPv6 (`ip_version = 6`) and alias the v4-mapped range onto the v4
  data. Use the GeoLite2 databases `geoipupdate` provides; a
  hand-built IPv4-only or non-aliasing DB would silently not geo-check
  v4-mapped clients.

---

## Design note: why GeoIP kicks post-handshake

Country blocking is policy, not attack mitigation. A user from a blocked
country is not attacking the hub - so kicking them after the handshake
with a clear reason is better UX than silently dropping the socket, and
it lets `etc_geoip` log *who* was blocked (nick, IP, country, ASN), which
a pre-handshake drop cannot (no identity exists yet). The per-connection
mmdb lookup is depth-bounded and dwarfed by the TLS handshake that
already happened, so it does not slow the hub even under many concurrent
connects. Pre-handshake blocking is the job of the IP/CIDR blocklist and
the rate limiter; GeoIP layers cleanly on top of them.

---

## External feeds (`etc_blocklist_feeds`, #78 Phase E)

`etc_blocklist_feeds` pulls public known-bad-IP lists over HTTPS on a
per-feed timer and pushes them into the same pre-handshake blocklist, so
listed IPs are dropped at TCP-accept before they cost a handshake. Unlike
GeoIP (a post-handshake policy check), feeds are pure infrastructure
blocking and run through the engine's fast pre-handshake path.

Every feed is **independently opt-in and OFF by default**. The plugin
needs no API key and no external tool - it fetches directly (verified TLS
against the bundled CA bundle). A whole feed is ingested in one atomic
store write, and each refresh *replaces* the feed's previous entries, so
a shrinking feed leaves no stale rows.

### Built-in feeds

| Feed | Source | Default URL | Min interval | Notes |
|---|---|---|---|---|
| `tor` | Tor exit nodes | `check.torproject.org/torbulkexitlist` | 30 min | Plain IPv4, one per line. **Do not** point it at `dan.me.uk` - that host firewall-bans IPs fetching more than once per 30 min. |
| `spamhaus` | Spamhaus DROP v4 | `spamhaus.org/drop/drop_v4.json` | 1 h | JSON (one `{"cidr","sblid"}` per line). Spamhaus policy is "at least 1 h apart"; the default is 24 h (DROP churns slowly). EDROP merged into DROP in 2024 - there is no separate EDROP feed. |
| `spamhaus_v6` | Spamhaus DROP v6 | `spamhaus.org/drop/drop_v6.json` | 1 h | Same format; shares the `spamhaus` interval + stealth toggle. |
| `abuseipdb` | AbuseIPDB blacklist | `api.abuseipdb.com/api/v2/blacklist?plaintext` | 6 h | Top-N most-reported IPs (free tier = 10,000 individual IPs). **Needs an API key.** The blacklist-download endpoint is capped at 5 requests/day on the free tier - a separate limit from the "1,000 Checks & Reports" and "100 Block Checks" quotas shown on the pricing page - so the interval floor is 6 h (4 pulls/day). Default 24 h. |
| `generic` | operator URL | (none - you set it) | 5 min | Any line-list of one IP or CIDR per line (`#`/`;` comment lines and inline trailing comments tolerated). No API key. `etc_blocklist_feeds_generic_enabled` does nothing until you set `etc_blocklist_feeds_generic_url`. |

The operator's configured refresh interval is **clamped up** to the
feed's minimum at runtime - polling faster than a provider allows gets
the hub's IP firewalled by that provider.

### AbuseIPDB API key

The `abuseipdb` feed needs a free API key (register at abuseipdb.com).
Give it to the hub **env-var-first** (Docker-friendly) or via cfg:

```sh
# preferred (Docker / systemd): the key never touches cfg.tbl
export LUADCH_ETC_BLOCKLIST_FEEDS_ABUSEIPDB_KEY=your_key_here
```

```lua
-- or in cfg/cfg.tbl as a fallback:
etc_blocklist_feeds_abuseipdb_key = "your_key_here",
```

A key placed in `cfg.tbl` is redacted in `GET /v1/config`, but only once
the plugin is loaded (in `cfg.scripts`) - so prefer the env var, which is
never dumped by the config API at all. The key is sent in the `Key:`
request header and is never written to a log or the `+blfeeds` status.

If the feed is enabled but no key is found, the plugin leaves it disabled
(it never fires a keyless request) and shows it as `enabled=false` in
`+blfeeds`; with `log_scripts` on it also logs a one-time warning.

### Enable a feed

In `cfg/cfg.tbl`, turn the plugin on in `cfg.scripts`:

```lua
{ "etc_blocklist_feeds.lua", enabled = true },
```

then flip the master toggle and the feed(s) you want:

```lua
etc_blocklist_feeds_enabled = true,
etc_blocklist_feeds_tor_enabled = true,
etc_blocklist_feeds_spamhaus_enabled = true,
```

`+reload` (or restart). Each enabled feed refreshes a few seconds after
boot and then on its interval. Check state with `+blfeeds` (or
`GET /v1/blocklist/feeds`): it shows each feed's enabled state, interval,
current entry count, and the last refresh result.

### Stealth

By default a blocked feed IP gets the same visible pre-handshake drop as a
manual block. Set `etc_blocklist_feeds_tor_stealth = true` or
`etc_blocklist_feeds_spamhaus_stealth = true` (the v6 feed shares the
spamhaus toggle) to drop those connections silently (no per-attempt log
line; the aggregated rollup still counts them) - useful for large feeds
where per-attempt logging would be noisy.

### Failure behaviour

A fetch / parse / HTTP failure is **self-healing**: the last-good entries
stay in place (the store refuses to replace a feed with an all-invalid
parse), a `feed.refresh.fail` audit fires, and op-chat is alerted once on
the transition to failing (not every interval). Entries carry a TTL of
twice the refresh interval as a backstop, so a permanently-dead feed
eventually ages out rather than blocking forever on stale data.

---

## Live proxy / VPN / Tor detection (`etc_proxydetect`, #78 Phase F)

`etc_proxydetect` looks the connecting IP up against an external
detection provider on connect and, if it is a proxy / VPN / Tor exit of a
type you block, kicks the connection (`etc_proxydetect_action = "block"`)
or just logs it (`"log_only"`, the default). It is **OFF by default** and
needs a provider (an API key is recommended, and required for some
providers).

Unlike GeoIP (a local database lookup) this makes a **non-blocking
outbound HTTPS request** per new IP - the verdict arrives a moment later,
so the connection is allowed through first and kicked from the callback
if it turns out to be a proxy. To keep this cheap and quota-friendly:

- A **positive verdict in block mode is also pushed into the
  pre-handshake blocklist** with a TTL. The *next* connection from that
  IP is then dropped at TCP-accept (silently, by default) before it costs
  a handshake - and it survives `+reload` / restart because the blocklist
  store is persisted. So a repeat proxy is only ever queried once.
- **Clean verdicts are cached** (`scripts/data/etc_proxydetect.tbl`) for
  `etc_proxydetect_cache_ttl_sec`, so a reconnecting legitimate user does
  not burn a query each time.
- A **daily query cap** (`etc_proxydetect_max_queries_per_day`, default
  1000) is a quota / cost safety valve: a flood of distinct IPs cannot
  run past your provider's free tier or a paid bill. Over the cap the
  lookup is skipped and the connection allowed.

Operators are exempt by default (`etc_proxydetect_check_levels`, mirrors
GeoIP) so a provider false positive cannot lock staff out.

### Providers

Pick **one** via `etc_proxydetect_provider`. Review its free-tier terms
before enabling on a public hub - the free tiers differ sharply:

| Provider | `provider` | Free tier | Commercial use on free tier | Auth |
|---|---|---|---|---|
| [proxycheck.io](https://proxycheck.io) | `proxycheck` | 1,000/day (100/day without a key) | Not explicitly granted - the terms neither permit nor forbid it. Treat as unconfirmed. | API key as query param (optional) |
| [VPNAPI.io](https://vpnapi.io) | `vpnapi` | 1,000/day | **No** - the free tier is "personal, non-commercial use" only. A public/community hub needs a paid plan. | API key (required) |
| [IPQualityScore](https://www.ipqualityscore.com) | `ipqs` | 1,000/**month** (35/day cap) | **Evaluation only** - free/trial use is for testing; production/commercial use needs a paid plan. | API key in the URL path (required) |

**Phase F1 ships the `proxycheck` adapter only**; `vpnapi` and `ipqs`
land in F2. Selecting an unimplemented provider leaves the plugin inert
(it logs a one-time note and never queries).

Facts above were verified 2026-07-06; provider limits and terms drift -
re-check the provider's own pricing / terms pages before relying on them.

### API key

Give the key to the hub **env-var-first** (Docker / systemd friendly) or
via cfg:

```sh
# preferred: the key never touches cfg.tbl and is never dumped by the API
export LUADCH_ETC_PROXYDETECT_API_KEY=your_key_here
```

```lua
-- or in cfg/cfg.tbl as a fallback:
etc_proxydetect_api_key = "your_key_here",
```

A key in `cfg.tbl` is redacted in `GET /v1/config`, but only once the
plugin is loaded - so prefer the env var, which the config API never
dumps. The key is never written to a log or the `+proxydetect` status.

### Enable it

In `cfg/cfg.tbl`, turn the plugin on in `cfg.scripts`:

```lua
{ "etc_proxydetect.lua", enabled = true },
```

then set the master toggle, provider, and (recommended) start in
`log_only` to verify before enforcing:

```lua
etc_proxydetect_enabled = true,
etc_proxydetect_provider = "proxycheck",
etc_proxydetect_action = "log_only",   -- switch to "block" once the logs look right
```

`+reload` (or restart). Watch op-chat / the audit log for
`proxydetect.block` entries, then flip `etc_proxydetect_action = "block"`.
Check state with `+proxydetect` (or `GET /v1/proxydetect`): it shows the
provider, action mode, blocked types, cached-verdict count, and queries
used today.

### Config reference

| Key | Default | Meaning |
|---|---|---|
| `etc_proxydetect_enabled` | `false` | master toggle (the plugin loads either way; the check is inert when false) |
| `etc_proxydetect_provider` | `"proxycheck"` | `proxycheck` \| `vpnapi` \| `ipqs` (only `proxycheck` implemented in F1) |
| `etc_proxydetect_api_key` | `""` | provider key; prefer the `LUADCH_ETC_PROXYDETECT_API_KEY` env var |
| `etc_proxydetect_action` | `"log_only"` | `log_only` audits + reports a match; `block` kicks + pre-handshake-blocks the IP |
| `etc_proxydetect_block_types` | `{proxy,vpn,tor}` | which detected types trigger a block (re-evaluated live on every cache hit) |
| `etc_proxydetect_check_levels` | ops exempt | which user levels are checked (map of level -> bool) |
| `etc_proxydetect_cache_ttl_sec` | `86400` | how long a verdict is cached and a positive IP stays pre-handshake-blocked |
| `etc_proxydetect_query_timeout_sec` | `5` | per-lookup HTTP timeout (1..30) |
| `etc_proxydetect_fail_open` | `true` | on provider error/timeout/quota: `true` = allow (safe), `false` = kick (strict) |
| `etc_proxydetect_stealth` | `true` | repeat connections dropped silently pre-handshake; the first detection still gets a visible kick |
| `etc_proxydetect_max_queries_per_day` | `1000` | daily provider-query cap (0 = unlimited) |
| `etc_proxydetect_kick_reason` | (text) | kick message (block mode only) |
| `etc_proxydetect_oplevel` | `80` | min level to run `+proxydetect` |

### Failure behaviour: fail-open vs fail-closed

By **default the plugin fails OPEN**: if the provider errors, times out,
or the daily cap is spent, the connection is **allowed in**. This is
deliberate - an external HTTP dependency in the connect path should not
lock every joining user out when the provider has an outage. A
`proxydetect.query.fail` audit fires so you can see it.

Set `etc_proxydetect_fail_open = false` to fail **closed** (kick on
provider error) only if you have 24/7 monitoring - a provider outage will
otherwise reject every new user.

### Design note: two decision points

A proxy IP can be blocked at **two** layers, and they compose:

- **Pre-handshake** (the blocklist accept-hook): an IP already flagged in
  a *prior* session is dropped at TCP-accept - no query, no handshake.
- **Post-handshake** (this plugin's `onConnect`): a *new* IP is queried
  live; the verdict kicks the user and feeds the pre-handshake layer for
  next time.

Because the verdict is asynchronous, the plugin re-resolves the user from
its session ID when the answer lands and verifies the CID still matches -
so a client that inherited a recycled SID is never kicked for the
departed proxy's verdict.

Changing `etc_proxydetect_block_types` takes effect immediately for
cached verdicts (the block decision is re-evaluated on every hit), but an
IP already pushed into the pre-handshake blocklist stays blocked until
its TTL expires (up to `etc_proxydetect_cache_ttl_sec`).
