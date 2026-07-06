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

The operator's configured refresh interval is **clamped up** to the
feed's minimum at runtime - polling faster than a provider allows gets
the hub's IP firewalled by that provider.

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

*Phase F (live proxy/VPN detection) will be added to this guide as it
lands ([#78](https://github.com/luadch-ng/luadch/issues/78)).*
