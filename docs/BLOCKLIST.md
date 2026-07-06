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

*Phase E (external feeds: Tor / Spamhaus / AbuseIPDB) and Phase F
(live proxy/VPN detection) sections will be added to this guide as those
land ([#78](https://github.com/luadch-ng/luadch/issues/78)).*
