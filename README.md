# Luadch - DC++ ADC Hub Server

[![License](https://img.shields.io/badge/license-GPLv3.0-blueviolet.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20ARM-orange.svg)](docs/BUILDING.md)
[![Lua](https://img.shields.io/badge/lua-5.4-blue.svg)](https://www.lua.org/)
[![Smoke](https://github.com/luadch-ng/luadch/actions/workflows/smoke.yml/badge.svg)](https://github.com/luadch-ng/luadch/actions/workflows/smoke.yml)
[![Docker](https://github.com/luadch-ng/luadch/actions/workflows/docker.yml/badge.svg)](https://github.com/luadch-ng/luadch/actions/workflows/docker.yml)
[![Release](https://img.shields.io/github/v/release/luadch-ng/luadch.svg)](https://github.com/luadch-ng/luadch/releases/latest)
[![GHCR](https://img.shields.io/badge/ghcr.io-amd64%20%7C%20arm64-blue?logo=docker)](https://github.com/luadch-ng/luadch/pkgs/container/luadch)

A modernised fork of [luadch](https://github.com/luadch/luadch) by
**blastbeat** and **pulsar**, hosted at [`luadch-ng`](https://github.com/luadch-ng).
Maintained by [Aybo](https://github.com/Aybook), with help from Claude.

## Original Features

- TLS 1.3 with AES-128 / AES-256 cipher suites
- Fast, small footprint (≈ 3 MB install size)
- ARM-compatible (Raspberry Pi, ARM servers, Apple Silicon Linux)
- Easy-to-use Lua scripting API for plugins
- Many bundled command and bot scripts
- Right-click menu support in modern clients (AirDC++)

## New Features

- **DoS hardening** ([#56](https://github.com/luadch-ng/luadch/issues/56)) - per-IP / per-user rate limits, TLS handshake deadline, failed-auth lockout
- **Per-userlevel rate-limit tiers** ([#80](https://github.com/luadch-ng/luadch/issues/80)) - independent buckets for chat / PM / INF / CTM-RCM / search, optional named tiers per user level (see [`docs/SCRIPTS.md`](docs/SCRIPTS.md#rate-limit-configuration))
- **Encrypted user database** ([#52](https://github.com/luadch-ng/luadch/issues/52)) - AES-256-GCM at-rest encryption of `cfg/user.tbl`
- **Sandboxed config / state loaders** ([#51](https://github.com/luadch-ng/luadch/issues/51)) - tampered `.tbl` files cannot achieve RCE
- **POSIX file-permission enforcement** on secret files
- **TLS-only default + auto-generated cert on first boot** ([#77](https://github.com/luadch-ng/luadch/issues/77) / [#113](https://github.com/luadch-ng/luadch/pull/113)) - fresh installs ship TLS-only on both IPv4 and IPv6, with a P-256 ECDSA cert generated automatically when none exists
- **Atomic plugin saves** ([#133](https://github.com/luadch-ng/luadch/issues/133)) - `util.savearray` / `util.savetable` use tmp + rename so a hub crash mid-write leaves the `.tbl` intact
- **Docker plugin + language autosync** ([#118](https://github.com/luadch-ng/luadch/pull/118)) - container restarts pull in new bundled scripts and lang files without overwriting operator customisations

See [`docs/SECURITY.md`](docs/SECURITY.md) for the full threat model
and operator guidance.

## Documentation

- **[docs/BUILDING.md](docs/BUILDING.md)** - build from source on
  Linux, Windows, or ARM
- **[docs/INSTALLING.md](docs/INSTALLING.md)** - deploy a built hub
  (file layout, permissions, systemd, backups, updates)
- **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** - configure the
  hub, register users, manage plugins, set up TLS
- **[docs/SCRIPTS.md](docs/SCRIPTS.md)** - every bundled plugin with
  its commands and cfg keys, plus the rate-limit configuration guide
- **[docs/SECURITY.md](docs/SECURITY.md)** - threat model, plugin
  trust contract, file-permission baseline, network-defense map,
  CVE-tracking process, how to report a security issue
- **[docs/DOCKER.md](docs/DOCKER.md)** - container image, mount layout,
  TLS-only deployments, troubleshooting
- [docs/Luadch_Lua_API.txt](docs/Luadch_Lua_API.txt) - plugin scripting
  API reference (upstream-style)

## Quick start

Pre-built binaries for Linux x86_64 and Windows x86_64 are attached to
each [release](https://github.com/luadch-ng/luadch/releases/latest) - extract
and run.

### Docker

```sh
git clone https://github.com/luadch-ng/luadch.git
cd luadch
cp .env.example .env   # adjust PUID / PGID if `id -u` is not 1000
mkdir -p cfg scripts certs log secrets
docker compose up -d
```

The image (`ghcr.io/luadch-ng/luadch:latest`, multi-arch
linux/amd64+arm64) runs **unprivileged** by default; the entrypoint
seeds empty mounts, generates a self-signed TLS cert, and logs the
keyprint for the `adcs://` URL. See [`docs/DOCKER.md`](docs/DOCKER.md)
for the full operator guide.

### From source

```sh
git clone https://github.com/luadch-ng/luadch.git
cd luadch
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
cmake --install build
cd build/install/luadch && ./luadch
```

Then connect with an ADC client (e.g. AirDC++) to `adc://127.0.0.1:5000`,
log in as `dummy` / `test`, and read [CONFIGURATION.md](docs/CONFIGURATION.md)
for first-run steps. Windows users: see the Windows section of
[BUILDING.md](docs/BUILDING.md).

## License

GPLv3.0 - see [LICENSE](LICENSE).

## Credits

All conceptual credit goes to **blastbeat** and **pulsar**, the original
authors of luadch. This fork only modernises and extends their excellent
foundation.
