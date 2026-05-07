# Luadch - DC++ ADC Hub Server

[![License](https://img.shields.io/badge/license-GPLv3.0-blueviolet.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20ARM-orange.svg)](docs/BUILDING.md)
[![Lua](https://img.shields.io/badge/lua-5.4-blue.svg)](https://www.lua.org/)
[![Smoke](https://github.com/luadch-ng/luadch/actions/workflows/smoke.yml/badge.svg)](https://github.com/luadch-ng/luadch/actions/workflows/smoke.yml)
[![Release](https://img.shields.io/github/v/release/luadch-ng/luadch.svg)](https://github.com/luadch-ng/luadch/releases/latest)

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
- **Encrypted user database** ([#52](https://github.com/luadch-ng/luadch/issues/52)) - AES-256-GCM at-rest encryption of `cfg/user.tbl`
- **Sandboxed config / state loaders** ([#51](https://github.com/luadch-ng/luadch/issues/51)) - tampered `.tbl` files cannot achieve RCE
- **POSIX file-permission enforcement** on secret files

See [`docs/SECURITY.md`](docs/SECURITY.md) for the full threat model
and operator guidance.

## What's different in this fork

- Lua **5.1** (EOL since 2012) **→ 5.4.8**
- Unmaintained `slnunicode` C module replaced by a 40-line pure-Lua shim
  on top of Lua 5.4's builtin `utf8` library - same API, no C maintenance
- Build system rewritten to **CMake**: one pipeline for Linux / Windows /
  ARM (`cmake -B build && cmake --build build && cmake --install build`)
- The `*.c.not` source-rename hack on the Windows build is gone
- `core/cfg.lua` (3688 lines) and `core/hub.lua` (2245 lines)
  decomposed into focused modules under a 1500-line ceiling (Phase 6)
- Comprehensive security audit (Phase 7) - 24 findings filed,
  22 fixed; see [`docs/SECURITY.md`](docs/SECURITY.md) and
  [`docs/phases/PHASE_7_FINDINGS.md`](docs/phases/PHASE_7_FINDINGS.md)
- Password salts now drawn from OpenSSL CSPRNG (`RAND_bytes`)
  instead of `math.random` reseeded with `os.time()`
- CI smoke harness with 10 protocol-level tests (handshake, login,
  +cmd routing, rate-limit, encryption-at-rest) on every push and
  PR, both Linux and Windows
- Several pre-existing bugs fixed:
  - `os.difftime` 1-arg pattern (silently tolerated by 5.1, errors in 5.4)
  - `cmd_hubinfo.lua` crash on missing certificate file
  - `wmic` calls replaced with `Get-CimInstance` (Windows 11 24H2+ removed wmic)
  - `+!#` server commands from PMs now reach the command pipeline again
  - `make_cert.sh` no longer collides with bash's read-only `UID` builtin
- Repo hygiene: `.gitattributes` for line endings, reproducible Windows
  build via env vars, no more `register` C++17 warnings, dropped 1366
  lines of unmaintained C

Detail per phase in [docs/phases/](docs/phases/).

## Documentation

- **[docs/BUILDING.md](docs/BUILDING.md)** - build from source on
  Linux, Windows, or ARM
- **[docs/INSTALLING.md](docs/INSTALLING.md)** - deploy a built hub
  (file layout, permissions, systemd, backups, updates)
- **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** - configure the
  hub, register users, manage plugins, set up TLS
- **[docs/SECURITY.md](docs/SECURITY.md)** - threat model, plugin
  trust contract, file-permission baseline, network-defense map,
  CVE-tracking process, how to report a security issue
- **[docs/DOCKER.md](docs/DOCKER.md)** - container image, mount layout,
  TLS-only deployments, troubleshooting
- [docs/Luadch_Lua_API.txt](docs/Luadch_Lua_API.txt) - plugin scripting
  API reference (upstream-style)
- [docs/Luadch_Manual.pdf](docs/Luadch_Manual.pdf) - original upstream
  manual (predates this fork)

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
