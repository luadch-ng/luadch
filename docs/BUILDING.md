# Building luadch

luadch builds with CMake (≥ 3.20) on Linux, Windows (MinGW-w64), and
ARM (native or cross-compiled). The same three-step pipeline works on
every platform:

```
cmake -B build -DCMAKE_BUILD_TYPE=Release [platform options]
cmake --build build -j
cmake --install build
```

Output lands in `build/install/luadch/`. Run the hub from there.

---

## 🐧 Linux / BSD

### Prerequisites

```sh
# Debian / Ubuntu
sudo apt-get install -y build-essential cmake libssl-dev zlib1g-dev git

# Fedora / RHEL
sudo dnf install gcc gcc-c++ make cmake openssl-devel zlib-devel git

# FreeBSD / OpenBSD
pkg install cmake gcc git    # OpenSSL + zlib are in base
```

Required: gcc or clang (any version supporting C99 / C++17), CMake ≥ 3.20,
OpenSSL 3.x development headers, zlib development headers (used by the
Phase 8 S4b ADC-EXT ZLIF stream-compression binding;
`find_package(ZLIB REQUIRED)` is unconditional even when `zlif_enabled =
false` at runtime).

### Build & install

```sh
git clone https://github.com/luadch-ng/luadch.git
cd luadch
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
cmake --install build
```

### Run

```sh
cd build/install/luadch
./luadch              # plain ADC on port 5000
./certs/make_cert.sh  # once, for TLS on port 5001
```

---

## 🪟 Windows (MinGW-w64)

### Prerequisites

| Tool | Where | Notes |
|------|-------|-------|
| MinGW-w64 | https://winlibs.com/ | x86_64, POSIX threads, SEH, UCRT — extract so `C:\MinGW\bin\gcc.exe` exists |
| CMake ≥ 3.20 | https://cmake.org/download/ or `choco install cmake` | must be on PATH |
| OpenSSL 3.x | `C:\OpenSSL\` | see "OpenSSL on Windows" below |
| zlib 1.3+ | `C:\MinGW\include\zlib.h` + `C:\MinGW\lib\libz.a` | see "zlib on Windows" below |

For non-default install paths, point CMake at them at configure time, e.g.
`-DOPENSSL_ROOT_DIR=D:/path/to/openssl` or `-DZLIB_ROOT=D:/path/to/zlib`.
MinGW is picked up from `PATH` (make sure `gcc.exe` is reachable, or pass
`-DCMAKE_C_COMPILER=...`).

### OpenSSL on Windows

Cross-compile OpenSSL 3.x in WSL (or any Linux box). Easiest path:

```sh
sudo apt-get install -y mingw-w64
git clone --depth 1 --branch openssl-3.5 https://github.com/openssl/openssl.git
cd openssl
./Configure --cross-compile-prefix=x86_64-w64-mingw32- mingw64 \
            --prefix=$PWD/dist no-tests no-docs
make -j$(nproc) && make install_sw
```

Then copy from `dist/` to `C:\OpenSSL\` so that:

```
C:\OpenSSL\include\openssl\ssl.h
C:\OpenSSL\libssl-3-x64.dll
C:\OpenSSL\libcrypto-3-x64.dll
C:\OpenSSL\libssl.dll.a
C:\OpenSSL\libcrypto.dll.a
```

### zlib on Windows

Vanilla MinGW-w64 distributions do not ship zlib development files (only
the `zlib1.dll` runtime, embedded in projects like Git for Windows).
`find_package(ZLIB REQUIRED)` in our top-level CMakeLists therefore
needs a manual one-time install. Easiest path: build from upstream
source against the same MinGW you use for luadch.

```sh
# In any unix-y shell with the MinGW gcc on PATH:
curl -fsSL -o zlib-1.3.2.tar.gz https://www.zlib.net/zlib-1.3.2.tar.gz
# Optional but recommended: verify the SHA-256
# (bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16
#  at the time of writing; check https://www.zlib.net/ for the current
#  release / hash).
tar -xzf zlib-1.3.2.tar.gz
cd zlib-1.3.2
mingw32-make -f win32/Makefile.gcc \
    CC=C:/MinGW/bin/gcc.exe AR=C:/MinGW/bin/ar.exe
# The DLL build step needs gcc on PATH for windres - we only need the
# static lib (libz.a) and the headers, so a Makefile.gcc partial
# failure on the windres step is OK.
cp zlib.h zconf.h C:/MinGW/include/
cp libz.a            C:/MinGW/lib/
```

luadch's `zlib_stream.dll` then statically links `libz.a`, so the
runtime install tree does NOT need a separate `zlib1.dll`. Pass
`-DZLIB_ROOT=C:/MinGW` to CMake if zlib lives anywhere other than the
default search path.

### Build & install

In a PowerShell or `cmd` window with `C:\MinGW\bin` on `PATH`:

```cmd
cd D:\path\to\luadch
cmake -B build -G "MinGW Makefiles" -DOPENSSL_ROOT_DIR=C:/OpenSSL
cmake --build build -j
cmake --install build
```

### Run

```cmd
cd build\install\luadch
Luadch.exe                 :: plain ADC on port 5000
certs\make_cert.bat        :: once, for TLS on port 5001
```

The OpenSSL DLLs are bundled into the install tree automatically.

---

## 💪 ARM

### Native (Raspberry Pi, ARM server, …)

If you build *on* the ARM machine, follow the Linux section above —
nothing extra. Lua, adclib, and the rest are portable C/C++; CMake's
default toolchain detection picks up the system gcc.

### Cross-compile from x86_64 Linux to aarch64

Useful for CI or for producing a Pi binary on a desktop. Install the
cross-toolchain plus a cross-built OpenSSL, then point CMake at both.

```sh
# 1. Cross-toolchain
sudo apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

# 2. Cross-build OpenSSL (one-off; reuse afterwards)
git clone --depth 1 --branch openssl-3.5 https://github.com/openssl/openssl.git openssl-arm
cd openssl-arm
./Configure --cross-compile-prefix=aarch64-linux-gnu- linux-aarch64 \
            --prefix=$PWD/dist no-tests no-docs no-shared
make -j$(nproc) && make install_sw

# 3. Toolchain file (save anywhere; example path below)
cat > /tmp/aarch64.cmake <<'EOF'
set(CMAKE_SYSTEM_NAME      Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER       aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER     aarch64-linux-gnu-g++)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
EOF

# 4. Configure + build luadch for aarch64
cd /path/to/luadch
cmake -B build-arm \
    -DCMAKE_TOOLCHAIN_FILE=/tmp/aarch64.cmake \
    -DOPENSSL_ROOT_DIR=$PWD/../openssl-arm/dist \
    -DCMAKE_BUILD_TYPE=Release
cmake --build build-arm -j$(nproc)
cmake --install build-arm
```

The result in `build-arm/install/luadch/` runs on aarch64 (Pi 3+ /
Pi 4 / Pi 5 / Apple Silicon Linux / AWS Graviton, etc.). Verify with
`file build-arm/install/luadch/luadch` — should report `ARM aarch64`.

### Other ARM variants

- ARMv7 (32-bit Pi 1/2/Zero): use `gcc-arm-linux-gnueabihf` and
  `--cross-compile-prefix=arm-linux-gnueabihf-` in the OpenSSL build,
  point `CMAKE_C_COMPILER` at the same prefix.
- Apple Silicon Linux: native build per the Linux section.

---

## First-time login

Whichever platform you built on:

```
Nick:     dummy
Password: test
Address:  adc://127.0.0.1:5000     (plain)
          adcs://127.0.0.1:5001    (TLS, after the cert script)
```

After login: `+reg <yournick> 100`, `+delreg dummy`, `+reload`. The dummy
default account is hubowner — **delete it as soon as you have your own**.

---

## Single instance per install

The hub refuses to start a second time from the **same install
directory**: the launcher holds an exclusive lock on `luadch.lock` in
that directory for its whole lifetime. A second `./luadch` /
`Luadch.exe` against the same tree exits non-zero with `another instance
is already running in this directory` (also written to
`log/exception.txt`). This stops two hubs racing on the shared
`cfg/user.tbl`, `master.key`, `scripts/data/*.tbl` and logs.

- Running **several hubs on one machine** is fully supported - give each
  its own install directory; each gets its own lock and they never
  collide.
- The lock is released by the OS when the process exits or crashes, so
  there is **no stale lock file to clean up** after a crash.
- `+reload` keeps the lock (it re-runs in place, it is not a new
  process).
- If you script a restart, let the old process finish exiting before
  starting the new one: during the old hub's shutdown drain the lock is
  still held and the replacement is refused. `systemd` and
  `docker restart` do this sequentially and are unaffected.

---

## Concurrent connections (file-descriptor limit)

On Linux/BSD the hub's event loop uses `poll()`, so there is no fixed
software cap on how many clients can be connected at once
([#310](https://github.com/luadch-ng/luadch/issues/310)). The practical
ceiling is the process **open-file-descriptor limit** (each connection is
one socket, plus a handful for listeners, HBRI and the HTTP API). The
launcher raises the soft limit to the hard limit at boot, and the boot
line in `log/event.log` reports the resulting ceiling:

```
hub.lua: event loop backend: poll (socket ceiling ~= 1024 open files; raise via ulimit -n / systemd LimitNOFILE / Docker --ulimit)
```

To go higher than the hard limit (needed only for very large hubs), raise
it at the OS level - the hub then picks up the higher hard limit on the
next start:

- **bare metal / shell:** `ulimit -Hn 65535` (as root) before launching,
  or set `nofile` in `/etc/security/limits.conf`.
- **systemd:** `LimitNOFILE=65535` in the service unit's `[Service]`
  section.
- **Docker:** `--ulimit nofile=65535:65535` (or the `ulimits:` key in a
  compose file).

Windows uses the `select()` backend, capped at `FD_SETSIZE = 1024`
sockets (raised from the Winsock default of 64 in
[#416](https://github.com/luadch-ng/luadch/issues/416)); the boot line
there reports `select() capacity (FD_SETSIZE): 1024 sockets`.

---

## File permissions for secrets

`cfg/user.tbl` (registered users with their cleartext passwords - see
[F-AUTH-1](https://github.com/luadch-ng/luadch/issues/52) for the
ADC-protocol-mandated reason) and `certs/serverkey.pem` (TLS private
key) hold material that must not be world-readable.

### 🐧 Linux / BSD

The hub `chmod 600`s `user.tbl` automatically after every write
(`+reg`, `+delreg`, `+setpass`, etc.) and the `make_cert.sh` script
`chmod 600`s the generated private keys. **No manual step needed**
on a fresh install.

If you have an existing deployment from before this hardening, run
once:

```sh
chmod 600 cfg/user.tbl certs/serverkey.pem certs/cakey.pem
```

### 🪟 Windows

NTFS does not have POSIX permission bits, so the hub does not attempt
to enforce permissions automatically. Run once after install to
restrict the secret files to your user account only:

```cmd
icacls "cfg\user.tbl"           /inheritance:r /grant:r "%USERNAME%:F"
icacls "certs\serverkey.pem"    /inheritance:r /grant:r "%USERNAME%:F"
icacls "certs\cakey.pem"        /inheritance:r /grant:r "%USERNAME%:F"
```

If the hub runs as `LocalService` / a dedicated service user, replace
`%USERNAME%` with that account name. After you regenerate certificates
or migrate `user.tbl` to a new install, repeat the `icacls` command.

---

## Known cosmetic build warnings

The Linux build emits 5 deprecation warnings from the bundled `luasec/` C
sources against system OpenSSL 3.x (`EC_KEY_*`, `PEM_read_bio_DHparams`,
`SSL_CTX_set_tmp_dh_callback`, `EC_KEY_free`, `DH_free`). These are
cosmetic — the functions still work in current OpenSSL. The negotiated
TLS session is modern (TLS 1.3 + AES-256-GCM verified). Tracked in
[issue #3](https://github.com/luadch-ng/luadch/issues/3) as
`upstream-blocked` / `wontfix`.

The Windows build (gcc 16+) emits 2 stylistic `-Wparentheses` warnings
from the third-party Tiger hash code in `adclib/tiger.cpp`. Same category.
