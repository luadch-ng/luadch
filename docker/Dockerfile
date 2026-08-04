# syntax=docker/dockerfile:1.7

# luadch container image. Pure-rootless: the image runs as a fixed
# unprivileged user (UID/GID 1000), and operators override at run time
# via Docker's built-in `--user` flag (no s6-overlay / gosu / PUID-PGID
# entrypoint magic). See docs/DOCKER.md for the deployment recipe.

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM alpine:3.20 AS build

RUN apk add --no-cache build-base cmake openssl-dev zlib-dev linux-headers

WORKDIR /src
COPY . .
RUN cmake -B build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build -j"$(nproc)" \
 && cmake --install build

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM alpine:3.20

# Runtime deps only:
#   openssl       certs/make_cert.sh + keyprint computation
#   ca-certs      outbound TLS for any plugin that does HTTP (e.g. via
#                 luasec); the hub itself doesn't need them
#   tini          PID 1 with proper signal forwarding so SIGTERM from
#                 `docker stop` reaches the hub and triggers a clean
#                 shutdown (otherwise SIGTERM hits the entrypoint
#                 shell and the hub never sees it)
#   libstdc++     adclib.so (Tiger hash impl is C++) links against the
#                 GNU C++ runtime; alpine's musl base does not include
#                 it so we have to pull it in explicitly
#   zlib          dynamic dep of zlib_stream.so (Phase 8 S4b ADC-EXT
#                 ZLIF binding); only matters at runtime when
#                 cfg.zlif_enabled = true, but the shared object's
#                 dependency on libz.so.1 is resolved at hub start
#
# NOTE: GNU coreutils used to be pulled in for `base32` (the SHA-256
# keyprint -> adcs:// URL form). That moved into the hub in v3.1.6
# (cert_bootstrap.lua computes the keyprint via adclib base32), so the
# container no longer shells out to base32 and coreutils is dropped -
# every command the entrypoint uses (cp -rT, tail -F, cmp -s, ...) is
# provided by busybox. Dropping it also clears CVE-2016-2781.
RUN apk add --no-cache openssl zlib ca-certificates tini libstdc++

# Fixed image UID/GID. Operators who want their host bind-mount files
# owned by their own UID override this at run time with `--user $(id
# -u):$(id -g)` (or `user:` in compose) - the image stays the same.
RUN addgroup -g 1000 luadch \
 && adduser -D -u 1000 -G luadch -h /opt/luadch -s /sbin/nologin luadch

# Two copies of the install tree:
#   /opt/luadch  - runtime location (binary + libs + core); cfg/ scripts/
#                  certs/ log/ are bind-mount targets, populated from
#                  /defaults on first start by the entrypoint
#   /defaults    - read-only seed; chmod a+rX so the entrypoint can copy
#                  from it as any --user override
COPY --from=build --chown=luadch:luadch /src/build/install/luadch /opt/luadch
COPY --from=build /src/build/install/luadch /defaults
RUN chmod -R a+rX /defaults

# Container default points master.key outside the seeded cfg tree so the
# encrypted user.tbl backup (which lives in /opt/luadch/cfg) and the AES
# key (in /secrets) can be backed up on different schedules - matches
# the F-AUTH-1 threat model in docs/SECURITY.md.
#
# Patch BOTH /opt/luadch/cfg/cfg.tbl and /defaults/cfg/cfg.tbl: docker
# named volumes auto-populate from the image's mounted path (so
# /opt/luadch/cfg/cfg.tbl seeds the volume), while empty bind-mounts
# get seeded from /defaults by the entrypoint. Both paths must agree.
#
# Also create the /secrets mount point with luadch ownership so the
# hub can write master.key on first boot when no host volume is mounted.
RUN sed -i 's|^\(\s*\)master_key_path\s*=.*|\1master_key_path = "/secrets/master.key",|' \
        /opt/luadch/cfg/cfg.tbl /defaults/cfg/cfg.tbl \
 && mkdir -p /secrets \
 && chown luadch:luadch /secrets

COPY --chmod=0755 docker/entrypoint.sh /entrypoint.sh

USER luadch:luadch
WORKDIR /opt/luadch

EXPOSE 5000 5001

# `nc -z` is enough: the hub binds the listening port early in init,
# well before the smoke tests' START_TIMEOUT_SEC. We do NOT drive an
# ADC handshake here; that would pollute auth state and badpassword
# counters on every healthcheck tick.
#
# The probed port is LUADCH_HEALTHCHECK_PORT, defaulting to 5001 - the
# TLS listener the default cfg ships (ssl_ports = {5001}, tcp_ports
# empty). The old hardcoded 5000 never came up on a default install, so
# the container was permanently `unhealthy` (#567). Operators who run
# plain-only (tcp_ports = {5000}, ssl disabled) or a custom port set
# LUADCH_HEALTHCHECK_PORT to match in their compose `environment:` block.
# The HEALTHCHECK CMD runs via /bin/sh -c, so the var expands at check
# time and a runtime `-e` override takes effect without a rebuild.
ENV LUADCH_HEALTHCHECK_PORT=5001
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD nc -z localhost "${LUADCH_HEALTHCHECK_PORT:-5001}" || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
