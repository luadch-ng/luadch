# syntax=docker/dockerfile:1.7

# luadch container image. Pure-rootless: the image runs as a fixed
# unprivileged user (UID/GID 1000), and operators override at run time
# via Docker's built-in `--user` flag (no s6-overlay / gosu / PUID-PGID
# entrypoint magic). See docs/DOCKER.md for the deployment recipe.

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM alpine:3.20 AS build

RUN apk add --no-cache build-base cmake openssl-dev linux-headers

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
#   coreutils     busybox lacks `base32`, which we need for the
#                 SHA256 keyprint -> adcs:// URL form
RUN apk add --no-cache openssl ca-certificates tini libstdc++ coreutils

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
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD nc -z localhost 5000 || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
