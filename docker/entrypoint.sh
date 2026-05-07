#!/bin/sh
# luadch container entrypoint.
#
# Responsibilities (in order):
#   1. Seed empty bind-mounts (cfg / scripts / certs) from /defaults so
#      a fresh `docker compose up` lands a working hub without the
#      operator having to pre-populate the host directories.
#   2. Generate a self-signed TLS cert if none exists.
#   3. Print the keyprint so the operator can build the
#      adcs://host:port/?kp=SHA256/<hash> URL their users connect with.
#   4. Forward log files to container stdout/stderr so `docker logs`
#      shows the hub's output.
#   5. exec the hub binary (PID 1 via tini, signals propagate).

set -eu

LUADCH_HOME="/opt/luadch"
DEFAULTS="/defaults"
SECRETS_DIR="/secrets"

log() { printf '[entrypoint] %s\n' "$*"; }

# ---------------------------------------------------------------------------
# 1. Seed empty bind-mounts from the defaults tree
# ---------------------------------------------------------------------------
# `cp -rT` copies the *contents* of src into dst (no extra src/ level).
# The "empty" check via `ls -A` short-circuits if the operator has
# already populated the mount; we never overwrite their files.
for d in cfg scripts certs; do
    target="${LUADCH_HOME}/${d}"
    if [ -z "$(ls -A "$target" 2>/dev/null || true)" ]; then
        log "seeding ${target} from ${DEFAULTS}/${d}/"
        cp -rT "${DEFAULTS}/${d}" "${target}"
    fi
done

# log/ is special: never seeded (no defaults), just ensured present.
mkdir -p "${LUADCH_HOME}/log"

# ---------------------------------------------------------------------------
# 2. Generate TLS cert if missing
# ---------------------------------------------------------------------------
# Cert generation is a one-off on first start; the cert lives in the
# bind-mounted certs/ dir and persists across container restarts. If
# the operator has supplied their own cert (e.g. behind a reverse proxy
# or for a known hostname), we leave it alone.
CERTS_DIR="${LUADCH_HOME}/certs"
if [ ! -f "${CERTS_DIR}/servercert.pem" ] || [ ! -f "${CERTS_DIR}/serverkey.pem" ]; then
    log "no TLS cert in ${CERTS_DIR}, generating self-signed pair"
    (
        cd "${CERTS_DIR}"
        sh ./make_cert.sh
    )
fi

# ---------------------------------------------------------------------------
# 3. Print keyprint
# ---------------------------------------------------------------------------
# DC++ trust model: the adcs:// URL embeds a SHA256 fingerprint of the
# server cert (`?kp=SHA256/<base32>`). We compute and log it on every
# start so the operator can grab it from `docker logs` without having
# to re-derive it manually.
if [ -f "${CERTS_DIR}/servercert.pem" ]; then
    KP_HEX=$(openssl x509 -in "${CERTS_DIR}/servercert.pem" -noout -fingerprint -sha256 \
             | sed -e 's/^.*Fingerprint=//' -e 's/://g' \
             | tr 'A-F' 'a-f')
    if [ -n "${KP_HEX}" ]; then
        # Convert hex digest -> base32 (no padding) for the kp= URL form.
        KP_B32=$(printf '%s' "${KP_HEX}" | xxd -r -p | base32 | tr -d '=')
        log "TLS keyprint (SHA256, base32):  ${KP_B32}"
        log "share with users as:  adcs://<your-host>:5001/?kp=SHA256/${KP_B32}"
    fi
fi

# ---------------------------------------------------------------------------
# 4. Forward log files to stdout/stderr
# ---------------------------------------------------------------------------
# The hub writes to log/error.log and log/cmd.log on disk. `docker logs`
# only sees PID-1's stdout/stderr, so we tail those files in the
# background and let their content surface via the container log
# stream. -F (capital) keeps following across log rotation; -n 0 starts
# at the file end so we don't replay history every restart.
mkdir -p "${LUADCH_HOME}/log"
touch "${LUADCH_HOME}/log/error.log" "${LUADCH_HOME}/log/cmd.log"
( tail -F -n 0 "${LUADCH_HOME}/log/error.log" 1>&2 & ) 2>/dev/null
( tail -F -n 0 "${LUADCH_HOME}/log/cmd.log"   1>&1 & ) 2>/dev/null

# ---------------------------------------------------------------------------
# 5. exec the hub
# ---------------------------------------------------------------------------
# WORKDIR is /opt/luadch (set in Dockerfile); the hub anchors its
# config / scripts / log paths to the binary's directory after Phase 6b
# (#12), so `cd` is correct here.
exec "${LUADCH_HOME}/luadch"
