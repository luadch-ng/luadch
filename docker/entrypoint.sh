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
# 1b. Auto-sync bundled top-level scripts/*.lua from /defaults
# ---------------------------------------------------------------------------
# After the initial seed, the operator's mounted scripts/ directory is
# stable - the seed path above only fires when it's empty. That means
# bug-fixes we ship in subsequent images never reach existing
# deployments unless the operator manually copies them.
#
# This block fixes that for the narrow case of TOP-LEVEL .lua files
# (the bundled plugin code). It does NOT touch:
#
#   scripts/data/*.tbl     - runtime state (bans, regs, plugin caches)
#   scripts/cfg/*.tbl      - per-plugin operator settings
#   scripts/<dir>/         - any other subdirectory
#
# scripts/lang/*.lang.* is handled separately in block 1c below
# (add-only, never overwrite).
#
# Operators who hand-patched a bundled .lua (rare, discouraged) can
# disable this with LUADCH_AUTOSYNC_SCRIPTS=0 in their .env. The
# recommended pattern for custom plugins is a NEW filename - those
# never collide with the bundle so the auto-sync leaves them alone.
#
# Idempotent: cmp -s skips files that are already byte-identical, so
# steady-state restarts are no-ops.
if [ "${LUADCH_AUTOSYNC_SCRIPTS:-1}" = "1" ]; then
    updated=0
    for f in "${DEFAULTS}"/scripts/*.lua; do
        [ -f "$f" ] || continue
        n=$(basename "$f")
        target="${LUADCH_HOME}/scripts/${n}"
        if [ ! -e "$target" ] || ! cmp -s "$f" "$target"; then
            cp "$f" "$target"
            log "auto-synced bundled script: ${n}"
            updated=$((updated + 1))
        fi
    done
    if [ "$updated" -gt 0 ]; then
        log "auto-synced ${updated} bundled scripts from /defaults"
    fi
fi

# ---------------------------------------------------------------------------
# 1c. Auto-add NEW bundled scripts/lang/*.lang.* from /defaults
# ---------------------------------------------------------------------------
# When a release ships a new plugin or adds i18n infrastructure to an
# existing one, the bundled .lua lands via 1b but the matching language
# files never reach the operator's mounted scripts/lang/ directory -
# the seed in block 1 only fires for an empty mount. The script then
# falls back to its hardcoded English defaults, silently for English
# operators but visibly broken for non-English ones.
#
# This block closes the gap with a STRICTLY ADD-ONLY copy: bundled
# .lang.* files that don't exist on the operator's mount are added,
# but existing files are NEVER overwritten. That preserves any
# operator-customized translations / MOTD strings - the same
# "operator's edits are sacred" rule the lang/ tree was carved out
# from 1b for.
#
# Same LUADCH_AUTOSYNC_SCRIPTS=0 escape hatch as 1b. Idempotent on
# steady-state restarts (target exists -> skipped).
if [ "${LUADCH_AUTOSYNC_SCRIPTS:-1}" = "1" ]; then
    added=0
    mkdir -p "${LUADCH_HOME}/scripts/lang"
    for f in "${DEFAULTS}"/scripts/lang/*.lang.*; do
        [ -f "$f" ] || continue
        n=$(basename "$f")
        target="${LUADCH_HOME}/scripts/lang/${n}"
        if [ ! -e "$target" ]; then
            cp "$f" "$target"
            log "auto-added new bundled lang file: ${n}"
            added=$((added + 1))
        fi
    done
    if [ "$added" -gt 0 ]; then
        log "auto-added ${added} new bundled lang files from /defaults"
    fi
fi

# ---------------------------------------------------------------------------
# 1d. Recover the core config files on a PARTIALLY-populated cfg/
# ---------------------------------------------------------------------------
# Block 1 only seeds cfg/ when it is ENTIRELY empty. But the hub writes
# operator-facing artifacts INTO cfg/ - e.g. cfg/geoip/ for the GeoIP
# database (#78 Phase D) and cfg/blocklist-export-*.jsonl (#78 Phase B) -
# so a cfg/ that has lost its cfg.tbl / user.tbl but still holds one of
# those stays non-empty, the full seed never re-fires, and the hub boots
# on the in-memory default cfg with no cfg.tbl on disk for the operator to
# edit (and no user.tbl, so no login).
#
# Close that gap: add cfg.tbl and user.tbl from /defaults when they are
# missing. STRICTLY ADD-ONLY - an existing file is never overwritten
# (operator edits are sacred), the same rule as the lang autosync in 1c.
for f in cfg.tbl user.tbl; do
    target="${LUADCH_HOME}/cfg/${f}"
    if [ ! -e "$target" ] && [ -f "${DEFAULTS}/cfg/${f}" ]; then
        cp "${DEFAULTS}/cfg/${f}" "$target"
        log "seeded missing ${f} from ${DEFAULTS}/cfg/"
    fi
done

# ---------------------------------------------------------------------------
# 2. Cert generation + keyprint (handled by the hub)
# ---------------------------------------------------------------------------
# As of v3.1.6, cert generation and keyprint logging are handled by
# core/cert_bootstrap.lua inside the hub itself (#77). It runs in the
# core-module init loop, BEFORE hub.init() binds the TLS listener, so
# missing certs are auto-generated as a P-256 ECDSA self-signed pair.
# The keyprint is written directly to stdout in the boot banner, so
# `docker compose logs` shows it without any entrypoint glue.
#
# Earlier image versions ran make_cert.sh + an openssl x509 keyprint
# pipeline here. Both are now redundant - we keep certs/make_cert.sh
# (and openssl) on disk for operators who want to manually rotate
# outside the hub process, but the entrypoint no longer touches them.

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
# 5. exec the hub (or forward one-shot args, e.g. --restore)
# ---------------------------------------------------------------------------
# WORKDIR is /opt/luadch (set in Dockerfile); the hub anchors its
# config / scripts / log paths to the binary's directory after Phase 6b
# (#12), so `cd` is correct here.
#
# "$@" forwards any args the operator passed to `docker compose run` /
# `docker run` straight to the binary. With none (the normal `up`) it
# expands to nothing, so a plain hub boot is unchanged; with e.g.
# `--restore <file>` it runs the offline restore (#480 PR-B) in a one-shot
# container against the same mounted volumes. The seed/log-forward setup
# above is harmless for a restore (on a fresh DR host it even provides the
# current bundled scripts/*.lua that the backup deliberately omits).
exec "${LUADCH_HOME}/luadch" "$@"
