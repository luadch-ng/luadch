# Backup and restore

Encrypted, self-contained hub backups (`etc_backup` plugin + `core/backup*`,
[#480](https://github.com/luadch-ng/luadch/issues/480)) and an offline restore
(`Luadch --restore`). The hub is a **producer only**: it writes encrypted
`.ldbk` artifacts to a local directory. Copying them off-site (rclone, restic,
a cron job, a mounted volume) is the operator's job - see
[Off-site copies](#off-site-copies).

- [What a backup contains](#what-a-backup-contains)
- [Enabling backups](#enabling-backups)
- [Schedule](#schedule)
- [The passphrase](#the-passphrase)
- [master.key](#masterkey)
- [Integrity sidecar](#integrity-sidecar)
- [Off-site copies](#off-site-copies)
- [Restore](#restore)
- [Disaster-recovery runbook](#disaster-recovery-runbook)
- [Docker](#docker)
- [Security model](#security-model)

---

## What a backup contains

One backup is the **restore-minimum set** - everything a fresh hub needs to
come back as the old one:

- `cfg/cfg.tbl` (settings), `cfg/user.tbl` + `cfg/user.tbl.bak` (accounts)
- the TLS material named by `ssl_params` (`serverkey.pem`, `servercert.pem`,
  `cacert.pem`)
- every `scripts/data/*.tbl` and `scripts/cfg/*.tbl` (plugin state)
- `master.key` (the at-rest encryption key), unless you opt out - see below

Half-written `*.tmp` files are skipped. Everything is packed into one tar,
sealed with **AES-256-GCM** (key = PBKDF2-HMAC-SHA256 of your passphrase), and
written as `cfg/backups/luadch-backup-YYYYMMDD-HHMMSS.ldbk` plus a
`.ldbk.sha256` sidecar. The artifact is 0600 on POSIX.

The hub is single-threaded and takes the snapshot synchronously, so a backup is
consistent by construction - no file is being written while it runs.

## Enabling backups

`scripts/etc_backup.lua` ships enabled by default, but stays **inert until a
passphrase is set** (it nags the hub owner until then). To turn it on:

1. Set a passphrase (see [The passphrase](#the-passphrase)).
2. Confirm the plugin is whitelisted in `cfg.scripts` (the default `cfg.tbl`
   already lists `{ "etc_backup.lua", enabled = true }`).
3. `+reload`.

Config keys (`core/cfg_defaults.lua`, all `etc_backup_*`):

| Key | Default | Meaning |
|---|---|---|
| `etc_backup_enabled` | `true` | master on/off for the engine |
| `etc_backup_dir` | `"cfg/backups"` | where artifacts land (may be absolute / a mount) |
| `etc_backup_keep` | `7` | retention: prune oldest beyond N |
| `etc_backup_daily_at` | `"04:00"` | server-local HH:MM daily run |
| `etc_backup_interval_hours` | `0` | fallback cadence when `daily_at` is empty |
| `etc_backup_include_master_key` | `true` | pack `master.key` into the backup |
| `etc_backup_passphrase` | `""` | seal passphrase (prefer the env var) |
| `etc_backup_oplevel` | `80` | level for `+backup` |
| `etc_backup_notify_level` | `100` | level that gets the readiness nag |

Operator commands (level `etc_backup_oplevel`):

- `+backup now` - run a backup immediately
- `+backup list` - list artifacts in the backup dir
- `+backup status` - schedule + readiness summary

## Schedule

Two mutually exclusive modes, both persisted across `+reload` (a reload never
re-triggers or skips a run):

- **Daily at a fixed time** (default): `etc_backup_daily_at = "04:00"`,
  server-local. Pick a quiet hour.
- **Every N hours**: clear `etc_backup_daily_at` (`""`) and set
  `etc_backup_interval_hours = 6` (or 2 / 4 / 12).

## The passphrase

The passphrase protects the backup independently of `master.key`, so a backup
stays recoverable even if the hub host and its key are lost together. There is
**no passphrase-recovery path** - store it in a password manager. Two sources,
env var first (`core/secrets`):

- **Environment** (recommended, Docker-friendly):
  `LUADCH_ETC_BACKUP_PASSPHRASE`
- **cfg.tbl** (bare-metal): `etc_backup_passphrase = "..."`. This is fine - the
  encrypted backup does not depend on cfg.tbl secrecy; the passphrase only ever
  seals/opens the artifact.

The restore side reads a **separate** env var, `LUADCH_BACKUP_PASSPHRASE` (there
is no cfg to read on a fresh host); see [Restore](#restore).

## master.key

`master.key` is the AES key for `user.tbl` at-rest encryption
([SECURITY.md](SECURITY.md)). By default it is packed **into** the backup, so a
single artifact + the passphrase is enough to fully restore. That is convenient
but means the passphrase is the only thing standing between an attacker and
`user.tbl`. To decouple them, set `etc_backup_include_master_key = false`: the
backup then omits `master.key`, and a restore leaves you to supply your own
(`--master-key-path`, or drop it at `master_key_path`). Without the right
`master.key`, `user.tbl` cannot be decrypted after restore.

`master.key` may live outside the install tree (`master_key_path` in cfg.tbl,
e.g. `/etc/luadch/master.key`). The real path travels in the backup manifest.
On restore, an in-tree location (the `cfg/master.key` default) is put back
automatically; an **out-of-tree absolute path is only used when you pass
`--master-key-path`** - restore will not write `master.key` to an absolute
location on the manifest's say-so alone (so a backup from an untrusted source
cannot steer an arbitrary write). Restoring your own out-of-tree setup is one
flag: `--master-key-path /etc/luadch/master.key`.

## Integrity sidecar

Every artifact gets a `.ldbk.sha256` sidecar in standard `sha256sum` format, so
you can check an artifact on any host without the passphrase:

```sh
cd cfg/backups && sha256sum -c luadch-backup-YYYYMMDD-HHMMSS.ldbk.sha256
```

`--restore` verifies the sidecar automatically before spending the KDF.

## Off-site copies

The hub does not push anywhere. Copy `cfg/backups/` off the box on your own
schedule. Examples:

```sh
# rclone to any remote (S3, B2, WebDAV, SFTP, ...)
rclone sync /opt/luadch/cfg/backups remote:luadch-backups

# restic (dedup + its own encryption on top)
restic -r s3:s3.example.com/luadch backup /opt/luadch/cfg/backups

# plain scp in cron
0 5 * * * scp -q /opt/luadch/cfg/backups/*.ldbk* backup@host:/srv/luadch/
```

The `.ldbk` is already encrypted, so an untrusted remote is acceptable; restic's
extra layer is optional defense-in-depth.

## Restore

Offline, one-shot, on a hub that is **not running** (the restore refuses to run
while a hub holds the install's single-instance lock, so it can never race live
`cfg`/`user.tbl`/`master.key` writes):

```sh
cd /opt/luadch          # the install root (where the binary lives)
export LUADCH_BACKUP_PASSPHRASE='your-backup-passphrase'
./luadch --restore cfg/backups/luadch-backup-20260721-040000.ldbk
```

Flags:

| Flag | Effect |
|---|---|
| `--restore <file>` | restore this artifact, then exit |
| `--verify` | dry run: check + decrypt + list the plan, write nothing |
| `--force` | overwrite files that already exist |
| `--master-key-path <p>` | place `master.key` at `<p>` instead of its recorded path |

Restore is two-phase and transactional per file: it verifies the sidecar,
decrypts + authenticates (AES-256-GCM), parses the manifest, **rejects any
unsafe path** (absolute or `..` - a foreign archive cannot escape the tree),
checks for conflicts, then writes each file via a temp + atomic rename. Every
restored file lands owner-only (0600). Into a populated tree it refuses unless
you pass `--force`; `--verify` is exempt (it only reports). A wrong passphrase
fails cleanly and writes nothing.

Always dry-run first:

```sh
./luadch --restore <file> --verify
```

## Disaster-recovery runbook

Rebuild a dead hub on a fresh host:

1. Install luadch the normal way ([INSTALLING.md](INSTALLING.md)) - do **not**
   run it yet, or first-boot writes a fresh cfg/certs you would overwrite.
2. Copy the chosen `.ldbk` (and its `.sha256`) onto the host.
3. From the install root:
   ```sh
   export LUADCH_BACKUP_PASSPHRASE='...'
   ./luadch --restore /path/to/luadch-backup-....ldbk --verify   # inspect
   ./luadch --restore /path/to/luadch-backup-....ldbk            # apply
   ```
   On a fresh install nothing exists yet, so `--force` is not needed.
4. If the backup **excluded** `master.key`, put your own copy in place now
   (`--master-key-path`, or at `master_key_path`), else `user.tbl` will not
   decrypt.
5. Start the hub. Log in and confirm accounts/settings.

## Docker

- Mount the backup dir out of the container so artifacts survive it:
  `-v ./cfg/backups:/luadch/cfg/backups` (or point `etc_backup_dir` at a
  dedicated volume).
- Set the passphrase via env: `-e LUADCH_ETC_BACKUP_PASSPHRASE=...`.
- Container clocks are usually UTC - `etc_backup_daily_at` is server-local, so
  pick the hour in UTC.
- To restore, run the one-shot in a container over the target tree with the hub
  stopped:
  ```sh
  docker compose run --rm -e LUADCH_BACKUP_PASSPHRASE=... \
    luadch --restore cfg/backups/luadch-backup-....ldbk
  ```
  See [DOCKER.md](DOCKER.md) for the `master_key_path`-on-`secrets/`-mount
  layout.

## Security model

- The backup is only as strong as its passphrase (PBKDF2-HMAC-SHA256 ->
  AES-256-GCM). No recovery path; use a password manager.
- The engine reads its **own** policy (dir / keep / passphrase / master.key
  inclusion) from cfg + `core/secrets`, never from a caller, so a sandboxed
  plugin can trigger a backup only to the operator-configured destination - it
  cannot redirect the artifact or choose the key.
- Restore holds the single-instance lock, sanitizes every archive path against
  `..`/absolute escapes, and authenticates the ciphertext before writing.
- With `include_master_key = true`, treat the artifact like `master.key`
  itself: the passphrase is then the only barrier to `user.tbl`. Set it to
  `false` to keep the two secrets separate.
