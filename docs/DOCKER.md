# Running luadch in Docker

The official image is built from this repo's [`docker/Dockerfile`](../docker/Dockerfile)
and published to GitHub Container Registry on every release tag and
master push:

| Tag pattern | Source |
|---|---|
| `ghcr.io/luadch-ng/luadch:vX.Y.Z` | exact release |
| `ghcr.io/luadch-ng/luadch:vX.Y`   | latest patch in `vX.Y` line |
| `ghcr.io/luadch-ng/luadch:vX`     | latest minor in `vX` line |
| `ghcr.io/luadch-ng/luadch:latest` | latest released `vX.Y.Z` |
| `ghcr.io/luadch-ng/luadch:master` | bleeding-edge (post-merge, pre-release) |

Available platforms: `linux/amd64`, `linux/arm64`.

## Security model

The image runs as the unprivileged user `luadch` (UID/GID 1000) -
**never as root**, no `s6-overlay`, no `gosu` drop-priv step. Operators
who want host bind-mount files owned by their own UID override at run
time with `--user $(id -u):$(id -g)` (or the `user:` key in compose).

The `/defaults` tree shipped in the image is world-readable so the
entrypoint can copy from it under any `--user` override.

## First-time setup

```sh
git clone https://github.com/luadch-ng/luadch.git
cd luadch
cp .env.example .env
# adjust PUID / PGID in .env if `id -u` on your host is not 1000

mkdir -p cfg scripts certs log secrets
docker compose up -d
```

On first start the container's entrypoint will:

1. **Seed empty mounts** from `/defaults`: `cfg/`, `scripts/`, `certs/`
   are populated from the bundled defaults if you mounted them empty.
2. **Generate a TLS cert** by running `certs/make_cert.sh` if no
   `servercert.pem` / `serverkey.pem` exists.
3. **Log the keyprint** so you can build the `adcs://` URL.

Pull the keyprint from the logs:

```sh
docker compose logs luadch | grep keyprint
# [entrypoint] TLS keyprint (SHA256, base32):  4OVZAB...
# [entrypoint] share with users as:  adcs://<your-host>:5001/?kp=SHA256/4OVZAB...
```

Replace `<your-host>` with the hostname / IP your users will connect
to. The `kp=SHA256/...` parameter is the trust anchor in the DC++
ecosystem - clients pin against it instead of validating a CA chain.

### First login

```
Nick:     dummy
Password: test
Address:  adc://127.0.0.1:5000      (plain)
          adcs://127.0.0.1:5001/?kp=SHA256/<as logged>
```

After login, register yourself, delete the bootstrap account, reload:

```
+reg <yournick> 100
+delreg dummy
+reload
```

See [`docs/CONFIGURATION.md`](CONFIGURATION.md) for the full first-run
walk-through.

## Mount layout

The compose file sets up six bind mounts:

| Host path | Container path | Purpose |
|---|---|---|
| `./cfg/`     | `/opt/luadch/cfg/`     | Hub settings (`cfg.tbl`), encrypted user database (`user.tbl`) |
| `./scripts/` | `/opt/luadch/scripts/` | Plugin scripts. Seeded with the bundled set; you can drop in custom plugins or override individual files. |
| `./certs/`   | `/opt/luadch/certs/`   | TLS server cert + key. Replace with your own to skip the auto-generated self-signed pair. |
| `./log/`     | `/opt/luadch/log/`     | Hub log files (`error.log`, `cmd.log`, ...). Also mirrored to `docker logs` via the entrypoint. |
| `./secrets/` | `/secrets/`            | AES master key for at-rest `user.tbl` encryption (cfg key `master_key_path`). Kept separate from `./cfg/` so backup tooling can split them. |

The `./secrets/` separation is the F-AUTH-1 threat-model recommendation
in [`docs/SECURITY.md`](SECURITY.md): the encrypted backup of `user.tbl`
should not live alongside the AES key that decrypts it.

## Configuration changes

Edit `cfg/cfg.tbl` on the host with your favourite editor. Then either:

```sh
docker compose restart luadch
```

or, in the hub itself (after logging in as a level-100 user):

```
+reload
```

`+reload` is faster (no TCP listener restart) and what you'll usually
want for non-network-port changes.

## TLS-only deployments

Once your users are on `adcs://` URLs, drop the plain port:

```yaml
ports:
  # - "5000:5000"   # commented out
  - "5001:5001"
```

Or restrict the plain port to localhost only (useful for `+!#` admin
tooling that can't speak TLS):

```yaml
ports:
  - "127.0.0.1:5000:5000"
  - "5001:5001"
```

## Updating

Pull the new image and recreate the container; mounts persist:

```sh
docker compose pull
docker compose up -d
```

For `vX.Y.Z` releases pin the tag in `docker-compose.yml` so you don't
get unexpected jumps:

```yaml
image: ghcr.io/luadch-ng/luadch:v3.1.3
```

## Troubleshooting

### Permission denied on bind mounts

Symptom: container exits with `cannot create '/opt/luadch/log/...':
Permission denied`.

Cause: host directory not owned by the runtime UID. The image runs as
1000:1000 by default; if your host user is 1001 the bind-mount
directories are 1001-owned and the container user can't write to them.

Fix:

```sh
# either set PUID/PGID to your host user
echo "PUID=$(id -u)"  >> .env
echo "PGID=$(id -g)" >> .env
docker compose up -d

# or chown the dirs to the container's default 1000
sudo chown -R 1000:1000 cfg scripts certs log secrets
```

### Lost the keyprint

The entrypoint logs the keyprint on every start; restart the container
to see it again:

```sh
docker compose restart luadch
docker compose logs luadch --tail 20 | grep keyprint
```

Or compute it directly from the cert on the host:

```sh
openssl x509 -in certs/servercert.pem -noout -fingerprint -sha256 \
  | sed 's/.*=//' | tr -d ':' | tr 'A-F' 'a-f' \
  | xxd -r -p | base32 | tr -d '='
```

### `docker logs` shows nothing after a while

The hub writes to `log/error.log` and `log/cmd.log` on disk; the
entrypoint forwards them via `tail -F`. If you `docker compose
restart`, you'll see the most recent lines plus everything written
afterwards. The on-disk log files persist independently in `./log/`.

### Self-signed cert rejected by my client

DC++ clients trust by **keyprint**, not by CA chain. If your client is
complaining about an unverified cert, check that the `adcs://` URL you
gave it actually includes the `?kp=SHA256/<hash>` suffix. Without it
the client falls back to PKI validation which a self-signed cert
won't pass.

If you already replaced the cert with one from a public CA, drop the
keyprint suffix from the URL.

## Building the image yourself

```sh
docker build -f docker/Dockerfile -t luadch:dev .
docker run --rm -d --name luadch-dev \
  --user $(id -u):$(id -g) \
  -p 5000:5000 -p 5001:5001 \
  -v "$(pwd)/dev/cfg:/opt/luadch/cfg" \
  -v "$(pwd)/dev/scripts:/opt/luadch/scripts" \
  -v "$(pwd)/dev/certs:/opt/luadch/certs" \
  -v "$(pwd)/dev/log:/opt/luadch/log" \
  -v "$(pwd)/dev/secrets:/secrets" \
  luadch:dev
```

For multi-arch test builds, set up `buildx` and target the platforms
your release would publish:

```sh
docker buildx create --use
docker buildx build --platform linux/amd64,linux/arm64 \
  -f docker/Dockerfile -t luadch:dev .
```
