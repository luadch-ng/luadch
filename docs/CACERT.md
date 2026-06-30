# Bundled CA root certificates

`certs/ca-bundle.pem` is a snapshot of [Mozilla's CA root certificate
bundle](https://wiki.mozilla.org/CA), extracted and packaged by
the [curl project](https://curl.se/docs/caextract.html) from the
[Firefox NSS root store](https://hg.mozilla.org/mozilla-central/file/tip/security/nss/lib/ckfw/builtins/certdata.txt).

The bundle is consumed by [`core/http_client.lua`](../core/http_client.lua)
to verify the certificate chain of any outbound HTTPS request the
hub makes (hublist announce, future external feed pulls, future
proxy/VPN detection API calls). It is NOT used by the listening
TLS port (`ssl_ports` / `ssl_ports_ipv6` use the operator's own
`certs/servercert.pem` + `certs/serverkey.pem`, and the inbound
`ssl_params.cafile = certs/cacert.pem` is managed by
[`core/cert_bootstrap.lua`](../core/cert_bootstrap.lua) for the
mutual-TLS existence-check use case).

## Why `ca-bundle.pem` and not `cacert.pem`

`cacert.pem` is the conventional curl/openssl filename for a CA
bundle, but luadch ALREADY uses `certs/cacert.pem` for an inbound
role: [`core/cert_bootstrap.lua`](../core/cert_bootstrap.lua)
writes the self-signed TLS-listener cert to that path as a
satisfy-existence-check for `ssl_params.cafile` (LuaSec's
wrapserver demands the file even when mutual TLS is off).

Two different roles at one path is a latent bug:
- **Inbound** (`ssl_params.cafile`) wants a SINGLE cert (the hub's
  self-signed or operator-supplied root) used for mutual-TLS
  client-cert verify. `cert_bootstrap.lua` manages it.
- **Outbound** (`http_client.cafile`) wants a 186 KB bundle of
  ~120 trusted public CA roots used to verify remote-server certs
  on outbound HTTPS. `cacert_bootstrap.lua` (Precursor 0d) manages
  it.

The rename to `ca-bundle.pem` (Precursor 0d of the unified-blocklist
arc) splits the two paths cleanly.

## Snapshot in this release

| Field | Value |
|---|---|
| Source URL | `https://curl.se/ca/cacert.pem` |
| Snapshot date | 2026-05-14 (see header lines inside the file) |
| File size | ~186 KB |
| CA count | 121 trusted roots |
| SHA-256 (of ca-bundle.pem on disk) | `86a1f3366afac7c6f8ae9f3c779ac221129328c43f0ab2b8817eb2f362a5025c` (re-run `sha256sum certs/ca-bundle.pem` after every refresh) |
| SHA-256 (of the certdata.txt source published by Mozilla, embedded in the file header) | `77130ef91213772844561fbd3aa31d413b25c2ac7f576fea3bc3bbff7ef93489` |

The two SHA-256s are different by design: the first is the hash of
the PEM file shipped in this repo (what `sha256sum` of the bundle
returns); the second is the upstream Mozilla certdata.txt source
hash, printed inside the bundle's `## SHA256:` header line. Verify
both before any refresh - the file hash gates "did we receive the
file we expected" and the certdata hash gates "did curl extract
from the certdata.txt revision we expected".

## Bootstrap: first-boot + upgrade behaviour

On every hub start, [`core/cacert_bootstrap.lua`](../core/cacert_bootstrap.lua)
runs through this matrix:

| Runtime state | Hub action |
|---|---|
| `certs/ca-bundle.pem` missing | Copy from `lib/luadch/ca-bundle.pem` (immutable system path); log INFO |
| Bundle present + SHA-256 matches `lib/luadch/ca-bundle.pem` | No log, no action |
| Bundle present + SHA-256 mismatch + `ca_bundle_auto_update = false` (default) | Log WARN with both hashes; leave file in place. Operator decides if it is a custom bundle (corporate PKI) or an outdated snapshot |
| Bundle present + SHA-256 mismatch + `ca_bundle_auto_update = true` | Backup the existing file as `certs/ca-bundle.pem.bak-<timestamp>` and copy the bundled file; log INFO |

**For Docker operators with `./certs:` volume-mounted from the host:**
the bundled `lib/luadch/ca-bundle.pem` is shipped in the image at
an immutable path NOT overlaid by the volume mount. The bootstrap
copies from there into the host-mounted `certs/` directory on
first boot. Subsequent image pulls leave the host file alone
unless `ca_bundle_auto_update = true` is set.

**For bare-metal operators on `cmake --install`:** the CMake rule
installs `ca-bundle.pem` to BOTH `<install>/certs/` (operator-
overwriteable; this is the default `http_client.cafile`) and
`<install>/lib/luadch/` (immutable source-of-truth). The bootstrap
restores the operator-facing copy when missing.

**Migration from `cacert.pem`:** existing deployments that have a
`certs/cacert.pem` left over from an older luadch release (or from
`cert_bootstrap.lua`'s self-signed copy) are NOT touched. The
bundle is at a new path. If you maintained a custom Mozilla bundle
at the old name, copy it to `certs/ca-bundle.pem`.

## Cfg keys

| Key | Default | What |
|---|---|---|
| `ca_bundle_path` | `certs/ca-bundle.pem` | Runtime location, also the default `http_client.cafile` |
| `ca_bundle_source_path` | `lib/luadch/ca-bundle.pem` | Immutable system path, source-of-truth bundled with the install |
| `ca_bundle_auto_update` | `false` | If true, hub auto-replaces an out-of-date `ca_bundle_path` with the bundled version (backup file kept) |

## License

The bundle is dual-licensed by the curl project under
[MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/) (carrying Mozilla's
original license) or
[ISC](https://opensource.org/licenses/ISC). Both are GPL-3.0
compatible per the FSF's
[compatibility list](https://www.gnu.org/licenses/license-list.html).
The bundle itself is a collection of public CA certificates; the
licensing applies to the extraction tool's output format and the
Mozilla source data layout.

## Update recipe

CAs change over time - certificates expire, new ones are added, and
some get revoked. Refresh the bundle every 3-6 months (Mozilla
publishes a new NSS release roughly that often).

### One-time refresh (manual)

```sh
# 1. Download fresh snapshot + published checksum
curl -fsSL -o examples/certs/ca-bundle.pem.new https://curl.se/ca/cacert.pem
curl -fsSL -o /tmp/cacert.pem.sha256           https://curl.se/ca/cacert.pem.sha256

# 2. Compare published checksum against the downloaded file
( cd /tmp && sha256sum -c cacert.pem.sha256 ) \
    && mv examples/certs/ca-bundle.pem.new examples/certs/ca-bundle.pem \
    || rm examples/certs/ca-bundle.pem.new

# 3. Update the SHA rows in this file with the new on-disk + certdata hashes
sha256sum examples/certs/ca-bundle.pem
grep "^## SHA256:" examples/certs/ca-bundle.pem

# 4. Commit
git add examples/certs/ca-bundle.pem docs/CACERT.md
git commit -m "chore(cacert): refresh Mozilla CA bundle to <date>"
```

### Verifying the running install

```sh
# Count CA blocks
grep -c "^-----BEGIN CERTIFICATE-----$" certs/ca-bundle.pem
# Should be around 120-150

# Header date
head -5 certs/ca-bundle.pem

# Hash on disk
sha256sum certs/ca-bundle.pem
```

## Why bundled vs system store

LuaSec (the OpenSSL binding) has no built-in default CA path. Three
alternatives, with the trade-offs we considered:

| Approach | Pro | Con | Verdict |
|---|---|---|---|
| Operator-supplied cafile (cfg key) | Operator chooses | Most ops leave it unset -> verify="none" silently OR the request fails with cryptic LuaSec error | Loses the security benefit by default |
| OS system CA store | No bundle to maintain | Path varies (Debian/RHEL/Alpine), absent on minimal Docker images, missing on Windows | Inconsistent UX across platforms |
| Bundle in repo + bootstrap | One known path everywhere, fail-closed if missing, smooth upgrade UX | We carry ~186 KB and own the refresh cadence | **Picked.** Consistent behaviour; refresh is one-line / quarterly maintenance |

The fail-closed behaviour at [`core/http_client.lua`](../core/http_client.lua) -
refusing the request if cafile is missing rather than silently
falling back to verify="none" - is the load-bearing piece. An
out-of-the-box deployment authenticates outbound HTTPS or
explicitly does not.

## Opting out

Callers that need to talk to a self-signed endpoint pass
`verify = "none"` explicitly:

```lua
http_client.request {
    url     = "https://internal.example/api",
    verify  = "none",   -- intentional opt-out; explain WHY in the call site comment
    ...
}
```

Callers using their own CA pass a path:

```lua
http_client.request {
    url     = "https://corporate-pki.example/api",
    verify  = "peer",
    cafile  = "/etc/corporate-pki/ca-bundle.pem",
    ...
}
```

Neither path requires touching `certs/ca-bundle.pem` - the default
just becomes irrelevant for that call.

## Related

- [`core/http_client.lua`](../core/http_client.lua) - the consumer.
- [`core/cacert_bootstrap.lua`](../core/cacert_bootstrap.lua) - the bootstrap mechanism.
- [`core/sha256.lua`](../core/sha256.lua) - pure-Lua SHA-256 for the bootstrap's content check.
- [`docs/SECURITY.md`](SECURITY.md) §6 / outbound HTTPS - threat model.
- Precursor 0b + 0d of the unified-blocklist arc (`#78`).
