# Bundled CA root certificates

`certs/cacert.pem` is a snapshot of [Mozilla's CA root certificate
bundle](https://wiki.mozilla.org/CA), extracted and packaged by
the [curl project](https://curl.se/docs/caextract.html) from the
[Firefox NSS root store](https://hg.mozilla.org/mozilla-central/file/tip/security/nss/lib/ckfw/builtins/certdata.txt).

The bundle is consumed by [`core/http_client.lua`](../core/http_client.lua)
to verify the certificate chain of any outbound HTTPS request the
hub makes (hublist announce, future external feed pulls, future
proxy/VPN detection API calls). It is NOT used by the listening
TLS port (`ssl_ports` / `ssl_ports_ipv6` use the operator's own
`certs/servercert.pem` + `certs/serverkey.pem`).

## Snapshot in this release

| Field | Value |
|---|---|
| Source URL | `https://curl.se/ca/cacert.pem` |
| Snapshot date | 2026-05-14 (see header lines inside the file) |
| File size | ~186 KB |
| CA count | 121 trusted roots |
| SHA-256 (of cacert.pem on disk) | `86a1f3366afac7c6f8ae9f3c779ac221129328c43f0ab2b8817eb2f362a5025c` (re-run `sha256sum certs/cacert.pem` after every refresh) |
| SHA-256 (of the certdata.txt source published by Mozilla, embedded in the file header) | `77130ef91213772844561fbd3aa31d413b25c2ac7f576fea3bc3bbff7ef93489` |

The two SHA-256s are different by design: the first is the hash of
the PEM file shipped in this repo (what `sha256sum` of the bundle
returns); the second is the upstream Mozilla certdata.txt source
hash, printed inside the bundle's `## SHA256:` header line. Verify
both before any refresh - the file hash gates "did we receive the
file we expected" and the certdata hash gates "did curl extract
from the certdata.txt revision we expected".

## License

The cacert.pem bundle is dual-licensed by the curl project under
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
curl -fsSL -o examples/certs/cacert.pem.new https://curl.se/ca/cacert.pem
curl -fsSL -o /tmp/cacert.pem.sha256        https://curl.se/ca/cacert.pem.sha256

# 2. Compare published checksum against the downloaded file
( cd /tmp && sha256sum -c cacert.pem.sha256 ) \
    && mv examples/certs/cacert.pem.new examples/certs/cacert.pem \
    || rm examples/certs/cacert.pem.new

# 3. Commit
git add examples/certs/cacert.pem docs/CACERT.md
git commit -m "chore(cacert): refresh Mozilla CA bundle to <date>"
```

Update the snapshot-date row in this file to match the new bundle's
header line.

### Verifying the running install

```sh
# Count CA blocks
grep -c "^-----BEGIN CERTIFICATE-----$" certs/cacert.pem
# Should be around 120-150

# Header date
head -5 certs/cacert.pem
```

## Why bundled vs system store

LuaSec (the OpenSSL binding) has no built-in default CA path. Three
alternatives, with the trade-offs we considered:

| Approach | Pro | Con | Verdict |
|---|---|---|---|
| Operator-supplied cafile (cfg key) | Operator chooses | Most ops leave it unset -> verify="none" silently OR the request fails with cryptic LuaSec error | Loses the security benefit by default |
| OS system CA store | No bundle to maintain | Path varies (Debian/RHEL/Alpine), absent on minimal Docker images, missing on Windows | Inconsistent UX across platforms |
| Bundle in repo | One known path everywhere, fail-closed if missing | We carry ~186 KB and own the refresh cadence | **Picked.** Consistent behaviour; refresh is a one-line cron / quarterly maintenance |

The fail-closed behaviour at [core/http_client.lua](../core/http_client.lua) -
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

Neither path requires touching `certs/cacert.pem` - the default
just becomes irrelevant for that call.

## Related

- [`core/http_client.lua`](../core/http_client.lua) - the consumer.
- [`docs/SECURITY.md`](SECURITY.md) §6 / outbound HTTPS - threat model.
- Precursor 0b of the unified-blocklist arc (`#78`) - PR introducing
  this bundle.
