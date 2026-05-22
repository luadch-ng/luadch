# HTTP API design

Local HTTP listener for hub state and admin actions. Plugin-extensible
read/write API, designed as the substrate for a future WebUI.

**Status:** design draft (closes #82 once implemented). Implementation
phased - see [§13 Implementation phases](#13-implementation-phases).
This document is the authoritative spec; it is updated in lockstep
with the implementation PRs.

---

## 1. Goals + non-goals

**Goals.**

- Read + write API over HTTP for hub state and operator commands.
- **Plugin-extensible** - bundled and third-party plugins register
  their own endpoints via a hub-side API. Core only ships the router
  + a handful of hub-intrinsic endpoints; everything else is plugin-
  owned. If a plugin is not loaded, its endpoints return
  `404 E_NOT_CONFIGURED`.
- Designed to underpin a future WebUI (live monitoring + plugin
  management) - discoverable, versioned, machine-readable error shape.
- Inherits the Phase-8 S3 hardened HTTP framer (`core/iostream.lua:
  newhttpstage`) for transport robustness.

**Non-goals.**

- HTTPS termination on the API port. The listener is local-only
  (bind details in §2); operators put a reverse proxy in front for
  non-loopback access.
- Public-facing API. The threat model is "operator + their tools on
  the same host or behind their reverse proxy" - not anonymous
  internet traffic.
- Event streams (WebSocket, SSE). May be added in a future phase; not
  in v3.2.0.
- Service discovery beyond `GET /v1/endpoints` (no consul / mDNS).

---

## 2. Transport

| Property | Value |
|---|---|
| Protocol | HTTP/1.1 (HTTP/1.0 accepted, downgraded to no-keep-alive) |
| Bind | `127.0.0.1` only - **hard-coded**, no cfg knob |
| Port | cfg `http_port` (default `false` = off). Distinct from ADC ports |
| TLS | Never. Use a reverse proxy if remote access is needed |
| Connection | One request per connection (`Connection: close`) - rationale in `core/iostream.lua` framer comment |
| Server header | Never emitted (no version fingerprint pre-auth) |
| Content-Type response | `application/json; charset=utf-8` (envelope); except `/health` which returns `text/plain` for LB compatibility |
| Content-Type request | `application/json; charset=utf-8` for endpoints with a body; rejected with `415` otherwise |

The framer is `core/iostream.lua:newhttpstage`, extended for phase 1
of this API to permit a `Content-Length`-bounded body. S3 ships
GET/HEAD-only with hard body-reject; the extension is not a knob
flip - see §2.1.

Caps in the framer:

- Request-line: 8192 bytes
- Single header line: 8192 bytes
- Total headers (incl. request-line): 16384 bytes
- Header count: 100
- Request target: 2048 bytes
- Body: `MAXBODY = 65536` bytes (writes are operator-shaped, not
  bulk-upload; cap is generous but bounded)
- `Transfer-Encoding`: rejected outright (smuggling defence)
- Multiple `Content-Length`: rejected (smuggling defence)
- OWS before header colon: rejected (smuggling defence)

### 2.1 Framer body extension (phase 1 substrate change)

The current S3 framer is a single-shot stage (`done = true` after
the header parse; subsequent `push` returns `nil` and discards
trailing bytes - `core/iostream.lua:469-481`). Phase 1 adds a new
post-header state for collecting body bytes, plus a richer emit
shape. The state machine becomes:

```
[parsing-headers]  ── headers complete, CL == 0 or absent ─►  emit{method, target, version, headers, body=""}; done
                ╲
                 ╲── headers complete, CL > 0, CL <= MAXBODY ─►  [collecting-body]
                ╲
                 ╲── headers complete, CL > MAXBODY ─►  emit{reject = 413}; done
                ╲
                 ╲── any smuggling-defence trigger (TE, multi-CL, ...) ─►  emit{reject = 400}; done

[collecting-body]  ── enough bytes received ─►  emit{method, target, version, headers, body=<CL bytes>}; done
                ╲
                 ╲── socket EOF before CL bytes ─►  emit{reject = 400}; done
                ╲
                 ╲── per-push limit / overflow guard tripped ─►  emit{reject = 413}; done

[done]  any further push  ─►  returns nil, false  (trailing bytes discarded)
```

Concrete contracts:

- **Rejection ordering is preserved:** smuggling defences (TE,
  multi-CL, OWS-before-colon, malformed CL value) ALL fire during
  the header-complete branch BEFORE the body-state transition.
- **413 fires on the CL value, not on byte count.** If a client
  sends `Content-Length: 1000000`, the framer emits `413` and
  closes WITHOUT reading any body bytes. Prevents per-request
  memory amplification.
- **The router gets the 413 (and 400) reject units the same way it
  gets parsed-request units today** - via the existing
  `{reject = <status>}` shape. No new router-side code path for
  rejection.
- **`body` field on success is a Lua string of EXACTLY
  `Content-Length` bytes** (or `""` for no-body requests). The
  router JSON-parses it; the framer is content-agnostic.
- **HEAD requests:** body MUST be absent (per RFC). If a HEAD
  arrives with `Content-Length > 0`, framer emits `400`.
- **Connection close mid-body:** when the underlying socket closes
  before `Content-Length` bytes have been collected, the framer
  stays in `[collecting-body]` with no emitted unit. server.lua's
  read loop tears down the handler on EOF, the framer state is
  GC'd. **No response is sent** - the client crashed first, a
  partial-write would have nowhere to land. Matches RFC 7230 §3.4
  (implicit recovery). The stage has no close-hook today; if a
  future use-case demands an explicit 400 on mid-body EOF, add a
  `flush_on_close()` method to the stage contract then.

Unit-test coverage required for phase-1 framer extension:

- POST with `Content-Length: 0` and no body → success unit, empty body
- POST with `Content-Length: N` and exactly N body bytes → success
- POST with `Content-Length: N` arriving in 1, 2, N TCP segments → success
- POST with `Content-Length: MAXBODY` (exact boundary) → success
- POST with `Content-Length: MAXBODY+1` → 413, no body read
- POST with `Transfer-Encoding: chunked` → 400 (smuggling defence)
- POST with `Content-Length: 0\r\nContent-Length: 5\r\n` → 400 (multi-CL)
- POST with lowercase method (`post`) → 400 (request-line regex anchors `^(%u+)`)
- POST with NUL bytes in body → success, body byte-exact
- POST with body containing `\r\n\r\n` → success, body byte-exact (must not mis-parse as header end)
- GET with `Content-Length: 5` → 400 (no GET endpoint accepts a body)
- HEAD with `Content-Length: 5` → 400
- HEAD with `Content-Length: 0` → success (HEAD)

---

## 3. Architecture

```
                    /v1/...
client  ─►  iostream.newhttpstage  ─►  core/http.lua router  ─┬─►  core handler
   ▲           (framer + caps)              │                 │
   │                                        │                 └─►  plugin handler
   │                                        │                       (registered via hub.http_register)
   └────────  envelope response  ◄──────────┘
                  + audit log
                  + rate-limit decision
```

`core/http.lua` owns:

- Request dispatch (method + path → registered handler)
- Auth check (token resolve → scope check)
- Rate-limit decision (per-token bucket)
- Idempotency-key cache (per-token TTL map)
- Audit log emission (every write goes to `api_audit.log`)
- Envelope formatting (success + error)
- JSON encode/decode (via bundled `dkjson`)
- Discovery endpoint `GET /v1/endpoints`

Plugins (and core itself for the few hub-intrinsic endpoints) register
handlers via the [Plugin Registration API](#5-plugin-registration-api).
Handlers receive a parsed request struct and return a result struct;
the core router does everything else.

---

## 4. Auth model

Token-based bearer auth with two scopes: `read` and `admin`.

### 4.1 cfg shape

```lua
http_api_tokens = {
    ["dashboard-readonly-7f3..."] = { scope = "read",  comment = "grafana scraper" },
    ["operator-3kd2..."]          = { scope = "admin", comment = "ops cli" },
}
```

- Map key = token (opaque string, operator-generated). Any non-empty
  string works syntactically; recommended ≥32 bytes from
  `/dev/urandom` base64-encoded for adequate entropy.
- `scope`: required, exactly one of `"read"` or `"admin"`. Any other
  value rejects the entry at startup with a logged error and the
  token does not become active.
- `comment`: optional, free-form; surfaced in `api_audit.log` for
  attribution.
- Empty table or missing key = API is reachable but answers `401`
  for everything except `/health`. The first-boot bootstrap (§4.7)
  ensures a freshly-installed hub still has a usable admin token.

### 4.2 Token lifecycle

- Read at hub startup (`loadsettings`).
- Re-read on `+reload` (operator changed cfg, intent is to pick up
  the change). Tokens that were removed in cfg invalidate immediately;
  tokens that were added become active. Tokens with no change persist.
- **Tokens never rotate without explicit operator action.** External
  apps only need to update their token when the operator rotates it.

### 4.3 Token transport

- Header `Authorization: Bearer <token>` (RFC 6750).
- No query-string fallback (tokens in URLs leak into proxy logs).
- Constant-time comparison required: Lua's `==` on strings short-
  circuits at first mismatch byte, leaking length and prefix-match
  timing. Phase 1 ships a small `adclib.constant_time_eq( a, b )`
  in C (XOR-accumulate over equal-length strings, single branch on
  final accumulator). Interim Lua fallback while the C function is
  in review: same algorithm in pure Lua with `bit32.bxor` /
  `string.byte` (timing-leak-free at the Lua level; the JIT may
  still optimize, but our hub uses plain Lua 5.4 interpreter, not
  LuaJIT, so the constant-time property holds).

### 4.4 Scope semantics

| Scope | Can | Cannot |
|---|---|---|
| `none` | Reached without a bearer token; the route is part of the route table and listed by `/v1/endpoints`. Only used for `/health` today. | n/a (no auth gate) |
| `read` | GET endpoints + `GET /v1/endpoints` filtered to {`none`, `read`} routes | Any non-GET; admin-scoped GETs (none planned but reserved) |
| `admin` | Everything `read` + all writes (POST/PUT/PATCH/DELETE) + admin-scoped GETs | n/a |

The dispatcher checks scope BEFORE invoking the handler. A scope
mismatch returns `403 E_FORBIDDEN`. Auth itself is skipped for
`scope = "none"` routes; the route still goes through the regular
route-lookup + 405 + OPTIONS machinery.

### 4.5 `/health`

Unversioned, registered with `scope = "none"` (unauthenticated),
public on the loopback port. Returns `200 text/plain "ok\n"`.
Purpose: load-balancer / supervisor health probe (cfg-management
ops should not have to ship a token to systemd or similar). Carries
no hub state. Listed in `/v1/endpoints` like every other registered
route; the implementation routes it through the regular dispatch
pipeline (the `scope = "none"` flag is what makes it
unauthenticated, not a special case in the router).

### 4.6 `X-Confirm: yes` for destructive endpoints

A small handful of endpoints have outsized blast radius if hit
accidentally (shell history misfire, IDE autocompletion of a wrong
URL). Those require the client to set the header

```
X-Confirm: yes
```

in addition to the bearer token. Missing or wrong value returns
`400 E_CONFIRMATION_REQUIRED`. A WebUI sets the header automatically
when the operator clicks the confirm dialog; a CLI tool spells it
out (the muscle-memory step the guardrail is meant to add).

Endpoints with `X-Confirm: yes` required:

- `POST /v1/reload`
- `POST /v1/restart`
- `POST /v1/shutdown`
- `DELETE /v1/registered/{nick}`

Not required for `DELETE /v1/users/{sid}` (kick) or other write
endpoints - those are common, low-impact, and the audit log is
sufficient.

### 4.7 First-boot token bootstrap

If `http_port` is set but `http_api_tokens` is empty or absent at
startup, the hub generates one `admin`-scoped token, writes it to
`cfg/api_token.first` (chmod 600, owner-only), and prominently logs
the path to `error.log`:

```
hub.lua: http_api_tokens empty - generated initial admin token at cfg/api_token.first. Copy the value into cfg.tbl http_api_tokens and delete the file.
```

(Logged via `out.error` with the standard `hub.lua: ...` prefix
matching neighbouring `out_error` lines in `core/hub.lua`.)

The operator copies the value into `cfg.tbl`, runs `+reload`, then
deletes the bootstrap file. Pattern mirrors `master_key_path` from
Phase 7. Avoids the "how do I get the first token" chicken-and-egg.

**In-memory activation.** The bootstrap token is ALSO injected into
the runtime cfg cache via `cfg.set(..., nosave = true)`, so the API
is usable on the very first session - the operator does not have to
edit `cfg.tbl` + `+reload` before the first call works. The
file-copy step is required only for persistence across hub restarts;
absent it, the bootstrap regenerates a fresh token on the next
startup (the on-disk `cfg/api_token.first` is overwritten and any
previously-issued bootstrap token becomes invalid).

**Ordering:** the bootstrap file is written BEFORE the HTTP
listener binds `http_port`. If the file write fails (EACCES,
filesystem full) the hub aborts the HTTP-listener bring-up with a
logged error - it does NOT proceed to bind without a usable token
(the operator would have an open port and no way to access it).
ADC listeners are unaffected; the hub continues to serve ADC.

### 4.8 Failed-auth rate-limit

The per-token rate-limit (§6.3) only attributes to known tokens. A
brute-forcer hitting random tokens gets `401` but no token-bucket
attribution. To bound that traffic without locking out the WebUI
that happens to share the loopback IP with a misbehaving client:

- **Per-prefix failed-auth bucket.** When an
  `Authorization: Bearer <X>` header is present and resolves to no
  known token, the per-prefix bucket is consumed. The bucket is
  keyed on the first 4 chars of `<X>` (length-leak limited; not the
  full token because we don't want to log it). Default 10
  failed-auths / minute / prefix, burst 5. Cfg keys
  `http_api_authfail_prefix_rate` / `_burst`. Bucket exhaustion
  returns `429 E_RATE_LIMITED` with `Retry-After: 60`.
  Anonymous probes (no `Authorization` header) and malformed headers
  do NOT consume the prefix bucket - they fall straight into 401.
- **Per-connection counter is moot under the current transport.**
  The spec originally called for a per-TCP-connection counter
  (`MAX_FAILED_AUTHS_PER_CONN = 3`) as the first line of defence.
  The HTTP listener currently issues `Connection: close` on every
  response (one HTTP request per TCP connection), which makes the
  per-connection counter equivalent to a 1-strike rule before TCP
  teardown. The per-prefix bucket already carries the abuse-
  defence load on its own; the per-connection counter would only
  add value if we ever introduced HTTP keep-alive, at which point
  it can be revisited.
- **Reverse-proxy-aware:** if the listener is reached via a reverse
  proxy (operator deployment), the proxy SHOULD set
  `X-Forwarded-For`. Loopback proxy → use `X-Forwarded-For` value
  to augment the prefix bucket. Without trusted X-F-F, accounting
  stays at the prefix level. The reverse-proxy X-F-F augmentation
  is not implemented in Phase 1c (no proxy in the loopback-only
  default deployment); it is reserved for the Phase 2+ WebUI work.
- Loopback hits are NOT exempt: the prefix bucket fires even when
  the connecting peer is `127.0.0.1`.

---

## 5. Plugin registration API

Plugins register endpoints by calling a hub-provided global from
inside an `onStart` listener.

```lua
hub.http_register( method, path, scope, handler, meta )
```

### 5.1 Arguments

| Arg | Type | Meaning |
|---|---|---|
| `method` | string | `"GET"` / `"POST"` / `"PUT"` / `"PATCH"` / `"DELETE"` |
| `path` | string | URL path including version prefix, e.g. `"/v1/bans"`. Path variables in `{name}` form, e.g. `"/v1/bans/{id}"` |
| `scope` | string | `"read"` or `"admin"` |
| `handler` | function | `function(req) -> result` (see §6 + §7) |
| `meta` | table or nil | Optional metadata - `{description=, request_schema=, response_schema=}`. Surfaced via `/v1/endpoints`. Used by WebUI for form rendering |

### 5.2 Registration lifecycle

- Plugin calls `hub.http_register` from inside its `onStart` listener.
- `+reload` clears the entire route table BEFORE re-running plugin
  init. Plugins re-register their routes on the new `onStart` cycle.
- Conflict (two plugins claim the same method + path) raises an error
  at registration time and the second plugin's `onStart` returns
  false. Operator sees a startup error in `error.log`; hub continues
  with the first registration.
- Registration is single-shot per plugin per route; idempotent re-
  registration in the same `onStart` (same method + path + handler)
  is a no-op.

### 5.3 Naming convention

- Bundled plugins use the unprefixed `/v1/<resource>` form, e.g.
  `cmd_ban` → `/v1/bans`.
- Third-party plugins SHOULD use `/v1/x/<plugin-id>/...` to avoid
  clashing with future bundled plugins. The router does not enforce
  this - it is convention.

### 5.4 Handler contract

```lua
local handler = function( req )
    -- req = parsed request struct (§6)
    -- return either a success result or an error result (§7)
    return { status = 200, data = { ... } }
    -- or:  return { status = 400, error = { code = "E_BAD_INPUT", message = "..." } }
end
```

The handler MUST be pure-Lua; it MUST NOT block on I/O (the hub's
event loop is single-threaded). It SHOULD return an error result
table for expected error cases (clearer trace, machine-readable code)
rather than raising. The router wraps every handler call in `pcall`
as a defence-in-depth - an uncaught error becomes
`500 E_INTERNAL` and is logged to `error.log` with the traceback.
A handler that uses errors for control flow works but is harder to
debug.

### 5.5 Router-side schema validation (optional)

`meta.request_schema` may declare a minimal type + required spec.
The router validates the parsed `req.body` against it BEFORE the
handler is invoked. Failure returns `400 E_BAD_INPUT` with a
`message` naming the offending field. Reduces boilerplate in every
handler.

```lua
hub.http_register( "POST", "/v1/bans", "admin", ban_handler, {
    description = "create a ban",
    request_schema = {
        target_type      = { type = "string", required = true, enum = { "nick", "cid", "ip" } },
        target           = { type = "string", required = true, max_length = 64 },
        duration_minutes = { type = "integer", required = false, min = 1, max = 525600 },
        reason           = { type = "string", required = false, max_length = 256 },
    },
    response_schema = {
        id = { type = "string", required = true },
    },
} )
```

Supported field-spec keys: `type` (`"string"` / `"integer"` /
`"number"` / `"boolean"` / `"object"` / `"array"`), `required`,
`enum`, `min` / `max` (numbers), `min_length` / `max_length`
(strings), `pattern` (Lua pattern - NOT PCRE; `%d` is digit, `.`
matches any char, no `\d` / `\w`; WebUI builders MUST be told this).

For `type = "array"` and `"object"` the router validates ONLY the
top-level shape (is-array vs is-object, is-present). Nested item
or property validation is the handler's job. Rationale: phase 1
endpoints (see catalog §10) all have flat request bodies; a full
recursive validator is bloat we don't pay for until a real
nested-body endpoint shows up. The schema mini-spec is
intentionally constrained.

If a future endpoint genuinely needs nested validation, options:
(a) extend the mini-spec with `items` + `properties` (~20 LoC), or
(b) keep flat schemas and have the handler validate the nested
shape inline. Decide at that endpoint's design time, not pre-
emptively here.

Handlers MAY skip the schema and validate inside themselves; that
is fine when the validation is dynamic (e.g. depends on a runtime
table). For static shapes the schema is the canonical and shorter
way.

**`response_schema` is documentation only.** It surfaces via
`GET /v1/endpoints` so the WebUI can pre-build forms / table
columns, but the router does NOT validate the handler's actual
response against it. The handler is trusted to keep them in sync;
diverging schema vs response is a bug to find in code review, not
at runtime.

---

## 6. Request shape

The router parses the framer's parsed-request unit into a `req`
struct passed to the handler:

```lua
req = {
    method      = "POST",                      -- uppercase
    path        = "/v1/bans",                  -- with version prefix
    path_vars   = { id = "abc" },              -- {} if no {name} segments
    query       = { lines = "100" },           -- query-string parsed; values are RAW URL-encoded strings
                                               -- (the router does NOT %-decode; handlers do so per-endpoint)
    headers     = { ["content-type"] = "..." },-- lowercased keys
    body        = { reason = "spam" },         -- nil for no-body methods or empty body;
                                               -- parsed JSON object for endpoints with a body
    raw_body    = "{ \"reason\": \"spam\" }",  -- original string, for handlers that want it
    token_label = "ops cli (operato…3kd2)",    -- non-secret label for logs:
                                               -- "comment (first4…last4)". Handlers MUST
                                               -- log this, never the cfg key itself.
    token_scope = "admin",
    source_ip   = "127.0.0.1",                 -- for audit log
    idempotency_key = nil,                     -- string if client sent X-Idempotency-Key
    request_id  = "01HKE7...",                 -- client-sent X-Request-ID, or auto-generated UUIDv4
    confirm     = false,                       -- true iff client sent X-Confirm: yes
}
```

### 6.1 JSON parsing

- Body is parsed with `dkjson` once by the router; failure returns
  `400 E_BAD_JSON` to the client and the handler is not invoked.
- Top-level MUST be a JSON object (not array, not bare value). Arrays
  go in fields of the object.

### 6.2 Idempotency-key

- Header `X-Idempotency-Key: <opaque-string>` (recommended UUID).
- Per-token cache mapping `(token_label, key) → (status, body, headers)` with a
  5-minute TTL.
- Cache hit ⇒ router returns the cached response immediately, handler
  is not invoked, **audit log NOT re-emitted** (the original write
  was already logged; an idempotent retry must not double-log).
  The current request's `X-Request-ID` is overlaid on the replay
  so the client can correlate its log line with this turn rather
  than the original.
- Cache miss ⇒ handler runs, the response is stored before being
  returned, audit log emits once.
- Applies only to write methods (POST/PUT/PATCH/DELETE). GET / HEAD
  responses are not cached. Errors (4xx/5xx) ARE cached: a retry of
  a deterministically-failing request gets the same response, not
  a re-execution that might race differently.
- **Bounded size.** Cfg `http_api_idempotency_max_entries`
  (default 1024). When the cap is hit, oldest entry by insertion
  time is evicted (FIFO, not LRU - keeps the data structure
  trivial; the cache is bounded by both 5-min TTL and entry-count,
  so eviction strategy precision matters little).
- **Cache is cleared on `+reload`.** The route table clear (§5.2)
  invalidates the handler closures the cached responses were
  produced by - keeping the cache across reload could surface a
  response whose code path no longer exists. A write retry that
  spans a `+reload` may therefore double-execute; that is the
  intended trade-off (operator-initiated reloads are rare, retries
  spanning one are rarer, double-execution is recoverable while
  a stale cache hit is silent and confusing).

### 6.3 Rate-limit

- Token-bucket per `token_label`. Defaults: `read` scope 120/min,
  `admin` scope 60/min, burst 10 (shared across scopes). Cfg-
  tunable per scope (`http_api_rate_read`, `http_api_rate_admin`)
  and burst (`http_api_burst`). Read default is doubled because
  the WebUI polls.
- Exceeded ⇒ `429 E_RATE_LIMITED` with `Retry-After: <seconds>` header.
- Buckets share `core/ratelimit.lua` infrastructure with the ADC
  side. Per-token buckets are keyed on the resolved token *label*
  (non-secret comment + first4...last4); the full token never
  enters the bucket map, so the rate-limit state cannot leak
  secrets even if dumped.
- The failed-auth bucket (§4.8) is checked BEFORE the token bucket:
  an attacker grinding tokens hits the failed-auth defences first.
- `/health` is NOT rate-limited (probes are noisy by design;
  scope=none routes bypass auth and therefore have no token to
  attribute the bucket to).
- **Scope=none routes (`/health`) bypass rate-limit** entirely as a
  consequence of bypassing auth. **X-Confirm endpoints
  (`/v1/reload`, `/v1/restart`, `/v1/shutdown`,
  `DELETE /v1/registered/{nick}`) are exempt** from the per-token
  bucket budget (§4.6): an operator's recovery action must succeed
  even if a runaway script just burned the admin token's budget.
  The X-Confirm header is the abuse-protection guard for these
  endpoints (forces human intent); the audit log is the forensic
  trail.
- **403 / X-Confirm-missing responses do not consume bucket
  budget.** The rate-limit gate runs after the scope check + the
  X-Confirm carve-out lookup, so a token that lacks scope (403) or
  fails the X-Confirm check (400) does not pay the bucket cost.

### 6.4 Pagination

`GET /v1/users` and `GET /v1/registered` may return large lists and
support pagination:

```
GET /v1/users?limit=100&offset=0
```

- `limit` default 200, max 1000. Values outside the range are
  clamped (not rejected) - clients that ask for `limit=999999` get
  1000, which is friendlier than 400.
- `offset` default 0.
- Response carries a `pagination` sibling of `data`:

```json
{
  "ok": true,
  "data": { "users": [...] },
  "pagination": { "total": 4231, "limit": 100, "offset": 0, "next_offset": 100 }
}
```

- `next_offset` is `null` when the page is the last one.

Filtering and sorting (`?q=`, `?level=`, `?sort=connect_time:desc`)
are NOT in phase 1. The query-param convention is reserved; future
phases will add validation per-endpoint.

**Tail-style endpoints (logs, chatlog) use `?lines=N` instead of
limit/offset.** Different shape because they return a contiguous
window from the end of the resource, not paginated random-access
through it. Cap `max_lines = 1000`; clamping rules follow §6.4.

### 6.5 X-Request-ID

- If the client sends `X-Request-ID: <opaque>`, the router echoes it
  in the response header and in the audit log.
- If the client does NOT send one, the router generates a UUIDv4 and
  echoes it back. The client can then correlate its log line with
  the audit log entry without having to invent IDs.

### 6.6 OPTIONS + HEAD auto-support

- For any registered `GET` route, `HEAD` automatically works -
  responds with the same headers as `GET` and an empty body. Status
  is the would-be GET status. Handlers do NOT receive HEAD; the
  router runs the GET handler, serializes the JSON envelope to
  measure its length, sets `Content-Length` to that exact value,
  then discards the body before writing. This is the RFC-conformant
  answer; the cost (a discarded serialization) is acceptable for
  the very rare HEAD on an admin API.
  - **GET handler side-effect contract.** Because HEAD invokes the
    same handler as GET, GET handlers MUST be idempotent / side-
    effect-free. A counter increment or a state mutation inside a
    GET handler would fire on HEAD probes too. Plugin authors:
    write changes in POST/PUT/PATCH/DELETE handlers only.
- `OPTIONS <path>` on a registered path returns the allowed methods
  for that path in the `Allow` header. Body is empty, status 204.
  No auth required (this is introspection, not data). HEAD is
  implicitly listed alongside any registered GET; OPTIONS itself
  is always listed. OPTIONS on an UNKNOWN path falls into the
  normal unknown-path handling (401 anonymous, 404 authed).
- Method mismatch (path registered for POST but client sends GET)
  returns `405 E_METHOD_NOT_ALLOWED` with `Allow: POST` header.
  Distinct from `404 E_NOT_FOUND` which means "path not registered
  at all". Anonymous callers do NOT see 405 - they get 401 first
  (no path-existence leak to unauthenticated callers).

---

## 7. Response shape

All responses except `/health` use a JSON envelope.

### 7.1 Success

```json
{
  "ok": true,
  "data": { ... }
}
```

HTTP status carries the high-level outcome (200 / 201 / 204) and the
`data` field carries the payload. For 204 No Content, `data` is `null`
and the body may be empty.

### 7.2 Error

```json
{
  "ok": false,
  "error": {
    "code":    "E_NOT_FOUND",
    "message": "user with sid 'ABCD' not found"
  }
}
```

HTTP status mirrors the broad error class (400 / 401 / 403 / 404 /
409 / 429 / 500); the `error.code` is the precise machine-readable
discriminator. WebUI / clients pattern-match on `code`, surface
`message` to humans.

### 7.3 Reserved error codes

| Code | HTTP | Meaning |
|---|---|---|
| `E_BAD_JSON` | 400 | Body is not valid JSON or not an object |
| `E_BAD_INPUT` | 400 | Body parsed but a field is missing / wrong type / fails schema |
| `E_CONFIRMATION_REQUIRED` | 400 | Endpoint requires `X-Confirm: yes` header (§4.6) |
| `E_UNAUTHENTICATED` | 401 | No / bad bearer token |
| `E_FORBIDDEN` | 403 | Token scope insufficient for endpoint |
| `E_NOT_FOUND` | 404 | Resource does not exist (e.g. sid not online) |
| `E_NOT_CONFIGURED` | 404 | Endpoint path exists in spec but plugin is not loaded |
| `E_METHOD_NOT_ALLOWED` | 405 | Method not implemented for path; `Allow` header lists what is |
| `E_CONFLICT` | 409 | State conflict (e.g. user already banned) |
| `E_PAYLOAD_TOO_LARGE` | 413 | Body exceeds `MAXBODY` (64 KiB) |
| `E_UNSUPPORTED_MEDIA_TYPE` | 415 | Request body present but Content-Type is not JSON |
| `E_RATE_LIMITED` | 429 | Token bucket or failed-auth bucket empty; check `Retry-After` |
| `E_INTERNAL` | 500 | Handler raised; details in `error.log` only |

Plugins MAY define their own error codes following the `E_*` prefix
convention. They SHOULD document them in their `meta.response_schema`.

---

### 7.4 Timestamp + ID conventions

- **Timestamps**: ISO 8601 UTC, second precision, trailing `Z`:
  `"2026-05-21T19:32:11Z"`. Never epoch seconds. Generated via
  Lua `os.date("!%Y-%m-%dT%H:%M:%SZ", t)`.
- **Durations**: integer seconds in field name `_seconds` (e.g.
  `uptime_seconds`, `connect_time_seconds_ago`) or integer minutes
  in `_minutes` for human-input-sized things (ban duration).
  Never both for the same concept.
- **IDs**: opaque strings unless explicitly noted. SIDs are 4-char
  Base32 (ADC native). Ban IDs are server-assigned UUIDv4. User
  nicks are the natural primary key for the registered-users
  resource.

### 7.5 CORS - explicitly not handled

The hub does NOT emit CORS headers. The listener is loopback-only;
non-loopback access goes through a reverse proxy where the operator
handles CORS (and TLS, and IP allowlisting, and request logging) at
that layer. If a future WebUI is hosted on a separate origin from
the API, that origin's reverse proxy adds the `Access-Control-Allow-
Origin` headers - not the hub.

Same-origin WebUI (served by the hub on the same port - future
phase, not now) would not need CORS at all.

---

## 8. Audit log

Dedicated `api_audit.log` in the standard log path, written through
the existing `out.createlog` infrastructure for consistency with
`event.log` / `error.log` / `script.log`:

```lua
-- in core/out.lua's return table:
api_audit = createlog( "api_audit", "api_audit.log", "log_api_audit" )
```

New cfg key `log_api_audit` (default `true`) gates the stream;
operators can disable via cfg + reload. One line per non-GET request:

```
[2026-05-22 | 14:32:11] POST /v1/bans 200 token=operator-3k...kd2 (ops cli) src=127.0.0.1 idem=- body={"target_type":"nick","target":"baduser","duration_minutes":60}
```

- Token field shows first + last 4 chars (full token never in logs).
- `comment` field from cfg appears in parens.
- Body is JSON-serialised, max 512 bytes (truncated with `…` if
  longer), control-bytes replaced with `?` (consistent with
  `core/http.lua:logsafe`).
- Failure responses are logged with the resolved HTTP status.

GET requests are NOT logged in `api_audit.log` (would be noisy under
WebUI polling). They can be enabled by cfg flag
`http_api_log_reads = true` for forensic sessions.

---

## 9. Discovery endpoint

`GET /v1/endpoints` (scope `read`) returns the live route registry,
scope-filtered to what the calling token can reach:

```json
{
  "ok": true,
  "data": {
    "endpoints": [
      {
        "method": "GET",
        "path": "/v1/users",
        "scope": "read",
        "plugin": "core",
        "description": "list online users",
        "request_schema": null,
        "response_schema": { "type": "object", "properties": { "users": { "type": "array" } } }
      },
      {
        "method": "POST",
        "path": "/v1/bans",
        "scope": "admin",
        "plugin": "cmd_ban",
        "description": "create a ban",
        "request_schema": { "type": "object", "required": ["target_type","target"] },
        "response_schema": { "type": "object", "properties": { "id": { "type": "string" } } }
      }
    ]
  }
}
```

- A `read` token sees only `read`-scoped endpoints.
- An `admin` token sees both.
- The `/v1/endpoints` route is itself listed in its own output (the
  registry is self-describing).
- Plugin authors who omit `meta` get `description=null`, schemas
  `null`. Bundled plugins SHOULD include meta.

---

## 10. Endpoint catalog

Distinguishes **core endpoints** (hub-intrinsic, always available
when the listener is bound) from **plugin endpoints** (registered
when the named plugin is loaded; 404 `E_NOT_CONFIGURED` otherwise).

### 10.1 Core endpoints

| Method | Path | Scope | Description |
|---|---|---|---|
| GET | `/health` | none | Health probe, plain text `ok` |
| GET | `/v1/version` | read | hub name, version, build, uptime (seconds), start_time (ISO 8601) |
| GET | `/v1/stats` | read | online user count, total share, traffic, by-level breakdown |
| GET | `/v1/users` | read | online users list - **paginated**, see §6.4 |
| GET | `/v1/users/{sid}` | read | full INF + session metadata |
| GET | `/v1/endpoints` | read | live route registry (scope-filtered) |
| GET | `/v1/log/api` | admin | tail of this API's own audit log; query `?lines=N` (default 100, max 1000) |

### 10.2 Plugin endpoints

Mapped from existing `+cmd` operations. Each row's `plugin` column
names the bundled plugin that registers the endpoint; if that plugin
is disabled in `cfg.scripts`, the endpoint returns 404
`E_NOT_CONFIGURED`.

#### User control

| Method | Path | Scope | Plugin |
|---|---|---|---|
| DELETE | `/v1/users/{sid}` | admin | `cmd_disconnect` |
| POST | `/v1/users/{sid}/redirect` | admin | `cmd_redirect` |
| POST | `/v1/users/{sid}/gag` | admin | `cmd_gag` |
| DELETE | `/v1/users/{sid}/gag` | admin | `cmd_gag` |

#### Registered users

| Method | Path | Scope | Plugin |
|---|---|---|---|
| GET | `/v1/registered` | read | `cmd_reg` - **paginated**, see §6.4 |
| GET | `/v1/registered/{nick}` | read | `cmd_accinfo` |
| POST | `/v1/registered` | admin | `cmd_reg` |
| PUT | `/v1/registered/{nick}/password` | admin | `cmd_setpass` |
| PUT | `/v1/registered/{nick}/nick` | admin | `cmd_nickchange` |
| PUT | `/v1/registered/{nick}/level` | admin | `cmd_upgrade` |
| PATCH | `/v1/registered/{nick}` | admin | `cmd_reg` (free-form fields: `comment`, others) |
| DELETE | `/v1/registered/{nick}` | admin | `cmd_delreg` - requires `X-Confirm: yes` (§4.6) |

#### Bans + blacklist

| Method | Path | Scope | Plugin |
|---|---|---|---|
| GET | `/v1/bans` | read | `cmd_ban` (= `+ban show`) |
| GET | `/v1/bans/history` | read | `cmd_ban` (= `+ban showhis`); query `?nick=` for single-nick history |
| POST | `/v1/bans` | admin | `cmd_ban`. body: `{target_type: nick\|cid\|ip\|sid, target, duration_minutes?, reason?}` |
| DELETE | `/v1/bans/{id}` | admin | `cmd_ban` |
| GET | `/v1/blacklist` | read | `etc_blacklist` |
| DELETE | `/v1/blacklist/{nick}` | admin | `etc_blacklist` |

#### Hub control

| Method | Path | Scope | Plugin |
|---|---|---|---|
| POST | `/v1/announce` | admin | `cmd_mass` - body: `{message, scope: "all"\|"hub"\|"level", level?: int}`. `all` = announce to everyone (`+mass`), `hub` = announce without sender (`+masshub`), `level` = announce to level N (`+masslvl N`). |
| POST | `/v1/topic` | admin | `cmd_topic` |
| POST | `/v1/reload` | admin | `cmd_reload` - requires `X-Confirm: yes` (§4.6) |
| POST | `/v1/restart` | admin | `cmd_restart` - requires `X-Confirm: yes` (§4.6) |
| POST | `/v1/shutdown` | admin | `cmd_shutdown` - requires `X-Confirm: yes` (§4.6) |

#### Logs + records + runtime

| Method | Path | Scope | Plugin |
|---|---|---|---|
| GET | `/v1/log/error?lines=N` | admin | `cmd_errors` |
| GET | `/v1/log/cmd?lines=N` | admin | `etc_cmdlog` |
| DELETE | `/v1/log/{name}` | admin | `etc_log_cleaner` - `{name}` ∈ `error`, `cmd`, `event`, `script` |
| GET | `/v1/records` | read | `etc_records` |
| DELETE | `/v1/records` | admin | `etc_records` |
| GET | `/v1/runtime` | read | `hub_runtime` |
| PUT | `/v1/runtime` | admin | `hub_runtime` |
| GET | `/v1/chatlog?lines=N` | read | `etc_chatlog` |

#### Subsystem managers

| Method | Path | Scope | Plugin |
|---|---|---|---|
| GET | `/v1/msgmanager` | read | `etc_msgmanager` |
| POST | `/v1/msgmanager/{nick}` | admin | `etc_msgmanager` |
| DELETE | `/v1/msgmanager/{nick}` | admin | `etc_msgmanager` |
| GET | `/v1/trafficmanager/settings` | read | `etc_trafficmanager` (= `+trafficmanager show settings`) |
| GET | `/v1/trafficmanager/blocks` | read | `etc_trafficmanager` (= `+trafficmanager show blocks`) |
| POST | `/v1/trafficmanager/blocks/{nick}` | admin | `etc_trafficmanager` (= `+trafficmanager block`). body: `{reason?}` |
| DELETE | `/v1/trafficmanager/blocks/{nick}` | admin | `etc_trafficmanager` (= `+trafficmanager unblock`) |
| GET | `/v1/usercleaner/expired` | read | `cmd_usercleaner` |
| DELETE | `/v1/usercleaner/expired` | admin | `cmd_usercleaner` |
| GET | `/v1/usercleaner/ghosts` | read | `cmd_usercleaner` |
| DELETE | `/v1/usercleaner/ghosts` | admin | `cmd_usercleaner` |

#### Reserved for future (out of scope phase 1-4)

- Plugin management: `GET /v1/plugins`, `POST /v1/plugins/{id}/reload`,
  `PUT /v1/plugins/{id}/enabled`. Requires extending `core/scripts.lua`
  to expose a per-plugin enable/disable + state API. Future phase.
- Config view/edit: `GET /v1/config`, `PUT /v1/config/{key}`. Needs
  field-level secret masking + validator wiring. Future phase.
- Event stream: `GET /v1/events` (SSE) for live updates. Future phase
  when WebUI demands it.

---

## 11. Out-of-scope of the catalog

User SELF-service commands (`+myinf`, `+myip`, `+slots`, `+sslinfo`,
`+accinfo` self, `+nickchange` self, `+setpass` self, `+talk`,
`+uptime`, `+hubinfo`, `+rules`, `+ascii`, `+hubstats` user-side,
`+help`) are excluded - users already have an ADC session for these.
Operator-side inspection of an arbitrary user's INF / slots / SSL
info lives in `GET /v1/users/{sid}` per §10.1; the exclusions
listed here are the USER-SELF variants only.
Cosmetic plugins (`bot_*`, `etc_motd`, `etc_banner`, `etc_keyprint`,
`etc_userlogininfo`, `etc_unknown_command`, `usr_*`) don't expose
actionable operations.

---

## 12. Dependencies

- `dkjson` (pure Lua, ~700 LoC): bundled as `lua_modules/dkjson.lua`,
  registered via `core/init.lua` import block. Decision rationale:
  pure Lua keeps the build dep-free; performance is fine for an admin
  API (no 10k req/sec workload).
- No new C modules.

---

## 13. Implementation phases

Each phase ships as its own sub-PR with its own review gate per
CLAUDE.md §1a.6. The phases are designed to be independently
reviewable and shippable.

### Phase 1: core framework + read-only core endpoints

- Bundle `dkjson` as `lua_modules/dkjson.lua`; wire it through
  `core/init.lua`.
- Extend `core/iostream.lua:newhttpstage` to permit a CL-bounded
  body for non-GET methods (S3 caps stay; body cap = 64 KiB).
- Auto-support HEAD for GET routes; OPTIONS introspection; 405 + `Allow`
  header for method mismatch (§6.6).
- New module `core/http_router.lua` (or extend `core/http.lua`):
  route table, dispatch, auth, scope, envelope, JSON marshalling,
  error mapping, rate-limit (token + per-IP failed-auth), idempotency-
  key cache, audit log, X-Request-ID generation, schema validation.
- New plugin API global `hub.http_register(...)` with optional `meta`
  (description + request_schema + response_schema).
- `+reload` integration: clear route table before re-running plugin
  `onStart` cycle.
- First-boot token bootstrap (§4.7): generate + write
  `cfg/api_token.first` with chmod 600 when `http_api_tokens` empty.
- Core endpoints: `/health` (already exists), `/v1/version`,
  `/v1/stats`, `/v1/users` (paginated), `/v1/users/{sid}`,
  `/v1/endpoints`, `/v1/log/api`.
- New cfg keys: `http_api_tokens` (table), `http_api_rate_read`
  (default 60/min), `http_api_rate_admin` (default 60/min),
  `http_api_log_reads` (default false).
- Smoke tests: token resolution + scope check, envelope shape, error
  codes (esp. 404 vs 405), idempotency-key behaviour + 5-min TTL +
  max-entries cap, rate-limit kick-in (per-token AND per-conn
  failed-auth AND prefix-bucket), X-Confirm enforcement, route
  registration / re-registration on +reload, idempotency cache
  cleared on +reload, pagination clamping (limit=999999 → 1000),
  HEAD/OPTIONS auto-response, first-boot bootstrap file generated +
  chmoded BEFORE port bind, ISO-8601 timestamp format on both Linux
  + Windows MinGW builds (locale-safety of `os.date("!%Y-%m-%dT%H:
  %M:%SZ", t)`), framer body-extension state machine (§2.1
  test list).

### Phase 2: bundled-plugin migration (writes, low-risk)

Plugins migrate to register their endpoints. Each plugin gets the
register call added in `onStart` plus a thin handler that calls into
the same code path the `+cmd` listener uses.

> **Convention:** plugins SHOULD extract the actual operation into a
> module-local function (e.g. `local function do_ban(target_type,
> target, dur, reason) ... end`). Both the `+cmd` listener and the
> HTTP handler call into it. Avoids duplicating ban logic between
> the chat side and the API side - a divergence here is the kind of
> bug that takes months to surface.

- `cmd_mass` → `POST /v1/announce`
- `cmd_topic` → `POST /v1/topic`
- `cmd_ban` → `GET/POST /v1/bans`, `DELETE /v1/bans/{id}`
- `cmd_disconnect` → `DELETE /v1/users/{sid}`
- `cmd_gag` → `POST/DELETE /v1/users/{sid}/gag`
- `cmd_redirect` → `POST /v1/users/{sid}/redirect`
- `cmd_reg`, `cmd_delreg`, `cmd_setpass`, `cmd_nickchange`,
  `cmd_upgrade`, `cmd_accinfo` → `/v1/registered/*` family
- `cmd_reload` → `POST /v1/reload`

### Phase 3: destructive ops + log endpoints

- `cmd_restart` → `POST /v1/restart` (requires `X-Confirm`, see §4.6)
- `cmd_shutdown` → `POST /v1/shutdown` (requires `X-Confirm`, see §4.6)
- `cmd_errors` → `GET /v1/log/error`
- `etc_cmdlog` → `GET /v1/log/cmd`
- `etc_log_cleaner` → `DELETE /v1/log/{name}`

(Note: `GET /v1/log/api` is in Phase 1 because the router owns the
audit log; the other log endpoints are plugin-owned.)

### Phase 4: subsystem manager plugins

- `etc_blacklist`, `etc_msgmanager`, `etc_trafficmanager`,
  `etc_records`, `etc_chatlog`, `hub_runtime`, `cmd_usercleaner`.

### Future (post-v3.2.0)

- **Plugin management endpoints** (`GET /v1/plugins`,
  `POST /v1/plugins/{id}/reload`, `PUT /v1/plugins/{id}/enabled`).
  Requires extending `core/scripts.lua` to expose a per-plugin
  enable/disable + state API. Sized as its own phase.
- **Config view/edit** (`GET /v1/config`, `PUT /v1/config/{key}`).
  Needs field-level secret masking + validator wiring. Sized as
  its own phase.
- **Server-Sent Events `GET /v1/events`** for live updates the
  WebUI subscribes to (user-joined / user-quit / ban-added /
  topic-changed / etc.). Sized as its own phase; designed in this
  spec only at the URL shape level so plugin authors can plan for
  it. The current request/response model has no streaming surface
  - SSE adds one explicitly.
- **Filter + sort query params** (`?q=`, `?level=`, `?sort=`) on
  list endpoints. Query-param convention reserved here; per-endpoint
  validation lives in future phases.
- **Unix-domain-socket bind** as an alternative to TCP loopback
  (`http_socket_path = "/var/run/luadch/api.sock"`). More secure
  (filesystem perms gating, no localhost spoofing on weird network
  stacks), Linux-only (Windows abstract socket support is messier).
  Phase TBD, not phase 1.
- **WebUI itself** (separate repo, consumes this API).

---

## 14. Open questions

- **Bulk endpoints.** `DELETE /v1/users` with body
  `{sids: [...]}` for bulk kick? YAGNI for now; clients can loop.
  Same call applies to `+ban clear` / `+ban clearhis` /
  `+trafficmanager` bulk clears: not surfaced, clients loop
  client-side. The audit log gets one entry per call this way,
  which is the right shape for forensic review.
- **API versioning lifecycle.** When does `/v2` land? Document a
  deprecation policy before the first breaking change is needed.
  Convention: `/v1` is supported as long as the 3.x major line is
  current; a `/v2` rollout overlaps with `/v1` for one full minor
  version before `/v1` is removed.
- **Schema validation depth.** Phase 1 ships the minimal type +
  required + enum + min/max validator. Full JSON-Schema is out of
  scope unless a real client demand surfaces.

---

## 15. Related

- Issue [#82](https://github.com/luadch-ng/luadch/issues/82)
- Phase 8 IO substrate: [`docs/phases/PHASE_8_IO.md`](phases/PHASE_8_IO.md)
- Plugin model: [`docs/PLUGIN_API.md`](PLUGIN_API.md)
- Security model: [`docs/SECURITY.md`](SECURITY.md) (loopback-only +
  reverse-proxy posture lives there)
