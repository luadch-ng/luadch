# Phase 8 - IO layer rework

**Status:** in progress (started 2026-05-15)
**Integration branch:** `phase8-io` (steps land as sub-PRs into this branch;
the branch merges to `master` once the whole phase is reviewed and green).
**Drivers:** #82 (HTTP API), #83 (Prometheus), #147 T2.2 BLOM, #147 T3.2 ZLIF.

## Why

`core/server.lua` delegates ADC framing to LuaSocket's `*l` line pattern
(`receive( socket, "*l" )`, `core/server.lua:565`). That works only because
ADC frames are newline-delimited UTF-8 text. Three independent pieces of
planned work cannot live on a `*l`-framed transport:

- **#82 HTTP API** - request bodies are `Content-Length` / chunked binary.
- **#147 BLOM** - the `HSND` reply has an `m/8`-byte raw-binary data phase
  (may contain `\n`, non-UTF-8).
- **#147 ZLIF** - after `ZON` the wire is an opaque zlib stream; framing
  only exists *after* inflate. Symmetric, partial-flush (Z_SYNC_FLUSH).

All three reduce to one prerequisite: stop letting LuaSocket frame for us;
read raw bytes into a per-connection pipeline that we frame explicitly.
Cross-refs: #82 comment (IO-cluster), #147 (T2.2/T3.2 gated behind this).

## Verified current IO contract (must be preserved byte-for-byte by S1)

Source-read 2026-05-15, `core/server.lua`:

- `receive = socket.receive` (LuaSocket, or luasec-wrapped over TLS),
  `send = socket.send`; assigned at `:773-774`, re-assigned after the TLS
  handshake swap at `:742-743`.
- Single read choke point: `_readbuffer` (`:564`), calls
  `receive( socket, pattern )` with `pattern = "*l"` (`handler.pattern()`
  at `:547` can swap it per connection - the hook point exists, unused for
  binary today).
- Single write choke point: `handler.write` -> `write` (`:531/:546`) ->
  `_sendbuffer` (`:602`) -> `send( socket, buffer, 1, bufferlen )`.
- LuaSocket `*l` nonblocking contract the code relies on (`:565-567`):
  - success: returns the line **without** the `\n`.
  - partial: returns `nil, "wantread"|"wantwrite", partial`. The code
    treats success OR (`part` present and err in {wantread,wantwrite}) as
    "received data" and forwards `buffer or part` to `dispatch`.
  - `timeout` is treated as **fatal** (explicit comment at `:567`).
  - **LuaSocket internally buffers the partial line** across calls - today
    LuaSocket owns line reassembly. Moving to raw bytes moves that
    ownership into our code; this is the core of S1.
- `maxreadlen` cap (`:570`) closes the oversized-frame hole (Phase 7).
- TLS handshake path swaps `receive`/`send` and routes through
  `handler.handshake` (`:760-762`); raw-byte reads must not regress the
  luasec `wantread`/`wantwrite` renegotiation handling.

## Module boundary (CLAUDE.md §2 - do not grow server.lua)

New `core/iostream.lua` owns the per-connection inbound/outbound pipeline.
`server.lua` only: raw bytes -> `iostream` -> framed units -> `dispatch`;
framed write -> `iostream` -> raw bytes -> `send`. server.lua's
select / SSL / timeout / list bookkeeping stays untouched.

## Rollout (incremental, S1 behaviour-neutral first - maintainer-approved)

Each step: own branch off `phase8-io`, own sub-PR into `phase8-io`,
mandatory two-pass pre-merge review (CLAUDE.md §1a.6), full smoke green
(§1b.11). The integration branch merges to master only after the whole
phase passes the review gate.

| Step | Content | Behaviour change |
|---|---|---|
| **S1** | `iostream` with ONLY the ADC-line framer. `*l` receive -> raw read + our own newline reassembly + `maxreadlen` cap. Preserve the wantread/wantwrite/timeout + TLS-handshake contract above exactly. | **none** (proof step) |
| **S2** | Generalise inbound/outbound into a composable pipeline (passthrough stage only) + stage API | none |
| **S3** | HTTP framer stage (#82) | additive (new listener type) |
| **S4** | ZLIF inflate/deflate stage + `ZON`/`ZOF` + zlib build dep | opt-in via SUP |
| **S5** | BLOM counted-binary capture stage + H-class GET/SND | opt-in via SUP |

### Finding 2026-05-15: the old `*l` path has a latent fragmented-frame disconnect bug

Verified against bundled LuaSocket `luasocket/src/buffer.c:105-152`
(`buffer_meth_receive`) + `recvline`:

- `sock:receive("*l")` on an incomplete line returns `nil, errstr,
  <partial>`. errstr is `"timeout"` for plain-TCP nonblocking, or
  `"wantread"`/`"wantwrite"` for the luasec TLS want-dance.
- The old `_readbuffer` guard was
  `if (not err) or (part and (err=="wantread" or err=="wantwrite"))`.
  For a **plain-TCP** frame split across TCP segments, `err=="timeout"`
  -> falls to the `else` branch -> `handler.close` -> **the connection
  is dropped**. TLS partials (`wantread`/`wantwrite`) were tolerated;
  plain-TCP partials were fatal. Asymmetric and fragile.

So the old behaviour for a fragmented frame on plain TCP is "disconnect
the client", almost certainly the root of the historical "Kungen
disconnect bug" / "occasional unwanted disconnects in big hubs"
(server.lua changelog). It rarely bites because small ADC control
frames usually arrive in one TCP segment.

Consequence: "behaviour-neutral" for S1 means neutral w.r.t. the
*intended* behaviour (each complete ADC frame processed exactly once),
**not** bug-for-bug compatible. S1's raw-read + framer **fixes** this
latent disconnect bug. This also upgrades the fragmentation smoke test
from a no-regression check to a genuine pre/post regression test
(fails on old code = connection drops; passes on S1).

### Finding 2026-05-15 (during S1 impl): data + FIN coalescing

The first S1 implementation processed received bytes only on the
benign branch and treated `err == "closed"` as purely fatal (discard,
close). The `+setpass` smoke test failed deterministically. Root cause
(found via instrumented `_readbuffer`): a final TCP segment can carry
both data and the FIN, so `receive( socket, n )` returns
`nil, "closed", <final-bytes>` in a single call. The old `*l` path
never hit this (one line per call; the close arrived as a separate
empty read), so discarding the bytes on "closed" lost the last
command - here a `+setpass` sent immediately before the client closed.
`+help`-style tests masked it (they matched an unrelated login
broadcast frame and passed spuriously); `+setpass`'s strict re-login
assertion exposed it.

Fix: `_readbuffer` now feeds the framer and dispatches complete frames
whenever `got > 0`, **regardless of err**, then performs the close if
the error was terminal. This is the correct read-returns-data-then-EOF
handling and is another strict correctness improvement over the old
path (which could also lose a last command on a fast client close;
rarely bit because clients usually waited for a reply first).

### Finding 2026-05-15 (two-pass review, BLOCKER B1): CR-strip scope

The first framer stripped only a single trailing `\r` before `\n`. The
independent reviewer caught (and the maintainer spot-check confirmed
against `luasocket/src/buffer.c:231-234` recvline, "we ignore all
\r's") that LuaSocket `*l` strips **every** `\r` anywhere in the line.
So `BMSG <sid> a\rb\n` was accepted pre-S1 (`*l` -> `BMSG <sid> ab`)
but rejected post-S1 (embedded CR -> Phase-7 `%c` parser reject ->
silently dropped). The "behaviour-neutral" claim was false - exactly
the §1a.5 "verify every assumption against current source" trap. Fix:
the framer now drops every `\r` in the frame (`gsub`), true `*l`
parity, verified by an embedded-CR framer unit test. This is why the
mandatory two-pass review exists.

### Review findings carried as documented notes (not blocking)

- **C1 - per-tick read pacing changed (acknowledged, not a regression).**
  Pre-S1, `*l` returned one line per `_readbuffer` call; pipelined
  frames sat in LuaSocket's 8 KiB userspace buffer so a flood was
  implicitly throttled to ~1 frame / select-tick / connection. S1
  dispatches all complete frames in the segment in one synchronous
  loop (bounded by `_maxreadlen` = 1 MiB worth, then overflow-close).
  Net: a latency improvement (also fixes a latent pipelined-2nd-frame
  stall) but worst-case synchronous work per tick per connection grew
  from 1 to N frames. There is no per-message ratelimit in the read
  path (ratelimit.lua is per-IP-accept / handshake-deadline only). S2+
  adds heavier per-frame stages (HTTP, ZLIF inflate) and MUST account
  for this - consider a per-tick frame budget when the pipeline lands.
- **C2 - `maxreadlen` cap split.** The framer is constructed once with
  the module-global `_maxreadlen`; the per-frame cap in `_readbuffer`
  uses the per-handler local `maxreadlen`. Equal unless
  `handler.bufferlen()` mutates it - no in-tree caller does (dead
  today). Resolve (pass the live cap into the framer) when S2+ makes
  per-connection caps live.
- **N2 - two-frames smoke test kept as-is.** Reviewer rated it
  adequate; a "two distinct replies" assertion against `+help`'s
  multi-frame reply would add flakiness (worse than the current
  over-merge-caught-via-timeout + desync-caught-via-followup proof).
  Deliberate.

### S1 acceptance (the load-bearing step)

1. Full smoke suite (plain + TLS handshake / login / +cmd routing /
   burst / negative battery) stays green unchanged.
2. New smoke test: an ADC frame delivered split across multiple TCP
   segments (write half a frame, flush, write the rest) is reassembled
   into exactly one processed frame. **This FAILS on pre-S1 code**
   (plain-TCP partial -> "timeout" -> connection dropped) and PASSES on
   S1 - a true pre/post differentiator per CLAUDE.md s1a.7.
3. New smoke test: two ADC frames in a single TCP segment are processed
   as exactly two frames (no over-merge, no drop of the second).
4. error.log gains no new entries during the suite.

S1 is NOT done until 1-4 hold on both Linux (CI) and Windows (local).

### Known highest risk (flagged before any edit)

The luasec TLS path: raw-byte reads over TLS have their own
`wantread`/`wantwrite` semantics during renegotiation, which the current
`*l` code already wrestles with ("SSL nightmare" comments in server.lua
history). S1 preserves the `wantwrite` cross-wiring byte-for-byte and
the handshake coroutine is untouched (the framer is only installed
*after* handshake), and both reviews judged the path logically
equivalent (or better - S1 also keeps the partial on `wantread`).

**GATE RESOLVED 2026-05-15 (not by a test - by removing the cause).**
Re-derived from source instead of building a synthetic reneg test:
`protocol = "tlsv1_3"` makes luasec pin the SSL context to
`min == max == TLS1_3_VERSION` (`luasec/src/context.c:107-111` +
`SSL_CTX_set_min/max_proto_version` at `:337-338`). TLS 1.3 has **no
renegotiation** (RFC 8446). So under the shipped default the
mid-stream `wantread`/`wantwrite` reneg inversion is impossible *by
protocol*, not by luck - the "SSL nightmare" comments predate the
TLS-1.3 default. The only path back to renegotiation was a manual
operator downgrade to `protocol = "tlsv1_2"`. That opt-out is now
removed: the commented `tlsv1_2` blocks are deleted from
`examples/cfg/cfg.tbl` (replaced with an explicit "TLS 1.2 is
UNSUPPORTED" note), and `"no_renegotiation"` (OpenSSL
`SSL_OP_NO_RENEGOTIATION`, luasec `options.c:113-114`) is added to the
default `ssl_params.options` in both `core/cfg_defaults.lua` and
`examples/cfg/cfg.tbl` as defense-in-depth. Dependency constraint:
`no_renegotiation` needs OpenSSL >= 1.1.0h (project bundles 3.x
everywhere; luasec raises "invalid option" on an undefined flag, so a
future OpenSSL downgrade would fail TLS startup loudly, not silently).
Residual want-dance can now only originate from the normal handshake
(framer installed only *after* handshake - untouched) and benign
partial-record reads (handled). Folded into PR #184 as the direct
resolution of this IO-stack review finding.

## S2 spec (locked 2026-05-15, maintainer-approved)

Generalise `core/iostream.lua` from one fixed framer into a
composable per-connection **pipeline of stages**. Behaviour-neutral
proof step (no new functional stage; the S1 ADC-line logic becomes
*a* stage). Decisions:

- **Stage interface (Q1, chosen):** a stage is an object with
  `stage:push( chunk ) -> units, overflow`. `units` is an ordered
  array of whatever this stage emits (the ADC-line stage emits
  complete frame strings; a passthrough stage re-emits its input
  byte chunk as a single unit; future inflate emits decompressed
  byte chunks; future HTTP emits request units). `overflow` is a
  bool only the terminal/framing stage sets (size-cap breach).
- **Pipeline:** `iostream.newpipeline( maxlen )` builds the default
  inbound pipeline = `{ adcline(maxlen) }` and returns an object
  with the **same `:feed( bytes ) -> frames, overflow` contract as
  S1's framer** (so server.lua is a ~2-line change and behaviour is
  provably identical: a 1-stage pipeline == the old framer). `feed`
  runs bytes through stage 1, its units through stage 2, ... ; the
  terminal stage's units are the dispatchable frames.
- **Rebuild seam:** the pipeline exposes an internal `:prepend(stage)`
  so a future stage (S4 ZON -> splice inflate ahead of the framer)
  can rebuild mid-stream. Defined in S2, exercised first in S4 - no
  server.lua hook is added now (YAGNI; the existing unused
  `handler.pattern()` is left as-is, not repurposed).
- **Scope (Q2):** inbound only. The outbound seam is deferred to S4
  (ZLIF deflate); an outbound passthrough now would be speculative.
- Public surface becomes `newpipeline`, `newadclinestage`,
  `newpassthroughstage`; `newframer` is dropped (server.lua is its
  only consumer, verified by grep).

S2 acceptance: the S1 framer unit-test cases pass byte-identically
through the pipeline; a passthrough stage and a `[passthrough,
adcline]` composition behave exactly like `[adcline]`; full smoke
stays green unchanged (neutrality proof). Risk is well below S1 -
the dangerous `*l` -> raw socket change is already shipped; S2 only
restructures the byte/frame flow already in our hands.

## S3 spec (locked 2026-05-15, maintainer-approved - SECURITY-CRITICAL)

First *additive* step: an HTTP request-framer stage so the pipeline
can also carry an HTTP listener (drives #82). **Scope split decision:**
S3 ships ONLY the hardened framing + listener substrate + a trivial
`/health` endpoint (no auth, no data). #82 phase-1 proper (token
auth, `/users` `/stats` `/version`, JSON) is a SEPARATE follow-up PR
with its own security-focused review - the sensitive auth / data
exposure work must not be bundled with IO plumbing.

Default behaviour change: **none**. No `http_port` in cfg -> no HTTP
listener bound -> existing hubs byte-unaffected. Purely additive.

**JSON:** deferred to the endpoints PR (S3 `/health` needs none).
Decision criteria recorded now so it is not relitigated: prefer
`dkjson` (pure-Lua, no new C dep / build change / supply-chain
surface; the read-only API only *serialises* trusted hub state and
never *parses* untrusted JSON input). Final call in the endpoints PR.

### Hardening contract (S3 MUST enforce all of these)

Module split (CLAUDE.md §2): the hardened parser is
`iostream.newhttpstage` (pure bytes -> request-unit, unit-testable in
isolation - this is where every limit lives); `core/http.lua` (new)
is the request router (parsed request -> response); `server.lua` only
binds the HTTP listener (pipeline = `[httpstage]`, dispatch ->
`http.handle`).

- **Listener:** bind `127.0.0.1` only; bind nothing unless cfg
  `http_port` is set (default unset). No HTTPS on the API port (#82:
  reverse-proxy assumed for non-loopback; out of scope here). The new
  listener still goes through `ratelimit.accept_ip` (per-IP accept
  cap) and the existing handshake-deadline / idle-timeout in
  server.lua.
- **One request per connection.** No keep-alive: parse one request,
  respond, `Connection: close`, close. Eliminates keep-alive request
  smuggling and slowloris-via-many-requests in one stroke; read-only
  health/stat probes do not need pipelining.
- **Request-line:** length cap; method in {GET, HEAD} only (else
  405); HTTP version in {HTTP/1.0, HTTP/1.1} only (else 505);
  request-target must start with `/`, length cap, reject NUL / CR /
  LF / control bytes / `..` traversal.
- **Headers:** cap total header bytes, header count, single-line
  length; reject NUL/control in names/values; case-insensitive field
  names.
- **Body / smuggling:** GET/HEAD carry no body - any `Content-Length`
  > 0 or any `Transfer-Encoding` -> 400. `Content-Length` AND
  `Transfer-Encoding` both present -> 400. Multiple `Content-Length`
  -> 400. `Transfer-Encoding: chunked` is rejected outright (the
  classic smuggling vector; never needed for read-only GET).
- **Oversize / slowloris:** an unterminated request that exceeds the
  cap trips the pipeline overflow (S1/S2 mechanism) -> connection
  closed. The per-connection idle timeout already bounds a stalled
  request.
- **Response:** minimal fixed headers (`Content-Type: text/plain`,
  `Content-Length`, `Connection: close`); **no `Server` header** (no
  version fingerprint pre-auth). Body for `/health` is a tiny static
  `ok\n` (200). Everything else: 400 (malformed) / 404 (unknown
  path) / 405 (method) / 505 (version). HEAD = same status/headers,
  empty body.
- **Logging:** malformed/oversize/rejected requests logged at low
  verbosity via `out`; never log the body; sanitise the path in log
  lines (no log injection via CR/LF - already rejected, defence in
  depth).

### S3 acceptance

- `iostream_test.lua` extended with httpstage hardening cases, each
  asserting the reject: oversize request-line/header, header-count
  cap, `CL`+`TE` together, multiple `CL`, `chunked` rejected,
  body-on-GET, bad method (405), bad version (505), NUL/CRLF in
  path, `..` traversal, partial-request reassembly across feeds,
  the happy `GET /health` and `HEAD /health` paths.
- Smoke: HTTP roundtrip test (staging cfg enables `http_port`):
  `GET /health` -> 200 `ok`; malformed -> 400; unknown path -> 404;
  bad method -> 405. Existing ADC smoke unaffected (no http_port in
  the default path = no listener).
- `tests/unit/iostream_test.lua` wired into CI (smoke.yml) in S3
  (closes the S2 deferred gate early - S3 adds a second testable
  stage that needs the same net).
- Mandatory two-pass review is **security-focused** (CLAUDE.md
  §1a.6 + §1.1): the new network listener is the highest-risk
  surface added since the modernisation.


### Finding 2026-05-15 (S3 security review, BLOCKER B1 + C1-C5)

The mandatory security-focused two-pass review (independent agent +
maintainer spot-check vs source) found, and S3 fixed in-branch:

- **B1 (BLOCKER) - HTTP listener bound 0.0.0.0, not 127.0.0.1.**
  `server.addserver` binds `p.addr` (default `"*"`); it never reads
  `p.ip`. hub.lua passed `ip = "127.0.0.1"` -> silently ignored ->
  the unauthenticated, no-TLS HTTP socket was exposed on ALL
  interfaces, nullifying the entire loopback-only security premise.
  Fix: pass `addr = "127.0.0.1"` (the param addserver actually
  reads). Smoke now asserts the listener is unreachable on a
  non-loopback address. The pre-existing ADC-side `hub_listen`
  ignored / `addserver` dead range-clause are tracked separately as
  #186 (CLAUDE.md §7, no drive-by).
- **C1 - zero-byte connection slowloris.** `_activitytimes[handler]`
  was armed only on first read with bytes, so a connect-and-send-
  nothing was never idle-swept. Fixed: armed at accept in
  wrapconnection (bounds every connection by the standard
  `_max_idle_time`, all listener types).
- **C2 - http_port validator had no range/integer check** (0 / floats
  slipped through). Now: false, or integer 1..65535.
- **C3 - http_port colliding with an ADC port** silently failed to
  bind. Now: explicit `out_error` and the HTTP API is not started
  (fail loud).
- **C4 - header name whitespace bypass.** `Content-Length : 0`
  matched the old name pattern, dodging the CL/TE smuggling
  classifier. Pattern tightened to reject any whitespace in the
  header name (-> 400). Unit-tested.
- **C5 - the loopback property was untested** (smoke connected to
  127.0.0.1, which a 0.0.0.0 bind also accepts, so it was green with
  B1 live). Added the non-loopback-unreachable smoke assertion.

Everything else in the hardening contract held: the reviewer could
not smuggle, DoS the framer, leak info, or escape the sandbox; the
type-guard does not weaken S1/S2; HTTP never enters hub user
machinery. This is exactly the §1a.5 "verify every assumption
against current source" miss the security two-pass gate exists to
catch.

## S4 spec (locked 2026-05-20, maintainer-approved)

ZLIF = ADC-EXT zlib stream compression per connection. Hub <-> client
agree on `ZLIF` in SUP, then either side can flip its outbound stream
to a zlib stream with `ZON` (peer decompresses inbound after this
line) and back with `ZOF` (in the compressed stream). `Z_SYNC_FLUSH`
after each chunk. Spec is silent on error handling, TLS interaction,
decompression-bomb caps -> all hardened by us.

### S4 splits into two sub-PRs

S4 is the biggest single step (pipeline contract change + outbound
seam + new C dep + Lua binding + dispatch + cfg + smoke). Per CLAUDE.md
§1a.8 (small reviewable PRs), it splits cleanly along the
behaviour-neutral / additive boundary already used in S1->S2->S3:

- **S4a - iterator pipeline + outbound passthrough seam
  (behaviour-neutral).** Refactors the pipeline contract to lazy /
  one-frame-at-a-time, adds an outbound pipeline seam to server.lua
  (default = passthrough = byte-identical send path). No new
  dependency, no protocol change. The clean review base for S4b.
- **S4b - ZLIF feature.** zlib_stream C module + inflate/deflate
  stages + ZON/ZOF dispatch + cfg gates + smoke. Built on the S4a
  seams; this PR ONLY adds the compression layer, never restructures
  IO. Maintains the S3 split-by-risk-surface pattern.

### Locked design decisions (Q1-Q3, maintainer-approved)

- **Q1 - zlib binding: own minimal C module.** New
  `zlib_stream/zlib_stream.c` (`require "zlib_stream"`), exposes only
  `deflate_stream` and `inflate_stream` objects with `:push(bytes) ->
  bytes` (Z_SYNC_FLUSH). Mirrors the project pattern of `adclib` /
  `slnunicode` shim - minimum surface, hub-specific. Build:
  `find_package(ZLIB REQUIRED)` (system zlib on Linux + MinGW, CI
  installs `zlib1g-dev`). Vendored `lua-zlib` rejected: 4x larger,
  features we don't need, extra supply-chain surface.
- **Q2 - default policy: opt-in.** New cfg key `zlif_enabled` (default
  `false`). Hub advertises `ADZLIF` only when enabled. Matches the
  S3 default-off pattern (`http_port = false`) - new IO surface is
  opt-in by operator, not bundled into the default behaviour set.
- **Q3 - TLS + ZLIF: default-off on TLS connections.** Independent
  cfg flag `zlif_over_tls` (default `false`). CRIME-class chosen-
  plaintext-length leak is theoretically possible on the hub's TLS
  outbound (attacker PMs victim, hub forwards mixed with victim's
  other traffic, observer infers length deltas). Mitigation:
  opt-in only, document in SECURITY.md. Plain ADC connections see
  ZLIF when `zlif_enabled = true` and the client advertises `ADZLIF`.

### Pipeline contract change (S4a, load-bearing correctness)

The pipeline's `:feed(bytes) -> frames, overflow` contract returns
ALL frames in one shot. With S4b's mid-stream `ZON` arrival, an input
chunk can carry `"ZON\nXXX..."` where `XXX` is compressed - the
ADC-line stage cannot know `ZON` is the last plain frame and will
happily parse compressed bytes as ADC frames before the dispatcher
gets a chance to splice in the inflate stage. Result: dispatched
garbage frames. This is the load-bearing correctness issue.

Fix (S4a, behaviour-neutral): pipeline switches to **lazy / iterator**
contract:

    pipeline:feed( bytes )         -- inputs bytes, no return
    pipeline:next( ) -> frame, overflow    -- pulls ONE frame; nil = drained
    pipeline:drain( ) -> frames, overflow  -- convenience: loop next() to nil

Internal model: top-down lazy pull. `_pull(i)` asks stage `i` for a
unit; if stage `i` has none, ask stage `i-1` and feed its output to
stage `i`. The stage contract is tightened: `stage:push(chunk) ->
unit, overflow` returns AT MOST ONE unit (with `chunk = ""` meaning
"drain pending state"). Stages also expose `:residual() -> bytes` so
the pipeline can extract the front stage's unprocessed suffix on
reshape.

Reshape semantic:

    pipeline:prepend( newstage )
        residual = stages[1]:residual()         -- empty, or unprocessed suffix
        stages = { newstage } ++ stages
        input_buffer = residual ++ input_buffer  -- new front sees residual first

So when the ZON dispatch handler (S4b) calls
`pipeline:prepend(inflate_stage)` immediately after dispatching the
ZON frame, the compressed bytes the ADC-line stage had buffered post-
ZON get re-fed through the new inflate stage. By construction, the
dispatcher's outer loop has not yet asked for the next frame, so no
garbage was emitted. Verified by the new "ZON-mid-chunk" unit test
(`tests/unit/iostream_test.lua`).

Outbound seam (S4a): mirrors the inbound seam. `server.lua` gains a
per-connection `outframer` constructed from `listeners.pipeline_out`
(default = passthrough = current behaviour, byte-identical). Stage
contract for outbound: `stage:write(bytes) -> bytes`. Pipeline:
`outpipeline:write(bytes) -> bytes`, `outpipeline:prepend(stage)`.
`handler.write(data)` becomes `bufferqueue ++= outframer:write(data)`.
S4b adds a `deflate_stream` stage prepended on `IZON`-out.

### S4a acceptance

1. `tests/unit/iostream_test.lua` extends to cover the iterator API
   (next/drain), ZON-mid-chunk reshape (a "ZON" line in a chunk with
   compressed-looking suffix bytes is dispatched alone; subsequent
   bytes are re-fed through a prepended stage and not mis-framed),
   outbound pipeline composition (passthrough x passthrough is
   byte-identical to the input).
2. Full smoke green unchanged (no protocol behaviour change).
3. S1/S2 behaviour-equivalence checks: `pipeline:drain(bytes)` on
   the default pipeline returns the exact same `(frames, overflow)`
   tuple S1/S2's feed did, for every existing test case.

### S4b acceptance

- Unit tests: deflate-stream / inflate-stream basic roundtrip
  (Z_SYNC_FLUSH partial flush correctness); ZON activates inflate
  mid-chunk in the pipeline; ZOF removes inflate stage; size-cap on
  inflate output (decompression-bomb guard, hard byte cap per push
  + ADC `_maxreadlen` enforced post-inflate as today); malformed
  compressed input -> handler.close (no silent garbage frames).
- Smoke: a "ZLIF roundtrip" test on a plain-ADC test client that
  speaks ZON, login completes, +help routes correctly, ZOF reverts
  cleanly. Default `zlif_enabled = false` path: existing smoke
  unchanged (the ZLIF SUP token MUST NOT appear in the default
  `_normalsup` advertise string, lest non-ZLIF clients try and we
  fail).
- Hardening: inflate output cap per `:push` call = 4 MiB (well above
  any realistic ADC frame burst, well below memory-pressure); ratio
  guard not needed (the byte cap already bounds decompression). Cfg
  validator on `zlif_enabled` / `zlif_over_tls` = boolean only.
- Two-pass review focus: decompression-bomb path, TLS interaction
  (assert plain default; cfg gate works), correct reshape on edge
  cases (ZON immediately followed by ZOF; multiple ZON/ZOF cycles;
  client-initiated ZON before hub-initiated; only-one-side-ZON).

### Build / CI (S4b)

- Top-level `CMakeLists.txt`: `find_package(ZLIB REQUIRED)` next to
  the OpenSSL find. Log the version (matches OpenSSL pattern).
- New module dir `zlib_stream/` with `CMakeLists.txt` + `zlib_stream.c`.
  Links `ZLIB::ZLIB` + `lua`. Builds to `lib/zlib_stream/zlib_stream.{so,dll}`
  identical to `adclib` layout.
- `.github/workflows/smoke.yml` Linux job: add `zlib1g-dev` to the
  apt-get install line. Windows MinGW already ships zlib via the
  default mingw distribution (verify in S4b CI run, bundle if not).
- aarch64 Bullseye container build: zlib is base-system, no change.

## S5 spec (locked 2026-05-21, the LAST Phase-8 step)

BLOM = ADC-EXT bloom-filter routing for hash-searches (#147 T2.2).
Clients send the hub a bloom filter of their shared TTHs; the hub
forwards each hash-search SCH only to clients whose filter could
match. The hub initiates `HGET blom / 0 <m/8> BK<k> BH<h>`, the
client replies `HSND blom / 0 <m/8>` + **m/8 raw binary bytes** as
the data phase after the header newline. This is the IO-refactor
reason BLOM was deferred to Phase 8 in the first place - the binary
phase can contain `\n` and non-UTF-8 bytes, both of which would have
been mis-framed by the pre-S1 LuaSocket `*l` path.

### Locked design decisions

- **Q1 - Counted-binary capture stage in iostream.** New stage type
  `newcountedstage( byte_count, callback )`. Captures exactly
  `byte_count` bytes (regardless of `\n`), invokes the callback
  once with the captured bytes, then becomes a transparent
  passthrough for any subsequent input. **Rejected alternative:
  explicit `pipeline:strip_front()` semantic.** Passthrough-after-
  budget needs no stage-contract change and no mid-pull stages[]
  mutation; the dead-stage memory cost across many BLOM refreshes
  is negligible (~50 bytes per HSND, accumulating to KB after
  hours - well below DoS thresholds). S4a's `prepend` reshape
  carries adcline's residual buf (binary bytes already in the same
  TCP chunk as the HSND header) into the new counted stage.
- **Q2 - Hub-initiates-HGET timing.** MVP: send HGET once when the
  user enters NORMAL state AND advertised `ADBLOM` AND
  `cfg.blom_enabled`. Periodic refresh on `SF` / `SS` BINF updates
  is spec-permitted ("the hub may at any time") but deferred to a
  follow-up - initial-only is spec-compliant and covers the common
  case for static shares.
- **Q3 - Per-user filter state.** Lives on the user object as
  `_blom_filter` (bytes string) + `_blom_supports_blom` (bool). Set
  by HSND handler via `user.setblom( bytes )`. Read by the SCH
  router via `user.getblom( )`. Plugins get read-only access.
- **Q4 - Hash-vs-keyword routing (the LOAD-BEARING SPEC TRAP).** The
  filter is consulted ONLY when a SCH carries a `TR` named
  parameter (hash-search by TTH). Keyword searches (AN / NO / EX /
  TY / etc.) MUST broadcast unchanged - a naive "consult filter on
  every SCH" silently breaks keyword search hub-wide because the
  filter has zero bits set for plain-text keywords by design. DSCH
  (D-class, single recipient) bypasses filtering entirely - no
  fanout to optimise.
- **Q5 - Default BLOM parameters.** `k = 6`, `h = 16`, `m = 32768`
  bits (4 KiB filter per user, m % 64 == 0, 2^h = 65536 > m). With
  a 10k-file share that gives ~39 % false-positive rate -
  acceptable baseline; operators tune up via cfg for larger
  shares. Validators: `m % 64 == 0`, `2^h > m`, `k * h <= 192`
  (TTH is 192 bits), `h % 8 == 0` (spec restriction), `k >= 1`,
  all integers.
- **Q6 - 200-local + sandbox gotchas (S4b lessons).** Cfg packed
  into one `local _cfg_blom = { enabled, k, h, m }` to stay under
  Lua 5.4's 200-locals ceiling in hub.lua. Every Lua-stdlib name
  used in new core code audited against the file's existing `use`
  block (bloom.lua needs `string`, `table`, `setmetatable`,
  `tonumber`, `math` - all available via `use`).

### S5 module / file plan

- **`core/bloom.lua`** (new, pure Lua): `newfilter(bytes,k,h,m) ->
  obj:contains(tth_24)` per spec section 3.20.
- **`core/iostream.lua`**: add `newcountedstage` + export.
- **`core/adc.lua`**: add `GET` / `SND` / `GFI` to
  `_protocol.commands` (contexts already covered).
- **`core/hub_dispatch.lua`**: `_normal.HSND` handler, HGET sender
  on NORMAL-state entry, BSCH/FSCH hash-router hook, ADBLOM SUP
  advertise via gsub.
- **`core/hub.lua`**: `_cfg_blom` cache, the F-class `featuresend`
  bloom-aware wrapper, bind plumbing.
- **`core/hub_user_object.lua`**: `setblom` / `getblom` /
  `supportsblom` accessors.
- **`core/cfg_defaults.lua`**: `blom_enabled` / `blom_k` /
  `blom_h` / `blom_m` keys with validators.
- **`examples/cfg/cfg.tbl`**: the four new keys with docs +
  default-off + tuning guidance.

### S5 acceptance

- `tests/unit/iostream_test.lua`: extends with newcountedstage
  cases (basic capture, exact-budget vs. over-budget, post-budget
  passthrough, callback fires once).
- `tests/unit/bloom_test.lua` (new): basic membership oracle test,
  spec-vector roundtrip, false-negative-never property, false-
  positive sanity at default params.
- Smoke: `test_blom_roundtrip` flips `blom_enabled = true`, walks
  an ADC login that advertises ADBLOM in HSUP, receives the hub's
  HGET, sends HSND + binary filter with one known TTH, sends a
  hash-search BSCH for that TTH and asserts it arrives. Pair
  tests: a hash-search for a TTH whose bits are zero must NOT
  arrive (filter blocked it); a KEYWORD-search must broadcast
  unconditionally (regression test for the spec-trap).
- Mandatory two-pass review CLAUDE.md §1a.6 + §1.1: the hash-vs-
  keyword distinction is the load-bearing security / correctness
  property; the independent agent must verify it cannot be
  bypassed.

## Log

- 2026-05-15: phase opened, integration branch `phase8-io` created, design
  + S1 spec recorded (this doc). IO contract verified against source.
- 2026-05-15: S1 implemented (core/iostream.lua + server.lua _readbuffer),
  commit 36d932c. Two latent bugs found+fixed during impl (plain-TCP
  fragmentation disconnect; data+FIN coalescing). Mandatory two-pass
  review run: independent agent + maintainer spot-check found BLOCKER B1
  (CR-strip scope, false neutrality claim) - fixed (strip all CR, true
  `*l` parity). C1/C2/N1/N2 carried as documented notes above. Smoke
  green 3x on Windows incl. the +setpass test that exposed the FIN bug;
  framer unit-tested incl. embedded-CR. Sub-PR #184 -> phase8-io.
- 2026-05-15: TLS-reneg gate RESOLVED by removing the cause (not a
  test): default is TLS-1.3-only (min==max pin verified in luasec
  context.c; RFC 8446 = no reneg), tlsv1_2 opt-out removed from
  examples/cfg, "no_renegotiation" added to default ssl_params.options
  in cfg_defaults.lua + examples/cfg.tbl as defense-in-depth. Folded
  into PR #184 (direct resolution of the IO-stack review finding).
- 2026-05-15: S1 PR #184 merged into phase8-io (squash 42e2393), all
  CI green (Linux + Windows smoke, image build). S2 spec locked
  (above); branch phase8-io-s2 opened.
- 2026-05-15: S2 implemented (stage pipeline, commit 8336c01),
  behaviour-neutral, full smoke green. Two-pass review: independent
  agent verdict SOUND (no BLOCKER/CONCERN), confirmed by maintainer
  spot-check. Two cosmetic NITs fixed (server.lua phase tag /
  framer->pipeline wording). TEST-DEBT closed in-step rather than
  deferred: added committed `tests/unit/iostream_test.lua` (15
  checks: S1 framer parity + passthrough + composition + prepend
  ordering) - S1/S2 had only throwaway scripts before, which prove
  nothing per s1a.7. **Open gate (S4):** wire
  `tests/unit/iostream_test.lua` into CI before S4 - S4 already
  touches the build/CI for the zlib dependency, so the lua-unit
  runner is in-scope there; the pipeline `prepend` seam gets its
  first production caller in S4 and must be CI-guarded by then.
- 2026-05-15: S3 implemented on branch phase8-io-s3 - hardened HTTP
  request framer (iostream.newhttpstage + newhttppipeline), core/http.lua
  /health router, server.lua per-listener pipeline seam
  (listeners.pipeline), hub.lua 127.0.0.1-only HTTP listener gated on
  cfg http_port (default false), http_port added to cfg_defaults +
  examples/cfg. iostream_test.lua extended to 35 checks (HTTP hardening:
  TE/CL smuggling, oversize 414/431, bad version 505, traversal,
  control bytes, obs-fold, partial reassembly, one-req-per-conn) and
  WIRED INTO CI (smoke.yml lua5.4 step, Linux job) - closes the S2
  deferred gate early. Smoke gained an HTTP /health roundtrip +
  hardening + ADC-still-works test. Integration bug found+fixed during
  smoke: _readbuffer's per-unit oversize cap did `string_len(frame)`
  assuming string frames (true for S1/S2 ADC-line) but S3 emits table
  units -> type-guarded the cap (ADC behaviour identical; non-string
  units carry their own in-stage hardening). Full smoke green on
  Windows; iostream_test 35/35. Next: security-focused two-pass review
  -> sub-PR into phase8-io.
- 2026-05-15: S3 security two-pass review found BLOCKER B1 (HTTP
  listener bound 0.0.0.0 not 127.0.0.1 - addserver reads p.addr,
  not p.ip) + C1-C5; all fixed in-branch (see finding above). N4
  pre-existing hub_listen/addserver bugs tracked as #186. Re-run
  security review on the fixes before sub-PR.
- 2026-05-20: S4 split into S4a (behaviour-neutral pipeline
  iterator + outbound passthrough seam) and S4b (ZLIF feature) per
  CLAUDE.md §1a.8. S4a (#189) merged into phase8-io (squash f56dd44),
  CI green: pipeline contract switched from "feed -> all frames" to
  lazy iterator (feed + next + drain), stage contract tightened to
  one-unit-per-push, outbound pipeline added (default passthrough =
  byte-identical), 51/51 unit tests including mid-chunk reshape +
  multi-stage sticky_overflow + outbound prepend-ordering. Two-pass
  review: 0 BLOCKER / 2 CONCERN (C1 misleading sticky-overflow
  comment, C2 dead branch in `_pull`) / 5 NIT - C1/C2/N2 fixed
  in-branch before merge.
- 2026-05-20: S4b implemented on branch phase8-io-s4b. New zlib
  build dep (`find_package(ZLIB REQUIRED)`); new C module
  `zlib_stream/zlib_stream.c` (~250 LoC: deflate_stream +
  inflate_stream userdata, Z_SYNC_FLUSH semantic, 4 MiB
  decompression-bomb cap per inflate push). New Lua stages
  `iostream.newinflatestage` / `newdeflatestage` wrapping the C
  module; pcall around inflate so a corrupt / bomb-cap stream
  surfaces as the pipeline overflow signal -> server.lua closes
  the connection. Handler accessors
  `inframer_prepend` / `outframer_prepend` added to server.lua so
  the dispatcher can splice stages mid-stream. `cfg.zlif_enabled`
  + `cfg.zlif_over_tls` validators added (boolean only). hub.lua's
  HSUP handler gsubs `ADZLIF` into the SUP advertise template when
  `zlif_enabled`, sends `IZON\n` after the SUP response (last
  plain frame) and prepends the outbound deflate stage so all
  subsequent writes are compressed. Inbound `ZON` intercepted in
  `hub.lua's incoming()` before plugins / state dispatch see it,
  routes to `inframer_prepend(newinflatestage())`; the post-ZON
  residual buf the ADC-line stage had buffered re-feeds through
  the new inflate stage by S4a's reshape semantic. Inbound `ZOF`
  closes the connection politely (spec-permitted; clean strip-
  inflate-mid-stream is deferred until a real client actually
  exercises the path).

  **Lua 5.4 200-locals-per-chunk ceiling encountered.** hub.lua
  already sat near the limit; adding two new cfg cache locals +
  the iostream binding tripped it. Resolved by packing the ZLIF
  cfg cache into a single table (`local _cfg_zlif = { enabled,
  over_tls }`) and looking up `iostream` via `use` at ZON dispatch
  time instead of aliasing it into a top-level local. Per-connect
  cost is negligible; the comment in hub.lua documents the
  constraint so future refactors do not re-grow the local count
  without noticing.

  **zlib_stream is loaded as `_optional` in core/init.lua.** If the
  C module failed to build / link, the hub still starts; loadsettings
  detects `_cfg_zlif.enabled = true and use "zlib_stream" == false`
  and overrides to `false` with an out_error so ZLIF is silently
  disabled rather than crashing at connect time.

  **CI:** Linux job apt-installs `zlib1g-dev`; Windows MSYS2 job
  adds `mingw-w64-ucrt-x86_64-zlib`. Maintainer's local Windows
  MinGW needed a one-time zlib 1.3.2 source + libz.a static
  install into `C:\MinGW\{include,lib}` - documented in
  docs/BUILDING.md (TODO: actually add the note).

  Tests: iostream unit tests grow to 66/66 (was 51), with a
  mock-zlib `_real` shim entry so inflate/deflate stages can be
  unit-tested without loading the real C binding (standalone Lua
  cannot load the hub-bundled liblua-linked .dll). The real C
  binding is exercised via the new smoke test
  `test_zlif_roundtrip`: stops the hub, flips `zlif_enabled =
  true`, restarts, runs a full ADC login + `+help` reply over the
  zlib-compressed inbound (Python `zlib.decompressobj()`,
  matches Z_SYNC_FLUSH cadence). Default-off smoke run (47 tests)
  stays green unchanged.

  Next: security-focused two-pass review (decompression-bomb
  path, TLS-over-ZLIF cfg gate, ZON reshape correctness, missing-
  module graceful degradation) -> sub-PR into phase8-io ->
  phase8-io review gate -> phase8-io merge to master.

- 2026-05-21: S5 implemented on branch phase8-io-s5. **The LAST
  Phase-8 step.**
  - `core/bloom.lua` (new, pure-Lua membership oracle per ADC-EXT
    3.20 - bit slicing, modulo m, LSB-first per byte).
  - `core/iostream.lua` adds `newcountedstage(byte_count,
    callback)`. Captures exactly N bytes regardless of `\n`, fires
    callback once, then passes through. Pipeline reshape carries
    adcline's residual binary bytes into the new stage via the S4a
    prepend semantic - no further pipeline contract changes
    needed.
  - `core/adc.lua` adds `GET` / `SND` / `GFI` to
    `_protocol.commands` (the H-class context was already present;
    same ZON/ZOF lesson from S4b - both contexts AND commands
    tables need the entry for adc_parse to accept the wire shape).
  - `core/cfg_defaults.lua` adds `blom_enabled` (default false) +
    `blom_k` / `blom_h` / `blom_m` parameter validators (defaults
    k=6, h=16, m=32768 = 4 KiB filter per user). Cross-validation
    in `hub.lua` loadsettings: `k*h <= 192`, `2^h > m`, `m % 64 ==
    0`, `h % 8 == 0`, basexx loaded - failing any forces blom off
    with out_error.
  - `core/hub_user_object.lua` adds `user.setblom` / `user.getblom`
    / `user.supportsblom` accessors + a **write-side filter
    check** that wraps `client_write`. The wrap parses outbound
    BSCH/FSCH frames for a TR field; if present and the user's
    filter says definitely-not-present, the write is dropped
    silently. Keyword-search SCH (no TR) and all non-SCH writes
    early-exit to passthrough.
  - `core/hub_dispatch.lua` adds the `HSND` handler in `_normal`
    (validates type=blom + ident=/ + start=0 + bytes==m/8,
    installs the iostream counted-binary stage; the callback
    constructs a bloom filter and stores it on the user). HSUP
    SUP advertise gsubs `ADBLOM` alongside `ADZLIF` in a SINGLE
    pass (single-gsub refactor so both tokens accumulate
    correctly when both features are on).
  - `core/hub.lua` packs both ZLIF and BLOM cfg state into ONE
    `_cfg_p8` table (renamed from `_cfg_zlif`) because the
    200-locals-per-chunk ceiling is at exactly 200 again - the
    do/end block at the bottom of the file would push us over
    with any new top-level local. login() triggers HGET on
    NORMAL-state entry when both sides support BLOM.
  - **Architecture decision: write-side filter, NOT sender-side
    router.** A first-draft `_cfg_p8.blom.route` closure in
    hub.lua did the bloom check at the B/F-class broadcast fanout
    in incoming(). The smoke test exposed the flaw: bundled
    plugins (etc_trafficmanager) take over SCH fanout via the
    onSearch listener returning PROCESSED, which bypasses the
    default sendtoall / featuresend branch entirely. A
    sender-side hook therefore would not fire in real-world hubs
    that enable trafficmanager. Moved the check to the user
    object's client_write wrapper - works uniformly regardless of
    who is doing the fanout, with near-zero overhead on non-SCH
    writes and on writes to users without a filter installed.
    Removed the router closure + the B/F-class incoming hooks.
  - **Sandbox imports caught during smoke debug**: `tonumber` for
    hub_dispatch.lua (HSND parses the bytes positional),
    `pcall`/`string`/`string_sub`/`string_match` for the
    write-side filter check in hub_user_object.lua. Same lesson
    as the S4b iostream pcall - audit every Lua-stdlib name used
    in new core code against the file's existing `use` block.
  - **Tests**: `tests/unit/bloom_test.lua` (new, 13 checks: empty
    filter, insert+contains roundtrip, false-positive sanity at
    n=5 with m=32768 (0/200 positives observed), h=8 + h=24 slice
    widths, distinguishability). `tests/unit/iostream_test.lua`
    extended to 87 checks (counted-stage exact-budget, partial,
    over-budget, passthrough-after-fire, residual, BLOM-compose
    integration). Both wired into CI via smoke.yml's lua5.4 step.
    New `test_blom_roundtrip` smoke (single-user; the user-write
    filter check fires for the sender's own search-echo too,
    making the oracle observable without a second logged-in
    user). Three asserts: TTH in filter -> echo arrives; TTH not
    in filter -> NO echo; keyword-search -> echo arrives
    regardless (load-bearing spec-trap regression).
    Default-off smoke run unchanged at 49 tests; full run with
    BLOM mode added is 50 PASS.
  - Next: security-focused two-pass review (write-side filter
    correctness; hash-vs-keyword routing; spec-trap regression;
    HSND validation; bloom param cross-validation) -> sub-PR into
    phase8-io. After that: Phase-8 FINAL REVIEW GATE over the
    whole integration branch, then `phase8-io -> master` merge.
- 2026-05-21: **Phase-8 FINAL REVIEW GATE** (CLAUDE.md s1b.11) run
  over the full `master..phase8-io` diff: independent reviewer
  agent + plugin-repo impact sweep against `luadch-ng/scripts`.
  Plugin sweep: 36 plugins, 7 io-stack concerns checked, **0
  blockers / 0 concerns** (write-side BLOM filter is transparent
  to non-search frames; no plugin bypasses `client_write`; no
  plugin registers a handler on the new GET / SND / GFI / HSND
  commands; no plugin parses hard-coded SUP substrings affected
  by the new ADBLOM / ADZLIF advertise). Main-repo review: three
  fix-then-advance findings landed on the merge commit:
    - **B1** master commit 2a94cbf (#188, hub_listen / port-validation
      fix for #186) had been merged to master AFTER phase8-io branched.
      Squash-merging phase8-io -> master as-is would silently regress
      it. Resolved by merging master into phase8-io (the merge commit
      that closes this phase) and restoring `test_hub_listen_honored`
      to the smoke battery as the LAST test (mutates hub_listen +
      blanks v6).
    - **B2** dead optional-dep guard in `core/hub.lua` loadsettings
      (`use "zlib_stream" == false`). `core/init.lua`'s `use()` falls
      through to `loadscript` on a `false` slot, and `loadscript`
      short-circuits to `nil` for those - so `use "zlib_stream"`
      returns `nil`, not `false`. Result: an operator with
      `zlif_enabled = true` on a build without the C module sailed
      past the guard and crashed on the first ZON dispatch. Fixed to
      `not use "X"`; same shape applied to the `basexx` guard for
      consistency (latent there - basexx is in `_module` and always
      loaded).
    - **B3** the BLOM+ZLIF mutex mitigation introduced in S5 had no
      regression test. Added `test_blom_zlif_mutex_no_adblom`:
      handshakes with `ADBLOM ADZLIF` in HSUP, asserts ADBLOM is NOT
      in the hub's ISUP (and ADZLIF is - the surviving side of the
      mutex). Provably fails pre-fix; provably passes post-fix.
      *(Superseded later the same day by `test_blom_zlif_combined`
      when #192 cleared the mutex - see the next journal entry.)*
  Plus C3 (HSND `start` numeric compare for `0` / `00` / `+0`
  parity). C1 (TLS hardening flagged by the reviewer as a drive-by
  refactor) re-verified in-scope per commit 50cc561, dismissed.
  Windows smoke after the fixes: **52 PASS / 0 FAIL**.
  Sub-PR #193 (phase8-io -> master) opened with the full Phase-8
  recap + journal pointer. Phase-9 follow-up tracked in **#192**
  (BLOM+ZLIF combined-mode needs `insert_before_terminal` pipeline
  semantic; mutex mitigation ships in this release).
- 2026-05-21 (later): **#192 closed** as a Phase-8 follow-up PR
  rather than a Phase-9 kickoff (maintainer scope call). New
  pipeline op `insert_before_terminal(stage)` in `core/iostream.lua`
  splices a stage at position N-1; for 2-stage pipelines it pulls
  the OLD terminal's residual, drives it synchronously through the
  new stage (residual bytes are post-upstream-processing, so re-
  feeding via `input_buf` would re-run them through inflate /
  corrupt the stream), and parks any frames the terminal emits
  from that drain in a deferred FIFO that `next_frame` surfaces
  before resuming `_pull`. Empty-string guard on the deferred
  enqueue prevents a leading-`\n` tail from queuing a zero-length
  ADC frame (post-review concern). HSND dispatcher switched from
  `inframer_prepend` to `inframer_insert_before_terminal`; the
  S5-shipped `_cfg_p8.zlif.enabled` mutex branch in
  `loadsettings` removed; `examples/cfg/cfg.tbl` doc string for
  `blom_enabled` updated to describe the combined-mode behaviour
  instead of "mutually exclusive". The S5-shipped smoke
  `test_blom_zlif_mutex_no_adblom` is **superseded** by the new
  `test_blom_zlif_combined`: full HGET / BZON / compressed HSND /
  compressed BSCH roundtrip over a single zlib stream from the
  python harness, asserts both the in-filter TR echo and the
  not-in-filter TR drop. §1a.7 proof: temporarily reverting the
  dispatcher to `inframer_prepend` makes the combined test FAIL
  with "timed out waiting for BSCH echo" (counted captures
  deflated noise -> filter bits random -> inserted TTH misses its
  own filter), restoring the fix makes it PASS. Independent
  review caught two test-quality issues (1-stage unit test would
  not actually exercise the deferred FIFO path; empty-frame guard
  needed on the synchronous drain enqueue), both addressed before
  merge. Windows smoke after the fixes: **54 PASS / 0 FAIL**.
