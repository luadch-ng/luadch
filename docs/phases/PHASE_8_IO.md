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
