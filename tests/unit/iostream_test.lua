--[[

    tests/unit/iostream_test.lua

    Committed unit test for core/iostream.lua (Phase 8 S1 + S2 + S3 +
    S4a). Pure Lua, no hub, no sockets: stubs the `use` sandbox shim,
    loads the module, asserts the stage/pipeline contract.

    S4a changed the pipeline contract from "feed -> get all frames" to
    a lazy iterator (`feed(bytes)`, `next() -> frame | nil`,
    `drain() -> frames` convenience). The tests use `drain()` for the
    S1/S2/S3 parity cases (one-line equivalent of the old `feed`
    shape) plus add explicit `next()` cases for the iterator
    behaviour and a ZON-style mid-chunk reshape case that exercises
    the load-bearing correctness fix S4b will rely on.

    Run: lua tests/unit/iostream_test.lua   (any Lua 5.4)
    Exit code 0 = all pass, 1 = a failure (CI-friendly).

    CI: wired into .github/workflows/smoke.yml's Linux job since S3
    (lua5.4 step ahead of the build).

]]--

-- minimal sandbox shim: core/iostream.lua does `local x = use "x"`.
-- Keep this in lockstep with iostream.lua's `use` imports.
--
-- zlib_stream is mocked: the real C binding cannot be loaded by a
-- standalone lua interpreter against the hub's bundled liblua. The
-- mock implements a trivial "compression" (prefix the input with
-- "C:") so we can verify the inflate / deflate STAGES wire the
-- module correctly + propagate errors. C-binding correctness is
-- covered by the smoke test (which runs the hub with real zlib).
local _mock_zlib_stream = {
    deflate = function( )
        return setmetatable( { }, { __index = {
            push = function( _, b ) return "C:" .. ( b or "" ) end,
        } } )
    end,
    inflate = function( )
        return setmetatable( { }, { __index = {
            push = function( _, b )
                if not b or b == "" then return "" end
                if b:sub( 1, 2 ) ~= "C:" then
                    error( "mock inflate: not compressed input" )
                end
                return b:sub( 3 )
            end,
        } } )
    end,
}

local _real = {
    string = string, table = table,
    setmetatable = setmetatable, tonumber = tonumber,
    pcall = pcall,    -- iostream.lua's S4b inflate stage pcall's the C binding
    zlib_stream = _mock_zlib_stream,
}
_G.use = function( name )
    local v = _real[ name ]
    assert( v ~= nil, "iostream_test shim missing dep: use \"" .. name .. "\"" )
    return v
end

local iostream = assert( loadfile( "core/iostream.lua" ) )( )

local NL, CR, BS = string.char( 10 ), string.char( 13 ), string.char( 92 )

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-34s got=%q want=%q\n", label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end
-- frames array -> single comparable string
local function j( t ) return "[" .. table.concat( t, "|" ) .. "]" end

-- S1/S2/S3 parity helper: behaviour-equivalent of the pre-S4a
-- "feed(bytes) -> frames, overflow" shape. The lazy iterator makes
-- this two calls; the helper hides that so the parity assertions
-- below read like the pre-S4a tests.
local function feed_drain( p, bytes )
    p:feed( bytes )
    return p:drain( )
end

----------------------------------------------------------------------
-- S1 parity: default 1-stage pipeline must be byte-identical to the
-- old newframer for every input class.
----------------------------------------------------------------------

local p = iostream.newpipeline( 1048576 )
eq( "single frame, escaped body",
    j( ( feed_drain( p, "BMSG AAAA +setpass" .. BS .. "snick" .. BS .. "smyself" .. BS .. "ssmoketestnew" .. NL ) ) ),
    "[BMSG AAAA +setpass\\snick\\smyself\\ssmoketestnew]" )

p = iostream.newpipeline( 1048576 )
eq( "fragmented part 1 -> no frame", j( ( feed_drain( p, "BMSG AAAA +he" ) ) ), "[]" )
eq( "fragmented part 2 -> reassembled", j( ( feed_drain( p, "lp" .. NL ) ) ), "[BMSG AAAA +help]" )

p = iostream.newpipeline( 1048576 )
eq( "two frames one feed",
    j( ( feed_drain( p, "BMSG AAAA +help" .. NL .. "BMSG AAAA +help" .. NL ) ) ),
    "[BMSG AAAA +help|BMSG AAAA +help]" )

p = iostream.newpipeline( 1048576 )
local fr, ov = feed_drain( p, "ABC" .. CR .. NL .. "DEF" .. NL .. "GHI" )
eq( "CRLF stripped + two frames", j( fr ), "[ABC|DEF]" )
eq( "no overflow on normal input", ov, false )
eq( "remainder kept then completed", j( ( feed_drain( p, NL ) ) ), "[GHI]" )

p = iostream.newpipeline( 1048576 )
eq( "embedded CR all stripped (*l recvline parity)",
    j( ( feed_drain( p, "BMSG x he" .. CR .. "ll" .. CR .. "o" .. CR .. NL ) ) ),
    "[BMSG x hello]" )

p = iostream.newpipeline( 8 )
local g, gov = feed_drain( p, "ABCDEFGHIJKL" )    -- 12 byte unterminated > maxlen 8
eq( "oversize unterminated -> overflow", gov, true )
eq( "oversize unterminated -> no frame yet", j( g ), "[]" )

----------------------------------------------------------------------
-- S2 surface: passthrough, composition, prepend ordering. The stage
-- contract changed in S4a (push -> single unit, not list); rebuilt
-- here against the new shape.
----------------------------------------------------------------------

local pt = iostream.newpassthroughstage( )
local u, o = pt:push( "raw" .. NL .. "bytes" )
eq( "passthrough re-emits input as one unit", u, "raw" .. NL .. "bytes" )
eq( "passthrough never overflows", o, false )

-- [passthrough, adcline] must behave exactly like [adcline], incl.
-- unterminated-remainder reassembly across feeds.
p = iostream.newpipeline( 1048576 )
p:prepend( iostream.newpassthroughstage( ) )
eq( "compose: frame split, 2nd held",
    j( ( feed_drain( p, "BMSG Z +help" .. NL .. "BMSG Z +x" ) ) ), "[BMSG Z +help]" )
eq( "compose: remainder completes across feed",
    j( ( feed_drain( p, "yz" .. NL ) ) ), "[BMSG Z +xyz]" )

-- prepend must run the new stage BEFORE the framer (the S4
-- inflate-before-framing ordering). A stage that turns 'X' into CR,
-- prepended, must let the framer then strip those CRs.
p = iostream.newpipeline( 1048576 )
local crstage = setmetatable( { }, { __index = {
    push = function( self, c )
        if c and c ~= "" then return ( c:gsub( "X", CR ) ), false end
        return nil, false
    end,
    residual = function( ) return "" end,
} } )
p:prepend( crstage )
eq( "prepend ordering: stage runs before framer",
    j( ( feed_drain( p, "aXbXc" .. NL ) ) ), "[abc]" )

----------------------------------------------------------------------
-- S4a iterator API: next() returns one frame at a time; drain()
-- collects to convenience array. Asserts the contract directly.
----------------------------------------------------------------------

p = iostream.newpipeline( 1048576 )
p:feed( "AAA" .. NL .. "BBB" .. NL .. "CCC" )
local f1 = p:next( ); local f2 = p:next( ); local f3 = p:next( )
eq( "next: frame 1", f1, "AAA" )
eq( "next: frame 2", f2, "BBB" )
eq( "next: only complete frames emitted", f3, nil )
p:feed( NL )
eq( "next: completes remainder on more bytes", p:next( ), "CCC" )
eq( "next: drained returns nil", p:next( ), nil )

----------------------------------------------------------------------
-- S4a multi-stage overflow propagation (sticky_overflow path). The
-- 1-stage default pipeline never exercises this - the upstream stage
-- in a 2-stage pipeline (e.g. S4b's inflate) signals overflow, and
-- next() must surface it on its return tuple regardless of which
-- iteration the upstream stage decided to overflow on. Reviewer N2
-- gate before S4b uses this in production.
----------------------------------------------------------------------

p = iostream.newpipeline( 1048576 )
local overflow_stage_fired = false
local overflow_stage = setmetatable( { }, { __index = {
    push = function( _, c )
        if overflow_stage_fired then return nil, false end
        if c and c ~= "" then
            overflow_stage_fired = true
            return c, true    -- emit unit AND signal overflow on same call
        end
        return nil, false
    end,
    residual = function( ) return "" end,
} } )
p:prepend( overflow_stage )
p:feed( "AAA" .. NL )
local mu, mov = p:next( )
eq( "multi-stage: upstream-stage overflow surfaces", mov, true )
eq( "multi-stage: unit still threaded through downstream", mu, "AAA" )

----------------------------------------------------------------------
-- S4a load-bearing fix: mid-chunk reshape. A "ZON\nXX\nYY\n" pattern
-- where the post-ZON suffix is opaque-to-framer bytes (here ASCII
-- standing in for compressed bytes for the unit test - the test does
-- not depend on actual zlib) must NOT have "XX" / "YY" dispatched
-- before the ZON-handler reshape. Modelled as: pull ZON, prepend a
-- byte-rewriting stage that maps the suffix bytes into something
-- the framer must see, assert the rewritten output emerges.
----------------------------------------------------------------------

p = iostream.newpipeline( 1048576 )
p:feed( "ZON" .. NL .. "XX" .. NL .. "YY" .. NL )
local first = p:next( )
eq( "reshape: first frame is ZON", first, "ZON" )
-- Splice in a stage that uppercases each byte chunk (stands in for
-- inflate). The post-ZON residual ("XX\nYY\n") was buffered in the
-- ADC-line stage's `buf`; prepend MUST route it through the new
-- stage so the resulting frames reflect the transform.
local upperstage = setmetatable( { }, { __index = {
    push = function( self, c )
        if c and c ~= "" then return ( c:lower( ) ), false end
        return nil, false
    end,
    residual = function( ) return "" end,
} } )
p:prepend( upperstage )
eq( "reshape: post-ZON suffix re-fed via new stage", p:next( ), "xx" )
eq( "reshape: continued through new stage", p:next( ), "yy" )
eq( "reshape: pipeline drains cleanly", p:next( ), nil )

----------------------------------------------------------------------
-- S3: hardened HTTP request-framer stage. Each reject case asserts the
-- transport-level rejection status; the happy cases assert the parsed
-- request. (Method policy 404/405 is the router's job, not the
-- framer's - see core/http.lua - so DELETE frames OK here.)
----------------------------------------------------------------------

local CRLF = CR .. NL
-- single-feed helper: returns the one emitted unit (or nil). S4a:
-- the stage emits a single unit, not a list.
local function httpreq( s )
    local st = iostream.newhttpstage( )
    return ( st:push( s ) )
end
-- describe a unit as a stable comparable string
local function du( u )
    if not u then return "NONE" end
    if u.reject then return "reject=" .. u.reject end
    return u.method .. " " .. u.target .. " " .. u.version
end

eq( "http: GET /health",
    du( httpreq( "GET /health HTTP/1.1" .. CRLF .. "Host: x" .. CRLF .. CRLF ) ),
    "GET /health HTTP/1.1" )
eq( "http: HEAD /health 1.0",
    du( httpreq( "HEAD /health HTTP/1.0" .. CRLF .. CRLF ) ),
    "HEAD /health HTTP/1.0" )
eq( "http: framer passes non-GET/HEAD (router 405s)",
    du( httpreq( "DELETE /health HTTP/1.1" .. CRLF .. CRLF ) ),
    "DELETE /health HTTP/1.1" )
eq( "http: Content-Length: 0 accepted",
    du( httpreq( "GET /health HTTP/1.1" .. CRLF .. "Content-Length: 0" .. CRLF .. CRLF ) ),
    "GET /health HTTP/1.1" )

eq( "http: bad version -> 505",
    du( httpreq( "GET /health HTTP/2.0" .. CRLF .. CRLF ) ), "reject=505" )
eq( "http: no space in request-line -> 400",
    du( httpreq( "GET/health HTTP/1.1" .. CRLF .. CRLF ) ), "reject=400" )
eq( "http: target not /-rooted -> 400",
    du( httpreq( "GET health HTTP/1.1" .. CRLF .. CRLF ) ), "reject=400" )
eq( "http: path traversal -> 400",
    du( httpreq( "GET /../etc HTTP/1.1" .. CRLF .. CRLF ) ), "reject=400" )
eq( "http: control byte in request-line -> 400",
    du( httpreq( "GET /h" .. string.char( 1 ) .. " HTTP/1.1" .. CRLF .. CRLF ) ), "reject=400" )
eq( "http: Transfer-Encoding rejected outright -> 400",
    du( httpreq( "GET /health HTTP/1.1" .. CRLF .. "Transfer-Encoding: chunked" .. CRLF .. CRLF ) ), "reject=400" )
eq( "http: multiple Content-Length -> 400",
    du( httpreq( "GET /health HTTP/1.1" .. CRLF .. "Content-Length: 0" .. CRLF .. "Content-Length: 0" .. CRLF .. CRLF ) ), "reject=400" )
eq( "http: non-zero body (Content-Length) -> 400",
    du( httpreq( "GET /health HTTP/1.1" .. CRLF .. "Content-Length: 5" .. CRLF .. CRLF ) ), "reject=400" )
eq( "http: non-numeric Content-Length -> 400",
    du( httpreq( "GET /health HTTP/1.1" .. CRLF .. "Content-Length: ab" .. CRLF .. CRLF ) ), "reject=400" )
eq( "http: obs-fold continuation rejected -> 400",
    du( httpreq( "GET /health HTTP/1.1" .. CRLF .. "X: a" .. CRLF .. " cont" .. CRLF .. CRLF ) ), "reject=400" )
eq( "http: whitespace in header name rejected -> 400 (CL/TE classifier bypass)",
    du( httpreq( "GET /health HTTP/1.1" .. CRLF .. "Content-Length : 0" .. CRLF .. CRLF ) ), "reject=400" )
eq( "http: oversize request-line -> 414",
    du( httpreq( "GET /" .. string.rep( "a", 9000 ) .. " HTTP/1.1" .. CRLF .. CRLF ) ), "reject=414" )

-- header-count cap -> 431
local manyhdrs = "GET /health HTTP/1.1" .. CRLF
for i = 1, 150 do manyhdrs = manyhdrs .. "X-h" .. i .. ": v" .. CRLF end
eq( "http: >100 headers -> 431", du( httpreq( manyhdrs .. CRLF ) ), "reject=431" )

-- oversize total before terminator -> 431 (slowloris / unbounded buf)
local big = iostream.newhttpstage( )
eq( "http: oversize pre-terminator -> 431",
    du( big:push( "GET /health HTTP/1.1" .. CRLF .. "X: " .. string.rep( "a", 17000 ) ) ),
    "reject=431" )

-- partial request reassembled across feeds
local hp = iostream.newhttpstage( )
eq( "http: partial feed 1 -> no unit", tostring( hp:push( "GET /heal" ) ), "nil" )
local hp2 = hp:push( "th HTTP/1.1" .. CRLF .. CRLF )
eq( "http: partial feed 2 -> request", du( hp2 ), "GET /health HTTP/1.1" )

-- one request per connection: stage goes inert after the first
local hi = iostream.newhttpstage( )
hi:push( "GET /health HTTP/1.1" .. CRLF .. CRLF )
eq( "http: inert after first request",
    tostring( hi:push( "GET /again HTTP/1.1" .. CRLF .. CRLF ) ), "nil" )

----------------------------------------------------------------------
-- #82 Phase 1 (docs/HTTP_API.md §2.1) framer body extension.
-- POST/PUT/PATCH/DELETE may carry a Content-Length-bounded body;
-- GET/HEAD body still rejected (smuggling defence).
----------------------------------------------------------------------

-- helper: feed `s` to a fresh stage and return (unit, body_or_nil).
local function http_with_body( s )
    local st = iostream.newhttpstage( )
    local u = st:push( s )
    if not u then return nil, nil end
    if u.reject then return u, nil end
    return u, u.body
end

-- POST with Content-Length: 0 (no body) -> success unit with body=""
do
    local u, b = http_with_body(
        "POST /v1/announce HTTP/1.1" .. CRLF
        .. "Content-Length: 0" .. CRLF .. CRLF
    )
    eq( "ibt: POST CL=0 method", u and u.method, "POST" )
    eq( "ibt: POST CL=0 body empty", b, "" )
end

-- POST with full body in same chunk -> success unit with body=<bytes>
do
    local body = '{"message":"hi"}'
    local u, b = http_with_body(
        "POST /v1/announce HTTP/1.1" .. CRLF
        .. "Content-Length: " .. #body .. CRLF .. CRLF .. body
    )
    eq( "ibt: POST one-chunk method", u and u.method, "POST" )
    eq( "ibt: POST one-chunk body", b, body )
end

-- POST body arriving across multiple pushes - the §2.1 state machine
-- core: accumulate across pushes, emit only when CL bytes collected.
do
    local body = '{"target":"baduser","duration_minutes":60}'
    local st = iostream.newhttpstage( )
    eq( "ibt: POST split header-only -> nil",
        tostring( st:push(
            "POST /v1/bans HTTP/1.1" .. CRLF
            .. "Content-Length: " .. #body .. CRLF .. CRLF
        ) ), "nil" )
    eq( "ibt: POST split mid-body -> nil",
        tostring( st:push( body:sub( 1, 10 ) ) ), "nil" )
    local u = st:push( body:sub( 11 ) )
    eq( "ibt: POST split complete -> method", u and u.method, "POST" )
    eq( "ibt: POST split complete -> body", u and u.body, body )
end

-- Header + body in the SAME chunk, then trailing bytes in a SECOND
-- push. The trailing bytes must be discarded (one request per
-- connection, the inert state kicks in after emit).
do
    local body = '{"x":1}'
    local st = iostream.newhttpstage( )
    local u = st:push(
        "POST /v1/announce HTTP/1.1" .. CRLF
        .. "Content-Length: " .. #body .. CRLF .. CRLF .. body
    )
    eq( "ibt: POST one-chunk emit", u and u.method, "POST" )
    eq( "ibt: POST trailing bytes discarded after emit",
        tostring( st:push( "trailing-garbage" ) ), "nil" )
end

-- POST with Content-Length: 65537 (> MAXBODY = 65536) -> 413 with NO
-- body bytes read. The reject must fire on the DECLARED CL value,
-- not on accumulated byte count - prevents per-request memory
-- amplification.
do
    local u = http_with_body(
        "POST /v1/announce HTTP/1.1" .. CRLF
        .. "Content-Length: 65537" .. CRLF .. CRLF
    )
    eq( "ibt: POST CL > MAXBODY -> 413", du( u ), "reject=413" )
end

-- PUT body accepted (the catalog uses PUT for password / nick / level
-- updates on /v1/registered/{nick}/*).
do
    local body = '{"password":"correct horse battery staple"}'
    local u, b = http_with_body(
        "PUT /v1/registered/dummy/password HTTP/1.1" .. CRLF
        .. "Content-Length: " .. #body .. CRLF .. CRLF .. body
    )
    eq( "ibt: PUT body accepted", u and u.method, "PUT" )
    eq( "ibt: PUT body content", b, body )
end

-- DELETE body accepted (DELETE /v1/users/{sid} carries {reason?}).
do
    local body = '{"reason":"spam"}'
    local u, b = http_with_body(
        "DELETE /v1/users/ABCD HTTP/1.1" .. CRLF
        .. "Content-Length: " .. #body .. CRLF .. CRLF .. body
    )
    eq( "ibt: DELETE body accepted", u and u.method, "DELETE" )
    eq( "ibt: DELETE body content", b, body )
end

-- PATCH body accepted.
do
    local body = '{"comment":"trusted"}'
    local u, b = http_with_body(
        "PATCH /v1/registered/dummy HTTP/1.1" .. CRLF
        .. "Content-Length: " .. #body .. CRLF .. CRLF .. body
    )
    eq( "ibt: PATCH body accepted", u and u.method, "PATCH" )
    eq( "ibt: PATCH body content", b, body )
end

-- HEAD with CL > 0 -> 400 (RFC 9110 §15.4.1).
do
    local u = http_with_body(
        "HEAD /v1/users HTTP/1.1" .. CRLF
        .. "Content-Length: 5" .. CRLF .. CRLF .. "12345"
    )
    eq( "ibt: HEAD CL > 0 -> 400", du( u ), "reject=400" )
end

-- HEAD with CL: 0 -> success (still no body, but explicit zero is
-- legal).
do
    local u = http_with_body(
        "HEAD /v1/users HTTP/1.1" .. CRLF
        .. "Content-Length: 0" .. CRLF .. CRLF
    )
    eq( "ibt: HEAD CL=0 ok", u and u.method, "HEAD" )
end

-- Smuggling defences preserved: TE on a POST still 400, multi-CL on
-- a POST still 400. The body-extension must NOT regress these.
do
    local u = http_with_body(
        "POST /v1/announce HTTP/1.1" .. CRLF
        .. "Transfer-Encoding: chunked" .. CRLF .. CRLF
    )
    eq( "ibt: POST TE -> 400 (smuggling)", du( u ), "reject=400" )
end
do
    local u = http_with_body(
        "POST /v1/announce HTTP/1.1" .. CRLF
        .. "Content-Length: 0" .. CRLF
        .. "Content-Length: 5" .. CRLF .. CRLF
    )
    eq( "ibt: POST multi-CL -> 400 (smuggling)", du( u ), "reject=400" )
end

-- POST with malformed CL value -> 400.
do
    local u = http_with_body(
        "POST /v1/announce HTTP/1.1" .. CRLF
        .. "Content-Length: ab" .. CRLF .. CRLF
    )
    eq( "ibt: POST CL malformed -> 400", du( u ), "reject=400" )
end

-- POST with body containing the CRLFCRLF byte sequence: the framer
-- must NOT mis-parse this as another header end. The header-end
-- search is scoped to bytes BEFORE the transition into collecting-
-- body, not on the buffer that grows during body collection.
do
    local body = "AAAA" .. CRLF .. CRLF .. "BBBB"    -- 12 bytes with CRLFCRLF in the middle
    local u, b = http_with_body(
        "POST /v1/announce HTTP/1.1" .. CRLF
        .. "Content-Length: " .. #body .. CRLF .. CRLF .. body
    )
    eq( "ibt: POST body with CRLFCRLF preserved", b, body )
    eq( "ibt: POST body length sanity", #b, 12 )
end

-- Body exactly at MAXBODY boundary (CL = 65536) -> success. Locks
-- the off-by-one against the CL > MAXBODY -> 413 case above.
do
    local body = string.rep( "x", 65536 )
    local u, b = http_with_body(
        "POST /v1/announce HTTP/1.1" .. CRLF
        .. "Content-Length: 65536" .. CRLF .. CRLF .. body
    )
    eq( "ibt: POST CL == MAXBODY -> success", u and u.method, "POST" )
    eq( "ibt: POST CL == MAXBODY body length", b and #b, 65536 )
end

-- Body containing NUL bytes - the framer must be byte-transparent.
-- A naive header-parser that strtok'd on NUL would truncate; the
-- byte-precise sub() / find() Lua primitives keep it whole.
do
    local body = "before" .. string.char( 0 ) .. "after" .. string.char( 0, 0, 0 )
    local u, b = http_with_body(
        "POST /v1/announce HTTP/1.1" .. CRLF
        .. "Content-Length: " .. #body .. CRLF .. CRLF .. body
    )
    eq( "ibt: POST body with NUL bytes preserved", b, body )
    eq( "ibt: POST body NUL count", #b, #body )
end

-- Lowercase method ("post") rejected by the request-line regex
-- `^(%u+)`. Pins the case-sensitivity so a future Phase-1b "let's
-- be lenient with case" cannot silently regress.
do
    local u = http_with_body(
        "post /v1/announce HTTP/1.1" .. CRLF
        .. "Content-Length: 0" .. CRLF .. CRLF
    )
    eq( "ibt: lowercase method -> 400", du( u ), "reject=400" )
end

-- GET with non-zero Content-Length -> 400. The implementation
-- explicitly rejects bodies on non-write methods (smuggling
-- vector); pin it so a future "RFC says GET MAY carry a body"
-- relaxation requires an explicit decision.
do
    local u = http_with_body(
        "GET /v1/users HTTP/1.1" .. CRLF
        .. "Content-Length: 5" .. CRLF .. CRLF .. "12345"
    )
    eq( "ibt: GET CL > 0 -> 400", du( u ), "reject=400" )
end

----------------------------------------------------------------------
-- S4a outbound passthrough pipeline: identity transform, default.
-- Prepending more passthrough stages must stay identity.
----------------------------------------------------------------------

local op = iostream.newoutpipeline( )
eq( "out: passthrough is identity", op:write( "BMSG x +help" .. NL ), "BMSG x +help" .. NL )
eq( "out: empty input -> empty output", op:write( "" ), "" )

-- A test stage that uppercases its input - asserts stage ordering:
-- stage[1] (prepended) runs first, then stage[2] (the existing
-- passthrough) - so the final output is uppercased.
local upper_out = setmetatable( { }, { __index = {
    write = function( _, b ) return ( b:upper( ) ) end,
} } )
op:prepend( upper_out )
eq( "out: prepended stage runs first", op:write( "hello" ), "HELLO" )

-- Two prepended stages: stage1 (added 2nd, ends up at front) -> stage2
-- (added 1st, now stage 2) -> passthrough. So the input runs front-to-back.
local op2 = iostream.newoutpipeline( )
local add_x = setmetatable( { }, { __index = { write = function( _, b ) return b .. "X" end } } )
local add_y = setmetatable( { }, { __index = { write = function( _, b ) return b .. "Y" end } } )
op2:prepend( add_y )    -- stages = { add_y, passthrough }
op2:prepend( add_x )    -- stages = { add_x, add_y, passthrough }
eq( "out: prepend ordering (front-to-back)", op2:write( "a" ), "aXY" )

----------------------------------------------------------------------
-- S4b ZLIF stages. Wires the iostream stage shapes against the
-- mock zlib_stream installed at the top of this file. The mock
-- prefixes input with "C:" for "compression", strips it for
-- "decompression", and errors on bad input - just enough surface to
-- prove the stages a) call the C-binding method, b) propagate
-- errors as overflow, c) compose with the framer the way ZLIF
-- needs (inflate prepended ahead of adcline = decompress-then-frame
-- chain).
----------------------------------------------------------------------

-- inbound inflate stage: wraps zlib_stream.inflate.
local inf = iostream.newinflatestage( )
local infunit, infov = inf:push( "C:hello" )
eq( "inflate: pushes through mock zlib", infunit, "hello" )
eq( "inflate: no overflow on success", infov, false )
-- residual is always "" - inflate has no movable input buffer.
eq( "inflate: residual is empty", inf:residual( ), "" )
-- empty input -> no unit.
local inf2 = iostream.newinflatestage( )
local emptyunit, emptyov = inf2:push( "" )
eq( "inflate: empty input -> nil unit", emptyunit, nil )
eq( "inflate: empty input -> no overflow", emptyov, false )
-- malformed compressed input -> mock errors -> stage signals overflow.
local inf3 = iostream.newinflatestage( )
local badunit, badov = inf3:push( "not-compressed" )
eq( "inflate: malformed input -> overflow", badov, true )
eq( "inflate: malformed input -> nil unit", badunit, nil )

-- Composition: prepend inflate ahead of the ADC-line framer. Feed a
-- "compressed" stream that decompresses to two ADC frames. Asserts
-- inflate -> adcline ordering (the ZLIF runtime topology).
local zp = iostream.newpipeline( 1048576 )
zp:prepend( iostream.newinflatestage( ) )
zp:feed( "C:BMSG x +help" .. NL .. "BMSG x +done" .. NL )
local zf1 = zp:next( ); local zf2 = zp:next( ); local zf3 = zp:next( )
eq( "ZLIF compose: frame 1 after inflate", zf1, "BMSG x +help" )
eq( "ZLIF compose: frame 2 after inflate", zf2, "BMSG x +done" )
eq( "ZLIF compose: pipeline drains", zf3, nil )

-- The full reshape sequence that S4b's ZON dispatcher will execute:
-- arrive with "ZON\n<compressed-tail>" in one chunk, dispatch ZON,
-- prepend inflate, the residual compressed-tail emerges as
-- decompressed ADC frames through the new pipeline. This is the
-- *integration* of S4a's reshape and S4b's inflate stage.
local rp = iostream.newpipeline( 1048576 )
rp:feed( "ZON" .. NL .. "C:BMSG x +help" .. NL )
local rf1 = rp:next( )
eq( "ZON reshape: first frame is ZON", rf1, "ZON" )
rp:prepend( iostream.newinflatestage( ) )
eq( "ZON reshape: post-ZON tail decompressed + framed", rp:next( ), "BMSG x +help" )

-- outbound deflate stage: wraps zlib_stream.deflate. write(bytes) =
-- compressed bytes. Empty input -> empty output.
local df = iostream.newdeflatestage( )
eq( "deflate: pushes through mock zlib", df:write( "hello" ), "C:hello" )
eq( "deflate: empty input -> empty output", df:write( "" ), "" )

-- Composition: prepend deflate ahead of the outbound passthrough.
-- Asserts the outbound topology for ZLIF (deflate runs FIRST, then
-- the rest of the stack = nothing meaningful in S4b, just identity).
local zop = iostream.newoutpipeline( )
zop:prepend( iostream.newdeflatestage( ) )
eq( "ZLIF outbound: write deflated", zop:write( "BMSG hi" .. NL ), "C:BMSG hi" .. NL )

----------------------------------------------------------------------
-- S5 BLOM counted-binary capture stage. Captures exactly N bytes
-- (regardless of `\n`), fires callback once with the captured blob,
-- then passes any subsequent input through to the next stage
-- unchanged. The BLOM HSND handler in hub_dispatch wires this up
-- via inframer:prepend() so the post-HSND-header binary payload is
-- routed away from adcline.
----------------------------------------------------------------------

-- exact-budget capture: 8 bytes in one push, callback fires once,
-- stage emits nothing as a unit.
do
    local captured, calls = nil, 0
    local cs = iostream.newcountedstage( 8, function( blob )
        captured = blob; calls = calls + 1
    end )
    local u, ov = cs:push( "ABCDEFGH" )
    eq( "counted: exact-budget no unit emitted", u, nil )
    eq( "counted: exact-budget no overflow", ov, false )
    eq( "counted: exact-budget callback fired once", calls, 1 )
    eq( "counted: exact-budget captured bytes", captured, "ABCDEFGH" )
end

-- partial-then-complete capture across multiple pushes.
do
    local captured, calls = nil, 0
    local cs = iostream.newcountedstage( 8, function( blob )
        captured = blob; calls = calls + 1
    end )
    local u1 = cs:push( "ABC" )
    local u2 = cs:push( "DEFG" )
    local u3 = cs:push( "H" )
    eq( "counted: partial push 1 -> nil", u1, nil )
    eq( "counted: partial push 2 -> nil", u2, nil )
    eq( "counted: partial push 3 -> nil (finalising)", u3, nil )
    eq( "counted: callback fired exactly once", calls, 1 )
    eq( "counted: captured assembled blob", captured, "ABCDEFGH" )
end

-- over-budget: incoming chunk exceeds remaining budget; the tail
-- emerges as the stage's emitted unit (which the next stage in the
-- pipeline will consume).
do
    local captured, calls = nil, 0
    local cs = iostream.newcountedstage( 4, function( blob )
        captured = blob; calls = calls + 1
    end )
    local u, ov = cs:push( "ABCDEFGH" )
    eq( "counted: over-budget callback fires", calls, 1 )
    eq( "counted: over-budget captured matches budget", captured, "ABCD" )
    eq( "counted: over-budget tail emitted as unit", u, "EFGH" )
    eq( "counted: over-budget no overflow", ov, false )
end

-- post-capture passthrough: subsequent pushes flow through
-- unchanged, the callback never fires again.
do
    local captured, calls = nil, 0
    local cs = iostream.newcountedstage( 4, function( blob )
        captured = blob; calls = calls + 1
    end )
    cs:push( "ABCD" )
    eq( "counted: passthrough callback count after fill", calls, 1 )
    local u1 = cs:push( "EFG" )
    eq( "counted: passthrough relays input as unit", u1, "EFG" )
    eq( "counted: passthrough callback not refired", calls, 1 )
    local u2 = cs:push( "X" .. NL .. "Y" )
    eq( "counted: passthrough relays NL-containing input verbatim", u2, "X" .. NL .. "Y" )
end

-- residual is always "" (the counted stage has no movable
-- pre-prepend bytes; the S4a reshape feeds it through input_buf).
do
    local cs = iostream.newcountedstage( 4, function( ) end )
    eq( "counted: residual is empty", cs:residual( ), "" )
end

-- Integration with the inbound pipeline: HSND-style scenario where
-- the header arrives via the ADC-line stage and the binary payload
-- arrives in the SAME chunk (so adcline's residual buf carries the
-- binary bytes through the prepend reshape into the new counted
-- stage). The captured blob can contain `\n` - the binary nature
-- of the counted stage is the whole reason it exists.
do
    local binary_blob = "B1" .. NL .. "B2" .. NL .. "B3"  -- 8 bytes, has \n
    p = iostream.newpipeline( 1048576 )
    p:feed( "HSND blom / 0 8" .. NL .. binary_blob )
    local frame = p:next( )
    eq( "BLOM compose: first frame is HSND header", frame, "HSND blom / 0 8" )

    local captured
    p:prepend( iostream.newcountedstage( 8, function( blob ) captured = blob end ) )

    -- pull until pipeline drains. The counted stage swallows all 8
    -- bytes from adcline's residual without emitting them; nothing
    -- else is buffered, so next() returns nil.
    local extra = p:next( )
    eq( "BLOM compose: counted stage swallowed binary, no further frame", extra, nil )
    eq( "BLOM compose: counted callback fired with the full binary blob",
        captured, binary_blob )
end

----------------------------------------------------------------------
-- #192 insert_before_terminal: pipeline splice operation that puts
-- the new stage at position N-1 (immediately before the current
-- terminal). Needed when ZLIF + BLOM are both active: the BLOM
-- counted-binary capture must sit AFTER inflate (so it captures the
-- decompressed filter bytes), but BEFORE the ADC-line framer (so
-- binary content with \n is not misinterpreted as frames). The
-- prepend semantic from S4a sits the new stage at the FRONT, which
-- is wrong when ZLIF is active because counted then sees raw
-- deflated wire bytes.

-- Degenerate case: 1-stage pipeline. insert_before_terminal must
-- behave identically to prepend - there is no terminal to insert
-- "before" if the pipeline has nothing else, so the new stage
-- becomes the front-and-only-non-terminal, matching prepend's
-- ordering exactly.
do
    local captured
    p = iostream.newpipeline( 1048576 )
    p:feed( "HSND blom / 0 5" .. NL .. "ABCDE" )
    local frame = p:next( )
    eq( "ibt 1-stage: first frame is HSND header", frame, "HSND blom / 0 5" )
    p:insert_before_terminal(
        iostream.newcountedstage( 5, function( blob ) captured = blob end )
    )
    eq( "ibt 1-stage: no further frame (counted swallowed binary)", p:next( ), nil )
    eq( "ibt 1-stage: counted callback fired with full blob",
        captured, "ABCDE" )
end

-- Two-stage pipeline (inflate, adcline): feed a deflated stream
-- containing `HSND blom / 0 8\nB1\nB2\nB3` where the binary blob
-- contains \n bytes. Insert counted before terminal AFTER the
-- HSND header surfaces. The inserted stage must capture the
-- post-inflate bytes (the binary blob), NOT the raw deflated wire
-- bytes. Equivalent test against the OLD prepend semantic FAILS
-- (counted would see deflated noise) - this is the §1a.7
-- pre-fix-fails proof at the unit level. Uses the "C:"-prefix
-- mock deflate format from the file-top shim.
do
    local binary_blob = "B1" .. NL .. "B2" .. NL .. "B3"    -- 8 bytes, has \n
    local plaintext = "HSND blom / 0 8" .. NL .. binary_blob
    local compressed = "C:" .. plaintext

    p = iostream.newpipeline( 1048576 )
    p:prepend( iostream.newinflatestage( ) )    -- topology: [inflate, adcline]
    p:feed( compressed )
    local frame = p:next( )
    eq( "ibt 2-stage: first frame is HSND header (post-inflate)",
        frame, "HSND blom / 0 8" )

    local captured
    p:insert_before_terminal(
        iostream.newcountedstage( 8, function( blob ) captured = blob end )
    )

    eq( "ibt 2-stage: no further frame (counted swallowed binary)", p:next( ), nil )
    eq( "ibt 2-stage: counted captured DECOMPRESSED blob (not zlib noise)",
        captured, binary_blob )
end

-- Edge: residual contains the COMPLETE blob plus tail bytes whose
-- first byte is NOT `\n`, so counted's >budget tail produces a
-- non-empty frame from adcline at splice time. The frame must
-- surface via the deferred FIFO on the next next() call - not be
-- lost. Needs a 2-stage pipeline (the path that actually exercises
-- the synchronous-drain + deferred-FIFO code; a 1-stage pipeline
-- would fall through to prepend and the callback would not fire
-- at splice time). Layout: blob = "12345" (5 bytes, exactly the
-- budget), tail = "67\nBMSG AAAA hi\n". counted's tail "67\nBMSG..."
-- fed to adcline emits "67" as the deferred frame, leaves
-- "BMSG AAAA hi\n" buffered for the next normal pull. Uses the
-- "C:"-prefix mock deflate format so the test works against a
-- standalone lua interpreter.
do
    local binary_blob = "12345"
    local plaintext = "HSND blom / 0 5" .. NL .. binary_blob .. "67" .. NL .. "BMSG AAAA hi" .. NL
    local compressed = "C:" .. plaintext

    p = iostream.newpipeline( 1048576 )
    p:prepend( iostream.newinflatestage( ) )    -- topology: [inflate, adcline]
    p:feed( compressed )
    eq( "ibt deferred: HSND header (post-inflate)",
        p:next( ), "HSND blom / 0 5" )

    local captured
    p:insert_before_terminal(
        iostream.newcountedstage( 5, function( blob ) captured = blob end )
    )

    eq( "ibt deferred: counted captured the budget bytes synchronously",
        captured, binary_blob )
    -- The first surfaced frame is the deferred one ("67"); the
    -- second comes from the normal post-deferred pull.
    eq( "ibt deferred: tail's first frame surfaces via deferred FIFO",
        p:next( ), "67" )
    eq( "ibt deferred: trailing buffered frame drains normally",
        p:next( ), "BMSG AAAA hi" )
    eq( "ibt deferred: nothing else queued", p:next( ), nil )
end

-- Edge: residual tail contains MULTIPLE frames after the counted
-- blob. With the eager-drain semantic, all N frames should be
-- enqueued in the deferred queue at splice time (not only frame #1
-- with #2..N stranded in adcline's buf waiting for the next TCP
-- read). Layout: blob = "12345" (5 bytes), post-blob tail =
-- "67\nM1\nM2\n" (3 frames in the tail).
do
    local binary_blob = "12345"
    local plaintext = "HSND blom / 0 5" .. NL .. binary_blob
        .. "67" .. NL .. "M1" .. NL .. "M2" .. NL
    local compressed = "C:" .. plaintext

    p = iostream.newpipeline( 1048576 )
    p:prepend( iostream.newinflatestage( ) )
    p:feed( compressed )
    p:next( )    -- swallow HSND header

    local captured
    p:insert_before_terminal(
        iostream.newcountedstage( 5, function( blob ) captured = blob end )
    )
    eq( "ibt multi-frame deferred: blob captured", captured, binary_blob )
    -- All 3 tail frames must have been eagerly drained into the
    -- deferred queue at splice time (issue #192 review C2).
    eq( "ibt multi-frame deferred: frame 1", p:next( ), "67" )
    eq( "ibt multi-frame deferred: frame 2", p:next( ), "M1" )
    eq( "ibt multi-frame deferred: frame 3", p:next( ), "M2" )
    eq( "ibt multi-frame deferred: nothing else queued",
        p:next( ), nil )
end

-- Edge: blob ends EXACTLY on a `\n` (the >budget tail starts with
-- `\n`). Adcline's first push therefore returns "" (the slice
-- before the leading `\n` is empty). The empty-string guard in
-- insert_before_terminal must NOT enqueue that empty frame; the
-- frame AFTER the leading `\n` should still surface via the
-- subsequent next() driving adcline normally.
do
    local binary_blob = "12345678"    -- 8 bytes, no \n
    local tail_frame = "BMSG AAAA hi"
    -- binary_blob immediately followed by `\n` then the frame -
    -- counted's tail starts with `\n` so adcline.push returns ""
    -- on its first call.
    local plaintext = "HSND blom / 0 8" .. NL .. binary_blob .. NL .. tail_frame .. NL
    -- Already the same plaintext as above; the SAME shape exercises
    -- the empty-leading-newline guard because counted's tail is
    -- (length - 8) bytes = NL + tail_frame + NL = leading-\n case.
    local compressed = "C:" .. plaintext

    p = iostream.newpipeline( 1048576 )
    p:prepend( iostream.newinflatestage( ) )
    p:feed( compressed )
    p:next( )    -- swallow HSND header

    local captured
    p:insert_before_terminal(
        iostream.newcountedstage( 8, function( blob ) captured = blob end )
    )
    eq( "ibt empty-frame guard: blob captured", captured, binary_blob )
    -- The deferred FIFO must NOT contain an empty string from the
    -- first adcline emit (which saw the leading `\n` and returned
    -- ""). The next surfaced frame is the real trailing one.
    eq( "ibt empty-frame guard: empty leading frame not enqueued",
        p:next( ), tail_frame )
    eq( "ibt empty-frame guard: nothing else queued",
        p:next( ), nil )
end

-- Edge: empty residual on the terminal at splice time. No
-- synchronous drain happens; the deferred FIFO stays empty;
-- subsequent feed() drives the pipeline through the inserted
-- stage normally. Uses the "C:"-prefix mock deflate format.
do
    p = iostream.newpipeline( 1048576 )
    p:prepend( iostream.newinflatestage( ) )    -- 2-stage, terminal empty
    local captured
    p:insert_before_terminal(
        iostream.newcountedstage( 4, function( blob ) captured = blob end )
    )
    -- Pipeline shape now: [inflate, counted, adcline].
    -- Feed mock-compressed `XXXX` (4 bytes, no \n) - counted
    -- swallows it post-inflate and fires the callback.
    p:feed( "C:XXXX" )
    eq( "ibt empty-residual: no frame surfaces (counted swallowed)", p:next( ), nil )
    eq( "ibt empty-residual: counted captured the 4 bytes",
        captured, "XXXX" )
    -- After capture, counted is in passthrough. Feed a mock-
    -- compressed ADC frame; it should now make it to the terminal.
    p:feed( "C:BMSG AAAA hi" .. NL )
    eq( "ibt empty-residual: post-capture passthrough surfaces frame",
        p:next( ), "BMSG AAAA hi" )
end

----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
