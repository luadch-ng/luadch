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
local _real = {
    string = string, table = table,
    setmetatable = setmetatable, tonumber = tonumber,
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

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
