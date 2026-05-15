--[[

    tests/unit/iostream_test.lua

    Committed unit test for core/iostream.lua (Phase 8 S1 + S2). Pure
    Lua, no hub, no sockets: stubs the `use` sandbox shim, loads the
    module, asserts the stage/pipeline contract.

    Why this exists: S1/S2 were verified with throwaway scripts, which
    prove nothing for the next person (CLAUDE.md s1a.7). The S2
    pre-merge review flagged the new abstraction surface (passthrough,
    multi-stage fan-in, prepend ordering) as having no committed
    regression - that surface is what S4 (ZLIF inflate spliced ahead of
    the framer via pipeline:prepend) will rely on. This file is the
    durable regression for it.

    Run: lua tests/unit/iostream_test.lua   (any Lua 5.4)
    Exit code 0 = all pass, 1 = a failure (CI-friendly).

    CI wiring: not run by .github/workflows/smoke.yml yet (that harness
    is Python and the build does not emit a standalone lua interpreter).
    The neutral path is already CI-guarded transitively by the S1
    protocol smoke tests (a 1-stage pipeline is byte-identical to the
    S1 framer, so test_s1_fragmented_frame_reassembled /
    test_s1_two_frames_one_segment would break if framing regressed).
    Wiring this file into CI is an explicit gate before S4 lands (see
    docs/phases/PHASE_8_IO.md) - S4 already touches the build for the
    zlib dependency, so the lua-unit runner is in-scope there.

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

----------------------------------------------------------------------
-- S1 parity: default 1-stage pipeline must be byte-identical to the
-- old newframer for every input class.
----------------------------------------------------------------------

local p = iostream.newpipeline( 1048576 )
eq( "single frame, escaped body",
    j( ( p:feed( "BMSG AAAA +setpass" .. BS .. "snick" .. BS .. "smyself" .. BS .. "ssmoketestnew" .. NL ) ) ),
    "[BMSG AAAA +setpass\\snick\\smyself\\ssmoketestnew]" )

p = iostream.newpipeline( 1048576 )
eq( "fragmented part 1 -> no frame", j( ( p:feed( "BMSG AAAA +he" ) ) ), "[]" )
eq( "fragmented part 2 -> reassembled", j( ( p:feed( "lp" .. NL ) ) ), "[BMSG AAAA +help]" )

p = iostream.newpipeline( 1048576 )
eq( "two frames one feed",
    j( ( p:feed( "BMSG AAAA +help" .. NL .. "BMSG AAAA +help" .. NL ) ) ),
    "[BMSG AAAA +help|BMSG AAAA +help]" )

p = iostream.newpipeline( 1048576 )
local fr, ov = p:feed( "ABC" .. CR .. NL .. "DEF" .. NL .. "GHI" )
eq( "CRLF stripped + two frames", j( fr ), "[ABC|DEF]" )
eq( "no overflow on normal input", ov, false )
eq( "remainder kept then completed", j( ( p:feed( NL ) ) ), "[GHI]" )

p = iostream.newpipeline( 1048576 )
eq( "embedded CR all stripped (*l recvline parity)",
    j( ( p:feed( "BMSG x he" .. CR .. "ll" .. CR .. "o" .. CR .. NL ) ) ),
    "[BMSG x hello]" )

p = iostream.newpipeline( 8 )
local g, gov = p:feed( "ABCDEFGHIJKL" )    -- 12 byte unterminated > maxlen 8
eq( "oversize unterminated -> overflow", gov, true )
eq( "oversize unterminated -> no frame yet", j( g ), "[]" )

----------------------------------------------------------------------
-- S2 new surface: passthrough, composition, prepend ordering.
----------------------------------------------------------------------

local pt = iostream.newpassthroughstage( )
local u, o = pt:push( "raw" .. NL .. "bytes" )
eq( "passthrough re-emits input as one unit", j( u ), "[raw\nbytes]" )
eq( "passthrough never overflows", o, false )

-- [passthrough, adcline] must behave exactly like [adcline], incl.
-- unterminated-remainder reassembly across feeds.
p = iostream.newpipeline( 1048576 )
p:prepend( iostream.newpassthroughstage( ) )
eq( "compose: frame split, 2nd held",
    j( ( p:feed( "BMSG Z +help" .. NL .. "BMSG Z +x" ) ) ), "[BMSG Z +help]" )
eq( "compose: remainder completes across feed",
    j( ( p:feed( "yz" .. NL ) ) ), "[BMSG Z +xyz]" )

-- prepend must run the new stage BEFORE the framer (the S4
-- inflate-before-framing ordering). A stage that turns 'X' into CR,
-- prepended, must let the framer then strip those CRs.
p = iostream.newpipeline( 1048576 )
local crstage = setmetatable( { }, { __index = { push = function( _, c )
    return { ( c:gsub( "X", CR ) ) }, false
end } } )
p:prepend( crstage )
eq( "prepend ordering: stage runs before framer",
    j( ( p:feed( "aXbXc" .. NL ) ) ), "[abc]" )

----------------------------------------------------------------------
-- S3: hardened HTTP request-framer stage. Each reject case asserts the
-- transport-level rejection status; the happy cases assert the parsed
-- request. (Method policy 404/405 is the router's job, not the
-- framer's - see core/http.lua - so DELETE frames OK here.)
----------------------------------------------------------------------

local CRLF = CR .. NL
-- single-feed helper: returns the one emitted unit (or nil)
local function httpreq( s )
    local st = iostream.newhttpstage( )
    local u = st:push( s )
    return u[ 1 ]
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
    du( ( big:push( "GET /health HTTP/1.1" .. CRLF .. "X: " .. string.rep( "a", 17000 ) ) )[ 1 ] ),
    "reject=431" )

-- partial request reassembled across feeds
local hp = iostream.newhttpstage( )
eq( "http: partial feed 1 -> no unit", j( ( hp:push( "GET /heal" ) ) ), "[]" )
local hp2 = ( hp:push( "th HTTP/1.1" .. CRLF .. CRLF ) )[ 1 ]
eq( "http: partial feed 2 -> request", du( hp2 ), "GET /health HTTP/1.1" )

-- one request per connection: stage goes inert after the first
local hi = iostream.newhttpstage( )
hi:push( "GET /health HTTP/1.1" .. CRLF .. CRLF )
eq( "http: inert after first request",
    j( ( hi:push( "GET /again HTTP/1.1" .. CRLF .. CRLF ) ) ), "[]" )

----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
