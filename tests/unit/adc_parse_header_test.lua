--[[

    tests/unit/adc_parse_header_test.lua

    Regression test for the ADC header-parameter parse crash.

    A 2-field-header message class (F / D / E, header.len == 2) that
    carries the fourcc plus only ONE header field slipped past the
    length gate: `if eol < len` accepts eol == len (fourcc + 1 field),
    then the header loop reads buffer[3] == nil and calls _regex.sid /
    _regex.feature with nil, which throw (string.match(nil,...) / #nil).
    That throw is uncaught all the way up (server.tick -> readbuffer ->
    dispatch -> incoming -> adc.parse, no pcall), so a single frame such
    as `FSCH AAAA` from an unauthenticated peer terminates the hub.

    This mirrors the positional-parameter fix (Phase 8a F-PRS-7): the
    fix requires eol >= len + 1 (fourcc + len header params) AND adds the
    param == nil guard the positional loop already has.

    Pure Lua, no hub, no sockets: stubs the `use` sandbox shim, loads the
    module, drives adc.parse under pcall.

    Run: lua tests/unit/adc_parse_header_test.lua   (any Lua 5.4)
    Exit code 0 = all pass, 1 = a failure (CI-friendly).

]]--

-- minimal sandbox shim: core/adc.lua does `local x = use "x"`. Keep this
-- in lockstep with adc.lua's `use` imports. parse() itself needs only the
-- string libs + out.put; the rest exist so module load-time aliasing
-- (adclib.hash, unicode.utf8.find, types.utf8, ...) does not nil-index.
local _real = {
    type = type, ipairs = ipairs, tostring = tostring,
    os = os, table = table, string = string, setmetatable = setmetatable,
    adclib = {
        isutf8 = function( ) return true end,
        hash = function( ) end,
        hashpas = function( ) end,
        random_bytes = function( n ) return string.rep( "\0", n or 0 ) end,
    },
    unicode = { utf8 = { find = string.find } },
    out = { put = function( ) end },
    types = { utf8 = function( ) end, check = function( ) end, add = function( ) end },
}
_G.use = function( name )
    local v = _real[ name ]
    assert( v ~= nil, "adc_parse_header_test shim missing dep: use \"" .. name .. "\"" )
    return v
end

local adc = assert( loadfile( "core/adc.lua" ) )( )

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-46s got=%q want=%q\n", label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

-- parse must never throw on malformed input; it returns nil on reject.
local function safeparse( frame )
    return pcall( adc.parse, frame )    -- ok, result
end

----------------------------------------------------------------------
-- Regression: 2-field-header classes (F / D / E) with fourcc + only one
-- header field. Pre-fix these crash in the header loop; post-fix they
-- are rejected (nil) at the length gate. AAAA is a syntactically valid
-- SID so field 1 passes and field 2 (missing) is the trigger. Covers
-- both header validators: _regex.feature (FSCH) and _regex.sid (D/E).
----------------------------------------------------------------------
for _, frame in ipairs( { "FSCH AAAA", "DCTM AAAA", "ECTM AAAA", "DMSG AAAA" } ) do
    local ok, res = safeparse( frame )
    eq( "short-header '" .. frame .. "' does not crash parse", ok, true )
    eq( "short-header '" .. frame .. "' rejected (nil)", ok and res, nil )
end

----------------------------------------------------------------------
-- Positive controls: valid frames must still parse (the length gate
-- change must not over-reject). B-class (len 1) and a full-header
-- D-class (len 2) frame both return a parsed command table.
----------------------------------------------------------------------
do
    local ok, res = safeparse( "BMSG AAAA hi" )
    eq( "valid BMSG does not crash", ok, true )
    eq( "valid BMSG parses (table)", ok and type( res ), "table" )
end
-- Header complete (B sid present) but the positional body missing: must
-- clean-reject via the positional nil-guard (F-PRS-7), not crash.
do
    local ok, res = safeparse( "BMSG AAAA" )
    eq( "BMSG missing body does not crash", ok, true )
    eq( "BMSG missing body rejected (nil)", ok and res, nil )
end
do
    local ok, res = safeparse( "DMSG AAAA BBBB hello" )
    eq( "valid DMSG does not crash", ok, true )
    eq( "valid DMSG parses (table)", ok and type( res ), "table" )
end

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
