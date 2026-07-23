--[[

    tests/unit/util_string_test.lua

    Unit tests for core/util.lua's string helpers: trimstring, encode,
    decode. First-ever coverage of these three (#453) - they carried a
    dead type guard for 15 years precisely because nothing tested them.

    #453 hardening (Option A):
      - trimstring requires a string. A non-string now returns
        (nil, err) instead of the stringified garbage the old
        `local str = tostring( str )` shadow produced. trimstring( nil )
        used to return the literal "nil" - a data-corruption footgun.
      - encode / decode are DELIBERATELY left coercing (zero callers,
        harmless round-trip). This test pins that behaviour so a future
        "consistency" change to them is a conscious decision, not a slip.

    Regression proof (§1a.7): the non-string trimstring cases FAIL on
    the unpatched module (they return "nil" / "123" / "table: 0x..",
    not nil) and PASS patched.

    Run: lua5.4 tests/unit/util_string_test.lua   (from repo root)
    Exit 0 = all pass, 1 = a failure (CI-friendly).

]]--

----------------------------------------------------------------------
-- shim layer: stub `use` so util.lua loads in isolation
-- (mirrors tests/unit/util_safe_path_test.lua)
----------------------------------------------------------------------

local _io_stub = {
    open = function( ) return nil, "stubbed io.open" end,
}
local _adclib_stub = {
    isutf8 = function( ) return true end,
    random_bytes = function( ) return "x" end,
}
local _unicode_stub = {
    ascii = { sub = string.sub, gsub = string.gsub },
    utf8  = { format = string.format },
}
local _out_stub = { put = function( ) end, error = function( ) end }
local _mem_stub = { free = function( ) end }

local _real = {
    type = type, load = load, table = table, pairs = pairs,
    pcall = pcall, select = select, ipairs = ipairs,
    tostring = tostring, tonumber = tonumber, loadfile = loadfile,
    setmetatable = setmetatable,
    io = _io_stub, math = math, string = string, os = os,
    package = package,
    adclib = _adclib_stub, unicode = _unicode_stub,
    out = _out_stub, mem = _mem_stub,
}
_G.use = function( name )
    local v = _real[ name ]
    assert( v ~= nil, "util_string_test shim missing dep: use \"" .. name .. "\"" )
    return v
end

local util = assert( loadfile( "core/util.lua" ) )( )
util.init( )

----------------------------------------------------------------------
-- minimal test framework
----------------------------------------------------------------------

local failures, checks = 0, 0

local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-58s got=%q want=%q\n",
            label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

-- Assert the call returns nil + a non-empty diagnostic string.
local function rejects( label, ... )
    checks = checks + 1
    local got, err = util.trimstring( ... )
    if got == nil and type( err ) == "string" and #err > 0 then
        io.write( string.format( "ok   %-58s (%s)\n", label, err ) )
    else
        failures = failures + 1
        io.write( string.format( "FAIL %-58s got=%q err=%q\n",
            label, tostring( got ), tostring( err ) ) )
    end
end

----------------------------------------------------------------------
-- 1. trimstring: valid string inputs (unchanged behaviour)
----------------------------------------------------------------------

eq( "trim: surrounding spaces",   util.trimstring( "  hello  " ), "hello" )
eq( "trim: no whitespace",        util.trimstring( "hello" ),     "hello" )
eq( "trim: leading only",         util.trimstring( "  hi" ),      "hi" )
eq( "trim: trailing only",        util.trimstring( "hi  " ),      "hi" )
eq( "trim: inner spaces kept",    util.trimstring( "  a b  " ),   "a b" )
eq( "trim: mixed ws (tab/nl)",    util.trimstring( "\t x \n" ),   "x" )
eq( "trim: empty string -> ''",   util.trimstring( "" ),          "" )
eq( "trim: all whitespace -> ''", util.trimstring( "   \t\n" ),   "" )
eq( "trim: single char",          util.trimstring( "x" ),         "x" )

----------------------------------------------------------------------
-- 2. trimstring: non-string inputs now return (nil, err)
--    (each of these returned a garbage STRING pre-#453)
----------------------------------------------------------------------

rejects( "reject: nil (was \"nil\")",           nil )
rejects( "reject: number (was \"123\")",        123 )
rejects( "reject: table (was \"table: 0x..\")", { } )
rejects( "reject: boolean true",                true )
rejects( "reject: boolean false",               false )
rejects( "reject: function",                    function( ) end )

----------------------------------------------------------------------
-- 3. encode / decode: round-trip preserved; coercion pinned (#453)
----------------------------------------------------------------------

local function roundtrip( label, s )
    eq( label, util.decode( util.encode( s ) ), s )
end

roundtrip( "roundtrip: ascii",         "secret" )
roundtrip( "roundtrip: with spaces",   "hello world" )
roundtrip( "roundtrip: empty string",  "" )
roundtrip( "roundtrip: digits string", "1234567890" )
roundtrip( "roundtrip: punctuation",   "a-b_c.d!e" )

-- encode output is lowercase hex (2 chars per input byte).
do
    local enc = util.encode( "AB" )
    eq( "encode: hex length = 2*len", #enc, 4 )
    eq( "encode: hex charset only",   ( enc:match( "^[0-9a-f]*$" ) ~= nil ), true )
end

-- Coercion is intentional (#453): a number stringifies and round-trips
-- to its STRING form (decode always yields a string).
eq( "coerce: decode(encode(123)) == \"123\"", util.decode( util.encode( 123 ) ), "123" )

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
