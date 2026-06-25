--[[

    tests/unit/cmd_disconnect_tl_test.lua

    Unit test for #343 - the optional TL<N> token parser in
    scripts/cmd_disconnect.lua.

    Exercises parse_tl_token (the pure helper exported by the
    plugin) against every realistic shape:
      - no TL token (rest = full reason)
      - TL<N> with valid N in -1..86400
      - TL<N> with N out of bounds -> (false, nil) for loud reject
      - TL prefix on a non-numeric tail -> NOT a TL token, treated
        as part of the reason
      - empty / whitespace input

    Run: lua5.4 tests/unit/cmd_disconnect_tl_test.lua

]]--

----------------------------------------------------------------------
-- stub layer: sandbox globals the plugin reads at file scope
----------------------------------------------------------------------

local _registered = { onStart = nil, http = { } }

_G.hub = {
    setlistener = function( event, opts, fn ) _registered[ event ] = fn end,
    debug    = function( ) end,
    getbot   = function( ) return "stub-bot" end,
    import   = function( name )
        if name == "etc_report" then return { send = function( ) end } end
        return nil
    end,
    escapefrom = function( s ) return s end,
    escapeto   = function( s ) return s end,
}
_G.cfg = {
    get = function( key )
        if key == "language" then return "en" end
        if key == "cmd_disconnect_minlevel" then return 60 end
        if key == "cmd_disconnect_sendmainmsg" then return false end
        if key == "cmd_disconnect_default_tl" then return 30 end
        if key == "cmd_disconnect_report" then return true end
        if key == "cmd_disconnect_llevel" then return 60 end
        if key == "cmd_disconnect_report_hubbot" then return false end
        if key == "cmd_disconnect_report_opchat" then return true end
        return nil
    end,
    loadlanguage = function( ) return { }, nil end,
}
_G.util = {
    strip_control_bytes = function( s ) return s end,
}
_G.utf = {
    match  = string.match,
    format = string.format,
}
_G.audit = {
    build = function( ) return { } end,
    fire  = function( ) end,
}
_G.util_http = {
    http_register_user_action = function( name, method, path, action, fn, meta )
        _registered.http[ method .. " " .. path ] = fn
    end,
}
_G.PROCESSED = 1

----------------------------------------------------------------------
-- minimal test framework
----------------------------------------------------------------------

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-65s got=%q want=%q\n", label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

----------------------------------------------------------------------
-- load plugin + extract parse_tl_token
----------------------------------------------------------------------

local plugin = assert( loadfile( "scripts/cmd_disconnect.lua" ) )( )
assert( plugin and type( plugin.parse_tl_token ) == "function",
        "plugin must export parse_tl_token" )
local parse = plugin.parse_tl_token

----------------------------------------------------------------------
-- 1. No TL token (the plain-reason case)
----------------------------------------------------------------------

do
    local tl, rest = parse( "spamming the hub" )
    eq( "no TL: tl is nil",    tl,   nil )
    eq( "no TL: rest is full", rest, "spamming the hub" )
end

----------------------------------------------------------------------
-- 2. TL<N> with valid N in -1..86400
----------------------------------------------------------------------

do
    local tl, rest = parse( "TL30 short cooldown" )
    eq( "TL30: tl",   tl,   30 )
    eq( "TL30: rest", rest, "short cooldown" )

    tl, rest = parse( "TL0 immediate retry allowed" )
    eq( "TL0: tl",   tl,   0 )
    eq( "TL0: rest", rest, "immediate retry allowed" )

    tl, rest = parse( "TL-1 never auto-reconnect" )
    eq( "TL-1: tl",   tl,   -1 )
    eq( "TL-1: rest", rest, "never auto-reconnect" )

    tl, rest = parse( "TL3600 one hour cooldown" )
    eq( "TL3600: tl",   tl,   3600 )
    eq( "TL3600: rest", rest, "one hour cooldown" )

    tl, rest = parse( "TL86400 one day cap" )
    eq( "TL86400 (max): tl",   tl,   86400 )
    eq( "TL86400 (max): rest", rest, "one day cap" )
end

----------------------------------------------------------------------
-- 3. TL<N> out of bounds -> (false, nil)
----------------------------------------------------------------------

do
    local tl, rest = parse( "TL-2 below min" )
    eq( "TL-2: tl is false (out-of-bounds)", tl,   false )
    eq( "TL-2: rest is nil",                 rest, nil )

    tl, rest = parse( "TL86401 above max" )
    eq( "TL86401: tl is false",   tl,   false )
    eq( "TL86401: rest is nil",   rest, nil )

    tl, rest = parse( "TL999999 way above" )
    eq( "TL999999: tl is false", tl, false )
end

----------------------------------------------------------------------
-- 4. TL prefix on non-numeric tail -> NOT a TL token (treated as reason)
----------------------------------------------------------------------

do
    local tl, rest = parse( "TLabc not a tl token" )
    eq( "TLabc: tl is nil",        tl,   nil )
    eq( "TLabc: rest unchanged",   rest, "TLabc not a tl token" )

    tl, rest = parse( "TL30abc not a tl token" )
    eq( "TL30abc: tl is nil",      tl,   nil )
    eq( "TL30abc: rest unchanged", rest, "TL30abc not a tl token" )

    tl, rest = parse( "TL not a tl token" )
    eq( "TL alone: tl is nil",      tl,   nil )
    eq( "TL alone: rest unchanged", rest, "TL not a tl token" )
end

----------------------------------------------------------------------
-- 5. Reason that HAPPENS to contain TL later -> still no TL token
--    (TL must be the FIRST whitespace-token)
----------------------------------------------------------------------

do
    local tl, rest = parse( "spamming hub including TL30 reference" )
    eq( "trailing TL: tl is nil", tl, nil )
    eq( "trailing TL: rest unchanged",
        rest, "spamming hub including TL30 reference" )
end

----------------------------------------------------------------------
-- 6. Empty / whitespace / nil inputs
----------------------------------------------------------------------

do
    local tl, rest = parse( "" )
    eq( "empty: tl is nil",  tl,   nil )
    eq( "empty: rest is ''", rest, "" )

    tl, rest = parse( nil )
    eq( "nil: tl is nil",  tl,   nil )
    eq( "nil: rest is ''", rest, "" )

    tl, rest = parse( 42 )
    eq( "number: tl is nil",  tl, nil )

    tl, rest = parse( "   " )
    eq( "whitespace only: tl is nil", tl,   nil )
    eq( "whitespace only: rest unchanged", rest, "   " )
end

----------------------------------------------------------------------
-- 7. TL token with no reason after it -> tl applied, reason ""
--    The original pattern required a trailing reason; the v0.10
--    follow-up extended parse_tl_token to also accept "TL<N>"
--    alone (reason becomes ""). Operators should still type a
--    reason in practice, but the previous quirk (where "TL30"
--    became the literal reason) was surprising. Per #343 review
--    NIT 2.
----------------------------------------------------------------------

do
    local tl, rest = parse( "TL30" )
    eq( "TL30 alone: tl is 30",  tl,   30 )
    eq( "TL30 alone: rest is ''", rest, "" )

    tl, rest = parse( "TL-1" )
    eq( "TL-1 alone: tl is -1",  tl,   -1 )
    eq( "TL-1 alone: rest is ''", rest, "" )

    tl, rest = parse( "TL30  " )
    eq( "TL30 trailing-ws: tl is 30",  tl,   30 )
    eq( "TL30 trailing-ws: rest is ''", rest, "" )

    -- Out-of-bounds still rejected even without a reason.
    tl, rest = parse( "TL999999" )
    eq( "TL999999 alone: tl is false (oob)", tl, false )
end

----------------------------------------------------------------------
-- summary
----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures > 0 and 1 or 0 )
