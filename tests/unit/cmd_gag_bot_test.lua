--[[

    tests/unit/cmd_gag_bot_test.lua

    Regression test for #355: the ADC `+gag mute|kennylize|shadowmute`
    path must REJECT a bot target (Hubbot / OpChat / RegChat) instead of
    gagging it. The HTTP path is already covered by util_http's non-bot
    preflight; this covers the ADC command handler (onbmsg).

    FAIL-PRE-FIX: on the unpatched plugin a bot target reaches add_user and
    is gagged (an entry is persisted + the reply is the "was gagged"
    report); patched it is rejected with msg_isbot and no entry is created.

    Run: lua5.4 tests/unit/cmd_gag_bot_test.lua

]]--

-- Mutable cfg + the sandbox-global stubs the plugin reads at load. Plugins
-- get NO `use`; every global is a whitelisted table.
local _cfg = {
    language                = "en",
    cmd_gag_permission      = { [50] = 50, [60] = 60, [100] = 100 },
    hub_bot                 = "HubBot",
    cmd_gag_user_notifiy    = false,
    cmd_gag_report          = false,
    cmd_gag_llevel          = 80,
    cmd_gag_report_hubbot   = false,
    cmd_gag_report_opchat   = false,
    bot_opchat_nick         = "OpChat",
    bot_opchat_permission   = { [100] = 100 },
    bot_regchat_nick        = "RegChat",
    bot_regchat_permission  = { [100] = 100 },
}

_G.PROCESSED = "PROCESSED"
_G.os = os; _G.string = string; _G.table = table
_G.tonumber = tonumber; _G.tostring = tostring
_G.ipairs = ipairs; _G.pairs = pairs; _G.type = type
_G.cfg = {
    get = function( k ) return _cfg[ k ] end,
    loadlanguage = function( ) return { } end,
}
_G.utf = {
    match  = function( s, pat ) return string.match( s, pat ) end,
    format = function( fmt, ... ) return string.format( fmt, ... ) end,
}
_G.util = {
    loadtable = function( ) return { } end,
    getlowestlevel = function( tbl )
        local lo
        for lvl in pairs( tbl ) do if not lo or lvl < lo then lo = lvl end end
        return lo or 0
    end,
    strip_control_bytes = function( s ) return s end,
    savearray = function( ) end,
    formatseconds = function( ) return 0, 0, 0, 0, 0 end,
}
_G.audit = { build = function( ) return { } end, fire = function( ) end }
_G.hub = {
    setlistener  = function( ) end,
    debug        = function( ) end,
    getbot       = function( ) return "bot" end,
    getregusers  = function( ) return { } end,
    import       = function( name )
        if name == "etc_report" then return { send = function( ) end } end
        return nil
    end,
    isnickonline = nil,   -- set per case below
}

local p = assert( loadfile( "scripts/cmd_gag.lua" ) )( )

local failures, checks = 0, 0
local function ok( label, cond )
    checks = checks + 1
    if cond then io.write( "ok   " .. label .. "\n" )
    else failures = failures + 1; io.write( "FAIL " .. label .. "\n" ) end
end

-- operator stub: level 100 (hubowner), captures its last reply
local function make_op( )
    local last
    return {
        level     = function( ) return 100 end,
        nick      = function( ) return "[OP]op" end,
        firstnick = function( ) return "op" end,
        reply     = function( _self, msg ) last = msg end,
        _last     = function( ) return last end,
    }
end
-- a resolvable online target
local function make_target( is_bot, nick )
    return {
        isbot     = function( ) return is_bot end,
        level     = function( ) return 50 end,
        nick      = function( ) return nick end,
        firstnick = function( ) return nick end,
        reply     = function( ) end,
    }
end

local function reset_gag( )
    for i = #p._gag_tbl, 1, -1 do p._gag_tbl[ i ] = nil end
end

----------------------------------------------------------------------
-- 1. gagging a BOT is rejected with msg_isbot; no entry created
----------------------------------------------------------------------
do
    reset_gag( )
    _G.hub.isnickonline = function( ) return make_target( true, "HubBot" ) end
    local op = make_op( )
    local r = p._onbmsg( op, "gag", "mute HubBot" )
    ok( "bot: handler returns PROCESSED",        r == "PROCESSED" )
    ok( "bot: reply is msg_isbot",               op._last( ) == "User is a bot." )
    ok( "bot: NOT added to the gag table",       #p._gag_tbl == 0 )
end

----------------------------------------------------------------------
-- 2. control: gagging a human still works (the guard is bot-specific)
----------------------------------------------------------------------
do
    reset_gag( )
    _G.hub.isnickonline = function( ) return make_target( false, "Alice" ) end
    local op = make_op( )
    p._onbmsg( op, "gag", "mute Alice" )
    ok( "human: reply is NOT msg_isbot",         op._last( ) ~= "User is a bot." )
    ok( "human: added to the gag table",         #p._gag_tbl == 1 )
    ok( "human: entry carries the right nick",   p._gag_tbl[ 1 ] and p._gag_tbl[ 1 ].user_nick == "Alice" )
end

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
