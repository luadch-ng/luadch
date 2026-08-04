--[[

    tests/unit/cmd_botflag_test.lua

    Unit tests for cmd_botflag.lua (#571). The `+botflag <nick> on|off`
    handler toggles the `show_as_bot` profile flag on a registered account.
    This covers the plugin's decision logic: permission gate, on/off parse,
    mutate-in-place + saveusers, the is_bot guard (must never touch an
    in-hub bot object), the unknown-nick reject, and the no-op path.

    The CORE behaviours (the _regex.reguser schema add + insertreglevel
    ORing the CT bot bit) live in core/hub.lua and are covered by the
    smoke test `test_botflag_ct_bit` in tests/smoke/run.py - they cannot be
    stubbed here.

    FAIL-PRE-FIX: on the unpatched tree the plugin does not exist, so this
    file is the executable contract for the new handler; the is_bot-guard
    and no-op cases lock the guards that a future edit could regress.

    Run: lua5.4 tests/unit/cmd_botflag_test.lua

]]--

----------------------------------------------------------------------
-- Tiny harness
----------------------------------------------------------------------
local failures, checks = 0, 0
local function ok( label, cond )
    checks = checks + 1
    if cond then io.write( "ok   " .. label .. "\n" )
    else failures = failures + 1; io.write( "FAIL " .. label .. "\n" ) end
end

----------------------------------------------------------------------
-- Sandbox-global stubs. Plugins get NO `use`; every global is a
-- whitelisted table. Only what cmd_botflag touches at load + in _onbmsg.
----------------------------------------------------------------------
local _cfg = {
    language              = "en",
    cmd_botflag_permission = { [ 100 ] = true },   -- hubowner only
}

local _saveusers_calls = 0
local _saved_ref = nil

_G.PROCESSED = "PROCESSED"
_G.tonumber = tonumber; _G.tostring = tostring
_G.pairs = pairs; _G.type = type

_G.cfg = {
    get          = function( k ) return _cfg[ k ] end,
    loadlanguage = function( ) return { } end,
    saveusers    = function( ref ) _saveusers_calls = _saveusers_calls + 1; _saved_ref = ref end,
}
_G.utf = {
    match  = function( s, pat ) return string.match( s, pat ) end,
    format = function( fmt, ... ) return string.format( fmt, ... ) end,
    lower  = function( s ) return string.lower( s ) end,
}
_G.util = {
    getlowestlevel = function( tbl )
        local lo
        for lvl, v in pairs( tbl ) do if v and ( not lo or lvl < lo ) then lo = lvl end end
        return lo or 0
    end,
}
_G.audit = { build = function( ) return { } end, fire = function( ) end }

-- The registered store: regnicks values share table identity with the
-- regusers_list entries (as hub.getregusers guarantees), so a mutation
-- via regnicks is visible on the list the plugin passes to saveusers.
local _online_target = nil
local function fresh_store( )
    local botacc  = { level = 20, nick = "botacc" }
    local realbot = { level = 55, nick = "realbot", is_bot = 1 }
    local list = { botacc, realbot }
    local nicks = { botacc = botacc, realbot = realbot }
    return list, nicks, botacc, realbot
end
local _list, _nicks, _botacc, _realbot = fresh_store( )

_G.hub = {
    setlistener            = function( ) end,
    debug                  = function( ) end,
    getbot                 = function( ) return "bot" end,
    getregusers            = function( ) return _list, _nicks end,
    find_online_by_firstnick = function( ) return _online_target end,
}

local p = assert( loadfile( "scripts/cmd_botflag.lua" ) )( )
assert( p and p._onbmsg, "cmd_botflag did not expose the _onbmsg seam" )

----------------------------------------------------------------------
-- user stub: given level; captures its last reply
----------------------------------------------------------------------
local function make_user( level )
    local last
    return {
        level     = function( ) return level end,
        isregged  = function( ) return true end,
        nick      = function( ) return "[OP]op" end,
        firstnick = function( ) return "op" end,
        reply     = function( _self, msg ) last = msg end,
        _last     = function( ) return last end,
    }
end

local function reset( )
    _list, _nicks, _botacc, _realbot = fresh_store( )
    _saveusers_calls = 0
    _saved_ref = nil
    _online_target = nil
end

----------------------------------------------------------------------
-- 1. permission gate: a level below the permission table is denied
----------------------------------------------------------------------
do
    reset( )
    local u = make_user( 60 )
    local r = p._onbmsg( u, "botflag", "botacc on" )
    ok( "denied: returns PROCESSED",          r == "PROCESSED" )
    ok( "denied: reply is msg_denied",        u._last( ) == "You are not allowed to use this command." )
    ok( "denied: no mutation",                _botacc.show_as_bot == nil )
    ok( "denied: no saveusers",               _saveusers_calls == 0 )
end

----------------------------------------------------------------------
-- 2. usage: missing on|off token
----------------------------------------------------------------------
do
    reset( )
    local u = make_user( 100 )
    p._onbmsg( u, "botflag", "botacc" )
    ok( "usage: reply is msg_usage (missing state)", u._last( ):find( "Usage" ) ~= nil )
    ok( "usage: no saveusers",                _saveusers_calls == 0 )
end

----------------------------------------------------------------------
-- 3. bad state token -> usage
----------------------------------------------------------------------
do
    reset( )
    local u = make_user( 100 )
    p._onbmsg( u, "botflag", "botacc maybe" )
    ok( "bad-state: reply is msg_usage",      u._last( ):find( "Usage" ) ~= nil )
    ok( "bad-state: no mutation",             _botacc.show_as_bot == nil )
end

----------------------------------------------------------------------
-- 4. on: sets the flag, persists, notifies online target
----------------------------------------------------------------------
do
    reset( )
    local notified
    _online_target = { reply = function( _self, msg ) notified = msg end }
    local u = make_user( 100 )
    local r = p._onbmsg( u, "botflag", "botacc on" )
    ok( "on: returns PROCESSED",              r == "PROCESSED" )
    ok( "on: show_as_bot == 1",               _botacc.show_as_bot == 1 )
    ok( "on: saveusers called once",          _saveusers_calls == 1 )
    ok( "on: saveusers got the regusers list", _saved_ref == _list )
    ok( "on: online target notified",         notified ~= nil )
end

----------------------------------------------------------------------
-- 5. no-op: flag already on -> msg_nochange, no persist
----------------------------------------------------------------------
do
    reset( )
    _botacc.show_as_bot = 1
    local u = make_user( 100 )
    p._onbmsg( u, "botflag", "botacc on" )
    ok( "noop: reply is msg_nochange",        u._last( ) == "There are no changes needed." )
    ok( "noop: no saveusers",                 _saveusers_calls == 0 )
    ok( "noop: flag unchanged",               _botacc.show_as_bot == 1 )
end

----------------------------------------------------------------------
-- 6. off: clears the flag (to nil), persists
----------------------------------------------------------------------
do
    reset( )
    _botacc.show_as_bot = 1
    local u = make_user( 100 )
    p._onbmsg( u, "botflag", "botacc off" )
    ok( "off: show_as_bot cleared to nil",    _botacc.show_as_bot == nil )
    ok( "off: saveusers called once",         _saveusers_calls == 1 )
end

----------------------------------------------------------------------
-- 7. is_bot guard: an in-hub bot account is rejected, never touched
----------------------------------------------------------------------
do
    reset( )
    local u = make_user( 100 )
    p._onbmsg( u, "botflag", "realbot on" )
    ok( "is_bot: reply is msg_reg",           u._last( ):find( "not a registered account" ) ~= nil )
    ok( "is_bot: flag not set on the bot",    _realbot.show_as_bot == nil )
    ok( "is_bot: no saveusers",               _saveusers_calls == 0 )
end

----------------------------------------------------------------------
-- 8. unknown nick -> reject
----------------------------------------------------------------------
do
    reset( )
    local u = make_user( 100 )
    p._onbmsg( u, "botflag", "ghost on" )
    ok( "unknown: reply is msg_reg",          u._last( ):find( "not a registered account" ) ~= nil )
    ok( "unknown: no saveusers",              _saveusers_calls == 0 )
end

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
