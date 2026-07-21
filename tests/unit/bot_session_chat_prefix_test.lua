--[[

    tests/unit/bot_session_chat_prefix_test.lua

    Regression test for bot_session_chat.lua v0.5: session-chat owner +
    members are now identified by firstnick, not the current display nick.

    THE BUG: usr_nick_prefix re-keys the hub nick table to the PREFIXED
    nick, so `+add <base nick>` (typed by the chat owner into the session
    bot) hit hub.isnickonline(<base nick>) -> nil -> "user not online", and
    the member could not be added. A bare fallback would have resolved the
    user but stored an inconsistent key, because the membership checks
    compared the current (prefixed) display nick. The fix re-keys the whole
    identity model (owner + members, add/del/membership) to
    user:firstnick() - the stable, prefix-independent nick.

    This drives the real `client` EMSG handler (the bot's message sink) for
    an `+add` and a `+del` of a prefixed online user typed by BASE nick,
    and asserts the member store holds the firstnick and that membership is
    recognised.

    FAIL-PRE-FIX (§1a.7): on v0.4 the plugin exports nothing (the `_` seams
    below are absent -> the guards fire); and had the add been drivable, it
    would take the "user not online" branch (base nick misses isnickonline)
    and store nothing. Reproduce red: `git stash push scripts/bot_session_chat.lua`
    then run; `git stash pop` to restore.

    Plugins get NO `use`; every hub-injected global is a stub. Base Lua
    globals are the real ones (no _G.io / _G.os reassignment).

    Run: lua5.4 tests/unit/bot_session_chat_prefix_test.lua

]]--

local checks, failures = 0, 0
local function ok( label, cond )
    checks = checks + 1
    if cond then io.write( "ok   " .. label .. "\n" )
    else failures = failures + 1; io.write( "FAIL " .. label .. "\n" ) end
end

local SESSIONS_FILE = "scripts/data/bot_session_chat.tbl"
local CHAT          = "#session"

----------------------------------------------------------------------
-- online users: prefixed display nicks; base nicks miss isnickonline
----------------------------------------------------------------------
local function make_user( firstnick, nick, sid, level )
    return {
        firstnick = function( ) return firstnick end,
        nick      = function( ) return nick end,
        sid       = function( ) return sid end,
        level     = function( ) return level end,
        isbot     = function( ) return false end,
        reply     = function( ) end,
    }
end

local alice = make_user( "Alice", "[OP]Alice", "ALICE", 100 )   -- owner
local bob   = make_user( "Bob",   "[REG]Bob",  "BOB",   20 )    -- add target
local bot   = {
    nick      = function( ) return CHAT end,
    sid       = function( ) return "BOT1" end,
    firstnick = function( ) return CHAT end,
    isbot     = function( ) return true end,
    kill      = function( ) end,
    reply     = function( ) end,
}

-- isnickonline is keyed by CURRENT nick: base nicks miss, prefixed hit,
-- the bot nick hits (bots are never prefixed).
local _online = { [ "[OP]Alice" ] = alice, [ "[REG]Bob" ] = bob, [ CHAT ] = bot }

-- controllable sessions store
local _fs = {}

_G.PROCESSED = "PROCESSED"
_G.cfg = {
    get = function( k )
        local t = {
            language                    = "en",
            bot_session_chat_minlevel   = 10,
            bot_session_chat_masterlevel = 100,
            bot_session_chat_chatprefix = "#",
        }
        return t[ k ]
    end,
    loadlanguage = function( ) return {} end,
}
_G.utf = {
    match  = function( s, pat ) return string.match( s, pat ) end,
    format = function( fmt, ... ) return string.format( fmt, ... ) end,
}
_G.util = {
    loadtable = function( path ) return _fs[ path ] end,
    savetable = function( t, _name, path ) _fs[ path ] = t end,
}
_G.hub = {
    setlistener  = function( ) end,
    debug        = function( ) end,
    getbot       = function( ) return bot end,
    broadcast    = function( ) end,
    regbot       = function( ) return bot end,
    escapefrom   = function( s ) return s end,
    escapeto     = function( s ) return s end,
    getuser      = function( sid )
        if sid == "ALICE" then return alice end
        if sid == "BOB" then return bob end
        if sid == "BOT1" then return bot end
        return nil
    end,
    getusers     = function( ) return { ALICE = alice, BOB = bob, BOT1 = bot } end,
    isnickonline = function( n ) return _online[ n ] end,
    import       = function( ) return nil end,
}

-- a minimal EMSG cmd carrying `body`, sent by `mysid`
local function make_cmd( mysid, body )
    return {
        fourcc    = function( ) return "EMSG" end,
        mysid     = function( ) return mysid end,
        pos       = function( _self, _n ) return body end,
        setnp     = function( ) end,
        adcstring = function( ) return "EMSG " .. body end,
    }
end

local p = assert( loadfile( "scripts/bot_session_chat.lua" ) )( )

if type( p ) ~= "table" or type( p._client ) ~= "function"
   or type( p._check_if_member ) ~= "function"
   or type( p._find_online_by_firstnick ) ~= "function" then
    io.write( "FAIL bot_session_chat.lua does not export the _ seams - pre-v0.5 plugin?\n" )
    os.exit( 1 )
end

----------------------------------------------------------------------
-- 0. the firstnick resolver
----------------------------------------------------------------------
ok( "find_online_by_firstnick resolves the prefixed user by base nick",
    p._find_online_by_firstnick( "Bob" ) == bob )
ok( "find_online_by_firstnick nil for unknown",
    p._find_online_by_firstnick( "Nobody" ) == nil )

----------------------------------------------------------------------
-- seed a chat owned by Alice (stored by firstnick), Bob not yet a member
----------------------------------------------------------------------
local function members_of( )
    local m = _fs[ SESSIONS_FILE ][ CHAT ].members
    local set = {}
    for _, v in pairs( m ) do set[ v ] = true end
    return m, set
end

_fs[ SESSIONS_FILE ] = { [ CHAT ] = { owner = "Alice", members = { "Alice" } } }

ok( "owner recognised by firstnick",          p._check_if_owner( alice, CHAT ) == true )
ok( "Bob is NOT a member yet",                p._check_if_member( "Bob", CHAT ) == false )

----------------------------------------------------------------------
-- 1. `+add Bob` (base nick, Bob online as [REG]Bob) must add Bob's firstnick
----------------------------------------------------------------------
p._client( bot, make_cmd( "ALICE", "+add Bob" ) )
do
    local m, set = members_of( )
    ok( "add by base nick: member count is now 2", #m == 2 )
    ok( "add by base nick: stored the FIRSTNICK 'Bob'", set[ "Bob" ] == true )
    ok( "add by base nick: did NOT store the prefixed nick", set[ "[REG]Bob" ] == nil )
    ok( "Bob is now recognised as a member (by firstnick)", p._check_if_member( "Bob", CHAT ) == true )
end

----------------------------------------------------------------------
-- 2. `+del Bob` (base nick) must remove Bob again
----------------------------------------------------------------------
p._client( bot, make_cmd( "ALICE", "+del Bob" ) )
do
    local m, set = members_of( )
    ok( "del by base nick: Bob removed",          set[ "Bob" ] == nil )
    ok( "del by base nick: owner Alice remains",  set[ "Alice" ] == true )
    ok( "del by base nick: member count back to 1", #m == 1 )
end

----------------------------------------------------------------------
-- 3. a non-owner cannot add (owner gate still firstnick-based)
----------------------------------------------------------------------
_fs[ SESSIONS_FILE ] = { [ CHAT ] = { owner = "Alice", members = { "Alice", "Bob" } } }
ok( "non-owner Bob is not the owner", p._check_if_owner( bob, CHAT ) == false )

----------------------------------------------------------------------
io.write( string.format( "\n%d/%d checks passed\n", checks - failures, checks ) )
if failures > 0 then io.write( "FAIL bot_session_chat_prefix_test\n" ); os.exit( 1 ) end
io.write( "OK bot_session_chat_prefix_test\n" )
