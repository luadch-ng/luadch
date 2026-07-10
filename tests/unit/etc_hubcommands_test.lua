--[[

    tests/unit/etc_hubcommands_test.lua

    Unit tests for scripts/etc_hubcommands.lua (#356).

    Focus: the bare-word "Did you mean +X?" hint. It fires only when the
    message is EXACTLY a command word ("talk") AND the user may run it
    (#356 + follow-up). A command word followed by chat text ("talk to
    me brother") is ordinary chat and must reach main unmolested.
    Exception: a secret-carrying command (setpass, { secret = true }) is
    still swallowed in its "cmd <args>" form, regardless of level, so a
    forgot-prefix password never broadcasts.

    The literal-bracket branch (`[+!#]reg <user> <pw>`, #137) is
    deliberately NOT level-gated - it must keep swallowing regardless of
    level to prevent a credential leak - and this test locks that.

    Captures the onBroadcast listener via a hub stub at file-load time,
    registers commands with levels through the plugin's public `add`,
    then fires the listener with stub users of varying level.

    §1a.7: assertions marked [FAIL-PRE-FIX] fail on the unpatched
    plugin (where the hint fires for any registered command regardless
    of level) and pass on the patched plugin.

    Run: lua5.4 tests/unit/etc_hubcommands_test.lua
    Exit 0 = all pass, 1 = a failure (CI-friendly).

]]--

----------------------------------------------------------------------
-- stub layer: sandbox globals the plugin reads at file scope
----------------------------------------------------------------------

local _registered = { }
local _alias_map = { }     -- alias -> real command, consulted by hub.import("etc_aliases")

local stub_hub = {
    setlistener = function( event, opts, fn )
        _registered[ event ] = fn
    end,
    debug = function( ) end,
    getbot = function( ) return "stub-bot" end,
    import = function( name )
        if name == "etc_aliases" then
            return { resolve = function( n ) return _alias_map[ n ] end }
        end
        return nil
    end,
}

_G.hub = stub_hub
_G.cfg = {
    get = function( key )
        if key == "language" then return "en" end
        return nil
    end,
    loadlanguage = function( ) return { }, nil end,
}
_G.utf = { match = string.match, format = string.format }
_G.PROCESSED = 1

----------------------------------------------------------------------
-- minimal test framework
----------------------------------------------------------------------

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-60s got=%q want=%q\n", label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end
local function truthy( label, got )
    checks = checks + 1
    if not got then
        failures = failures + 1
        io.write( string.format( "FAIL %-60s got=%q (want truthy)\n", label, tostring( got ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

-- stub user object: level() + reply() as method calls
local function make_user( level )
    local replies = { }
    local u = {
        level = function( self ) return level end,
        reply = function( self, msg, bot ) replies[ #replies + 1 ] = msg end,
    }
    return u, replies
end

----------------------------------------------------------------------
-- load plugin + register commands
----------------------------------------------------------------------

local plugin = assert( loadfile( "scripts/etc_hubcommands.lua" ) )( )
local onBroadcast = assert( _registered.onBroadcast, "onBroadcast listener was not registered" )

local dispatched = { }
local function handler( user, command, parameters, txt )
    dispatched[ #dispatched + 1 ] = command
    return "HANDLED"
end

-- "talk" and "reg" are op-only (level 50, not secret); "help" is public
-- (ungated, registered WITHOUT a level to prove back-compat); "setpass"
-- is op-only AND carries a secret inline ({ secret = true }).
assert( plugin.add( "talk",    handler, 50 ) )
assert( plugin.add( "reg",     handler, 50 ) )
assert( plugin.add( "help",    handler ) )                 -- ungated (nil level)
assert( plugin.add( "setpass", handler, 50, { secret = true } ) )
_alias_map[ "t" ] = "talk"                                 -- alias -> op command

----------------------------------------------------------------------
-- 1. EXACT op command word, high user -> hint fires + swallowed
----------------------------------------------------------------------

do
    local u, replies = make_user( 50 )
    local ret = onBroadcast( u, { }, "talk" )
    eq( "high user exact 'talk': one hint",      #replies, 1 )
    truthy( "high user exact 'talk': mentions +talk", replies[ 1 ] and replies[ 1 ]:find( "talk", 1, true ) )
    eq( "high user exact 'talk': swallowed",     ret, _G.PROCESSED )
end

----------------------------------------------------------------------
-- 2. EXACT op command word, low user -> gated (no hint, #356)
----------------------------------------------------------------------

do
    local u, replies = make_user( 10 )
    local ret = onBroadcast( u, { }, "talk" )
    eq( "low user exact 'talk': no hint",        #replies, 0 )
    eq( "low user exact 'talk': not swallowed",  ret, nil )
end

----------------------------------------------------------------------
-- 3. Op command word + trailing chat text -> ordinary chat (#356 f/u).
--    This is the core follow-up behaviour: an op writing "talk to me
--    brother" in chat must NOT be hinted/swallowed.
----------------------------------------------------------------------

do
    local u, replies = make_user( 50 )
    local ret = onBroadcast( u, { }, "talk to me brother" )
    eq( "[FAIL-PRE-FIX] op 'talk to me brother': no hint", #replies, 0 )
    eq( "[FAIL-PRE-FIX] op 'talk to me brother': not swallowed", ret, nil )
end

----------------------------------------------------------------------
-- 4. Public command word + trailing text -> ordinary chat (#356 f/u)
----------------------------------------------------------------------

do
    local u, replies = make_user( 10 )
    local ret = onBroadcast( u, { }, "help me please" )
    eq( "[FAIL-PRE-FIX] 'help me please': no hint", #replies, 0 )
    eq( "[FAIL-PRE-FIX] 'help me please': not swallowed", ret, nil )
end

----------------------------------------------------------------------
-- 5. EXACT public command word -> hint for everyone (ungated)
----------------------------------------------------------------------

do
    local u, replies = make_user( 10 )
    local ret = onBroadcast( u, { }, "help" )
    eq( "low user exact 'help': hint fires (ungated)", #replies, 1 )
    eq( "low user exact 'help': swallowed",            ret, _G.PROCESSED )
end

----------------------------------------------------------------------
-- 6. Alias: EXACT resolves + gated; alias + trailing text -> chat
----------------------------------------------------------------------

do
    local hu, hreplies = make_user( 50 )
    eq( "high user exact alias 't'->talk: hint", ( onBroadcast( hu, { }, "t" ) ), _G.PROCESSED )
    eq( "high user exact alias 't': one reply",  #hreplies, 1 )

    local lu, lreplies = make_user( 10 )
    onBroadcast( lu, { }, "t" )
    eq( "low user exact alias 't': no hint (gated)", #lreplies, 0 )

    local cu, creplies = make_user( 50 )
    local cret = onBroadcast( cu, { }, "t hello" )
    eq( "[FAIL-PRE-FIX] alias 't hello' + text: no hint", #creplies, 0 )
    eq( "[FAIL-PRE-FIX] alias 't hello' + text: not swallowed", cret, nil )
end

----------------------------------------------------------------------
-- 7. SECRET command + args -> swallowed regardless of level (leak guard).
--    A forgot-prefix "setpass nick x <pw>" must NOT broadcast, even for
--    a user who cannot run setpass.
----------------------------------------------------------------------

do
    local u, replies = make_user( 10 )
    local ret = onBroadcast( u, { }, "setpass alice hunter2" )
    eq( "[FAIL-PRE-FIX] low user 'setpass alice hunter2': swallowed", ret, _G.PROCESSED )
    truthy( "secret-cmd hint does not leak the password",
        replies[ 1 ] and not replies[ 1 ]:find( "hunter2", 1, true ) )

    local hu, hreplies = make_user( 50 )
    local hret = onBroadcast( hu, { }, "setpass bob s3cr3t" )
    eq( "high user 'setpass bob s3cr3t': swallowed", hret, _G.PROCESSED )
    truthy( "secret-cmd hint (high) does not leak the password",
        hreplies[ 1 ] and not hreplies[ 1 ]:find( "s3cr3t", 1, true ) )
end

----------------------------------------------------------------------
-- 8. NON-secret command + args -> ordinary chat (no swallow), even op
----------------------------------------------------------------------

do
    local u, replies = make_user( 50 )
    local ret = onBroadcast( u, { }, "reg alice 20" )
    eq( "[FAIL-PRE-FIX] op 'reg alice 20' (non-secret): no hint", #replies, 0 )
    eq( "[FAIL-PRE-FIX] op 'reg alice 20' (non-secret): not swallowed", ret, nil )
end

----------------------------------------------------------------------
-- 8b. Multi-name table form + opts -> secret flag propagates to EVERY
--     registered name (add({a,b}, fn, lvl, {secret=true})).
----------------------------------------------------------------------

do
    assert( plugin.add( { "setpw", "chpw" }, handler, 50, { secret = true } ) )
    local u1 = make_user( 10 )
    eq( "multi-name secret 'setpw x y': swallowed", ( onBroadcast( u1, { }, "setpw alice hunter2" ) ), _G.PROCESSED )
    local u2 = make_user( 10 )
    eq( "multi-name secret 'chpw x y': swallowed",  ( onBroadcast( u2, { }, "chpw alice hunter2" ) ), _G.PROCESSED )
end

----------------------------------------------------------------------
-- 9. Literal-bracket branch is NOT gated (#137 credential-leak guard)
--    low user must STILL be swallowed even for an op-only command.
----------------------------------------------------------------------

do
    local u, replies = make_user( 10 )
    local ret = onBroadcast( u, { }, "[+!#]reg foo secret" )
    eq( "low user '[+!#]reg foo secret': swallowed (no cred leak)", ret, _G.PROCESSED )
    eq( "low user '[+!#]reg foo secret': one hint sent", #replies, 1 )
    truthy( "literal-bracket hint does not leak the password",
        replies[ 1 ] and not replies[ 1 ]:find( "secret", 1, true ) )
end

----------------------------------------------------------------------
-- 10. Correct prefixed command still dispatches (regression guard)
----------------------------------------------------------------------

do
    local u, replies = make_user( 50 )
    local ret = onBroadcast( u, { }, "+talk hi there" )
    eq( "prefixed '+talk': dispatched to handler", dispatched[ #dispatched ], "talk" )
    eq( "prefixed '+talk': returns handler result", ret, "HANDLED" )
    truthy( "prefixed '+talk': echo reply sent", #replies >= 1 )
end

----------------------------------------------------------------------
-- 11. Ordinary chat with no command word -> untouched
----------------------------------------------------------------------

do
    local u, replies = make_user( 10 )
    local ret = onBroadcast( u, { }, "hello everyone" )
    eq( "ordinary chat: no hint", #replies, 0 )
    eq( "ordinary chat: not swallowed", ret, nil )
end

----------------------------------------------------------------------
-- summary
----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures > 0 and 1 or 0 )
