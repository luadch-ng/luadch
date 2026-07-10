--[[

    tests/unit/etc_hubcommands_test.lua

    Unit tests for scripts/etc_hubcommands.lua (#356).

    Focus: the bare-word "Did you mean +X?" hint must only fire for a
    command the user is actually allowed to run. A normal chat line that
    merely starts with a privileged command word (e.g. "talk to me
    brother") must reach main chat unmolested, and op-only command names
    must not leak to unprivileged users.

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

-- "talk" and "reg" are op-only (level 50); "help" is public (ungated,
-- registered WITHOUT a level to prove back-compat).
assert( plugin.add( "talk", handler, 50 ) )
assert( plugin.add( "reg",  handler, 50 ) )
assert( plugin.add( "help", handler ) )       -- ungated (nil level)
_alias_map[ "t" ] = "talk"                    -- alias -> op command

----------------------------------------------------------------------
-- 1. Low-level user, bare-word privileged command -> NO hint, chat passes
----------------------------------------------------------------------

do
    local u, replies = make_user( 10 )
    local ret = onBroadcast( u, { }, "talk to me brother" )
    eq( "[FAIL-PRE-FIX] low user 'talk ...': no hint sent", #replies, 0 )
    eq( "[FAIL-PRE-FIX] low user 'talk ...': not swallowed (ret nil)", ret, nil )
end

----------------------------------------------------------------------
-- 2. High-level user, same line -> hint fires + swallowed
----------------------------------------------------------------------

do
    local u, replies = make_user( 50 )
    local ret = onBroadcast( u, { }, "talk to me brother" )
    eq( "high user 'talk ...': one hint sent", #replies, 1 )
    truthy( "high user 'talk ...': hint text mentions +talk", replies[ 1 ] and replies[ 1 ]:find( "talk", 1, true ) )
    eq( "high user 'talk ...': swallowed (PROCESSED)", ret, _G.PROCESSED )
end

----------------------------------------------------------------------
-- 3. Bare-word public/ungated command -> hint fires for everyone
----------------------------------------------------------------------

do
    local u, replies = make_user( 10 )
    local ret = onBroadcast( u, { }, "help me please" )
    eq( "low user 'help ...': hint still fires (ungated)", #replies, 1 )
    eq( "low user 'help ...': swallowed (PROCESSED)", ret, _G.PROCESSED )
end

----------------------------------------------------------------------
-- 4. Whole-word privileged command as chat -> not swallowed for low user
----------------------------------------------------------------------

do
    local u, replies = make_user( 10 )
    local ret = onBroadcast( u, { }, "talk" )
    eq( "[FAIL-PRE-FIX] low user bare 'talk': no hint", #replies, 0 )
    eq( "[FAIL-PRE-FIX] low user bare 'talk': not swallowed", ret, nil )
end

----------------------------------------------------------------------
-- 5. Alias resolving to an op command -> gated too
----------------------------------------------------------------------

do
    local u, replies = make_user( 10 )
    local ret = onBroadcast( u, { }, "t hello" )
    eq( "[FAIL-PRE-FIX] low user alias 't'->talk: no hint", #replies, 0 )
    eq( "[FAIL-PRE-FIX] low user alias 't'->talk: not swallowed", ret, nil )
    -- high user: alias resolves and hint fires
    local hu, hreplies = make_user( 50 )
    local hret = onBroadcast( hu, { }, "t hello" )
    eq( "high user alias 't'->talk: hint fires", #hreplies, 1 )
    eq( "high user alias 't'->talk: swallowed", hret, _G.PROCESSED )
end

----------------------------------------------------------------------
-- 6. Literal-bracket branch is NOT gated (#137 credential-leak guard)
--    low user must STILL be swallowed even for an op-only command.
----------------------------------------------------------------------

do
    local u, replies = make_user( 10 )
    local ret = onBroadcast( u, { }, "[+!#]reg foo secret" )
    eq( "low user '[+!#]reg foo secret': swallowed (no cred leak)", ret, _G.PROCESSED )
    eq( "low user '[+!#]reg foo secret': one hint sent", #replies, 1 )
    -- the hint must NOT echo the password
    truthy( "literal-bracket hint does not leak the password",
        replies[ 1 ] and not replies[ 1 ]:find( "secret", 1, true ) )
end

----------------------------------------------------------------------
-- 7. Correct prefixed command still dispatches (regression guard)
----------------------------------------------------------------------

do
    local u, replies = make_user( 50 )
    local ret = onBroadcast( u, { }, "+talk hi there" )
    eq( "prefixed '+talk': dispatched to handler", dispatched[ #dispatched ], "talk" )
    eq( "prefixed '+talk': returns handler result", ret, "HANDLED" )
    truthy( "prefixed '+talk': echo reply sent", #replies >= 1 )
end

----------------------------------------------------------------------
-- 8. Ordinary chat with no command word -> untouched
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
