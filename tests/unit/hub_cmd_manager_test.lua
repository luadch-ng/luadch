--[[

    tests/unit/hub_cmd_manager_test.lua

    Unit tests for scripts/hub_cmd_manager.lua's C2C level gates, focused
    on the v0.03 NAT-traversal fix.

    hub_cmd_manager gates ADC commands by a minimum level. It already
    dropped CTM (onConnectToMe, gated by ctmlevel) and RCM
    (onRevConnectToMe, gated by rcmlevel) for below-level users, but did
    NOT hook NAT traversal - so a below-level passive / CGNAT peer, whose
    client falls back to DNAT / DRNT when a direct connection is
    impossible, slipped through the gate. v0.03 adds onNatTraversal and
    onNatTraversalReply. NATT exists because a passive uploader cannot
    send a usable CTM, so it sends DNAT instead: DNAT is the CTM-role
    stand-in (gated by ctmlevel) and DRNT is the RCM-role reply from the
    original RCM sender (gated by rcmlevel).

    The plugin's levels are hardcoded to 0 in-source (inert by default),
    so the test patches ctmlevel/rcmlevel to two DIFFERENT non-zero
    thresholds (40 / 20). The differing thresholds let the level-30 probe
    prove the role mapping: onNatTraversal must gate by ctmlevel (40, so
    30 is blocked) and onNatTraversalReply by rcmlevel (20, so 30 is
    allowed) - swapping them would flip both results. The patch is
    orthogonal to the fix and applies equally pre- and post-fix.

    Run: lua5.4 tests/unit/hub_cmd_manager_test.lua
    Exit 0 = all pass, 1 = a failure (CI-friendly).

    Regression contract (CLAUDE.md §1a.7): the two "onNatTraversal /
    onNatTraversalReply registered" checks (and the guarded gate
    assertions) FAIL on the pre-v0.03 plugin (the listeners are
    unregistered; the guarded calls are then skipped) and PASS patched -
    2 RED-pre-fix registration checks. The onConnectToMe / onRevConnectToMe
    sanity + parity checks are guards that pass on both revisions.
    Verified by running this file with the fix stashed (2 failures
    pre-fix, 0 post-fix).

]]--

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-56s got=%q want=%q\n", label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

----------------------------------------------------------------------
-- stub the globals the plugin touches at load time + capture listeners
----------------------------------------------------------------------

local _registered = { }
_G.PROCESSED = 1
_G.hub = {
    setlistener = function( event, opts, fn ) _registered[ event ] = fn end,
    debug       = function( ) end,
}

----------------------------------------------------------------------
-- load the plugin with the two C2C gates set to distinct thresholds
----------------------------------------------------------------------

local RCM, CTM = 20, 40
local path = "scripts/hub_cmd_manager.lua"
local fh = assert( io.open( path, "r" ), "cannot open " .. path )
local src = fh:read( "*a" ); fh:close( )
src = src:gsub( "local rcmlevel = 0", "local rcmlevel = " .. RCM )
src = src:gsub( "local ctmlevel = 0", "local ctmlevel = " .. CTM )
assert( src:find( "local rcmlevel = " .. RCM, 1, true ), "rcmlevel patch did not apply" )
assert( src:find( "local ctmlevel = " .. CTM, 1, true ), "ctmlevel patch did not apply" )
assert( load( src, "hub_cmd_manager", "t" ) )( )

local function user( level ) return { level = function( ) return level end } end

----------------------------------------------------------------------
-- sanity + parity guards (pass on both pre- and post-fix revisions)
----------------------------------------------------------------------

eq( "onConnectToMe registered",    _registered.onConnectToMe    ~= nil, true )
eq( "onRevConnectToMe registered", _registered.onRevConnectToMe ~= nil, true )
eq( "CTM gates below ctmlevel -> PROCESSED", _registered.onConnectToMe( user( 10 ) ),    1 )
eq( "RCM gates below rcmlevel -> PROCESSED", _registered.onRevConnectToMe( user( 10 ) ), 1 )

----------------------------------------------------------------------
-- the fix: NAT traversal gated too, with role-correct level mapping
-- RED pre-fix: the two "registered" checks fail; guarded calls skipped.
----------------------------------------------------------------------

eq( "onNatTraversal registered",      _registered.onNatTraversal      ~= nil, true )
eq( "onNatTraversalReply registered", _registered.onNatTraversalReply ~= nil, true )

local nat = _registered.onNatTraversal
local rnt = _registered.onNatTraversalReply
if nat then
    -- gated by ctmlevel (40); level 30 blocked also proves NOT rcmlevel (20)
    eq( "NAT: below ctmlevel -> PROCESSED",  nat( user( 30 ) ), 1 )
    eq( "NAT: at/above ctmlevel -> nil",     nat( user( 50 ) ), nil )
end
if rnt then
    -- gated by rcmlevel (20); level 30 allowed also proves NOT ctmlevel (40)
    eq( "RNT: at/above rcmlevel -> nil",     rnt( user( 30 ) ), nil )
    eq( "RNT: below rcmlevel -> PROCESSED",  rnt( user( 10 ) ), 1 )
end

----------------------------------------------------------------------
-- summary
----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures > 0 and 1 or 0 )
