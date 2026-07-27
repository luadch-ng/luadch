--[[

    tests/unit/etc_forcetlstransfer_test.lua

    Unit tests for scripts/etc_forcetlstransfer.lua (#500 force ADCS C2C).
    All-or-nothing gate - NO level / whitelist exemption. Exercises:
      - is_tls classifier: ADCS/ prefix allow-list; ADC/1.0, NEODC,
        "ADCSX/" (not fooled), lowercase, nil, "" all count as plain
      - check (block): plain -> PROCESSED + BOTH parties notified via PM
        (with the setup link); ADCS -> pass (nil), no notify
      - check (warn): plain -> pass (nil) + both notified; ADCS -> no notify
      - all four setup events (CTM/RCM/NAT/RNT) drop a plain setup
      - notify dedupe per firstnick (30s window); onLogout clears the entry
      - fail-closed: unknown mode blocks; a throwing notify still blocks
      - nil target / nil protocol handled

    Plugins get NO `use`; every dependency is a sandbox-global stub.
    Run: lua5.4 tests/unit/etc_forcetlstransfer_test.lua

]]--

----------------------------------------------------------------------
-- Tiny harness
----------------------------------------------------------------------
local _pass, _fail = 0, 0
local function eq( what, got, want )
    if got == want then _pass = _pass + 1
    else _fail = _fail + 1
        io.stderr:write( string.format( "FAIL: %s\n  got:  %s\n  want: %s\n",
            what, tostring( got ), tostring( want ) ) ) end
end
local function truthy( what, v ) if v then _pass = _pass + 1
    else _fail = _fail + 1; io.stderr:write( "FAIL: " .. what .. " got=" .. tostring( v ) .. "\n" ) end end
local function falsy( what, v ) if not v then _pass = _pass + 1
    else _fail = _fail + 1; io.stderr:write( "FAIL: " .. what .. " got=" .. tostring( v ) .. "\n" ) end end

----------------------------------------------------------------------
-- Controllable clock + cfg
----------------------------------------------------------------------
local _now = 1000000
local _cfg
local function reset_cfg( )
    _cfg = { language = "en", etc_forcetlstransfer_mode = "block" }
end

----------------------------------------------------------------------
-- Sandbox globals ( no `whitelist` - the plugin no longer uses it )
----------------------------------------------------------------------
_G.use = nil
_G.PROCESSED = "PROCESSED"
_G.table, _G.string, _G.math = table, string, math
_G.type, _G.pairs, _G.ipairs, _G.next = type, pairs, ipairs, next
_G.tonumber, _G.tostring, _G.pcall = tonumber, tostring, pcall

local _real_os = os
_G.os = setmetatable( { time = function( ) return _now end }, { __index = _real_os } )

_G.cfg = {
    get          = function( k ) return _cfg[ k ] end,
    loadlanguage = function( ) return { } end,
}
_G.utf = { format = function( fmt, ... ) return string.format( fmt, ... ) end }
_G.hub = {
    setlistener = function( ev, _opts, fn ) _G._listeners[ ev ] = fn end,
    debug       = function( ) end,
    getbot      = function( ) return "bot" end,
}

local function mkuser( ip, nick )
    local u
    u = {
        ip        = function( ) return ip end,
        firstnick = function( ) return nick or ( "u" .. tostring( ip ) ) end,
        reply     = function( _, msg, from, pm )
            u._replies = ( u._replies or 0 ) + 1; u._last = msg; u._pm = pm ~= nil
        end,
    }
    return u
end

local function mkcmd( proto ) return { [ 8 ] = proto } end

local function load_plugin( overrides )
    reset_cfg( )
    if overrides then for k, v in pairs( overrides ) do _cfg[ k ] = v end end
    _G._listeners = { }
    local p = assert( loadfile( "scripts/etc_forcetlstransfer.lua" ) )( )
    return p, _G._listeners
end

----------------------------------------------------------------------
-- is_tls classifier
----------------------------------------------------------------------
do
    local p = load_plugin( )
    truthy( "is_tls: ADCS/0.10",         p._is_tls( "ADCS/0.10" ) )
    truthy( "is_tls: ADCS/ bare prefix", p._is_tls( "ADCS/" ) )
    falsy( "is_tls: ADC/1.0 plain",      p._is_tls( "ADC/1.0" ) )
    falsy( "is_tls: NEODC",              p._is_tls( "NEODC/1.0" ) )
    falsy( "is_tls: ADCSX not fooled",   p._is_tls( "ADCSX/1.0" ) )
    falsy( "is_tls: lowercase adcs",     p._is_tls( "adcs/0.10" ) )
    falsy( "is_tls: nil",                p._is_tls( nil ) )
    falsy( "is_tls: empty",              p._is_tls( "" ) )
    eq( "PROTO_IDX is 8", p._PROTO_IDX, 8 )
end

----------------------------------------------------------------------
-- block mode + listeners
----------------------------------------------------------------------
do
    local p, L = load_plugin( )
    truthy( "listener: onConnectToMe registered",       L.onConnectToMe )
    truthy( "listener: onRevConnectToMe registered",    L.onRevConnectToMe )
    truthy( "listener: onNatTraversal registered",      L.onNatTraversal )
    truthy( "listener: onNatTraversalReply registered", L.onNatTraversalReply )
    eq( "listener: all four are the same handler",
        L.onConnectToMe, L.onNatTraversalReply )

    -- plain -> block + BOTH parties notified via PM ( with the setup link )
    local s, t = mkuser( "1.0.0.1" ), mkuser( "1.0.0.2" )
    eq( "block: plain -> PROCESSED", L.onConnectToMe( s, t, mkcmd( "ADC/1.0" ) ), "PROCESSED" )
    eq( "block: sender notified once", s._replies, 1 )
    eq( "block: target also notified", t._replies, 1 )
    truthy( "block: notify is a PM (sender)", s._pm )
    truthy( "block: notify is a PM (target)", t._pm )
    truthy( "block: message carries the setup link",
        s._last and s._last:find( "dcvault.net", 1, true ) )

    -- ADCS -> pass, no notify
    local a, b = mkuser( "1.0.0.3" ), mkuser( "1.0.0.4" )
    eq( "block: ADCS passes (nil)", L.onConnectToMe( a, b, mkcmd( "ADCS/0.10" ) ), nil )
    falsy( "block: ADCS no notify (sender)", a._replies )
    falsy( "block: ADCS no notify (target)", b._replies )

    -- no exemption: a plain setup is blocked whoever the parties are;
    -- nil target / nil protocol are handled ( treated as plain, no crash )
    eq( "block: nil target -> still blocked",
        L.onConnectToMe( mkuser( "1.0.1.5" ), nil, mkcmd( "ADC/1.0" ) ), "PROCESSED" )
    eq( "block: nil protocol -> plain -> blocked",
        L.onConnectToMe( mkuser( "1.0.1.6" ), mkuser( "1.0.1.7" ), mkcmd( nil ) ), "PROCESSED" )
end

----------------------------------------------------------------------
-- all four setup events: plain dropped / ADCS forwarded
----------------------------------------------------------------------
do
    local p, L = load_plugin( )
    for _, ev in ipairs{ "onConnectToMe", "onRevConnectToMe", "onNatTraversal", "onNatTraversalReply" } do
        eq( ev .. ": plain dropped",
            L[ ev ]( mkuser( "9.0.0.1" ), mkuser( "9.0.0.2" ), mkcmd( "ADC/1.0" ) ), "PROCESSED" )
        eq( ev .. ": ADCS passes",
            L[ ev ]( mkuser( "9.0.0.3" ), mkuser( "9.0.0.4" ), mkcmd( "ADCS/0.10" ) ), nil )
    end
end

----------------------------------------------------------------------
-- warn mode
----------------------------------------------------------------------
do
    local p, L = load_plugin( { etc_forcetlstransfer_mode = "warn" } )
    local u1, u2 = mkuser( "2.0.0.1" ), mkuser( "2.0.0.2" )
    eq( "warn: plain passes (nil)", L.onConnectToMe( u1, u2, mkcmd( "ADC/1.0" ) ), nil )
    eq( "warn: sender notified", u1._replies, 1 )
    eq( "warn: target notified", u2._replies, 1 )
    truthy( "warn: notify is a PM", u1._pm )
    truthy( "warn: message carries the setup link",
        u1._last and u1._last:find( "dcvault.net", 1, true ) )
    local a1 = mkuser( "2.0.0.3" )
    eq( "warn: ADCS passes (nil)", L.onConnectToMe( a1, mkuser( "2.0.0.4" ), mkcmd( "ADCS/0.10" ) ), nil )
    falsy( "warn: ADCS no notify", a1._replies )
end

----------------------------------------------------------------------
-- notify dedupe per sender + onLogout clear
----------------------------------------------------------------------
do
    local p, L = load_plugin( )
    local s = mkuser( "3.0.0.1", "spammer" )
    L.onConnectToMe( s, mkuser( "3.0.0.2" ), mkcmd( "ADC/1.0" ) )
    L.onConnectToMe( s, mkuser( "3.0.0.3" ), mkcmd( "ADC/1.0" ) )
    L.onRevConnectToMe( s, mkuser( "3.0.0.4" ), mkcmd( "ADC/1.0" ) )
    eq( "dedupe: burst within interval -> notified once", s._replies, 1 )
    _now = _now + 31
    L.onConnectToMe( s, mkuser( "3.0.0.5" ), mkcmd( "ADC/1.0" ) )
    eq( "dedupe: notified again after interval", s._replies, 2 )
    _now = 1000000
end

do
    local p, L = load_plugin( )
    local s = mkuser( "5.0.0.1", "leaver" )
    L.onConnectToMe( s, mkuser( "5.0.0.2" ), mkcmd( "ADC/1.0" ) )
    eq( "logout: notified once", s._replies, 1 )
    L.onConnectToMe( s, mkuser( "5.0.0.3" ), mkcmd( "ADC/1.0" ) )
    eq( "logout: deduped before logout", s._replies, 1 )
    L.onLogout( s )
    L.onConnectToMe( s, mkuser( "5.0.0.4" ), mkcmd( "ADC/1.0" ) )
    eq( "logout: entry cleared -> notifies again within interval", s._replies, 2 )
end

----------------------------------------------------------------------
-- fail-closed hardening
----------------------------------------------------------------------
do
    -- unknown mode -> BLOCKS (fail-closed), never silently passes through
    local p, L = load_plugin( { etc_forcetlstransfer_mode = "blokc" } )
    eq( "fail-closed: unknown mode blocks a plain setup",
        L.onConnectToMe( mkuser( "6.0.0.1" ), mkuser( "6.0.0.2" ), mkcmd( "ADC/1.0" ) ), "PROCESSED" )
end

do
    -- a throwing notify (reply errors) must NOT turn a block into a pass
    local p, L = load_plugin( )
    local bad = { ip = function( ) return "6.0.1.1" end, firstnick = function( ) return "bad" end,
                  reply = function( ) error( "boom" ) end }
    eq( "fail-closed: notify error still blocks",
        L.onConnectToMe( bad, mkuser( "6.0.1.2" ), mkcmd( "ADC/1.0" ) ), "PROCESSED" )
end

----------------------------------------------------------------------
io.write( string.format( "\netc_forcetlstransfer: %d passed, %d failed\n", _pass, _fail ) )
os.exit( _fail == 0 and 0 or 1 )
