--[[

    tests/unit/hbri_test.lua

    Committed unit test for core/hbri.lua (#214 / #291 / #286 HBRI).
    Pure Lua, no hub, no sockets: stubs the `use` sandbox shim, loads the
    module, and asserts the activation gate (active()) and the eligibility
    contract (eligible()) - the two pure predicates that decide whether the
    hub solicits HBRI at all.

    These two predicates are the security-relevant gate: active() must be
    false unless the hub is fully HBRI-capable (enabled + dual-stack + both
    plain ports + both advertise addresses), and eligible() must only fire
    for an HBRI-supporting client that claimed a secondary on the family
    OPPOSITE its main connection. #294 made the hub feed active() a nil
    port for a TLS-only family (no plain listener); this test locks the
    contract that a nil port -> active() false -> no solicit (secondary
    stays stripped), so a regression in either the gate or the port wiring
    is caught.

    The side-effecting paths (initiate / validate / sweep / commit) need a
    real socket + adccmd and are covered by tests/smoke/run.py; this file
    deliberately tests only the pure predicates.

    Run: lua tests/unit/hbri_test.lua   (any Lua 5.4)
    Exit code 0 = all pass, 1 = a failure (CI-friendly).

]]--

-- minimal sandbox shim: core/hbri.lua does `local x = use "x"`.
-- Keep this in lockstep with hbri.lua's `use` imports.
local _real = {
    pairs = pairs, tostring = tostring, ipairs = ipairs,
    os = { time = function( ) return 0 end },
    -- only initiate() touches adclib/cfg; the predicates under test do
    -- not, but the module resolves these at load time.
    adclib = { createsalt = function( ) return "TESTTOKEN0000000" end },
    cfg = { get = function( ) return nil end },
}
_G.use = function( name )
    local v = _real[ name ]
    assert( v ~= nil, "hbri_test shim missing dep: use \"" .. name .. "\"" )
    return v
end

local hbri = assert( loadfile( "core/hbri.lua" ) )( )

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

-- Sentinel for "override this dep to nil" - a plain `{ k = nil }` table
-- cannot express that (Lua drops nil-valued keys), which would silently
-- no-op a nil-port test case.
local NIL = { }

-- A fully HBRI-capable bind. Individual cases clone + override one field.
local function bind_full( over )
    local deps = {
        enter_normal      = function( ) end,
        sendtoall         = function( ) end,
        hbri_enabled      = true,
        hbri_timeout      = 5,
        hbri_advertise_v4 = "203.0.113.1",
        hbri_advertise_v6 = "2001:db8::1",
        hbri_port_v4      = 5000,
        hbri_port_v6      = 5000,
        hbri_dual_stack   = true,
    }
    if over then for k, v in pairs( over ) do deps[ k ] = ( v ~= NIL ) and v or nil end end
    hbri.bind( deps )
end

----------------------------------------------------------------------
-- active(): the hub-capability gate. False unless EVERY prerequisite
-- holds; in particular a nil port (a TLS-only family after #294) or a
-- false dual_stack flag must disable HBRI.
----------------------------------------------------------------------

bind_full( ); eq( "active: all set", hbri.active( ), true )
bind_full{ hbri_enabled = false };          eq( "active: disabled",        hbri.active( ), false )
bind_full{ hbri_dual_stack = false };       eq( "active: not dual-stack",  hbri.active( ), false )
bind_full{ hbri_port_v6 = NIL };            eq( "active: no v6 plain port", hbri.active( ), false )
bind_full{ hbri_port_v4 = NIL };            eq( "active: no v4 plain port", hbri.active( ), false )
bind_full{ hbri_advertise_v4 = "" };        eq( "active: no v4 advertise",  hbri.active( ), false )
bind_full{ hbri_advertise_v6 = "" };        eq( "active: no v6 advertise",  hbri.active( ), false )

----------------------------------------------------------------------
-- eligible(): per-client gate. Needs active() + ADHBRI + a claimed
-- secondary on the family OPPOSITE the main connection. Placeholder
-- secondaries (::/0.0.0.0) are eligible (#291 discovery).
----------------------------------------------------------------------

local function mk_user( main_ip, claim, supports_hbri )
    return {
        _hbri_claim = claim,
        ip = function( ) return main_ip end,
        supports = function( _, feat ) return supports_hbri and feat == "HBRI" end,
    }
end

bind_full( )

-- v4 main connection, concrete I6 secondary claim -> eligible.
eq( "eligible: v4 main, concrete I6 claim",
    hbri.eligible( mk_user( "1.2.3.4", { family = "I6", ip = "2001:db8::5" }, true ) ), true )

-- v4 main, PLACEHOLDER I6 claim (the #291 discovery case) -> eligible.
eq( "eligible: v4 main, placeholder I6 claim",
    hbri.eligible( mk_user( "1.2.3.4", { family = "I6", ip = "::" }, true ) ), true )

-- v6 main, I4 secondary claim -> eligible (symmetric direction).
eq( "eligible: v6 main, I4 claim",
    hbri.eligible( mk_user( "2001:db8::9", { family = "I4", ip = "0.0.0.0" }, true ) ), true )

-- Client does not support HBRI -> not eligible.
eq( "eligible: no ADHBRI support",
    hbri.eligible( mk_user( "1.2.3.4", { family = "I6", ip = "::" }, false ) ), false )

-- No claim captured -> not eligible.
eq( "eligible: no claim",
    hbri.eligible( mk_user( "1.2.3.4", nil, true ) ), false )

-- Empty claim ip -> not eligible.
eq( "eligible: empty claim ip",
    hbri.eligible( mk_user( "1.2.3.4", { family = "I6", ip = "" }, true ) ), false )

-- Claim family SAME as the main family (cannot happen via the BINF
-- capture, but the gate must reject it) -> not eligible.
eq( "eligible: claim family == main family",
    hbri.eligible( mk_user( "1.2.3.4", { family = "I4", ip = "9.9.9.9" }, true ) ), false )

-- When the hub is not active, no client is eligible.
bind_full{ hbri_enabled = false }
eq( "eligible: hub inactive",
    hbri.eligible( mk_user( "1.2.3.4", { family = "I6", ip = "2001:db8::5" }, true ) ), false )

----------------------------------------------------------------------
io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
