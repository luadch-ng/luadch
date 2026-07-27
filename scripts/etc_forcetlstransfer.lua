--[[

    etc_forcetlstransfer.lua v0.01 by Aybo ( #500 )

        Force encrypted ( ADCS ) client-to-client transfers. ADC peer-
        connection setup ( CTM / RCM / NAT-traversal ) routes through the
        hub and carries the transfer protocol as its first positional
        param: `ADC/1.0` ( plain ) vs `ADCS/0.10` ( TLS ). The hub cannot
        encrypt or inspect the transfer itself ( client-to-client, the
        peers' own certs ), but it CAN refuse to broker a plain setup -
        which is enough to force TLS. A dropped plain setup fails that one
        transfer; it is not auto-upgraded ( that is the point - it pushes
        users to enable "forced" transfer encryption / forward their TLS
        port ).

        Covers all four setup events. NAT-traversal is a SEPARATE path
        from CTM / RCM and must be covered too; the E-class variants
        ( ECTM / ERCM ) fire the same onConnectToMe / onRevConnectToMe
        listeners, so one handler per event covers D and E.

        Modes ( etc_forcetlstransfer_mode, default "block" ):
          - "block" ( default ): drop the plain setup ( return PROCESSED )
            and notify both parties ( sender + target ). Enforces TLS
            immediately.
          - "warn": let the plain setup pass but notify both parties - a
            softer roll-out that breaks nothing while users switch.

        No exemptions - all-or-nothing. When the plugin is loaded, EVERY
        plain transfer is acted on ( no level or IP escape hatch ): either
        you want all transfers encrypted or you don't, so the only knob is
        the mode. Bots / infra that still transfer plain must move to ADCS
        too; if a hub genuinely needs plain transfers, it simply does not
        load this plugin.

        Allow-LIST the protocol ( `^ADCS/` passes ), never blacklist
        `ADC/1.0`: version suffixes vary and unknown / non-ADCS protocols
        must be treated as plain.

        Notes:
          - CCPM ( client-to-client PM ) always uses ADCS, so it is never
            blocked here ( unlike etc_trafficmanager's level block ).
          - Any mode other than "warn" fails CLOSED ( blocks ), and the
            block decision is locked in before the best-effort notify, so
            neither a misconfig nor a notify error can silently disable
            enforcement.
          - Listener order: this handler returns PROCESSED / nil only, but
            the firelistener chain lets the FIRST non-nil return win. Keep
            this ahead of any plugin that returns a truthy non-PROCESSED
            sentinel on these events, or its drop could be masked. The
            bundled etc_trafficmanager returns only PROCESSED / nil, so the
            default plugin set is safe in any order.

        Off by default: add { "etc_forcetlstransfer.lua", enabled = false }
        to cfg.scripts to load it.

]]--


--------------
--[SETTINGS]--
--------------

local scriptname    = "etc_forcetlstransfer"
local scriptversion = "0.01"

--// imports
local scriptlang = cfg.get( "language" )
local lang, lang_err = cfg.loadlanguage( scriptlang, scriptname )
lang = lang or { }
if lang_err then hub.debug( lang_err ) end

local mode             = cfg.get( "etc_forcetlstransfer_mode" ) or "block"
-- Fail-closed: only an explicit "warn" lets a plain setup pass; anything
-- else ( incl. an unexpected value ) blocks, so a misconfigured mode can
-- never silently disable enforcement.
local blocking         = ( mode ~= "warn" )

--// table lookups
local hub_getbot   = hub.getbot
local os_time      = os.time
local string_match = string.match

-- The transfer protocol is the FIRST positional param of the CTM / RCM /
-- NAT / RNT setup command. D/E-class commands carry a 2-SID header, and
-- the parser interleaves separator slots, so positional #1 lands at
-- adccmd[8] ( the same slot a DMSG body occupies ). CTM/NAT/RNT are
-- {protocol, port, token}; RCM is {protocol, token} - protocol is
-- adccmd[8] in every case.
local PROTO_IDX = 8

-- Per-sender notify throttle so a burst of setup commands ( a client
-- retrying, or one download firing RCM then CTM ) does not spam.
local NOTIFY_INTERVAL = 30
local last_notify = { }


--// lang
-- Role-neutral wording: the same message goes to BOTH the sender and the
-- target of the setup, so it must read correctly for either side.
local msg_block = lang.msg_block or "[ FORCE TLS ]--> An unencrypted transfer was blocked - this hub requires encrypted ( ADCS ) transfers. Please enable forced transfer encryption in your client and forward your TLS port. Setup guide: https://dcvault.net/docs/clients/installation-setup#connection"
local msg_warn  = lang.msg_warn  or "[ FORCE TLS ]--> An unencrypted transfer was detected - this hub asks for encrypted ( ADCS ) transfers. Please enable forced transfer encryption in your client and forward your TLS port. Setup guide: https://dcvault.net/docs/clients/installation-setup#connection"


----------
--[CODE]--
----------

-- Allow-list: only a protocol that starts with "ADCS/" is TLS. Anything
-- else ( ADC/1.0, NEODC, unknown, or a missing field ) counts as plain.
local function is_tls( proto )
    return type( proto ) == "string" and string_match( proto, "^ADCS/" ) ~= nil
end

-- Notify one party ( sender or target ) via PM, throttled per firstnick
-- so neither a retrying client nor a popular uploader gets spammed. A nil
-- party ( e.g. a target that just left ) is skipped.
local function notify( u )
    if not u then return end
    local nick = u:firstnick( )
    if not nick then return end
    local now  = os_time( )
    local last = last_notify[ nick ]
    if last and ( now - last ) < NOTIFY_INTERVAL then return end
    last_notify[ nick ] = now
    u:reply( blocking and msg_block or msg_warn, hub_getbot( ), hub_getbot( ) )
end

-- Shared handler for all four setup events. Returns PROCESSED to DROP the
-- setup ( block mode ), or nil to let it pass ( warn mode, or an already-
-- TLS transfer ). No exemptions: an enabled hub forces TLS on EVERY
-- transfer - if you want a plain transfer, do not load this plugin.
local function check( user, target, adccmd )
    if is_tls( adccmd[ PROTO_IDX ] ) then return nil end
    -- Lock in the decision FIRST, then notify best-effort ( pcall ): the
    -- listener chain forwards a plain setup if a listener throws, so a
    -- notify error must never turn a block into a pass. Both endpoints
    -- need TLS, so notify both.
    local decision = blocking and PROCESSED or nil
    pcall( notify, user )
    pcall( notify, target )
    return decision
end


-----------------
--[LIFECYCLE ]--
-----------------

-- ECTM / ERCM fire onConnectToMe / onRevConnectToMe too, so one handler
-- per event covers D and E. NAT-traversal is a separate path.
hub.setlistener( "onConnectToMe",       { }, check )
hub.setlistener( "onRevConnectToMe",    { }, check )
hub.setlistener( "onNatTraversal",      { }, check )
hub.setlistener( "onNatTraversalReply", { }, check )

-- Bound the notify-throttle table to the online population: clear a
-- sender's entry when they leave. Otherwise it would accumulate one entry
-- per distinct firstnick for the hub's whole uptime ( the throttle only
-- ever needs entries younger than NOTIFY_INTERVAL ).
hub.setlistener( "onLogout", { },
    function( user )
        local nick = user:firstnick( )
        if nick then last_notify[ nick ] = nil end
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

--// expose internals for unit tests
return {
    _is_tls      = is_tls,
    _check       = check,
    _notify      = notify,
    _PROTO_IDX   = PROTO_IDX,
}
