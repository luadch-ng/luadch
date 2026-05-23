--[[

        hub_inf_manager by blastbeat

        - this script kills users with forbidden inf flags
        - do not change anything here when you dont know what you are doing

        v0.07: by Aybo
            - #222: split flags_on_inf into _kill (PD/ID, identity
              spoofing) and _strip (I4/I6, IP mutation). Post-login
              INF with I4 or I6 is now silent-stripped instead of
              killing the user. Real DC++ clients refresh INF
              (incl. I4) on routine triggers - killing them was
              user-hostile. Anti-spoofing preserved: stored _inf
              IP fields are NEVER mutated, broadcast does not
              carry the new IP claim.

        v0.06: by Aybo
            - re-enabled "I4" + added "I6" to flags_on_inf
                - paired with the kill_wrong_ips default flip in #97;
                  closes the "user changes their advertised IP after
                  login via a fresh BINF in normal state" path that
                  the on-connect check alone cannot cover

        v0.05: by pulsar
            - improved user:kill()

        v0.04: by pulsar
            - commented "I4" in flags_on_inf table to prevent check

        v0.03: by blastbeat
          - updated script api

]]--

local scriptname = "hub_inf_manager"
local scriptversion = "0.07"
local scriptlang = cfg.get "language"

local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub.debug( err )

local msg_invalid = hub.escapeto( lang.msg_invalid or "invalid named parameter in inf: " )
local msg_failedauth_reason = lang.msg_failedauth_reason or "User sent offending flag in INF: "

--// forbidden named parameters in inf //--

local forbidden = {

    flags = {

        "HI",
        "CT",
        "OP",
        "RG",
        "HU",
        "BO",

    },
    -- Identity-spoofing attempts on PD / ID post-login = kill. These
    -- are the user's permanent identifier; mutation IS the attack.
    flags_on_inf_kill = {

        "PD",
        "ID",

    },
    -- #97 / #222: I4 / I6 are valid in the initial BINF (the hub
    -- validates and fills them in core/hub_dispatch.lua) but MUST NOT
    -- be changed after login - allowing it would let a normal-state
    -- user re-stamp their advertised IP and bypass per-IP rate
    -- limits / GeoIP rules / abuse logs.
    --
    -- v0.07 (#222): silent-strip instead of kill. Real DC++ clients
    -- emit post-login INF updates that include I4 on routine triggers
    -- (NAT rebind, ISP-IP change, plain refresh). Killing them on
    -- every such update was user-hostile; the original "clients
    -- reconnect if their NAT setup changes mid-session" assumption
    -- doesn't hold in practice. Stripping preserves anti-spoofing
    -- (stored _inf never mutated, broadcast doesn't carry the new
    -- claim) without disconnecting legitimate sessions.
    --
    -- T3.1 HBRI re-affirms this: under HBRI a BINF carries BOTH
    -- I4 and I6, but the hub validates only the family that
    -- matches the TCP source. The other family is unverified-
    -- but-stored. If a future contributor relaxes the post-login
    -- strip on the assumption "hub validated I4 / I6 at BINF so
    -- post-login mutation is OK", they re-open #97 because the
    -- OTHER family was never validated to begin with.
    flags_on_inf_strip = {

        "I4",
        "I6",

    },

}

local check = function( cmd, flags )
    for i, name in ipairs( flags ) do    -- check if user sends forbidden parameters...
        if cmd:getnp( name ) then
            return nil, ( name or "" )
        end
    end
    return true
end

local fire_onfailedauth = function( user, offending_flag )
    -- remember: never fire listenter X inside listener X; will cause infinite loop
    -- also: never fire listener X in listener Y, where listener Y fires listener X; will as well cause a infinite loop.
    scripts.firelistener( "onFailedAuth", user:nick( ), user:ip( ), user:cid( ), msg_failedauth_reason .. offending_flag )
end

hub.setlistener( "onConnect", { },
    function( user )
        local cmd = user:inf( )
        local valid, offending_flag = check( cmd, forbidden.flags )
        if not valid then
            fire_onfailedauth( user, offending_flag )
            user:kill( "ISTA 240 " .. msg_invalid .. offending_flag .. "\n", "TL300" )
            return PROCESSED
        end
        return nil
    end
)

hub.setlistener( "onInf", { },
    function( user, cmd )
        local valid, offending_flag = check( cmd, forbidden.flags )
        if not valid then
            fire_onfailedauth( user, offending_flag )
            user:kill( "ISTA 240 " .. msg_invalid .. offending_flag .. "\n", "TL300" )
            return PROCESSED
        end
        valid, offending_flag = check( cmd, forbidden.flags_on_inf_kill )
        if not valid then
            fire_onfailedauth( user, offending_flag )
            user:kill( "ISTA 240 " .. msg_invalid .. offending_flag .. "\n", "TL300" )
            return PROCESSED
        end
        -- #222: silent-strip I4 / I6 from post-login INF updates.
        -- See `flags_on_inf_strip` block above for rationale. The
        -- mutation is non-fatal for the user; the stripped fields
        -- never reach the broadcast (cmd:deletenp removes them
        -- from cmd's iteration AND from the outbound wire form).
        for _, name in ipairs( forbidden.flags_on_inf_strip ) do
            if cmd:getnp( name ) then
                cmd:deletenp( name )
                hub.debug( scriptname .. ": stripped post-login INF flag "
                    .. name .. " from " .. ( user:nick( ) or "?" ) )
            end
        end
        local discard
        local user_inf = user:inf( )
        for name, value in cmd:getallnp( ) do
            if name == "NI" then
                if cfg.get "nick_change" then    -- nick change allowed?
                    local bol, err = user:updatenick( value, true )
                    if err then
                        cmd:deletenp "NI"
                        user:reply( err, hub.getbot( ) )
                    end
                else
                    cmd:deletenp "NI"    -- delete new nick from inf
                    --discard = true    -- no parameter left in inf -> discard message
                end
            else
                user_inf:setnp( name, value )    -- change user inf
            end
        end
        if discard then
            return PROCESSED
        else
            return nil
        end
    end
)

hub.debug( "** Loaded "..scriptname.." "..scriptversion.." **" )
