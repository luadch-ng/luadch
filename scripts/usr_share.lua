--[[

    usr_share.lua by blastbeat

        - this script checks the share size of a user

        v0.13: by Aybo
            - kill TL on the share-size-limit path (both min and max
              branches) changed from TL300 to TL-1 (don't auto-
              reconnect). The user cannot satisfy a min-share / max-
              share rule by waiting 5 minutes - they need to add or
              remove files from their share, a client-side change.

        v0.12:
            - fix dead German translation: lookup was `lang.msg_minmax`
              but the .lang.{de,en} files define the key as
              `msg_sharelimits` (introduced in v0.06 with the new output
              msg). The wrong-named lookup always returned nil so the
              `or` fallback to the hardcoded English literal fired on
              every msg, and the German translation was unreachable.
              Part of #301.

        v0.11: by pulsar
            - changed visuals
            - removed table lookups

        v0.10: by pulsar
            - added "usr_share_redirect"
                - use redirect instead of disconnect

        v0.09: by pulsar
            - added "etc_trafficmanager_check_minshare"
                - block user instead of disconnect if usershare < minshare

        v0.08: by pulsar
            - improved user:kill()

        v0.07: by pulsar
            - using min/max share tables to check share separate for each level

        v0.06: by pulsar
            - fix share check  / thx Kaas
            - add table lookups
            - new output msg

        v0.05: by pulsar
            - changed calc of share

        v0.04: by pulsar
            - export scriptsettings to "/cfg/cfg.tbl"

        v0.03: by blastbeat
            - updated script api

        v0.02: by blastbeat
            - added language files

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "usr_share"
local scriptversion = "0.13"

--// imports
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or {}; err = err and hub.debug( err )
local min_share = cfg.get( "min_share" )
local max_share = cfg.get( "max_share" )
local minsharecheck = cfg.get( "etc_trafficmanager_check_minshare" )
local trafficmanager_activate = cfg.get( "etc_trafficmanager_activate" )
local usr_share_redirect = cfg.get( "usr_share_redirect" )
local redirect_url = cfg.get( "cmd_redirect_url" )

--// msgs
local msg_sharelimits = lang.msg_sharelimits or "[ USER SHARE ]--> Hub min share:  %s  |  Hub max share:  %s  |  Your share:  %s"
local msg_redirect = lang.msg_redirect or "[ USER SHARE ]--> You got redirected because:  "


----------
--[CODE]--
----------

local check = function( user )
    local user_level = user:level()
    -- Phase 8a F-INF-1: a client that did not send SS in BINF (or sent
    -- an unparseable one) leaves user:share() == nil. Pre-fix, the
    -- comparison below crashed with "attempt to compare number with
    -- nil" on every such login. Treat missing share as 0 so the
    -- min-share policy still applies (a client with no SS fails the
    -- min-share check exactly like a client with SS=0 would).
    local user_share = user:share() or 0
    local min = min_share[ user_level ] * 1024 * 1024 * 1024
    local max = max_share[ user_level ] * 1024 * 1024 * 1024 * 1024
    if user_share > max then
        if usr_share_redirect then
            local msg_out = hub.escapeto( utf.format( msg_sharelimits, util.formatbytes( min ), util.formatbytes( max ), util.formatbytes( user_share ) ) )
            local msg_redirect = hub.escapeto( msg_redirect )
            user:redirect( redirect_url, msg_redirect .. msg_out )
            return PROCESSED
        else
            local msg_out = hub.escapeto( utf.format( msg_sharelimits, util.formatbytes( min ), util.formatbytes( max ), util.formatbytes( user_share ) ) )
            user:kill( "ISTA 120 " .. msg_out .. "\n", "TL-1" )
            return PROCESSED
        end
    end
    if user_share < min then
        if usr_share_redirect then
            local msg_out = hub.escapeto( utf.format( msg_sharelimits, util.formatbytes( min ), util.formatbytes( max ), util.formatbytes( user_share ) ) )
            local msg_redirect = hub.escapeto( msg_redirect )
            user:redirect( redirect_url, msg_redirect .. msg_out )
            return PROCESSED
        else
            if not ( trafficmanager_activate and minsharecheck ) then
                local msg_out = hub.escapeto( utf.format( msg_sharelimits, util.formatbytes( min ), util.formatbytes( max ), util.formatbytes( user_share ) ) )
                user:kill( "ISTA 120 " .. msg_out .. "\n", "TL-1" )
                return PROCESSED
            end
        end
    end
    return nil
end

hub.setlistener( "onInf", {},
    function( user, cmd )
        if cmd:getnp "SS" then
            return check( user )
        end
        return nil
    end
)

hub.setlistener( "onConnect", {},
    function( user )
        return check( user )
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )