--[[

    usr_nick_length.lua by blastbeat

        - this script checks for proper nicknames onConnect and onInf

        v0.03: by Aybo
            - kill TL on invalid-nick-length changed from TL300 to TL-1
              (don't auto-reconnect). The user cannot satisfy the min /
              max nick length by waiting 5 minutes - they need a
              different nick, which is a client-side config change.

        v0.02: by Aybo
            - i18n the onFailedAuth reason (operator-facing, lands in
              cmd.log / blacklist scripts) and the ISTA 221 kill message
              (user-facing). Closes the i18n half of #48 for this script.
              Both strings now route through scripts/lang/usr_nick_length.lang.{en,de}.

]]--


local scriptname = "usr_nick_length"
local scriptversion = "0.03"
local scriptlang = cfg.get "language"

local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub.debug( err )

local msg_failedauth_reason = lang.msg_failedauth_reason or "Invalid nick length: "
local msg_invalid_length    = hub.escapeto( lang.msg_invalid_length or "Invalid nick length." )

local check = function( user, nick )
    -- min/max_nickname_length is documented in codepoints; use utf.len so
    -- multi-byte (e.g. Cyrillic) nicks aren't rejected at lower codepoint
    -- counts than ASCII nicks.
    local len = utf.len( nick )
    if ( cfg.get "min_nickname_length" <= len ) and ( len <= cfg.get "max_nickname_length" ) then
        return nil
    end
    --remember: never fire listenter X inside listener X; will cause infinite loop
    scripts.firelistener( "onFailedAuth", nick, user:ip( ), user:cid( ), msg_failedauth_reason .. len )
    user:kill( "ISTA 221 " .. msg_invalid_length .. "\n", "TL-1" )
    return PROCESSED
end

hub.setlistener( "onConnect", { },
    function( user )
        return check( user, user:nick( ) )
    end
)

hub.setlistener( "onInf", { },
    function( user, cmd )
        for name, value in cmd:getallnp( ) do
            if name == "NI" then
                return check( user, value )
            end
        end
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )
