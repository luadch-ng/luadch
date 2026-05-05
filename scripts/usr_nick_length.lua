--[[

    usr_nick_length.lua by blastbeat

        - this script checks for proper nicknames onConnect and onInf

]]--


local scriptname = "usr_nick_length.lua"
local scriptversion = "0.01"

local check = function( user, nick )
    -- min/max_nickname_length is documented in codepoints; use utf.len so
    -- multi-byte (e.g. Cyrillic) nicks aren't rejected at lower codepoint
    -- counts than ASCII nicks.
    local len = utf.len( nick )
    if ( cfg.get "min_nickname_length" <= len ) and ( len <= cfg.get "max_nickname_length" ) then
        return nil
    end
    --remember: never fire listenter X inside listener X; will cause infinite loop
    -- failure-reason string is hardcoded English; i18n tracked in #48.
    scripts.firelistener( "onFailedAuth", nick, user:ip( ), user:cid( ), "Invalid nick length: " .. len )
    user:kill( "ISTA 221 " .. hub.escapeto( "Invalid nick length." ) .. "\n", "TL300" )
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
