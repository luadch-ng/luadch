--[[

        etc_unknown_command.lua by blastbeat

        - this script avoids mistyped commands in mainchat

        - changelog 0.04:
          - route msg_denied through lang. New lang file
            scripts/lang/{de,en}/etc_unknown_command.json.
            Part of #301 i18n cleanup.

        - changelog 0.03: by pulsar
          - check leading spaces on commands
            - thx Sopor for the idea and perlaxe for the code changes

        - changelog 0.02:
          - updated script api

]]--

--// settings begin //--

local scriptname = "etc_unknown_command"
local scriptversion = "0.04"

-- #301 PR-4: route the denial msg through lang (was hardcoded English).
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or {}; err = err and hub.debug( err )
local msg_denied = lang.msg_denied or "Unknown command. Check leading spaces and syntax."

--// settings end //--

local utf_match = utf.match

local hub_getbot = hub.getbot

hub.setlistener( "onBroadcast", { },
    function( user, cmd, txt )
        --local command = utf_match( txt, "^[+!#](%a+)" )
        local command = utf_match( txt, "^%s*[!#+](%a+)" )
        if command then
            user:reply( msg_denied, hub_getbot( ) )
            return PROCESSED
        end
        return nil
    end
)

hub.debug( "** Loaded "..scriptname.." "..scriptversion.." **" )