--[[

        etc_hubcommands.lua v0.03 by blastbeat

        v0.07: by Aybo
            - alias-resolver fallback for #327. On a missed direct
              lookup the dispatcher consults etc_aliases via
              hub.import, resolves the typed token to a real
              command, and dispatches the real command with its
              own name in the echo line. Both miss-hints (the
              forgot-the-prefix "Did you mean +X?" and the
              literal-bracket "Try +X" hint) also resolve through
              the alias map so the suggestion is the real target,
              not the alias. The resolver is re-imported on every
              miss (no caching) so a +reload of etc_aliases never
              leaves a stale closure here.
            - public surface gets two additive helpers: has(cmd)
              for callers (etc_aliases at +addalias time) that
              want to validate a command name without reaching
              into the private `commands` table; list() returns a
              flat array of {name, fn} pairs so callers can group
              multi-name registrations (e.g. {useruptime, uu}) by
              function identity for display.

        v0.06:
            - route the three operator-facing chat hints (the
              "[command]" echo, the "Did you mean +X?" forgot-prefix
              hint, and the literal-bracket hint) through lang. New
              lang file scripts/lang/etc_hubcommands.lang.{de,en}.
              Part of #301 i18n cleanup.

        v0.05: by Aybo
            - catch users who type the literal `[+!#]command` form
              with the doc-notation brackets included
                - closes luadch-ng/luadch#137 (Sopor)
                - same swallow-and-hint mechanism as the bare-word
                  case; the hint never echoes the input args because
                  the args can carry a password (e.g. `[+!#]reg
                  <user> <pw>`)

        v0.04: by Aybo
            - upstream #223: catch the bare-word "forgot the prefix"
              case for known commands and reply with a hint

        v0.03: by blastbeat
            - improve error handling

        v0.02: by pulsar
            - add support for multiple commands, usage: hubcmd.add( { cmd1, cmd2, cmd3 ... }, onbmsg )

        v0.01: by blastbeat
            - this script exports a module to reg hubcommands

]]--

--// settings begin //--

--// settings end //--

local scriptname = "etc_hubcommands"
local scriptversion = "0.07"

local utf_match = utf.match
local utf_format = utf.format
local hub_getbot = hub.getbot

-- #301 PR-4: route the three operator-facing chat hints through lang
-- (previously hardcoded English). Defaults preserve the pre-#301
-- wording so an en hub sees no change.
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or {}; err = err and hub.debug( err )

local msg_command_echo     = lang.msg_command_echo     or "[command] %s"
local msg_did_you_mean     = lang.msg_did_you_mean     or "Did you mean +%s? Hub commands need the [+!#] prefix; your message was NOT sent to main chat."
local msg_literal_brackets = lang.msg_literal_brackets or "The `[+!#]` in the docs is notation for 'pick one of +, !, or #', not literal brackets. Try `+%s` (your message was NOT sent to main chat)."

local commands = { }

-- v0.07 (#327): alias resolution. Looks up etc_aliases on every
-- miss rather than caching, so a +reload of etc_aliases doesn't
-- leave a stale closure here. The plugin export shape is
-- documented in scripts/etc_aliases.lua; we tolerate its absence
-- (returns nil) and tolerate it not exposing a resolve function.
local resolve_alias = function( name )
    if not name then return nil end
    local m = hub.import( "etc_aliases" )
    if not m or not m.resolve then return nil end
    return m.resolve( name )
end

local reg_cmd = function( cmd, func )
    if ( type( cmd ) == "string" ) and ( type( func ) == "function" ) then
        if commands[ cmd ] then
            return false -- name is already registered
        end
        commands[ cmd ] = func
        return true
    end
    return false
end

local add = function( cmd, func ) -- quick and dirty...
    if type( cmd ) == "string" then
        cmd = { cmd }
    end
    if type( cmd ) == "table" then
        for _, name in pairs( cmd ) do
            if not reg_cmd( name, func ) then
                return false
            end
        end
        return true
    end
    return false
end

hub.setlistener( "onBroadcast", { },
    function( user, adccmd, txt )
        local cmd, parameters = utf_match( txt, "^[+!#](%a+) ?(.*)" )
        local func = commands[ cmd ]
        local effective_cmd = cmd
        -- v0.07 (#327): direct miss -> try the alias map. If the
        -- alias resolves to a real command, dispatch the real
        -- command and echo its name (not the alias) so the
        -- operator sees what actually ran.
        if cmd and not func then
            local target = resolve_alias( cmd )
            if target and commands[ target ] then
                func = commands[ target ]
                effective_cmd = target
            end
        end
        if func then
            user:reply( utf_format( msg_command_echo, txt ), hub_getbot( ) )
            return func( user, effective_cmd, parameters, txt )
        end
        -- Closes upstream luadch/luadch#223: catch the common "forgot
        -- the [+!#] prefix" mistake. If the message starts with a
        -- known command name as a whole word and is the entire line
        -- or "cmd args" (no period / question mark / etc - so not
        -- mid-sentence chat), swallow the broadcast and remind the
        -- operator. Conservative match: only `^cmd$` or `^cmd <args>$`.
        local first_word = utf_match( txt, "^(%a+)$" ) or utf_match( txt, "^(%a+) " )
        if first_word then
            -- v0.07 (#327): hint at the real command, not the alias.
            local fw_target = commands[ first_word ] and first_word or resolve_alias( first_word )
            if fw_target and commands[ fw_target ] then
                user:reply(
                    utf_format( msg_did_you_mean, fw_target ),
                    hub_getbot( )
                )
                return PROCESSED
            end
        end
        -- Closes luadch-ng/luadch#137 (Sopor): catch the "literal
        -- bracket" mistake. Users who are not familiar with the
        -- documentation notation type the form `[+!#]command` (or
        -- partial forms like `[+]command`, `[!#]command`) as if
        -- the brackets were part of the syntax. The literal-bracket
        -- message currently broadcasts as main-chat text, which can
        -- leak credentials when the user typed e.g.
        -- `[+!#]reg <user> <password>`. Swallow the broadcast and
        -- hint at the correct form. The hint does NOT echo the
        -- input args - only the command-name capture (`%a+`), which
        -- is never a password.
        local lit_cmd = utf_match( txt, "^%[[%+!#]+%](%a+)" )
        if lit_cmd then
            -- v0.07 (#327): hint at the real command, not the alias.
            local lit_target = commands[ lit_cmd ] and lit_cmd or resolve_alias( lit_cmd )
            if lit_target and commands[ lit_target ] then
                user:reply(
                    utf_format( msg_literal_brackets, lit_target ),
                    hub_getbot( )
                )
                return PROCESSED
            end
        end
        return nil
    end
)

hub.debug( "** Loaded "..scriptname.." "..scriptversion.." **" )

--// public //--

return {

    add = add,

    -- v0.07 (#327): predicate for callers (etc_aliases) that want
    -- to check whether a name is already a registered command,
    -- without reaching into the private `commands` table.
    has = function( cmd )
        return commands[ cmd ] ~= nil
    end,

    -- v0.07 (#327): flat list of {name = name, fn = func} pairs
    -- so callers can group multi-name registrations by function
    -- identity (e.g. usr_uptime's "useruptime" + "uu" both point
    -- at the same fn). Returns a fresh table on every call;
    -- mutating it is harmless.
    list = function( )
        local out = { }
        for name, fn in pairs( commands ) do
            out[ #out + 1 ] = { name = name, fn = fn }
        end
        return out
    end,

}
