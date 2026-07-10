--[[

        etc_hubcommands.lua v0.03 by blastbeat

        v0.09: by Aybo
            - #356 follow-up: the bare-word "Did you mean +X?" hint now
              fires ONLY when the message is EXACTLY a command word
              ("talk"), no longer for "command word + trailing text"
              ("talk to me brother"). A lone command word is a genuine
              forgot-the-prefix attempt; a command word followed by text
              is almost always ordinary chat, and matching it produced
              constant false-positive swallows (an op in chat mode
              writes "talk to me brother" and it got eaten). Exception:
              a command that carries a secret inline (registered with
              `{ secret = true }` - only cmd_setpass today) is still
              caught in its "cmd <args>" form and swallowed regardless
              of level, so a forgot-the-prefix `setpass nick x <pw>`
              never broadcasts the password to main chat (same intent
              as the #137 literal-bracket guard). The #356 access-level
              gate still applies to the exact-word case.

        v0.08: by Aybo
            - #356: the bare-word "Did you mean +X?" hint now only
              fires for a command the user is actually allowed to run.
              Previously it fired for ANY registered command name, so a
              normal chat line that merely starts with a privileged
              command word (e.g. "talk to me brother", "reg me") was
              swallowed and the existence of op-only commands leaked to
              unprivileged users. `add` gains an optional third arg
              `minlevel`; commands register their level (mirroring the
              level already passed to cmd_help.reg and ucmd.add). A
              command whose level was never registered (nil, e.g. a
              public command or a not-yet-updated third-party plugin)
              is treated as ungated, so the hint behaves exactly as
              before. The literal-bracket branch (`[+!#]reg <user>
              <pw>`) is deliberately NOT gated: it must keep swallowing
              to prevent the #137 credential leak, and its input form
              has no false-positive chat overlap.

        v0.07: by Aybo
            - alias-resolver fallback for #327. On a missed direct
              lookup the dispatcher consults etc_aliases via
              hub.import, resolves the typed token to a real
              command, and dispatches the real command's handler
              with the resolved name as the `command` argument
              (the chat-echo `[command] %s` line still shows the
              user's raw input - that's an acknowledgement, not a
              routing trace). Both miss-hints (the forgot-the-
              prefix "Did you mean +X?" and the literal-bracket
              "Try +X" hint) DO resolve through the alias map
              because those messages exist to teach the operator
              the correct command name. The resolver is re-imported
              on every miss (no caching) so a +reload of etc_aliases
              never leaves a stale closure here.
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
local scriptversion = "0.09"

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
-- v0.08 (#356): per-command minlevel, parallel to `commands`. A nil
-- entry means the command's level was never registered (public
-- command, or a plugin that has not yet adopted the third `add` arg);
-- such commands are treated as ungated by the hint (unchanged
-- behaviour).
local command_levels = { }
-- v0.09 (#356 f/u): commands that carry a secret inline (e.g. setpass's
-- `<PASS>`), registered with `add( cmd, func, minlevel, { secret = true } )`.
-- Their "cmd <args>" forgot-prefix form is still swallowed (regardless of
-- level) so a mistyped password never broadcasts to main chat.
local command_secret = { }

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

local reg_cmd = function( cmd, func, minlevel, is_secret )
    if ( type( cmd ) == "string" ) and ( type( func ) == "function" ) then
        if commands[ cmd ] then
            return false -- name is already registered
        end
        commands[ cmd ] = func
        command_levels[ cmd ] = minlevel -- #356: nil == ungated (unchanged behaviour)
        command_secret[ cmd ] = is_secret or nil -- #356 f/u: carries an inline secret
        return true
    end
    return false
end

-- v0.08 (#356): optional `minlevel` records the level required to run
-- the command, so the "Did you mean +X?" hint can be gated on access.
-- v0.09 (#356 f/u): optional `opts.secret` marks a command that carries
-- a secret inline (setpass) so its "cmd <args>" forgot-prefix form keeps
-- being swallowed. Back-compatible: callers that omit either register an
-- ungated, non-secret command.
local add = function( cmd, func, minlevel, opts ) -- quick and dirty...
    local is_secret = opts and opts.secret and true or nil
    if type( cmd ) == "string" then
        cmd = { cmd }
    end
    if type( cmd ) == "table" then
        for _, name in pairs( cmd ) do
            if not reg_cmd( name, func, minlevel, is_secret ) then
                return false
            end
        end
        return true
    end
    return false
end

-- #356: may `user` run the command `cmd`? An unregistered level (nil)
-- is treated as "yes" so public and not-yet-updated commands keep the
-- pre-#356 hint behaviour. Mirrors the `user_level < minlevel` guard
-- each command handler already performs internally. For a command
-- whose handler gates on a permission SET (`permission[level]`) rather
-- than a threshold, plugins register the lowest permitted level; this
-- `>=` check may therefore over-fire the hint for a user ABOVE that
-- floor under a non-contiguous permission config, but it never leaks
-- to a user BELOW it - the safe direction, and strictly narrower than
-- the bug this fixes.
local user_may_run = function( user, cmd )
    local lvl = command_levels[ cmd ]
    if not lvl then return true end
    return user:level() >= lvl
end

hub.setlistener( "onBroadcast", { },
    function( user, adccmd, txt )
        local cmd, parameters = utf_match( txt, "^[+!#](%a+) ?(.*)" )
        local func = commands[ cmd ]
        local effective_cmd = cmd
        -- v0.07 (#327): direct miss -> try the alias map. If the
        -- alias resolves to a real command, dispatch the real
        -- command's handler with the resolved name as the
        -- `command` arg (the echo line still shows the raw input,
        -- which is the chat acknowledgement).
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
        -- Closes upstream luadch/luadch#223 (+ #356 and its follow-up):
        -- catch the "forgot the [+!#] prefix" mistake. Trigger ONLY when
        -- the message is EXACTLY a command word ("talk"). A lone command
        -- word is a genuine forgot-the-prefix attempt (nobody types it as
        -- chat); a command word FOLLOWED by text ("talk to me brother")
        -- is ordinary chat and must reach main unmolested - the old
        -- "cmd <args>" match ate normal chat lines (#356 f/u). Exception:
        -- a command that carries a secret inline (registered with
        -- { secret = true }, e.g. setpass) is still caught in its
        -- "cmd <args>" form so a mistyped password does not broadcast.
        local exact_word  = utf_match( txt, "^(%a+)$" )
        local secret_word = ( not exact_word ) and utf_match( txt, "^(%a+) " ) or nil
        local candidate   = exact_word or secret_word
        if candidate then
            -- v0.07 (#327): hint at the real command, not the alias.
            local fw_target = commands[ candidate ] and candidate or resolve_alias( candidate )
            if fw_target and commands[ fw_target ] then
                -- exact word: gate on access (#356) so op-only command
                -- names do not leak to unprivileged users. Secret command
                -- in "cmd <args>" form: swallow regardless of level, like
                -- the #137 literal-bracket guard below - the point is to
                -- stop the credential broadcast, not to teach the prefix.
                local fire
                if exact_word then
                    fire = user_may_run( user, fw_target )
                elseif command_secret[ fw_target ] then
                    fire = true
                end
                if fire then
                    user:reply(
                        utf_format( msg_did_you_mean, fw_target ),
                        hub_getbot( )
                    )
                    return PROCESSED
                end
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
