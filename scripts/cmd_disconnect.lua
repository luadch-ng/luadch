
--[[

    cmd_disconnect.lua by pulsar

        - Usage: [+!#]disconnect <NICK> <REASON>

        v1.3:
            - send msg_usage on missing parameter  / thx Sopor

        v1.2:
            - changed visuals
            - removed table lookups

        v1.1:
            - fix typo  / thx Motnahp

        v1.0:
            - imroved user:kill()

        v0.9:
            - removed send_report() function, using report import functionality now

        v0.8:
            - check if opchat is activated

        v0.7:
            - added some new table lookups
            - added possibility to send report as feed to opchat
            - using utf.format for output message

        v0.6:
            - bugfix in user send method
            - code cleaning

        v0.5:
            - bugfix in "user:kill" funktion

        v0.4:
            - changed rightclick style

        v0.3:
            - bugfix: disconnect bots

        v0.2:
            - export scriptsettings to "/cfg/cfg.tbl"

        v0.1:
            - simple script to disconnect users

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_disconnect"
local scriptversion = "1.5"

local cmd = "disconnect"

-- #343: ADC TL bounds. -1 = permanent, 0 = immediate retry,
-- positive seconds otherwise. The 1-day upper bound matches the
-- cfg validator (longer cooldowns are abuse-of-tool; the right
-- mechanism for those is +ban).
local TL_MIN = -1
local TL_MAX = 86400

--// imports
local help, ucmd, hubcmd
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or {}; err = err and hub.debug( err )
local minlevel = cfg.get( "cmd_disconnect_minlevel" )
local sendmainmsg = cfg.get( "cmd_disconnect_sendmainmsg" )
local default_tl = cfg.get( "cmd_disconnect_default_tl" ) or 30
local report = hub.import( "etc_report" )
local report_activate = cfg.get( "cmd_disconnect_report" )
local llevel = cfg.get( "cmd_disconnect_llevel" )
local report_hubbot = cfg.get( "cmd_disconnect_report_hubbot" )
local report_opchat = cfg.get( "cmd_disconnect_report_opchat" )

--// msgs
local help_title = lang.help_title or "cmd_disconnect.lua"
local help_usage = lang.help_usage or "[+!#]disconnect <NICK> [TL<SECONDS>] <REASON>"
local help_desc = lang.help_desc or "Disconnects a user. Optional TL<SECONDS> sets the ADC time-left field: -1 = don't auto-reconnect, 0 = immediate retry, N = wait N seconds (default from cfg)."

local user_msg = lang.user_msg or "[ DISCONNECT ]--> You were disconnected by: %s  |  reason: %s"
local report_msg = lang.report_msg or "[ DISCONNECT ]--> User  %s  was disconnected by  %s  |  reason: %s"

local msg_usage = lang.msg_usage or "Usage: [+!#]disconnect <NICK> [TL<SECONDS>] <REASON>"
local msg_bad_tl = lang.msg_bad_tl or "Invalid TL value. Must be an integer between -1 and 86400 (-1 = permanent, 0 = immediate, N = wait N seconds)."
local msg_denied1 = lang.msg_denied1 or "You are not allowed to use this command."
local msg_denied2 = lang.msg_denied2 or "You can't disconnect superior users."
local msg_denied3 = lang.msg_denied3 or "You can't disconnect yourself."
local msg_denied4 = lang.msg_denied4 or "User is offline."
local msg_bot = lang.msg_bot or "Error: User is a bot."

local ucmd_target = lang.ucmd_target or "Username"
local ucmd_reason = lang.ucmd_reason or "Reason"
local ucmd_menu1 = lang.ucmd_menu1 or { "User", "Control", "Disconnect", "by NICK" }
local ucmd_menu2 = lang.ucmd_menu2 or { "Disconnect", "OK" }


----------
--[CODE]--
----------

-- Shared action helper used by BOTH the ADC `+disconnect` chat-cmd
-- path AND the HTTP `DELETE /v1/users/{sid}` path (#82 Phase 2).
-- Performs ONLY the kill; does NOT fire the opchat report itself.
-- Returns the formatted report-message string; each caller invokes
-- `report.send` with it at the right moment for their surface.
-- This split preserves the historic ADC ordering
-- (kill -> chat echo to operator -> opchat report), which the
-- pre-v1.4 code did inline.
--
-- The caller is also responsible for any policy checks (level
-- hierarchy, self-disconnect, bot rejection); the helper trusts
-- its inputs.
--
-- `actor_label` is what shows in the opchat report and the kicked
-- user's ISTA message: a nick for the ADC path, a non-secret
-- token label for the HTTP path. Both `reason` and `actor_label`
-- are control-byte sanitised via `util.strip_control_bytes`
-- (single source of truth across the Phase 2 bundled-plugin
-- migrations - defence in depth around adclib::escape, which only
-- handles ' ', '\n', '\\').
-- Pure parser: extract optional TL<N> token from the raw
-- parameters string. Returns (tl, remaining_reason) where tl is
-- nil if the second token does not match the TL<N> shape (in
-- which case the entire parameters[after-nick] is the reason).
-- Returns (false, err_msg) when a TL<N> token IS present but
-- the N is malformed / out of bounds - we fail loud at parse
-- time rather than silently clamping. Exported via the public
-- return table for unit testing.
local function parse_tl_token( params_after_nick )
    if type( params_after_nick ) ~= "string" then return nil, params_after_nick or "" end
    local maybe_tl, rest = utf.match( params_after_nick, "^(TL%-?%d+)%s+(.*)$" )
    if not maybe_tl then
        return nil, params_after_nick
    end
    local n_str = maybe_tl:sub( 3 )    -- strip "TL" prefix
    local n = tonumber( n_str )
    if not n or n ~= math.floor( n ) or n < TL_MIN or n > TL_MAX then
        return false, nil
    end
    return n, rest
end

local do_disconnect = function( targetuser, reason, actor_label, tl )
    local clean_reason = util.strip_control_bytes( reason )
    local clean_actor  = util.strip_control_bytes( actor_label )
    local targetuser_nick = targetuser:nick()
    local effective_tl = tl
    if type( effective_tl ) ~= "number"
       or effective_tl ~= math.floor( effective_tl )
       or effective_tl < TL_MIN or effective_tl > TL_MAX
    then
        effective_tl = default_tl
    end
    local msg_target = utf.format( user_msg, clean_actor, clean_reason )
    targetuser:kill( "ISTA 230 " .. hub.escapeto( msg_target ) .. "\n", "TL" .. effective_tl )
    local msg_report = utf.format( report_msg, targetuser_nick, clean_actor, clean_reason )
    return msg_report, effective_tl
end

local onbmsg = function( user, adccmd, parameters )
    local user_level = user:level()
    local user_nick = user:nick()
    local target = utf.match( parameters, "^(%S+)" )
    local rest = ( target and utf.match( parameters, "^%S+%s+(.*)$" ) ) or ""
    -- #343: optional TL<N> token between NICK and REASON. parse_tl_token
    -- returns (nil, rest) if no TL token, (false, nil) if a TL<N> is
    -- present but malformed/out-of-bounds (loud usage error), or
    -- (N, reason) on a valid TL override.
    local tl, reason = parse_tl_token( rest )
    if tl == false then
        user:reply( msg_bad_tl, hub.getbot() )
        return PROCESSED
    end
    reason = reason or ""
    local targetuser = hub.isnickonline( target )
    if not target then
        user:reply( msg_usage, hub.getbot() )
        return PROCESSED
    end
    if not targetuser then
        user:reply( msg_denied4, hub.getbot() )
        return PROCESSED
    end
    if targetuser:isbot() then
        user:reply( msg_bot, hub.getbot() )
        return PROCESSED
    end
    local targetuser_level = targetuser:level()
    local targetuser_nick = targetuser:nick()
    if user_level < minlevel then
        user:reply( msg_denied1, hub.getbot() )
        return PROCESSED
    end
    if user_level < targetuser_level then
        user:reply( msg_denied2, hub.getbot() )
        return PROCESSED
    end
    if user_nick == targetuser_nick then
        user:reply( msg_denied3, hub.getbot() )
        return PROCESSED
    end
    local msg_report, effective_tl = do_disconnect( targetuser, reason, user_nick, tl )
    -- Order preserved from v1.3: chat echo to the operator BEFORE
    -- the opchat report fires (the report can hit the same operator
    -- in opchat, and historically they saw their own kick echo first).
    if sendmainmsg then user:reply( msg_report, hub.getbot() ) end
    report.send( report_activate, report_hubbot, report_opchat, llevel, msg_report )
    audit.fire( audit.build( "user.kick", user, targetuser,
        ( reason ~= "" and reason or nil ), { tl = effective_tl } ) )
    return PROCESSED
end

-- HTTP handler body: DELETE /v1/users/{sid} (#82 Phase 2). The
-- shared `util.http_register_user_action` helper handles the
-- preflight (SID extraction + online check + non-bot rejection)
-- and the response envelope (action/sid/nick); the handler below
-- just does the action-specific bits: pull `reason` from the
-- body, drive the kick + opchat report, return the
-- action-specific fields to merge into the envelope.
--
-- Audit log is emitted automatically by the router; the ADC-side
-- level hierarchy check does NOT apply on the HTTP path: the
-- bearer token's `admin` scope IS the authorisation gate.
local http_handler_disconnect = function( req, target )
    local reason = ( req.body and req.body.reason ) or ""
    local actor_label = req.token_label or "http-api"
    -- #343: optional body.tl integer. Schema validation in the
    -- router already enforces type + range; we accept nil here
    -- as "use cfg default" via do_disconnect's own clamp logic.
    local tl = req.body and req.body.tl
    local msg_report, effective_tl = do_disconnect( target, reason, actor_label, tl )
    -- HTTP path has no operator-chat to echo into; fire the
    -- opchat report directly so an operator watching opchat sees
    -- a consistent line regardless of which surface drove the kick.
    report.send( report_activate, report_hubbot, report_opchat, llevel, msg_report )
    audit.fire( audit.build( "user.kick",
        { nick = actor_label, sid = "<http>" },
        target,
        ( reason ~= "" and reason or nil ), { tl = effective_tl } ) )
    return { reason = reason, tl = effective_tl }
end

hub.setlistener( "onStart", {},
    function()
        help = hub.import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )
        end
        ucmd = hub.import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu1, cmd, { "%[line:" .. ucmd_target .. "]", "%[line:" .. ucmd_reason .. "]" }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu2, cmd, { "%[nick]", "%[line:" .. ucmd_reason .. "]" }, { "CT2" }, minlevel )
        end
        hubcmd = hub.import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg ) )
        -- HTTP API endpoint (#82 Phase 2). The util_http helper
        -- does the fail-soft check, the preflight, the envelope,
        -- and the audit-log integration; this plugin only owns the
        -- action-specific handler body above.
        util_http.http_register_user_action( scriptname,
            "DELETE", "/v1/users/{sid}", "disconnect",
            http_handler_disconnect, {
                description = "disconnect (kick) an online user by SID; body { reason: string optional, tl: integer optional (-1..86400, ADC time-left; -1 = permanent, 0 = immediate retry, N = wait N seconds; #343) }",
                request_schema = {
                    reason = { type = "string", max_length = 256 },
                    tl     = { type = "integer", min = -1, max = 86400 },
                },
            }
        )
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .." **" )


-- Public surface: expose the pure parser for the unit test. The
-- ADC + HTTP handlers use it internally; the test exercises the
-- TL token shape contract.
return {
    parse_tl_token = parse_tl_token,
}
