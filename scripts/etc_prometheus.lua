--[[

    etc_prometheus.lua

        description: Prometheus text-exposition `/metrics` endpoint for
                     the HTTP API. Closes #83.

        Counters reset on hub restart AND on `+reload` (the plugin's
        file-local upvalues are re-initialised by the onStart re-run).
        That matches the Prometheus convention of monotonic-since-
        scrape-target-restart counters; operators who run the scraper
        across reloads see the dip and recover.

        Activation: `etc_prometheus_activate` cfg toggle. Default
        `false` - the route is NOT registered when off, and the router
        returns a generic 404 E_NOT_FOUND for `GET /metrics`.

        Scope: `read` (same as other read endpoints). Prometheus must
        be configured with the bearer token. `http_api_log_reads`
        defaults to false so the scrape pulls do not flood
        `log/api_audit.log`.

        v0.1: by Aybo
            - GET /metrics (read scope), Prometheus 0.0.4 exposition.
            - 7 gauges + 7 counters (see catalog in docs/HTTP_API.md).
            - opt-in via cfg etc_prometheus_activate.

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "etc_prometheus"
local scriptversion = "0.1"

local activate = cfg.get( "etc_prometheus_activate" )


----------
--[CODE]--
----------

if not activate then
    hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " (not active) **" )
    return
end

--// Counters (monotonic since plugin onStart; reset on +reload).
local logins_total        = 0
local logouts_total       = 0
local failed_auths_total  = 0
local chat_msgs_total     = 0
local pm_msgs_total       = 0
local searches_total      = 0
local script_errors_total = 0

--// Format one Prometheus metric in v0.0.4 text exposition:
--//   # HELP <name> <help text>
--//   # TYPE <name> <gauge|counter>
--//   <name> <value>
local format_metric = function( name, mtype, help, value )
    return "# HELP " .. name .. " " .. help .. "\n"
        .. "# TYPE " .. name .. " " .. mtype .. "\n"
        .. name .. " " .. tostring( value ) .. "\n"
end

--// Walk online users once, returning (humans, bots, share, files).
--// `hub.getusers()` returns three tables; we need both:
--//   [1] humans-only (`_nobot_normalstatesids`) for the share /
--//       files totals (matches /v1/stats which deliberately
--//       excludes bots from the share metric so it is comparable
--//       to the ADC `+hubstats` value),
--//   [2] all users in normal state (includes bots) so we can
--//       count bots via `user:isbot()`.
local count_online = function()
    local humans_tbl, all_normal_tbl = hub.getusers()
    local humans, bots = 0, 0
    local share_total, files_total = 0, 0
    for _, user in pairs( humans_tbl or {} ) do
        humans = humans + 1
        share_total = share_total + ( user:share() or 0 )
        files_total = files_total + ( user:files() or 0 )
    end
    for _, user in pairs( all_normal_tbl or {} ) do
        if user:isbot() then
            bots = bots + 1
        end
    end
    return humans, bots, share_total, files_total
end

--// Count active bans via the cmd_ban export. Returns 0 nil-safely
--// when cmd_ban is not loaded (hub.import returns nil) OR when the
--// export structure has no `bans` field.
--//
--// hub.import returns a shallow copy of the export table per
--// core/scripts.lua:418-430; the `bans` slot in that copy points
--// at cmd_ban's underlying table, which is mutated in place after
--// #239 / #246 (cleanbans uses `for k in pairs(bans) do bans[k]=nil
--// end` instead of rebinding `bans = {}`). So iterating `ban.bans`
--// here is correct across `+ban clear` and any other clear
--// operation - we always see the current contents.
local count_active_bans = function()
    local ban = hub.import( "cmd_ban" )
    if not ban or type( ban.bans ) ~= "table" then
        return 0
    end
    local n = 0
    for _ in pairs( ban.bans ) do n = n + 1 end
    return n
end

--// HTTP handler: GET /metrics
local http_handler_metrics = function( req )
    local humans, bots, share_total, files_total = count_online()
    local start_ts = signal.get( "start" ) or os.time()
    local uptime = math.floor( os.difftime( os.time(), start_ts ) )
    local mem_kb = math.floor( collectgarbage( "count" ) )
    local active_bans = count_active_bans()

    local body =
        format_metric( "luadch_users_online",
            "gauge", "Current count of online human users",
            humans ) ..
        format_metric( "luadch_users_online_bots",
            "gauge", "Current count of online bots",
            bots ) ..
        format_metric( "luadch_share_total_bytes",
            "gauge", "Sum of share sizes (bytes) across online humans",
            share_total ) ..
        format_metric( "luadch_files_total",
            "gauge", "Sum of file counts across online humans",
            files_total ) ..
        format_metric( "luadch_hub_uptime_seconds",
            "gauge", "Hub process uptime in seconds",
            uptime ) ..
        format_metric( "luadch_lua_memory_kb",
            "gauge", "Lua interpreter memory usage in KiB (collectgarbage count)",
            mem_kb ) ..
        format_metric( "luadch_active_bans",
            "gauge", "Current count of active bans (0 if cmd_ban not loaded)",
            active_bans ) ..
        format_metric( "luadch_logins_total",
            "counter", "Successful logins since plugin onStart",
            logins_total ) ..
        format_metric( "luadch_logouts_total",
            "counter", "Logouts since plugin onStart",
            logouts_total ) ..
        format_metric( "luadch_failed_auths_total",
            "counter", "Failed auth attempts since plugin onStart",
            failed_auths_total ) ..
        format_metric( "luadch_chat_msgs_total",
            "counter", "Main-chat messages since plugin onStart",
            chat_msgs_total ) ..
        format_metric( "luadch_pm_msgs_total",
            "counter", "Private messages since plugin onStart",
            pm_msgs_total ) ..
        format_metric( "luadch_searches_total",
            "counter", "Search requests since plugin onStart",
            searches_total ) ..
        format_metric( "luadch_script_errors_total",
            "counter", "Plugin script errors (onError) since plugin onStart",
            script_errors_total )

    return {
        status = 200,
        raw_body = body,
        content_type = "text/plain; version=0.0.4; charset=utf-8",
    }
end

--// Lifecycle counters. Each listener does only counter increment -
--// no I/O, no fallible ops - so they cannot trigger onError and
--// recurse into themselves (the onError listener increment is also
--// safe by the same argument).
hub.setlistener( "onLogin", {},
    function() logins_total = logins_total + 1 return nil end )
hub.setlistener( "onLogout", {},
    function() logouts_total = logouts_total + 1 return nil end )
hub.setlistener( "onFailedAuth", {},
    function() failed_auths_total = failed_auths_total + 1 return nil end )
hub.setlistener( "onBroadcast", {},
    function() chat_msgs_total = chat_msgs_total + 1 return nil end )
hub.setlistener( "onPrivateMessage", {},
    function() pm_msgs_total = pm_msgs_total + 1 return nil end )
hub.setlistener( "onSearch", {},
    function() searches_total = searches_total + 1 return nil end )
hub.setlistener( "onError", {},
    function() script_errors_total = script_errors_total + 1 return nil end )

hub.setlistener( "onStart", {},
    function()
        if hub.http_register then
            hub.http_register( "GET", "/metrics", "read", http_handler_metrics, {
                plugin = scriptname,
                description = "Prometheus text exposition (#83); 7 gauges + 7 counters",
            } )
        end
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )
