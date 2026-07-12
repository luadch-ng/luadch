--[[

    etc_webhook.lua by Aybo

        Generic INBOUND webhook receiver. An external service POSTs a
        signed JSON body to a hub HTTP endpoint; the hub verifies the
        HMAC-SHA256 signature over the raw body, applies an event filter
        + dedup, renders a templated message and announces it in the hub
        chat as a named bot. First consumer: a Discourse forum (new
        topics / posts); the same protocol serves GitHub / GitLab / CI /
        monitoring - anything that signs the request body with
        HMAC-SHA256.

        This is the PUSH-inbound mirror of etc_status_push (outbound) and
        the inbound complement of etc_prometheus (pull /metrics).

        Multi-endpoint: the operator-edited cfg/webhooks.tbl holds an
        array of endpoints, each with its own path, signature/event/id
        headers, event filter, bot nick, min-level and message templates
        ( {dotted.path} placeholders resolved against the decoded body,
        plus {event} ). Secrets are resolved per endpoint env-var-first
        (LUADCH_ETC_WEBHOOK_<NAME>_SECRET, else the etc_webhook_<name>_secret
        cfg key) and finally the inline `secret` in cfg/webhooks.tbl.

        cfg.tbl carries only the master switch etc_webhook_activate; all
        endpoint config lives in cfg/webhooks.tbl (keeps cfg.tbl lean).
        Runtime dedup state lives in scripts/data/etc_webhook.tbl.

        Security: the endpoint registers with scope="none" (the router's
        bearer-token gate is skipped) and does its OWN HMAC auth over
        req.raw_body, constant-time compared (adclib.constant_time_eq).
        The HTTP listener itself is only reachable per the operator's
        http_port + reverse-proxy setup - see docs/WEBHOOKS.md.

        v0.02: by Aybo - dedup_load probes with io.open before
               util.loadtable, so a first run (no dedup file yet) no
               longer logs a spurious checkfile error (the sibling
               state-file loaders already did this).
        v0.01: by Aybo - initial release (#398).

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "etc_webhook"
local scriptversion = "0.02"

local config_file = "cfg/webhooks.tbl"
local dedup_file  = "scripts/data/etc_webhook.tbl"


--// table lookups
local hub_debug       = hub.debug
local hub_broadcast   = hub.broadcast
local hub_getbot      = hub.getbot
local hub_getusers    = hub.getusers
local hub_regbot      = hub.regbot
local util_loadtable  = util.loadtable
local util_savetable  = util.savetable
local util_strip      = util.strip_control_bytes
local hmac_sha256     = hmac.sha256
local ct_eq           = adclib.constant_time_eq
local adclib_sanitize = adclib.sanitize_utf8
local os_time         = os.time


-- No lang files / no help entry: this plugin has NO chat command and no
-- operator-facing chat output of its own (it only announces the
-- operator-authored templates). Same shape as its sibling
-- etc_status_push. Diagnostics go to hub.debug (gated on log_scripts).


----------
--[CODE]--
----------

-- Response shapes for the scope="none" handler.
local RESP_OK = { status = 200, raw_body = "", content_type = "text/plain; charset=utf-8" }
local function resp_unauthorized( )
    return { status = 401, error = { code = "unauthorized", message = "invalid or missing signature" } }
end

-- Module state (all reset on +reload, which re-runs this file).
local endpoints   = { }    -- validated, active endpoints
local bots        = { }    -- bot_nick -> bot object (deduped)
local enabled     = false
local tuning      = { max_per_minute = 10, dedup_max = 500, field_maxlen = 300 }

-- dedup: seen[id] = last-seen epoch. Bounded to tuning.dedup_max.
local seen        = { }
local seen_count  = 0
local seen_dirty  = false    -- persisted by the onTimer throttle, not per-event
local last_save   = 0

-- flood window (global across endpoints)
local flood_count = 0
local flood_start = 0


--// config load (operator-edited Lua table; same trust level as cfg.tbl)
local function load_config( )
    -- first-run-silent: a missing file is the normal not-configured
    -- state, not an error worth a log line.
    local f = io.open( config_file, "r" )
    if not f then return nil end
    f:close()
    local ok, tbl = pcall( util_loadtable, config_file )
    if not ok or type( tbl ) ~= "table" then
        hub_debug( scriptname .. ": " .. config_file .. " missing or unreadable - inert" )
        return nil
    end
    return tbl
end

--// per-endpoint validation + normalisation. Returns a normalised entry
--// or nil + reason. Does NOT resolve the secret (caller does).
local function normalise_endpoint( raw )
    if type( raw ) ~= "table" then return nil, "not a table" end
    local name = raw.name
    if type( name ) ~= "string" or not name:match( "^[%a%d_]+$" ) then
        return nil, "invalid/missing name (need [A-Za-z0-9_])"
    end
    local sig_header = raw.signature_header
    if type( sig_header ) ~= "string" or sig_header == "" then
        return nil, "endpoint '" .. name .. "': missing signature_header"
    end
    local events = { }
    if type( raw.events ) == "table" then
        for _, e in ipairs( raw.events ) do
            if type( e ) == "string" then events[ e ] = true end
        end
    end
    local templates = { }
    if type( raw.templates ) == "table" then
        for k, v in pairs( raw.templates ) do
            if type( k ) == "string" and type( v ) == "string" then templates[ k ] = v end
        end
    end
    local path = raw.path
    if type( path ) ~= "string" or path:sub( 1, 1 ) ~= "/" then
        path = "/v1/webhook/" .. name
    end
    local min_level = tonumber( raw.min_level ) or 0
    -- header keys arrive lowercased in req.headers
    local event_header = ( type( raw.event_header ) == "string" and raw.event_header ~= "" and raw.event_header:lower() ) or nil
    if next( events ) ~= nil and not event_header then
        hub_debug( scriptname .. ": endpoint '" .. name .. "': an events filter is set but no event_header - every delivery will be dropped" )
    end
    return {
        name             = name,
        path             = path,
        signature_header = sig_header:lower(),
        signature_prefix = ( type( raw.signature_prefix ) == "string" and raw.signature_prefix ) or "",
        event_header     = event_header,
        events           = events,          -- set; empty = allow all
        has_events       = next( events ) ~= nil,
        id_header        = ( type( raw.id_header ) == "string" and raw.id_header ~= "" and raw.id_header:lower() ) or nil,
        bot_nick         = ( type( raw.bot_nick ) == "string" and raw.bot_nick ~= "" and raw.bot_nick ) or nil,
        min_level        = min_level,
        templates        = templates,
        default_template = ( type( raw.default_template ) == "string" and raw.default_template ) or "",
        inline_secret    = ( type( raw.secret ) == "string" and raw.secret ~= "" and raw.secret ) or nil,
        secret           = nil,             -- filled by caller
    }
end


--// dedup
local function dedup_load( )
    -- first-run-silent: probe with io.open before util.loadtable, which
    -- otherwise calls checkfile and logs an error.log line for the
    -- absent file - the HubSecurity bot relays that to ops on every
    -- fresh start. A missing dedup file is the normal "nothing seen
    -- yet" state. Mirrors load_config() above + the sibling state
    -- loaders (etc_regserver_announce, etc_blocklist_feeds).
    local f = io.open( dedup_file, "r" )
    if not f then return end
    f:close()
    local ok, tbl = pcall( util_loadtable, dedup_file )
    if ok and type( tbl ) == "table" and type( tbl.seen ) == "table" then
        seen = tbl.seen
        seen_count = 0
        for _ in pairs( seen ) do seen_count = seen_count + 1 end
    end
end

local function dedup_save( )
    util_savetable( { seen = seen }, "webhook", dedup_file )
end

-- true if this id was already processed (duplicate delivery).
local function dedup_hit( id )
    return seen[ id ] ~= nil
end

local function dedup_add( id )
    if seen[ id ] == nil then seen_count = seen_count + 1 end
    seen[ id ] = os_time()
    seen_dirty = true
    -- bound: once over the cap, drop the oldest ~10% in a single sorted
    -- pass (amortised ~O(log n) per add; avoids the O(k*n) repeated scan
    -- a signed flooder could otherwise use to stall the loop).
    if seen_count > tuning.dedup_max then
        local arr = { }
        for k, v in pairs( seen ) do arr[ #arr + 1 ] = { k, v } end
        table.sort( arr, function( a, b ) return a[ 2 ] < b[ 2 ] end )
        local drop = math.max( 1, math.floor( tuning.dedup_max * 0.1 ) )
        for i = 1, drop do
            local e = arr[ i ]
            if e then seen[ e[ 1 ] ] = nil; seen_count = seen_count - 1 end
        end
    end
end


--// flood cap (global)
local function flood_ok( )
    local now = os_time()
    if now - flood_start >= 60 then
        flood_start = now
        flood_count = 0
    end
    if flood_count >= tuning.max_per_minute then
        return false
    end
    flood_count = flood_count + 1
    return true
end


--// template render: {dotted.path} against the decoded body, plus {event}.
local function resolve_path( body, path )
    local cur = body
    for key in path:gmatch( "[^%.]+" ) do
        if type( cur ) ~= "table" then return nil end
        local v = cur[ key ]
        if v == nil then
            -- JSON arrays decode to integer-keyed tables; {items.1.x}
            -- should reach cur[1], not cur["1"].
            local nk = tonumber( key )
            if nk ~= nil then v = cur[ nk ] end
        end
        cur = v
    end
    return cur
end

local function sanitise_value( v )
    local t = type( v )
    -- only scalars render. A non-leaf path (table / array) would else
    -- tostring() to "table: 0x..." - a heap-pointer info-leak + garbage
    -- into chat (reachable by a signed sender putting an object where a
    -- scalar was expected).
    if t ~= "string" and t ~= "number" and t ~= "boolean" then return "" end
    -- strip control bytes, then coerce to valid UTF-8: a signed sender
    -- could send an invalid-UTF-8 field, which would make the broadcast
    -- path's types_utf8 gate raise and silently drop the announce.
    v = adclib_sanitize( util_strip( tostring( v ) ) )
    if utf.len and utf.len( v ) > tuning.field_maxlen then
        v = utf.sub( v, 1, tuning.field_maxlen ) .. "..."
    elseif #v > tuning.field_maxlen then
        v = v:sub( 1, tuning.field_maxlen ) .. "..."
    end
    return v
end

local function render( template, body, event )
    return ( template:gsub( "{([%w_%.]+)}", function( path )
        if path == "event" then return sanitise_value( event ) end
        return sanitise_value( resolve_path( body, path ) )
    end ) )
end


--// announce
local function announce( text, bot, min_level )
    if min_level and min_level > 0 then
        for _, user in pairs( hub_getusers() ) do
            if user:level() >= min_level then
                user:reply( text, bot )
            end
        end
    else
        hub_broadcast( text, bot )
    end
end


--// build a scope="none" HTTP handler bound to one endpoint.
local function make_handler( entry )
    return function( req )
        -- 1. HMAC auth over the EXACT raw bytes, constant-time compared.
        local sig = req.headers and req.headers[ entry.signature_header ]
        if type( sig ) ~= "string" or sig == "" then return resp_unauthorized() end
        if entry.signature_prefix ~= "" then
            local plen = #entry.signature_prefix
            if sig:sub( 1, plen ) == entry.signature_prefix then
                sig = sig:sub( plen + 1 )
            end
        end
        local computed = hmac_sha256( entry.secret, req.raw_body or "" )
        if not ct_eq( computed, sig:lower() ) then return resp_unauthorized() end

        -- From here the request is authenticated. Everything below
        -- returns 200 (the sender should not retry a well-formed,
        -- correctly-signed delivery we chose not to announce).

        -- 2. event filter (ping / unlisted events are acknowledged, not announced)
        local event = entry.event_header and req.headers[ entry.event_header ] or nil
        if entry.has_events and not ( event and entry.events[ event ] ) then
            return RESP_OK
        end

        -- 3. dedup on the delivery id
        local id = entry.id_header and req.headers[ entry.id_header ] or nil
        if id then
            id = entry.name .. ":" .. util_strip( tostring( id ) ):sub( 1, 128 )
            if dedup_hit( id ) then return RESP_OK end
        end

        -- 4. pick a template; nothing to say -> ack
        local template = ( event and entry.templates[ event ] ) or entry.default_template
        if not template or template == "" then
            if id then dedup_add( id ) end
            return RESP_OK
        end

        -- 5. global flood cap
        if not flood_ok() then
            hub_debug( scriptname .. ": flood cap hit (" .. tuning.max_per_minute .. "/min), dropping announce for '" .. entry.name .. "'" )
            -- do NOT dedup a flood-dropped delivery: it was not delivered,
            -- so a later retry (once the flood clears) should still announce.
            return RESP_OK
        end

        -- 6. render + announce
        local text = render( template, req.body or { }, event )
        if text ~= "" then
            local bot = ( entry.bot_nick and bots[ entry.bot_nick ] ) or hub_getbot()
            announce( text, bot, entry.min_level )
        end
        if id then dedup_add( id ) end
        return RESP_OK
    end
end


--// module-load init (re-runs on +reload)
local config = load_config()
if type( config ) == "table" then
    if type( config.max_per_minute ) == "number" and config.max_per_minute > 0 then tuning.max_per_minute = config.max_per_minute end
    if type( config.dedup_max ) == "number" and config.dedup_max > 0 then tuning.dedup_max = config.dedup_max end
    if type( config.field_maxlen ) == "number" and config.field_maxlen > 0 then tuning.field_maxlen = config.field_maxlen end
    if type( config.endpoints ) == "table" then
        for _, raw in ipairs( config.endpoints ) do
            local entry, reason = normalise_endpoint( raw )
            if not entry then
                hub_debug( scriptname .. ": skipped endpoint (" .. tostring( reason ) .. ")" )
            else
                -- Secret resolution: register the derived cfg key (so a
                -- cfg.tbl-stored secret would be redacted from
                -- GET /v1/config), then env-var-first, then the inline
                -- secret in cfg/webhooks.tbl. Registration happens for
                -- every configured endpoint, before the activate gate.
                local secret_key = "etc_webhook_" .. entry.name .. "_secret"
                if secrets and secrets.register then secrets.register( secret_key ) end
                local resolved = ( secrets and secrets.lookup and secrets.lookup( secret_key ) ) or entry.inline_secret
                if type( resolved ) ~= "string" or resolved == "" then
                    hub_debug( scriptname .. ": endpoint '" .. entry.name .. "' has no secret (env LUADCH_" .. string.upper( secret_key ) .. " / cfg / inline) - skipped" )
                else
                    entry.secret = resolved
                    endpoints[ #endpoints + 1 ] = entry
                end
            end
        end
    end
end

local activate = cfg.get( "etc_webhook_activate" )
if activate and #endpoints > 0 then
    enabled = true
    dedup_load()
    flood_start = os_time()
    last_save = os_time()
    -- Create one bot per distinct bot_nick (module-load, like
    -- bot_opchat; killscripts kills all bots on +reload and this file
    -- re-runs, so no duplicates accumulate).
    for _, entry in ipairs( endpoints ) do
        local nick = entry.bot_nick
        if nick and not bots[ nick ] then
            local bot = hub_regbot{ nick = nick, desc = "Webhook announcer", client = function() return true end }
            if bot then bots[ nick ] = bot
            else hub_debug( scriptname .. ": could not create bot '" .. nick .. "' (nick taken?) - using hub bot for '" .. entry.name .. "'" ) end
        end
    end
    hub_debug( scriptname .. ": active with " .. #endpoints .. " endpoint(s)" )
else
    hub_debug( scriptname .. ": inert (" .. ( activate and "no valid endpoints" or "etc_webhook_activate = false" ) .. ")" )
end


hub.setlistener( "onStart", { },
    function( )
        if not enabled then return nil end
        if not hub.http_register then
            hub_debug( scriptname .. ": hub.http_register unavailable - endpoints not registered" )
            return nil
        end
        -- Register one scope="none" POST route per endpoint. The router
        -- unregister_all's on every +reload before this fires, so a
        -- straight re-register is safe (no duplicate-path throw).
        for _, entry in ipairs( endpoints ) do
            -- pcall so one bad custom path (duplicate / invalid) does not
            -- abort registration of the remaining endpoints.
            local ok, reg_err = pcall( hub.http_register, "POST", entry.path, "none", make_handler( entry ), {
                plugin = scriptname,
                description = "inbound webhook receiver for '" .. entry.name .. "' (HMAC-SHA256 signed; announces to chat)",
            } )
            if not ok then
                hub_debug( scriptname .. ": could not register route " .. entry.path .. " for '" .. entry.name .. "': " .. tostring( reg_err ) )
            end
        end
        return nil
    end
)

-- Persist the dedup set on a throttle (not per-event), so a high-volume
-- signed source cannot turn every delivery into a disk write. A crash
-- loses at most the last <=30s of dedup keys (worst case: a duplicate
-- announce for those after a restart - harmless).
hub.setlistener( "onTimer", { },
    function( )
        if enabled and seen_dirty and ( os_time() - last_save ) >= 30 then
            dedup_save()
            seen_dirty = false
            last_save = os_time()
        end
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )
