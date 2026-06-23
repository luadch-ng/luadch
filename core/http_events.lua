--[[

    http_events.lua

        Event ringbuffer + emit/poll for the HTTP API's
        `GET /v1/events` endpoint (#263 of #82).

        PR-A scope: immediate-return polling only. Client GETs,
        server returns whatever has accumulated in the ringbuffer
        since the supplied `?since=` cursor. Client polls again.
        Long-polling (server-side wait + coroutine yield) lands in
        PR-B.

        Events are appended via `emit(type, payload)` from two
        sources:

          1. The core-side tap registered into scripts.firelistener
             via scripts.register_tap - captures every event the
             rest of the hub fires via the existing listener-chain
             machinery (onLogin / onLogout / onBroadcast / onReg /
             onDelreg / onPrivateMessage / onFailedAuth / onError /
             onSearch). No plugin changes needed for these.

          2. Direct emit calls from plugins that want to advertise
             events that don't have a listener-chain counterpart
             (ban_added / ban_removed / topic_changed - PR-B will
             wire these as the plugins migrate).

        The ringbuffer is bounded by cfg `http_events_buffer_size`
        (default 1000). When a client's `since=` cursor falls
        below the buffer's minimum id, the response carries
        `cursor_lost: true` and the client catches up via the
        per-resource GET endpoints, then resumes polling at the
        returned `cursor`.

]]--

----------------------------------// DECLARATION //--

local type = use "type"
local ipairs = use "ipairs"
local pairs = use "pairs"
local pcall = use "pcall"
local tonumber = use "tonumber"
local tostring = use "tostring"

local os = use "os"
local table = use "table"
local socket = use "socket"

local os_date         = os.date
local os_time         = os.time
local socket_gettime  = socket.gettime
local table_insert    = table.insert
local table_remove    = table.remove

local cfg = use "cfg"

local util = use "util"
local strip_control_bytes = util.strip_control_bytes

----------------------------------// DEFINITION //--

local DEFAULT_BUFFER_SIZE = 1000

local _buffer = { }      -- array: ringbuffer of {id, type, timestamp, payload...}
local _next_id = 1       -- monotonic counter; never reset within a process lifetime
local _max_size           -- cached cfg.get("http_events_buffer_size")

-- PR-B: long-polling waiters. Each waiter holds the server handler
-- (open HTTP connection), the poll cursor / types filter, and a
-- render closure that builds the HTTP response bytes from the
-- final ( rows, cursor, cursor_lost ) tuple. The render closure
-- owns scope filtering (pm-events admin-only), so the resolver
-- itself stays scope-agnostic.
local _waiters = { }     -- array of { handler, since, types_str, types_filter, deadline_epoch, render_fn }

local _iso_now = function( )
    return os_date( "!%Y-%m-%dT%H:%M:%SZ", os_time( ) )
end

-- Sanitise every string value in a payload table at emit time so
-- consumers never see raw control bytes that came in from ADC
-- frames. Recurses one level (event payloads are flat per spec).
local _sanitise = function( payload )
    if type( payload ) ~= "table" then return { } end
    local clean = { }
    for k, v in pairs( payload ) do
        if type( v ) == "string" then
            clean[ k ] = strip_control_bytes( v )
        else
            clean[ k ] = v
        end
    end
    return clean
end

-- Forward decls for the PR-B waiter machinery.
local _resolve_waiter

-- Append an event to the ringbuffer. Drops the oldest entry when
-- the buffer is at cap. Public; callable from any module (core or
-- plugin sandbox - http_events is whitelisted).
--
-- Re-reads cfg.http_events_buffer_size on every emit so a live PUT
-- /v1/config/{key} change takes effect immediately - the cfg key
-- is classified `live` in #262, and capturing the cap at init()
-- would silently no-op the operator's edit.
--
-- PR-B: after appending, walk the waiter list and resolve every
-- waiter whose filter matches the new event. This gives sub-tick
-- latency for matching events (vs the 1s tick() granularity).
local emit = function( event_type, payload )
    if type( event_type ) ~= "string" or event_type == "" then return end
    local clean = _sanitise( payload )
    clean.id        = _next_id
    clean.type      = event_type
    clean.timestamp = _iso_now( )
    _next_id = _next_id + 1
    table_insert( _buffer, clean )
    local cap = tonumber( cfg.get( "http_events_buffer_size" ) ) or DEFAULT_BUFFER_SIZE
    if cap < 1 then cap = DEFAULT_BUFFER_SIZE end
    while #_buffer > cap do
        table_remove( _buffer, 1 )
    end
    -- PR-B: notify long-poll waiters whose filter matches this event.
    for i = #_waiters, 1, -1 do
        local w = _waiters[ i ]
        if w.types_filter == nil or w.types_filter[ event_type ] then
            _resolve_waiter( w )
            table_remove( _waiters, i )
        end
    end
end

-- Map a comma-separated `types=` query param into a lookup table.
-- Returns nil if the filter is absent (= all types pass).
local _parse_types_filter = function( q )
    if q == nil or q == "" then return nil end
    local set = { }
    for piece in tostring( q ):gmatch( "[^,]+" ) do
        local trimmed = piece:match( "^%s*(.-)%s*$" )
        if trimmed and trimmed ~= "" then
            set[ trimmed ] = true
        end
    end
    return set
end

-- Read events with id > since that match the optional type filter.
-- Returns ( rows, cursor, cursor_lost ).
--   rows         array of event tables (each has id/type/timestamp + payload)
--   cursor       the highest id we've handed out so far (caller's next `since`)
--   cursor_lost  true if `since` is below the buffer's minimum id (oldest evicted)
-- This is the immediate-return path. PR-B adds the wait/yield variant.
--
-- NB: this function does NOT do scope-based filtering. The HTTP
-- handler is responsible for masking `pm` events from read-scope
-- tokens. Plugins calling poll() directly see everything (matches
-- the documented trust contract in docs/SECURITY.md §2).
-- Shared core: given a parsed `since` integer and types_filter set
-- (nil = match all), return ( rows, cursor, cursor_lost ). Used by
-- both poll() and _resolve_waiter so the filter / cursor-lost
-- semantics stay consistent across the immediate-return AND the
-- long-poll resolve paths.
local _compute_rows = function( since, types_filter )
    if since == nil or since < 0 then since = 0 end
    local cursor_lost = false
    if #_buffer > 0 then
        local min_id = _buffer[ 1 ].id
        if since < min_id - 1 then
            cursor_lost = true
        end
    end
    local rows = { }
    for _, ev in ipairs( _buffer ) do
        if ev.id > since then
            if types_filter == nil or types_filter[ ev.type ] then
                rows[ #rows + 1 ] = ev
            end
        end
    end
    return rows, _next_id - 1, cursor_lost
end

local poll = function( since_raw, types_filter_raw )
    local since = tonumber( since_raw )
    if since == nil then
        if since_raw == "latest" then
            -- Client signals "I just want the latest cursor, no replay" -
            -- return empty + the current cursor so next poll picks up new
            -- events only.
            return { }, _next_id - 1, false
        end
        since = 0
    end
    return _compute_rows( since, _parse_types_filter( types_filter_raw ) )
end

-- Map a scripts.firelistener call (ltype + up-to-five args) into a
-- public event-type + payload. Returns ( event_type, payload ) or
-- ( nil ) for ltypes we deliberately don't surface.
local _listener_arg_to_event = function( ltype, a1, a2, a3, a4, a5 )
    if ltype == "onLogin" then
        -- a1 = user
        if not a1 then return nil end
        return "login", {
            nick  = a1.nick  and a1:nick( )  or "",
            sid   = a1.sid   and a1:sid( )   or "",
            level = a1.level and a1:level( ) or 0,
        }
    end
    if ltype == "onLogout" then
        if not a1 then return nil end
        return "logout", {
            nick = a1.nick and a1:nick( ) or "",
            sid  = a1.sid  and a1:sid( )  or "",
        }
    end
    if ltype == "onBroadcast" then
        -- a1 = user, a2 = adccmd (unused), a3 = decoded text
        if not a1 then return nil end
        return "broadcast", {
            nick    = a1.nick and a1:nick( ) or "",
            sid     = a1.sid  and a1:sid( )  or "",
            message = a3 or "",
        }
    end
    if ltype == "onPrivateMessage" then
        -- core/hub_dispatch.lua fires this as
        -- (user, targetuser, adccmd, decoded_text). a3 is the
        -- adccmd TABLE (NOT the message - early PR-A draft got
        -- this wrong); a4 is the escapefrom-decoded text.
        if not a1 then return nil end
        return "pm", {
            from_nick = ( type( a1 ) == "table" and a1.nick and a1:nick( ) ) or tostring( a1 ),
            to_nick   = ( type( a2 ) == "table" and a2.nick and a2:nick( ) ) or tostring( a2 or "" ),
            message   = tostring( a4 or "" ),
        }
    end
    if ltype == "onFailedAuth" then
        -- a1 = nick (string), a2 = ip, a3 = cid, a4 = reason
        return "failed_auth", {
            nick      = tostring( a1 or "" ),
            source_ip = tostring( a2 or "" ),
            reason    = tostring( a4 or "" ),
        }
    end
    if ltype == "onReg" then
        return "reg_added", {
            nick = tostring( a1 or "" ),
        }
    end
    if ltype == "onDelreg" then
        return "reg_removed", {
            nick = tostring( a1 or "" ),
        }
    end
    if ltype == "onError" then
        return "script_error", {
            message = tostring( a1 or "" ),
        }
    end
    -- #84: audit events for staff actions. a1 is the canonical
    -- event table built by core/audit.lua (action / actor /
    -- target / reason / meta). We flatten the nested actor +
    -- target shapes into the ringbuffer payload so the existing
    -- per-string _sanitise pass covers everything in one
    -- recursion level. `meta` is dropped from the live stream
    -- to keep the wire size bounded - the disk JSONL (written by
    -- etc_auditlog.lua) carries the full payload for operators
    -- who need it. Admin-scope-only filter belongs in the HTTP
    -- handler (same model as `pm`), see docs/SECURITY.md §X.
    if ltype == "onAudit" then
        if type( a1 ) ~= "table" then return nil end
        local actor  = a1.actor  or { }
        local target = a1.target or { }
        return "audit", {
            action      = tostring( a1.action      or "" ),
            actor_nick  = tostring( actor.nick     or "" ),
            actor_level = tonumber( actor.level    ) or 0,
            actor_sid   = tostring( actor.sid      or "" ),
            actor_cid   = tostring( actor.cid      or "" ),
            actor_ip    = tostring( actor.ip       or "" ),
            target_nick = tostring( target.nick    or "" ),
            target_sid  = tostring( target.sid     or "" ),
            target_cid  = tostring( target.cid     or "" ),
            target_ip   = tostring( target.ip      or "" ),
            target_level = tonumber( target.level  ) or 0,
            reason      = tostring( a1.reason      or "" ),
        }
    end
    return nil
end

-- PR-B: resolve a waiter - compute the current ( rows, cursor,
-- cursor_lost ) tuple, hand to the render closure (which applies
-- the scope-specific pm filter), write the response bytes to the
-- held handler, close the connection. Wrapped in pcall because
-- the client may have disconnected mid-poll.
_resolve_waiter = function( w )
    local rows, cursor, cursor_lost = _compute_rows( w.since, w.types_filter )
    local response_bytes = w.render_fn( rows, cursor, cursor_lost )
    pcall( w.handler.write, response_bytes )
    pcall( w.handler.close )
end

-- PR-B public API: handler returned a deferred response.
-- Register the open connection as a waiter; emit() / tick() will
-- resolve it.
local register_waiter = function( handler, since_raw, types_str, wait_seconds, render_fn )
    if type( handler ) ~= "table" then return end
    if type( render_fn ) ~= "function" then return end
    local since = tonumber( since_raw ) or 0
    if since < 0 then since = 0 end
    local secs = tonumber( wait_seconds ) or 30
    if secs < 1 then secs = 1 end
    if secs > 60 then secs = 60 end
    _waiters[ #_waiters + 1 ] = {
        handler      = handler,
        since        = since,
        types_str    = types_str,
        types_filter = _parse_types_filter( types_str ),
        -- socket.gettime() gives ms-resolution wall clock; os.time()
        -- returns integer seconds, which on the deadline math meant a
        -- request arriving at epoch T.99 with wait=2 got deadline =
        -- floor(T.99)+2 = T+2 and resolved at the very next tick at
        -- T+2 (elapsed = 1.01s, NOT the requested 2s). Closes the
        -- "events PR-B long-poll: returned too fast" flake from
        -- post-merge Windows CI (#332 master run, post #263 PR-B).
        deadline     = socket_gettime( ) + secs,
        render_fn    = render_fn,
    }
end

-- PR-B: called from server.lua's timer loop ~once per second.
-- Resolves any waiter whose deadline has elapsed with an empty
-- events array (client picks up the cursor and immediately re-polls).
-- Uses socket.gettime() to match register_waiter's ms-resolution
-- deadline (see comment above).
local tick = function( )
    local now = socket_gettime( )
    for i = #_waiters, 1, -1 do
        local w = _waiters[ i ]
        if w.deadline <= now then
            _resolve_waiter( w )
            table_remove( _waiters, i )
        end
    end
end

-- The tap callback registered into scripts.firelistener. Wrapped
-- in pcall by scripts.lua so a bad mapping here can't cascade
-- into the listener-chain's contract.
local _firelistener_tap = function( ltype, a1, a2, a3, a4, a5 )
    local event_type, payload = _listener_arg_to_event( ltype, a1, a2, a3, a4, a5 )
    if event_type then
        emit( event_type, payload )
    end
end

local init = function( )
    _max_size = tonumber( cfg.get( "http_events_buffer_size" ) ) or DEFAULT_BUFFER_SIZE
    if _max_size < 1 then _max_size = DEFAULT_BUFFER_SIZE end
    local scripts = use "scripts"
    if type( scripts.register_tap ) == "function" then
        scripts.register_tap( _firelistener_tap )
    end
    -- PR-B: register the deadline-tick into server.lua's ~1s
    -- timer loop. The same timer also drives the existing
    -- onTimer listener-chain (core/hub.lua), but we use a
    -- dedicated entry so a long-poll timeout doesn't run
    -- through the plugin tap chain (would emit a tick-loop event).
    local server = use "server"
    if type( server.addtimer ) == "function" then
        server.addtimer( tick )
    end
end

----------------------------------// PUBLIC INTERFACE //--

return {
    init            = init,
    emit            = emit,
    poll            = poll,
    -- PR-B: long-poll wiring used by core/http_router.lua's
    -- events_get_handler when ?wait=<seconds> is supplied.
    register_waiter = register_waiter,
    -- Test / introspection helpers (NOT for plugin use).
    _buffer_size  = function( ) return #_buffer end,
    _next_id      = function( ) return _next_id end,
    _waiter_count = function( ) return #_waiters end,
}
