--[[

    core/audit.lua - structured audit-log event builder + fire helper.

    Closes part of #84 (Audit log for staff actions). Centralises
    the audit event shape so all fire sites across admin plugins
    emit the same canonical payload. The corresponding writer
    plugin (scripts/etc_auditlog.lua) subscribes to the `onAudit`
    listener and serializes events as JSON-Lines to
    log/audit-YYYY-MM-DD.jsonl with daily rollover and configurable
    retention. core/http_events.lua also taps onAudit so events
    show up in the GET /v1/events long-poll stream as type=audit
    for admin-scope clients.

    Event shape (canonical, enforced here):

        {
            action = "ban.add",                          -- dotted scoped
            actor  = { nick, level, sid, cid, ip },      -- snapshot at fire time
            target = { nick, sid, cid, ip, level, ... }, -- subset relevant to action
            reason = "...",                              -- optional
            meta   = { ... },                            -- optional plugin-specific
        }

    Plugin usage:

        local audit = use "audit"
        ...
        audit.fire( audit.build(
            "ban.add",
            user,                                   -- actor: user-object OR table
            { nick = target_nick, ip = target_ip }, -- target shape
            reason,
            { duration_sec = 86400 }                -- meta
        ) )

    The actor argument accepts:
      - a user-object: nick / level / sid / cid / ip extracted via the
        documented user-object API (cmd handlers always have this).
      - a flat table { nick=..., level=..., sid=..., ... } for the
        HTTP API path where there is no user-object (use sid="<http>"
        and nick=req.token_label).
      - a plain string: shorthand for { nick = <string>, ... }.

    Snapshotting at fire time means the writer never has to call
    methods on a possibly-disconnected user object.

    Append discipline + sandbox forgery caveats live in
    docs/SECURITY.md "Audit log".

]]--

----------------------------------// DECLARATION //--

local use = use

local type = use "type"
local pairs = use "pairs"
local tostring = use "tostring"
local tonumber = use "tonumber"

local string = use "string"
local string_sub = string.sub

local util = use "util"
local strip_control_bytes = util.strip_control_bytes

-- scripts + cfg + out are late-bound to avoid a load-order cycle
-- (scripts.lua does not `use "audit"` but audit needs scripts at
-- fire time; cfg needs to be live before reading the cap keys).
local _scripts
local cfg_get
local out_error

----------------------------------// CONSTANTS //--

local DEFAULT_MAX_REASON_CHARS     = 1000
local DEFAULT_MAX_META_VALUE_CHARS = 1000

----------------------------------// IMPLEMENTATION //--

-- Snapshot a user-object into the actor table. Plugins call
-- audit.build with the user-object; snapshotting here means the
-- writer never has to call methods on a possibly-disconnected user.
-- nick is captured as `firstnick` (canonical identity, prefix-less)
-- to match the user.tbl `by` field and the etc_report convention -
-- audit-trail entries survive nick-prefix-table edits this way.
-- `display_nick` carries the at-the-time visible form (with level
-- prefix if any) for operators correlating chat lines.
local function _snapshot_actor( actor )
    if actor == nil then
        return { nick = "", level = 0, sid = "", cid = "", ip = "" }
    end
    if type( actor ) == "string" then
        return { nick = actor, level = 0, sid = "", cid = "", ip = "" }
    end
    if type( actor ) ~= "table" then
        return { nick = tostring( actor ), level = 0, sid = "", cid = "", ip = "" }
    end
    -- user-object detection: `nick` is a method (function), not a string.
    if type( actor.nick ) == "function" then
        local canonical = ( type( actor.firstnick ) == "function" )
                          and tostring( actor:firstnick( ) or "" )
                          or  tostring( actor:nick( )      or "" )
        local visible   = tostring( actor:nick( ) or "" )
        local snap = {
            nick  = canonical,
            level = tonumber( actor:level( ) ) or 0,
            sid   = tostring( actor:sid( )   or "" ),
            cid   = ( actor.cid and tostring( actor:cid( ) or "" ) ) or "",
            ip    = ( actor.ip  and tostring( actor:ip( )  or "" ) ) or "",
        }
        if visible ~= "" and visible ~= canonical then
            snap.display_nick = visible
        end
        return snap
    end
    -- Flat table: pass-through with defaults for missing fields.
    return {
        nick  = tostring( actor.nick  or "" ),
        level = tonumber( actor.level ) or 0,
        sid   = tostring( actor.sid   or "" ),
        cid   = tostring( actor.cid   or "" ),
        ip    = tostring( actor.ip    or "" ),
    }
end

-- Strip control bytes + cap string length. Returns nil if input was nil.
local function _normalize_str( s, max )
    if s == nil then return nil end
    s = strip_control_bytes( tostring( s ) )
    if max and #s > max then s = string_sub( s, 1, max ) end
    return s
end

-- One-level table normalize: string values get _normalize_str,
-- numbers and booleans pass through, anything else gets tostring'd.
-- Returns nil for empty input or all-keys-collapsed result so the
-- downstream JSON encoder produces no `meta` / `target` field
-- instead of an ambiguous `[]` (Lua empty tables serialize as
-- arrays under dkjson).
local function _normalize_table( t, max )
    if t == nil or type( t ) ~= "table" then return nil end
    local out = { }
    local has_any = false
    for k, v in pairs( t ) do
        local vt = type( v )
        if vt == "string" then
            out[ k ] = _normalize_str( v, max )
        elseif vt == "number" or vt == "boolean" then
            out[ k ] = v
        else
            out[ k ] = _normalize_str( tostring( v ), max )
        end
        has_any = true
    end
    if not has_any then return nil end
    return out
end

-- Target snapshot: accepts user-object OR flat table OR nil.
-- Same shape (nick / sid / cid / ip / level) as actor, but flat
-- tables can also carry plugin-specific keys (e.g. cmd_ban passes
-- ip in addition to nick - those keys pass through normalize_table).
-- Mirrors _snapshot_actor's firstnick-canonical / nick-display split.
local function _snapshot_target( target, max )
    if target == nil then return nil end
    -- user-object: nick is a method.
    if type( target ) == "table" and type( target.nick ) == "function" then
        local canonical = ( type( target.firstnick ) == "function" )
                          and tostring( target:firstnick( ) or "" )
                          or  tostring( target:nick( )      or "" )
        local visible   = tostring( target:nick( ) or "" )
        local snap = {
            nick  = canonical,
            level = tonumber( target:level( ) ) or 0,
            sid   = tostring( target:sid( )   or "" ),
            cid   = ( target.cid and tostring( target:cid( ) or "" ) ) or "",
            ip    = ( target.ip  and tostring( target:ip( )  or "" ) ) or "",
        }
        if visible ~= "" and visible ~= canonical then
            snap.display_nick = visible
        end
        return snap
    end
    -- Flat table: pass through normalize_table.
    return _normalize_table( target, max )
end

local function build( action, actor, target, reason, meta )
    if type( action ) ~= "string" or action == "" then
        if out_error then
            out_error( "audit.lua: build: action must be a non-empty string" )
        end
        return nil
    end

    local max_reason = DEFAULT_MAX_REASON_CHARS
    local max_meta   = DEFAULT_MAX_META_VALUE_CHARS
    if cfg_get then
        max_reason = tonumber( cfg_get "audit_log_max_reason_chars"     ) or max_reason
        max_meta   = tonumber( cfg_get "audit_log_max_meta_value_chars" ) or max_meta
    end

    return {
        action = action,
        actor  = _snapshot_actor( actor ),
        target = _snapshot_target( target, max_reason ),
        reason = _normalize_str(  reason, max_reason ),
        meta   = _normalize_table( meta,  max_meta ),
    }
end

local function fire( event )
    if type( event ) ~= "table" then return end
    -- Late-bind scripts on first call to avoid a load-order cycle
    -- (init.lua loads scripts AFTER audit, so use "scripts" at
    -- module load time would fail).
    if not _scripts then
        _scripts = use "scripts"
    end
    if type( _scripts.firelistener ) == "function" then
        _scripts.firelistener( "onAudit", event )
    end
end

local function init( )
    local cfg = use "cfg"
    cfg_get = cfg.get
    local out = use "out"
    out_error = out.error
end

----------------------------------// PUBLIC INTERFACE //--

return {
    init  = init,
    build = build,
    fire  = fire,
}
