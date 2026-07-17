--[[

    core/whitelist.lua - global IP/CIDR allowlist consulted by every
    IP-blocking path (the deferred #78 allowlist).

    A trusted-infrastructure allowlist: an IP/CIDR on this list is
    exempt from the AUTOMATED blockers - GeoIP country/ASN, proxy
    detection, external feeds (Tor / Spamhaus / AbuseIPDB), the
    hub-limit ban - AND from the automated entries in the unified
    blocklist store. It does NOT override a deliberate manual block
    (a `+blocklist add` with source="manual" or a `+ban`): a
    manual/operator block wins, so an operator can still block a
    specific IP even if it falls in a whitelisted range. If you need
    to block a whitelisted IP, remove it from the whitelist first.

    Structurally this is a stripped-down sibling of core/blocklist.lua:
    same in-memory bucketed cache, same hex-encoded .tbl store, same
    v4-mapped-v6 normalisation on lookup. It drops everything a
    deny-engine needs but an allow-set does not: no source PRIORITY
    (any match = allowed; the `source` field is a label only, e.g.
    "manual" vs the bundled "pinger" seed), no stealth flag, no
    aggregated-log rollup, no feed bulk_replace.

    Consumed by:
      * core/blocklist.lua check_ip() - overrides an automated block
        pre-handshake (manual pins excepted, see above).
      * plugins that block by IP (etc_geoip / etc_proxydetect /
        usr_hubs / ...) - each calls whitelist.is_whitelisted(ip)
        before its own block. Exposed as the sandbox global
        `whitelist` (mirrors `blocklist`).

    Public surface:

        whitelist.is_whitelisted(ip) -> bool
            true if ip is covered by an active (non-expired) entry.
            nil / empty ip -> false. Disabled or empty store -> false
            via a single next() fast-path (zero meaningful overhead).

        whitelist.add(cidr_or_ip, opts) -> ok, id, err
            opts = { source, reason, by_nick, by_level, expires_at, meta }
            source defaults to "manual" (a label only, no priority).

        whitelist.remove(id) -> ok, err
            By numeric id. false + "not_found" if absent.

        whitelist.list(filter_spec) -> rows        (filter: { source })
        whitelist.count() -> { total, by_source }
        whitelist.reload()                          re-read the .tbl
        whitelist._resolve_match(ip) -> entry | nil (exposed for tests)

]]--

local use = use

local type      = use "type"
local next      = use "next"
local pairs     = use "pairs"
local ipairs    = use "ipairs"
local tostring  = use "tostring"
local tonumber  = use "tonumber"
local string    = use "string"
local table     = use "table"
local math      = use "math"
local io        = use "io"
local socket    = use "socket"

local string_byte    = string.byte
local string_format  = string.format
local string_sub     = string.sub
local table_insert   = table.insert
local table_remove   = table.remove
local math_floor     = math.floor
local io_open        = io.open
local socket_gettime = socket.gettime

local util    = use "util"
local ipmatch = use "ipmatch"

local util_loadtable  = util.loadtable
local util_savetable  = util.savetable
local ipmatch_parse_cidr   = ipmatch.parse_cidr
local ipmatch_parse_ip     = ipmatch.parse_ip
local ipmatch_match        = ipmatch.match
local ipmatch_format_bytes = ipmatch.format_bytes

-- Late-bound core deps (bound in init(), mirroring blocklist.lua).
local cfg_get
local out_put
local out_error

----------------------------------------------------------------------
-- State
----------------------------------------------------------------------

local _enabled = true
local _store_path = "scripts/data/etc_whitelist.tbl"

local _entries = { }        -- array of entry records, order = insert
local _next_id = 1
local _buckets_v4 = { }     -- [byte 1] -> array of entry refs
local _buckets_v6 = { }     -- [byte1 * 256 + byte2] -> array of entry refs

----------------------------------------------------------------------
-- Bucket helpers (identical radix scheme to core/blocklist.lua: first
-- byte for v4, first two bytes for v6; short prefixes enroll in every
-- covering bucket so the lookup stays O(1) + linear-scan-of-bucket).
----------------------------------------------------------------------

local function _bucket_for( family, network_bytes, prefix_len )
    if family == 4 then
        if prefix_len >= 8 then
            return { string_byte( network_bytes, 1 ) }
        end
        local first_byte = string_byte( network_bytes, 1 )
        local span = ( 1 << ( 8 - prefix_len ) )
        local out = { }
        for i = 0, span - 1 do
            out[ #out + 1 ] = first_byte + i
        end
        return out
    end
    -- family == 6
    if prefix_len >= 16 then
        local b1, b2 = string_byte( network_bytes, 1, 2 )
        return { b1 * 256 + b2 }
    end
    local b1 = string_byte( network_bytes, 1 )
    if prefix_len >= 8 then
        local b2 = string_byte( network_bytes, 2 )
        local span = ( 1 << ( 16 - prefix_len ) )
        local base = b1 * 256 + b2
        local out = { }
        for i = 0, span - 1 do
            out[ #out + 1 ] = base + i
        end
        return out
    end
    local span = ( 1 << ( 8 - prefix_len ) )
    local out = { }
    for i = 0, span - 1 do
        local first = b1 + i
        for j = 0, 255 do
            out[ #out + 1 ] = first * 256 + j
        end
    end
    return out
end

local function _bucket_table( family )
    if family == 4 then return _buckets_v4 end
    return _buckets_v6
end

local function _bucket_insert( entry )
    local tbl = _bucket_table( entry.family )
    for _, key in ipairs( entry._buckets ) do
        local list = tbl[ key ]
        if not list then
            list = { }
            tbl[ key ] = list
        end
        list[ #list + 1 ] = entry
    end
end

local function _bucket_remove( entry )
    local tbl = _bucket_table( entry.family )
    for _, key in ipairs( entry._buckets ) do
        local list = tbl[ key ]
        if list then
            for i, e in ipairs( list ) do
                if e == entry then
                    table_remove( list, i )
                    break
                end
            end
            if #list == 0 then tbl[ key ] = nil end
        end
    end
end

----------------------------------------------------------------------
-- Disk persistence (Lua-table dump; raw network bytes hex-encoded to
-- keep the .tbl text-safe, exactly as core/blocklist.lua does).
----------------------------------------------------------------------

local function _hex_encode( s )
    local out = { }
    for i = 1, #s do
        out[ i ] = string_format( "%02x", string_byte( s, i ) )
    end
    return table.concat( out )
end

local function _hex_decode( s )
    if type( s ) ~= "string" or ( #s % 2 ) ~= 0 then return nil end
    local out = { }
    for i = 1, #s, 2 do
        local byte_val = tonumber( s:sub( i, i + 1 ), 16 )
        if not byte_val then return nil end
        out[ #out + 1 ] = string.char( byte_val )
    end
    return table.concat( out )
end

local function _persist_one( e )
    return {
        id          = e.id,
        cidr        = e.cidr,
        family      = e.family,
        network_b64 = e._network_b64,
        prefix_len  = e.prefix_len,
        source      = e.source,
        reason      = e.reason or "",
        by_nick     = e.by_nick or "",
        by_level    = e.by_level,
        expires_at  = e.expires_at,
        created_at  = e.created_at,
        meta        = e.meta,
    }
end

local function _save_to_disk( )
    local snapshot = { }
    for i, e in ipairs( _entries ) do
        snapshot[ i ] = _persist_one( e )
    end
    local ok, err = util_savetable( snapshot, "whitelist", _store_path )
    if not ok then
        if out_error then out_error( "whitelist: save failed: " .. tostring( err ) ) end
        return false, err
    end
    return true
end

----------------------------------------------------------------------
-- Entry construction
----------------------------------------------------------------------

local function _make_entry( cidr, opts )
    local family, network_bytes, prefix_len = ipmatch_parse_cidr( cidr )
    if not family then
        return nil, network_bytes    -- second value is the err string
    end
    local canonical_ip = ipmatch_format_bytes( family, network_bytes )
    if not canonical_ip then
        return nil, "internal: cannot format canonical CIDR from bytes"
    end
    local canonical_cidr = canonical_ip .. "/" .. prefix_len

    opts = opts or { }
    local now = socket_gettime( )
    local entry = {
        id            = _next_id,
        cidr          = canonical_cidr,
        family        = family,
        network_bytes = network_bytes,
        prefix_len    = prefix_len,
        -- `source` is a LABEL only (no priority): "manual" for an
        -- operator add, "pinger" for the bundled seed, etc. Any match
        -- means allowed regardless of source.
        source        = opts.source or "manual",
        reason        = opts.reason or "",
        by_nick       = opts.by_nick or "",
        -- by_level = operator level at add time, for the Phase B
        -- `+whitelist del` hierarchy check. nil for the seed.
        by_level      = tonumber( opts.by_level ),
        expires_at    = opts.expires_at,
        created_at    = math_floor( now ),
        meta          = opts.meta,
        _network_b64  = _hex_encode( network_bytes ),
    }
    return entry
end

local function _sweep_expired( now )
    local kept = { }
    local removed_any = false
    for _, e in ipairs( _entries ) do
        if e.expires_at and e.expires_at <= now then
            _bucket_remove( e )
            removed_any = true
        else
            kept[ #kept + 1 ] = e
        end
    end
    if removed_any then _entries = kept end
    return removed_any
end

----------------------------------------------------------------------
-- Lookup
----------------------------------------------------------------------

local _resolve_match

local function is_whitelisted( ip )
    if not _enabled then return false end
    if not ip then return false end
    -- Fast path: an empty store is the common case for operators who
    -- never add an allow entry - a single next() and we are out, no
    -- parse, no bucket work.
    if not next( _entries ) then return false end
    return _resolve_match( ip ) ~= nil
end

_resolve_match = function( ip )
    if type( ip ) ~= "string" or ip == "" then return nil end
    local family, bytes = ipmatch_parse_ip( ip )
    if not family then return nil end

    -- v4-mapped-v6 normalisation, identical to core/blocklist.lua
    -- _resolve_decision: a dual-stack listener delivers IPv4 clients
    -- as `::ffff:a.b.c.d`, so re-key those to plain v4 or an
    -- operator's v4 whitelist entry would never match a v4-over-v6
    -- client. Explicit `::ffff:.../128` v6 entries still work (they
    -- were canonicalised to v6 bytes at add() time).
    if family == 6 and #bytes == 16 then
        local is_mapped = true
        for i = 1, 10 do
            if string_byte( bytes, i ) ~= 0 then is_mapped = false; break end
        end
        if is_mapped and string_byte( bytes, 11 ) == 0xff
                     and string_byte( bytes, 12 ) == 0xff then
            family = 4
            bytes = string_sub( bytes, 13, 16 )
        end
    end

    local bucket
    if family == 4 then
        bucket = _buckets_v4[ string_byte( bytes, 1 ) ]
    else
        local b1, b2 = string_byte( bytes, 1, 2 )
        bucket = _buckets_v6[ b1 * 256 + b2 ]
    end
    if not bucket then return nil end

    local now = socket_gettime( )
    for _, entry in ipairs( bucket ) do
        if entry.expires_at and entry.expires_at <= now then
            -- expired; filtered on every lookup, removed on next add/reload
        elseif ipmatch_match( bytes, entry.network_bytes, entry.prefix_len ) then
            -- No priority to resolve: first active match wins.
            return entry
        end
    end
    return nil
end

----------------------------------------------------------------------
-- Mutators
----------------------------------------------------------------------

local function add( cidr, opts )
    local entry, err = _make_entry( cidr, opts )
    if not entry then return false, nil, err end
    _sweep_expired( socket_gettime( ) )
    entry._buckets = _bucket_for( entry.family, entry.network_bytes, entry.prefix_len )
    _next_id = _next_id + 1
    _entries[ #_entries + 1 ] = entry
    _bucket_insert( entry )
    local ok, save_err = _save_to_disk( )
    if not ok then
        _entries[ #_entries ] = nil
        _next_id = _next_id - 1
        _bucket_remove( entry )
        return false, nil, "save failed: " .. tostring( save_err )
    end
    return true, entry.id
end

local function remove( id )
    if type( id ) ~= "number" then return false, "id must be a number" end
    for i, e in ipairs( _entries ) do
        if e.id == id then
            table_remove( _entries, i )
            _bucket_remove( e )
            local ok, err = _save_to_disk( )
            if not ok then
                table_insert( _entries, i, e )
                _bucket_insert( e )
                return false, "save failed: " .. tostring( err )
            end
            return true
        end
    end
    return false, "not_found"
end

local _FILTER_KEYS = { source = true }

local function list( filter_spec )
    local out = { }
    filter_spec = filter_spec or { }
    for k in pairs( filter_spec ) do
        if not _FILTER_KEYS[ k ] then
            if out_put then
                out_put( "whitelist: list() ignoring unknown filter key '" ..
                    tostring( k ) .. "'" )
            end
        end
    end
    for _, e in ipairs( _entries ) do
        local include = true
        if filter_spec.source and e.source ~= filter_spec.source then include = false end
        if include then
            local meta_copy
            if type( e.meta ) == "table" then
                meta_copy = { }
                for k, v in pairs( e.meta ) do meta_copy[ k ] = v end
            end
            out[ #out + 1 ] = {
                id         = e.id,
                cidr       = e.cidr,
                source     = e.source,
                reason     = e.reason,
                by_nick    = e.by_nick,
                by_level   = e.by_level,
                expires_at = e.expires_at,
                created_at = e.created_at,
                meta       = meta_copy,
            }
        end
    end
    return out
end

local function count( )
    local by_source = { }
    for _, e in ipairs( _entries ) do
        by_source[ e.source ] = ( by_source[ e.source ] or 0 ) + 1
    end
    return { total = #_entries, by_source = by_source }
end

----------------------------------------------------------------------
-- Load / reload
----------------------------------------------------------------------

local function reload( )
    _entries = { }
    _next_id = 1
    _buckets_v4 = { }
    _buckets_v6 = { }

    -- Peek before util.loadtable to avoid the noisy checkfile error
    -- line on a fresh install (mirrors blocklist.lua). Empty store is
    -- the correct first-boot state; the Phase B plugin seeds the
    -- bundled pinger allowlist on its first run, not here.
    local probe = io_open( _store_path, "r" )
    if not probe then return end
    probe:close( )

    local data, err = util_loadtable( _store_path )
    if not data then
        if err and not err:find( "No such file" ) then
            if out_error then out_error( "whitelist: load failed: " .. tostring( err ) ) end
        end
        return
    end
    if type( data ) ~= "table" then return end

    local now = socket_gettime( )
    for _, row in ipairs( data ) do
        local expired = row.expires_at and row.expires_at <= now
        local network_bytes = _hex_decode( row.network_b64 or "" )
        if ( not expired ) and network_bytes and ( ( row.family == 4 and #network_bytes == 4 ) or ( row.family == 6 and #network_bytes == 16 ) ) then
            local entry = {
                id            = tonumber( row.id ) or _next_id,
                cidr          = row.cidr,
                family        = row.family,
                network_bytes = network_bytes,
                prefix_len    = tonumber( row.prefix_len ) or ( row.family == 4 and 32 or 128 ),
                source        = row.source or "manual",
                reason        = row.reason or "",
                by_nick       = row.by_nick or "",
                by_level      = tonumber( row.by_level ),
                expires_at    = row.expires_at,
                created_at    = row.created_at,
                meta          = row.meta,
                _network_b64  = row.network_b64,
            }
            entry._buckets = _bucket_for( entry.family, entry.network_bytes, entry.prefix_len )
            _entries[ #_entries + 1 ] = entry
            _bucket_insert( entry )
            if entry.id >= _next_id then _next_id = entry.id + 1 end
        end
    end
end

----------------------------------------------------------------------
-- Init - called from init.lua _core sweep
----------------------------------------------------------------------

local function _resnapshot_cfg( )
    local cfg_enabled = cfg_get "whitelist_enabled"
    _enabled = ( cfg_enabled == nil ) or ( cfg_enabled and true ) or false
    _store_path = cfg_get( "whitelist_store_path" ) or _store_path
end

local function _reload_on_cfg_reload( )
    _resnapshot_cfg( )
    reload( )
end

local function init( )
    cfg_get = use( "cfg" ).get
    local out_mod = use "out"
    out_put = out_mod.put
    out_error = out_mod.error

    _resnapshot_cfg( )
    reload( )

    local cfg_mod = use "cfg"
    if type( cfg_mod.registerevent ) == "function" then
        cfg_mod.registerevent( "reload", _reload_on_cfg_reload )
    end
end

return {
    init           = init,
    is_whitelisted = is_whitelisted,
    add            = add,
    remove         = remove,
    list           = list,
    count          = count,
    reload         = reload,
    _resolve_match = _resolve_match,
    _hex_encode    = _hex_encode,
    _hex_decode    = _hex_decode,
}
