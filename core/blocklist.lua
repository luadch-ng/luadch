--[[

    core/blocklist.lua - unified pre-handshake IP/CIDR blocklist.

    Phase A of the unified-blocklist arc (#78). Stands up the
    in-memory bucketed cache + persistent .tbl store + decision
    API consumed by the stealth hook in core/server.lua and by
    Phase B's `+blocklist` admin plugin + Phase C's HTTP API +
    Phase D/E/F's GeoIP / external-feed / proxy plugins.

    Design notes:

      * In-memory cache, .tbl-backed. On add/remove we mutate the
        in-memory state AND persist atomically. Plugins call
        public API only; they never hold a reference to the
        entries array (avoids the stale-rebind hazard documented
        in past arcs).

      * Bucketing on the first byte (v4) / first two bytes (v6)
        keeps the hot-path scan local: at 5k entries spread over
        256 v4 buckets, the average bucket has ~20 entries and
        linear scan within a bucket is microseconds. The radix
        keys are extracted from the raw IP bytes returned by
        core/ipmatch.lua - no integer conversion needed.

      * Decision priority order: manual > geoip > proxycheck >
        ipqs > vpnapi > external. Higher-priority sources win
        when multiple entries match the same IP. The order is
        documented + locked here; future sources slot into the
        table at registration time.

      * Aggregated log rollup: per-IP attempt counters, flushed
        every `blocklist_aggregated_log_window_sec` seconds (one
        line per IP+source pair). LRU-capped at 10k IPs to keep
        IPv6 randomisation from OOMing the hub.

      * Stealth flag per entry: blocks happen identically at the
        TCP-accept layer (close-without-reply by construction -
        we are pre-ADC-handshake there), so stealth distinguishes
        visibility in the operator log:

           stealth = false (default) -> per-attempt out.put line
                                        + included in aggregated rollup
           stealth = true            -> NO per-attempt line, included
                                        in aggregated rollup only

        Plus an explicit "stealth-only" rollup omits the source
        meta from the line to avoid leaking the detection method
        to an attacker reading logs.

    Public surface:

        blocklist.check_ip(ip) -> blocked, source, meta
            true if the IP is in the active store; source is the
            winning entry's source string; meta is the entry's
            audit-shape table { cidr, reason, stealth, meta }.

        blocklist.add(cidr_or_ip, opts) -> ok, id, err
            opts = { source, reason, by_nick, stealth, expires_at, meta }
            Source defaults to "manual"; stealth defaults to cfg
            `blocklist_stealth_default`.

        blocklist.remove(id) -> ok, err
            By numeric id. Returns false + "not_found" if absent.

        blocklist.list(filter_spec) -> rows
            Full snapshot when filter_spec is nil/{}; supports
            { source = "manual" }, { stealth = true }, ...

        blocklist.count() -> { total, by_source }

        blocklist.reload()
            Re-reads the .tbl from disk and rebuilds the cache.
            Called on cfg-reload event by init().

        blocklist._resolve_decision(ip) -> entry | nil
            Internal helper; exposed for tests. Returns the
            winning entry (highest priority source) when matched,
            nil when no match.

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
local socket    = use "socket"

local string_byte    = string.byte
local string_format  = string.format
local string_lower   = string.lower
local table_insert   = table.insert
local table_remove   = table.remove
local math_floor     = math.floor
local socket_gettime = socket.gettime

local util    = use "util"
local ipmatch = use "ipmatch"

local util_loadtable = util.loadtable
local util_savetable = util.savetable
local ipmatch_parse_cidr  = ipmatch.parse_cidr
local ipmatch_parse_ip    = ipmatch.parse_ip
local ipmatch_match       = ipmatch.match
local ipmatch_format_bytes = ipmatch.format_bytes

-- Late-bound dependencies (cfg / out are core modules loaded
-- alongside us; address by `use` at call time so the load-order
-- in init.lua stays simple).
local cfg_get
local out_put
local out_error

-- Source priority: higher number = higher priority. When multiple
-- entries match the same IP, the winner is the highest-priority.
-- New sources for Phase D/E/F register into this table.
local _SOURCE_PRIORITY = {
    manual     = 100,
    geoip      = 50,
    proxycheck = 40,
    ipqs       = 35,
    vpnapi     = 30,
    external   = 20,
}
local _DEFAULT_PRIORITY = 0

local function _priority( source )
    return _SOURCE_PRIORITY[ source or "" ] or _DEFAULT_PRIORITY
end

----------------------------------------------------------------------
-- State
----------------------------------------------------------------------

local _enabled = true
local _store_path = "cfg/blocklist.tbl"
local _stealth_default = false
local _log_window = 3600
local _rollup_cap = 10000

local _entries = { }        -- array of entry records, order = insert
local _next_id = 1
local _buckets_v4 = { }     -- [byte 1] -> array of entry refs
local _buckets_v6 = { }     -- [byte1 * 256 + byte2] -> array of entry refs

----------------------------------------------------------------------
-- Aggregated rollup state
----------------------------------------------------------------------

local _rollup = { }        -- key (ip..\0..source) -> { ip, source, count, last_seen, stealth }
local _rollup_lru_head = 0
local _rollup_size = 0
local _last_flush_time = 0

local function _rollup_flush_locked( now )
    if next( _rollup ) == nil then
        _last_flush_time = now
        return
    end
    local rows = { }
    for _, agg in pairs( _rollup ) do
        rows[ #rows + 1 ] = agg
    end
    -- Sort by count DESCENDING so the loudest IPs show first in the
    -- flush block. Ties broken by IP for stable output across runs.
    table.sort( rows, function( a, b )
        if a.count ~= b.count then return a.count > b.count end
        return a.ip < b.ip
    end )
    for _, agg in ipairs( rows ) do
        local source_part = agg.stealth and "" or ( " [source=" .. tostring( agg.source ) .. "]" )
        if out_put then
            out_put( string_format( "blocklist: %s %d blocked attempts in last %ds%s",
                agg.ip, agg.count, _log_window, source_part ) )
        end
    end
    _rollup = { }
    _rollup_size = 0
    _last_flush_time = now
end

local function _rollup_maybe_flush( now )
    if _last_flush_time == 0 then _last_flush_time = now end
    if now - _last_flush_time >= _log_window then
        _rollup_flush_locked( now )
    end
end

local function _rollup_record( ip, source, stealth, now )
    _rollup_maybe_flush( now )
    local key = ip .. "\0" .. tostring( source )
    local agg = _rollup[ key ]
    if agg then
        agg.count = agg.count + 1
        agg.last_seen = now
        return
    end
    -- Cap eviction must be O(1) because this fires inside the
    -- accept-time hot path. Under an IPv6-randomisation flood the
    -- rollup sits AT cap, so a per-call O(N) scan would amplify
    -- the very class of attack F-NET-1 is meant to prevent. Drop
    -- an arbitrary entry via `next()` instead of hunting for the
    -- "oldest" - the rollup is a best-effort statistic; perfect-
    -- LRU is not load-bearing.
    if _rollup_size >= _rollup_cap then
        local evict_key = next( _rollup )
        if evict_key then
            _rollup[ evict_key ] = nil
            _rollup_size = _rollup_size - 1
        end
    end
    _rollup[ key ] = {
        ip = ip, source = source, stealth = stealth and true or false,
        count = 1, last_seen = now,
    }
    _rollup_size = _rollup_size + 1
end

----------------------------------------------------------------------
-- Bucket helpers
----------------------------------------------------------------------

local function _bucket_for( family, network_bytes, prefix_len )
    -- For prefixes shorter than the bucket-key width, we have to
    -- enroll the entry in every covering bucket. /0 means every
    -- bucket. /8 in v4 means exactly one bucket. /4 means 16
    -- contiguous buckets. We keep the precomputed list on insert
    -- so the lookup path stays O(1) + linear-scan-of-bucket.
    if family == 4 then
        if prefix_len >= 8 then
            return { string_byte( network_bytes, 1 ) }
        end
        -- /< 8: enumerate the byte range that the prefix covers.
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
        -- prefix covers part of byte 2; enumerate the relevant
        -- low-bits.
        local span = ( 1 << ( 16 - prefix_len ) )
        local base = b1 * 256 + b2
        local out = { }
        for i = 0, span - 1 do
            out[ #out + 1 ] = base + i
        end
        return out
    end
    -- prefix < 8: covers many top-bytes. Conservative: enumerate.
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
-- Disk persistence
--
-- File format: a Lua-table dump (util.savetable / util.loadtable)
-- with the array of entries. We strip the bucket-key cache before
-- saving (computed at load time from network_bytes + prefix_len).
----------------------------------------------------------------------

local function _persist_one( e )
    return {
        id           = e.id,
        cidr         = e.cidr,
        family       = e.family,
        network_b64  = e._network_b64,    -- stored as base64-ish to keep .tbl text-safe
        prefix_len   = e.prefix_len,
        source       = e.source,
        stealth      = e.stealth and true or false,
        reason       = e.reason or "",
        by_nick      = e.by_nick or "",
        expires_at   = e.expires_at,
        created_at   = e.created_at,
        meta         = e.meta,
    }
end

-- Hex-encode raw network bytes (small, robust, no dep on basexx
-- ordering of bytes). 4 bytes for v4 -> 8 hex chars; 16 bytes for
-- v6 -> 32 hex chars. Decoder is `_hex_decode`.
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

local function _save_to_disk( )
    local snapshot = { }
    for i, e in ipairs( _entries ) do
        snapshot[ i ] = _persist_one( e )
    end
    local ok, err = util_savetable( snapshot, "blocklist", _store_path )
    if not ok then
        if out_error then out_error( "blocklist: save failed: " .. tostring( err ) ) end
        return false, err
    end
    return true
end

----------------------------------------------------------------------
-- Entry construction
----------------------------------------------------------------------

local function _rebuild_indices( )
    _buckets_v4 = { }
    _buckets_v6 = { }
    for _, e in ipairs( _entries ) do
        e._buckets = _bucket_for( e.family, e.network_bytes, e.prefix_len )
        _bucket_insert( e )
    end
end

local function _make_entry( cidr, opts )
    local family, network_bytes, prefix_len = ipmatch_parse_cidr( cidr )
    if not family then
        return nil, network_bytes    -- second value is the err string
    end
    -- Canonical CIDR string is computed DIRECTLY from raw bytes via
    -- ipmatch.format_bytes - one pass, no parse/normalize round-trip
    -- and no dependency on the string round-trip producing identical
    -- output across future normalize-helper changes.
    local canonical_ip = ipmatch_format_bytes( family, network_bytes )
    if not canonical_ip then
        return nil, "internal: cannot format canonical CIDR from bytes"
    end
    local canonical_cidr = canonical_ip .. "/" .. prefix_len

    opts = opts or { }
    local source = opts.source or "manual"
    local stealth = opts.stealth
    if stealth == nil then stealth = _stealth_default end

    local now = socket_gettime( )
    local entry = {
        id           = _next_id,
        cidr         = canonical_cidr,
        family       = family,
        network_bytes = network_bytes,
        prefix_len   = prefix_len,
        source       = source,
        stealth      = stealth and true or false,
        reason       = opts.reason or "",
        by_nick      = opts.by_nick or "",
        expires_at   = opts.expires_at,
        created_at   = math_floor( now ),
        meta         = opts.meta,
        _network_b64 = _hex_encode( network_bytes ),
    }
    return entry
end

----------------------------------------------------------------------
-- Public API
----------------------------------------------------------------------

local _resolve_decision

local function check_ip( ip )
    if not _enabled then return false end
    if not next( _entries ) then return false end

    local entry = _resolve_decision( ip )
    if not entry then return false end

    local now = socket_gettime( )
    -- Per-attempt visible log when NOT stealth; the rollup picks
    -- up the count regardless.
    if ( not entry.stealth ) and out_put then
        out_put( string_format(
            "blocklist: refused %s (source=%s, cidr=%s, reason=%s)",
            ip, entry.source, entry.cidr, entry.reason or "" ) )
    end
    _rollup_record( ip, entry.source, entry.stealth, now )

    -- Shallow-copy meta on the way out so a caller doing
    -- `r.meta.foo = "x"` cannot mutate the live entry through this
    -- reference (the trust contract documented in the module header
    -- says plugins NEVER hold a reference to the entries array).
    local meta_copy
    if type( entry.meta ) == "table" then
        meta_copy = { }
        for k, v in pairs( entry.meta ) do meta_copy[ k ] = v end
    end
    return true, entry.source, {
        cidr    = entry.cidr,
        reason  = entry.reason,
        stealth = entry.stealth,
        meta    = meta_copy,
    }
end

_resolve_decision = function( ip )
    if type( ip ) ~= "string" or ip == "" then return nil end
    local family, bytes = ipmatch_parse_ip( ip )
    if not family then return nil end

    local bucket
    if family == 4 then
        bucket = _buckets_v4[ string_byte( bytes, 1 ) ]
    else
        local b1, b2 = string_byte( bytes, 1, 2 )
        bucket = _buckets_v6[ b1 * 256 + b2 ]
    end
    if not bucket then return nil end

    local now = socket_gettime( )
    local best
    for _, entry in ipairs( bucket ) do
        if entry.expires_at and entry.expires_at <= now then
            -- expired; filtered here on every check. Actual removal
            -- from _entries happens on the next add() via _sweep_expired
            -- or on the next reload() (skip-on-load). expires_at
            -- semantics: an entry is "expired" when now >= expires_at
            -- (inclusive boundary).
        elseif ipmatch_match( bytes, entry.network_bytes, entry.prefix_len ) then
            if ( not best ) or _priority( entry.source ) > _priority( best.source ) then
                best = entry
            end
        end
    end
    return best
end

-- Periodic expired-entry sweep. Phase D/E/F auto-feeds (GeoIP,
-- proxydetect, external lists) push entries with expires_at TTLs;
-- without this they accumulate in _entries forever because
-- check_ip only FILTERS expired entries, never removes them.
-- We piggyback the sweep on add() so it runs at human-tunable
-- cadence (operator + auto-feed insert rate) rather than per
-- accept (which would slow the hot path).
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

local function add( cidr, opts )
    local entry, err = _make_entry( cidr, opts )
    if not entry then return false, nil, err end
    -- Sweep expired entries BEFORE persisting the new state so the
    -- .tbl on disk doesn't keep accumulating stale rows. Best-effort:
    -- if the sweep finds nothing, no extra disk I/O happens because
    -- the save below writes the post-sweep snapshot regardless.
    _sweep_expired( socket_gettime( ) )
    entry._buckets = _bucket_for( entry.family, entry.network_bytes, entry.prefix_len )
    _next_id = _next_id + 1
    _entries[ #_entries + 1 ] = entry
    _bucket_insert( entry )
    local ok, save_err = _save_to_disk( )
    if not ok then
        -- Roll back: rebuilding indices keeps state consistent.
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
                -- Re-insert on save failure to keep state consistent.
                table_insert( _entries, i, e )
                _bucket_insert( e )
                return false, "save failed: " .. tostring( err )
            end
            return true
        end
    end
    return false, "not_found"
end

-- Supported filter_spec keys. Extending the set is a Phase B/C
-- task; unknown keys today log a one-time warn so an operator
-- typo through the future HTTP API doesn't silently return "all
-- entries" (would read as "filter did nothing", concealing the bug).
local _FILTER_KEYS = { source = true, stealth = true }

local function list( filter_spec )
    local out = { }
    filter_spec = filter_spec or { }
    for k in pairs( filter_spec ) do
        if not _FILTER_KEYS[ k ] then
            if out_put then
                out_put( "blocklist: list() ignoring unknown filter key '" ..
                    tostring( k ) .. "'" )
            end
        end
    end
    for _, e in ipairs( _entries ) do
        local include = true
        if filter_spec.source and e.source ~= filter_spec.source then include = false end
        if filter_spec.stealth ~= nil and e.stealth ~= ( filter_spec.stealth and true or false ) then
            include = false
        end
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
                stealth    = e.stealth,
                reason     = e.reason,
                by_nick    = e.by_nick,
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

local function reload( )
    _entries = { }
    _next_id = 1
    _buckets_v4 = { }
    _buckets_v6 = { }
    _rollup = { }
    _rollup_size = 0
    _last_flush_time = 0

    local data, err = util_loadtable( _store_path )
    if not data then
        if err and not err:find( "No such file" ) then
            if out_error then out_error( "blocklist: load failed: " .. tostring( err ) ) end
        end
        return
    end
    if type( data ) ~= "table" then return end

    local now = socket_gettime( )
    for _, row in ipairs( data ) do
        -- Skip already-expired rows on load. Prevents unbounded
        -- accumulation across reload boundaries when Phase D/E/F
        -- auto-feeds push lots of short-TTL entries.
        local expired = row.expires_at and row.expires_at <= now
        local network_bytes = _hex_decode( row.network_b64 or "" )
        if ( not expired ) and network_bytes and ( ( row.family == 4 and #network_bytes == 4 ) or ( row.family == 6 and #network_bytes == 16 ) ) then
            local entry = {
                id           = tonumber( row.id ) or _next_id,
                cidr         = row.cidr,
                family       = row.family,
                network_bytes = network_bytes,
                prefix_len   = tonumber( row.prefix_len ) or ( row.family == 4 and 32 or 128 ),
                source       = row.source or "manual",
                stealth      = row.stealth and true or false,
                reason       = row.reason or "",
                by_nick      = row.by_nick or "",
                expires_at   = row.expires_at,
                created_at   = row.created_at,
                meta         = row.meta,
                _network_b64 = row.network_b64,
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

-- Re-read cfg keys into the module's local snapshot. Used both at
-- init() time and on cfg-reload so a `+reload` after editing
-- `blocklist_enabled = false` or `blocklist_stealth_default = true`
-- takes effect without a hub restart (the original reload-handler
-- only re-read the .tbl - cfg keys were stuck until restart).
local function _resnapshot_cfg( )
    local cfg_enabled = cfg_get "blocklist_enabled"
    _enabled = ( cfg_enabled == nil ) or ( cfg_enabled and true ) or false
    _store_path      = cfg_get( "blocklist_store_path" ) or _store_path
    _stealth_default = cfg_get( "blocklist_stealth_default" ) and true or false
    _log_window      = cfg_get( "blocklist_aggregated_log_window_sec" ) or _log_window
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

    -- Register on cfg-reload event so `+reload` re-reads the .tbl
    -- AND the cfg keys. The handler is a separate function (not
    -- `reload`) because reload() only touches the store; cfg-key
    -- changes need _resnapshot_cfg too.
    local cfg_mod = use "cfg"
    if type( cfg_mod.registerevent ) == "function" then
        cfg_mod.registerevent( "reload", _reload_on_cfg_reload )
    end
end

return {
    init               = init,
    check_ip           = check_ip,
    add                = add,
    remove             = remove,
    list               = list,
    count              = count,
    reload             = reload,
    _resolve_decision  = _resolve_decision,
    _priority          = _priority,           -- exposed for tests
    _hex_encode        = _hex_encode,
    _hex_decode        = _hex_decode,
}
