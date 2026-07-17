--[[

    http_filter.lua

        Shared filter / sort / paginate helper for HTTP API list
        endpoints (#264 of #82). Lets each endpoint declare a
        per-field allowlist + access functions and applies the
        ?nick= / ?level_min= / ?sort=-lastseen / ?limit= / ?offset=
        query semantics uniformly.

        Field types:
          string  - case-sensitive substring match
                    (`string.find(stored, qval, 1, true)`).
          integer - exact match (`?level=20`) AND optional `_min` /
                    `_max` range params (`?level_min=20&level_max=50`).
          boolean - `?key=true` or `?key=false` exact match.
          date    - `_after` / `_before` range params. Stored field
                    can be epoch integer OR a lexicographically-
                    sortable string (e.g. "YYYY-MM-DD / HH:MM:SS");
                    the field spec declares a `parse_query` function
                    that converts the query string to whatever shape
                    `get` returns, so comparison stays type-consistent.

        Sort:
          `?sort=field` ascending; `?sort=-field` descending. Single
          key only. Default sort comes from the spec's
          `default_sort_field` / `default_sort_descending`.

        Pagination:
          `?limit=` clamps to [1, max_limit] (default max 1000).
          `?offset=` clamps to >=0. Filter applies BEFORE pagination;
          `pagination.total` reflects the filtered count.

        Returns ( ok = true, rows, pagination ) on success
        or       ( ok = false, status, err_code, err_msg ) on bad input.

]]--

----------------------------------// DECLARATION //--

local type = use "type"
local ipairs = use "ipairs"
local pairs = use "pairs"
local tonumber = use "tonumber"
local tostring = use "tostring"

local table = use "table"
local string = use "string"
local math = use "math"

local table_sort   = table.sort
local table_concat = table.concat
local string_find  = string.find
local string_sub   = string.sub
local math_floor   = math.floor
local math_min     = math.min

local DEFAULT_LIMIT     = 200
local MAX_LIMIT_DEFAULT = 1000

----------------------------------// DEFINITION //--

-- Build a sorted list of allowed filter param names from a spec.
-- Used in 400 error messages to point operators at the right names.
local function _allowed_filter_names( spec )
    local out = { }
    for name in pairs( spec.string_fields  or { } ) do out[ #out + 1 ] = name end
    for name in pairs( spec.boolean_fields or { } ) do out[ #out + 1 ] = name end
    for name in pairs( spec.integer_fields or { } ) do
        out[ #out + 1 ] = name
        out[ #out + 1 ] = name .. "_min"
        out[ #out + 1 ] = name .. "_max"
    end
    for name in pairs( spec.date_fields or { } ) do
        out[ #out + 1 ] = name .. "_after"
        out[ #out + 1 ] = name .. "_before"
    end
    table_sort( out )
    return out
end

local function _allowed_sort_names( spec )
    local out = { }
    for name in pairs( spec.sortable_fields or { } ) do out[ #out + 1 ] = name end
    table_sort( out )
    return out
end

-- Whitelist check: a query key must be either a filter param recognised
-- by the spec, OR one of the reserved control names (sort, limit, offset,
-- and any spec-declared reserved_query_keys like the existing /v1/bans/history
-- "nick" param that predates this helper).
local function _is_recognised( spec, key, allowed_filter_set )
    if key == "sort" or key == "limit" or key == "offset" then
        return true
    end
    if spec.reserved_query_keys and spec.reserved_query_keys[ key ] then
        return true
    end
    return allowed_filter_set[ key ] == true
end

local apply = function( query, spec, rows )
    query = query or { }
    rows  = rows  or { }

    -- Build the filter-name set up front so unknown-key detection is O(1).
    local allowed_filter_set = { }
    for _, name in ipairs( _allowed_filter_names( spec ) ) do
        allowed_filter_set[ name ] = true
    end

    -- 1. Reject unknown query keys (400 E_BAD_INPUT).
    for k in pairs( query ) do
        if not _is_recognised( spec, k, allowed_filter_set ) then
            return false, 400, "E_BAD_INPUT",
                "unknown query param '" .. tostring( k ) ..
                "'; allowed filters: " ..
                table_concat( _allowed_filter_names( spec ), ", " ) ..
                "; allowed sort fields: " ..
                table_concat( _allowed_sort_names( spec ), ", " )
        end
    end

    -- 2. Resolve sort field + direction.
    local sort_field, sort_desc
    if query.sort and query.sort ~= "" then
        local s = query.sort
        if string_sub( s, 1, 1 ) == "-" then
            sort_field = string_sub( s, 2 )
            sort_desc  = true
        else
            sort_field = s
            sort_desc  = false
        end
        if not ( spec.sortable_fields and spec.sortable_fields[ sort_field ] ) then
            return false, 400, "E_BAD_INPUT",
                "unknown sort field '" .. tostring( sort_field ) ..
                "'; allowed: " ..
                table_concat( _allowed_sort_names( spec ), ", " )
        end
    else
        sort_field = spec.default_sort_field
        sort_desc  = spec.default_sort_descending or false
    end

    -- 3. Build a predicate per filter param. Pre-resolve query values
    --    so we don't reparse on every row.
    local filters = { }    -- array of fn(row) -> bool

    -- string fields
    for name, getter in pairs( spec.string_fields or { } ) do
        local qval = query[ name ]
        if qval ~= nil and qval ~= "" then
            filters[ #filters + 1 ] = function( row )
                local stored = getter( row )
                if type( stored ) ~= "string" then return false end
                return string_find( stored, qval, 1, true ) ~= nil
            end
        end
    end

    -- boolean fields
    for name, getter in pairs( spec.boolean_fields or { } ) do
        local qval = query[ name ]
        if qval == "true" or qval == "false" then
            local want = ( qval == "true" )
            filters[ #filters + 1 ] = function( row )
                local stored = getter( row )
                return ( stored and true or false ) == want
            end
        elseif qval ~= nil and qval ~= "" then
            return false, 400, "E_BAD_INPUT",
                "boolean param '" .. name .. "' must be 'true' or 'false' (got '" ..
                tostring( qval ) .. "')"
        end
    end

    -- integer fields: exact + _min/_max
    for name, getter in pairs( spec.integer_fields or { } ) do
        local q_exact = query[ name ]
        local q_min   = query[ name .. "_min" ]
        local q_max   = query[ name .. "_max" ]
        if q_exact ~= nil and q_exact ~= "" then
            local v = tonumber( q_exact )
            if not v then
                return false, 400, "E_BAD_INPUT",
                    "integer param '" .. name .. "' must be a number (got '" ..
                    tostring( q_exact ) .. "')"
            end
            filters[ #filters + 1 ] = function( row )
                local stored = getter( row )
                return tonumber( stored ) == v
            end
        end
        if q_min ~= nil and q_min ~= "" then
            local v = tonumber( q_min )
            if not v then
                return false, 400, "E_BAD_INPUT",
                    "integer param '" .. name .. "_min' must be a number (got '" ..
                    tostring( q_min ) .. "')"
            end
            filters[ #filters + 1 ] = function( row )
                local stored = tonumber( getter( row ) )
                return stored ~= nil and stored >= v
            end
        end
        if q_max ~= nil and q_max ~= "" then
            local v = tonumber( q_max )
            if not v then
                return false, 400, "E_BAD_INPUT",
                    "integer param '" .. name .. "_max' must be a number (got '" ..
                    tostring( q_max ) .. "')"
            end
            filters[ #filters + 1 ] = function( row )
                local stored = tonumber( getter( row ) )
                return stored ~= nil and stored <= v
            end
        end
    end

    -- date fields: _after / _before. Spec provides parse_query(qval) ->
    -- comparable value (same shape as get(row) returns).
    for name, fdef in pairs( spec.date_fields or { } ) do
        local getter = fdef.get
        local parse  = fdef.parse_query
        local q_after  = query[ name .. "_after" ]
        local q_before = query[ name .. "_before" ]
        if q_after ~= nil and q_after ~= "" then
            local parsed, perr = parse( q_after )
            if parsed == nil then
                return false, 400, "E_BAD_INPUT",
                    "date param '" .. name .. "_after' invalid: " ..
                    tostring( perr or q_after )
            end
            filters[ #filters + 1 ] = function( row )
                local stored = getter( row )
                if stored == nil then return false end
                return stored >= parsed
            end
        end
        if q_before ~= nil and q_before ~= "" then
            local parsed, perr = parse( q_before )
            if parsed == nil then
                return false, 400, "E_BAD_INPUT",
                    "date param '" .. name .. "_before' invalid: " ..
                    tostring( perr or q_before )
            end
            filters[ #filters + 1 ] = function( row )
                local stored = getter( row )
                if stored == nil then return false end
                return stored <= parsed
            end
        end
    end

    -- 4. Apply filters (AND across all). Always produce a fresh
    -- output array; the sort below mutates it in place, and a
    -- shared/cached `rows` from the caller must not be reordered
    -- as a side-effect of calling apply().
    local filtered = { }
    if #filters == 0 then
        for i, row in ipairs( rows ) do filtered[ i ] = row end
    else
        for _, row in ipairs( rows ) do
            local keep = true
            for _, predicate in ipairs( filters ) do
                if not predicate( row ) then
                    keep = false
                    break
                end
            end
            if keep then filtered[ #filtered + 1 ] = row end
        end
    end

    -- 5. Sort.
    if sort_field and spec.sortable_fields then
        local sort_getter = spec.sortable_fields[ sort_field ]
        if type( sort_getter ) == "function" then
            table_sort( filtered, function( a, b )
                local va, vb = sort_getter( a ), sort_getter( b )
                -- nil sorts last regardless of direction (stable
                -- "missing values at the end" behaviour)
                if va == nil and vb == nil then return false end
                if va == nil then return false end
                if vb == nil then return true  end
                if sort_desc then return va > vb end
                return va < vb
            end )
        end
    end

    -- 6. Paginate.
    local limit_default = spec.default_limit or DEFAULT_LIMIT
    local limit_max     = spec.max_limit     or MAX_LIMIT_DEFAULT
    local limit = tonumber( query.limit ) or limit_default
    local offset = tonumber( query.offset ) or 0
    if limit  < 1         then limit  = 1         end
    if limit  > limit_max then limit  = limit_max end
    if offset < 0         then offset = 0         end
    limit  = math_floor( limit )
    offset = math_floor( offset )

    local total = #filtered
    local page  = { }
    for i = offset + 1, math_min( offset + limit, total ) do
        page[ #page + 1 ] = filtered[ i ]
    end
    local next_offset
    if offset + limit < total then
        next_offset = offset + limit
    end

    return true, page, {
        total       = total,
        limit       = limit,
        offset      = offset,
        next_offset = next_offset,
    }
end

----------------------------------// PUBLIC INTERFACE //--

return {
    apply = apply,
}
