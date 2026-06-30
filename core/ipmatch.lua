--[[

    core/ipmatch.lua - IPv4/IPv6/CIDR parse + prefix-match.

    Phase A of the unified-blocklist arc (#78). Pure-Lua because
    the hot path is TCP accept (already kHz-bounded by ratelimit),
    not per-packet, so the overhead is negligible. Adding a C
    primitive would re-open the adclib ABI class we already audited.

    Wire format: parsed IPs are returned as raw byte strings, NOT
    integers. IPv4 = 4 bytes, IPv6 = 16 bytes. Big-endian (network
    byte order). The radix bucket in core/blocklist.lua keys on the
    first byte (v4) or first two bytes (v6); a `string.byte` call on
    the raw bytes is O(1) regardless of family.

    Public surface:

        ipmatch.parse_ip(s) -> family, bytes | nil, err
            family: integer 4 or 6
            bytes:  raw 4-byte or 16-byte string
            err:    descriptive string on parse failure

        ipmatch.parse_cidr(s) -> family, network_bytes, prefix_len | nil, err
            Accepts "1.2.3.0/24", "1.2.3.4", "2001:db8::/32", "::1".
            A single IP (no /N) maps to family-max prefix
            (/32 for v4, /128 for v6). Rejects host-bits-set CIDRs
            ("1.2.3.4/24") with a clear error so the operator
            cleans up rather than getting a silently-canonicalised
            block.

        ipmatch.match(ip_bytes, network_bytes, prefix_len) -> bool
            Both byte strings MUST be the same family (length).
            prefix_len in [0..32] for v4, [0..128] for v6.

        ipmatch.family(s) -> 4 | 6 | nil
            Quick "is this a valid IPv4 / IPv6 / neither?" check.
            Returns nil on parse failure (use parse_ip for err).

        ipmatch.normalize(s) -> string | nil, err
            Canonical form: IPv4 = dotted-quad no leading zeros;
            IPv6 = lowercase hex, longest-zero-run compressed to
            `::`, no zero-padded fields. Stable round-trip.

    IPv4-mapped IPv6 quirk: `::ffff:1.2.3.4` parses as IPv6 (16
    bytes) by default. The caller decides whether to treat the
    mapped form as identical to its v4 source (it isn't on the
    wire). core/blocklist.lua keeps them separate to avoid
    surprising operators; documented in docs/BLOCKLIST.md when it
    lands.

]]--

local use = use

local type      = use "type"
local string    = use "string"
local table     = use "table"
local tonumber  = use "tonumber"
local tostring  = use "tostring"

local string_byte    = string.byte
local string_char    = string.char
local string_format  = string.format
local string_match   = string.match
local string_gmatch  = string.gmatch
local string_find    = string.find
local string_sub     = string.sub
local string_lower   = string.lower
local string_rep     = string.rep
local table_concat   = table.concat
local table_insert   = table.insert

----------------------------------------------------------------------
-- IPv4 parse
----------------------------------------------------------------------

local function _parse_ipv4( s )
    local a, b, c, d = string_match( s, "^(%d+)%.(%d+)%.(%d+)%.(%d+)$" )
    if not a then return nil, "not a dotted-quad IPv4" end
    -- Reject leading zeros: "01.2.3.4" is ambiguous (octal vs
    -- decimal historically). RFC 6943 + every modern parser
    -- treats it as parse error.
    for _, oct in ipairs{ a, b, c, d } do
        if #oct > 1 and string_sub( oct, 1, 1 ) == "0" then
            return nil, "IPv4 octet has leading zero: '" .. oct .. "'"
        end
    end
    a, b, c, d = tonumber( a ), tonumber( b ), tonumber( c ), tonumber( d )
    if a > 255 or b > 255 or c > 255 or d > 255 then
        return nil, "IPv4 octet > 255"
    end
    return string_char( a, b, c, d )
end

----------------------------------------------------------------------
-- IPv6 parse
--
-- Handles:
--   - full 8-group form         "2001:db8:0:0:0:0:0:1"
--   - zero-compressed form      "2001:db8::1"   "::1"   "::"
--   - v4-mapped suffix          "::ffff:192.0.2.1"
----------------------------------------------------------------------

local function _hex16_to_bytes( h )
    local n = tonumber( h, 16 )
    if not n or n > 0xffff then return nil end
    return string_char( ( n >> 8 ) & 0xff, n & 0xff )
end

local function _parse_ipv6( s )
    if string_find( s, "%s" ) then return nil, "IPv6 contains whitespace" end

    -- Check for trailing v4-mapped suffix.
    local v4suffix
    local v4_dot_idx = string_find( s, "%." )
    if v4_dot_idx then
        -- Find the last colon separating the v6 prefix from the v4
        -- suffix.
        local last_colon = nil
        for i = string_find( s, "%." ), 1, -1 do
            if string_sub( s, i, i ) == ":" then last_colon = i; break end
        end
        if not last_colon then return nil, "IPv6 with dot but no colon" end
        v4suffix = string_sub( s, last_colon + 1 )
        -- Drop the trailing colon too so the v6 prefix that remains
        -- does not look like "trailing colon malformed". For the
        -- pure-`::ffff:1.2.3.4` form this leaves `::ffff`; for the
        -- full `0:0:0:0:0:ffff:1.2.3.4` form it leaves
        -- `0:0:0:0:0:ffff`.
        s = string_sub( s, 1, last_colon - 1 )
    end

    -- Split on "::" - at most one occurrence.
    local left_part, right_part
    local dcolon = string_find( s, "::", 1, true )
    if dcolon then
        if string_find( s, "::", dcolon + 2, true ) then
            return nil, "IPv6 has multiple '::'"
        end
        left_part  = string_sub( s, 1, dcolon - 1 )
        right_part = string_sub( s, dcolon + 2 )
    else
        left_part = s
    end

    local function _split_groups( part )
        if part == "" then return { } end
        local out = { }
        for g in string_gmatch( part, "([^:]+)" ) do
            out[ #out + 1 ] = g
        end
        -- Reject leading or trailing single colon (e.g. ":1234")
        if string_sub( part, 1, 1 ) == ":" then return nil end
        if string_sub( part, -1 ) == ":" then return nil end
        return out
    end

    local left_groups  = _split_groups( left_part or "" )
    if not left_groups then return nil, "IPv6 malformed colon placement" end
    local right_groups
    if right_part then
        right_groups = _split_groups( right_part )
        if not right_groups then return nil, "IPv6 malformed colon placement" end
    end

    -- Validate each group as 1-4 hex digits.
    local function _check_groups( groups )
        for _, g in ipairs( groups ) do
            if #g < 1 or #g > 4 or not string_match( g, "^[0-9a-fA-F]+$" ) then
                return false
            end
        end
        return true
    end
    if not _check_groups( left_groups ) then return nil, "IPv6 bad hex group" end
    if right_groups and not _check_groups( right_groups ) then
        return nil, "IPv6 bad hex group"
    end

    -- v4 suffix consumes 2 groups (32 bits = 4 octets = 2 v6 groups).
    local v4groups_used = 0
    local v4bytes
    if v4suffix then
        local b, err = _parse_ipv4( v4suffix )
        if not b then return nil, "IPv6 v4-mapped: " .. tostring( err ) end
        v4bytes = b
        v4groups_used = 2
    end

    local total_groups = #left_groups + ( right_groups and #right_groups or 0 ) + v4groups_used
    if dcolon then
        if total_groups > 8 then return nil, "IPv6 too many groups for '::'" end
    else
        if total_groups ~= 8 then
            return nil, "IPv6 needs 8 groups (got " .. total_groups .. ")"
        end
    end

    -- Materialise all 16 bytes.
    local out = { }
    for _, g in ipairs( left_groups ) do
        local two = _hex16_to_bytes( g )
        if not two then return nil, "IPv6 group out of range" end
        out[ #out + 1 ] = two
    end
    if dcolon then
        local zeros_needed = 8 - total_groups
        for i = 1, zeros_needed do
            out[ #out + 1 ] = "\0\0"
        end
        if right_groups then
            for _, g in ipairs( right_groups ) do
                local two = _hex16_to_bytes( g )
                if not two then return nil, "IPv6 group out of range" end
                out[ #out + 1 ] = two
            end
        end
    end
    if v4bytes then
        out[ #out + 1 ] = v4bytes
    end

    local bytes = table_concat( out )
    if #bytes ~= 16 then
        return nil, "IPv6 internal length error (" .. #bytes .. " bytes)"
    end
    return bytes
end

----------------------------------------------------------------------
-- Public API
----------------------------------------------------------------------

local function parse_ip( s )
    if type( s ) ~= "string" or s == "" then
        return nil, "ipmatch.parse_ip: empty / non-string input"
    end
    -- Strip surrounding brackets for IPv6-literal URL form.
    if string_sub( s, 1, 1 ) == "[" and string_sub( s, -1 ) == "]" then
        s = string_sub( s, 2, -2 )
    end
    if string_find( s, ":", 1, true ) then
        local bytes, err = _parse_ipv6( s )
        if bytes then return 6, bytes end
        return nil, err or "IPv6 parse failed"
    end
    local bytes, err = _parse_ipv4( s )
    if bytes then return 4, bytes end
    return nil, err or "IPv4 parse failed"
end

local function family( s )
    local f = parse_ip( s )
    return f
end

local function parse_cidr( s )
    if type( s ) ~= "string" or s == "" then
        return nil, "ipmatch.parse_cidr: empty / non-string input"
    end
    local slash = string_find( s, "/", 1, true )
    local ip_part, prefix
    if slash then
        ip_part = string_sub( s, 1, slash - 1 )
        prefix = tonumber( string_sub( s, slash + 1 ) )
        -- Reject non-integer / negative / NaN. `tonumber("24.5")` returns
        -- the float 24.5 which would pass the simple `< 0` guard but
        -- then crash the `prefix >> 3` bitop downstream (Lua 5.4
        -- integer-bitop strict mode).
        if ( not prefix ) or prefix < 0 or prefix ~= ( prefix // 1 ) then
            return nil, "CIDR prefix not a non-negative integer"
        end
    else
        ip_part = s
    end

    -- parse_ip returns (fam, bytes) on success or (nil, errstring) on
    -- failure - the failure msg lives in the second return value, not
    -- a third. Propagate it via `bytes_or_err` so an operator typo
    -- through Phase B's `+blocklist add` gets a clear error.
    local fam, bytes_or_err = parse_ip( ip_part )
    if not fam then return nil, bytes_or_err end
    local bytes = bytes_or_err

    local max_prefix = ( fam == 4 ) and 32 or 128
    if not prefix then
        prefix = max_prefix
    end
    if prefix > max_prefix then
        return nil, "CIDR prefix " .. prefix .. " > max " .. max_prefix .. " for IPv" .. fam
    end

    -- Reject host-bits-set: "1.2.3.4/24" must be "1.2.3.0/24".
    -- Compute network bytes from input bytes and assert equality.
    local n = #bytes
    local full_bytes = prefix >> 3
    local tail_bits  = prefix & 7
    local mask_bytes = { }
    for i = 1, n do
        if i <= full_bytes then
            mask_bytes[ i ] = string_byte( bytes, i )
        elseif i == full_bytes + 1 and tail_bits > 0 then
            local m = ( 0xff << ( 8 - tail_bits ) ) & 0xff
            mask_bytes[ i ] = string_byte( bytes, i ) & m
        else
            mask_bytes[ i ] = 0
        end
    end
    local network_bytes = string_char( table.unpack( mask_bytes ) )
    if network_bytes ~= bytes then
        return nil, "CIDR has host bits set: " .. s ..
            " (use the network address instead)"
    end

    return fam, network_bytes, prefix
end

local function match( ip_bytes, network_bytes, prefix_len )
    if type( ip_bytes ) ~= "string" or type( network_bytes ) ~= "string" then
        return false
    end
    if #ip_bytes ~= #network_bytes then
        return false    -- different families never match
    end
    if prefix_len == 0 then return true end    -- 0.0.0.0/0 matches all
    local full_bytes = prefix_len >> 3
    local tail_bits  = prefix_len & 7
    if full_bytes > 0 then
        if string_sub( ip_bytes, 1, full_bytes ) ~=
           string_sub( network_bytes, 1, full_bytes ) then
            return false
        end
    end
    if tail_bits > 0 then
        local m = ( 0xff << ( 8 - tail_bits ) ) & 0xff
        local idx = full_bytes + 1
        if ( string_byte( ip_bytes, idx ) & m ) ~=
           ( string_byte( network_bytes, idx ) & m ) then
            return false
        end
    end
    return true
end

----------------------------------------------------------------------
-- Normalize: canonical string form for diagnostics + dedup
----------------------------------------------------------------------

local function _v4_normalize( bytes )
    return string_format( "%d.%d.%d.%d",
        string_byte( bytes, 1 ), string_byte( bytes, 2 ),
        string_byte( bytes, 3 ), string_byte( bytes, 4 ) )
end

local function _v6_normalize( bytes )
    -- RFC 5952 §5: an IPv4-mapped address (first 80 bits zero, then
    -- 0xffff, then 32 v4 bits) is rendered with dotted-quad tail
    -- "::ffff:1.2.3.4" rather than "::ffff:102:304". Detect the
    -- mapped prefix first.
    local is_v4_mapped = true
    for i = 1, 10 do
        if string_byte( bytes, i ) ~= 0 then is_v4_mapped = false; break end
    end
    if is_v4_mapped and string_byte( bytes, 11 ) == 0xff and string_byte( bytes, 12 ) == 0xff then
        return string_format( "::ffff:%d.%d.%d.%d",
            string_byte( bytes, 13 ), string_byte( bytes, 14 ),
            string_byte( bytes, 15 ), string_byte( bytes, 16 ) )
    end
    -- Decompose into 8 hex groups.
    local groups = { }
    for i = 1, 8 do
        local hi = string_byte( bytes, ( i - 1 ) * 2 + 1 )
        local lo = string_byte( bytes, ( i - 1 ) * 2 + 2 )
        groups[ i ] = string_format( "%x", hi * 256 + lo )
    end
    -- Find the longest run of consecutive "0" groups, length >= 2.
    local best_start, best_len = nil, 1
    local cur_start, cur_len = nil, 0
    for i = 1, 8 do
        if groups[ i ] == "0" then
            if cur_start == nil then cur_start = i end
            cur_len = cur_len + 1
            if cur_len > best_len then
                best_start = cur_start
                best_len = cur_len
            end
        else
            cur_start = nil
            cur_len = 0
        end
    end
    if best_start then
        local out = { }
        for i = 1, best_start - 1 do out[ #out + 1 ] = groups[ i ] end
        local left  = table_concat( out, ":" )
        out = { }
        for i = best_start + best_len, 8 do out[ #out + 1 ] = groups[ i ] end
        local right = table_concat( out, ":" )
        return left .. "::" .. right
    end
    return table_concat( groups, ":" )
end

local function normalize( s )
    local fam, bytes_or_err = parse_ip( s )
    if not fam then return nil, bytes_or_err end
    if fam == 4 then return _v4_normalize( bytes_or_err ) end
    return _v6_normalize( bytes_or_err )
end

-- Direct bytes-to-text format. Skips the parse/normalize round-trip
-- when the caller already holds canonical raw bytes (e.g.
-- core/blocklist.lua after parse_cidr returns network_bytes).
-- Returns the canonical text representation per RFC 5952; returns
-- nil if family / bytes are inconsistent.
local function format_bytes( fam, bytes )
    if type( bytes ) ~= "string" then return nil end
    if fam == 4 then
        if #bytes ~= 4 then return nil end
        return _v4_normalize( bytes )
    end
    if fam == 6 then
        if #bytes ~= 16 then return nil end
        return _v6_normalize( bytes )
    end
    return nil
end

----------------------------------------------------------------------

return {
    parse_ip     = parse_ip,
    parse_cidr   = parse_cidr,
    match        = match,
    family       = family,
    normalize    = normalize,
    format_bytes = format_bytes,
}
