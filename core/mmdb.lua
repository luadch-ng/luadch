--[[

    core/mmdb.lua - pure-Lua MaxMind DB (MMDB) binary reader.

    Phase D1 of the unified-blocklist arc (#78). Reads MaxMind's
    GeoLite2 / GeoIP2 `.mmdb` databases (Country + ASN) so the Phase
    D2 plugin (etc_geoip) can resolve an IP to its country / ASN and
    push CIDR entries into core/blocklist.lua.

    Pure-Lua on purpose: a C binding (lua-maxminddb / libmaxminddb)
    would re-open the adclib ABI-clash class we already audited, and
    the lookup cost (~microseconds, done at start/refresh not per
    packet) makes native code unnecessary. The MMDB binary format is
    well-documented and read-only, so a bounded pure-Lua reader is the
    right trade.

    Format reference: https://maxmind.github.io/MaxMind-DB/ . An MMDB
    file has three parts laid out front to back:

        [ binary search tree ] [ 16-byte 0x00 separator ] [ data
          section ] [ 14-byte marker ] [ metadata (data-format map) ]

    - Search tree: node_count nodes, each holding two `record_size`-bit
      records (left = next-bit-0, right = next-bit-1). A record value
      < node_count is a pointer to another node; == node_count means
      "no data" (miss); > node_count is an offset into the data
      section.
    - Data section: values are self-describing, tagged by a control
      byte (top 3 bits = type, low 5 bits = size). Maps / arrays
      nest; pointers dedup repeated strings.
    - Metadata: a data-format map at EOF, found by scanning back for
      the marker `\xab\xcd\xef` .. "MaxMind.com". Carries node_count,
      record_size (24 / 28 / 32), ip_version (4 / 6), database_type,
      build_epoch, ...

    Public surface:

        mmdb.open(path) -> reader | nil, err
            Reads the whole file into RAM (capped at MAX_FILE_SIZE),
            parses + validates the metadata, returns a reader. A
            corrupt / truncated / oversized file NEVER throws - it
            returns nil + a descriptive error (this runs on the hub
            boot / plugin-refresh path, so a bad operator drop must
            not crash the hub).

        reader:lookup(ip) -> record | nil | nil, err
            ip is a string ("1.2.3.4" or "2001:db8::1"). Returns the
            decoded data record (a nested Lua table) on a hit, plain
            nil on a clean miss (IP not in the tree), or nil + err on
            a decode error / bad argument. Looking up an IPv4 address
            in an IPv6 database follows the standard ::/96 embedding;
            looking up IPv6 in an IPv4-only database is an error.

        reader:close() -> true
            Marks the reader unusable and drops its buffer for GC.
            Advisory: open() already closed the OS file handle after
            reading. Call it on refresh before dropping the old
            reader.

        reader.metadata -> table
            The decoded metadata map (MMDB key names: database_type,
            ip_version, record_size, node_count, build_epoch, ...).

        mmdb.MAX_FILE_SIZE
            Hard cap on the file we will read into RAM (16 MiB). The
            Country DB is ~9 MB and ASN ~10 MB; a City DB (~60 MB) is
            deliberately refused rather than pressuring the hub's RAM.

    uint128 note: Lua 5.4 integers are 64-bit, so a 128-bit unsigned
    value (only ever seen in the MaxMind decoder-test DB, never in
    Country / ASN data) is returned as a lowercase hex string with no
    leading zeros ("0" for zero) to avoid a silent precision loss.
    uint64 values >= 2^63 wrap to a negative Lua integer for the same
    reason; Country / ASN numbers stay well under 2^32 so this never
    bites in practice.

]]--

local use = use

local type          = use "type"
local tostring      = use "tostring"
local error         = use "error"
local pcall         = use "pcall"
local string        = use "string"
local table         = use "table"
local io            = use "io"

local ipmatch       = use "ipmatch"
local ipmatch_parse_ip = ipmatch.parse_ip

local string_byte   = string.byte
local string_sub    = string.sub
local string_find   = string.find
local string_rep    = string.rep
local string_gsub   = string.gsub
local string_format = string.format
local string_unpack = string.unpack
local table_concat  = table.concat
local io_open       = io.open

----------------------------------------------------------------------
-- Constants
----------------------------------------------------------------------

local MAX_FILE_SIZE       = 16 * 1024 * 1024
local METADATA_MARKER     = "\xab\xcd\xef" .. "MaxMind.com"
local METADATA_MAX_SIZE   = 128 * 1024        -- metadata lives in the last 128 KiB
local DATA_SEPARATOR_SIZE = 16                 -- 16 zero bytes between tree + data
local MAX_DECODE_DEPTH    = 512                -- guards deep nesting (C-stack overflow)
-- Total decoded-node budget for one top-level decode (the metadata
-- map, or one data record). The depth guard alone does NOT bound work:
-- a wide-shallow structure - many pointers all re-decoding one shared
-- big array, or a single map/array whose size-escape claims millions
-- of entries - runs O(entries) at constant depth. Without a budget a
-- ~5 KB crafted file drives millions of decodes + table allocations
-- and freezes the single-threaded hub (pcall does not contain a hang /
-- OOM). 1e6 is ~1000x above any real Country / ASN record or metadata
-- map, so it never trips on a legitimate file.
local MAX_DECODE_OPS      = 1000000
local ZERO12              = string_rep( "\0", 12 )   -- v4-in-v6 ::/96 prefix

-- Data-section type tags (top 3 bits of the control byte). Extended
-- types (tag 0) read one more byte and add 7.
local T_POINTER = 1
local T_UTF8    = 2
local T_DOUBLE  = 3
local T_BYTES   = 4
local T_UINT16  = 5
local T_UINT32  = 6
local T_MAP     = 7
local T_INT32   = 8
local T_UINT64  = 9
local T_UINT128 = 10
local T_ARRAY   = 11
local T_CACHE   = 12
local T_END     = 13
local T_BOOL    = 14
local T_FLOAT   = 15

----------------------------------------------------------------------
-- Bounds-checked primitive reads. All offsets are 0-indexed into the
-- buffer; string.byte / string.sub are 1-indexed so we add 1. On an
-- out-of-range read we raise (caught by the pcall in open / lookup)
-- rather than let string.sub silently truncate.
----------------------------------------------------------------------

local function _need( data, offset, n )
    if offset < 0 or offset + n > #data then
        error( "mmdb: read of " .. n .. " byte(s) past buffer end at offset " .. offset )
    end
end

local function _read_uint( data, offset, size )    -- big-endian unsigned
    if size == 0 then return 0 end
    if size > 8 then error( "mmdb: unsigned int size " .. size .. " > 8" ) end
    _need( data, offset, size )
    return ( string_unpack( ">I" .. size, data, offset + 1 ) )
end

local function _read_int32( data, offset, size )   -- big-endian signed, zero-padded to 4
    if size == 0 then return 0 end
    if size > 4 then error( "mmdb: int32 size " .. size .. " > 4" ) end
    _need( data, offset, size )
    local raw = string_sub( data, offset + 1, offset + size )
    if size < 4 then raw = string_rep( "\0", 4 - size ) .. raw end
    return ( string_unpack( ">i4", raw ) )
end

local function _read_uint128_hex( data, offset, size )
    if size == 0 then return "0" end
    if size > 16 then error( "mmdb: uint128 size " .. size .. " > 16" ) end
    _need( data, offset, size )
    local parts = { }
    for i = 1, size do
        parts[ i ] = string_format( "%02x", string_byte( data, offset + i ) )
    end
    local s = ( string_gsub( table_concat( parts ), "^0+", "" ) )
    if s == "" then s = "0" end
    return s
end

----------------------------------------------------------------------
-- Recursive data-section decoder.
--
--   _decode(data, offset, pbase, depth) -> value, next_offset
--
-- `pbase` is the pointer base for this section: data-record pointers
-- resolve to pbase + value, metadata pointers to metadata_start +
-- value. `depth` guards pointer cycles / hostile nesting.
----------------------------------------------------------------------

local _decode    -- forward declaration (recurses on maps / arrays / pointers)

-- Cumulative decoded-node counter for the CURRENT top-level decode.
-- Reset to 0 by each top-level caller (metadata decode + record
-- resolve) before descending. Safe as module state because the hub is
-- single-threaded and _decode never yields, so two decodes cannot
-- interleave; a decode that errors out just leaves a stale value that
-- the next reset clears.
local _decode_ops = 0

_decode = function( data, offset, pbase, depth )
    _decode_ops = _decode_ops + 1
    if _decode_ops > MAX_DECODE_OPS then
        error( "mmdb: decode op budget exceeded (" .. MAX_DECODE_OPS ..
               ") - hostile / corrupt file?" )
    end
    if depth > MAX_DECODE_DEPTH then
        error( "mmdb: decode nesting/pointer depth exceeded " .. MAX_DECODE_DEPTH )
    end
    if offset < 0 or offset >= #data then
        error( "mmdb: control byte offset out of range: " .. offset )
    end

    local ctrl = string_byte( data, offset + 1 )
    offset = offset + 1
    local typ = ctrl >> 5

    -- Pointer: the low 5 bits are (2-bit size selector, 3-bit value
    -- high bits), not a length. Resolve the target, decode there, but
    -- advance only past the pointer's own bytes.
    if typ == T_POINTER then
        local size5 = ctrl & 0x1f
        local ss    = ( size5 >> 3 ) & 0x3
        local vvv   = size5 & 0x7
        local ptr
        if ss == 0 then
            _need( data, offset, 1 )
            ptr = ( vvv << 8 ) | string_byte( data, offset + 1 )
            offset = offset + 1
            ptr = ptr + pbase
        elseif ss == 1 then
            _need( data, offset, 2 )
            local b0, b1 = string_byte( data, offset + 1, offset + 2 )
            ptr = ( vvv << 16 ) | ( b0 << 8 ) | b1
            offset = offset + 2
            ptr = ptr + pbase + 2048
        elseif ss == 2 then
            _need( data, offset, 3 )
            local b0, b1, b2 = string_byte( data, offset + 1, offset + 3 )
            ptr = ( vvv << 24 ) | ( b0 << 16 ) | ( b1 << 8 ) | b2
            offset = offset + 3
            ptr = ptr + pbase + 526336
        else -- ss == 3
            _need( data, offset, 4 )
            local b0, b1, b2, b3 = string_byte( data, offset + 1, offset + 4 )
            ptr = ( b0 << 24 ) | ( b1 << 16 ) | ( b2 << 8 ) | b3
            offset = offset + 4
            ptr = ptr + pbase
        end
        local value = _decode( data, ptr, pbase, depth + 1 )
        return value, offset
    end

    -- Extended type: real type is in the next byte, + 7.
    if typ == 0 then
        _need( data, offset, 1 )
        typ = string_byte( data, offset + 1 ) + 7
        offset = offset + 1
    end

    -- Size: low 5 bits, with 29/30/31 escapes to 1/2/3 extra bytes.
    local size = ctrl & 0x1f
    if size >= 29 then
        if size == 29 then
            _need( data, offset, 1 )
            size = 29 + string_byte( data, offset + 1 )
            offset = offset + 1
        elseif size == 30 then
            _need( data, offset, 2 )
            local b0, b1 = string_byte( data, offset + 1, offset + 2 )
            size = 285 + ( b0 << 8 ) + b1
            offset = offset + 2
        else -- 31
            _need( data, offset, 3 )
            local b0, b1, b2 = string_byte( data, offset + 1, offset + 3 )
            size = 65821 + ( b0 << 16 ) + ( b1 << 8 ) + b2
            offset = offset + 3
        end
    end

    if typ == T_MAP then
        local m = { }
        for _ = 1, size do
            local key, val
            key, offset = _decode( data, offset, pbase, depth + 1 )
            val, offset = _decode( data, offset, pbase, depth + 1 )
            m[ key ] = val
        end
        return m, offset
    elseif typ == T_ARRAY then
        local a = { }
        for i = 1, size do
            a[ i ], offset = _decode( data, offset, pbase, depth + 1 )
        end
        return a, offset
    elseif typ == T_UTF8 then
        _need( data, offset, size )
        return string_sub( data, offset + 1, offset + size ), offset + size
    elseif typ == T_UINT16 or typ == T_UINT32 or typ == T_UINT64 then
        return _read_uint( data, offset, size ), offset + size
    elseif typ == T_INT32 then
        return _read_int32( data, offset, size ), offset + size
    elseif typ == T_BOOL then
        -- No payload bytes: the size field IS the value (0 / 1).
        return ( size ~= 0 ), offset
    elseif typ == T_DOUBLE then
        -- Size MUST be 8: string.unpack reads a fixed 8 bytes, so a
        -- forged size would desync the decode stream (offset advances
        -- by `size`, not by 8) and shift every following field.
        if size ~= 8 then error( "mmdb: double with size " .. size .. " (expected 8)" ) end
        _need( data, offset, size )
        return ( string_unpack( ">d", data, offset + 1 ) ), offset + size
    elseif typ == T_FLOAT then
        if size ~= 4 then error( "mmdb: float with size " .. size .. " (expected 4)" ) end
        _need( data, offset, size )
        return ( string_unpack( ">f", data, offset + 1 ) ), offset + size
    elseif typ == T_BYTES then
        _need( data, offset, size )
        return string_sub( data, offset + 1, offset + size ), offset + size
    elseif typ == T_UINT128 then
        return _read_uint128_hex( data, offset, size ), offset + size
    elseif typ == T_CACHE then
        error( "mmdb: unexpected data-cache container in record stream" )
    elseif typ == T_END then
        error( "mmdb: unexpected end marker in record stream" )
    else
        error( "mmdb: unknown data type " .. tostring( typ ) )
    end
end

----------------------------------------------------------------------
-- Metadata: scan the last 128 KiB for the LAST marker occurrence, then
-- decode the map that follows (pointer base = metadata start).
----------------------------------------------------------------------

local function _find_metadata_start( data )
    local from = #data - METADATA_MAX_SIZE
    if from < 1 then from = 1 end
    local last, pos = nil, from
    while true do
        local s = string_find( data, METADATA_MARKER, pos, true )
        if not s then break end
        last = s
        pos = s + 1
    end
    if not last then return nil end
    return last + #METADATA_MARKER - 1    -- 0-indexed offset of first metadata byte
end

----------------------------------------------------------------------
-- Reader construction. Runs under pcall from open(); any error here
-- becomes a clean (nil, err) to the caller.
----------------------------------------------------------------------

local function _build_reader( data )
    local meta_start = _find_metadata_start( data )
    if not meta_start then
        error( "no MaxMind metadata marker found (not an MMDB file?)" )
    end

    _decode_ops = 0
    local metadata = _decode( data, meta_start, meta_start, 0 )
    if type( metadata ) ~= "table" then
        error( "metadata is not a map" )
    end

    local node_count  = metadata.node_count
    local record_size = metadata.record_size
    local ip_version  = metadata.ip_version
    if type( node_count ) ~= "number" or node_count < 0 or node_count ~= ( node_count // 1 ) then
        error( "metadata node_count invalid: " .. tostring( node_count ) )
    end
    -- Upper-bound node_count by the file size BEFORE multiplying. A
    -- node is at least 6 bytes, so a valid node_count is <= #data / 6;
    -- rejecting node_count > #data both catches an absurd value and
    -- prevents node_count * node_size from overflowing 64-bit (which
    -- would wrap search_tree_size negative and slip past the
    -- truncation check below, yielding a broken reader).
    if node_count > #data then
        error( "metadata node_count (" .. node_count ..
               ") exceeds file size (" .. #data .. ")" )
    end
    if record_size ~= 24 and record_size ~= 28 and record_size ~= 32 then
        error( "unsupported record_size: " .. tostring( record_size ) )
    end
    if ip_version ~= 4 and ip_version ~= 6 then
        error( "unsupported ip_version: " .. tostring( ip_version ) )
    end

    local node_size         = record_size * 2 // 8       -- 6 / 7 / 8 bytes per node
    local search_tree_size  = node_count * node_size
    local data_section_start = search_tree_size + DATA_SEPARATOR_SIZE
    if data_section_start > #data then
        error( "truncated file: search tree + separator (" .. data_section_start ..
               ") exceeds file size (" .. #data .. ")" )
    end

    -- Read one record (left index 0, right index 1) of a tree node.
    -- Node offsets are bounded by node_count * node_size <=
    -- search_tree_size <= #data, so reads are in-bounds by
    -- construction as long as callers only pass node_number <
    -- node_count (the traversal loop guarantees this).
    local read_node
    if record_size == 28 then
        read_node = function( node_number, index )
            local base = node_number * node_size
            if index == 0 then
                local b0  = string_byte( data, base + 1 )
                local b1  = string_byte( data, base + 2 )
                local b2  = string_byte( data, base + 3 )
                local mid = string_byte( data, base + 4 )
                return ( ( mid & 0xf0 ) << 20 ) | ( b0 << 16 ) | ( b1 << 8 ) | b2
            else
                local mid = string_byte( data, base + 4 )
                local b0  = string_byte( data, base + 5 )
                local b1  = string_byte( data, base + 6 )
                local b2  = string_byte( data, base + 7 )
                return ( ( mid & 0x0f ) << 24 ) | ( b0 << 16 ) | ( b1 << 8 ) | b2
            end
        end
    elseif record_size == 24 then
        read_node = function( node_number, index )
            local o = node_number * node_size + index * 3
            return ( string_byte( data, o + 1 ) << 16 )
                 | ( string_byte( data, o + 2 ) << 8 )
                 |   string_byte( data, o + 3 )
        end
    else -- 32
        read_node = function( node_number, index )
            local o = node_number * node_size + index * 4
            return ( string_byte( data, o + 1 ) << 24 )
                 | ( string_byte( data, o + 2 ) << 16 )
                 | ( string_byte( data, o + 3 ) << 8 )
                 |   string_byte( data, o + 4 )
        end
    end

    -- Resolve the terminal record value reached by a traversal.
    local function resolve( node )
        if node <= node_count then
            -- == node_count: empty record (clean miss).
            -- <  node_count: ran out of address bits inside the tree
            --                without reaching a leaf -> no data.
            return nil
        end
        local data_offset = node - node_count + search_tree_size
        _decode_ops = 0
        return ( _decode( data, data_offset, data_section_start, 0 ) )
    end

    -- Walk the tree bit by bit (MSB first) over the raw address bytes.
    local function lookup_bytes( addr_bytes )
        local bit_count = #addr_bytes * 8
        local node = 0
        for i = 0, bit_count - 1 do
            if node >= node_count then break end
            local octet = string_byte( addr_bytes, ( i >> 3 ) + 1 )
            local bit   = ( octet >> ( 7 - ( i & 7 ) ) ) & 1
            node = read_node( node, bit )
        end
        return resolve( node )
    end

    local reader = { metadata = metadata }

    reader.lookup = function( self, ip )
        -- Accept both reader:lookup(ip) (canonical) and
        -- reader.lookup(ip) (dot call: self holds the ip string).
        if ip == nil and type( self ) == "string" then
            ip = self
        end
        if reader._closed then return nil, "mmdb: reader is closed" end
        if type( ip ) ~= "string" then
            return nil, "mmdb.lookup: ip must be a string"
        end
        local fam, bytes_or_err = ipmatch_parse_ip( ip )
        if not fam then
            return nil, "mmdb.lookup: " .. tostring( bytes_or_err )
        end
        local bytes = bytes_or_err
        if ip_version == 4 then
            if fam ~= 4 then
                return nil, "mmdb.lookup: cannot look up IPv6 in an IPv4 database"
            end
        elseif fam == 4 then
            -- v4-in-v6 tree: MaxMind embeds IPv4 at ::/96, so a
            -- 12-zero-byte prefix + the 4 v4 bytes traversed as a full
            -- 128-bit address reaches the same subtree as following 96
            -- zero-bit records from the root.
            bytes = ZERO12 .. bytes
        end
        local ok, result = pcall( lookup_bytes, bytes )
        if not ok then
            return nil, "mmdb.lookup: decode error: " .. tostring( result )
        end
        return result    -- table on hit, nil on clean miss
    end

    reader.close = function( )
        reader._closed = true
        return true
    end

    return reader
end

----------------------------------------------------------------------
-- Public: open
----------------------------------------------------------------------

local function open( path )
    if type( path ) ~= "string" or path == "" then
        return nil, "mmdb.open: path must be a non-empty string"
    end
    local f, oerr = io_open( path, "rb" )
    if not f then
        return nil, "mmdb.open: cannot open '" .. path .. "': " .. tostring( oerr )
    end
    local size = f:seek( "end" )
    if not size then
        f:close()
        return nil, "mmdb.open: cannot determine size of '" .. path .. "'"
    end
    if size == 0 then
        f:close()
        return nil, "mmdb.open: empty file '" .. path .. "'"
    end
    if size > MAX_FILE_SIZE then
        f:close()
        return nil, "mmdb.open: file too large (" .. size .. " > " .. MAX_FILE_SIZE .. " bytes)"
    end
    f:seek( "set", 0 )
    local data = f:read( "a" )
    f:close()
    if not data or #data ~= size then
        return nil, "mmdb.open: short read on '" .. path .. "'"
    end

    -- Parse under pcall: a corrupt / hostile file must degrade to a
    -- clean error return, never a thrown boot / refresh failure.
    local ok, reader_or_err = pcall( _build_reader, data )
    if not ok then
        return nil, "mmdb.open: " .. tostring( reader_or_err )
    end
    return reader_or_err
end

----------------------------------------------------------------------

return {
    open          = open,
    MAX_FILE_SIZE = MAX_FILE_SIZE,
}
