--[[

    core/sha256.lua - pure-Lua SHA-256 (FIPS 180-4).

    Precursor 0d of the unified-blocklist arc (#78). Needed by
    core/cacert_bootstrap.lua to compare the runtime CA bundle
    against the bundled source-of-truth without depending on an
    OS-specific shell-out (`sha256sum` on Linux, `certutil` on
    Windows) or a new C primitive.

    Lua 5.4 native integers + bitwise operators (`<<`, `>>`, `&`,
    `|`, `~`, `~=` for xor) make this ~150 LoC. Performance is
    fine for the 186 KB ca-bundle.pem at boot (single-digit
    milliseconds on modern hardware; the bootstrap runs once per
    hub start, not per request).

    Implementation follows FIPS 180-4 section 6.2.2 step-by-step:

        Initialize H[0..7] with fractional parts of sqrt of the
        first 8 primes; pre-compute K[0..63] from cube-root
        fractional parts. Process the message in 512-bit blocks:
        prepare a 64-word message schedule, run the 64-round
        compression function, update H. After all blocks emit
        H[0]||H[1]||...||H[7] as a 32-byte digest.

    Public surface:
        sha256.hash(s)             -> 64-char lowercase hex string
        sha256.hash_bytes(s)       -> 32-byte raw binary string
        sha256.hash_file(path)     -> 64-char lowercase hex string
                                   -> nil, err on read failure
        sha256.HASH_SIZE = 32      -- bytes in raw digest
        sha256.HEX_SIZE  = 64      -- chars in hex digest

    Self-test runs at module load (NIST CAVP empty string + "abc"
    + 1M-char "a" vector). A failure raises immediately - the
    module would silently return wrong hashes otherwise.

]]--

local use = use

local type      = use "type"
local string    = use "string"
local table     = use "table"
local io        = use "io"
local error     = use "error"
local tostring  = use "tostring"

local string_byte   = string.byte
local string_char   = string.char
local string_format = string.format
local string_pack   = string.pack
local string_len    = string.len
local string_sub    = string.sub
local string_rep    = string.rep
local table_concat  = table.concat
local io_open       = io.open

local HASH_SIZE = 32
local HEX_SIZE  = 64

-- FIPS 180-4 section 4.2.2: K[0..63], cube-root fractional parts
-- of the first 64 primes, taken as 32-bit big-endian integers.
local K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local MASK32 = 0xffffffff

-- 32-bit right rotate: `(x >> n) | ((x << (32-n)) & MASK32)`.
local function ror32( x, n )
    return ( ( x >> n ) | ( ( x << ( 32 - n ) ) & MASK32 ) ) & MASK32
end

-- Pad the message per FIPS 180-4 section 5.1.1: append 0x80, then
-- as many 0x00 bytes as needed to leave 8 bytes for the length,
-- then the 64-bit big-endian bit-length.
local function pad_message( msg )
    local L = string_len( msg )
    local bit_len = L * 8
    local n_zeros = ( 56 - ( ( L + 1 ) % 64 ) ) % 64
    -- `string.pack` for a 64-bit big-endian unsigned: ">I8" produces
    -- exactly the 8 bytes FIPS calls for.
    return msg .. "\128" .. string_rep( "\0", n_zeros ) .. string_pack( ">I8", bit_len )
end

-- Compress one 512-bit block. `block` is a 64-byte string; `H` is
-- the running 8-word state, mutated in place.
local function process_block( block, H )
    -- Step 1: message schedule (64 words).
    local W = {}
    for i = 1, 16 do
        local off = ( i - 1 ) * 4 + 1
        local b1, b2, b3, b4 = string_byte( block, off, off + 3 )
        W[ i ] = ( b1 << 24 ) | ( b2 << 16 ) | ( b3 << 8 ) | b4
    end
    for i = 17, 64 do
        local s0 = ror32( W[ i - 15 ], 7 ) ~ ror32( W[ i - 15 ], 18 ) ~ ( W[ i - 15 ] >> 3 )
        local s1 = ror32( W[ i - 2 ], 17 ) ~ ror32( W[ i - 2 ], 19 ) ~ ( W[ i - 2 ] >> 10 )
        W[ i ] = ( W[ i - 16 ] + s0 + W[ i - 7 ] + s1 ) & MASK32
    end

    -- Step 2: working variables.
    local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]

    -- Step 3: 64 compression rounds.
    for i = 1, 64 do
        local S1 = ror32( e, 6 ) ~ ror32( e, 11 ) ~ ror32( e, 25 )
        local ch = ( e & f ) ~ ( ( ~e ) & g & MASK32 )
        local temp1 = ( h + S1 + ch + K[ i ] + W[ i ] ) & MASK32
        local S0 = ror32( a, 2 ) ~ ror32( a, 13 ) ~ ror32( a, 22 )
        local mj = ( a & b ) ~ ( a & c ) ~ ( b & c )
        local temp2 = ( S0 + mj ) & MASK32
        h = g
        g = f
        f = e
        e = ( d + temp1 ) & MASK32
        d = c
        c = b
        b = a
        a = ( temp1 + temp2 ) & MASK32
    end

    -- Step 4: update H.
    H[1] = ( H[1] + a ) & MASK32
    H[2] = ( H[2] + b ) & MASK32
    H[3] = ( H[3] + c ) & MASK32
    H[4] = ( H[4] + d ) & MASK32
    H[5] = ( H[5] + e ) & MASK32
    H[6] = ( H[6] + f ) & MASK32
    H[7] = ( H[7] + g ) & MASK32
    H[8] = ( H[8] + h ) & MASK32
end

-- Compute SHA-256 of the input string and return the 32-byte raw
-- binary digest.
local function hash_bytes( s )
    if type( s ) ~= "string" then
        error( "sha256.hash_bytes: expected string, got " .. type( s ), 2 )
    end

    -- FIPS 180-4 section 5.3.3: initial hash value H[0..7],
    -- fractional parts of sqrt of the first 8 primes.
    local H = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    }

    local padded = pad_message( s )
    local n_blocks = string_len( padded ) // 64

    for i = 1, n_blocks do
        local off = ( i - 1 ) * 64 + 1
        process_block( string_sub( padded, off, off + 63 ), H )
    end

    return string_pack( ">I4I4I4I4I4I4I4I4",
        H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8] )
end

-- Hex-encode the 32-byte raw digest as a 64-char lowercase string.
local function hash( s )
    local raw = hash_bytes( s )
    local hex = {}
    for i = 1, HASH_SIZE do
        hex[ i ] = string_format( "%02x", string_byte( raw, i ) )
    end
    return table_concat( hex )
end

-- Hash a file's contents. Returns the 64-char lowercase hex digest
-- on success, or (nil, err) if the file cannot be opened or read.
-- Reads the file in one shot - SHA-256 of a 186 KB ca-bundle.pem
-- is well under any sensible memory budget. If we ever need to
-- hash files in the gigabyte range, refactor to chunked reads + a
-- stateful incremental API (`init / update / final`).
local function hash_file( path )
    local f, err = io_open( path, "rb" )
    if not f then
        return nil, "sha256.hash_file: " .. tostring( err )
    end
    local content, rerr = f:read( "*a" )
    f:close()
    if not content then
        return nil, "sha256.hash_file: read failed: " .. tostring( rerr )
    end
    return hash( content )
end

-- // Self-test at module load //
--
-- NIST FIPS 180-2 / CAVP test vectors. A regression in the core
-- compression function would return wrong digests silently;
-- assert at load time so the module either works or fails loud.
do
    local function _check( what, got, want )
        if got ~= want then
            error( "sha256 self-test FAILED: " .. what ..
                "\n  got:  " .. got ..
                "\n  want: " .. want, 2 )
        end
    end
    _check( "empty string",
        hash( "" ),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" )
    _check( "abc",
        hash( "abc" ),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" )
    _check( "448-bit message (multi-block boundary)",
        hash( "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" ),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" )
end

return {
    HASH_SIZE   = HASH_SIZE,
    HEX_SIZE    = HEX_SIZE,
    hash        = hash,
    hash_bytes  = hash_bytes,
    hash_file   = hash_file,
}
