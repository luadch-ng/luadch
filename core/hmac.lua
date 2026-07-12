--[[

    core/hmac.lua - HMAC-SHA256 (RFC 2104 / FIPS 198-1) over core/sha256.lua.

    Crypto precursor for the etc_webhook inbound-webhook receiver: an
    external service signs each delivery with an HMAC of the raw request
    body - Discourse sends `X-Discourse-Event-Signature: sha256=<hex>` =
    HMAC-SHA256(secret, raw_body); GitHub does the same via
    `X-Hub-Signature-256`. A plugin must recompute that MAC to
    authenticate the request, but the plugin sandbox exposes no HMAC
    primitive and deliberately withholds raw sha256 (core/scripts.lua -
    the geoip_update ordering note spells out why). This module is the
    whitelisted surface: plugins get the MAC, not the underlying hash.

    RFC 2104 construction with SHA-256 (block size B = 64 bytes):

        K'   = sha256(K)  if len(K) > B  (pre-hash), else K
        K'   = K' zero-padded to B bytes
        HMAC = sha256( (K' XOR opad) .. sha256( (K' XOR ipad) .. msg ) )
        ipad = 0x36 repeated B times
        opad = 0x5c repeated B times

    Public surface:
        hmac.sha256(key, msg)        -> 64-char lowercase hex string
        hmac.sha256_bytes(key, msg)  -> 32-byte raw binary MAC
        hmac.BLOCK_SIZE = 64

    Self-test runs at module load against RFC 4231 test cases 1, 2 and 6
    (case 6 exercises the len(K) > B pre-hash branch). A regression in
    the pad / concat logic would forge or reject signatures silently, so
    assert at load - same fail-loud discipline as core/sha256.lua.

]]--

local use = use

local type    = use "type"
local string  = use "string"
local table   = use "table"
local error   = use "error"
local sha256  = use "sha256"

local string_byte  = string.byte
local string_char  = string.char
local string_rep   = string.rep
local table_concat = table.concat

local sha256_hash       = sha256.hash
local sha256_hash_bytes = sha256.hash_bytes

local BLOCK_SIZE = 64
local IPAD = 0x36
local OPAD = 0x5c

-- Normalise a key to exactly BLOCK_SIZE bytes per RFC 2104: keys longer
-- than the block are replaced by their SHA-256 digest (32 bytes), then
-- every key is zero-padded up to the block size.
local function normalize_key( key )
    if #key > BLOCK_SIZE then
        key = sha256_hash_bytes( key )
    end
    if #key < BLOCK_SIZE then
        key = key .. string_rep( "\0", BLOCK_SIZE - #key )
    end
    return key
end

-- XOR every byte of a BLOCK_SIZE-byte string with a constant pad byte
-- (Lua 5.4 native integer XOR, same operator core/sha256.lua uses).
local function xor_block( block, pad )
    local out = { }
    for i = 1, BLOCK_SIZE do
        out[ i ] = string_char( string_byte( block, i ) ~ pad )
    end
    return table_concat( out )
end

-- Build the outer-hash input: (K' XOR opad) .. sha256((K' XOR ipad) .. msg).
-- Both public entry points hash this and differ only in hex vs raw
-- output, so the shared work (and the input validation) lives here.
-- error level 3 so a bad argument points at the plugin call site, not
-- at this internal helper.
local function outer_input( key, msg )
    if type( key ) ~= "string" then
        error( "hmac: key must be a string, got " .. type( key ), 3 )
    end
    if type( msg ) ~= "string" then
        error( "hmac: msg must be a string, got " .. type( msg ), 3 )
    end
    local k = normalize_key( key )
    local inner = sha256_hash_bytes( xor_block( k, IPAD ) .. msg )
    return xor_block( k, OPAD ) .. inner
end

-- HMAC-SHA256 as a 64-char lowercase hex string. This is the wire form
-- Discourse / GitHub send after the `sha256=` prefix.
local function hmac_hex( key, msg )
    return sha256_hash( outer_input( key, msg ) )
end

-- HMAC-SHA256 as the 32-byte raw MAC (for callers that prefer a
-- constant-time compare over raw bytes).
local function hmac_bytes( key, msg )
    return sha256_hash_bytes( outer_input( key, msg ) )
end

-- // Self-test at module load //
--
-- RFC 4231 vectors (cross-checked against Python `hmac` at authoring
-- time - never trust memory for these). Case 6 uses a 131-byte key to
-- exercise the len(K) > B pre-hash branch. A load failure aborts boot
-- LOUD, which is what we want for a silent-signature-forgery-class bug.
do
    local function _check( what, got, want )
        if got ~= want then
            error( "hmac self-test FAILED: " .. what ..
                "\n  got:  " .. got ..
                "\n  want: " .. want, 2 )
        end
    end
    _check( "RFC 4231 case 1",
        hmac_hex( string_rep( "\11", 20 ), "Hi There" ),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" )
    _check( "RFC 4231 case 2",
        hmac_hex( "Jefe", "what do ya want for nothing?" ),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" )
    _check( "RFC 4231 case 6 (key > block size)",
        hmac_hex( string_rep( "\170", 131 ),
            "Test Using Larger Than Block-Size Key - Hash Key First" ),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" )
end

return {
    BLOCK_SIZE   = BLOCK_SIZE,
    sha256       = hmac_hex,
    sha256_bytes = hmac_bytes,
}
