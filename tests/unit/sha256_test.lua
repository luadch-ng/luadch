--[[

    tests/unit/sha256_test.lua

    Unit tests for core/sha256.lua (#78 Precursor 0d). Verifies the
    pure-Lua FIPS 180-4 SHA-256 against canonical NIST test vectors
    (all cross-checked with `sha256sum` at test authoring time).

    Run: lua5.4 tests/unit/sha256_test.lua
    Exit 0 = all pass, 1 = a failure.

]]--

----------------------------------------------------------------------
-- `use` shim - sha256.lua needs only stdlib via use("X").
----------------------------------------------------------------------

local _real = {
    type     = type,
    string   = string,
    table    = table,
    io       = io,
    error    = error,
    tostring = tostring,
}

_G.use = function( name )
    local v = _real[ name ]
    if v == nil then
        error( "sha256_test shim missing dep: use \"" .. tostring( name ) .. "\"" )
    end
    return v
end

local sha = assert( loadfile( "core/sha256.lua" ) )( )

----------------------------------------------------------------------
-- Tiny test harness.
----------------------------------------------------------------------

local _passes, _fails = 0, 0

local function eq( what, got, expected )
    if got == expected then
        _passes = _passes + 1
    else
        _fails = _fails + 1
        io.stderr:write( string.format(
            "FAIL: %s\n  got:      %s\n  expected: %s\n",
            what, tostring( got ), tostring( expected )
        ) )
    end
end

----------------------------------------------------------------------
-- Module surface
----------------------------------------------------------------------

eq( "HASH_SIZE constant", sha.HASH_SIZE, 32 )
eq( "HEX_SIZE constant",  sha.HEX_SIZE,  64 )
eq( "hash is function",   type( sha.hash ),       "function" )
eq( "hash_bytes is function", type( sha.hash_bytes ),  "function" )
eq( "hash_file is function",  type( sha.hash_file ),   "function" )

----------------------------------------------------------------------
-- Canonical NIST vectors (each cross-checked with `sha256sum` at
-- test authoring time - never trust memory for these).
----------------------------------------------------------------------

eq( "empty string",
    sha.hash( "" ),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" )

eq( "abc",
    sha.hash( "abc" ),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" )

eq( "message digest",
    sha.hash( "message digest" ),
    "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650" )

eq( "alphabet",
    sha.hash( "abcdefghijklmnopqrstuvwxyz" ),
    "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73" )

eq( "alphanumeric (62 chars)",
    sha.hash( "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" ),
    "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0" )

eq( "55-byte (just-fits-one-block-boundary)",
    sha.hash( "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" ),
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" )

eq( "112-byte (two-block padding edge case)",
    sha.hash( "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" ),
    "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1" )

-- 1,000,000 byte test (NIST's "long string" vector). Stress-tests the
-- multi-block loop. Pure-Lua hash time on this is ~1-2 seconds; fine
-- for one test invocation, would be problematic for many.
eq( "1M-char 'a' (long-message stress)",
    sha.hash( string.rep( "a", 1000000 ) ),
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" )

----------------------------------------------------------------------
-- Padding boundary scan: lengths around the 56-byte threshold where
-- the message length field forces a second block.
----------------------------------------------------------------------

-- For L in 54..66 around the 56-byte one-vs-two-block boundary,
-- assert hash is a well-formed 64-char hex string. Functional shape
-- check; the canonical-vector tests above are the load-bearing ones.
for L = 54, 66 do
    local h = sha.hash( string.rep( "a", L ) )
    if type( h ) == "string" and #h == 64 and h:match( "^[0-9a-f]+$" ) then
        _passes = _passes + 1
    else
        _fails = _fails + 1
        io.stderr:write( string.format(
            "FAIL: boundary L=%d: hash shape wrong\n  got: %s\n",
            L, tostring( h )
        ) )
    end
end

----------------------------------------------------------------------
-- hash_bytes: returns 32 raw bytes
----------------------------------------------------------------------

local raw = sha.hash_bytes( "abc" )
eq( "hash_bytes length", #raw, 32 )

-- Round-trip: hex of hash_bytes == hash
local hex = {}
for i = 1, 32 do
    hex[ i ] = string.format( "%02x", string.byte( raw, i ) )
end
eq( "hash_bytes hex roundtrip",
    table.concat( hex ),
    sha.hash( "abc" ) )

----------------------------------------------------------------------
-- hash_file: reads + hashes; reports error on missing file
----------------------------------------------------------------------

-- Use the bundled ca-bundle.pem (known good hash) as a real-world
-- file test.
local h, err = sha.hash_file( "examples/certs/ca-bundle.pem" )
if h then
    eq( "hash_file ca-bundle.pem (known good)",
        h,
        "86a1f3366afac7c6f8ae9f3c779ac221129328c43f0ab2b8817eb2f362a5025c" )
else
    -- Test runs from a fresh checkout - if file missing, that's a
    -- different test (bundle absent), not a sha256 bug. Note the
    -- skip but don't fail.
    io.write( "skip: hash_file ca-bundle.pem - bundle missing in this tree\n" )
end

local nh, nerr = sha.hash_file( "tests/unit/this_file_does_not_exist.bin" )
eq( "hash_file missing returns nil",  nh, nil )
if type( nerr ) == "string" and nerr:find( "hash_file" ) then
    _passes = _passes + 1
else
    _fails = _fails + 1
    io.stderr:write( "FAIL: hash_file missing - err string shape\n  got: " ..
        tostring( nerr ) .. "\n" )
end

----------------------------------------------------------------------
-- Input validation
----------------------------------------------------------------------

local ok = pcall( sha.hash, nil )
eq( "hash(nil) errors", ok, false )

ok = pcall( sha.hash, 42 )
eq( "hash(number) errors", ok, false )

ok = pcall( sha.hash, { } )
eq( "hash(table) errors", ok, false )

----------------------------------------------------------------------
-- Output
----------------------------------------------------------------------

if _fails > 0 then
    io.stderr:write( string.format(
        "\nFAIL: %d/%d checks failed\n",
        _fails, _passes + _fails
    ) )
    os.exit( 1 )
end

print( string.format( "OK: %d checks passed", _passes ) )
