--[[

    tests/unit/hmac_test.lua

    Unit tests for core/hmac.lua (HMAC-SHA256, RFC 2104). Verifies the
    pure-Lua construction against the canonical RFC 4231 test vectors
    (all cross-checked with Python's `hmac` module at authoring time -
    never trust memory for these), plus the len(K) > block-size pre-hash
    branch, the raw-vs-hex surface, and argument validation.

    core/hmac.lua depends on core/sha256.lua via use("sha256"), so the
    shim loads sha256 first (stdlib-only) and hands the loaded module
    back for hmac's use("sha256").

    Run: lua5.4 tests/unit/hmac_test.lua   (or C:\lua-5.4.8_Win64_bin\lua54.exe)
    Exit 0 = all pass, 1 = a failure.

]]--

----------------------------------------------------------------------
-- `use` shim. sha256.lua needs stdlib only; hmac.lua additionally
-- needs the loaded sha256 module, so we add it to the shim table
-- BEFORE loading hmac.
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
        error( "hmac_test shim missing dep: use \"" .. tostring( name ) .. "\"" )
    end
    return v
end

local sha256 = assert( loadfile( "core/sha256.lua" ) )( )
_real.sha256 = sha256

local hmac = assert( loadfile( "core/hmac.lua" ) )( )

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

local rep = string.rep

----------------------------------------------------------------------
-- Module surface
----------------------------------------------------------------------

eq( "BLOCK_SIZE constant",       hmac.BLOCK_SIZE, 64 )
eq( "sha256 is function",        type( hmac.sha256 ),       "function" )
eq( "sha256_bytes is function",  type( hmac.sha256_bytes ), "function" )

----------------------------------------------------------------------
-- RFC 4231 canonical vectors (hex form). Cross-checked with Python
-- `hmac.new(key, msg, hashlib.sha256).hexdigest()` at authoring time.
----------------------------------------------------------------------

eq( "RFC 4231 case 1 (20-byte 0x0b key, 'Hi There')",
    hmac.sha256( rep( "\11", 20 ), "Hi There" ),
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" )

eq( "RFC 4231 case 2 ('Jefe' key)",
    hmac.sha256( "Jefe", "what do ya want for nothing?" ),
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" )

eq( "RFC 4231 case 4 (25-byte 0x01..0x19 key, 0xcd x50)",
    hmac.sha256(
        "\1\2\3\4\5\6\7\8\9\10\11\12\13\14\15\16\17\18\19\20\21\22\23\24\25",
        rep( "\205", 50 ) ),
    "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b" )

eq( "RFC 4231 case 6 (131-byte key > block size, pre-hash path)",
    hmac.sha256( rep( "\170", 131 ),
        "Test Using Larger Than Block-Size Key - Hash Key First" ),
    "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" )

eq( "RFC 4231 case 7 (131-byte key, larger data)",
    hmac.sha256( rep( "\170", 131 ),
        "This is a test using a larger than block-size key and a larger " ..
        "than block-size data. The key needs to be hashed before being " ..
        "used by the HMAC algorithm." ),
    "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2" )

----------------------------------------------------------------------
-- Edge cases (also Python-verified): empty key/msg, short key, and the
-- exactly-block-size vs one-over-block-size boundary that switches the
-- pre-hash branch on.
----------------------------------------------------------------------

eq( "empty key + empty msg",
    hmac.sha256( "", "" ),
    "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad" )

eq( "short key 'key' + 'abc'",
    hmac.sha256( "key", "abc" ),
    "9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab" )

eq( "key exactly block size (64 bytes, no pre-hash)",
    hmac.sha256( rep( "\11", 64 ), "exactly-block-size-key" ),
    "326a25948f0b97527c970b881771a476f99e82e3b991c5deae629916acc25596" )

eq( "key one over block size (65 bytes, pre-hash path)",
    hmac.sha256( rep( "\11", 65 ), "one-over-block-size-key" ),
    "2cf312211353cb8fb96f2e64dcc80a2df1eed12eeedd7717fc8c2c80db42de0c" )

----------------------------------------------------------------------
-- Raw (sha256_bytes) surface: 32 bytes + hex round-trip == sha256()
----------------------------------------------------------------------

local raw = hmac.sha256_bytes( "key", "abc" )
eq( "sha256_bytes length", #raw, 32 )

local hex = { }
for i = 1, 32 do
    hex[ i ] = string.format( "%02x", string.byte( raw, i ) )
end
eq( "sha256_bytes hex round-trip == sha256()",
    table.concat( hex ),
    hmac.sha256( "key", "abc" ) )

----------------------------------------------------------------------
-- Determinism
----------------------------------------------------------------------

eq( "deterministic: same inputs -> same MAC",
    hmac.sha256( "s3cr3t", "payload" ),
    hmac.sha256( "s3cr3t", "payload" ) )

----------------------------------------------------------------------
-- A one-byte body change flips the MAC (tamper detection - the whole
-- point of using this for webhook signatures).
----------------------------------------------------------------------

if hmac.sha256( "s3cr3t", "payload" ) ~= hmac.sha256( "s3cr3t", "payloax" ) then
    _passes = _passes + 1
else
    _fails = _fails + 1
    io.stderr:write( "FAIL: MAC did not change on a 1-byte body edit\n" )
end

----------------------------------------------------------------------
-- Argument validation: non-string key / msg must error, not silently
-- coerce (a nil secret slipping through would authenticate anything).
----------------------------------------------------------------------

eq( "sha256(nil, msg) errors",     pcall( hmac.sha256, nil, "x" ),  false )
eq( "sha256(key, nil) errors",     pcall( hmac.sha256, "k", nil ),  false )
eq( "sha256(number, msg) errors",  pcall( hmac.sha256, 42, "x" ),   false )
eq( "sha256(key, table) errors",   pcall( hmac.sha256, "k", { } ),  false )
eq( "sha256_bytes(nil, msg) errors", pcall( hmac.sha256_bytes, nil, "x" ), false )

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
