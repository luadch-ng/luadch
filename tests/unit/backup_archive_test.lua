--[[

    tests/unit/backup_archive_test.lua

    Pure-Lua unit tests for core/backup_archive.lua that need NO real
    crypto: the ustar writer/reader, the PBKDF2-HMAC-SHA256 KDF (against
    Python-verified known-answer vectors), the manifest serialiser, and the
    full pack()/unpack() plumbing driven through a FAKE identity "adclib"
    (seal = append 16-byte tag, open = strip it). The real AES-GCM
    round-trip, ciphertext-secrecy, tamper and wrong-passphrase behaviour
    live in backup_archive_crypto_test.lua (needs the built adclib C module,
    Linux CI leg only, per #318).

    core/backup_archive.lua depends on core/hmac.lua -> core/sha256.lua, so
    the `use` shim loads those (stdlib-only) first and hands them back.

    Run: lua5.4 tests/unit/backup_archive_test.lua
    Exit 0 = all pass, 1 = a failure.

]]--

----------------------------------------------------------------------
-- `use` shim + fake adclib (identity crypto so pack/unpack round-trips
-- without OpenSSL). random_bytes is deterministic; seal appends a fake
-- 16-byte tag, open strips it - mirrors the real ct||tag length shape.
----------------------------------------------------------------------

local _real = {
    type = type, error = error, pcall = pcall, tostring = tostring,
    tonumber = tonumber, load = load, pairs = pairs, ipairs = ipairs,
    string = string, table = table, io = io, debug = debug,
    adclib = {
        random_bytes = function( n ) return string.rep( "R", n ) end,
        aes_gcm_seal = function( _key, _nonce, pt ) return pt .. string.rep( "\0", 16 ) end,
        aes_gcm_open = function( _key, _nonce, ct ) return string.sub( ct, 1, #ct - 16 ) end,
    },
}
_G.use = function( name )
    local v = _real[ name ]
    if v == nil then error( "backup_archive_test shim missing dep: use \"" .. tostring( name ) .. "\"" ) end
    return v
end

local sha256 = assert( loadfile( "core/sha256.lua" ) )( )
_real.sha256 = sha256
local hmac = assert( loadfile( "core/hmac.lua" ) )( )
_real.hmac = hmac

local A = assert( loadfile( "core/backup_archive.lua" ) )( )

----------------------------------------------------------------------
-- Tiny harness
----------------------------------------------------------------------

local passes, fails = 0, 0
local function ok( label, cond )
    if cond then passes = passes + 1
    else fails = fails + 1; io.stderr:write( "FAIL: " .. label .. "\n" ) end
end
local function eq( label, got, want )
    if got == want then passes = passes + 1
    else
        fails = fails + 1
        io.stderr:write( string.format( "FAIL: %s\n  got:  %s\n  want: %s\n",
            label, tostring( got ), tostring( want ) ) )
    end
end
local function hexof( s )
    local t = { }
    for i = 1, #s do t[ i ] = string.format( "%02x", string.byte( s, i ) ) end
    return table.concat( t )
end

----------------------------------------------------------------------
-- Surface
----------------------------------------------------------------------

eq( "pack is function",   type( A.pack ),   "function" )
eq( "unpack is function", type( A.unpack ), "function" )
eq( "MAGIC is LDBK",      A.MAGIC,          "LDBK" )
eq( "VERSION is 1",       A.VERSION,        1 )

----------------------------------------------------------------------
-- PBKDF2-HMAC-SHA256 known-answer vectors (Python hashlib.pbkdf2_hmac).
----------------------------------------------------------------------

eq( "PBKDF2 c=1",
    hexof( A._pbkdf2( "password", "salt", 1, 32 ) ),
    "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b" )
eq( "PBKDF2 c=4096",
    hexof( A._pbkdf2( "password", "salt", 4096, 32 ) ),
    "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a" )
eq( "PBKDF2 long key/salt c=4096",
    hexof( A._pbkdf2( "passwordPASSWORDpassword",
        "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 32 ) ),
    "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1" )

----------------------------------------------------------------------
-- ustar writer/reader round-trip, incl. binary bodies with NUL bytes and
-- a body that is an exact multiple of 512 (padding edge).
----------------------------------------------------------------------

local tar = assert( A._build_tar( {
    { name = "cfg/user.tbl",            mode = 384, body = "a\0b\0c" },
    { name = "scripts/data/x.tbl",      mode = 420, body = string.rep( "Z", 512 ) },
    { name = "empty",                   mode = 420, body = "" },
} ) )
local ents = assert( A._parse_tar( tar ) )
eq( "tar: entry count",        #ents,           3 )
eq( "tar: name 1",             ents[ 1 ].name,  "cfg/user.tbl" )
eq( "tar: mode 1 preserved",   ents[ 1 ].mode,  384 )
eq( "tar: binary body 1",      ents[ 1 ].body,  "a\0b\0c" )
eq( "tar: 512-multiple body",  ents[ 2 ].body,  string.rep( "Z", 512 ) )
eq( "tar: empty body",         ents[ 3 ].body,  "" )

-- an all-zero stream parses to zero entries (two terminator blocks only)
eq( "tar: terminator-only -> 0 entries", #assert( A._parse_tar( string.rep( "\0", 1024 ) ) ), 0 )
-- garbage / truncated stream degrades to (nil, err), never a raise
ok( "tar: truncated stream -> nil", A._parse_tar( "not-a-tar-block-too-short" ) == nil )

----------------------------------------------------------------------
-- Manifest serialise/parse round-trip.
----------------------------------------------------------------------

local m_in = { hub_version = "v3.2.0-dev", created_at = 1700000000,
    include_master_key = true, master_key_path = "cfg/master.key",
    kinds = { ["__masterkey__"] = "masterkey", ["cfg/user.tbl"] = "tree" } }
local m_out = assert( A._manifest_parse( A._manifest_serialize( m_in ) ) )
eq( "manifest: string field",  m_out.hub_version,        "v3.2.0-dev" )
eq( "manifest: number field",  m_out.created_at,         1700000000 )
eq( "manifest: bool field",    m_out.include_master_key, true )
eq( "manifest: kinds map a",   m_out.kinds[ "__masterkey__" ], "masterkey" )
eq( "manifest: kinds map b",   m_out.kinds[ "cfg/user.tbl" ],  "tree" )

-- #485: a crafted manifest must not hang the offline restore. Pre-fix this
-- spins forever (the eval had no work bound); post-fix the instruction-count
-- hook aborts it and _manifest_parse returns (nil, err). If this test ever
-- HANGS instead of failing fast, the bound regressed.
do
    local bad = A._manifest_parse( "return (function() while true do end end)()" )
    ok( "manifest: infinite loop bounded -> nil", bad == nil )
    -- an over-budget bounded loop is refused too, not silently accepted
    local heavy = A._manifest_parse( "local x=0 for i=1,1e9 do x=x+1 end return {}" )
    ok( "manifest: over-budget loop -> nil", heavy == nil )
    -- oversized manifest rejected before load
    local huge = A._manifest_parse( "return {}" .. string.rep( " ", 70000 ) )
    ok( "manifest: oversized -> nil", huge == nil )
    -- a normal manifest still parses after all that
    ok( "manifest: normal still ok", type( A._manifest_parse( "return { a = 1 }" ) ) == "table" )
end

----------------------------------------------------------------------
-- Full pack()/unpack() plumbing (identity crypto, iters=1 for speed).
----------------------------------------------------------------------

local files = {
    { name = "cfg/cfg.tbl",   mode = 420, body = "settings=1",       kind = "tree" },
    { name = "cfg/user.tbl",  mode = 384, body = "user\0secret",     kind = "tree" },
    { name = "__masterkey__", mode = 384, body = string.rep( "K", 32 ), kind = "masterkey" },
}
local meta = { hub_version = "v3.2.0-dev", created_at = 1700000042,
    master_key_path = "/etc/luadch/master.key", include_master_key = true }

local blob = assert( A.pack( files, meta, "correct horse", { iters = 1 } ) )
eq( "pack: LDBK magic prefix", string.sub( blob, 1, 4 ), "LDBK" )

local res = assert( A.unpack( blob, "correct horse" ) )
eq( "unpack: format_version in meta", res.meta.format_version, 1 )
eq( "unpack: hub_version",            res.meta.hub_version,    "v3.2.0-dev" )
eq( "unpack: created_at",             res.meta.created_at,     1700000042 )
eq( "unpack: master_key_path",        res.meta.master_key_path, "/etc/luadch/master.key" )
eq( "unpack: include_master_key",     res.meta.include_master_key, true )
eq( "unpack: file count (MANIFEST hidden)", #res.files, 3 )

-- files come back in order, byte-identical, with mode + kind
local by = { }
for _, f in ipairs( res.files ) do by[ f.name ] = f end
eq( "unpack: cfg.tbl body",       by[ "cfg/cfg.tbl" ].body,   "settings=1" )
eq( "unpack: user.tbl body",      by[ "cfg/user.tbl" ].body,  "user\0secret" )
eq( "unpack: user.tbl mode 0600", by[ "cfg/user.tbl" ].mode,  384 )
eq( "unpack: masterkey body",     by[ "__masterkey__" ].body, string.rep( "K", 32 ) )
eq( "unpack: masterkey kind",     by[ "__masterkey__" ].kind, "masterkey" )
eq( "unpack: tree kind",          by[ "cfg/cfg.tbl" ].kind,   "tree" )
ok( "unpack: MANIFEST not surfaced as a file", by[ "MANIFEST" ] == nil )

----------------------------------------------------------------------
-- Error paths
----------------------------------------------------------------------

ok( "pack: empty passphrase rejected",  ( A.pack( files, meta, "" ) ) == nil )
ok( "pack: nil passphrase rejected",    ( A.pack( files, meta, nil ) ) == nil )
ok( "pack: reserved name MANIFEST rejected",
    ( A.pack( { { name = "MANIFEST", body = "x" } }, meta, "pw", { iters = 1 } ) ) == nil )
ok( "unpack: empty passphrase rejected", ( A.unpack( blob, "" ) ) == nil )
ok( "unpack: bad magic rejected",        ( A.unpack( "XXXX" .. string.rep( "\0", 60 ), "pw" ) ) == nil )
ok( "unpack: too-short blob rejected",   ( A.unpack( "LDBK", "pw" ) ) == nil )

-- bad format version byte
local badver = "LDBK" .. string.char( 9 ) .. string.sub( blob, 6 )
ok( "unpack: unsupported version rejected", ( A.unpack( badver, "correct horse" ) ) == nil )

-- iterations bounds (pack side)
ok( "pack: iters=0 rejected",     ( A.pack( files, meta, "pw", { iters = 0 } ) ) == nil )
ok( "pack: iters>MAX rejected",   ( A.pack( files, meta, "pw", { iters = 99999999 } ) ) == nil )
ok( "pack: non-string name rejected",
    ( A.pack( { { name = 42, body = "x" } }, meta, "pw", { iters = 1 } ) ) == nil )
ok( "pack: non-number mode rejected",
    ( A.pack( { { name = "a", body = "x", mode = "644" } }, meta, "pw", { iters = 1 } ) ) == nil )

-- iterations bounds (unpack side): a crafted header must DEGRADE to
-- (nil, err), never raise and never spin an unbounded KDF (Finding 2).
local iters0  = string.sub( blob, 1, 6 ) .. "\0\0\0\0"     .. string.sub( blob, 11 )
local itersXL = string.sub( blob, 1, 6 ) .. "\255\255\255\255" .. string.sub( blob, 11 )
local c0, r0 = pcall( A.unpack, iters0, "correct horse" )
ok( "unpack: iters=0 header -> nil, no raise", c0 and r0 == nil )
local cx, rx = pcall( A.unpack, itersXL, "correct horse" )
ok( "unpack: huge iters header -> nil, no raise (no KDF spin)", cx and rx == nil )

----------------------------------------------------------------------
-- checksum + sidecar helpers
----------------------------------------------------------------------

eq( "checksum length 64 hex", #A.checksum( "hello" ), 64 )
eq( "checksum == sha256(hello)", A.checksum( "hello" ),
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" )
eq( "sidecar_line format", A.sidecar_line( "deadbeef", "backup.ldbk" ),
    "deadbeef  backup.ldbk\n" )

----------------------------------------------------------------------
-- Output
----------------------------------------------------------------------

if fails > 0 then
    io.stderr:write( string.format( "\nFAIL: %d/%d checks failed\n", fails, passes + fails ) )
    os.exit( 1 )
end
print( string.format( "OK: %d checks passed", passes ) )
