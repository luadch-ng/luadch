--[[

    tests/unit/backup_archive_crypto_test.lua

    Real-AES-256-GCM tests for core/backup_archive.lua: a full pack()/
    unpack() round-trip that actually encrypts, proof the ciphertext hides
    the plaintext, wrong-passphrase rejection, and GCM tamper detection.

    Needs the built adclib shared object (OpenSSL) and the bundled liblua
    it links against, so - like adclib_unescape_test.lua / zlib_stream_test
    .lua - it must run from INSIDE the install tree, LINUX CI leg only
    (the msys2/Windows adclib segfaults via an ABI clash, #318):

      cd build/install/luadch
      LD_LIBRARY_PATH=. lua5.4 ../../../tests/unit/backup_archive_crypto_test.lua

    Exit 0 = all pass, 1 = a failure.

]]--

-- CWD-relative cpath - the install tree has lib/adclib/adclib.<so|dll>.
local filetype = ( os.getenv "COMSPEC" and os.getenv "WINDIR" and ".dll" ) or ".so"
package.cpath = "lib/?/?" .. filetype .. ";lib/?" .. filetype .. ";" .. package.cpath
local adclib = require( "adclib" )

local _real = {
    type = type, error = error, pcall = pcall, tostring = tostring,
    tonumber = tonumber, load = load, pairs = pairs, ipairs = ipairs,
    string = string, table = table, io = io, debug = debug,
    adclib = adclib,
}
_G.use = function( name )
    local v = _real[ name ]
    if v == nil then error( "crypto_test shim missing dep: use \"" .. tostring( name ) .. "\"" ) end
    return v
end

local sha256 = assert( loadfile( "core/sha256.lua" ) )( )
_real.sha256 = sha256
local hmac = assert( loadfile( "core/hmac.lua" ) )( )
_real.hmac = hmac
local A = assert( loadfile( "core/backup_archive.lua" ) )( )

local passes, fails = 0, 0
local function ok( label, cond )
    if cond then passes = passes + 1
    else fails = fails + 1; io.stderr:write( "FAIL: " .. label .. "\n" ) end
end
local function eq( label, got, want )
    if got == want then passes = passes + 1
    else
        fails = fails + 1
        io.stderr:write( string.format( "FAIL: %s\n  got:  %q\n  want: %q\n",
            label, tostring( got ), tostring( want ) ) )
    end
end

local PW = "correct horse battery staple"
local files = {
    { name = "cfg/cfg.tbl",   mode = 420, body = "hub_name = \"secretHub\"\0binary" , kind = "tree" },
    { name = "cfg/user.tbl",  mode = 384, body = string.rep( "u", 1000 ),              kind = "tree" },
    { name = "__masterkey__", mode = 384, body = string.rep( "\255", 32 ),             kind = "masterkey" },
}
local meta = { hub_version = "v3.2.0-dev", created_at = 1700000000,
    master_key_path = "/etc/luadch/master.key", include_master_key = true }

-- iters low so the test is fast; the KDF itself is vector-checked in the
-- pure test. This proves the AES-GCM path + framing end to end.
local blob = assert( A.pack( files, meta, PW, { iters = 2 } ) )
ok( "pack returned bytes", type( blob ) == "string" and #blob > 0 )

-- real encryption: the plaintext markers must NOT appear in the ciphertext
ok( "ciphertext hides 'secretHub'", blob:find( "secretHub", 1, true ) == nil )
ok( "ciphertext hides master.key bytes", blob:find( string.rep( "\255", 32 ), 1, true ) == nil )

-- round-trip fidelity
local res = assert( A.unpack( blob, PW ) )
eq( "meta hub_version", res.meta.hub_version, "v3.2.0-dev" )
eq( "meta master_key_path", res.meta.master_key_path, "/etc/luadch/master.key" )
eq( "file count", #res.files, 3 )
local by = { }
for _, f in ipairs( res.files ) do by[ f.name ] = f end
eq( "cfg.tbl body byte-identical",   by[ "cfg/cfg.tbl" ].body,   files[ 1 ].body )
eq( "user.tbl body byte-identical",  by[ "cfg/user.tbl" ].body,  files[ 2 ].body )
eq( "masterkey body byte-identical", by[ "__masterkey__" ].body, files[ 3 ].body )
eq( "masterkey kind",                by[ "__masterkey__" ].kind, "masterkey" )

-- wrong passphrase must fail (derives a different key -> GCM auth fails)
local r2, e2 = A.unpack( blob, "wrong passphrase" )
ok( "wrong passphrase -> nil", r2 == nil )
ok( "wrong passphrase -> error string", type( e2 ) == "string" )

-- tamper: flip the last ciphertext byte -> GCM tag rejects it
local last = string.byte( blob, #blob )
local tampered = string.sub( blob, 1, #blob - 1 ) .. string.char( last ~ 0xFF )
local r3 = A.unpack( tampered, PW )
ok( "tampered ciphertext -> nil (GCM auth)", r3 == nil )

-- tamper the outer salt (byte 12) -> wrong key -> fail closed
local s = string.byte( blob, 12 )
local tampsalt = string.sub( blob, 1, 11 ) .. string.char( s ~ 0xFF ) .. string.sub( blob, 13 )
local r4 = A.unpack( tampsalt, PW )
ok( "tampered salt -> nil (fail closed)", r4 == nil )

-- checksum sidecar is stable + hex
eq( "checksum length", #A.checksum( blob ), 64 )
eq( "checksum deterministic", A.checksum( blob ), A.checksum( blob ) )

if fails > 0 then
    io.stderr:write( string.format( "\nFAIL: %d/%d checks failed\n", fails, passes + fails ) )
    os.exit( 1 )
end
print( string.format( "OK: %d checks passed", passes ) )
