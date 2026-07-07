--[[

    tests/unit/zlib_stream_test.lua

    C round-trip test for the zlib_stream.gunzip() binding (the GeoIP
    auto-update precursor - decodes MaxMind's .tar.gz). Exercises the real
    built C module, so it must run from the install tree with the bundled
    liblua on the loader path - Linux CI only, same as adclib_unescape_test
    (msys2's own `lua` segfaults loading a bundled C module built against
    our liblua: the two-liblua ABI clash noted in .github/workflows/smoke.yml).

    Run:
      cd build/install/luadch
      LD_LIBRARY_PATH=. lua5.4 ../../../tests/unit/zlib_stream_test.lua

]]--

local zlib_stream = require( "zlib_stream" )

local pass, fail = 0, 0
local function ok( what, cond )
    if cond then pass = pass + 1
    else fail = fail + 1; io.stderr:write( "FAIL: " .. what .. "\n" ) end
end

-- Fixture: gzip (mtime=0) of exactly this plaintext (1104 bytes, repetitive
-- so DEFLATE actually compresses -> 77 bytes). Regenerate with:
--   python -c "import gzip;open('x','wb').write(gzip.compress((b'GeoLite2 auto-update round-trip test payload. '*24),mtime=0))"
local PLAIN = ( "GeoLite2 auto-update round-trip test payload. " ):rep( 24 )
local GZ =
    "\31\139\8\0\0\0\0\0\2\255\115\79\205\247\201\44\73\53\82\72\44\45\201\215\45\45\72\73\44\73\85\40\202\47\205" ..
    "\75\209\45\41\202\44\80\40\73\45\46\81\40\72\172\204\201\79\76\209\83\112\31\85\61\170\122\84\245\168\106\156" ..
    "\170\1\147\95\3\240\80\4\0\0"

-- 1. the new function exists
ok( "gunzip is a function", type( zlib_stream.gunzip ) == "function" )

-- 2. whole-blob round trip
do
    local g = zlib_stream.gunzip( )
    local out = g:push( GZ )
    g:close( )
    ok( "whole: round-trips to the exact plaintext", out == PLAIN )
end

-- 3. chunked feed - the GeoIP use case pushes small input slices across
--    many :push calls; the decompressed output must reassemble exactly.
do
    local g = zlib_stream.gunzip( )
    local parts = { }
    for i = 1, #GZ, 4 do parts[ #parts + 1 ] = g:push( GZ:sub( i, i + 3 ) ) end
    g:close( )
    ok( "chunked: reassembles to the exact plaintext", table.concat( parts ) == PLAIN )
end

-- 4. a non-gzip body is rejected LOUDLY (Z_DATA_ERROR -> Lua error), not
--    silently mis-parsed - important because the input is an untrusted CDN
--    download that could be an HTML error page.
do
    local g = zlib_stream.gunzip( )
    local good = pcall( function( ) return g:push( "this is definitely not a gzip stream" ) end )
    g:close( )
    ok( "non-gzip input throws", good == false )
end

-- 5. the existing zlib-format inflate() still REJECTS a gzip stream -
--    confirms gunzip and inflate stay distinct (my change added a function,
--    it did not relax inflate()'s zlib-only wrapper).
do
    local i = zlib_stream.inflate( )
    local good = pcall( function( ) return i:push( GZ ) end )
    i:close( )
    ok( "inflate() still rejects a gzip stream (zlib-only, unchanged)", good == false )
end

-- 6. symmetric guard: gunzip() REJECTS a plain zlib-format stream. Proves
--    windowBits 15+16 (gzip-ONLY) was used, not 15+32 (auto-detect zlib OR
--    gzip, which WOULD accept this). ZLIB blob = zlib.compress("plain zlib
--    stream, not gzip"), header 78 9c.
do
    local ZLIB = "\120\156\43\200\73\204\204\83\168\202\201\76\82\40\46\41\74\77\204\213\81\200\203\47\81\72\175\202\44\0\0\141\160\10\9"
    local g = zlib_stream.gunzip( )
    local good = pcall( function( ) return g:push( ZLIB ) end )
    g:close( )
    ok( "gunzip() rejects a zlib-format stream (gzip-only, not auto-detect)", good == false )
end

-- 7. push after close throws (shared inflate machinery contract)
do
    local g = zlib_stream.gunzip( )
    g:close( )
    local good = pcall( function( ) return g:push( GZ ) end )
    ok( "push after close throws", good == false )
end

io.write( string.format( "\n%d passed, %d failed\n", pass, fail ) )
os.exit( fail == 0 and 0 or 1 )
