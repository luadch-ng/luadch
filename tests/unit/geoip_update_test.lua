--[[

    tests/unit/geoip_update_test.lua

    Unit tests for core/geoip_update.lua (#78 Phase D3, in-hub MaxMind
    GeoLite2 auto-update). Exercises:
      - _parse_octal / _parse_sha256_body (defensive parsers)
      - _tar_extract_mmdb: extract the .mmdb member, no-member soft-fail,
        traversal-name reject, member-data-past-archive reject
      - _parse_octal: over-size-field reject (DoS guard)
      - update() orchestration end-to-end with mocked http_client /
        sha256 / zlib_stream / mmdb / server: unchanged-skip, updated
        happy path, sha256 mismatch, missing-credential guard,
        decompression-bomb cap, rename-failure fail-open

    Run: lua5.4 tests/unit/geoip_update_test.lua

]]--

----------------------------------------------------------------------
-- Mocks, driven by the control vars below. Loaded via a use-stub, as
-- the module runs under init.lua's restricted env (only `use`).
----------------------------------------------------------------------

local M = { }                              -- mock control surface
local _requests                            -- captured http_client.request calls
local _pending_co                          -- captured server.addtimer coroutine
local function reset( )
    _requests = { }
    _pending_co = nil
    M.hash = string.rep( "a", 64 )         -- sha256.hash_file result
    M.tar = nil                            -- bytes zlib_stream.gunzip yields
    M.mmdb_ok = true                       -- mmdb.open sanity result
    M.rename_ok = true                     -- os.rename result
    M.written = nil                        -- bytes written to the .tmp
    M.bomb = nil                           -- if set, gunzip:push returns it every call (over-cap)
    M.makedirs = { }                       -- captured makedir(dir) calls (dest-dir self-heal)
end
reset( )

local real = {
    type = type, tostring = tostring, tonumber = tonumber, pcall = pcall,
    pairs = pairs, ipairs = ipairs, error = error, string = string,
    table = table, math = math, coroutine = coroutine,
    io = {
        open = function( path, mode )
            if mode == "rb" then
                local served = false
                return { read = function( ) if served then return nil end served = true; return "GZIPBYTES" end,
                         close = function( ) end }
            end
            -- "wb": capture the extracted .mmdb bytes
            return { write = function( _, b ) M.written = ( M.written or "" ) .. b; return true end,
                     close = function( ) return true end }
        end,
    },
    os = { remove = function( ) return true end,
           rename = function( ) if M.rename_ok then return true end return nil, "rename failed" end },
    util = { },
    out = { error = function( ) end },
    basexx = { to_base64 = function( s ) return "B64(" .. s .. ")" end },
    http_client = {
        request = function( req )
            _requests[ #_requests + 1 ] = req
            return true
        end,
    },
    sha256 = { hash_file = function( ) return M.hash end },
    mmdb = { open = function( ) if M.mmdb_ok then return { close = function( ) end } end return nil, "not mmdb" end },
    server = { addtimer = function( co ) _pending_co = co end },
    zlib_stream = { gunzip = function( )
        local done = false
        return { push = function( )
                     if M.bomb then return M.bomb end   -- oversize output every push -> trips the cumulative cap
                     if done then return "" end done = true; return M.tar or "" end,
                 close = function( ) end }
    end },
    makedir = function( d ) M.makedirs[ #M.makedirs + 1 ] = d; return true end,
}
_G.use = function( name ) local v = real[ name ]; if v == nil then error( "use: missing " .. name ) end return v end
local gu = assert( loadfile( "core/geoip_update.lua" ) )( )

----------------------------------------------------------------------
-- harness + tar builder
----------------------------------------------------------------------

local pass, fail = 0, 0
local function ok( what, cond ) if cond then pass = pass + 1
    else fail = fail + 1; io.stderr:write( "FAIL: " .. what .. "\n" ) end end
local function eq( what, got, want ) ok( what .. " (got=" .. tostring( got ) .. ")", got == want ) end

local function tar_header( name, size, typeflag )
    local h = name .. string.rep( "\0", 100 - #name )
    h = h .. string.rep( "\0", 24 )                         -- mode/uid/gid @100..123
    h = h .. string.format( "%011o", size ) .. "\0"         -- size @124 (12)
    h = h .. string.rep( "\0", 20 )                         -- mtime@136 + cksum@148 (20)
    h = h .. typeflag                                       -- typeflag @156
    return h .. string.rep( "\0", 512 - #h )
end
local function tar_member( name, data, typeflag )
    local pad = ( math.ceil( #data / 512 ) * 512 ) - #data
    return tar_header( name, #data, typeflag or "0" ) .. data .. string.rep( "\0", pad )
end
local END = string.rep( "\0", 1024 )

----------------------------------------------------------------------
-- parsers
----------------------------------------------------------------------
eq( "octal 644 -> 420", gu._parse_octal( "644" ), 420 )
eq( "octal NUL/space trim", gu._parse_octal( "0000644\0  " ), 420 )
ok( "octal rejects non-octal", gu._parse_octal( "9z" ) == nil )
eq( "octal empty -> 0", gu._parse_octal( "" ), 0 )
eq( "sha256 first hex token", gu._parse_sha256_body( string.rep( "d", 64 ) .. "  file.tar.gz\n" ), string.rep( "d", 64 ) )
ok( "sha256 rejects short", gu._parse_sha256_body( "abc  file" ) == nil )
ok( "sha256 rejects non-string", gu._parse_sha256_body( 123 ) == nil )
ok( "octal rejects over-size (> MAX_MEMBER_SIZE)", ( gu._parse_octal( string.format( "%o", 128 * 1024 * 1024 ) ) ) == nil )

----------------------------------------------------------------------
-- tar extractor
----------------------------------------------------------------------
do
    local MMDB = "FAKE_MMDB_" .. string.rep( "x", 700 )
    local tar = tar_member( "GeoLite2-Country_20260707/COPYRIGHT.txt", "copyright" )
             .. tar_member( "GeoLite2-Country_20260707/GeoLite2-Country.mmdb", MMDB ) .. END
    eq( "tar: extracts the .mmdb member exactly", gu._tar_extract_mmdb( tar ), MMDB )

    ok( "tar: no .mmdb -> nil+err", ( gu._tar_extract_mmdb( tar_member( "d/x.txt", "y" ) .. END ) ) == nil )
    ok( "tar: rejects traversal name", gu._tar_extract_mmdb( tar_member( "../evil.mmdb", "x" ) .. END ) == nil )
    ok( "tar: rejects absolute name", gu._tar_extract_mmdb( tar_member( "/etc/x.mmdb", "x" ) .. END ) == nil )
    ok( "tar: non-string -> nil", gu._tar_extract_mmdb( nil ) == nil )
    -- a header claiming more data than the archive holds is rejected (no OOB read)
    ok( "tar: member data past archive -> nil",
        gu._tar_extract_mmdb( tar_header( "x/GeoLite2-Country.mmdb", 4096, "0" ) .. "short" ) == nil )
end

----------------------------------------------------------------------
-- update() orchestration
----------------------------------------------------------------------
local function drive_co( )   -- run the captured decompress coroutine to completion
    if not _pending_co then return end
    while coroutine.status( _pending_co ) ~= "dead" do
        local o, e = coroutine.resume( _pending_co )
        if not o then error( "coro error: " .. tostring( e ) ) end
    end
end

local BASE_OPTS = { edition = "GeoLite2-Country", dest = "cfg/geoip/GeoLite2-Country.mmdb",
                    account_id = "12345", license_key = "LICKEY" }
local function opts( extra )
    local o = { }; for k, v in pairs( BASE_OPTS ) do o[ k ] = v end
    if extra then for k, v in pairs( extra ) do o[ k ] = v end end
    return o
end

-- missing credentials -> failed, no request
do
    reset( )
    local res
    gu.update( { edition = "GeoLite2-Country", dest = "d.mmdb" }, function( r ) res = r end )
    eq( "no creds -> failed", res and res.status, "failed" )
    eq( "no creds -> no request", #_requests, 0 )
end

-- unchanged: sidecar hash == known_sha256 -> skip the big download
do
    reset( )
    local res
    gu.update( opts( { known_sha256 = string.rep( "b", 64 ) } ), function( r ) res = r end )
    eq( "unchanged: first request is the sha256 sidecar", #_requests, 1 )
    ok( "unchanged: sidecar url", _requests[ 1 ].url:find( "tar.gz.sha256", 1, true ) ~= nil )
    ok( "unchanged: Basic auth header set", _requests[ 1 ].headers.Authorization:find( "Basic", 1, true ) ~= nil )
    _requests[ 1 ].on_complete( { status = 200, body = string.rep( "b", 64 ) .. "  f.tar.gz" } )
    eq( "unchanged: status", res and res.status, "unchanged" )
    eq( "unchanged: NO download fired", #_requests, 1 )
end

-- updated: sidecar differs -> download -> verify -> decompress -> place
do
    reset( )
    local MMDB = "REAL_MMDB_BYTES_" .. string.rep( "z", 900 )
    M.tar = tar_member( "GeoLite2-Country_x/GeoLite2-Country.mmdb", MMDB ) .. END
    M.hash = string.rep( "c", 64 )
    local res
    gu.update( opts( { known_sha256 = string.rep( "b", 64 ) } ), function( r ) res = r end )
    -- sidecar returns a DIFFERENT hash -> triggers download
    _requests[ 1 ].on_complete( { status = 200, body = string.rep( "c", 64 ) .. "  f.tar.gz" } )
    eq( "updated: download fired", #_requests, 2 )
    ok( "updated: download url is tar.gz", _requests[ 2 ].url:find( "?suffix=tar.gz", 1, true ) ~= nil )
    eq( "updated: download_to_file set", type( _requests[ 2 ].download_to_file ), "string" )
    -- download completes -> hash_file matches sidecar -> decompress coroutine spawned
    _requests[ 2 ].on_complete( { status = 200, downloaded_path = "d", downloaded_bytes = 10 } )
    drive_co( )
    eq( "updated: status", res and res.status, "updated" )
    eq( "updated: sha256 returned", res and res.sha256, string.rep( "c", 64 ) )
    eq( "updated: extracted .mmdb written to tmp", M.written, MMDB )
    eq( "updated: bytes reported", res and res.bytes, #MMDB )
end

-- sha256 mismatch: downloaded file hash != sidecar -> failed, no decompress
do
    reset( )
    M.hash = string.rep( "9", 64 )        -- hash_file returns something else
    local res
    gu.update( opts( ), function( r ) res = r end )
    _requests[ 1 ].on_complete( { status = 200, body = string.rep( "c", 64 ) .. "  f.tar.gz" } )
    _requests[ 2 ].on_complete( { status = 200, downloaded_path = "d", downloaded_bytes = 10 } )
    eq( "mismatch -> failed", res and res.status, "failed" )
    ok( "mismatch: no decompress coroutine", _pending_co == nil )
    ok( "mismatch: err mentions sha256", res.err:find( "sha256", 1, true ) ~= nil )
end

-- extraction sanity: extracted file fails mmdb.open -> failed, not committed
do
    reset( )
    M.tar = tar_member( "x/GeoLite2-Country.mmdb", "corrupt" ) .. END
    M.hash = string.rep( "c", 64 )
    M.mmdb_ok = false                     -- the extracted file is not a valid mmdb
    local res
    gu.update( opts( ), function( r ) res = r end )
    _requests[ 1 ].on_complete( { status = 200, body = string.rep( "c", 64 ) .. "  f.tar.gz" } )
    _requests[ 2 ].on_complete( { status = 200, downloaded_path = "d", downloaded_bytes = 10 } )
    drive_co( )
    eq( "sanity-fail -> failed", res and res.status, "failed" )
    ok( "sanity-fail: err mentions mmdb", res.err:find( "mmdb", 1, true ) ~= nil )
end

-- decompression bomb: cumulative gunzip output over the cap -> failed.
-- FAIL-PRE-FIX: without the cumulative total-size guard this concatenates
-- the whole (all-zero) blob and _tar_extract_mmdb errors with "no .mmdb
-- member", NOT the cap message, so "err names the cap" fails on the
-- unpatched module - and a REAL valid-tar bomb would OOM the hub first.
do
    reset( )
    M.bomb = string.rep( "\0", 32 * 1024 * 1024 + 1 )   -- one push exceeds MAX_DECOMPRESSED (32 MiB)
    M.hash = string.rep( "c", 64 )
    local res
    gu.update( opts( ), function( r ) res = r end )
    _requests[ 1 ].on_complete( { status = 200, body = string.rep( "c", 64 ) .. "  f.tar.gz" } )
    _requests[ 2 ].on_complete( { status = 200, downloaded_path = "d", downloaded_bytes = 10 } )
    drive_co( )
    eq( "bomb -> failed", res and res.status, "failed" )
    ok( "bomb: err names the cap", res.err and res.err:find( "cap", 1, true ) ~= nil )
end

-- atomic-place failure (os.rename fails both ways) -> failed, last-good
-- untouched (the extracted file is never committed onto the live path)
do
    reset( )
    M.tar = tar_member( "x/GeoLite2-Country.mmdb", "REAL_" .. string.rep( "q", 700 ) ) .. END
    M.hash = string.rep( "c", 64 )
    M.rename_ok = false
    local res
    gu.update( opts( ), function( r ) res = r end )
    _requests[ 1 ].on_complete( { status = 200, body = string.rep( "c", 64 ) .. "  f.tar.gz" } )
    _requests[ 2 ].on_complete( { status = 200, downloaded_path = "d", downloaded_bytes = 10 } )
    drive_co( )
    eq( "rename-fail -> failed", res and res.status, "failed" )
    ok( "rename-fail: err mentions rename", res.err and res.err:find( "rename", 1, true ) ~= nil )
end

-- dest-dir self-heal: update() makedir's the destination's PARENT dir
-- (default cfg/geoip/, which nothing else creates) before any write.
-- FAIL-PRE-FIX: the unpatched update() never calls makedir, so the
-- "makedir('cfg/geoip')" assertion below fails on pre-fix code.
do
    reset( )
    gu.update( opts( { known_sha256 = string.rep( "b", 64 ) } ), function( ) end )
    local made = false
    for _, d in ipairs( M.makedirs ) do if d == "cfg/geoip" then made = true end end
    ok( "dest-dir: makedir('cfg/geoip') called at update() start", made )
    -- and it happens before the sidecar request is even queued (so the
    -- directory exists before any download/extract write)
    ok( "dest-dir: makedir ran (>=1 call)", #M.makedirs >= 1 )
end

-- absolute / bare dest: a dest with no directory component makes no
-- makedir call (nothing to create), and update() still proceeds.
do
    reset( )
    gu.update( opts( { dest = "flat.mmdb", known_sha256 = string.rep( "b", 64 ) } ), function( ) end )
    ok( "dest-dir: bare filename -> no makedir call", #M.makedirs == 0 )
    eq( "dest-dir: bare filename still queues the sidecar", #_requests, 1 )
end

io.write( string.format( "\n%d passed, %d failed\n", pass, fail ) )
os.exit( fail == 0 and 0 or 1 )
