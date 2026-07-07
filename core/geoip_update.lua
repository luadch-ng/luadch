--[[

    core/geoip_update.lua - in-hub MaxMind GeoLite2 database auto-update.

    MaxMind ships GeoLite2 databases ONLY as `.tar.gz`, so keeping them
    fresh has historically meant an operator-side `geoipupdate` cron /
    Docker sidecar. This module lets the hub fetch + refresh them itself
    (opt-in), on every platform the hub runs on.

    Pipeline (all work on temp files; the live `.mmdb` is touched only by
    the final atomic rename, so ANY earlier failure keeps the last-good DB):

        1. GET the tiny `.tar.gz.sha256` sidecar; if its hash equals the
           caller's stored hash the DB is unchanged -> stop (no big
           download, respects MaxMind's download rate limit).
        2. download_to_file the `.tar.gz` (core/http_client, atomic tmp +
           rename built in). Auth is HTTP Basic (account-id : license-key)
           in a header, so the credential never touches the URL (and thus
           never the failure log).
        3. Verify sha256(downloaded) == the sidecar hash (integrity).
        4. In a server.addtimer coroutine (yields per MiB so the hub keeps
           serving): read the .tar.gz in chunks -> zlib_stream.gunzip ->
           parse the tar -> extract the single `*.mmdb` member.
        5. Sanity-check the extracted bytes with mmdb.open BEFORE committing
           (catches an extraction bug so a corrupt file is never persisted).
        6. Atomically rename the extracted file onto the destination path.

    This is INFRASTRUCTURE, not connect-time policy: it needs `sha256`
    (not in the plugin sandbox), full `os.rename`/`os.remove` (the plugin's
    curated `_os_safe` lacks them), and `server.addtimer` (`use`-only). The
    etc_geoip plugin owns the POLICY (when to update, which editions,
    swapping its live reader on success) and drives this module by import.

    Public surface:

        update( opts, on_done )
            opts = {
                edition      = "GeoLite2-Country",
                dest         = "cfg/geoip/GeoLite2-Country.mmdb",
                account_id   = "123456",
                license_key  = "<secret>",
                known_sha256 = "<hex>" | nil,   -- skip if the sidecar matches
                host         = "download.maxmind.com" | nil,
                verify       = "peer" | "none" | nil,
            }
            on_done( result )   -- called exactly once:
                { status = "updated",   sha256 = <hex>, bytes = N }
                { status = "unchanged", sha256 = <hex> }
                { status = "failed",    err = <string> }

        init()   -- core-module init hook (no-op; the module is passive).

    Test hooks (underscore-prefixed): _tar_extract_mmdb, _parse_sha256_body,
    _parse_octal.

]]--

local use = use

-- Core modules run under init.lua's restricted env: every stdlib / library
-- via `use` (a bare global fails at hub load with "undeclared var").
local type      = use "type"
local tostring  = use "tostring"
local tonumber  = use "tonumber"
local pcall     = use "pcall"
local error     = use "error"
local string    = use "string"
local table     = use "table"
local math      = use "math"
local coroutine = use "coroutine"
local io        = use "io"
local os        = use "os"
local out       = use "out"
local basexx    = use "basexx"
local http_client = use "http_client"
local sha256    = use "sha256"
local mmdb      = use "mmdb"
-- server + zlib_stream are resolved lazily at call time: server via
-- addtimer (http_client does the same), zlib_stream is an OPTIONAL module
-- (may be false if its require failed at boot).

local string_sub   = string.sub
local string_byte  = string.byte
local string_find  = string.find
local string_gsub  = string.gsub
local string_rep   = string.rep
local string_lower = string.lower
local string_match = string.match
local table_concat = table.concat
local math_ceil    = math.ceil
local io_open      = io.open
local os_remove    = os.remove
local os_rename    = os.rename
local coroutine_create = coroutine.create
local coroutine_yield  = coroutine.yield
local out_error    = out.error


local DEFAULT_HOST     = "download.maxmind.com"
local TAR_BLOCK        = 512
local MAX_TAR_BLOCKS   = 200000             -- cap the member HEADERS scanned (skipped data blocks are not counted)
local MAX_MEMBER_SIZE  = 16 * 1024 * 1024   -- refuse a member over mmdb.MAX_FILE_SIZE (mmdb.open would reject a larger file anyway)
local MAX_DECOMPRESSED = 32 * 1024 * 1024   -- total gunzip-output ceiling: bomb guard (per-push cap lives in zlib_stream.c). > MAX_MEMBER_SIZE + tar overhead, < http_client's 50 MiB download cap
local READ_CHUNK       = 256 * 1024         -- compressed bytes read from disk per iteration
local FLUSH_BUDGET     = 1024 * 1024        -- decompressed bytes per coroutine tick before yielding
local SHA_MAX_RESP     = 4096               -- the .sha256 sidecar is ~80 bytes
local DOWNLOAD_TIMEOUT = 120                -- seconds; a few-MB body over the 1 Hz drain

local ZERO_BLOCK = string_rep( "\0", TAR_BLOCK )


----------------------------------------------------------------------
-- tar (ustar) extraction - untrusted-input parser (DEVELOPMENT.md §5)
----------------------------------------------------------------------

-- Octal size field (offset 124, 12 bytes). Defensive: NUL/space trim,
-- reject any non-octal char, bound the value BEFORE it drives arithmetic.
local function _parse_octal( s )
    s = string_gsub( s, "%z.*$", "" )
    s = string_gsub( s, "^%s+", "" )
    s = string_gsub( s, "%s+$", "" )
    if s == "" then return 0 end
    if string_find( s, "[^0-7]" ) then return nil, "non-octal size field" end
    local n = tonumber( s, 8 )
    if not n or n < 0 or n > MAX_MEMBER_SIZE then return nil, "size out of range" end
    return n
end

-- Even though we only ever extract by ".mmdb" suffix into a fixed path we
-- own, reject traversal / absolute / control-byte names as defence in depth.
local function _name_is_mmdb( name )
    if string_find( name, "%.%." ) or string_find( name, "^/" ) or string_find( name, "%c" ) then
        return false
    end
    return string_lower( string_sub( name, -5 ) ) == ".mmdb"
end

-- Given the FULL decompressed tar bytes, return the single `*.mmdb`
-- member's bytes, or (nil, err). Bounds every 512-block read, caps the
-- block scan, and returns a soft error (keep last-good) when no member is
-- found rather than an empty/partial result.
local function _tar_extract_mmdb( tar )
    if type( tar ) ~= "string" then return nil, "tar: not a string" end
    local n = #tar
    local pos = 1
    local blocks = 0
    while pos + TAR_BLOCK - 1 <= n do
        blocks = blocks + 1
        if blocks > MAX_TAR_BLOCKS then return nil, "tar: too many blocks" end
        local header = string_sub( tar, pos, pos + TAR_BLOCK - 1 )
        pos = pos + TAR_BLOCK
        if header == ZERO_BLOCK then break end    -- end-of-archive marker

        local size, serr = _parse_octal( string_sub( header, 125, 136 ) )
        if not size then return nil, "tar: " .. tostring( serr ) end

        local data_start = pos
        local data_end   = pos + size - 1
        if data_end > n then return nil, "tar: member data extends past archive" end

        local typeflag = string_byte( header, 157 ) or 0    -- offset 156
        local name = string_gsub( string_sub( header, 1, 100 ), "%z.*$", "" )

        -- regular file: typeflag '0' (0x30) or legacy NUL (0x00)
        if ( typeflag == 48 or typeflag == 0 ) and _name_is_mmdb( name ) then
            return string_sub( tar, data_start, data_end )
        end

        pos = pos + math_ceil( size / TAR_BLOCK ) * TAR_BLOCK   -- skip padded data
    end
    return nil, "tar: no .mmdb member found"
end


----------------------------------------------------------------------
-- helpers
----------------------------------------------------------------------

-- First whitespace-delimited token of the sidecar body:
--   "<64-hex>  GeoLite2-Country_YYYYMMDD.tar.gz\n"
local function _parse_sha256_body( body )
    if type( body ) ~= "string" then return nil end
    local hex = string_match( body, "^%s*(%x+)" )
    if hex and #hex == 64 then return string_lower( hex ) end
    return nil
end

-- Cheap existence probe (no os.stat under the restricted env).
local function _file_exists( path )
    local fh = io_open( path, "rb" )
    if fh then fh:close( ); return true end
    return false
end

-- Atomic rename tmp -> dest. POSIX replaces atomically; Windows refuses an
-- existing target, so move it aside to <dest>.bak and roll back on failure
-- (mirrors core/http_client.lua's stream_to_file swap).
local function _atomic_place( tmp, dest )
    local rok, rerr = os_rename( tmp, dest )
    if not rok then
        local bak = dest .. ".bak"
        os_remove( bak )
        local had = os_rename( dest, bak )    -- nil if dest absent
        rok, rerr = os_rename( tmp, dest )
        if rok then
            if had then os_remove( bak ) end
        elseif had then
            if not os_rename( bak, dest ) then
                out_error( "geoip_update: swap for '", dest,
                    "' failed and the previous DB could not be restored; ",
                    "it is preserved at '", bak, "'" )
            end
        end
    end
    if not rok then
        os_remove( tmp )
        return false, "rename '" .. tmp .. "' -> '" .. dest .. "' failed: " .. tostring( rerr )
    end
    return true
end

-- Decompress the downloaded .tar.gz (src) in a yielding coroutine, extract
-- the .mmdb member, sanity-check it, and atomically place it at dest.
-- Calls back on_ok(bytes) / on_err(msg).
local function _decompress_extract( src, dest, on_ok, on_err )
    local zlib_stream = use "zlib_stream"
    if type( zlib_stream ) ~= "table" or type( zlib_stream.gunzip ) ~= "function" then
        return on_err( "zlib_stream.gunzip unavailable" )
    end
    local server = use "server"
    if type( server ) ~= "table" or type( server.addtimer ) ~= "function" then
        return on_err( "server.addtimer unavailable" )
    end

    local tmp = dest .. ".tmp"
    local co = coroutine_create( function( )
        local f, g                                    -- hoisted so cleanup can close them on ANY throw
        local ok, res = pcall( function( )
            f = io_open( src, "rb" )
            if not f then error( "open '" .. tostring( src ) .. "' failed" ) end
            g = zlib_stream.gunzip( )
            local parts, flushed, total = { }, 0, 0
            while true do
                local chunk = f:read( READ_CHUNK )
                if not chunk then break end
                local plain = g:push( chunk )         -- throws on a non-gzip / bomb body
                if #plain > 0 then
                    total = total + #plain
                    if total > MAX_DECOMPRESSED then  -- cumulative bomb guard (per-push cap lives in zlib_stream.c)
                        error( "decompressed output exceeds " .. MAX_DECOMPRESSED .. " byte cap (bomb?)" )
                    end
                    parts[ #parts + 1 ] = plain
                    flushed = flushed + #plain
                    if flushed >= FLUSH_BUDGET then flushed = 0; coroutine_yield( ) end
                end
            end
            f:close( ); f = nil
            g:close( ); g = nil

            local tar = table_concat( parts )
            local mmdb_bytes, terr = _tar_extract_mmdb( tar )
            if not mmdb_bytes then error( tostring( terr ) ) end

            os_remove( tmp )
            local wf, werr = io_open( tmp, "wb" )
            if not wf then error( "open tmp '" .. tmp .. "' failed: " .. tostring( werr ) ) end
            local wok = wf:write( mmdb_bytes )
            local cok = wf:close( )
            if not ( wok and cok ) then error( "write tmp '" .. tmp .. "' failed" ) end

            -- sanity: is the extracted file a real MMDB? (catches an
            -- extraction bug BEFORE we overwrite the last-good DB)
            local reader = mmdb.open( tmp )
            if not reader then error( "extracted file is not a valid .mmdb" ) end
            if reader.close then reader:close( ) end

            local pok, perr = _atomic_place( tmp, dest )
            if not pok then error( tostring( perr ) ) end
            return #mmdb_bytes
        end )
        -- close the source read handle + gunzip stream on EVERY path: a
        -- mid-loop throw (non-gzip / bomb body) leaves them open otherwise,
        -- and on Windows a leaked read handle blocks the .download cleanup.
        if f then pcall( function( ) f:close( ) end ) end
        if g and g.close then pcall( function( ) g:close( ) end ) end
        if ok then
            on_ok( res )
        else
            os_remove( tmp )
            on_err( tostring( res ) )
        end
    end )
    server.addtimer( co )
end


----------------------------------------------------------------------
-- public: update( opts, on_done )
----------------------------------------------------------------------

local function update( opts, on_done )
    if type( opts ) ~= "table" or type( on_done ) ~= "function" then
        error( "geoip_update.update: opts table + on_done function required", 2 )
    end
    local edition = opts.edition
    local dest    = opts.dest
    local account = opts.account_id
    local license = opts.license_key

    -- fire on_done exactly once + clean the download temp
    local dl = ( type( dest ) == "string" ) and ( dest .. ".download" ) or nil
    local fired = false
    local function finish( result )
        if fired then return end
        fired = true
        if dl then os_remove( dl ) end
        on_done( result )
    end

    if type( edition ) ~= "string" or edition == ""
       or type( dest ) ~= "string" or dest == "" then
        return finish( { status = "failed", err = "edition + dest required" } )
    end
    if type( account ) ~= "string" or account == ""
       or type( license ) ~= "string" or license == "" then
        return finish( { status = "failed", err = "account_id + license_key required" } )
    end
    -- credentials must not contain control bytes (they go into a header)
    if string_find( account, "%c" ) or string_find( license, "%c" ) then
        return finish( { status = "failed", err = "credential contains control bytes" } )
    end

    local host   = ( type( opts.host ) == "string" and opts.host ~= "" ) and opts.host or DEFAULT_HOST
    local verify = opts.verify or "peer"
    local base   = "https://" .. host .. "/geoip/databases/" .. edition .. "/download"
    local auth   = "Basic " .. basexx.to_base64( account .. ":" .. license )
    local headers = { [ "Authorization" ] = auth }

    -- step 3: verify sha256 of the downloaded tar.gz, then decompress+extract
    local function have_download( expected )
        local got, herr = sha256.hash_file( dl )
        if not got then
            return finish( { status = "failed", err = "hash_file: " .. tostring( herr ) } )
        end
        if string_lower( got ) ~= expected then
            return finish( { status = "failed", err = "sha256 mismatch (download corrupt)" } )
        end
        _decompress_extract( dl, dest,
            function( bytes ) finish( { status = "updated", sha256 = expected, bytes = bytes } ) end,
            function( emsg )  finish( { status = "failed", err = emsg } ) end )
    end

    -- step 2: download the tar.gz to <dest>.download
    local function do_download( expected )
        os_remove( dl )
        local ok, rerr = http_client.request{
            url          = base .. "?suffix=tar.gz",
            method       = "GET",
            headers      = headers,
            verify       = verify,
            download_to_file = dl,
            timeout      = DOWNLOAD_TIMEOUT,
            on_complete  = function( ) have_download( expected ) end,
            on_error     = function( err ) finish( { status = "failed", err = "download: " .. tostring( err ) } ) end,
        }
        if not ok then
            finish( { status = "failed", err = "download rejected: " .. tostring( rerr ) } )
        end
    end

    -- step 1: fetch the tiny .sha256 sidecar, compare to known_sha256
    local ok, rerr = http_client.request{
        url          = base .. "?suffix=tar.gz.sha256",
        method       = "GET",
        headers      = headers,
        verify       = verify,
        max_response = SHA_MAX_RESP,
        timeout      = 30,
        on_complete  = function( res )
            if res.status ~= 200 then
                return finish( { status = "failed", err = "sha256 fetch HTTP " .. tostring( res.status ) } )
            end
            local expected = _parse_sha256_body( res.body )
            if not expected then
                return finish( { status = "failed", err = "unparseable .sha256 sidecar" } )
            end
            if type( opts.known_sha256 ) == "string" and string_lower( opts.known_sha256 ) == expected
               and _file_exists( dest ) then
                -- stored hash matches AND the DB is actually on disk -> up to date
                return finish( { status = "unchanged", sha256 = expected } )
            end
            do_download( expected )   -- hash differs OR the .mmdb went missing -> (re)download (self-heal)
        end,
        on_error     = function( err ) finish( { status = "failed", err = "sha256 fetch: " .. tostring( err ) } ) end,
    }
    if not ok then
        finish( { status = "failed", err = "sha256 fetch rejected: " .. tostring( rerr ) } )
    end
end


local function init( ) end    -- passive at load; nothing to initialize


return {
    update = update,
    init   = init,

    -- exposed for the unit test
    _tar_extract_mmdb  = _tar_extract_mmdb,
    _parse_sha256_body = _parse_sha256_body,
    _parse_octal       = _parse_octal,
}
