--[[

    core/restore.lua - offline restore entry for the #480 backup arc (PR-B).

    NOT a hub module: it is never in core/init.lua's `_core` and never runs
    inside a live hub. The C launcher's run_restore() (hub/hub.c) loads THIS
    file into a fresh Lua state when the operator runs

        ./luadch --restore <file> [--verify] [--force] [--master-key-path P]

    after chdir-to-install-root and AFTER acquiring the single-instance lock,
    so a restore can never race a running hub over cfg/user.tbl/master.key.
    It reverses core/backup.lua: decrypt + verify one .ldbk artifact and lay
    its files back onto the install tree. It boots NOTHING else (no cfg, no
    listeners) - the config it would read is exactly what it is restoring.

    Two phases, transactional per file:
      preflight - sha256 sidecar check, AES-256-GCM decrypt + MANIFEST parse,
                  path-sanitize every entry, detect dest conflicts. No writes.
      apply     - tmp-write + atomic rename each file, chmod 0600 the secrets.
    --verify runs preflight only (a dry run). Without --force, restore refuses
    to overwrite an existing populated tree.

    SECURITY: an archive entry name is GCM-authenticated but is NOT a trusted
    path - a valid-yet-crafted (or foreign) archive can carry "../../etc/x".
    _safe_rel() rejects absolute paths and any ".."/"." component before a
    single byte is written (the guard core/backup_archive.unpack's note asks
    for). master.key is the one deliberately-absolute destination (the
    operator's own configured / --master-key-path location), never a tar name.

    Args arrive as globals set by the C caller: RESTORE_FILE (string),
    RESTORE_VERIFY / RESTORE_FORCE (bool), RESTORE_MASTER_KEY_PATH (string|nil).
    The passphrase is read out-of-band from $LUADCH_BACKUP_PASSPHRASE (there is
    no cfg to read it from on a fresh host - that is the whole point). Returns
    an integer exit code (0 = success/clean verify, 1 = failure).

]]--

----------------------------------// BOOTSTRAP //--
-- This chunk runs with _ENV = the real globals (loaded plain by the C side),
-- so require / io / os / string are directly reachable. We stand up the same
-- restricted `use` env core modules expect and pull in backup_archive (which
-- transitively loads hmac + sha256). adclib is a dynamic C lib, required the
-- way core/init.lua requires it.

local _G = _ENV

local require      = require
local loadfile     = loadfile
local setmetatable = setmetatable
local error        = error
local type         = type
local tostring     = tostring
local tonumber     = tonumber
local pcall        = pcall
local ipairs       = ipairs
local print        = print
local os           = os
local io           = io
local string       = string
local table        = table
local package      = package

local os_getenv  = os.getenv
local os_rename  = os.rename
local os_remove  = os.remove
local io_open    = io.open

-- .dll on Windows, .so elsewhere - same probe init.lua uses.
local _filetype = ( os_getenv "COMSPEC" and os_getenv "WINDIR" and ".dll" ) or ".so"

-- Resolve core/ + the bundled libs the way init.lua does, so require("adclib")
-- and loadfile("core/backup_archive.lua") work from the install root.
package.path = package.path .. ";"
    .. "././core/?.lua;"
    .. "././lib/?/?.lua;"
    .. "././lib/luasocket/lua/?.lua;"
    .. "././lib/luasec/lua/?.lua;"
package.cpath = package.cpath .. ";"
    .. "././lib/?/?" .. _filetype .. ";"
    .. "././lib/luasocket/?/?" .. _filetype .. ";"
    .. "././lib/luasec/?/?" .. _filetype .. ";"

local _env
local function loadscript( name )
    if _G[ name ] ~= nil then return _G[ name ] end
    local chunk, err = loadfile( "././core/" .. name .. ".lua", "t", _env )
    if not chunk then error( "restore: cannot load core/" .. name .. ".lua: " .. tostring( err ), 0 ) end
    _G[ name ] = chunk( )
    return _G[ name ]
end
local function use( name )
    local v = _G[ name ]
    if v ~= nil then return v end
    return loadscript( name )
end
_env = setmetatable( { use = use }, {
    __index    = function( _, k ) error( "attempt to read undeclared var: '" .. tostring( k ) .. "'", 2 ) end,
    __newindex = function( _, k ) error( "attempt to write undeclared var: '" .. tostring( k ) .. "'", 2 ) end,
} )

-- adclib is required (dynamic C lib); without it there is no AES-GCM/PBKDF2
-- and nothing can be decrypted - fail loud with a clear message. A unit test
-- may pre-inject a fake _G.adclib to exercise the pure helpers without the
-- built C module; a real --restore always takes the require path.
if _G.adclib == nil then
    local ok, lib = pcall( require, "adclib" )
    if not ok or type( lib ) ~= "table" then
        print( "luadch restore: FATAL - could not load the adclib crypto module (" .. tostring( lib ) .. ")" )
        print( "luadch restore: run --restore from the install root so lib/adclib is on the path." )
        return 1
    end
    _G.adclib = lib
end

local archive = use "backup_archive"

----------------------------------// CONSTANTS //--

local MASTERKEY_ENTRY   = "__masterkey__"
local DEFAULT_MK_PATH   = "cfg/master.key"
local SIDECAR_SUFFIX    = ".sha256"
local MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024   -- 1 GiB read cap (OOM guard)

-- Restored files are made owner-only (0600) by the umask run_restore() sets
-- before this script runs, so there is no per-file secret classification here -
-- master.key (0600 is load-bearing: cfg_secret refuses any other mode), the TLS
-- key, and user.tbl all land 0600 without a post-write chmod race.

----------------------------------// PURE HELPERS (test seams) //--

-- Sanitize a tar entry name into a path that can only land INSIDE the install
-- root. Rejects absolute paths (POSIX "/...", UNC "\\...", drive "C:...") and
-- any dot/space-only component ("..", "...", ".. "), which covers traversal and
-- its Windows normalisation. Returns (clean_relative_path) or (nil, reason).
local function _safe_rel( name )
    if type( name ) ~= "string" or name == "" then
        return nil, "empty name"
    end
    -- Absolute: leading slash/backslash, or a "X:" drive prefix.
    if string.match( name, "^[/\\]" ) or string.match( name, "^%a:" ) then
        return nil, "absolute path"
    end
    local parts = { }
    for seg in string.gmatch( name, "[^/\\]+" ) do
        if seg == "." then
            -- harmless no-op segment ("./x"), drop it
        elseif string.match( seg, "^[%.%s]+$" ) then
            -- ".." / "..." / ".. " / whitespace-only: rejects traversal AND the
            -- Windows trailing-dot/space normalisation that maps them onto "."/".."
            return nil, "unsafe component '" .. seg .. "'"
        else
            parts[ #parts + 1 ] = seg
        end
    end
    if #parts == 0 then return nil, "no path segments" end
    return table.concat( parts, "/" )
end

-- Where the master.key travels back to: an explicit --master-key-path wins,
-- else the path recorded in the manifest (may be absolute - a DR relocation),
-- else the in-tree default. Absolute here is BY DESIGN (operator-owned), unlike
-- a tar entry name, so it is not run through _safe_rel.
local function _resolve_masterkey_dest( meta, mk_override )
    if type( mk_override ) == "string" and mk_override ~= "" then return mk_override end
    if type( meta ) == "table" and type( meta.master_key_path ) == "string"
       and meta.master_key_path ~= "" then
        return meta.master_key_path
    end
    return DEFAULT_MK_PATH
end

-- Turn the unpacked { meta, files } into a concrete write plan without
-- touching disk. Returns plan, rejects where:
--   plan[i]    = { dest, body [, masterkey=true] }   (masterkey => the __masterkey__ entry)
--   rejects[i] = { name, reason }                    (unsafe path => fatal, aborts restore)
local function _build_plan( files, meta, mk_override )
    local plan, rejects = { }, { }
    local has_override = type( mk_override ) == "string" and mk_override ~= ""
    for _, f in ipairs( files ) do
        if f.name == MASTERKEY_ENTRY or f.kind == "masterkey" then
            local dest = _resolve_masterkey_dest( meta, mk_override )
            -- The manifest's master_key_path may be absolute / out-of-tree (a DR
            -- relocation). Honour that ONLY when the operator opted in with
            -- --master-key-path: a foreign archive must not steer an arbitrary
            -- absolute write via the manifest. An in-tree relative path is fine.
            if not has_override and _safe_rel( dest ) == nil then
                rejects[ #rejects + 1 ] = { name = f.name,
                    reason = "manifest places master.key out of tree at '" .. dest
                        .. "'; re-run with --master-key-path to choose where" }
            else
                plan[ #plan + 1 ] = { dest = dest, body = f.body, masterkey = true }
            end
        else
            local rel, why = _safe_rel( f.name )
            if not rel then
                rejects[ #rejects + 1 ] = { name = f.name, reason = why }
            else
                plan[ #plan + 1 ] = { dest = rel, body = f.body }
            end
        end
    end
    return plan, rejects
end

-- Verify the sidecar if present. Returns "ok" | "missing" | "mismatch".
local function _verify_sidecar( blob, sidecar_text )
    if type( sidecar_text ) ~= "string" or sidecar_text == "" then return "missing" end
    local want = string.match( sidecar_text, "^(%x+)" )
    if not want then return "mismatch" end
    return ( string.lower( want ) == string.lower( archive.checksum( blob ) ) ) and "ok" or "mismatch"
end

----------------------------------// DISK HELPERS //--

-- Parent-directory chain of a dest path, innermost last, so makedir walks it
-- top-down. Handles both separators; skips an absolute root / drive prefix.
local function _dir_of( path )
    return ( string.match( path, "^(.*)[/\\][^/\\]+$" ) )
end

local makedir = _G.makedir   -- C primitive registered by run_restore()

-- Create the parent directory chain of `dest`. The makedir C primitive is
-- already mkdir -p (it walks every separator and tolerates EEXIST, absolute
-- roots and a Windows drive prefix), so one call suffices; propagate its error
-- so a genuine failure (permission) surfaces as itself, not a later write error.
local function _ensure_parent( dest )
    local dir = _dir_of( dest )
    if not dir or dir == "" then return true end
    if not makedir then return true end   -- absent under a standalone lua (tests)
    local ok, err = makedir( dir )
    if not ok then return false, "cannot create directory '" .. dir .. "': " .. tostring( err ) end
    return true
end

local function _write_atomic( path, content )
    local tmp = path .. ".restore-tmp"
    local f, err = io_open( tmp, "wb" )
    if not f then return false, err end
    local ok, werr = f:write( content )
    f:close( )
    if not ok then os_remove( tmp ); return false, werr end
    -- Fast path: POSIX rename replaces atomically; Windows rename succeeds when
    -- the dest does not exist (a fresh-tree restore).
    local rok, rerr = os_rename( tmp, path )
    if rok then return true end
    -- Windows + existing dest (a --force overwrite): rename refuses. Move the
    -- original aside FIRST so a failed swap can never destroy it, then swap,
    -- then drop the saved copy. On any failure the original is put back.
    local saved = path .. ".restore-old"
    os_remove( saved )
    if os_rename( path, saved ) then
        if os_rename( tmp, path ) then os_remove( saved ); return true end
        os_rename( saved, path )   -- swap failed: restore the original
        os_remove( tmp )
        return false, "rename failed (original restored)"
    end
    os_remove( tmp )
    return false, rerr or "rename failed"
end

local function _exists( path )
    local f = io_open( path, "rb" )
    if f then f:close( ); return true end
    return false
end

----------------------------------// DRIVER //--

local function _read_capped( path )
    local f, err = io_open( path, "rb" )
    if not f then return nil, err end
    local size = f:seek( "end" )
    if size and size > MAX_ARCHIVE_BYTES then
        f:close( )
        return nil, "archive too large (" .. size .. " bytes > " .. MAX_ARCHIVE_BYTES .. ")"
    end
    f:seek( "set" )
    local data = f:read( "a" )
    f:close( )
    return data
end

local function main( )
    local file    = _G.RESTORE_FILE
    local verify  = _G.RESTORE_VERIFY and true or false
    local force   = _G.RESTORE_FORCE and true or false
    local mk_over = _G.RESTORE_MASTER_KEY_PATH

    if type( file ) ~= "string" or file == "" then
        print( "luadch restore: no backup file given" )
        return 1
    end

    local passphrase = os_getenv "LUADCH_BACKUP_PASSPHRASE"
    if type( passphrase ) ~= "string" or passphrase == "" then
        print( "luadch restore: set the backup passphrase in $LUADCH_BACKUP_PASSPHRASE, e.g." )
        print( "  LUADCH_BACKUP_PASSPHRASE='...' ./luadch --restore " .. file )
        return 1
    end

    print( "luadch restore: reading " .. file )
    local blob, rerr = _read_capped( file )
    if not blob then
        print( "luadch restore: cannot read '" .. file .. "': " .. tostring( rerr ) )
        return 1
    end

    -- Passphrase-free integrity gate (sha256sum sidecar). A mismatch means the
    -- artifact was truncated/altered on the media - abort before spending the
    -- KDF. A missing sidecar is only a warning (GCM still authenticates).
    local sidecar_text = _read_capped( file .. SIDECAR_SUFFIX )
    local sc = _verify_sidecar( blob, sidecar_text )
    if sc == "mismatch" then
        print( "luadch restore: ABORT - sidecar sha256 does not match (corrupt/altered archive)" )
        return 1
    end
    print( "luadch restore: sidecar " .. ( sc == "ok" and "sha256 OK" or "absent (skipped)" ) )

    local un, uerr = archive.unpack( blob, passphrase )
    if not un then
        print( "luadch restore: cannot open archive: " .. tostring( uerr ) )
        return 1
    end
    local meta = un.meta or { }
    print( string.format( "luadch restore: unpacked %s %s (%d file(s))",
        tostring( meta.program or "?" ), tostring( meta.hub_version or "?" ), #un.files ) )

    local plan, rejects = _build_plan( un.files, meta, mk_over )
    if #rejects > 0 then
        print( "luadch restore: ABORT - archive contains unsafe path(s):" )
        for _, r in ipairs( rejects ) do print( "  " .. r.name .. "  (" .. r.reason .. ")" ) end
        return 1
    end

    -- Conflict scan: refuse to clobber an already-populated tree unless forced.
    local conflicts = { }
    for _, p in ipairs( plan ) do
        if _exists( p.dest ) then conflicts[ #conflicts + 1 ] = p.dest end
    end

    print( "luadch restore: plan" )
    for _, p in ipairs( plan ) do
        print( "  " .. p.dest .. ( _exists( p.dest ) and "  (exists)" or "" ) )
    end

    -- --verify is a dry run: report the plan (conflicts included) and exit 0
    -- WITHOUT writing or refusing. Checked BEFORE the conflict refusal so a
    -- sanity-check against a live tree does not fail merely because files exist.
    if verify then
        local note = ( #conflicts > 0 )
            and ( " (" .. #conflicts .. " already exist; --force needed to overwrite)" ) or ""
        print( "luadch restore: --verify OK - " .. #plan .. " file(s) would be restored"
            .. note .. ", no changes written." )
        return 0
    end

    if #conflicts > 0 and not force then
        print( "luadch restore: REFUSING - " .. #conflicts
            .. " file(s) already exist. Restore into a clean install, or pass --force to overwrite." )
        return 1
    end

    -- Apply. Each file is tmp-write + atomic rename, so a mid-run failure never
    -- leaves a half-written dest; already-restored files stay put. Files land
    -- owner-only (0600) via the umask run_restore() set, so no chmod is needed.
    local done, failed, mk_done = 0, nil, false
    for _, p in ipairs( plan ) do
        local pok, perr = _ensure_parent( p.dest )
        if not pok then failed = perr; break end
        local ok, werr = _write_atomic( p.dest, p.body )
        if not ok then
            failed = "cannot write '" .. p.dest .. "': " .. tostring( werr )
            break
        end
        if p.masterkey then mk_done = true end
        done = done + 1
    end

    if failed then
        print( "luadch restore: FAILED after " .. done .. " file(s): " .. failed )
        return 1
    end

    print( "luadch restore: DONE - " .. done .. " file(s) restored." )
    if mk_done then
        print( "luadch restore: master.key placed at " .. _resolve_masterkey_dest( meta, mk_over ) )
    elseif meta.include_master_key then
        print( "luadch restore: NOTE - this backup was set to include master.key, but none was"
            .. " present at backup time; supply your own so user.tbl can decrypt." )
    else
        print( "luadch restore: NOTE - this backup excluded master.key; put your own in place"
            .. " (--master-key-path, or at master_key_path) so user.tbl can decrypt." )
    end
    print( "luadch restore: review cfg/, then start the hub." )
    return 0
end

----------------------------------// TEST SEAM / ENTRY //--

-- When required as a module (unit tests set RESTORE_TEST), export the pure
-- helpers instead of running. The C launcher never sets that flag, so a real
-- --restore falls through to main().
if _G.RESTORE_TEST then
    return {
        _safe_rel               = _safe_rel,
        _resolve_masterkey_dest = _resolve_masterkey_dest,
        _build_plan             = _build_plan,
        _verify_sidecar         = _verify_sidecar,
        _dir_of                 = _dir_of,
        archive                 = archive,
    }
end

return main( )
