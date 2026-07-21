--[[

    core/backup.lua - automatic-backup engine (#480, PR-A).

    The operator-state collector + rotation layer on top of the LDBK1
    archive format (core/backup_archive.lua). Given the hub's own config,
    it gathers the restore-minimum set of files, seals them into one
    encrypted `.ldbk` artifact (+ a `.sha256` sidecar), writes it to the
    configured backup directory, and prunes old artifacts to a retention
    count. The offline restore path (PR-B) consumes the same archive.

    Exposed to the plugin sandbox (core/scripts.lua SANDBOX_GLOBALS) so the
    thin scheduler/CLI plugin scripts/etc_backup.lua can drive it:
        backup.readiness()  -> { ok, issues }   -- config sanity for the owner nag
        backup.run()        -> result | nil,err -- produce one backup now
        backup.list()       -> rows | nil,err    -- artifacts in the backup dir

    SECURITY: the engine reads its own policy (dir / keep / passphrase /
    include_master_key) straight from cfg + core/secrets - it does NOT take
    them as caller arguments. A sandboxed plugin can therefore only TRIGGER
    a backup to the operator-configured destination with the operator's
    passphrase; it cannot redirect the artifact to an arbitrary absolute
    path or substitute a key it controls. Reading master.key / user.tbl is
    no new power either - a plugin's path-restricted io already reaches the
    in-tree cfg/ files; the engine only adds orchestration.

    Passive at load: no init(), no file I/O when the chunk runs. cfg/out are
    bound at file scope (this module loads after them in _core) and only
    called at run time.

    Collection set (see docs/BACKUP.md, PR-B):
        cfg/cfg.tbl, cfg/user.tbl (+ .bak), the TLS material from ssl_params
        (serverkey.pem = secret 0600, servercert.pem, cacert.pem), every
        scripts/data/*.tbl + scripts/cfg/*.tbl, and - when included -
        master.key at master_key_path (stored under the "__masterkey__"
        sentinel; the real path travels in the manifest so restore can put
        it back, even when it lives outside the tree). *.tmp is skipped.

]]--

----------------------------------// DECLARATION //--

local use = use

local type      = use "type"
local pcall     = use "pcall"
local tostring  = use "tostring"
local tonumber  = use "tonumber"
local ipairs    = use "ipairs"

local string       = use "string"
local string_match = string.match
local string_gsub  = string.gsub
local string_sub   = string.sub

local table       = use "table"
local table_sort  = table.sort

local os        = use "os"
local os_time    = os.time
local os_date    = os.date
local os_rename  = os.rename
local os_remove  = os.remove
local os_getenv  = os.getenv
local os_execute = os.execute

local io        = use "io"
local io_open   = io.open

--// core scripts //--

local const         = use "const"
local PROGRAM_NAME  = const.PROGRAM_NAME
local VERSION       = const.VERSION

local cfg     = use "cfg"
local cfg_get = cfg.get

local out       = use "out"
local out_put   = out.put
local out_error = out.error

local secrets        = use "secrets"
local secrets_lookup = secrets.lookup

local archive = use "backup_archive"

-- Raw C primitives from hub.c (core-only, NOT sandboxed). Used directly -
-- not the safe_path-gated util wrappers - because the backup directory and
-- master_key_path are operator-configured and MAY be absolute (a mounted
-- volume, a key relocated out of the tree). Same rationale cfg_secret uses
-- for the master.key parent dir.
local makedir = use "makedir"
local listdir = use "listdir"

----------------------------------// CONSTANTS //--

local MODE_SECRET = 384   -- 0600 (master.key, serverkey.pem)
local MODE_STATE  = 416   -- 0640 (everything else)

local MASTERKEY_ENTRY  = "__masterkey__"
local BACKUP_PREFIX     = "luadch-backup-"
local BACKUP_SUFFIX     = ".ldbk"
local SIDECAR_SUFFIX    = ".sha256"
local DEFAULT_DIR       = "cfg/backups"
local DEFAULT_KEEP      = 7

----------------------------------// CONFIG SNAPSHOT //--

-- Strip a trailing slash so `dir .. "/" .. name` never doubles it.
local function _norm_dir( dir )
    return ( string_gsub( dir, "[/\\]+$", "" ) )
end

-- Read the engine's policy from cfg + secrets. Central so run/readiness/
-- list share one interpretation of the defaults.
local function _config( )
    local enabled = cfg_get "etc_backup_enabled"
    if enabled == nil then enabled = true end

    local dir = cfg_get "etc_backup_dir"
    if type( dir ) ~= "string" or dir == "" then dir = DEFAULT_DIR end
    dir = _norm_dir( dir )

    local keep = tonumber( cfg_get "etc_backup_keep" ) or DEFAULT_KEEP
    if keep < 1 then keep = 1 end

    local include_mk = cfg_get "etc_backup_include_master_key"
    if include_mk == nil then include_mk = true end

    -- env-var-first via core/secrets; falls back to cfg.tbl for bare-metal.
    local passphrase = secrets_lookup( "etc_backup_passphrase" )

    return {
        enabled    = enabled,
        dir        = dir,
        keep       = keep,
        include_mk = include_mk,
        passphrase = ( type( passphrase ) == "string" and passphrase ~= "" ) and passphrase or nil,
    }
end

local function _master_key_path( )
    local mkp = cfg_get "master_key_path"
    if type( mkp ) == "string" and mkp ~= "" then return mkp end
    return "cfg/master.key"
end

----------------------------------// COLLECTION //--

-- Build the file plan (what to back up + where each entry restores to),
-- WITHOUT reading anything - pure and unit-testable. `lister(dir)` injects
-- the directory enumerator (the raw listdir primitive at run time, a stub
-- in tests). Each item: { read = <path to open>, name = <tar/restore name>,
-- mode = <octal perms>, kind = "tree"|"masterkey" }.
local function _collection_spec( include_mk, master_key_path, ssl, lister )
    local spec = {
        { read = "cfg/cfg.tbl",      name = "cfg/cfg.tbl",      mode = MODE_STATE,  kind = "tree" },
        { read = "cfg/user.tbl",     name = "cfg/user.tbl",     mode = MODE_STATE,  kind = "tree" },
        { read = "cfg/user.tbl.bak", name = "cfg/user.tbl.bak", mode = MODE_STATE,  kind = "tree" },
    }

    ssl = ssl or { }
    local key_pem  = ssl.key         or "certs/serverkey.pem"
    local cert_pem = ssl.certificate or "certs/servercert.pem"
    local ca_pem   = ssl.cafile      or "certs/cacert.pem"
    spec[ #spec + 1 ] = { read = key_pem,  name = key_pem,  mode = MODE_SECRET, kind = "tree" }
    spec[ #spec + 1 ] = { read = cert_pem, name = cert_pem, mode = MODE_STATE,  kind = "tree" }
    spec[ #spec + 1 ] = { read = ca_pem,   name = ca_pem,   mode = MODE_STATE,  kind = "tree" }

    if include_mk then
        spec[ #spec + 1 ] = {
            read = master_key_path, name = MASTERKEY_ENTRY, mode = MODE_SECRET, kind = "masterkey",
        }
    end

    -- Variable plugin state. Enumerate scripts/data + scripts/cfg; take the
    -- .tbl files, skip the .tmp half-writes of an in-flight atomic save.
    for _, dir in ipairs( { "scripts/data", "scripts/cfg" } ) do
        local names = lister( dir )
        if type( names ) == "table" then
            table_sort( names )   -- deterministic order
            for _, n in ipairs( names ) do
                if string_match( n, "%.tbl$" ) and not string_match( n, "%.tmp$" ) then
                    local p = dir .. "/" .. n
                    spec[ #spec + 1 ] = { read = p, name = p, mode = MODE_STATE, kind = "tree" }
                end
            end
        end
    end

    return spec
end

-- Match a backup artifact name by plain prefix + suffix. Deliberately NOT a
-- Lua pattern: BACKUP_PREFIX contains '-', which is a pattern magic char
-- (a quantifier), so a naive `string_match` silently matches nothing. The
-- ".sha256" sidecar ends in .sha256, so the .ldbk suffix check excludes it.
local function _is_backup_name( n )
    return #n > #BACKUP_PREFIX + #BACKUP_SUFFIX
        and string_sub( n, 1, #BACKUP_PREFIX ) == BACKUP_PREFIX
        and string_sub( n, -#BACKUP_SUFFIX ) == BACKUP_SUFFIX
end

-- Pick the artifacts to prune: keep the newest `keep` luadch-backup-*.ldbk
-- (timestamped names sort lexicographically = chronologically), return the
-- older ones. Pure/testable. `names` is a raw directory listing.
local function _rotation_victims( names, keep )
    local backups = { }
    for _, n in ipairs( names ) do
        if _is_backup_name( n ) then
            backups[ #backups + 1 ] = n
        end
    end
    table_sort( backups )
    local victims = { }
    local drop = #backups - keep
    for i = 1, drop do
        victims[ #victims + 1 ] = backups[ i ]
    end
    return victims
end

----------------------------------// IO HELPERS //--

local function _read_file( path )
    local f = io_open( path, "rb" )
    if not f then return nil end
    local content = f:read "*a"
    f:close( )
    return content
end

-- Atomic write via tmp + rename. Raw (no safe_path) so an absolute,
-- operator-configured backup dir works; the paths are trusted cfg, not
-- untrusted input. Mirrors util.atomic_write's Windows fallback.
local function _write_atomic( path, content )
    local tmp = path .. ".tmp"
    local f, err = io_open( tmp, "wb" )
    if not f then return false, err end
    local ok, werr = f:write( content )
    f:close( )
    if not ok then os_remove( tmp ); return false, werr end
    if os_rename( tmp, path ) then return true end
    os_remove( path )
    local rok, rerr = os_rename( tmp, path )
    if rok then return true end
    os_remove( tmp )
    return false, rerr or "rename failed"
end

-- POSIX chmod 600 on the sealed artifact - it bundles the (encrypted)
-- master.key / user.tbl / serverkey, so keep it owner-only even though the
-- AES-256-GCM sealing already protects the contents (the daemon umask leaves
-- new files group-readable). Best-effort, no-op on Windows. Mirrors
-- cfg_secret's helper.
local function _chmod_600( path )
    if os_getenv "COMSPEC" and os_getenv "WINDIR" then return end
    os_execute( "chmod 600 '" .. tostring( path ):gsub( "'", "'\\''" ) .. "'" )
end

----------------------------------// PUBLIC: READINESS //--

-- Config sanity the owner nag enumerates. Never raises; returns a list of
-- machine-readable issue codes (the plugin localises them).
local function readiness( )
    local c = _config( )
    local issues = { }

    if not c.passphrase then
        issues[ #issues + 1 ] = "no_passphrase"
    end

    -- Backup dir must be creatable + writable. Probe with a temp file so we
    -- catch a read-only / missing-parent destination before backup time.
    local mkok = makedir( c.dir )
    local probe = c.dir .. "/.backup_write_test"
    local wok = mkok and _write_atomic( probe, "ok" )
    if wok then os_remove( probe ) else
        issues[ #issues + 1 ] = "backup_dir_unwritable"
    end

    if c.include_mk then
        local mkp = _master_key_path( )
        local f = io_open( mkp, "rb" )
        if f then f:close( ) else
            issues[ #issues + 1 ] = "master_key_unreadable"
        end
    end

    return { ok = #issues == 0, issues = issues }
end

----------------------------------// PUBLIC: RUN //--

local function run( )
    local c = _config( )
    if not c.enabled then
        return nil, "backup: disabled (etc_backup_enabled = false)"
    end
    if not c.passphrase then
        return nil, "backup: no passphrase configured (etc_backup_passphrase / LUADCH_ETC_BACKUP_PASSPHRASE)"
    end

    local mkp = c.include_mk and _master_key_path( ) or nil
    local spec = _collection_spec( c.include_mk, mkp, cfg_get "ssl_params", listdir )

    local files, included, skipped = { }, 0, 0
    for _, item in ipairs( spec ) do
        local body = _read_file( item.read )
        if body then
            files[ #files + 1 ] = { name = item.name, mode = item.mode, body = body, kind = item.kind }
            included = included + 1
        else
            skipped = skipped + 1
        end
    end
    if included == 0 then
        return nil, "backup: nothing to back up (no state files found)"
    end

    local meta = {
        program            = PROGRAM_NAME,
        hub_version        = VERSION,
        created_at         = os_time( ),
        include_master_key = c.include_mk and true or false,
    }
    if mkp then meta.master_key_path = mkp end

    local blob, perr = archive.pack( files, meta, c.passphrase )
    if not blob then
        return nil, "backup: seal failed: " .. tostring( perr )
    end

    local mkdir_ok, mkdir_err = makedir( c.dir )
    if not mkdir_ok then
        return nil, "backup: cannot create backup dir '" .. c.dir .. "': " .. tostring( mkdir_err )
    end

    local fname = BACKUP_PREFIX .. os_date( "%Y%m%d-%H%M%S" ) .. BACKUP_SUFFIX
    local path  = c.dir .. "/" .. fname
    local wok, werr = _write_atomic( path, blob )
    if not wok then
        return nil, "backup: cannot write '" .. path .. "': " .. tostring( werr )
    end
    _chmod_600( path )

    -- Sidecar: passphrase-free integrity check (sha256sum -c). Best-effort -
    -- the backup itself already succeeded.
    local sidecar = path .. SIDECAR_SUFFIX
    local sok = _write_atomic( sidecar, archive.sidecar_line( archive.checksum( blob ), fname ) )
    if not sok then
        out_error( "backup: wrote artifact but sidecar failed: ", sidecar )
        sidecar = nil
    end

    -- Rotation: prune oldest beyond keep (artifact + its sidecar).
    local names = listdir( c.dir )
    if type( names ) == "table" then
        for _, victim in ipairs( _rotation_victims( names, c.keep ) ) do
            os_remove( c.dir .. "/" .. victim )
            os_remove( c.dir .. "/" .. victim .. SIDECAR_SUFFIX )
        end
    end

    out_put( "backup: wrote ", path, " (", #blob, " bytes, ", included, " files, ", skipped, " skipped)" )
    return {
        path    = path,
        sidecar = sidecar,
        bytes   = #blob,
        files   = included,
        skipped = skipped,
    }
end

----------------------------------// PUBLIC: LIST //--

-- Rows describing the artifacts currently in the backup dir, newest first,
-- for `+backup list`.
local function list( )
    local c = _config( )
    local names = listdir( c.dir )
    if type( names ) ~= "table" then
        return { }   -- dir missing / empty = no backups yet
    end
    local rows = { }
    for _, n in ipairs( names ) do
        if _is_backup_name( n ) then
            local size
            local f = io_open( c.dir .. "/" .. n, "rb" )
            if f then size = f:seek "end"; f:close( ) end
            rows[ #rows + 1 ] = { name = n, bytes = size }
        end
    end
    table_sort( rows, function( a, b ) return a.name > b.name end )   -- newest first
    return rows
end

----------------------------------// PUBLIC INTERFACE //--

return {
    readiness = readiness,
    run       = run,
    list      = list,

    -- test seams
    _collection_spec  = _collection_spec,
    _rotation_victims = _rotation_victims,
    _config           = _config,
}
