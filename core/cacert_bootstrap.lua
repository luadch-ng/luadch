--[[

    core/cacert_bootstrap.lua - CA bundle first-boot install +
    upgrade-aware reconciliation (Precursor 0d of #78 arc).

    Two operator-deployment realities the hub has to handle:

    1. Docker volume mount on ./certs/ -> /opt/luadch/certs/. The
       image's `certs/ca-bundle.pem` is overlaid by the host mount,
       so an image rebuild does NOT propagate a new bundle to a
       running operator's certs/ directory. Without a hub-side
       helper the operator must manually `curl > certs/ca-bundle.pem`
       after every release.

    2. Bare-metal `cmake --install` overwrites everything under the
       destination dir unconditionally. Operators with custom CAs
       (corporate PKI) lose their bundle on upgrade.

    This module bridges both. CMake installs the bundled file at an
    immutable system path (`lib/luadch/ca-bundle.pem`) that volume
    mounts and re-installs do NOT touch. On every hub start we
    reconcile `certs/ca-bundle.pem` against that source-of-truth:

        runtime missing                           -> copy bundled in
        runtime present + SHA matches bundled     -> no log
        runtime present + SHA mismatch + auto off -> log WARN
        runtime present + SHA mismatch + auto on  -> backup + replace

    The auto-update toggle defaults OFF: SHA mismatch is NOT
    guaranteed to mean "outdated", an operator might run a custom
    corporate PKI bundle deliberately. Default behaviour is non-
    destructive; opt-in `ca_bundle_auto_update = true` for the
    "always pull the latest from the install tree" preference.

    Public surface (mostly for tests):
        reconcile_bundle(opts) -> action, err
            opts = { runtime_path, source_path, auto_update, now }
            action = "installed" | "no-op" | "warned" | "auto-updated"
                   | "source-missing"
            err is a string when action is the failure cases.

        init() - core-module init() called from init.lua

]]--

local use = use

local type     = use "type"
local string   = use "string"
local io       = use "io"
local os       = use "os"
local tostring = use "tostring"

local io_open   = io.open
local io_write  = io.write
local os_date   = os.date
local os_remove = os.remove
local os_rename = os.rename

local sha256 = use "sha256"
local sha256_hash_file = sha256.hash_file

-- Late-binding: cfg + out are loaded as core modules in init.lua.
-- We belong to _core too, so init.lua's init() loop calls our init
-- after cfg + out are up.
local cfg_get
local out_put
local out_error

-- Boot-time message helpers. We want operators to see the install /
-- warn lines on stdout (docker logs / terminal) AND on the on-disk
-- log via out.put.
local function _bootmsg( ... )
    io_write( "\n", ... )
    if out_put then out_put( ... ) end
end

local function _booterr( ... )
    io_write( "\n", ... )
    if out_error then out_error( ... ) end
end

local function _file_exists( path )
    local f = io_open( path, "rb" )
    if f then f:close( ); return true end
    return false
end

local function _read_all( path )
    local f, err = io_open( path, "rb" )
    if not f then return nil, err end
    local content = f:read( "*a" )
    f:close( )
    return content
end

-- Atomic write: tmp + rename. Mirrors cert_bootstrap.lua's
-- _write_public so a power-loss mid-write cannot leave a half-
-- written ca-bundle.pem (would break the next boot's SHA check).
local function _write_atomic( path, content )
    local tmp = path .. ".tmp"
    local f, err = io_open( tmp, "wb" )
    if not f then return false, err end
    f:write( content )
    f:close( )
    os_remove( path )    -- Windows: rename fails if target exists
    local ok, rerr = os_rename( tmp, path )
    if not ok then
        os_remove( tmp )
        return false, rerr or "rename failed"
    end
    return true
end

-- Backup filename pattern: `<path>.bak-YYYYMMDD-HHMMSS`. Stable +
-- sortable so operators can see install history at a glance.
--
-- Production callers MUST pass `now = nil` so os.date uses the
-- current time. Unit tests MUST pass a fixed timestamp so the
-- resulting filename is deterministic (otherwise the test asserts
-- a time-dependent value and may flake at exact-second boundaries).
local function _backup_path( runtime_path, now )
    return runtime_path .. ".bak-" .. os_date( "%Y%m%d-%H%M%S", now )
end

-- Pure-function reconciliation - core decision logic. Exposed for
-- the unit test which exercises each branch with controlled file
-- state. `opts.now` lets tests pin the backup-timestamp.
local function reconcile_bundle( opts )
    local runtime_path = opts.runtime_path
    local source_path  = opts.source_path
    local auto_update  = opts.auto_update and true or false
    local now          = opts.now    -- nil OK; os_date interprets

    -- Source-of-truth must exist; without it bootstrap is a no-op
    -- and the operator gets one boot warning.
    if not _file_exists( source_path ) then
        return "source-missing",
            "bundled CA file missing at " .. source_path ..
            " (CMake install incomplete? Reinstall or place a Mozilla " ..
            "cacert.pem snapshot at that path)"
    end

    -- Runtime missing -> install bundled.
    if not _file_exists( runtime_path ) then
        local content, rerr = _read_all( source_path )
        if not content then
            return "source-missing",
                "cannot read bundled CA file at " .. source_path ..
                ": " .. tostring( rerr )
        end
        local ok, werr = _write_atomic( runtime_path, content )
        if not ok then
            return "source-missing",
                "cannot write runtime CA file at " .. runtime_path ..
                ": " .. tostring( werr )
        end
        return "installed"
    end

    -- Both files present; read source once and use the same bytes
    -- for both the SHA compare and the auto-update copy below.
    local source_content, source_read_err = _read_all( source_path )
    if not source_content then
        return "source-missing",
            "cannot read bundled CA file at " .. source_path ..
            ": " .. tostring( source_read_err )
    end
    local source_hash = sha256.hash( source_content )

    local runtime_hash, rerr = sha256_hash_file( runtime_path )
    if not runtime_hash then
        return "source-missing", "sha256 of runtime: " .. tostring( rerr )
    end

    if source_hash == runtime_hash then
        return "no-op"
    end

    -- Mismatch path - auto update or warn.
    if not auto_update then
        return "warned", "outdated " .. runtime_path ..
            " (runtime sha: " .. runtime_hash ..
            ", bundled sha: " .. source_hash ..
            "); set ca_bundle_auto_update=true to auto-update or " ..
            "see docs/CACERT.md to refresh manually"
    end

    local backup = _backup_path( runtime_path, now )
    local runtime_content, recontent_err = _read_all( runtime_path )
    if runtime_content then
        local bok, berr = _write_atomic( backup, runtime_content )
        if not bok then
            return "source-missing",
                "cannot write backup at " .. backup ..
                ": " .. tostring( berr )
        end
    else
        -- Read-failed of an existing file is unusual; surface but
        -- continue (without backup) rather than refuse the auto-update.
        _booterr( "cacert_bootstrap: cannot backup " .. runtime_path ..
            ": " .. tostring( recontent_err ) .. " - proceeding without backup" )
    end
    local wok, werr = _write_atomic( runtime_path, source_content )
    if not wok then
        return "source-missing",
            "cannot write runtime CA file at " .. runtime_path ..
            ": " .. tostring( werr )
    end
    return "auto-updated", backup
end

-- Reject empty-string cfg overrides at the boundary: the
-- `cfg_get "K" or default` shorthand does NOT trigger on "" (Lua
-- treats empty string as truthy), so an operator who explicitly
-- set `ca_bundle_path = ""` in cfg.tbl would land an empty path
-- in reconcile_bundle and get an uninformative log line. Fall
-- back to default in both nil and empty cases.
local function _cfg_path( key, default )
    local v = cfg_get( key )
    if type( v ) == "string" and v ~= "" then return v end
    return default
end

-- core-module init: called once from init.lua's import() loop
-- after cfg + out + sha256 are loaded. Reads cfg defaults, calls
-- reconcile_bundle, logs the outcome.
local function init( )
    cfg_get = use( "cfg" ).get
    local out = use "out"
    out_put = out.put
    out_error = out.error

    local runtime_path = _cfg_path( "ca_bundle_path",        "certs/ca-bundle.pem" )
    local source_path  = _cfg_path( "ca_bundle_source_path", "lib/luadch/ca-bundle.pem" )
    local auto_update  = cfg_get "ca_bundle_auto_update" and true or false

    local action, extra = reconcile_bundle{
        runtime_path = runtime_path,
        source_path  = source_path,
        auto_update  = auto_update,
    }

    if action == "installed" then
        _bootmsg( "cacert_bootstrap: installed initial ", runtime_path )
    elseif action == "auto-updated" then
        _bootmsg( "cacert_bootstrap: auto-updated ", runtime_path,
            " (backup at ", tostring( extra ), ")" )
    elseif action == "warned" then
        _booterr( "cacert_bootstrap: ", tostring( extra ) )
    elseif action == "source-missing" then
        _booterr( "cacert_bootstrap: ", tostring( extra ) )
    end
    -- "no-op": stay silent so the boot log is not cluttered on
    -- every restart of a healthy install.
end

return {
    init             = init,
    reconcile_bundle = reconcile_bundle,
    _backup_path     = _backup_path,    -- exposed for tests
}
