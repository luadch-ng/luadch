--[[

    cfg_users.lua - user.tbl I/O helpers extracted from core/cfg.lua

    Phase 6c-2 of the cfg.lua decomposition. Moves the three user-tbl
    helpers (loadusers, saveusers, checkusers) out of cfg.lua so the
    orchestrator file stays focused on cfg.tbl + the public cfg.X API.

    Phase 7f F-AUTH-1: user.tbl is now AES-256-GCM encrypted at rest
    via core/cfg_secret. Reads detect the LDC1 magic and decrypt; old
    plaintext files load via the existing util.loadtable path and get
    re-written as encrypted on the next save (transparent migration).

    Public surface returned to cfg.lua:

        {
            bind_late  = function()
            loadusers  = function(user_path)
            saveusers  = function(user_path, regusers)
            checkusers = function(user_path)
        }

]]--

local use = use
local io = use "io"
local util = use "util"
local secret = use "cfg_secret"

local io_open = io.open
local util_loadtable = util.loadtable
local util_loadtable_string = util.loadtable_string
local util_savearray = util.savearray
local util_arraytostring = util.arraytostring
local util_maketable = util.maketable
local util_chmod_secret = util.chmod_secret
local secret_seal = secret.seal
local secret_open = secret.open
local secret_is_blob = secret.is_blob
local secret_is_active = secret.is_active

local _

-- Late-bound: out.lua does `use "cfg"` at file scope, so loading it
-- here would create a cycle. cfg.init() calls bind_late() once out
-- is loaded; closures pick up the new value via Lua's by-reference
-- upvalue capture.
local out_error
local out_put

local function bind_late()
    local out = use "out"
    out_error = out.error
    out_put = out.put
end

-- Read the raw file bytes; nil if missing.
local function _read_raw( path )
    local f = io_open( path, "rb" )
    if not f then return nil end
    local content = f:read "*a"
    f:close( )
    return content
end

-- Write `content` to `path` as binary. chmod 600 on POSIX since
-- this file holds the encrypted user db with embedded plaintext
-- passwords.
local function _write_raw( path, content )
    local f, err = io_open( path, "wb" )
    if not f then return false, err end
    f:write( content )
    f:close( )
    util_chmod_secret( path )
    return true
end

-- Internal load: returns (table, err). Detects encrypted vs plaintext
-- format via the LDC1 magic prefix and routes accordingly. Plaintext
-- files load via the legacy util.loadtable path so existing
-- deployments keep working without a migration step; the next save
-- will rewrite the file as encrypted.
local function _load( path )
    local raw = _read_raw( path )
    if not raw then
        return nil, "file not found"
    end
    if secret_is_blob( raw ) then
        local plaintext, err = secret_open( raw )
        if not plaintext then
            return nil, err
        end
        return util_loadtable_string( plaintext, path )
    end
    -- Legacy plaintext format. Use the sandboxed loadtable so a
    -- tampered file cannot reach os/io/etc.
    return util_loadtable( path )
end

local function loadusers( user_path )
    local file = user_path .. "user.tbl"
    local users, err = _load( file )
    if err and out_error then
        out_error( "cfg_users.lua: function 'loadusers': ", err )
    end
    return ( users or { } ), err
end

local function saveusers( user_path, regusers )
    local file = user_path .. "user.tbl"
    if secret_is_active( ) then
        local plaintext = util_arraytostring( regusers )
        local blob, err = secret_seal( plaintext )
        if not blob then
            if out_error then out_error( "cfg_users.lua: function 'saveusers': seal: ", err ) end
            return false, err
        end
        local ok, werr = _write_raw( file, blob )
        if not ok then
            if out_error then out_error( "cfg_users.lua: function 'saveusers': write: ", werr ) end
            return false, werr
        end
        return true
    end
    -- cfg_secret never came up (init failed?). Fall back to plaintext
    -- so the hub at least keeps running. This branch is a defence
    -- against double-fault more than an expected path.
    local _, err = util_savearray( regusers, file )
    if err then
        if out_error then out_error( "cfg_users.lua: function 'saveusers': ", err ) end
        return false, err
    end
    util_chmod_secret( file )
    return true
end

local function checkusers( user_path )
    local file = user_path .. "user.tbl"
    local backup = user_path .. "user.tbl.bak"

    local users, err = _load( file )
    if users then
        -- Healthy primary; refresh the backup. Backup is also
        -- encrypted so the same threat-model applies.
        util_maketable( nil, backup )
        if secret_is_active( ) then
            local plaintext = util_arraytostring( users )
            local blob, sealerr = secret_seal( plaintext )
            if blob then
                local ok, werr = _write_raw( backup, blob )
                if not ok and out_error then
                    out_error( "cfg_users.lua: function 'checkusers': backup write: ", werr )
                end
            elseif out_error then
                out_error( "cfg_users.lua: function 'checkusers': backup seal: ", sealerr )
            end
        else
            local _, werr = util_savearray( users, backup )
            if werr and out_error then
                out_error( "cfg_users.lua: function 'checkusers': backup save: ", werr )
            end
            util_chmod_secret( backup )
        end
    else
        -- Primary broken; try the backup. Fail closed if both fail.
        local restored, berr = _load( backup )
        if restored then
            util_maketable( nil, file )
            if secret_is_active( ) then
                local plaintext = util_arraytostring( restored )
                local blob, sealerr = secret_seal( plaintext )
                if blob then
                    local ok, werr = _write_raw( file, blob )
                    if not ok and out_error then
                        out_error( "cfg_users.lua: function 'checkusers': restore write: ", werr )
                    end
                elseif out_error then
                    out_error( "cfg_users.lua: function 'checkusers': restore seal: ", sealerr )
                end
            else
                local _, werr = util_savearray( restored, file )
                if werr and out_error then
                    out_error( "cfg_users.lua: function 'checkusers': restore save: ", werr )
                end
                util_chmod_secret( file )
            end
        end
    end
end

return {
    bind_late  = bind_late,
    loadusers  = loadusers,
    saveusers  = saveusers,
    checkusers = checkusers,
}
