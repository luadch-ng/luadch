--[[

    cfg_users.lua - user.tbl I/O helpers extracted from core/cfg.lua

    Phase 6c-2 of the cfg.lua decomposition. Moves the three user-tbl
    helpers (loadusers, saveusers, checkusers) out of cfg.lua so the
    orchestrator file stays focused on cfg.tbl + the public cfg.X API.

    The functions take the user_path string explicitly rather than
    pulling it from `cfg.get` themselves, to avoid a cyclic
    cfg <-> cfg_users dependency at load time. cfg.lua passes the
    resolved path on every call from its thin wrappers.

    Public surface returned to cfg.lua:

        {
            bind_late  = function()  -- see comment below
            loadusers  = function(user_path)
            saveusers  = function(user_path, regusers)
            checkusers = function(user_path)
        }

    out_error is late-bound: out.lua does `use "cfg"` at file scope,
    so loading out at our own file-load time would create a cycle
    (cfg -> cfg_users -> out -> cfg). cfg.init() calls bind_late() at
    the right time, after which all three functions can log via
    out.error.

]]--

local use = use
local util = use "util"

local util_loadtable = util.loadtable
local util_savearray = util.savearray
local util_maketable = util.maketable
local util_chmod_secret = util.chmod_secret

local _

-- Late-bound: out.lua does `use "cfg"` at file scope, so loading it
-- here would create a cycle. cfg.init() calls bind_late() once out
-- is loaded; closures pick up the new value via Lua's by-reference
-- upvalue capture.
local out_error

local function bind_late()
    out_error = use("out").error
end

local function loadusers( user_path )
    local users, err = util_loadtable( user_path .. "user.tbl" )
    _ = err and out_error( "cfg_users.lua: function 'loadusers': error while loading users: ", err )
    return ( users or { } ), err
end

local function saveusers( user_path, regusers )
    local file = user_path .. "user.tbl"
    local _, err = util_savearray( regusers, file )
    _ = err and out_error( "cfg_users.lua: function 'saveusers': error while saving user db: ", err )
    if err then
        return false, err
    else
        util_chmod_secret( file )
        return true
    end
end

local function checkusers( user_path )
    local users, err = util_loadtable( user_path .. "user.tbl" )
    if users then
        local backup = user_path .. "user.tbl.bak"
        util_maketable( nil, backup )
        local _, err = util_savearray( users, backup )
        if err then
            out_error( "cfg_users.lua: function 'checkusers': error while saving user db backup: ", err )
        else
            util_chmod_secret( backup )
        end
    else
        local users, err = util_loadtable( user_path .. "user.tbl.bak" )
        if users then
            local file = user_path .. "user.tbl"
            util_maketable( nil, file )
            local _, err = util_savearray( users, file )
            if err then
                out_error( "cfg_users.lua: function 'checkusers': error while restoring corrupt user db from backup: ", err )
            else
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
