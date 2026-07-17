--[[

    cfg_users.lua - user.tbl I/O helpers extracted from core/cfg.lua

    Phase 6c-2 of the cfg.lua decomposition. Moves the three user-tbl
    helpers (loadusers, saveusers, checkusers) out of cfg.lua so the
    orchestrator file stays focused on cfg.tbl + the public cfg.X API.

    Phase 7f F-AUTH-1: user.tbl is now AES-256-GCM encrypted at rest
    via core/cfg_secret. Reads detect the LDC1 magic and decrypt; old
    plaintext files load via the existing util.loadtable path and get
    re-written as encrypted on the next save (transparent migration).

    Atomic-write + always-fresh .bak (closes upstream luadch#189):
    the previous saveusers() did open(W) + write + close on the live
    user.tbl, which truncates the file at open. A crash or filesystem
    error mid-write left user.tbl partial; checkusers() then fell back
    to user.tbl.bak (potentially weeks old, refreshed only at hub
    startup / +reload) and silently lost recent registrations. We now
    write to a .tmp sidecar and atomically rename, and we refresh
    user.tbl.bak with the same content on every successful save - the
    backup is therefore always current rather than a stale snapshot.

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

-- tostring is used in the both-primary-and-backup-unreadable error
-- path of checkusers(). Strict-globals in core/init.lua's sandbox
-- denies bare access; without this import that branch raised
-- "attempt to read undeclared var: 'tostring'" instead of logging
-- the underlying I/O error. Latent for years because the path only
-- triggers on a doubly-corrupted user.tbl pair, surfaced by the
-- #128 plaintext-mode smoke test which deliberately wipes both
-- files before the encrypt_usertbl=false restart.
local tostring = use "tostring"

local io_open = io.open
local util_loadtable = util.loadtable
local util_loadtable_string = util.loadtable_string
local util_arraytostring = util.arraytostring
local util_chmod_secret = util.chmod_secret
local util_atomic_write = util.atomic_write
local secret_seal = secret.seal
local secret_open = secret.open
local secret_is_blob = secret.is_blob
local secret_should_encrypt_writes = secret.should_encrypt_writes

local _

-- Late-bound: out.lua does `use "cfg"` at file scope, so loading it
-- here would create a cycle. cfg.init() calls bind_late() once out
-- is loaded; closures pick up the new value via Lua's by-reference
-- upvalue capture.
local out_error

local function bind_late()
    local out = use "out"
    out_error = out.error
end

-- Read the raw file bytes; nil if missing.
local function _read_raw( path )
    local f = io_open( path, "rb" )
    if not f then return nil end
    local content = f:read "*a"
    f:close( )
    return content
end

-- Atomic write + chmod 600 on the resulting file. The tmp+rename
-- mechanics live in util.atomic_write since F-PLG-1 (#133); we just
-- chmod the final path afterwards. chmod on the inode is preserved
-- across the rename on POSIX, but applying it post-rename is the
-- cleanest order regardless (and matches what the cfg_secret save
-- path expects: the user.tbl that lands on disk is 0600).
local function _atomic_write( path, content )
    local ok, err = util_atomic_write( path, content )
    if not ok then return false, err end
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
    local backup = user_path .. "user.tbl.bak"

    -- Build the on-disk bytes once (encrypted blob if cfg_secret is
    -- active AND the operator did not opt out via encrypt_usertbl=
    -- false, plaintext Lua-source otherwise). Both user.tbl and
    -- user.tbl.bak get written from the same buffer so they end up
    -- byte-identical; that lets `cmp user.tbl user.tbl.bak` validate
    -- the .bak refresh externally.
    local content
    if secret_should_encrypt_writes( ) then
        local plaintext = util_arraytostring( regusers )
        local blob, err = secret_seal( plaintext )
        if not blob then
            if out_error then out_error( "cfg_users.lua: function 'saveusers': seal: ", err ) end
            return false, err
        end
        content = blob
    else
        -- Either cfg_secret never came up (init failed - defence
        -- against double-fault) OR the operator set encrypt_usertbl=
        -- false (#128 opt-out). Both paths land plaintext Lua-source
        -- on disk; the next read auto-detects (no LDC1 magic, falls
        -- through to util.loadtable).
        content = util_arraytostring( regusers )
    end

    -- Atomic primary write. Anything fancier (fsync, filesystem
    -- barriers) is out of scope; the rename(2) call is the strongest
    -- crash-safety primitive standard Lua exposes.
    local ok, err = _atomic_write( file, content )
    if not ok then
        if out_error then out_error( "cfg_users.lua: function 'saveusers': write: ", err ) end
        return false, err
    end

    -- Refresh the backup with the same bytes. Best-effort: a failure
    -- here does NOT fail the save (the primary write already
    -- succeeded, callers should not have to handle "saved but no
    -- backup" as a separate state). The next save will retry.
    local bok, berr = _atomic_write( backup, content )
    if not bok and out_error then
        out_error( "cfg_users.lua: function 'saveusers': backup refresh: ", berr )
    end

    return true
end

local function checkusers( user_path )
    local file = user_path .. "user.tbl"
    local backup = user_path .. "user.tbl.bak"

    -- Primary OK? saveusers() refreshes .bak on every successful
    -- write, so when the primary is readable .bak is already current
    -- (or will be on the next save). No prophylactic refresh here.
    local users, err = _load( file )
    if users then
        return
    end

    -- Primary broken; try to restore from .bak. This path triggers
    -- when user.tbl was manually deleted or the filesystem corrupted
    -- it (since v3.1.5 the atomic-write path makes the
    -- crash-during-save case impossible).
    local restored, berr = _load( backup )
    if not restored then
        if out_error then
            out_error( "cfg_users.lua: function 'checkusers': both primary and backup unreadable: ",
                       tostring( err ), " / ", tostring( berr ) )
        end
        return
    end

    -- Re-write on restore. Two paths land here:
    --   - legacy plaintext .bak from a pre-7f deployment that gets
    --     written back encrypted now that cfg_secret is active
    --   - existing encrypted .bak that gets written back plaintext
    --     because the operator flipped encrypt_usertbl=false (#128)
    -- Either way: write whichever format the toggle currently asks
    -- for, same as a normal save would.
    local content
    if secret_should_encrypt_writes( ) then
        local plaintext = util_arraytostring( restored )
        local blob, sealerr = secret_seal( plaintext )
        if not blob then
            if out_error then
                out_error( "cfg_users.lua: function 'checkusers': restore seal: ", sealerr )
            end
            return
        end
        content = blob
    else
        content = util_arraytostring( restored )
    end

    local ok, werr = _atomic_write( file, content )
    if not ok and out_error then
        out_error( "cfg_users.lua: function 'checkusers': restore write: ", werr )
    end
end

return {
    bind_late  = bind_late,
    loadusers  = loadusers,
    saveusers  = saveusers,
    checkusers = checkusers,
}
