--[[

    core/cfg_secret.lua - at-rest encryption for user.tbl

    Phase 7f F-AUTH-1 mitigation. Standard ADC requires the hub to
    hold a password-equivalent secret at rest (the BASE HPAS challenge
    flow needs to recompute Tiger(stored, fresh_salt) on every login),
    so plaintext-equivalent in RAM is non-negotiable. This module
    eliminates plaintext on DISK with AES-256-GCM under a host-bound
    master key.

    Threat model covered:
      - Backup / snapshot exfiltration of cfg/ without the host
      - World-readable cfg/user.tbl from a default-umask
      - File-system-only read primitive (read-only mount, share)

    Threat model NOT covered:
      - On-host RCE / Lua-sandbox escape (key + plaintext in process RAM)
      - Plugin compromise (plugins are admin-trusted by design)
      - Master-key file theft (use OS-bound key wrapping in Phase 8 if
        needed: TPM, DPAPI, libsecret, ...)

    Wire format on disk:
      offset  bytes
        0     4    magic "LDC1"
        4    12    nonce (96-bit, fresh per write via OpenSSL RAND_bytes)
       16    N     ciphertext
     16+N   16    GCM authentication tag

    Master key:
      cfg/master.key, 32 raw bytes, mode 0600 on POSIX.
      Generated on first boot if missing. Hub refuses to start if the
      key file exists with overly-permissive POSIX permissions.

    Operator opt-out (#128):

      Set `encrypt_usertbl = false` in cfg/cfg.tbl to write user.tbl as
      plaintext Lua source instead of an encrypted blob. The master.key
      file is no longer generated; if one exists from a prior encrypted
      deployment it is still loaded so legacy LDC1 blobs (e.g. on
      user.tbl.bak from before the toggle was flipped) decrypt
      transparently. Operators choosing this mode are explicitly opting
      out of the F-AUTH-1 mitigation - documented in docs/SECURITY.md.

    Public surface:

        {
            init                  = function()         -- called by init.lua
            seal                  = function(plaintext) -- returns blob with magic
            open                  = function(blob)      -- returns plaintext or nil
            is_active             = function()          -- key loaded? (read path)
            should_encrypt_writes = function()          -- key + cfg toggle on? (write path)
            is_blob               = function(s)         -- detect magic prefix
        }

]]--

----------------------------------// DECLARATION //--

local use = use

local type = use "type"
local error = use "error"
local pcall = use "pcall"
local string = use "string"
local tonumber = use "tonumber"
local tostring = use "tostring"

local string_byte = string.byte
local string_char = string.char
local string_sub = string.sub
local string_match = string.match

local io = use "io"
local io_open = io.open
local io_popen = io.popen

local os = use "os"
local os_getenv = os.getenv
local os_remove = os.remove

--// extern libs //--

local adclib = use "adclib"
local adclib_random_bytes = adclib.random_bytes
local adclib_aes_gcm_seal = adclib.aes_gcm_seal
local adclib_aes_gcm_open = adclib.aes_gcm_open

--// core scripts //--

local const = use "const"
local CONFIG_PATH = const.CONFIG_PATH

-- cfg is late-bound: cfg.lua does `use "cfg_secret"` at file scope,
-- so importing cfg here would cycle. cfg.init() calls our init() and
-- by then cfg.get is fully wired.
local cfg_get

-- out is late-bound to avoid the cfg <-> out load cycle.
local out_error
local out_put

----------------------------------// CONSTANTS //--

local MAGIC = "LDC1"
local MAGIC_LEN = 4
local KEY_SIZE = 32       -- AES-256
local NONCE_SIZE = 12     -- GCM standard 96-bit nonce
local TAG_SIZE = 16       -- GCM standard 128-bit tag
local MIN_BLOB_LEN = MAGIC_LEN + NONCE_SIZE + TAG_SIZE

----------------------------------// STATE //--

local _key
local _key_path
local _encrypt_writes    -- mirrors cfg.encrypt_usertbl, set in init()

local function _is_windows( )
    return os_getenv "COMSPEC" and os_getenv "WINDIR"
end

----------------------------------// IMPLEMENTATION //--

local function _read_file( path )
    local f = io_open( path, "rb" )
    if not f then return nil end
    local content = f:read "*a"
    f:close( )
    return content
end

local function _write_file( path, content )
    local f, err = io_open( path, "wb" )
    if not f then return false, err end
    f:write( content )
    f:close( )
    return true
end

-- POSIX permissions check on the master key file. Returns:
--   true            -- OK (Linux 0600, or any Windows path)
--   false, message  -- mode wrong on POSIX; caller must abort
-- We shell out to stat(1) because the standalone Lua interpreter has
-- no native syscall surface; lua-posix would be a new dep.
--
-- #93: master_key_path is operator-controlled (cfg.tbl), not remote,
-- but POSIX-quote it anyway so paths with spaces / metacharacters
-- ("/var/lib/my hub/master.key") parse correctly instead of silently
-- bypassing the strict-mode check.
local function _check_master_key_perms( path )
    if _is_windows( ) then
        return true
    end
    local quoted = "'" .. tostring( path ):gsub( "'", "'\\''" ) .. "'"
    local cmd = "stat -c '%a' " .. quoted .. " 2>/dev/null"
    local p = io_popen( cmd )
    if not p then return true end    -- best-effort; can't check
    local mode = p:read "*l"
    p:close( )
    if mode and mode ~= "" and mode ~= "600" then
        return false, "master.key has insecure mode " .. mode .. " (expected 600); refuse to start. fix with: chmod 600 " .. path
    end
    return true
end

-- POSIX-only chmod 600 helper. Mirrors util.chmod_secret but used
-- before util is bound; duplicated to avoid an init-order dependency.
local function _chmod_600( path )
    if _is_windows( ) then return end
    local escaped = "'" .. tostring( path ):gsub( "'", "'\\''" ) .. "'"
    os.execute( "chmod 600 " .. escaped )
end

local function init( )
    -- out late-bind: out.lua does `use "cfg"` at file scope, so we
    -- can't import out at our own load time; cfg.init() calls our
    -- init after out is up.
    local out = use "out"
    out_error = out.error
    out_put = out.put

    -- cfg late-bind: cfg.init() guarantees _settings is loaded by
    -- the time we run, so cfg.get works for master_key_path.
    cfg_get = use( "cfg" ).get

    -- #128: operator can opt out of at-rest encryption via the new
    -- encrypt_usertbl cfg toggle. Default true (matches Phase 7f).
    -- When false, user.tbl is written as plaintext Lua source on
    -- every save. Existing LDC1 blobs (e.g. on a stale .bak from
    -- before the toggle flip) still decrypt if master.key is on disk
    -- - we just stop GENERATING a new key when there is none.
    _encrypt_writes = cfg_get "encrypt_usertbl" ~= false

    -- Resolve master.key path. The cfg key master_key_path can move
    -- the key outside the install dir entirely - see the strong
    -- recommendation in cfg_defaults.lua. Empty string falls back to
    -- the in-tree default.
    local configured = cfg_get "master_key_path"
    if type( configured ) == "string" and configured ~= "" then
        _key_path = configured
        out_put( "cfg_secret: master.key path overridden by cfg: ", _key_path )
    else
        _key_path = CONFIG_PATH .. "master.key"
    end

    -- Try to load existing key. We always load if the file is there,
    -- regardless of encrypt_usertbl, so a deployment that flips the
    -- toggle from on to off can still decrypt their existing user.tbl
    -- on the first boot post-flip. The save path then writes plain
    -- and the .bak migrates on the next save cycle.
    local content = _read_file( _key_path )
    if content then
        if #content ~= KEY_SIZE then
            error( "cfg_secret: master.key has wrong size " .. #content .. " (expected " .. KEY_SIZE .. ")", 0 )
        end
        local ok, err = _check_master_key_perms( _key_path )
        if not ok then
            error( "cfg_secret: " .. err, 0 )
        end
        _key = content
        out_put( "cfg_secret: loaded master.key (", KEY_SIZE, " bytes) from ", _key_path )
        if not _encrypt_writes then
            out_put( "cfg_secret: encrypt_usertbl=false; user.tbl will be saved as plaintext on next write. master.key kept on disk for legacy decrypt." )
        end
        return
    end

    -- No key on disk. If the operator disabled encryption, stop here
    -- - we don't need a key. A pre-existing plaintext user.tbl will
    -- load via util.loadtable; saves go straight to plaintext.
    if not _encrypt_writes then
        out_put( "cfg_secret: encrypt_usertbl=false and no master.key on disk; running in plaintext mode." )
        return
    end

    -- Encryption enabled and no key yet: generate one. F-AUTH-1
    -- first-boot migration.
    out_put( "cfg_secret: master.key not found, generating new 256-bit key at ", _key_path )
    local key, err = adclib_random_bytes( KEY_SIZE )
    if not key then
        error( "cfg_secret: failed to generate master.key: " .. tostring( err ), 0 )
    end
    -- Ensure the key's parent directory exists before writing. The
    -- operator can point master_key_path at a not-yet-created dir -
    -- including an absolute one outside the tree (e.g. /secrets on a
    -- non-Docker host) - and a missing parent makes io.open fail, so the
    -- error() below would abort the whole boot. Use the RAW makedir
    -- primitive (not util.makedir, which safe_path-rejects absolute
    -- paths); the path is operator-trusted cfg, not untrusted input.
    -- Best-effort - a genuine failure still surfaces as the write error.
    local key_dir = string_match( _key_path, "^(.*)[/\\][^/\\]+$" )
    if key_dir and key_dir ~= "" then
        local mok, mkdir = pcall( use, "makedir" )
        if mok and type( mkdir ) == "function" then pcall( mkdir, key_dir ) end
    end
    local ok, werr = _write_file( _key_path, key )
    if not ok then
        error( "cfg_secret: cannot write master.key to " .. _key_path .. ": " .. tostring( werr ), 0 )
    end
    _chmod_600( _key_path )
    _key = key
end

local function is_active( )
    return _key ~= nil
end

-- Write-side gate: encrypt new user.tbl saves only if the cfg toggle
-- is on AND we have a key. is_active() alone is not enough because
-- the key may be loaded for legacy-decrypt purposes while writes are
-- supposed to be plaintext (operator flipped encrypt_usertbl=false
-- but kept master.key around).
local function should_encrypt_writes( )
    return _key ~= nil and _encrypt_writes == true
end

local function is_blob( s )
    return type( s ) == "string"
        and #s >= MIN_BLOB_LEN
        and string_sub( s, 1, MAGIC_LEN ) == MAGIC
end

local function seal( plaintext )
    if not _key then
        return nil, "cfg_secret: not initialized"
    end
    local nonce = adclib_random_bytes( NONCE_SIZE )
    local ok, ct_with_tag = pcall( adclib_aes_gcm_seal, _key, nonce, plaintext )
    if not ok then
        return nil, "cfg_secret: seal failed: " .. tostring( ct_with_tag )
    end
    return MAGIC .. nonce .. ct_with_tag
end

local function open( blob )
    if not _key then
        return nil, "cfg_secret: not initialized"
    end
    if not is_blob( blob ) then
        return nil, "cfg_secret: not an encrypted blob"
    end
    local nonce = string_sub( blob, MAGIC_LEN + 1, MAGIC_LEN + NONCE_SIZE )
    local ct = string_sub( blob, MAGIC_LEN + NONCE_SIZE + 1 )
    local ok, plaintext, err = pcall( adclib_aes_gcm_open, _key, nonce, ct )
    if not ok then
        return nil, "cfg_secret: open call failed: " .. tostring( plaintext )
    end
    if not plaintext then
        return nil, "cfg_secret: decrypt failed: " .. tostring( err )
    end
    return plaintext
end

----------------------------------// PUBLIC INTERFACE //--

return {
    init = init,
    seal = seal,
    open = open,
    is_active = is_active,
    should_encrypt_writes = should_encrypt_writes,
    is_blob = is_blob,
}
