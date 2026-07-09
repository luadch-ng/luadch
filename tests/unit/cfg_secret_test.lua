--[[

    tests/unit/cfg_secret_test.lua

    Focused test for core/cfg_secret.lua's first-boot master.key
    generation: it must create the key's PARENT directory (via the raw
    makedir primitive) BEFORE writing the key, so an operator who points
    master_key_path at a not-yet-existing dir (incl. an absolute one like
    /secrets on a non-Docker host) does not hard-crash the boot when
    io.open fails on the missing parent.

    FAIL-PRE-FIX: on the unpatched module init() never calls makedir, so
    the "makedir called with the parent dir" assertion fails.

    Run: lua5.4 tests/unit/cfg_secret_test.lua

]]--

local _made   = { }   -- captured makedir calls
local _writes = { }   -- captured "wb" file writes (paths)
local _order  = { }   -- interleaved call order: "makedir:<dir>" / "write:<path>"

-- operator relocated the key into a not-yet-existing subdir
local _cfg = { encrypt_usertbl = true, master_key_path = "cfg/keys/master.key" }

local _real = {
    type = type, error = error, pcall = pcall, tonumber = tonumber, tostring = tostring,
    string = string,
    io = {
        open = function( path, mode )
            if mode == "rb" then return nil end          -- no existing key on disk
            _order[ #_order + 1 ] = "write:" .. path      -- "wb" master.key write
            _writes[ #_writes + 1 ] = path
            return { write = function( ) return true end, close = function( ) return true end }
        end,
        popen = function( ) return nil end,
    },
    os = {
        -- force _is_windows() -> true so the POSIX popen/stat + chmod
        -- paths are skipped (they are not what this test exercises)
        getenv = function( n ) if n == "COMSPEC" or n == "WINDIR" then return "x" end end,
        remove = function( ) return true end,
        execute = function( ) return true end,
    },
    adclib = {
        random_bytes = function( n ) return string.rep( "k", n ) end,
        aes_gcm_seal = function( ) end,
        aes_gcm_open = function( ) end,
    },
    const = { CONFIG_PATH = "././cfg/" },
    out = { error = function( ) end, put = function( ) end },
    cfg = { get = function( k ) return _cfg[ k ] end },
    makedir = function( d ) _order[ #_order + 1 ] = "makedir:" .. d; _made[ #_made + 1 ] = d; return true end,
}
_G.use = function( name )
    local v = _real[ name ]
    if v == nil then error( "use: missing " .. name ) end
    return v
end

local cs = assert( loadfile( "core/cfg_secret.lua" ) )( )

local failures, checks = 0, 0
local function ok( label, cond )
    checks = checks + 1
    if cond then io.write( "ok   " .. label .. "\n" )
    else failures = failures + 1; io.write( "FAIL " .. label .. "\n" ) end
end

-- first-boot key generation into the relocated dir
cs.init( )

local function order_index( needle )
    for i, e in ipairs( _order ) do if e == needle then return i end end
end
local function first_write_index( )
    for i, e in ipairs( _order ) do if e:match( "^write:" ) then return i end end
end

local made_parent = false
for _, d in ipairs( _made ) do if d == "cfg/keys" then made_parent = true end end
ok( "makedir called with the master.key parent dir (cfg/keys)", made_parent )

local mk_idx = order_index( "makedir:cfg/keys" )
local wr_idx = first_write_index( )
ok( "makedir runs BEFORE the master.key write", mk_idx and wr_idx and mk_idx < wr_idx )
ok( "master.key was written", #_writes >= 1 )
ok( "the key written is at the relocated path", _writes[ 1 ] == "cfg/keys/master.key" )

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
