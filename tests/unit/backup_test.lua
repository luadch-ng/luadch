--[[

    tests/unit/backup_test.lua

    Unit tests for core/backup.lua's pure decision logic, driven through a
    stubbed `use` shim (no real filesystem / crypto):
      - _config(): cfg + secrets interpretation, defaults, dir normalisation
      - _collection_spec(): which files enter a backup + their restore names,
        modes and kinds; master.key inclusion toggle; .tbl filter that skips
        .tmp half-writes and non-.tbl files; the injected directory lister
      - _rotation_victims(): keep-newest-N pruning selection

    The full read/pack/write/rotate path (run/readiness) touches the real
    filesystem + adclib and is covered by the backup smoke test (PR-A).

    Run: lua5.4 tests/unit/backup_test.lua   (exit 0 = pass, 1 = fail)

]]--

----------------------------------------------------------------------
-- `use` shim
----------------------------------------------------------------------

local _cfg    = { }   -- cfg.get source (set per test)
local _secret = { }   -- secrets.lookup source

local _real = {
    type = type, pcall = pcall, tostring = tostring, tonumber = tonumber, ipairs = ipairs,
    string = string, table = table, os = os, io = io,
    const   = { PROGRAM_NAME = "Luadch-NG", VERSION = "v3.2.0-dev", CONFIG_PATH = "cfg/" },
    cfg     = { get = function( k ) return _cfg[ k ] end },
    out     = { put = function( ) end, error = function( ) end },
    secrets = { lookup = function( k ) return _secret[ k ] end },
    backup_archive = { pack = function( ) end, checksum = function( ) return "x" end,
        sidecar_line = function( ) return "" end },
    makedir = function( ) return true end,
    listdir = function( ) return { } end,
}
_G.use = function( name )
    local v = _real[ name ]
    if v == nil then error( "backup_test shim missing dep: use \"" .. tostring( name ) .. "\"" ) end
    return v
end

local B = assert( loadfile( "core/backup.lua" ) )( )

----------------------------------------------------------------------
-- harness
----------------------------------------------------------------------

local passes, fails = 0, 0
local function ok( label, cond )
    if cond then passes = passes + 1
    else fails = fails + 1; io.stderr:write( "FAIL: " .. label .. "\n" ) end
end
local function eq( label, got, want )
    if got == want then passes = passes + 1
    else
        fails = fails + 1
        io.stderr:write( string.format( "FAIL: %s\n  got:  %s\n  want: %s\n",
            label, tostring( got ), tostring( want ) ) )
    end
end
local function find_entry( spec, name )
    for _, e in ipairs( spec ) do if e.name == name then return e end end
end

----------------------------------------------------------------------
-- _config: defaults when cfg is empty
----------------------------------------------------------------------

_cfg, _secret = { }, { }
do
    local c = B._config( )
    eq( "default enabled = true",    c.enabled, true )
    eq( "default dir = cfg/backups", c.dir,     "cfg/backups" )
    eq( "default keep = 7",          c.keep,    7 )
    eq( "default include_mk = true", c.include_mk, true )
    eq( "no passphrase -> nil",      c.passphrase, nil )
end

----------------------------------------------------------------------
-- _config: explicit values + dir normalisation + keep clamp
----------------------------------------------------------------------

_cfg = {
    etc_backup_enabled = false,
    etc_backup_dir = "/mnt/backups///",
    etc_backup_keep = 0,             -- must clamp to >= 1
    etc_backup_include_master_key = false,
}
_secret = { etc_backup_passphrase = "hunter2" }
do
    local c = B._config( )
    eq( "explicit enabled = false",   c.enabled, false )
    eq( "trailing slashes stripped",  c.dir,     "/mnt/backups" )
    eq( "keep clamped to 1",          c.keep,    1 )
    eq( "explicit include_mk = false", c.include_mk, false )
    eq( "passphrase from secrets",    c.passphrase, "hunter2" )
end

-- empty-string passphrase is treated as unset
_secret = { etc_backup_passphrase = "" }
eq( "empty passphrase -> nil", B._config( ).passphrase, nil )

----------------------------------------------------------------------
-- _collection_spec: full set with master.key, filtered plugin state
----------------------------------------------------------------------

local function fake_lister( dir )
    if dir == "scripts/data" then
        return { "cmd_ban_bans.tbl", "etc_geoip.tbl", "half.tbl.tmp", "readme.txt" }
    elseif dir == "scripts/cfg" then
        return { "etc_something.tbl" }
    end
    return { }
end

do
    local spec = B._collection_spec( true, "/etc/luadch/master.key", nil, fake_lister )

    ok( "cfg.tbl included",        find_entry( spec, "cfg/cfg.tbl" ) ~= nil )
    ok( "user.tbl included",       find_entry( spec, "cfg/user.tbl" ) ~= nil )
    ok( "user.tbl.bak included",   find_entry( spec, "cfg/user.tbl.bak" ) ~= nil )

    local key = find_entry( spec, "certs/serverkey.pem" )
    ok( "serverkey.pem included",  key ~= nil )
    eq( "serverkey mode 0600",     key and key.mode, 384 )
    ok( "servercert.pem included", find_entry( spec, "certs/servercert.pem" ) ~= nil )
    ok( "cacert.pem included",     find_entry( spec, "certs/cacert.pem" ) ~= nil )

    local mk = find_entry( spec, "__masterkey__" )
    ok( "master.key entry present", mk ~= nil )
    eq( "master.key kind",          mk and mk.kind, "masterkey" )
    eq( "master.key mode 0600",     mk and mk.mode, 384 )
    eq( "master.key read path",     mk and mk.read, "/etc/luadch/master.key" )

    ok( "scripts/data .tbl included",  find_entry( spec, "scripts/data/cmd_ban_bans.tbl" ) ~= nil )
    ok( "cache .tbl included too",     find_entry( spec, "scripts/data/etc_geoip.tbl" ) ~= nil )
    ok( "scripts/cfg .tbl included",   find_entry( spec, "scripts/cfg/etc_something.tbl" ) ~= nil )
    ok( ".tmp half-write skipped",     find_entry( spec, "scripts/data/half.tbl.tmp" ) == nil )
    ok( "non-.tbl file skipped",       find_entry( spec, "scripts/data/readme.txt" ) == nil )

    local state = find_entry( spec, "scripts/data/cmd_ban_bans.tbl" )
    eq( "state mode 0640", state and state.mode, 416 )
end

-- include_master_key = false -> no master.key entry
do
    local spec = B._collection_spec( false, "/etc/luadch/master.key", nil, fake_lister )
    ok( "master.key excluded when include=false", find_entry( spec, "__masterkey__" ) == nil )
    ok( "cfg.tbl still there", find_entry( spec, "cfg/cfg.tbl" ) ~= nil )
end

-- custom ssl_params paths honoured
do
    local ssl = { key = "certs/mykey.pem", certificate = "certs/mycert.pem", cafile = "certs/myca.pem" }
    local spec = B._collection_spec( false, nil, ssl, fake_lister )
    ok( "custom serverkey path",  find_entry( spec, "certs/mykey.pem" ) ~= nil )
    ok( "custom cert path",       find_entry( spec, "certs/mycert.pem" ) ~= nil )
    ok( "default serverkey absent when overridden", find_entry( spec, "certs/serverkey.pem" ) == nil )
end

----------------------------------------------------------------------
-- _rotation_victims: keep newest N, oldest pruned; non-backups ignored
----------------------------------------------------------------------

do
    local names = {
        "luadch-backup-20260101-010101.ldbk",
        "luadch-backup-20260102-010101.ldbk",
        "luadch-backup-20260103-010101.ldbk",
        "luadch-backup-20260104-010101.ldbk",
        "luadch-backup-20260105-010101.ldbk",
        "luadch-backup-20260105-010101.ldbk.sha256",   -- sidecar, NOT a victim
        "some-other-file.txt",
    }
    local v = B._rotation_victims( names, 3 )
    eq( "victim count (5 backups, keep 3)", #v, 2 )
    eq( "oldest victim first",  v[ 1 ], "luadch-backup-20260101-010101.ldbk" )
    eq( "second oldest victim", v[ 2 ], "luadch-backup-20260102-010101.ldbk" )
    -- sidecar + non-backup never selected
    for _, name in ipairs( v ) do
        ok( "victim is an .ldbk, not a sidecar/other", name:match( "%.ldbk$" ) ~= nil and name:match( "%.sha256$" ) == nil )
    end
end

-- fewer backups than keep -> nothing pruned
do
    local v = B._rotation_victims( { "luadch-backup-20260101-010101.ldbk" }, 7 )
    eq( "keep > count -> no victims", #v, 0 )
end

----------------------------------------------------------------------
-- output
----------------------------------------------------------------------

if fails > 0 then
    io.stderr:write( string.format( "\nFAIL: %d/%d checks failed\n", fails, passes + fails ) )
    os.exit( 1 )
end
print( string.format( "OK: %d checks passed", passes ) )
