--[[

    tests/unit/util_safe_path_test.lua

    Unit tests for core/util.lua's `safe_path` helper and its
    application in the plugin-callable I/O surface (#266).

    Pre-fix: util.checkfile / util.atomic_write / util.maketable
    captured the unsandboxed io.open at module load and accepted
    any path - a malicious plugin could read /etc/passwd or
    clobber arbitrary host files, bypassing the _io_safe shim
    added in #213. Post-fix: all three reject unsafe paths
    BEFORE invoking io.open, mirroring the _io_safe gate.

    Run: lua5.4 tests/unit/util_safe_path_test.lua
    Exit 0 = all pass, 1 = a failure (CI-friendly).

]]--

----------------------------------------------------------------------
-- shim layer: stub `use` so util.lua loads in isolation
----------------------------------------------------------------------

local _io_open_calls = { }    -- captured: each entry { path=..., mode=... }
local _io_open_real_return = nil    -- if non-nil, io.open stub returns this

local _io_stub = {
    open = function( path, mode )
        _io_open_calls[ #_io_open_calls + 1 ] = { path = path, mode = mode }
        if _io_open_real_return then return _io_open_real_return end
        return nil, "stubbed io.open"
    end,
}

local _adclib_stub = {
    isutf8 = function( ) return true end,
    random_bytes = function( ) return "x" end,
}

local _unicode_stub = {
    ascii = {
        sub = string.sub,
        gsub = string.gsub,
    },
    utf8 = {
        format = string.format,
    },
}

local _out_stub = {
    put = function( ) end,
    error = function( ) end,
}

local _mem_stub = { free = function( ) end }

local _real = {
    type = type, load = load, table = table, pairs = pairs,
    pcall = pcall, select = select, ipairs = ipairs,
    tostring = tostring, tonumber = tonumber, loadfile = loadfile,
    setmetatable = setmetatable,
    io = _io_stub, math = math, string = string, os = os,
    package = package,
    adclib = _adclib_stub, unicode = _unicode_stub,
    out = _out_stub, mem = _mem_stub,
}
_G.use = function( name )
    local v = _real[ name ]
    assert( v ~= nil, "util_safe_path_test shim missing dep: use \"" .. name .. "\"" )
    return v
end

local util = assert( loadfile( "core/util.lua" ) )( )
util.init( )

----------------------------------------------------------------------
-- minimal test framework
----------------------------------------------------------------------

local failures, checks = 0, 0

local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-65s got=%q want=%q\n",
            label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

local function ok_safe( label, path )
    local ok, _err = util.safe_path( path )
    eq( label, ok, true )
end

local function reject( label, path )
    local ok, err = util.safe_path( path )
    eq( label .. " (ok=false)", ok, false )
    -- second slot must be a non-empty diagnostic string
    if ok ~= false or type( err ) ~= "string" or #err == 0 then
        failures = failures + 1
        io.write( string.format( "FAIL %s: missing diagnostic string (err=%q)\n",
            label, tostring( err ) ) )
    end
end

----------------------------------------------------------------------
-- 1. safe_path: positive cases (relative, single-dot, dotted filenames)
----------------------------------------------------------------------

ok_safe( "safe: relative file in cwd",                  "log/error.log"   )
ok_safe( "safe: relative cfg",                          "cfg/cfg.tbl"     )
ok_safe( "safe: relative scripts/data/<plugin>.tbl",    "scripts/data/foo.tbl" )
ok_safe( "safe: leading ./",                            "./cfg/cfg.tbl"   )
ok_safe( "safe: legitimate ..-in-filename (foo..bar)",  "foo..bar"        )
ok_safe( "safe: legitimate filename thesis..v2.lua",    "log/thesis..v2.lua" )
ok_safe( "safe: backslash separator (Windows-style)",   "log\\error.log"  )
ok_safe( "safe: plain filename",                        "user.tbl"        )

----------------------------------------------------------------------
-- 2. safe_path: rejection cases
----------------------------------------------------------------------

reject( "reject: absolute POSIX root",                  "/etc/passwd"     )
reject( "reject: absolute POSIX nested",                "/var/log/foo"    )
reject( "reject: absolute Windows C:\\",                "C:\\Windows\\System32\\config\\sam" )
reject( "reject: absolute Windows C:/",                 "C:/Users/Aybo"   )
reject( "reject: absolute Windows lowercase",           "d:\\secret"      )
reject( "reject: UNC path \\\\server",                  "\\\\server\\share\\file" )
reject( "reject: parent-dir at start",                  "../escape"       )
reject( "reject: parent-dir mid-path",                  "log/../etc/passwd" )
reject( "reject: parent-dir end",                       "log/.."          )
reject( "reject: parent-dir backslash separator",       "log\\..\\etc\\shadow" )
reject( "reject: bare ..",                              ".."              )
reject( "reject: embedded NUL byte",                    "log/error.log\0.."  )
reject( "reject: NUL then traversal",                   "cfg/\0../secret" )

----------------------------------------------------------------------
-- 3. safe_path: type validation
----------------------------------------------------------------------

do
    local ok, err = util.safe_path( nil )
    eq( "reject: nil path returns false", ok, false )
    eq( "reject: nil path emits err string", type( err ), "string" )
end

do
    local ok, _ = util.safe_path( 42 )
    eq( "reject: number path returns false", ok, false )
end

do
    local ok, _ = util.safe_path( { } )
    eq( "reject: table path returns false", ok, false )
end

do
    local ok, err = util.safe_path( "" )
    eq( "reject: empty string returns false", ok, false )
    eq( "reject: empty string emits err string", type( err ), "string" )
end

----------------------------------------------------------------------
-- 4. checkfile: unsafe paths must NOT reach io.open
----------------------------------------------------------------------

do
    _io_open_calls = { }
    _io_open_real_return = nil
    local content, err = util.checkfile( "/etc/passwd" )
    eq( "checkfile: absolute path returns nil",         content, nil )
    eq( "checkfile: absolute path returns err string",  type( err ), "string" )
    eq( "checkfile: absolute path did NOT call io.open", #_io_open_calls, 0 )
end

do
    _io_open_calls = { }
    local content, _ = util.checkfile( "../../escape" )
    eq( "checkfile: traversal returns nil",             content, nil )
    eq( "checkfile: traversal did NOT call io.open",    #_io_open_calls, 0 )
end

do
    _io_open_calls = { }
    -- Safe path should pass safe_path and reach io.open. The stub returns
    -- (nil, "stubbed io.open") which checkfile propagates as a normal
    -- file-not-found - the key signal is that io.open WAS called.
    local _, _ = util.checkfile( "cfg/cfg.tbl" )
    eq( "checkfile: safe path DOES call io.open",       #_io_open_calls, 1 )
    if _io_open_calls[ 1 ] then
        eq( "checkfile: safe path passes through correct path",
            _io_open_calls[ 1 ].path, "cfg/cfg.tbl" )
    end
end

----------------------------------------------------------------------
-- 5. atomic_write: unsafe paths must NOT reach io.open
----------------------------------------------------------------------

do
    _io_open_calls = { }
    local ok, err = util.atomic_write( "/tmp/backdoor", "evil" )
    eq( "atomic_write: absolute path returns false",     ok, false )
    eq( "atomic_write: absolute path returns err string", type( err ), "string" )
    eq( "atomic_write: absolute path did NOT call io.open", #_io_open_calls, 0 )
end

do
    _io_open_calls = { }
    local ok, _ = util.atomic_write( "../escape.tbl", "x" )
    eq( "atomic_write: traversal returns false",         ok, false )
    eq( "atomic_write: traversal did NOT call io.open",  #_io_open_calls, 0 )
end

----------------------------------------------------------------------
-- 6. maketable: unsafe paths must NOT reach io.open
----------------------------------------------------------------------

do
    _io_open_calls = { }
    local ok, err = util.maketable( "evil", "/etc/cron.d/evil" )
    eq( "maketable: absolute path returns false",        ok, false )
    eq( "maketable: absolute path returns err string",   type( err ), "string" )
    eq( "maketable: absolute path did NOT call io.open", #_io_open_calls, 0 )
end

do
    _io_open_calls = { }
    local ok, _ = util.maketable( "evil", "C:\\Windows\\Temp\\b.tbl" )
    eq( "maketable: Windows absolute returns false",     ok, false )
    eq( "maketable: Windows absolute did NOT call io.open", #_io_open_calls, 0 )
end

----------------------------------------------------------------------
-- 7. savetable / savearray: route through atomic_write -> safe_path
----------------------------------------------------------------------

do
    _io_open_calls = { }
    local ok, _ = util.savetable( { x = 1 }, "evil", "/tmp/backdoor.tbl" )
    eq( "savetable: absolute path returns false",        ok, false )
    eq( "savetable: absolute path did NOT call io.open", #_io_open_calls, 0 )
end

do
    _io_open_calls = { }
    local ok, _ = util.savearray( { 1, 2, 3 }, "../escape.tbl" )
    eq( "savearray: traversal returns false",            ok, false )
    eq( "savearray: traversal did NOT call io.open",     #_io_open_calls, 0 )
end

----------------------------------------------------------------------
-- summary
----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures > 0 and 1 or 0 )
