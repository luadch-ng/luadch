--[[

    tests/unit/util_makedir_test.lua

    Unit tests for core/util.lua's `makedir` wrapper around the hub.c
    `makedir` C primitive. The primitive itself (recursive mkdir -p) is
    compiled into the launcher and exercised end-to-end by the smoke
    harness; here we test the Lua wrapper in isolation via a stubbed
    primitive:
      - safe_path gate: traversal / absolute paths are rejected BEFORE the
        primitive is called (a sandboxed plugin may only create in-tree dirs)
      - a valid relative path is passed through verbatim to the primitive
      - the primitive's (nil, err) return is propagated
      - a missing primitive (standalone lua / a broken build) degrades to
        (nil, err) instead of throwing

    Run: lua5.4 tests/unit/util_makedir_test.lua   (exit 0 = pass, 1 = fail)

]]--

----------------------------------------------------------------------
-- shim layer: stub `use` so util.lua loads in isolation
----------------------------------------------------------------------

local _makedir_calls, _makedir_ret_ok, _makedir_ret_err
local function reset_makedir( )
    _makedir_calls = { }; _makedir_ret_ok = true; _makedir_ret_err = nil
end
reset_makedir( )
local _makedir_present = true
local _makedir_stub = function( path )
    _makedir_calls[ #_makedir_calls + 1 ] = path
    if _makedir_ret_ok then return true end
    return nil, _makedir_ret_err or "mock makedir fail"
end

local _io_stub      = { open = function( ) return nil, "stubbed io.open" end }
local _adclib_stub  = { isutf8 = function( ) return true end, random_bytes = function( ) return "x" end }
local _unicode_stub = { ascii = { sub = string.sub, gsub = string.gsub }, utf8 = { format = string.format } }
local _out_stub     = { put = function( ) end, error = function( ) end }
local _mem_stub     = { free = function( ) end }

local _real = {
    type = type, load = load, table = table, pairs = pairs, pcall = pcall,
    select = select, ipairs = ipairs, tostring = tostring, tonumber = tonumber,
    loadfile = loadfile, setmetatable = setmetatable,
    io = _io_stub, math = math, string = string, os = os, package = package,
    adclib = _adclib_stub, unicode = _unicode_stub, out = _out_stub, mem = _mem_stub,
}
_G.use = function( name )
    if name == "makedir" then
        assert( _makedir_present, "makedir primitive absent" )   -- mimics init.lua loadscript's assert
        return _makedir_stub
    end
    local v = _real[ name ]
    assert( v ~= nil, "util_makedir_test shim missing dep: use \"" .. name .. "\"" )
    return v
end

local util = assert( loadfile( "core/util.lua" ) )( )
util.init( )

----------------------------------------------------------------------
-- minimal framework
----------------------------------------------------------------------

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-58s got=%q want=%q\n", label, tostring( got ), tostring( want ) ) )
    else
        io.write( "ok   " .. label .. "\n" )
    end
end
local function truthy( label, v ) eq( label, not not v, true ) end

----------------------------------------------------------------------
-- 1. safe_path gate: unsafe paths rejected, primitive NOT called
----------------------------------------------------------------------
reset_makedir( )
do
    local r, e = util.makedir( "../evil" )
    eq( "traversal rejected -> nil", r, nil )
    truthy( "traversal err is a string", type( e ) == "string" and #e > 0 )
end
do local r = util.makedir( "/etc/x" )   ; eq( "absolute posix rejected -> nil", r, nil ) end
do local r = util.makedir( "C:\\x" )    ; eq( "absolute windows rejected -> nil", r, nil ) end
do local r = util.makedir( 42 )         ; eq( "non-string rejected -> nil", r, nil ) end
eq( "primitive NOT called for unsafe paths", #_makedir_calls, 0 )

----------------------------------------------------------------------
-- 2. valid relative path passed through verbatim
----------------------------------------------------------------------
reset_makedir( )
do
    local r = util.makedir( "cfg/geoip" )
    eq( "valid path -> true", r, true )
    eq( "primitive called once", #_makedir_calls, 1 )
    eq( "primitive got the exact path", _makedir_calls[ 1 ], "cfg/geoip" )
end

----------------------------------------------------------------------
-- 3. primitive failure is propagated verbatim
----------------------------------------------------------------------
reset_makedir( )
_makedir_ret_ok = false; _makedir_ret_err = "disk full"
do
    local r, e = util.makedir( "scripts/data" )
    eq( "primitive failure -> nil", r, nil )
    eq( "primitive failure err propagated", e, "disk full" )
end

----------------------------------------------------------------------
-- 4. missing primitive degrades to (nil, err), does NOT throw
----------------------------------------------------------------------
reset_makedir( )
_makedir_present = false
do
    local okc, r, e = pcall( util.makedir, "cfg/geoip" )
    eq( "missing primitive: no throw", okc, true )
    eq( "missing primitive: -> nil", r, nil )
    truthy( "missing primitive: err is a string", type( e ) == "string" and #e > 0 )
end
_makedir_present = true

io.write( string.format( "\nutil_makedir_test: %d passed, %d failed\n", checks - failures, failures ) )
os.exit( failures == 0 and 0 or 1 )
