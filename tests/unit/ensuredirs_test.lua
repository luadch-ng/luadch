--[[

    tests/unit/ensuredirs_test.lua

    Unit tests for core/ensuredirs.lua (#78 follow-up: boot-time runtime-
    directory self-heal). Verifies ensure() makedir's every fixed runtime
    dir - including cfg/geoip/, which nothing else creates - and degrades
    cleanly when the makedir primitive is absent (standalone lua / an
    older launcher) instead of throwing at boot.

    Run: lua5.4 tests/unit/ensuredirs_test.lua

]]--

local _made               -- captured makedir calls for the current case

local _real = {
    type = type, pcall = pcall, ipairs = ipairs,
    makedir = function( path ) _made[ #_made + 1 ] = path; return true end,
}
-- mimic init.lua's use(): an absent name throws (loadscript assert).
-- ensure() pcall-wraps use"makedir" precisely so an absent primitive
-- degrades to (nil, err) rather than aborting the boot.
_G.use = function( name )
    local v = _real[ name ]
    if v == nil then error( "use: missing " .. name ) end
    return v
end

local ed = assert( loadfile( "core/ensuredirs.lua" ) )( )

local failures, checks = 0, 0
local function ok( label, cond )
    checks = checks + 1
    if cond then io.write( "ok   " .. label .. "\n" )
    else failures = failures + 1; io.write( "FAIL " .. label .. "\n" ) end
end

local function list_has( list, p )
    for _, x in ipairs( list ) do if x == p then return true end end
    return false
end

----------------------------------------------------------------------
-- 1. ensure() creates every fixed runtime dir
----------------------------------------------------------------------
do
    _made = { }
    local result = ed.ensure( )
    ok( "creates log/",          list_has( _made, "log" ) )
    ok( "creates cfg/",          list_has( _made, "cfg" ) )
    ok( "creates certs/",        list_has( _made, "certs" ) )
    ok( "creates scripts/data/", list_has( _made, "scripts/data" ) )
    ok( "creates cfg/geoip/ (nothing else does)", list_has( _made, "cfg/geoip" ) )
    ok( "result marks each dir true", result and result[ "cfg/geoip" ] == true )
    ok( "exactly the _DIRS set was created", #_made == #ed._DIRS )
end

----------------------------------------------------------------------
-- 2. cfg/geoip is in the canonical _DIRS list (the gap this closes)
----------------------------------------------------------------------
do
    ok( "_DIRS includes cfg/geoip", list_has( ed._DIRS, "cfg/geoip" ) )
    ok( "_DIRS includes log",       list_has( ed._DIRS, "log" ) )
end

----------------------------------------------------------------------
-- 3. degrade cleanly when the makedir primitive is absent
----------------------------------------------------------------------
do
    local saved = _real.makedir
    _real.makedir = nil        -- use"makedir" now throws -> ensure() pcall catches
    _made = { }
    local r, err = ed.ensure( )
    ok( "degrades to nil when primitive absent", r == nil )
    ok( "degrade err mentions unavailable", tostring( err ):match( "unavailable" ) ~= nil )
    _real.makedir = saved
end

----------------------------------------------------------------------
-- 4. a per-dir makedir failure does not abort the rest
----------------------------------------------------------------------
do
    _made = { }
    _real.makedir = function( path )
        _made[ #_made + 1 ] = path
        if path == "certs" then return nil, "permission denied" end
        return true
    end
    local result = ed.ensure( )
    ok( "one dir failing still attempts every dir", #_made == #ed._DIRS )
    ok( "failed dir recorded as its errmsg", result[ "certs" ] == "permission denied" )
    ok( "other dirs still marked true", result[ "log" ] == true )
    _real.makedir = function( path ) _made[ #_made + 1 ] = path; return true end
end

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
