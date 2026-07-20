--[[

    tests/unit/hub_runtime_migration_test.lua

    Regression tests for scripts/hub_runtime.lua v0.10 (#445): the persisted
    hub-runtime store moved from `core/hci.lua` (a SHIPPED directory - every
    `cmake --install` / Docker image update wrote a pristine `hubruntime = 0`
    over the operator's accumulated value) to `scripts/data/hub_runtime.tbl`
    (operator-owned, upgrade-safe). The load-time migration adopts a legacy
    value so the fix itself does not zero the counter.

    Two layers are tested:

      1. The pure decision `_runtime_seed(existing, legacy)` (exported test
         seam): no-op when the new store is valid, adopt-legacy when the new
         store is absent, zeros when neither exists.

      2. The load-time side effect (migrate_or_init runs on `loadfile`):
         with a controllable in-memory filesystem, loading the plugin writes
         the migrated value to the NEW path and never to the legacy path.

    Provably fails pre-fix: on v0.9 the module reads/writes `core/hci.lua`,
    has no `scripts/data/hub_runtime.tbl` path, no migration, and no
    `_runtime_seed` export - every assertion below errors or mismatches.

    Plugins get NO `use`; every dependency is a sandbox-global stub.

    Run: lua5.4 tests/unit/hub_runtime_migration_test.lua

]]--

----------------------------------------------------------------------
-- tiny harness
----------------------------------------------------------------------
local checks, failures = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then failures = failures + 1
        io.write( string.format( "FAIL %-54s got=%s want=%s\n", label, tostring( got ), tostring( want ) ) )
    else io.write( "ok   " .. label .. "\n" ) end
end
local function is_nil( label, got )
    checks = checks + 1
    if got ~= nil then failures = failures + 1
        io.write( string.format( "FAIL %-54s got=%s want=nil\n", label, tostring( got ) ) )
    else io.write( "ok   " .. label .. "\n" ) end
end

local NEW_PATH    = "scripts/data/hub_runtime.tbl"
local LEGACY_PATH = "core/hci.lua"

----------------------------------------------------------------------
-- controllable in-memory filesystem the util stubs close over
----------------------------------------------------------------------
local _files          -- path -> table (nil = "file absent")
local _writes         -- path -> table (what savetable last wrote)
local _legacy_reads   -- # times the legacy core/hci.lua was touched at load

local _real_os = os

_G.type = type; _G.pairs = pairs; _G.tonumber = tonumber; _G.tostring = tostring
_G.string = string; _G.table = table; _G.math = math
_G.PROCESSED = "PROCESSED"
_G.utf = { match = function( ) end, format = function( ) return "" end }
_G.os = setmetatable( { time = function( ) return 1000 end }, { __index = _real_os } )
_G.signal = { get = function( ) return 0 end }

_G.cfg = {
    get = function( k )
        if k == "language" then return "en" end
        return nil                         -- every other cfg key: harmless nil
    end,
    loadlanguage = function( ) return { }, nil end,
}

_G.util = {
    -- path-aware: returns the in-memory table for that path, or nil (absent)
    loadtable = function( path )
        if path == LEGACY_PATH then _legacy_reads = _legacy_reads + 1 end
        return _files[ path ]
    end,
    -- record the write AND reflect it into the fs so a re-read sees it
    savetable = function( t, _name, path ) _writes[ path ] = t; _files[ path ] = t end,
    date          = function( ) return "20260718120000" end,
    difftime      = function( ) return 0, 0, 0, 0, 0, 0 end,
    formatseconds = function( ) return 0, 0, 0, 0, 0 end,
    convertepochdate = function( x ) return x end,
}

-- migrate_or_init (v0.11) probes the legacy file's existence with io.open
-- before loadtable, so a missing core/hci.lua logs nothing. Model presence
-- via _files and count every legacy touch so the "steady state never reads
-- legacy" assertion below can prove the no-boot-noise fix.
local _real_io_open = io.open
io.open = function( path, mode )
    if path == LEGACY_PATH then
        _legacy_reads = _legacy_reads + 1
        if _files[ path ] ~= nil then return { close = function( ) end } end
        return nil, "no such file"
    end
    return _real_io_open( path, mode )
end

_G.hub = {
    setlistener   = function( ) end,       -- listeners captured but never fired here
    import        = function( ) return nil end,
    debug         = function( ) end,
    http_register = function( ) end,
    getbot        = function( ) return { } end,
}

----------------------------------------------------------------------
-- load the plugin fresh against the current fs; returns its export table
----------------------------------------------------------------------
local function load_plugin( )
    _writes = { }
    _legacy_reads = 0
    return assert( loadfile( "scripts/hub_runtime.lua" ) )( )
end

----------------------------------------------------------------------
-- Layer 1: the pure decision _runtime_seed(existing, legacy)
----------------------------------------------------------------------
_files = { }
local plugin = load_plugin( )
-- Guard so the pre-#445 module (no return / no export) fails cleanly here
-- instead of erroring on a nil-index below.
if type( plugin ) ~= "table" or type( plugin._runtime_seed ) ~= "function" then
    io.write( "FAIL hub_runtime.lua does not export _runtime_seed - pre-#445 module?\n" )
    os.exit( 1 )
end
local seed = plugin._runtime_seed
eq( "export _runtime_seed is a function", type( seed ), "function" )

-- new store already valid -> no-op (do NOT re-adopt legacy, even a bigger one)
is_nil( "valid new store -> nil (no-op)",
    seed( { hubruntime = 42, hubruntime_last_check = 7 }, { hubruntime = 999 } ) )
-- a zero-but-valid new store is still valid -> keep it (a legit reset stays reset)
is_nil( "new store hubruntime=0 is valid -> nil",
    seed( { hubruntime = 0, hubruntime_last_check = 0 }, { hubruntime = 999 } ) )

-- new store absent, legacy has a value -> adopt it (the upgrade path)
local s = seed( nil, { hubruntime = 123456, hubruntime_last_check = 77 } )
eq( "adopt legacy hubruntime", s and s.hubruntime, 123456 )
eq( "adopt legacy last_check", s and s.hubruntime_last_check, 77 )

-- legacy present but last_check missing -> hubruntime adopted, last_check 0
local s2 = seed( nil, { hubruntime = 55 } )
eq( "adopt legacy, default last_check", s2 and s2.hubruntime_last_check, 0 )

-- neither present -> zeros (fresh hub)
local s3 = seed( nil, nil )
eq( "fresh hub -> hubruntime 0", s3 and s3.hubruntime, 0 )

-- CLOBBERED LEGACY: new absent, legacy present but already zeroed. This is
-- what a `cmake --install` WITHOUT the CMakeLists `PATTERN "hci.lua" EXCLUDE`
-- would produce - the install overwrites the operator's core/hci.lua with
-- shipped zeros before the hub boots, so the migration would adopt 0 and
-- recover nothing. runtime_seed is correct in isolation (a zero legacy
-- yields zeros); the CMake exclusion is what keeps the legacy non-zero at
-- boot. Documented here so the two halves of the fix stay tied together.
local s_clobber = seed( nil, { hubruntime = 0, hubruntime_last_check = 0 } )
eq( "clobbered legacy (no CMake exclude) -> 0, recovers nothing", s_clobber and s_clobber.hubruntime, 0 )

-- corrupt new store (not a table) is treated as absent -> migrate
local s4 = seed( "garbage", { hubruntime = 9 } )
eq( "corrupt new store -> adopt legacy", s4 and s4.hubruntime, 9 )
-- corrupt legacy (hubruntime not a number) -> zeros, no crash
local s5 = seed( nil, { hubruntime = "oops" } )
eq( "corrupt legacy -> zeros", s5 and s5.hubruntime, 0 )

----------------------------------------------------------------------
-- Layer 2: migrate_or_init side effect on plugin load
----------------------------------------------------------------------

-- (a) UPGRADE: legacy core/hci.lua has a value, new store absent.
--     Loading the plugin must write the value to the NEW path only.
_files = { [ LEGACY_PATH ] = { hubruntime = 88888, hubruntime_last_check = 5 } }
load_plugin( )
eq( "upgrade: new store written with migrated value", _writes[ NEW_PATH ] and _writes[ NEW_PATH ].hubruntime, 88888 )
is_nil( "upgrade: legacy file never written", _writes[ LEGACY_PATH ] )
eq( "upgrade: new store now holds the value", _files[ NEW_PATH ].hubruntime, 88888 )

-- (b) STEADY STATE: new store already present. Loading must NOT rewrite it
--     and must NOT re-adopt the (stale) legacy value.
_files = {
    [ NEW_PATH ]    = { hubruntime = 200, hubruntime_last_check = 9 },
    [ LEGACY_PATH ] = { hubruntime = 999999, hubruntime_last_check = 1 },
}
load_plugin( )
is_nil( "steady state: new store not rewritten", _writes[ NEW_PATH ] )
eq( "steady state: value preserved", _files[ NEW_PATH ].hubruntime, 200 )
-- #445 follow-up (the no-boot-noise fix): with a valid new store the
-- legacy core/hci.lua must NEVER be read/probed. Pre-fix migrate_or_init
-- read it unconditionally on every boot, and util.loadtable logs a
-- "checkfile: No such file" error for a missing one. Red on v0.10.
eq( "steady state: legacy file never touched (no boot-time log noise)", _legacy_reads, 0 )

-- (c) FRESH HUB: neither file exists. Loading seeds zeros at the new path.
_files = { }
load_plugin( )
eq( "fresh: new store seeded to 0", _writes[ NEW_PATH ] and _writes[ NEW_PATH ].hubruntime, 0 )
is_nil( "fresh: legacy never written", _writes[ LEGACY_PATH ] )

----------------------------------------------------------------------
io.write( string.format( "\n%d/%d checks passed\n", checks - failures, checks ) )
if failures > 0 then io.write( "FAIL hub_runtime_migration_test\n" ); os.exit( 1 ) end
io.write( "OK hub_runtime_migration_test\n" )
