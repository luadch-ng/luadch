--[[

    tests/unit/etc_backup_schedule_test.lua

    Unit tests for scripts/etc_backup.lua's pure schedule math (_next_daily,
    _compute_next), loaded with stubbed sandbox globals. The command
    dispatch, owner nag and the actual backup run are covered by the backup
    smoke test (hub boots with etc_backup, +backup now produces an artifact).

    Run: lua5.4 tests/unit/etc_backup_schedule_test.lua   (exit 0 = pass)

]]--

-- Stub the sandbox globals the plugin binds at load. Assigning without
-- `local` sets the real global the plugin's `local x = x` then captures.
local _noop = function( ) end
cfg     = { get = function( ) return nil end, loadlanguage = function( ) return { }, nil end }
hub     = { debug = _noop, getbot = function( ) return { } end, getusers = function( ) return { } end,
            setlistener = _noop, import = function( ) return nil end }
backup  = { readiness = function( ) return { ok = true, issues = { } } end,
            run = function( ) end, list = function( ) return { } end }
audit   = { build = function( ) return { } end, fire = _noop }
secrets = { register = _noop, lookup = function( ) return nil end }
util    = { loadtable = function( ) return nil end, savetable = _noop }
utf     = string
PROCESSED = true

local E = assert( loadfile( "scripts/etc_backup.lua" ) )( )

local passes, fails = 0, 0
local function ok( label, cond )
    if cond then passes = passes + 1
    else fails = fails + 1; io.stderr:write( "FAIL: " .. label .. "\n" ) end
end
local function eq( label, got, want )
    if got == want then passes = passes + 1
    else fails = fails + 1
        io.stderr:write( string.format( "FAIL: %s\n  got:  %s\n  want: %s\n", label, tostring( got ), tostring( want ) ) )
    end
end

----------------------------------------------------------------------
-- _next_daily: valid HH:MM -> next local occurrence strictly after now
----------------------------------------------------------------------

local now = os.time( )   -- real local time
do
    local n = E._next_daily( now, "04:00" )
    ok( "04:00 -> a time",            type( n ) == "number" )
    ok( "04:00 -> strictly future",   n and n > now )
    ok( "04:00 -> within 24h",        n and n <= now + 86400 )
    eq( "04:00 -> lands on 04:00 local", n and os.date( "%H:%M", n ), "04:00" )

    -- a time one minute in the future today should be today (not +24h)
    local soon = os.date( "*t", now + 120 )
    local hhmm = string.format( "%02d:%02d", soon.hour, soon.min )
    local n2 = E._next_daily( now, hhmm )
    ok( "near-future HH:MM is today (<= 2min away)", n2 and n2 - now <= 120 and n2 > now )
end

-- invalid inputs -> nil (caller falls back to interval)
eq( "empty -> nil",       E._next_daily( now, "" ),      nil )
eq( "bad format -> nil",  E._next_daily( now, "4pm" ),   nil )
eq( "hour 25 -> nil",     E._next_daily( now, "25:00" ), nil )
eq( "min 60 -> nil",      E._next_daily( now, "04:60" ), nil )
eq( "non-string -> nil",  E._next_daily( now, 400 ),     nil )

----------------------------------------------------------------------
-- _compute_next: daily wins; else interval from anchor; overdue fires now
----------------------------------------------------------------------

-- interval mode (daily empty)
eq( "interval from anchor",  E._compute_next( 1000, 500, "", 3600 ), 4100 )   -- 500 + 3600
eq( "interval from now (no anchor)", E._compute_next( 1000, nil, "", 3600 ), 4600 )   -- 1000 + 3600
eq( "overdue interval -> now", E._compute_next( 10000, 500, "", 3600 ), 10000 )   -- 500+3600 <= now
eq( "interval 0 -> nil",     E._compute_next( 1000, 500, "", 0 ),    nil )
eq( "no schedule -> nil",    E._compute_next( 1000, 500, "", nil ),  nil )

-- daily wins over interval when both set
do
    local n = E._compute_next( now, now, "04:00", 3600 )
    eq( "daily wins over interval", n and os.date( "%H:%M", n ), "04:00" )
end

-- invalid daily falls through to interval
eq( "bad daily -> interval fallback", E._compute_next( 1000, 500, "nope", 3600 ), 4100 )

if fails > 0 then
    io.stderr:write( string.format( "\nFAIL: %d/%d checks failed\n", fails, passes + fails ) )
    os.exit( 1 )
end
print( string.format( "OK: %d checks passed", passes ) )
