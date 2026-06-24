--[[

    tests/unit/etc_clientblocker_test.lua

    Unit tests for scripts/etc_clientblocker.lua (#81).

    Exercises every branch of do_add_pattern / do_del_pattern via
    the HTTP API surface (pure-function shape: req -> response),
    the check_clients onConnect listener via a stubbed user
    object, and the +addblocker / +delblocker / +blocker ADC
    handlers via captured etc_hubcommands registrations.

    Run: lua5.4 tests/unit/etc_clientblocker_test.lua
    Exit 0 = all pass, 1 = a failure (CI-friendly).

]]--

----------------------------------------------------------------------
-- stub layer: sandbox globals the plugin reads at file scope
----------------------------------------------------------------------

local _registered = { onStart = nil, onConnect = nil, hub = { }, http = { } }
local _saved_table = nil
local _next_loaded = nil
local _audit_fired = { }
local _reports_sent = { }

local stub_hub = {
    setlistener = function( event, opts, fn )
        _registered[ event ] = fn
    end,
    debug = function( ) end,
    getbot = function( ) return "stub-bot" end,
    import = function( name )
        if name == "etc_hubcommands" then
            return {
                add = function( cmd, fn )
                    _registered.hub[ cmd ] = fn
                    return true
                end,
                has = function( ) return false end,
                list = function( ) return { } end,
            }
        end
        if name == "etc_report" then
            return {
                send = function( activate, hubbot, opchat, llevel, msg )
                    _reports_sent[ #_reports_sent + 1 ] = {
                        activate = activate, hubbot = hubbot, opchat = opchat,
                        llevel = llevel, msg = msg,
                    }
                end,
            }
        end
        if name == "etc_usercommands"  then return nil end
        if name == "cmd_help"          then return nil end
        if name == "bot_opchat"        then return nil end
        return nil
    end,
    escapefrom = function( s ) return s end,
    escapeto   = function( s ) return s end,
    http_register = function( method, path, scope, handler, meta )
        _registered.http[ method .. " " .. path ] = handler
    end,
}

_G.hub = stub_hub
_G.cfg = {
    get = function( key )
        if key == "language" then return "en" end
        if key == "etc_clientblocker_oplevel" then return 80 end
        if key == "etc_clientblocker_default_reason" then return "blocked default" end
        if key == "etc_clientblocker_max_pattern_len" then return 200 end
        if key == "etc_clientblocker_check_levels" then
            return {
                [ 0 ]   = true,  [ 10 ]  = true,  [ 20 ]  = true,
                [ 30 ]  = true,  [ 40 ]  = true,  [ 50 ]  = true,
                [ 55 ]  = false,
                [ 60 ]  = false, [ 70 ]  = false, [ 80 ]  = false,
                [ 100 ] = true,
            }
        end
        if key == "etc_clientblocker_report"        then return true  end
        if key == "etc_clientblocker_report_hubbot" then return false end
        if key == "etc_clientblocker_report_opchat" then return true  end
        if key == "etc_clientblocker_llevel"        then return 60    end
        return nil
    end,
    loadlanguage = function( ) return { }, nil end,
}
_G.util = {
    loadtable = function( )
        local r = _next_loaded
        _next_loaded = nil
        return r
    end,
    savetable = function( tbl )
        _saved_table = tbl
        return true
    end,
    -- REAL util.spairs impl from core/util.lua (intentional copy:
    -- the test must exercise the same mutate-orderedIndex behaviour
    -- so the R1 regression test catches early-return leaks). The
    -- only difference from the core impl is the `k ~= "orderedIndex"`
    -- guard in genOrderedIndex to avoid recursive re-indexing if a
    -- prior leak left the field in place (same as core does in #266
    -- variants but written explicitly here so the test stays
    -- self-contained).
    spairs = ( function( )
        local function genOrderedIndex( tbl )
            local idx = { }
            for k in pairs( tbl ) do
                if k ~= "orderedIndex" then idx[ #idx + 1 ] = k end
            end
            table.sort( idx )
            return idx
        end
        local function orderedNext( tbl, state )
            local key
            if state == nil then
                tbl.orderedIndex = genOrderedIndex( tbl )
                key = tbl.orderedIndex[ 1 ]
            else
                for i = 1, #tbl.orderedIndex do
                    if tbl.orderedIndex[ i ] == state then key = tbl.orderedIndex[ i + 1 ] end
                end
            end
            if key then return key, tbl[ key ] end
            tbl.orderedIndex = nil
            return
        end
        return function( tbl ) return orderedNext, tbl, nil end
    end )( ),
    strip_control_bytes = function( s ) return s end,
}
_G.utf = { match = string.match, format = string.format }
_G.PROCESSED = 1

_G.audit = {
    build = function( action, actor, target, reason, meta )
        return { action = action, actor = actor, target = target,
                 reason = reason, meta = meta }
    end,
    fire = function( ev ) _audit_fired[ #_audit_fired + 1 ] = ev end,
}

----------------------------------------------------------------------
-- minimal test framework
----------------------------------------------------------------------

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-65s got=%q want=%q\n", label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

----------------------------------------------------------------------
-- load plugin + onStart so handlers + patterns_tbl are live
----------------------------------------------------------------------

_next_loaded = { }
local plugin = assert( loadfile( "scripts/etc_clientblocker.lua" ) )( )
assert( _registered.onStart, "onStart not registered" )
assert( _registered.onConnect, "onConnect not registered" )
_registered.onStart( )

local POST   = _registered.http[ "POST /v1/clientblocker" ];               assert( POST,   "POST not registered" )
local GET    = _registered.http[ "GET /v1/clientblocker" ];                assert( GET,    "GET not registered" )
local DELETE = _registered.http[ "DELETE /v1/clientblocker/{pattern}" ];   assert( DELETE, "DELETE not registered" )
local add_h  = _registered.hub.addblocker;                                 assert( add_h,  "+addblocker not registered" )
local del_h  = _registered.hub.delblocker;                                 assert( del_h,  "+delblocker not registered" )
local list_h = _registered.hub.blocker;                                    assert( list_h, "+blocker not registered" )

local function fresh_user( opts )
    opts = opts or { }
    local killed = nil
    local replied = nil
    local function noop( ) end
    return {
        level   = function( ) return opts.level   or 20 end,
        nick    = function( ) return opts.nick    or "tester" end,
        ip      = function( ) return opts.ip      or "1.2.3.4" end,
        version = function( ) return opts.version end,
        reply   = function( _, msg, _ ) replied = msg end,
        kill    = function( _, msg )    killed  = msg end,
    }, function( ) return killed end, function( ) return replied end
end

----------------------------------------------------------------------
-- 1. POST happy path
----------------------------------------------------------------------

do
    _audit_fired = { }
    local r = POST{ body = { pattern = "badclient", reason = "stay out" }, token_label = "alice" }
    eq( "POST happy: status 201",     r.status,         201 )
    eq( "POST happy: action",         r.data.action,    "added" )
    eq( "POST happy: pattern echoed", r.data.pattern,   "badclient" )
    eq( "POST happy: reason echoed",  r.data.reason,    "stay out" )
    eq( "POST happy: resolve hits",   plugin.resolve( "badclient/1.0" ), "stay out" )
    eq( "POST happy: persisted",      _saved_table and _saved_table.badclient, "stay out" )
    eq( "POST happy: audit fired",    #_audit_fired, 1 )
    eq( "POST happy: audit action",   _audit_fired[ 1 ].action, "client.block.add" )
end

----------------------------------------------------------------------
-- 2. POST default reason when omitted
----------------------------------------------------------------------

do
    local r = POST{ body = { pattern = "uglycli" }, token_label = "alice" }
    eq( "POST default reason: status",      r.status,       201 )
    eq( "POST default reason: stored",      plugin.resolve( "uglycli" ), "blocked default" )
    eq( "POST default reason: echo in resp", r.data.reason, "blocked default" )
end

----------------------------------------------------------------------
-- 3. POST reject: bad_pattern (empty)
----------------------------------------------------------------------

do
    local r = POST{ body = { pattern = "" }, token_label = "alice" }
    eq( "bad_pattern empty: status", r.status,     400 )
    eq( "bad_pattern empty: code",   r.error.code, "bad_pattern" )
end

----------------------------------------------------------------------
-- 4. POST reject: bad_pattern (too long)
----------------------------------------------------------------------

do
    -- 250 chars - over the 200 cap but pcall-safe. Mix in `%a`
    -- character classes so the body is a realistic-looking
    -- pattern, not just `aaaaa...`, so the long-cap branch is
    -- exercised independently of the compile-probe branch.
    local long_pat = string.rep( "x%a", 100 )    -- 300 chars
    local r = POST{ body = { pattern = long_pat }, token_label = "alice" }
    eq( "bad_pattern long: status",  r.status,     400 )
    eq( "bad_pattern long: code",    r.error.code, "bad_pattern" )
end

----------------------------------------------------------------------
-- 5. POST reject: bad_pattern (fails compile probe)
----------------------------------------------------------------------

do
    -- Unbalanced bracket - Lua matcher will error on first run.
    local r = POST{ body = { pattern = "[abc" }, token_label = "alice" }
    eq( "bad_pattern compile: status", r.status,     400 )
    eq( "bad_pattern compile: code",   r.error.code, "bad_pattern" )
end

----------------------------------------------------------------------
-- 5b. POST reject: bad_pattern (URL-unsafe chars)
----------------------------------------------------------------------

do
    -- The DELETE endpoint uses the pattern as a path-var; the router
    -- captures with ([^/]+) and does not percent-decode. Patterns
    -- containing any of /?#& must be rejected at POST time so they
    -- never end up un-deletable.
    for _, ch in ipairs( { "/", "?", "#", "&" } ) do
        local r = POST{ body = { pattern = "pat" .. ch .. "x" }, token_label = "alice" }
        eq( "url-unsafe " .. ch .. ": status", r.status,     400 )
        eq( "url-unsafe " .. ch .. ": code",   r.error.code, "bad_pattern" )
    end
end

----------------------------------------------------------------------
-- 6. POST reject: exists
----------------------------------------------------------------------

do
    local r = POST{ body = { pattern = "badclient", reason = "x" }, token_label = "alice" }
    eq( "exists: status", r.status,     409 )
    eq( "exists: code",   r.error.code, "exists" )
    eq( "exists: did not overwrite", plugin.resolve( "badclient" ), "stay out" )
end

----------------------------------------------------------------------
-- 7. GET list
----------------------------------------------------------------------

do
    local r = GET{ }
    eq( "GET: status", r.status,     200 )
    eq( "GET: count",  r.data.count, 2 )
    -- Sorted alphabetically by util.spairs stub.
    eq( "GET: row 1 pattern", r.data.patterns[ 1 ].pattern, "badclient" )
    eq( "GET: row 2 pattern", r.data.patterns[ 2 ].pattern, "uglycli" )
end

----------------------------------------------------------------------
-- 8. DELETE happy path
----------------------------------------------------------------------

do
    _audit_fired = { }
    local r = DELETE{ path_vars = { pattern = "badclient" }, token_label = "alice" }
    eq( "DELETE happy: status",            r.status,         200 )
    eq( "DELETE happy: action",            r.data.action,    "deleted" )
    eq( "DELETE happy: previous reason",   r.data.previous,  "stay out" )
    eq( "DELETE happy: resolve nil",       plugin.resolve( "badclient" ), nil )
    eq( "DELETE happy: audit fired",       #_audit_fired,    1 )
    eq( "DELETE happy: audit action",      _audit_fired[ 1 ].action, "client.block.remove" )
end

----------------------------------------------------------------------
-- 9. DELETE reject: not_found
----------------------------------------------------------------------

do
    local r = DELETE{ path_vars = { pattern = "ghost" }, token_label = "alice" }
    eq( "not_found: status", r.status,     404 )
    eq( "not_found: code",   r.error.code, "not_found" )
end

----------------------------------------------------------------------
-- 10. check_clients onConnect - matching VE on covered level
----------------------------------------------------------------------

do
    -- Add "AirDC%+%+%s2" pattern, then clear the audit log so we
    -- only observe the .kick event from check_clients (the POST
    -- itself fires .add which would otherwise count toward
    -- #_audit_fired).
    POST{ body = { pattern = "AirDC%+%+%s2", reason = "old AirDC" }, token_label = "alice" }
    _audit_fired = { }
    _reports_sent = { }
    local user, killed_of = fresh_user{ level = 20, version = "AirDC++ 2.5.0" }
    local r = _registered.onConnect( user )
    eq( "check covered level: PROCESSED", r,            1 )
    eq( "check covered level: kill issued", killed_of( ) and true or false, true )
    eq( "check covered level: ISTA prefix", killed_of( ) and killed_of( ):sub( 1, 9 ) or "", "ISTA 231 " )
    eq( "check covered level: audit fired", #_audit_fired,                  1 )
    eq( "check covered level: audit action", _audit_fired[ 1 ].action,      "client.block.kick" )
    -- Actor on the kick event is the plugin name (string shorthand
    -- supported by core/audit.lua's _snapshot_actor); the test stub
    -- just forwards the raw value so we assert the string directly.
    eq( "check covered level: audit actor", _audit_fired[ 1 ].actor,        "etc_clientblocker" )
    -- Opchat report fires too (Sopor-imported v0.10 feature).
    eq( "check covered level: report fired",   #_reports_sent,              1 )
    eq( "check covered level: report opchat",  _reports_sent[ 1 ].opchat,   true )
    eq( "check covered level: report hubbot",  _reports_sent[ 1 ].hubbot,   false )
    eq( "check covered level: report contains nick",    ( _reports_sent[ 1 ].msg or "" ):find( "tester", 1, true ) ~= nil, true )
    eq( "check covered level: report contains pattern", ( _reports_sent[ 1 ].msg or "" ):find( "AirDC%+%+%s2", 1, true ) ~= nil, true )
end

----------------------------------------------------------------------
-- 10c. check_clients level-exempt path does NOT fire the report
--      (SBOT level 55 is exempt by default - added in the Sopor
--      import). Regression for the "report fires even on exempt
--      level" hazard.
----------------------------------------------------------------------

do
    _reports_sent = { }
    _audit_fired = { }
    local user, killed_of = fresh_user{ level = 55, version = "AirDC++ 2.5.0" }
    local r = _registered.onConnect( user )
    eq( "SBOT exempt: returns nil",  r,            nil )
    eq( "SBOT exempt: no kill",      killed_of( ), nil )
    eq( "SBOT exempt: no report",    #_reports_sent, 0 )
    eq( "SBOT exempt: no audit",     #_audit_fired,  0 )
end

----------------------------------------------------------------------
-- 10b. check_clients does NOT leak util.spairs `orderedIndex` field
--      into patterns_tbl after the kick early-returns. Regression
--      test for the security review R1 finding. The pre-fix code
--      ran `util_spairs(patterns_tbl)` and `return PROCESSED` mid-
--      iteration, leaving the internal `orderedIndex` array
--      attached to patterns_tbl. The test stub's util.spairs IS
--      the real impl (lifted from core/util.lua) so the leak is
--      observable here.
----------------------------------------------------------------------

do
    -- patterns_tbl currently has "AirDC%+%+%s2" (from test 10). A
    -- match + kick triggers the early-return; we then assert the
    -- internal util.spairs `orderedIndex` artifact did NOT leak
    -- through. Pre-fix code used `util_spairs(patterns_tbl)` +
    -- `return PROCESSED` mid-iteration, which leaked. The fix
    -- snapshot+sort+ipairs sidesteps it.
    local user, _killed_of = fresh_user{ level = 20, version = "AirDC++ 2.5.0" }
    _registered.onConnect( user )
    eq( "orderedIndex leak: not present", plugin.get_patterns_tbl( ).orderedIndex, nil )
end

----------------------------------------------------------------------
-- 11. check_clients onConnect - matching VE on exempt level (OP)
----------------------------------------------------------------------

do
    local user, killed_of = fresh_user{ level = 60, version = "AirDC++ 2.5.0" }
    local r = _registered.onConnect( user )
    eq( "check exempt level: returns nil", r,             nil )
    eq( "check exempt level: no kill",     killed_of( ),  nil )
end

----------------------------------------------------------------------
-- 12. check_clients onConnect - non-matching VE
----------------------------------------------------------------------

do
    local user, killed_of = fresh_user{ level = 20, version = "AirDC++ 4.10" }
    local r = _registered.onConnect( user )
    eq( "check non-match: returns nil", r,            nil )
    eq( "check non-match: no kill",     killed_of( ), nil )
end

----------------------------------------------------------------------
-- 13. check_clients onConnect - nil VE (F-INF-1d guard)
----------------------------------------------------------------------

do
    local user, killed_of = fresh_user{ level = 20, version = nil }
    local r = _registered.onConnect( user )
    eq( "check nil VE: returns nil", r,            nil )
    eq( "check nil VE: no kill",     killed_of( ), nil )
end

----------------------------------------------------------------------
-- 14. ADC: +addblocker happy path
----------------------------------------------------------------------

do
    _audit_fired = { }
    local user, _, replied_of = fresh_user{ level = 80, nick = "admin" }
    add_h( user, "addblocker", "newpattern\\s\\d a kick reason here" )
    -- utf.match (string.match in stubs) splits on first whitespace, so
    -- pattern = "newpattern\\s\\d", reason = "a kick reason here"
    eq( "+addblocker: persisted",  plugin.resolve( "newpattern\\s\\d/1.0" ) ~= nil
                                   or plugin.get_patterns_tbl( )[ "newpattern\\s\\d" ] ~= nil, true )
    eq( "+addblocker: audit",      #_audit_fired, 1 )
    eq( "+addblocker: audit action", _audit_fired[ 1 ].action, "client.block.add" )
    eq( "+addblocker: reply set",  type( replied_of( ) ), "string" )
end

----------------------------------------------------------------------
-- 15. ADC: +addblocker denied (low level)
----------------------------------------------------------------------

do
    _audit_fired = { }
    local user, _, replied_of = fresh_user{ level = 20, nick = "joe" }
    add_h( user, "addblocker", "denypat reason" )
    eq( "+addblocker denied: no persist", plugin.get_patterns_tbl( )[ "denypat" ], nil )
    eq( "+addblocker denied: no audit",   #_audit_fired,    0 )
    eq( "+addblocker denied: reply set",  type( replied_of( ) ), "string" )
end

----------------------------------------------------------------------
-- 16. ADC: +addblocker missing args
----------------------------------------------------------------------

do
    local user, _, replied_of = fresh_user{ level = 80 }
    add_h( user, "addblocker", "" )
    eq( "+addblocker empty: reply set", type( replied_of( ) ), "string" )
end

----------------------------------------------------------------------
-- 17. ADC: +delblocker happy
----------------------------------------------------------------------

do
    _audit_fired = { }
    local user, _, replied_of = fresh_user{ level = 80, nick = "admin" }
    del_h( user, "delblocker", "uglycli" )
    eq( "+delblocker: removed",    plugin.get_patterns_tbl( )[ "uglycli" ], nil )
    eq( "+delblocker: audit",      #_audit_fired, 1 )
    eq( "+delblocker: audit action", _audit_fired[ 1 ].action, "client.block.remove" )
end

----------------------------------------------------------------------
-- 18. ADC: +blocker list reply
----------------------------------------------------------------------

do
    local user, _, replied_of = fresh_user{ level = 80 }
    list_h( user, "blocker", "" )
    eq( "+blocker list: reply set",          type( replied_of( ) ), "string" )
    eq( "+blocker list: contains a pattern", ( replied_of( ) or "" ):find( "AirDC" ) ~= nil, true )
end

----------------------------------------------------------------------
-- 19. resolve() input handling
----------------------------------------------------------------------

eq( "resolve: nil input",    plugin.resolve( nil ),    nil )
eq( "resolve: number input", plugin.resolve( 42 ),     nil )
eq( "resolve: empty string", plugin.resolve( "" ),     nil )

----------------------------------------------------------------------
-- 20. +reload semantic: re-running onStart loads fresh from disk
----------------------------------------------------------------------

do
    -- Simulate operator hand-editing the file between reloads.
    _next_loaded = { manualpat = "from disk" }
    _registered.onStart( )
    eq( "reload: old in-memory map gone", plugin.get_patterns_tbl( )[ "AirDC%+%+%s2" ], nil )
    eq( "reload: new in-memory map live", plugin.get_patterns_tbl( )[ "manualpat" ],    "from disk" )
end

----------------------------------------------------------------------
-- summary
----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures > 0 and 1 or 0 )
