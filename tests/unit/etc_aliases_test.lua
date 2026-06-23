--[[

    tests/unit/etc_aliases_test.lua

    Unit tests for scripts/etc_aliases.lua (#327).

    Exercises every branch of do_add_alias and do_del_alias via
    the HTTP API surface (pure-function shape: req -> response).
    Hits each of the four add-time reject codes (`bad_alias`,
    `conflict_command`, `exists`, `no_target`) and both
    del-time codes (`bad_alias`, `not_found`), plus the
    happy paths.

    Captures the registered HTTP handlers via a hub stub at
    onStart-listener time. The plugin's resolve() export is
    also exercised to confirm a successful POST mutates the
    upvalue that resolve() closes over (and that +reload
    semantics work: re-running onStart loads a fresh on-disk
    file).

    Run: lua5.4 tests/unit/etc_aliases_test.lua
    Exit 0 = all pass, 1 = a failure (CI-friendly).

]]--

----------------------------------------------------------------------
-- stub layer: sandbox globals the plugin reads at file scope
----------------------------------------------------------------------

local _registered = { onStart = nil, http = { } }
local _saved_table = nil    -- last util.savetable call's table
local _next_loaded = nil    -- value returned by next util.loadtable call

local stub_hub = {
    setlistener = function( event, opts, fn )
        _registered[ event ] = fn
    end,
    debug = function( ) end,
    getbot = function( ) return "stub-bot" end,
    import = function( name )
        if name == "etc_hubcommands" then
            return {
                add = function( ) return true end,
                has = function( cmd )
                    -- The set of commands we pretend exist for these tests.
                    -- The test exercises the conflict_command branch via
                    -- "topic" (already a real command) and the no_target
                    -- branch via "missingcmd" (not in this set).
                    local real = { topic = true, usersearch = true, ban = true,
                                   addalias = true, delalias = true, aliases = true }
                    return real[ cmd ] ~= nil
                end,
                list = function( )
                    return {
                        { name = "topic", fn = function( ) end },
                        { name = "usersearch", fn = function( ) end },
                    }
                end,
            }
        end
        if name == "etc_report" then
            return { send = function( ) end }
        end
        if name == "cmd_help" then return nil end
        if name == "etc_usercommands" then return nil end
        if name == "bot_opchat" then return nil end
        return nil
    end,
    http_register = function( method, path, scope, handler, meta )
        _registered.http[ method .. " " .. path ] = handler
    end,
}

_G.hub = stub_hub
_G.cfg = {
    get = function( key )
        if key == "language" then return "en" end
        if key == "etc_aliases_minlevel" then return 80 end
        if key == "etc_aliases_report" then return true end
        if key == "etc_aliases_report_hubbot" then return false end
        if key == "etc_aliases_report_opchat" then return true end
        if key == "etc_aliases_llevel" then return 60 end
        return nil
    end,
    loadlanguage = function( ) return { }, nil end,
}
_G.util = {
    loadtable = function( path )
        local r = _next_loaded
        _next_loaded = nil
        return r
    end,
    savetable = function( tbl, varname, path )
        _saved_table = tbl
        return true
    end,
    spairs = function( t )
        local keys = { }
        for k in pairs( t ) do keys[ #keys + 1 ] = k end
        table.sort( keys )
        local i = 0
        return function( )
            i = i + 1
            if keys[ i ] then return keys[ i ], t[ keys[ i ] ] end
        end
    end,
    strip_control_bytes = function( s ) return s end,
}
_G.utf = { match = string.match, format = string.format }
_G.PROCESSED = 1

-- #84: etc_aliases now fires audit events via the core `audit`
-- module. Stub with no-op so the unit test stays free of the
-- core load order; the audit pipeline is covered by the smoke
-- harness's end-to-end test.
_G.audit = {
    build = function( ) return { } end,
    fire  = function( ) end,
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
-- load plugin + invoke onStart so HTTP handlers + aliases_tbl are live
----------------------------------------------------------------------

_next_loaded = { }    -- empty on-disk file
local plugin = assert( loadfile( "scripts/etc_aliases.lua" ) )( )
assert( _registered.onStart, "onStart listener was not registered" )
_registered.onStart( )

local POST   = _registered.http[ "POST /v1/aliases" ];        assert( POST,   "POST /v1/aliases not registered" )
local GET    = _registered.http[ "GET /v1/aliases" ];         assert( GET,    "GET /v1/aliases not registered" )
local DELETE = _registered.http[ "DELETE /v1/aliases/{alias}" ]; assert( DELETE, "DELETE /v1/aliases/{alias} not registered" )

----------------------------------------------------------------------
-- 1. POST happy path
----------------------------------------------------------------------

do
    local r = POST{ body = { alias = "us", target = "usersearch" }, token_label = "test" }
    eq( "POST happy: status 201",     r.status,        201 )
    eq( "POST happy: action='added'", r.data.action,   "added" )
    eq( "POST happy: alias",          r.data.alias,    "us" )
    eq( "POST happy: target",         r.data.target,   "usersearch" )
    eq( "POST happy: resolve()",      plugin.resolve( "us" ), "usersearch" )
    eq( "POST happy: persisted",      _saved_table and _saved_table.usersearch[ 1 ], "us" )
end

----------------------------------------------------------------------
-- 2. POST reject: bad_alias (digits)
----------------------------------------------------------------------

do
    local r = POST{ body = { alias = "us2", target = "usersearch" }, token_label = "test" }
    eq( "bad_alias: status 400",  r.status,      400 )
    eq( "bad_alias: code",        r.error.code,  "bad_alias" )
end

----------------------------------------------------------------------
-- 3. POST reject: bad_alias (empty alias)
----------------------------------------------------------------------

do
    local r = POST{ body = { alias = "", target = "usersearch" }, token_label = "test" }
    eq( "bad_alias empty: status 400", r.status,     400 )
    eq( "bad_alias empty: code",       r.error.code, "bad_alias" )
end

----------------------------------------------------------------------
-- 4. POST reject: conflict_command (alias is real cmd)
----------------------------------------------------------------------

do
    local r = POST{ body = { alias = "topic", target = "usersearch" }, token_label = "test" }
    eq( "conflict_command: status 409", r.status,     409 )
    eq( "conflict_command: code",       r.error.code, "conflict_command" )
end

----------------------------------------------------------------------
-- 5. POST reject: exists (alias already mapped)
----------------------------------------------------------------------

do
    -- `us` was added in test 1.
    local r = POST{ body = { alias = "us", target = "ban" }, token_label = "test" }
    eq( "exists: status 409", r.status,     409 )
    eq( "exists: code",       r.error.code, "exists" )
    eq( "exists: did not overwrite", plugin.resolve( "us" ), "usersearch" )
end

----------------------------------------------------------------------
-- 6. POST reject: no_target (target not a real cmd)
----------------------------------------------------------------------

do
    local r = POST{ body = { alias = "xx", target = "missingcmd" }, token_label = "test" }
    eq( "no_target: status 404", r.status,     404 )
    eq( "no_target: code",       r.error.code, "no_target" )
    eq( "no_target: not created", plugin.resolve( "xx" ), nil )
end

----------------------------------------------------------------------
-- 7. GET list
----------------------------------------------------------------------

do
    -- Add a second alias so we can confirm the list is sorted.
    POST{ body = { alias = "t", target = "topic" }, token_label = "test" }
    local r = GET{ }
    eq( "GET: status 200", r.status,     200 )
    eq( "GET: count",      r.data.count, 2 )
    eq( "GET: row 1 alias",  r.data.aliases[ 1 ].alias,  "t" )
    eq( "GET: row 1 target", r.data.aliases[ 1 ].target, "topic" )
    eq( "GET: row 2 alias",  r.data.aliases[ 2 ].alias,  "us" )
    eq( "GET: row 2 target", r.data.aliases[ 2 ].target, "usersearch" )
end

----------------------------------------------------------------------
-- 8. DELETE happy path
----------------------------------------------------------------------

do
    local r = DELETE{ path_vars = { alias = "us" }, token_label = "test" }
    eq( "DELETE happy: status 200",     r.status,         200 )
    eq( "DELETE happy: action",         r.data.action,    "deleted" )
    eq( "DELETE happy: previous",       r.data.previous,  "usersearch" )
    eq( "DELETE happy: resolve() nil",  plugin.resolve( "us" ), nil )
end

----------------------------------------------------------------------
-- 9. DELETE reject: not_found
----------------------------------------------------------------------

do
    local r = DELETE{ path_vars = { alias = "doesnotexist" }, token_label = "test" }
    eq( "not_found: status 404", r.status,     404 )
    eq( "not_found: code",       r.error.code, "not_found" )
end

----------------------------------------------------------------------
-- 10. DELETE reject: bad_alias
----------------------------------------------------------------------

do
    local r = DELETE{ path_vars = { alias = "u1" }, token_label = "test" }
    eq( "DELETE bad_alias: status 400", r.status,     400 )
    eq( "DELETE bad_alias: code",       r.error.code, "bad_alias" )
end

----------------------------------------------------------------------
-- 11. resolve() returns nil for unknown name + non-string input
----------------------------------------------------------------------

eq( "resolve: nil for unknown",   plugin.resolve( "ghost" ), nil )
eq( "resolve: nil for nil input", plugin.resolve( nil ),     nil )
eq( "resolve: nil for number",    plugin.resolve( 42 ),      nil )

----------------------------------------------------------------------
-- 12. +reload semantic: re-running onStart reloads from disk
----------------------------------------------------------------------

do
    -- Simulate the operator hand-editing the file between reloads.
    _next_loaded = { ban = { "b" } }
    _registered.onStart( )    -- fires +reload listener-chain re-entry
    eq( "reload: old `t` is gone",  plugin.resolve( "t" ), nil )
    eq( "reload: new `b` is live",  plugin.resolve( "b" ), "ban" )
    eq( "reload: get_aliases_tbl reflects new map",
        plugin.get_aliases_tbl( ).b, "ban" )
end

----------------------------------------------------------------------
-- summary
----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures > 0 and 1 or 0 )
