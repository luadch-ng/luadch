--[[

    tests/unit/cfg_lang_dualformat_test.lua

    Unit tests for core/cfg_lang.lua's dual-format `loadlanguage` (#301
    P3, lang Lua->JSON / Weblate migration). This locks the migration
    contract: loadlanguage probes the JSON path FIRST and falls back to
    the legacy Lua table (.tbl for core, .lang.X for plugins) only when
    the JSON is absent, so the migration can proceed file by file without
    a flag day.

    It drives the real loadlanguage against a FAKE util that records the
    exact paths and order of loadjsontable / loadtable calls and returns
    controllable fixtures. That isolates the DECISION logic (which format,
    which path, in which order) from real file I/O - the JSON parsing and
    silent-missing behaviour of util.loadjsontable itself is covered by
    util_loadjsontable_test.lua.

    Provably fails pre-fix (CLAUDE.md §1a.7): master's loadlanguage never
    calls loadjsontable and builds a single combined path, so the
    "probes JSON first" and JSON-path assertions are RED on master and
    GREEN patched.

    Run: lua5.4 tests/unit/cfg_lang_dualformat_test.lua   (from repo root)
    Exit 0 = all pass, 1 = a failure (CI-friendly).

]]--

----------------------------------------------------------------------
-- fake util: records calls, returns fixtures keyed by path
----------------------------------------------------------------------

local _json_files  = { }    -- path -> table (present) ; absent = "not found"
local _json_errors = { }    -- path -> err string (present-but-malformed)
local _lua_files   = { }    -- path -> table (present) ; absent = err
local _calls       = { }    -- ordered log of { fn=..., path=... }

local _fake_util = {
    loadjsontable = function( path )
        _calls[ #_calls + 1 ] = { fn = "json", path = path }
        if _json_errors[ path ] then return nil, _json_errors[ path ] end
        local t = _json_files[ path ]
        if t == nil then return nil, "not found" end
        return t, nil
    end,
    loadtable = function( path )
        _calls[ #_calls + 1 ] = { fn = "lua", path = path }
        local t = _lua_files[ path ]
        if t == nil then return nil, "no such file" end
        return t, nil
    end,
}

local _out_error_calls = 0
local _out_stub = { error = function( ) _out_error_calls = _out_error_calls + 1 end }

local _real = {
    util = _fake_util,
    tostring = tostring,
    out = _out_stub,
}
_G.use = function( name )
    local v = _real[ name ]
    assert( v ~= nil, "cfg_lang_dualformat_test shim missing dep: use \"" .. name .. "\"" )
    return v
end

local cfg_lang = assert( loadfile( "core/cfg_lang.lua" ) )( )
cfg_lang.bind_late( )

local CORE    = "lang/"
local SCRIPTS = "scripts/lang/"

local function reset( )
    _json_files, _json_errors, _lua_files, _calls, _out_error_calls = { }, { }, { }, { }, 0
end

----------------------------------------------------------------------
-- minimal test framework
----------------------------------------------------------------------

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-60s got=%q want=%q\n",
            label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

----------------------------------------------------------------------
-- 1. core, JSON present -> JSON wins, loadtable NOT consulted
----------------------------------------------------------------------

do
    reset( )
    _json_files[ "lang/en.json" ] = { hub_hub_is_full = "Hub is full." }
    local t, err = cfg_lang.loadlanguage( "en", nil, CORE, SCRIPTS )
    eq( "core/json: value from JSON",        t.hub_hub_is_full, "Hub is full." )
    eq( "core/json: err nil",                err, nil )
    eq( "core/json: exactly one loader call", #_calls, 1 )
    eq( "core/json: probed the JSON path",   _calls[ 1 ] and _calls[ 1 ].fn, "json" )
    eq( "core/json: JSON path is lang/en.json",
        _calls[ 1 ] and _calls[ 1 ].path, "lang/en.json" )
    eq( "core/json: no error logged",        _out_error_calls, 0 )
end

----------------------------------------------------------------------
-- 2. core, JSON absent -> falls back to .tbl; JSON probed FIRST
----------------------------------------------------------------------

do
    reset( )
    _lua_files[ "lang/en.tbl" ] = { hub_hub_is_full = "from tbl" }
    local t, err = cfg_lang.loadlanguage( "en", nil, CORE, SCRIPTS )
    eq( "core/fallback: value from .tbl",    t.hub_hub_is_full, "from tbl" )
    eq( "core/fallback: err nil",            err, nil )
    eq( "core/fallback: two loader calls",   #_calls, 2 )
    eq( "core/fallback: JSON probed first",  _calls[ 1 ] and _calls[ 1 ].fn, "json" )
    eq( "core/fallback: JSON path first",    _calls[ 1 ] and _calls[ 1 ].path, "lang/en.json" )
    eq( "core/fallback: .tbl probed second", _calls[ 2 ] and _calls[ 2 ].fn, "lua" )
    eq( "core/fallback: .tbl path is lang/en.tbl", _calls[ 2 ] and _calls[ 2 ].path, "lang/en.tbl" )
    eq( "core/fallback: no error logged",    _out_error_calls, 0 )
end

----------------------------------------------------------------------
-- 3. plugin, JSON present -> path is <scripts><name>.lang.<lng>.json
----------------------------------------------------------------------

do
    reset( )
    _json_files[ "scripts/lang/cmd_reg.lang.en.json" ] = { msg_ok = "ok" }
    local t = cfg_lang.loadlanguage( "en", "cmd_reg", CORE, SCRIPTS )
    eq( "plugin/json: value from JSON",      t.msg_ok, "ok" )
    eq( "plugin/json: JSON path shape",
        _calls[ 1 ] and _calls[ 1 ].path, "scripts/lang/cmd_reg.lang.en.json" )
    eq( "plugin/json: one call only",        #_calls, 1 )
end

----------------------------------------------------------------------
-- 4. plugin, JSON absent -> falls back to legacy .lang.<lng>
----------------------------------------------------------------------

do
    reset( )
    _lua_files[ "scripts/lang/cmd_reg.lang.de" ] = { msg_ok = "ok-de" }
    local t = cfg_lang.loadlanguage( "de", "cmd_reg", CORE, SCRIPTS )
    eq( "plugin/fallback: value from .lang.de", t.msg_ok, "ok-de" )
    eq( "plugin/fallback: JSON probed first", _calls[ 1 ] and _calls[ 1 ].fn, "json" )
    eq( "plugin/fallback: JSON path shape",
        _calls[ 1 ] and _calls[ 1 ].path, "scripts/lang/cmd_reg.lang.de.json" )
    eq( "plugin/fallback: legacy path shape",
        _calls[ 2 ] and _calls[ 2 ].path, "scripts/lang/cmd_reg.lang.de" )
end

----------------------------------------------------------------------
-- 4b. JSON present but MALFORMED -> falls back to the legacy .tbl.
--     Locks the `if not ret` fallback semantics: a present-but-corrupt
--     .json (loadjsontable returns nil + a parse error, not "not found")
--     must still hand off to the Lua table. Guards against a future
--     refactor narrowing the guard to `if err == "not found"`.
----------------------------------------------------------------------

do
    reset( )
    _json_errors[ "lang/en.json" ] = "json parse error"    -- present but corrupt
    _lua_files[ "lang/en.tbl" ]    = { hub_hub_is_full = "from tbl" }
    local t, err = cfg_lang.loadlanguage( "en", nil, CORE, SCRIPTS )
    eq( "malformed-json: value from .tbl fallback", t.hub_hub_is_full, "from tbl" )
    eq( "malformed-json: JSON probed first",  _calls[ 1 ] and _calls[ 1 ].fn, "json" )
    eq( "malformed-json: .tbl probed second", _calls[ 2 ] and _calls[ 2 ].fn, "lua" )
    eq( "malformed-json: err from good .tbl is nil", err, nil )
end

----------------------------------------------------------------------
-- 5. both absent -> returns an (empty) table, never nil; err surfaced
----------------------------------------------------------------------

do
    reset( )
    local t, err = cfg_lang.loadlanguage( "en", "missing_plugin", CORE, SCRIPTS )
    eq( "both-absent: still returns a table", type( t ), "table" )
    eq( "both-absent: table is empty",        next( t ), nil )
    eq( "both-absent: err is a string",       type( err ), "string" )
    eq( "both-absent: error was logged",      _out_error_calls >= 1, true )
end

----------------------------------------------------------------------
-- summary
----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures > 0 and 1 or 0 )
