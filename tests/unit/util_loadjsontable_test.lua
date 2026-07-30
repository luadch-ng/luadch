--[[

    tests/unit/util_loadjsontable_test.lua

    Unit tests for core/util.lua's `loadjsontable` helper (#301 P3, the
    lang Lua->JSON / Weblate migration). loadjsontable is the sandboxed
    JSON reader the dual-format language loader (cfg_lang.loadlanguage)
    probes first before falling back to the legacy .tbl / .lang.X.

    The four properties that matter, and why:

      1. A valid JSON object decodes to a Lua table with values intact -
         including a value carrying real newlines and a `%s` format
         specifier, because lang strings are format templates and a
         translation tool must not mangle them.
      2. A MISSING file returns (nil, "not found") and does NOT log. The
         migration is incremental: every not-yet-converted lang file
         probes a .json that is absent, on every boot and +reload. If
         that probe logged, error.log would fill with hundreds of lines
         of non-errors. This is the whole reason loadjsontable exists
         instead of a plain checkfile call.
      3. A file that EXISTS but is malformed / non-utf8 / a non-object
         root is a real fault: it returns (nil, err) AND logs.
      4. An unsafe path is rejected before io.open (defense in depth,
         mirrors checkfile / atomic_write / maketable per #266).

    Provably fails pre-fix (CLAUDE.md §1a.7): on master util.loadjsontable
    does not exist, so the very first call is on a nil value and the test
    aborts - RED. Patched, all checks pass - GREEN.

    Run: lua5.4 tests/unit/util_loadjsontable_test.lua   (from repo root)
    Exit 0 = all pass, 1 = a failure (CI-friendly).

]]--

----------------------------------------------------------------------
-- shim layer: stub `use` so util.lua loads in isolation, with the REAL
-- bundled dkjson so we exercise genuine JSON parsing (not a fake).
----------------------------------------------------------------------

local _dkjson = assert( loadfile( "dkjson/dkjson.lua" ) )( )

-- Virtual filesystem the io.open stub serves. nil entry = missing file.
local _files = { }
local _io_open_calls = { }    -- each entry { path=..., mode=... }

local _io_stub = {
    open = function( path, mode )
        _io_open_calls[ #_io_open_calls + 1 ] = { path = path, mode = mode }
        local content = _files[ path ]
        if content == nil then
            return nil, "no such file"
        end
        return {
            read  = function( ) return content end,
            close = function( ) end,
        }
    end,
}

-- isutf8 stub: honour a magic sentinel so we can force the non-utf8
-- branch; everything else is treated as valid utf8.
local _adclib_stub = {
    isutf8 = function( s ) return s ~= "<<NOT_UTF8>>" end,
    random_bytes = function( ) return "x" end,
}

local _unicode_stub = {
    ascii = { sub = string.sub, gsub = string.gsub },
    utf8  = { format = string.format },
}

local _out_error_calls = 0
local _out_stub = {
    put   = function( ) end,
    error = function( ) _out_error_calls = _out_error_calls + 1 end,
}

local _mem_stub = { free = function( ) end }

local _real = {
    type = type, load = load, table = table, pairs = pairs,
    pcall = pcall, select = select, ipairs = ipairs,
    tostring = tostring, tonumber = tonumber, loadfile = loadfile,
    setmetatable = setmetatable, getmetatable = getmetatable,
    io = _io_stub, math = math, string = string, os = os,
    package = package,
    adclib = _adclib_stub, unicode = _unicode_stub,
    out = _out_stub, mem = _mem_stub,
    dkjson = _dkjson,
}
_G.use = function( name )
    local v = _real[ name ]
    assert( v ~= nil, "util_loadjsontable_test shim missing dep: use \"" .. name .. "\"" )
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
        io.write( string.format( "FAIL %-60s got=%q want=%q\n",
            label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

----------------------------------------------------------------------
-- 1. valid JSON object -> table, values intact (newline + %s survive)
----------------------------------------------------------------------

do
    _files = { ["lang/en.json"] =
        '{ "msg_ok": "hello %s", "msg_multi": "a\\n\\nb %d", "empty": "" }' }
    _out_error_calls = 0
    local t, err = util.loadjsontable( "lang/en.json" )
    eq( "valid: returns a table",            type( t ), "table" )
    eq( "valid: err is nil",                 err, nil )
    if type( t ) == "table" then
        eq( "valid: plain %s template kept", t.msg_ok, "hello %s" )
        eq( "valid: newline + %d kept",      t.msg_multi, "a\n\nb %d" )
        eq( "valid: empty string kept",      t.empty, "" )
    end
    eq( "valid: did NOT log an error",       _out_error_calls, 0 )
end

----------------------------------------------------------------------
-- 2. MISSING file -> (nil, "not found") and NO log (migration probe)
----------------------------------------------------------------------

do
    _files = { }    -- nothing on disk
    _io_open_calls = { }
    _out_error_calls = 0
    local t, err = util.loadjsontable( "scripts/lang/foo.lang.en.json" )
    eq( "missing: returns nil",              t, nil )
    eq( "missing: err is 'not found'",       err, "not found" )
    eq( "missing: DID attempt io.open",      #_io_open_calls, 1 )
    eq( "missing: did NOT log (no spam)",    _out_error_calls, 0 )
end

----------------------------------------------------------------------
-- 3. malformed JSON that EXISTS -> (nil, err) and DOES log
----------------------------------------------------------------------

do
    _files = { ["lang/en.json"] = '{ "broken": ' }
    _out_error_calls = 0
    local t, err = util.loadjsontable( "lang/en.json" )
    eq( "malformed: returns nil",            t, nil )
    eq( "malformed: err is a string",        type( err ), "string" )
    eq( "malformed: DID log the fault",      _out_error_calls >= 1, true )
end

----------------------------------------------------------------------
-- 3b. empty / whitespace-only file MUST NOT throw. dkjson.decode RAISES
--     on these (not a clean nil,err), so an unwrapped decode would crash
--     loadlanguage on the boot / plugin-load path. It must degrade to
--     (nil, err) and log.
----------------------------------------------------------------------

for _, blank in ipairs( { "", "   ", "\n\t " } ) do
    _files = { ["lang/en.json"] = blank }
    _out_error_calls = 0
    local t, err = util.loadjsontable( "lang/en.json" )
    eq( "blank(" .. #blank .. "): returns nil (no throw)", t, nil )
    eq( "blank(" .. #blank .. "): err is a string",        type( err ), "string" )
    eq( "blank(" .. #blank .. "): DID log the fault",      _out_error_calls >= 1, true )
end

----------------------------------------------------------------------
-- 4. non-object root -> (nil, "invalid table")
--    dkjson decodes "42" to a Lua number and "[...]" to an array table;
--    a lang table must be a JSON object. Both must be rejected, while an
--    empty object "{}" must still pass.
----------------------------------------------------------------------

do
    _files = { ["lang/en.json"] = "42" }
    local t, err = util.loadjsontable( "lang/en.json" )
    eq( "non-object number: returns nil",     t, nil )
    eq( "non-object number: 'invalid table'", err, "invalid table" )
end

do
    _files = { ["lang/en.json"] = "[1, 2, 3]" }    -- array root, decodes to a table
    local t, err = util.loadjsontable( "lang/en.json" )
    eq( "array root: returns nil",            t, nil )
    eq( "array root: 'invalid table'",        err, "invalid table" )
end

do
    _files = { ["lang/en.json"] = "{}" }    -- empty object is a legitimate (empty) lang table
    local t, err = util.loadjsontable( "lang/en.json" )
    eq( "empty object: returns a table",      type( t ), "table" )
    eq( "empty object: err is nil",           err, nil )
end

----------------------------------------------------------------------
-- 4b. dkjson optional-lib absent -> (nil, "dkjson unavailable"), no throw.
--     `use "dkjson"` returns nil on an install that dropped the optional
--     lib. The decode must NOT be reached (an unwrapped index of nil would
--     throw OUTSIDE pcall into the boot path), and loadlanguage then falls
--     back to the legacy .tbl.
----------------------------------------------------------------------

do
    _files = { ["lang/en.json"] = '{ "k": "v" }' }
    _out_error_calls = 0
    local saved_use = _G.use
    _G.use = function( name )
        if name == "dkjson" then return nil end    -- simulate optional lib absent
        return saved_use( name )
    end
    local t, err = util.loadjsontable( "lang/en.json" )
    _G.use = saved_use
    eq( "dkjson-absent: returns nil (no throw)",  t, nil )
    eq( "dkjson-absent: err 'dkjson unavailable'", err, "dkjson unavailable" )
    eq( "dkjson-absent: DID log the fault",       _out_error_calls >= 1, true )
end

----------------------------------------------------------------------
-- 5. non-utf8 content that EXISTS -> (nil, "no utf8 format") and logs
----------------------------------------------------------------------

do
    _files = { ["lang/en.json"] = "<<NOT_UTF8>>" }
    _out_error_calls = 0
    local t, err = util.loadjsontable( "lang/en.json" )
    eq( "non-utf8: returns nil",             t, nil )
    eq( "non-utf8: err is 'no utf8 format'", err, "no utf8 format" )
    eq( "non-utf8: DID log the fault",       _out_error_calls >= 1, true )
end

----------------------------------------------------------------------
-- 6. unsafe path -> rejected before io.open (defense in depth, #266)
----------------------------------------------------------------------

do
    _files = { ["/etc/passwd.json"] = '{ "x": "y" }' }    -- present, but unsafe path
    _io_open_calls = { }
    _out_error_calls = 0
    local t, err = util.loadjsontable( "/etc/passwd.json" )
    eq( "unsafe: returns nil",               t, nil )
    eq( "unsafe: err is a string",           type( err ), "string" )
    eq( "unsafe: did NOT reach io.open",     #_io_open_calls, 0 )
    eq( "unsafe: DID log the rejection",     _out_error_calls >= 1, true )
end

----------------------------------------------------------------------
-- summary
----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures > 0 and 1 or 0 )
