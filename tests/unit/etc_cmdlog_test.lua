--[[

    tests/unit/etc_cmdlog_test.lua

    Regression test for scripts/etc_cmdlog.lua v1.5 (#460): the command
    log must be stored language-neutral and re-localized at read-time, so
    `+cmdlog show` renders in the hub's CURRENT language regardless of the
    language that was active when each entry was written.

    Pre-fix (v1.4) the onBroadcast writer baked the localized labels
    (msg1/msg2) into every stored line, and `+cmdlog show` dumped the file
    raw - so an entry written on an English hub stayed English forever,
    and a hub whose language later changed showed a frozen mix. Case 1
    below writes under "en", switches the hub to "de", and asserts show
    renders the German labels - it FAILS on v1.4 (the file holds
    "Command:" / "used by:") and PASSES on v1.5.

    The plugin gets NO `use`; every dependency is a sandbox-global stub.
    An in-memory filesystem (_fs) persists across plugin reloads so a
    write under one language is read back under another.

    Run: lua5.4 tests/unit/etc_cmdlog_test.lua

]]--

local checks, failures = 0, 0
local function ok( label, cond, extra )
    checks = checks + 1
    if not cond then failures = failures + 1
        io.write( "FAIL " .. label .. ( extra and ( " - " .. tostring( extra ) ) or "" ) .. "\n" )
    else io.write( "ok   " .. label .. "\n" ) end
end
local function contains( hay, needle ) return type( hay ) == "string" and hay:find( needle, 1, true ) ~= nil end

----------------------------------------------------------------------
-- in-memory filesystem (persists across plugin reloads)
----------------------------------------------------------------------
local _fs = { }

local function fake_open( path, mode )
    mode = mode or "r"
    if mode:find( "r" ) then
        local content = _fs[ path ]
        if content == nil then return nil, path .. ": no such file" end
        return {
            read  = function( _, fmt ) return content end,   -- only "*a" is used
            lines = function( )
                local pos = 1
                return function( )
                    if pos > #content then return nil end
                    local nl = content:find( "\n", pos, true )
                    if nl then
                        local line = content:sub( pos, nl - 1 ); pos = nl + 1; return line
                    end
                    local line = content:sub( pos ); pos = #content + 1; return line
                end
            end,
            close = function( ) end,
        }
    end
    -- append / write
    if mode:find( "a" ) then _fs[ path ] = _fs[ path ] or "" else _fs[ path ] = "" end
    return {
        write = function( _, ... )
            for _, s in ipairs( { ... } ) do _fs[ path ] = _fs[ path ] .. s end
        end,
        close = function( ) end,
    }
end

----------------------------------------------------------------------
-- sandbox-global stubs
----------------------------------------------------------------------
local _active_lang            -- what cfg.loadlanguage returns
local _listeners              -- event -> fn
local _onbmsg                 -- captured show handler
local _http                   -- captured http handler
local _last_reply             -- last user:reply text

_G.type = type; _G.pairs = pairs; _G.ipairs = ipairs
_G.tonumber = tonumber; _G.tostring = tostring
_G.string = string; _G.table = table; _G.math = math
_G.PROCESSED = "PROCESSED"

local _real_os, _real_io = os, io
_G.utf = { match = string.match, format = string.format }
_G.os  = setmetatable( { date = function( ) return "2026-07-18 / 12:00:00" end }, { __index = _real_os } )
_G.io  = setmetatable( { open = fake_open }, { __index = _real_io } )

_G.util = {
    strip_control_bytes = function( s ) return ( type( s ) == "string" ) and ( s:gsub( "%c", "?" ) ) or "" end,
}

_G.cfg = {
    get = function( k )
        if k == "etc_cmdlog_minlevel" then return 10 end
        if k == "etc_cmdlog_command_tbl" then return { accinfo = true, setpass = true, oldcmd = true } end
        if k == "etc_cmdlog_redact_args" then return { setpass = true } end
        if k == "language" then return "test" end
        return nil
    end,
    loadlanguage = function( ) return _active_lang, nil end,
}

_G.hub = {
    getbot      = function( ) return { } end,
    setlistener = function( ev, _opts, fn ) _listeners[ ev ] = fn end,
    debug       = function( ) end,
    http_register = function( _method, _path, _scope, fn ) _http = fn end,
    import      = function( name )
        if name == "cmd_help" then return { reg = function( ) end } end
        if name == "etc_usercommands" then return { add = function( ) end } end
        if name == "etc_hubcommands" then return { add = function( _cmd, fn ) _onbmsg = fn; return true end } end
        return nil
    end,
}

local LANG_EN = { msg1 = "   |   Command: [+!#]", msg2 = "   |   used by: " }
local LANG_DE = { msg1 = "   |   Befehl: [+!#]",  msg2 = "   |   benutzt von: " }

----------------------------------------------------------------------
-- helpers
----------------------------------------------------------------------
local function load_plugin( lang )
    _active_lang = lang
    _listeners, _onbmsg, _http = { }, nil, nil
    assert( loadfile( "scripts/etc_cmdlog.lua" ) )( )
    -- fire onStart so hubcmd.add captures the show handler
    if _listeners[ "onStart" ] then _listeners[ "onStart" ]( ) end
end

local function make_user( nick, level )
    return {
        level = function( ) return level or 100 end,
        nick  = function( ) return nick end,
        reply = function( _, text ) _last_reply = text end,
    }
end

-- fire onBroadcast with a "+cmd args" line
local function fire_write( cmdline )
    _listeners[ "onBroadcast" ]( make_user( "writer", 100 ), { }, cmdline )
end

-- fire the captured show handler
local function fire_show( user )
    _last_reply = nil
    return pcall( _onbmsg, user, { }, "show", "+cmdlog show" )
end

----------------------------------------------------------------------
-- Case 1: THE BUG. Write under English, switch hub to German, show must
-- render German labels. Fails on v1.4 (labels baked English at write).
----------------------------------------------------------------------
_fs = { }
load_plugin( LANG_EN )
fire_write( "+accinfo" )
load_plugin( LANG_DE )                      -- language change; log file persists
local okrun = fire_show( make_user( "op", 100 ) )
ok( "show does not crash after language switch", okrun, _last_reply )
ok( "entry written under en renders German label msg1 after switch to de",
    contains( _last_reply, "Befehl: [+!#]accinfo" ), _last_reply )
ok( "entry renders German label msg2 after switch to de",
    contains( _last_reply, "benutzt von: writer" ), _last_reply )
ok( "no stale English label leaks through",
    not contains( _last_reply, "Command:" ) and not contains( _last_reply, "used by:" ), _last_reply )
-- freeze the exact rendered layout: " [ ts ]" wrapper + label spacing +
-- the single cmd/args space (guards against a future off-by-one that a
-- loose substring check would miss). args is empty here.
local expected_entry = " [ 2026-07-18 / 12:00:00 ]" .. LANG_DE.msg1 .. "accinfo" .. " " .. LANG_DE.msg2 .. "writer"
ok( "rendered entry is byte-exact (spacing frozen)", contains( _last_reply, expected_entry ), expected_entry )

----------------------------------------------------------------------
-- Case 2: migration. An old baked (v1.4) line has no delimiter and must
-- render as-is (frozen language) without crashing or being dropped.
----------------------------------------------------------------------
_fs = { [ "log/cmd.log" ] = " [ 2026-01-01 / 00:00:00 ]   |   Command: [+!#]oldcmd    |   used by: OldUser\n" }
load_plugin( LANG_DE )
okrun = fire_show( make_user( "op", 100 ) )
ok( "old baked line: show does not crash", okrun, _last_reply )
ok( "old baked line rendered as-is (frozen English preserved)",
    contains( _last_reply, "Command: [+!#]oldcmd" ) and contains( _last_reply, "used by: OldUser" ), _last_reply )

----------------------------------------------------------------------
-- Case 3: mixed file. Old baked line + a new entry: old stays frozen,
-- new renders in the current (German) language.
----------------------------------------------------------------------
_fs = { [ "log/cmd.log" ] = " [ 2026-01-01 / 00:00:00 ]   |   Command: [+!#]oldcmd    |   used by: OldUser\n" }
load_plugin( LANG_DE )
fire_write( "+accinfo now" )
okrun = fire_show( make_user( "op", 100 ) )
ok( "mixed file: show does not crash", okrun, _last_reply )
ok( "mixed file: old line stays English", contains( _last_reply, "Command: [+!#]oldcmd" ), _last_reply )
ok( "mixed file: new line is German with its args", contains( _last_reply, "Befehl: [+!#]accinfo now" ), _last_reply )

----------------------------------------------------------------------
-- Case 4: redacted args. A command in redact_args stores <redacted>,
-- never the raw argument, and shows it re-localized.
----------------------------------------------------------------------
_fs = { }
load_plugin( LANG_DE )
fire_write( "+setpass hunter2secret" )
fire_show( make_user( "op", 100 ) )
ok( "redacted command never stores the raw secret", not contains( _fs[ "log/cmd.log" ], "hunter2secret" ), _fs[ "log/cmd.log" ] )
ok( "redacted command shows <redacted>", contains( _last_reply, "<redacted>" ), _last_reply )

----------------------------------------------------------------------
-- Case 5: control-byte hardening. A newline / delimiter in args is
-- stripped, so the stored file stays one line per entry and no false
-- field boundary is created.
----------------------------------------------------------------------
_fs = { }
load_plugin( LANG_DE )
fire_write( "+accinfo a\nb\31c" )           -- newline + a raw US delimiter in args
-- the stored file must be exactly one line (one trailing newline)
local nl_count = select( 2, _fs[ "log/cmd.log" ]:gsub( "\n", "" ) )
ok( "control bytes in args do not add extra lines", nl_count == 1, "newlines=" .. tostring( nl_count ) )
okrun = fire_show( make_user( "op", 100 ) )
ok( "control-byte entry: show does not crash", okrun, _last_reply )
ok( "control bytes replaced, args still one field", contains( _last_reply, "Befehl: [+!#]accinfo a?b?c" ), _last_reply )

----------------------------------------------------------------------
-- Case 6: HTTP path re-localizes too (same render as show).
----------------------------------------------------------------------
_fs = { }
load_plugin( LANG_EN )
fire_write( "+accinfo" )
load_plugin( LANG_DE )
local res = _http( { query = { } } )
ok( "HTTP handler returns 200", res and res.status == 200, res and res.status )
ok( "HTTP line re-localized to German", res and contains( res.data.lines[ 1 ], "Befehl: [+!#]accinfo" ), res and res.data.lines[ 1 ] )

----------------------------------------------------------------------
io.write( string.format( "\n%d/%d checks passed\n", checks - failures, checks ) )
if failures > 0 then io.write( "FAIL etc_cmdlog_test\n" ); os.exit( 1 ) end
io.write( "OK etc_cmdlog_test\n" )
