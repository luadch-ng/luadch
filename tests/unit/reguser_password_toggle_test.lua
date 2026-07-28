--[[

    tests/unit/reguser_password_toggle_test.lua

    Unit tests for the `show_reguser_password` cfg toggle shared by
    cmd_accinfo.lua (+accinfo / +accinfoop) and cmd_usersearch.lua
    (+usersearch). Both plugins expose the toggle/redaction decision as
    the `_password_cell` seam so the truth table has one tested definition.

    This guards the security-critical direction (a `show_password and ..`
    style expression can silently invert): toggle OFF must ALWAYS redact.

      - toggle FALSE -> "<REDACTED>" for any password (the #95 default)
      - toggle TRUE  -> the stored password verbatim
      - toggle TRUE + empty / nil password -> the plugin's "unknown"
        string (accinfo "<UNKNOWN>", usersearch "<unknown>")

    The per-user hierarchy gate (WHETHER a user may be inspected) lives in
    the callers, not in `_password_cell`, and is unchanged by this toggle.

    Both plugins are loaded with minimal cfg/hub stubs; `_password_cell`
    closes over `show_password` (read from cfg at load) and the lang
    fallbacks, so each toggle state is a separate load.

    Run: lua5.4 tests/unit/reguser_password_toggle_test.lua

]]--

----------------------------------------------------------------------
-- Tiny harness
----------------------------------------------------------------------
local _pass, _fail = 0, 0
local function eq( what, got, want )
    if got == want then _pass = _pass + 1
    else _fail = _fail + 1
        io.stderr:write( string.format( "FAIL: %s\n  got:  %s\n  want: %s\n",
            what, tostring( got ), tostring( want ) ) ) end
end

----------------------------------------------------------------------
-- Minimal stubs: only what the two plugins touch at module load.
-- Empty tables for the port / permission / prefix keys make the
-- load-time port-building loops no-ops; cmd_ban import must carry .bans.
----------------------------------------------------------------------
local _TBL_KEYS = {
    tcp_ports = true, ssl_ports = true, tcp_ports_ipv6 = true,
    ssl_ports_ipv6 = true, cmd_accinfo_permission = true,
    usr_nick_prefix_prefix_table = true,
}

local function load_plugin( path, show_pw )
    _G.PROCESSED = "PROCESSED"
    _G.cfg = {
        get = function( k )
            if k == "show_reguser_password" then return show_pw end
            if k == "language" then return "en" end
            if _TBL_KEYS[ k ] then return { } end
            return nil
        end,
        loadlanguage = function( ) return { } end,
    }
    _G.hub = {
        import      = function( name ) if name == "cmd_ban" then return { bans = { } } end return nil end,
        setlistener = function( ) end,
        debug       = function( ) end,
        getbot      = function( ) return "bot" end,
    }
    return assert( loadfile( path ) )( )
end

----------------------------------------------------------------------
-- cmd_accinfo  (unknown string is "<UNKNOWN>")
----------------------------------------------------------------------
do
    local off = load_plugin( "scripts/cmd_accinfo.lua", false )
    eq( "accinfo off: real pw -> REDACTED", off._password_cell( "s3cr3t" ), "<REDACTED>" )
    eq( "accinfo off: empty   -> REDACTED", off._password_cell( "" ),       "<REDACTED>" )
    eq( "accinfo off: nil     -> REDACTED", off._password_cell( nil ),      "<REDACTED>" )

    local on = load_plugin( "scripts/cmd_accinfo.lua", true )
    eq( "accinfo on: real pw -> pw",        on._password_cell( "s3cr3t" ),  "s3cr3t" )
    eq( "accinfo on: empty   -> UNKNOWN",   on._password_cell( "" ),        "<UNKNOWN>" )
    eq( "accinfo on: nil     -> UNKNOWN",   on._password_cell( nil ),       "<UNKNOWN>" )
end

----------------------------------------------------------------------
-- cmd_usersearch  (unknown string is "<unknown>")
----------------------------------------------------------------------
do
    local off = load_plugin( "scripts/cmd_usersearch.lua", false )
    eq( "usersearch off: real pw -> REDACTED", off._password_cell( "s3cr3t" ), "<REDACTED>" )
    eq( "usersearch off: empty   -> REDACTED", off._password_cell( "" ),       "<REDACTED>" )
    eq( "usersearch off: nil     -> REDACTED", off._password_cell( nil ),      "<REDACTED>" )

    local on = load_plugin( "scripts/cmd_usersearch.lua", true )
    eq( "usersearch on: real pw -> pw",        on._password_cell( "s3cr3t" ),  "s3cr3t" )
    eq( "usersearch on: empty   -> unknown",   on._password_cell( "" ),        "<unknown>" )
    eq( "usersearch on: nil     -> unknown",   on._password_cell( nil ),       "<unknown>" )
end

----------------------------------------------------------------------
io.write( string.format( "\nreguser_password_toggle: %d passed, %d failed\n", _pass, _fail ) )
os.exit( _fail == 0 and 0 or 1 )
