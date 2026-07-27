--[[

    tests/unit/etc_trafficmanager_test.lua

    Unit tests for scripts/etc_trafficmanager.lua `show blocks` /
    `show settings` output (luadch-ng/luadch#502).

    Focus: the v2.7 change that makes `+trafficmanager show blocks`
    also list currently-online users who are auto-blocked by share
    (0 B / below minshare) or by a blocked level. These are runtime
    need_block() classifications never persisted to block_tbl, so the
    pre-v2.7 handler (which only iterated block_tbl) showed nothing
    for them. Also covers the v2.7 `show settings` minshare-check line.

    The plugin is loaded with a stubbed sandbox environment; the
    `+trafficmanager` chat handler (onbmsg) is captured through the
    etc_hubcommands.add stub and invoked directly. hub.getusers() is
    stubbed to return a controllable online set.

    Run: lua5.4 tests/unit/etc_trafficmanager_test.lua
    Exit 0 = all pass, 1 = a failure (CI-friendly).

    Regression contract (CLAUDE.md §1a.7): the positive auto-block
    assertions, the "(none)" placeholder, and the settings minshare
    line (9 checks) FAIL on the pre-v2.7 plugin (no auto-block section;
    msg_users had only two %s) and PASS on v2.7. The negative auto
    assertions (clean/op NOT listed) and the manual-section / permission
    checks are guards that pass on both revisions. Verified by running
    this file against `git show origin/dev:scripts/etc_trafficmanager.lua`
    (9 failures pre-fix, 0 post-fix).

]]--

local GiB = 1024 * 1024 * 1024

----------------------------------------------------------------------
-- controllable state
----------------------------------------------------------------------

local _registered = { }        -- event/listener name -> fn
local _hubcmds = { }           -- cmd name -> handler (onbmsg)
local _online = { }            -- sid -> stub user (hub.getusers)
local _block_seed = nil        -- what util.loadtable returns for block_tbl

----------------------------------------------------------------------
-- stub sandbox globals the plugin reads at file scope + runtime
----------------------------------------------------------------------

_G.PROCESSED = 1

_G.hub = {
    setlistener = function( event, opts, fn ) _registered[ event ] = fn end,
    debug       = function( ) end,
    getbot      = function( ) return "stub-bot" end,
    sendtoall   = function( ) end,
    escapeto    = function( s ) return s end,
    escapefrom  = function( s ) return s end,
    isnickonline = function( ) return nil end,
    getusers    = function( ) return _online end,
    getregusers = function( ) return { }, { }, { } end,
    import = function( name )
        if name == "etc_hubcommands" then
            return {
                add = function( cmd, fn ) _hubcmds[ cmd ] = fn; return true end,
                has = function( ) return false end,
                list = function( ) return { } end,
            }
        end
        if name == "etc_report" then
            return { send = function( ) end }
        end
        return nil    -- cmd_help / etc_usercommands absent in the test
    end,
    http_register = function( ) end,
}

_G.cfg = {
    loadlanguage = function( ) return { }, nil end,   -- exercise inline fallbacks
    get = function( key )
        local t = {
            language                        = "en",
            etc_trafficmanager_activate     = true,
            etc_trafficmanager_permission   = { [ 60 ] = 60, [ 70 ] = 70, [ 80 ] = 80, [ 100 ] = 100 },
            etc_trafficmanager_report       = false,
            etc_trafficmanager_report_hubbot = false,
            etc_trafficmanager_report_opchat = false,
            etc_trafficmanager_llevel       = 60,
            etc_trafficmanager_blocklevel_tbl = { [ 10 ] = true },   -- level 10 auto-blocked
            etc_trafficmanager_sharecheck   = true,
            etc_trafficmanager_check_minshare = true,
            min_share                       = { [ 0 ] = 0, [ 10 ] = 0, [ 20 ] = 5, [ 60 ] = 0, [ 100 ] = 0 },
            etc_trafficmanager_oplevel      = 60,
            etc_trafficmanager_login_report = false,
            etc_trafficmanager_report_main  = false,
            etc_trafficmanager_report_pm    = false,
            usr_nick_prefix_activate        = false,
            usr_nick_prefix_permission      = { },
            usr_nick_prefix_prefix_table    = { },
            usr_desc_prefix_activate        = false,
            usr_desc_prefix_permission      = { },
            usr_desc_prefix_prefix_table    = { },
            etc_trafficmanager_send_loop    = false,
            etc_trafficmanager_loop_time    = 1,
            etc_trafficmanager_flag_blocked = "[BLOCKED]",
            levels = { [ 10 ] = "Guest", [ 20 ] = "Reg", [ 60 ] = "Op", [ 100 ] = "Owner" },
        }
        return t[ key ]
    end,
}

_G.util = {
    loadtable = function( ) return _block_seed end,
    savetable = function( ) return true end,
    date      = function( ) return "20260101000000" end,
    strip_control_bytes = function( s ) return s end,
    getlowestlevel = function( ) return 60 end,
    -- real spairs impl (copied from core/util.lua) so the manual-block
    -- section iterates in sorted order deterministically.
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
}

_G.utf = {
    match  = string.match,
    format = string.format,
    sub    = string.sub,
    len    = string.len,
}

----------------------------------------------------------------------
-- minimal test framework
----------------------------------------------------------------------

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-60s got=%q want=%q\n", label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

local function contains( hay, needle ) return ( hay or "" ):find( needle, 1, true ) ~= nil end
local function count( hay, needle )
    local n, i = 0, 1
    while true do
        local s = ( hay or "" ):find( needle, i, true )
        if not s then break end
        n = n + 1; i = s + #needle
    end
    return n
end

----------------------------------------------------------------------
-- stub user + op factory
----------------------------------------------------------------------

local function stub_user( opts )
    return {
        level     = function( ) return opts.level end,
        share     = function( ) return opts.share end,      -- may be nil
        firstnick = function( ) return opts.firstnick end,
        nick      = function( ) return opts.firstnick end,
        isbot     = function( ) return false end,
    }
end

local function op_user( )
    local replied
    local u = {
        level = function( ) return 100 end,
        nick  = function( ) return "owner" end,
        reply = function( _, msg ) replied = msg end,
    }
    return u, function( ) return replied end
end

----------------------------------------------------------------------
-- load plugin + onStart (empty online set) so onbmsg is captured
----------------------------------------------------------------------

_block_seed = { manual_guy = { "admin", "manual reason", "20260101000000" } }
_online = { }
assert( loadfile( "scripts/etc_trafficmanager.lua" ) )( )
assert( _registered.onStart, "onStart not registered" )
_registered.onStart( )
local onbmsg = _hubcmds.trafficmanager
assert( onbmsg, "+trafficmanager handler not registered" )

----------------------------------------------------------------------
-- 1. show blocks: auto-blocked online users appear with the right
--    reason, clean/op users do not, manual user appears once.
----------------------------------------------------------------------

do
    _online = {
        s1 = stub_user{ firstnick = "zeroshare_guy", level = 20, share = 0 },
        s2 = stub_user{ firstnick = "small_guy",     level = 20, share = 1 * GiB },
        s3 = stub_user{ firstnick = "level_guy",      level = 10, share = 999 * GiB },
        s4 = stub_user{ firstnick = "clean_guy",      level = 20, share = 10 * GiB },
        s5 = stub_user{ firstnick = "op_guy",         level = 60, share = 0 },
        s6 = stub_user{ firstnick = "manual_guy",     level = 20, share = 0 },  -- also in block_tbl
    }
    local op, replied_of = op_user( )
    local r = onbmsg( op, "trafficmanager", "show blocks" )
    local out = replied_of( )
    eq( "show blocks returns PROCESSED", r, 1 )
    eq( "auto: section header present",  contains( out, "Auto-blocked ( online )" ), true )

    eq( "auto: zeroshare_guy listed",    contains( out, "zeroshare_guy" ), true )
    eq( "auto: zeroshare reason",        contains( out, "0 B share" ),     true )
    eq( "auto: small_guy listed",        contains( out, "small_guy" ),     true )
    eq( "auto: minshare reason",         contains( out, "Below minshare" ), true )
    eq( "auto: level_guy listed",        contains( out, "level_guy" ),     true )
    eq( "auto: level reason + name",     contains( out, "Blocked level [ Guest ]" ), true )

    eq( "auto: clean_guy NOT listed",    contains( out, "clean_guy" ),     false )
    eq( "auto: op_guy NOT listed (>= oplevel)", contains( out, "op_guy" ), false )

    eq( "manual: manual_guy present",    contains( out, "manual_guy" ),    true )
    eq( "manual: manual_guy appears once (not duplicated in auto)", count( out, "manual_guy" ), 1 )
    eq( "manual: block reason present",  contains( out, "manual reason" ), true )
    eq( "manual: blocker present",       contains( out, "admin" ),         true )
end

----------------------------------------------------------------------
-- 2. show blocks: no online auto-blocked user -> "(none)" placeholder.
----------------------------------------------------------------------

do
    _online = {
        s1 = stub_user{ firstnick = "clean_guy", level = 20, share = 10 * GiB },
    }
    local op, replied_of = op_user( )
    onbmsg( op, "trafficmanager", "show blocks" )
    local out = replied_of( )
    eq( "empty auto: (none) placeholder", contains( out, "(none)" ), true )
    eq( "empty auto: clean_guy still not listed", contains( out, "clean_guy" ), false )
end

----------------------------------------------------------------------
-- 3. show settings: minshare-check toggle now reported.
----------------------------------------------------------------------

do
    local op, replied_of = op_user( )
    local r = onbmsg( op, "trafficmanager", "show settings" )
    local out = replied_of( )
    eq( "show settings returns PROCESSED",   r, 1 )
    eq( "settings: 0-B-share line present",  contains( out, "Block users with 0 B share" ), true )
    eq( "settings: minshare line present",   contains( out, "Block users below minshare" ), true )
end

----------------------------------------------------------------------
-- 4. non-op is denied show blocks (permission gate intact).
----------------------------------------------------------------------

do
    local replied
    local low = {
        level = function( ) return 20 end,
        reply = function( _, msg ) replied = msg end,
    }
    _online = { }
    onbmsg( low, "trafficmanager", "show blocks" )
    eq( "denied: low-level got denial reply", contains( replied, "not allowed" ), true )
end

----------------------------------------------------------------------
-- 5. lang-file template placeholder parity. The show-blocks / settings
--    call sites pass a fixed number of args; the bundled lang files
--    MUST carry the matching %s count. Lang files are add-only on
--    upgrade (never overwritten), so a bundled-file edit that drops a
--    %s is a realistic drift. The auto-block %s is intentionally LAST
--    in msg_users so a stale two-%s file degrades gracefully rather
--    than mislabelling the section - this guards the bundled files.
----------------------------------------------------------------------

do
    local function pct( s ) return select( 2, ( s or "" ):gsub( "%%s", "" ) ) end
    for _, lc in ipairs( { "en", "de" } ) do
        local L = assert( loadfile( "scripts/lang/etc_trafficmanager.lang." .. lc ) )( )
        eq( "lang " .. lc .. ": msg_users has 3 %s", pct( L.msg_users ), 3 )
        eq( "lang " .. lc .. ": opmsg has 8 %s",     pct( L.opmsg ),     8 )
    end
end

----------------------------------------------------------------------
-- summary
----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures > 0 and 1 or 0 )
