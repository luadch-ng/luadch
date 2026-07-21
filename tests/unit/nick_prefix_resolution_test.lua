--[[

    tests/unit/nick_prefix_resolution_test.lua

    Regression test for the nick-prefix resolution bug across the operator
    commands that resolve an arbitrary online user by a typed nick and then
    act on / report about them: ACTION commands (kick / gag / redirect /
    disconnect / hide-share / message-block) and read-only INFO commands
    (userinfo / sslinfo / myip / myinf), which showed "offline" or fell
    back to the caller's own info for a prefixed online user.

    THE BUG: usr_nick_prefix.lua prefixes online nicks via
    user:updatenick( prefix .. nick ), which re-keys the hub's internal
    _usernicks table from the base nick to the PREFIXED display nick. So
    hub.isnickonline( <base nick> ) returns nil for a prefixed online
    user, and these commands silently took the OFFLINE / "user not found"
    path: for cmd_ban the ban was stored but the user was NOT kicked (the
    operator believed they had removed them); for the others the action
    never fired at all. accinfo still showed the user online (it iterates
    by SID, prefix-agnostic), which is what made it look like "permanent
    ban does not kick" on the dev testhub. Right-click usercommands were
    NOT affected because they pass %[userNI] (the current *display* nick =
    the prefixed nick) or %[userSID]; only a TYPED base nick broke.

    THE FIX: each command falls back to user:firstnick() - the ORIGINAL
    nick, captured once at login and never re-keyed - via a plugin-local
    find_online_by_firstnick(), the same idiom etc_trafficmanager already
    uses (closed upstream luadch/luadch#240). The commands that DO know
    the target level up front (cmd_upgrade / cmd_setpass / cmd_delreg /
    cmd_nickchange) keep their prefix-dance and are intentionally NOT
    touched; the six below cannot prefix-dance (they act on an arbitrary
    online target whose level they only learn AFTER resolving).

    FAIL-PRE-FIX (§1a.7): on the unpatched plugins the base-nick lookup
    misses and the `_`-seams below are absent (the presence guards fire),
    while cmd_gag - whose `_onbmsg` already existed - additionally fails
    its behaviour assertions outright (the prefixed user is not gagged).
    The behaviour assertions (kick / gag / redirect / block fired) also
    guard against a future "hollow" regression that keeps the seam but
    drops the `or find_online_by_firstnick` wiring, because hub.isnickonline
    is stubbed to always miss. Reproduce red: `git stash push` the ten
    touched plugins (cmd_ban, cmd_disconnect, cmd_gag, cmd_redirect,
    usr_hide_share, etc_msgmanager, cmd_userinfo, cmd_sslinfo, cmd_myip,
    cmd_myinf) then run this file; `git stash pop` to restore.

    Plugins get NO `use`; every hub-injected global is a stub below. Base
    Lua globals (type/pairs/os/io/...) are the real ones - this test runs
    in a normal Lua env, not the restricted hub env, and deliberately does
    NOT reassign _G.io / _G.os (avoids the etc_cmdlog_test harness-clobber).

    Run: lua5.4 tests/unit/nick_prefix_resolution_test.lua

]]--

----------------------------------------------------------------------
-- tiny harness
----------------------------------------------------------------------
local checks, failures = 0, 0
local function ok( label, cond )
    checks = checks + 1
    if cond then io.write( "ok   " .. label .. "\n" )
    else failures = failures + 1; io.write( "FAIL " .. label .. "\n" ) end
end

-- A prefixed ONLINE user: current display nick carries the prefix, but
-- firstnick is the immutable base nick the operator actually types.
local BASE_NICK   = "Aybo"
local PREFIX_NICK = "[HUBOWNER]Aybo"

local function make_prefixed_target( )
    local t = { _killed = nil, _redirected = nil, _inf_set = {} }
    t.firstnick = function( ) return BASE_NICK end
    t.nick      = function( ) return PREFIX_NICK end
    t.level     = function( ) return 20 end
    t.isbot     = function( ) return false end
    t.cid       = function( ) return "CIDAYBO" end
    t.hash      = function( ) return "TIGR" end
    t.ip        = function( ) return "192.0.2.7" end
    t.sid       = function( ) return "AAAA" end
    t.reply     = function( ) end
    t.kill      = function( _self, adcstr ) t._killed = adcstr or true end
    t.redirect  = function( _self, url ) t._redirected = url end
    t.inf       = function( ) return { setnp = function( _s, k, v ) t._inf_set[ k ] = v end } end
    t.sslinfo   = function( ) return { protocol = "TLSv1.3", cipher = "TLS_AES_256_GCM_SHA384" } end
    return t
end

-- Operator: level 100, distinct base + display nick so the self-target
-- and hierarchy guards do not misfire against the target.
local function make_op( )
    local last
    return {
        level     = function( ) return 100 end,
        nick      = function( ) return "[OP]op" end,
        firstnick = function( ) return "op" end,
        sid       = function( ) return "OOOO" end,
        ip        = function( ) return "203.0.113.1" end,   -- caller ip (myip self-fallback)
        reply     = function( _self, msg ) last = msg end,
        _last     = function( ) return last end,
    }
end

-- Shared hub stub: the base-nick lookup ALWAYS misses (models the
-- prefix re-key), getusers returns the one prefixed human. A patched
-- plugin recovers the target via firstnick; an unpatched one does not.
-- `_sentall` records whether a BINF was broadcast (usr_hide_share proof).
local function make_hub( target )
    local h = { _sentall = false }
    h.setlistener  = function( ) end
    h.debug        = function( ) end
    h.getbot       = function( ) return "bot" end
    h.getregusers  = function( ) return {}, {}, {} end   -- offline branch: nothing
    h.isnickonline = function( ) return nil end          -- prefix miss
    h.issidonline  = function( ) return nil end
    h.iscidonline  = function( ) return nil end
    h.isiponline   = function( ) return nil end
    h.getusers     = function( ) return { AAAA = target } end
    h.escapeto     = function( _s ) return _s end
    h.escapefrom   = function( _s ) return _s end
    h.sendtoall    = function( ) h._sentall = true end
    h.http_register = function( ) end
    h.import       = function( name )
        if name == "etc_report" then return { send = function( ) end } end
        return nil
    end
    return h
end

local _utf = {
    match  = function( s, pat ) return string.match( s, pat ) end,
    format = function( fmt, ... ) return string.format( fmt, ... ) end,
    sub    = function( s, i, j ) return string.sub( s, i, j ) end,
    len    = function( s ) return #s end,
}
local _audit = { build = function( ) return {} end, fire = function( ) end }

----------------------------------------------------------------------
-- helper: assert the firstnick fallback resolves + is nil-safe
----------------------------------------------------------------------
local function check_helper( name, p, target )
    if type( p ) ~= "table" or type( p._find_online_by_firstnick ) ~= "function" then
        ok( name .. ": exports _find_online_by_firstnick (pre-fix plugin?)", false )
        return
    end
    local f = p._find_online_by_firstnick
    ok( name .. ": resolves the prefixed online user by base nick", f( BASE_NICK ) == target )
    ok( name .. ": returns nil for an unknown nick",                 f( "Nobody" ) == nil )
    ok( name .. ": nil-safe for a nil nick",                         f( nil ) == nil )
end

_G.PROCESSED = "PROCESSED"

----------------------------------------------------------------------
-- cmd_disconnect: `+disconnect <base nick>` must kick the prefixed user
----------------------------------------------------------------------
do
    local target = make_prefixed_target( )
    _G.cfg = {
        get = function( k )
            local t = {
                language                     = "en",
                cmd_disconnect_minlevel      = 10,
                cmd_disconnect_sendmainmsg   = false,
                cmd_disconnect_report        = false,
                cmd_disconnect_llevel        = 80,
                cmd_disconnect_report_hubbot = false,
                cmd_disconnect_report_opchat = false,
            }
            return t[ k ]
        end,
        loadlanguage = function( ) return {} end,
    }
    _G.utf   = _utf
    _G.util  = { strip_control_bytes = function( s ) return s end }
    _G.audit = _audit
    _G.hub   = make_hub( target )

    local p = assert( loadfile( "scripts/cmd_disconnect.lua" ) )( )
    check_helper( "cmd_disconnect", p, target )
    if type( p ) == "table" and type( p._onbmsg ) == "function" then
        local op = make_op( )
        local r = p._onbmsg( op, "disconnect", BASE_NICK .. " test reason" )
        ok( "cmd_disconnect: handler returns PROCESSED", r == "PROCESSED" )
        ok( "cmd_disconnect: prefixed online user IS kicked", target._killed ~= nil )
        ok( "cmd_disconnect: reply is NOT the offline message", op._last( ) ~= "User is offline." )
    else
        ok( "cmd_disconnect: exports _onbmsg (pre-fix plugin?)", false )
    end
end

----------------------------------------------------------------------
-- cmd_gag: `+gag mute <base nick>` gags; `+gag ungag <base nick>` lifts
----------------------------------------------------------------------
do
    local target = make_prefixed_target( )
    _G.cfg = {
        get = function( k )
            local t = {
                language               = "en",
                cmd_gag_permission     = { [10] = 10, [20] = 20, [100] = 100 },
                hub_bot                = "HubBot",
                cmd_gag_user_notifiy   = false,
                cmd_gag_report         = false,
                cmd_gag_llevel         = 80,
                cmd_gag_report_hubbot  = false,
                cmd_gag_report_opchat  = false,
                bot_opchat_nick        = "OpChat",
                bot_opchat_permission  = { [100] = 100 },
                bot_regchat_nick       = "RegChat",
                bot_regchat_permission = { [100] = 100 },
            }
            return t[ k ]
        end,
        loadlanguage = function( ) return {} end,
    }
    _G.utf  = _utf
    _G.util = {
        loadtable           = function( ) return {} end,
        getlowestlevel      = function( tbl )
            local lo; for lvl in pairs( tbl ) do if not lo or lvl < lo then lo = lvl end end
            return lo or 0
        end,
        strip_control_bytes = function( s ) return s end,
        savearray           = function( ) end,
        formatseconds       = function( ) return 0, 0, 0, 0, 0 end,
    }
    _G.audit = _audit
    _G.hub   = make_hub( target )

    local p = assert( loadfile( "scripts/cmd_gag.lua" ) )( )
    check_helper( "cmd_gag", p, target )
    if type( p ) == "table" and type( p._onbmsg ) == "function" and type( p._gag_tbl ) == "table" then
        -- gag (mute)
        for i = #p._gag_tbl, 1, -1 do p._gag_tbl[ i ] = nil end
        local op = make_op( )
        p._onbmsg( op, "gag", "mute " .. BASE_NICK )
        ok( "cmd_gag: prefixed online user IS gagged",    #p._gag_tbl == 1 )
        ok( "cmd_gag: entry keyed by the base firstnick", p._gag_tbl[ 1 ] and p._gag_tbl[ 1 ].user_nick == BASE_NICK )
        -- ungag: pre-seed by firstnick, then lift by the typed base nick
        for i = #p._gag_tbl, 1, -1 do p._gag_tbl[ i ] = nil end
        p._gag_tbl[ 1 ] = { user_nick = BASE_NICK, mode = "mute", added_by = "op", added_at = 1 }
        p._onbmsg( op, "gag", "ungag " .. BASE_NICK )
        ok( "cmd_gag: ungag by base nick lifts the prefixed user's gag", #p._gag_tbl == 0 )
    else
        ok( "cmd_gag: exports _onbmsg + _gag_tbl (pre-fix plugin?)", false )
    end
end

----------------------------------------------------------------------
-- cmd_redirect: `+redirect <base nick> <url>` must redirect the user
----------------------------------------------------------------------
do
    local target = make_prefixed_target( )
    _G.cfg = {
        get = function( k )
            local t = {
                language                    = "en",
                cmd_redirect_activate       = true,
                cmd_redirect_permission     = { [10] = 10, [20] = 20, [100] = 100 },
                cmd_redirect_level          = {},
                cmd_redirect_url            = "adcs://fallback:5001",
                levels                      = { [20] = "REG", [100] = "Owner" },
                cmd_redirect_report         = false,
                cmd_redirect_report_hubbot  = false,
                cmd_redirect_report_opchat  = false,
                cmd_redirect_llevel         = 80,
            }
            return t[ k ]
        end,
        loadlanguage = function( ) return {} end,
    }
    _G.utf  = _utf
    _G.util = {
        getlowestlevel      = function( tbl )
            local lo; for lvl in pairs( tbl ) do if not lo or lvl < lo then lo = lvl end end
            return lo or 0
        end,
        strip_control_bytes = function( s ) return s end,
    }
    _G.audit = _audit
    _G.hub   = make_hub( target )

    local p = assert( loadfile( "scripts/cmd_redirect.lua" ) )( )
    check_helper( "cmd_redirect", p, target )
    if type( p ) == "table" and type( p._onbmsg ) == "function" then
        local op = make_op( )
        local r = p._onbmsg( op, "redirect", BASE_NICK .. " adcs://newhub:5001" )
        ok( "cmd_redirect: handler returns PROCESSED", r == "PROCESSED" )
        ok( "cmd_redirect: prefixed online user IS redirected", target._redirected == "adcs://newhub:5001" )
        ok( "cmd_redirect: reply is NOT the offline message", op._last( ) ~= "User is offline." )
    else
        ok( "cmd_redirect: exports _onbmsg (pre-fix plugin?)", false )
    end
end

----------------------------------------------------------------------
-- cmd_ban: `+ban nick <base> ...` must KICK the prefixed user (the
--          headline bug: pre-fix the ban was stored offline and the
--          online user walked free). Timed -> STA 232, permanent -> 231.
--          The HTTP http_find_online nick path must resolve too.
----------------------------------------------------------------------
do
    local target = make_prefixed_target( )
    _G.cfg = {
        get = function( k )
            local t = {
                language             = "en",
                cmd_ban_default_time = 5,
                cmd_ban_permission   = { [10] = 10, [20] = 20, [100] = 100 },
                cmd_ban_report       = false,
                cmd_ban_report_hubbot = false,
                cmd_ban_report_opchat = false,
                cmd_ban_llevel       = 80,
                cmd_unban_permission = { [10] = 10, [100] = 100 },
            }
            return t[ k ]
        end,
        loadlanguage = function( ) return {} end,
    }
    _G.utf  = _utf
    _G.util = {
        loadtable           = function( ) return {} end,
        savearray           = function( ) end,
        savetable           = function( ) end,
        getlowestlevel      = function( tbl )
            local lo; for lvl in pairs( tbl ) do if not lo or lvl < lo then lo = lvl end end
            return lo or 0
        end,
        strip_control_bytes = function( s ) return s end,
        formatseconds       = function( ) return 0, 0, 0, 0, 0 end,
        date                = function( ) return "20260720120000" end,
    }
    _G.audit = _audit
    _G.hub   = make_hub( target )

    local p = assert( loadfile( "scripts/cmd_ban.lua" ) )( )
    check_helper( "cmd_ban", p, target )
    if type( p ) == "table" and type( p._onbmsg ) == "function" then
        local op = make_op( )
        -- timed ban -> ADC STA 232 + TL<seconds>
        target._killed = nil
        local r = p._onbmsg( op, "ban", "nick " .. BASE_NICK .. " 5 test reason" )
        ok( "cmd_ban: timed handler returns PROCESSED", r == "PROCESSED" )
        ok( "cmd_ban: timed - prefixed online user IS kicked", target._killed ~= nil )
        ok( "cmd_ban: timed kick uses ADC STA 232",
            type( target._killed ) == "string" and string.find( target._killed, "ISTA 232 ", 1, true ) == 1 )
        -- permanent ban -> ADC STA 231 + TL-1 (the actual testhub symptom)
        target._killed = nil
        p._onbmsg( op, "ban", "nick " .. BASE_NICK .. " permanent test reason" )
        ok( "cmd_ban: permanent - prefixed online user IS kicked", target._killed ~= nil )
        ok( "cmd_ban: permanent kick uses ADC STA 231",
            type( target._killed ) == "string" and string.find( target._killed, "ISTA 231 ", 1, true ) == 1 )
    else
        ok( "cmd_ban: exports _onbmsg (pre-fix plugin?)", false )
    end
    -- HTTP POST /v1/bans nick target resolution (http_find_online)
    if type( p ) == "table" and type( p._http_find_online ) == "function" then
        ok( "cmd_ban: http_find_online resolves the prefixed user by nick",
            p._http_find_online( "nick", BASE_NICK ) == target )
    else
        ok( "cmd_ban: exports _http_find_online (pre-fix plugin?)", false )
    end
end

----------------------------------------------------------------------
-- usr_hide_share: `+hideshare <base nick>` must toggle the prefixed
--                 user's share (BINF broadcast + INF SS/SF rewrite),
--                 not report "offline".
----------------------------------------------------------------------
do
    local target = make_prefixed_target( )
    _G.cfg = {
        get = function( k )
            local t = {
                language                    = "en",
                usr_hide_share_activate     = true,
                usr_hide_share_permission   = { [10] = 10, [20] = 20, [100] = 100 },
                usr_hide_share_restrictions = {},   -- level 20 not restricted -> hides
            }
            return t[ k ]
        end,
        loadlanguage = function( ) return {} end,
    }
    _G.utf  = _utf
    _G.util = {
        loadtable      = function( ) return {} end,
        savetable      = function( ) end,
        getlowestlevel = function( tbl )
            local lo; for lvl in pairs( tbl ) do if not lo or lvl < lo then lo = lvl end end
            return lo or 0
        end,
    }
    _G.audit = _audit
    _G.hub   = make_hub( target )

    local p = assert( loadfile( "scripts/usr_hide_share.lua" ) )( )
    check_helper( "usr_hide_share", p, target )
    if type( p ) == "table" and type( p._onbmsg ) == "function" then
        local op = make_op( )
        local r = p._onbmsg( op, "hideshare", BASE_NICK )
        ok( "usr_hide_share: handler returns PROCESSED", r == "PROCESSED" )
        ok( "usr_hide_share: prefixed user's share IS toggled (BINF sent)", _G.hub._sentall == true )
        ok( "usr_hide_share: INF share size (SS) was rewritten", target._inf_set[ "SS" ] ~= nil )
        ok( "usr_hide_share: reply is NOT the offline message", op._last( ) ~= "User is offline." )
    else
        ok( "usr_hide_share: exports _onbmsg (pre-fix plugin?)", false )
    end
end

----------------------------------------------------------------------
-- etc_msgmanager: is_online (the changed resolution wrapper feeding the
--   block/unblock sub-commands) must resolve the prefixed user by base
--   nick. block_tbl is only populated in onStart, so the resolution
--   wrapper is tested directly - it IS the line the fix changed.
----------------------------------------------------------------------
do
    local target = make_prefixed_target( )
    _G.cfg = {
        get = function( k )
            local t = {
                language                    = "en",
                etc_msgmanager_activate     = true,
                etc_msgmanager_permission   = { [10] = 10, [20] = 20, [100] = 100 },
                etc_msgmanager_permission_pm   = { [20] = 20 },
                etc_msgmanager_permission_main = { [20] = 20 },
                etc_msgmanager_report       = false,
                etc_msgmanager_report_hubbot = false,
                etc_msgmanager_report_opchat = false,
                etc_msgmanager_llevel       = 80,
            }
            return t[ k ]
        end,
        loadlanguage = function( ) return {} end,
    }
    _G.utf  = _utf
    _G.util = {
        loadtable      = function( ) return {} end,
        savetable      = function( ) end,
        getlowestlevel = function( tbl )
            local lo; for lvl in pairs( tbl ) do if not lo or lvl < lo then lo = lvl end end
            return lo or 0
        end,
    }
    _G.audit = _audit
    _G.hub   = make_hub( target )

    local p = assert( loadfile( "scripts/etc_msgmanager.lua" ) )( )
    check_helper( "etc_msgmanager", p, target )
    if type( p ) == "table" and type( p._is_online ) == "function" then
        local op = make_op( )
        local first_nick, disp_nick, lvl = p._is_online( op, BASE_NICK )
        ok( "etc_msgmanager: is_online resolves the prefixed user by base nick", first_nick == BASE_NICK )
        ok( "etc_msgmanager: is_online returns the prefixed display nick",       disp_nick == PREFIX_NICK )
        ok( "etc_msgmanager: is_online returns the target level",                lvl == 20 )
        ok( "etc_msgmanager: is_online misses only for an unknown nick",         p._is_online( op, "Nobody" ) == nil )
    else
        ok( "etc_msgmanager: exports _is_online (pre-fix plugin?)", false )
    end
end

----------------------------------------------------------------------
-- READ-ONLY info commands: they only DISPLAY a resolved user, but under a
-- nick-prefix `+userinfo nick <base>` / `+sslinfo <base>` showed "offline"
-- and `+myip <base>` / `+myinf <base>` silently fell back to the caller's
-- own info. Same one-line fallback; the resolution helper is unit-tested
-- for all four, and cmd_myip + cmd_sslinfo additionally get end-to-end
-- behaviour checks (target ip / target ssl info reached, not the caller's
-- / not "not found"). cmd_userinfo + cmd_myinf stay helper-level: an
-- end-to-end check would need heavy INF / stats accessor stubs and the
-- wiring is the byte-identical one-liner proven e2e elsewhere in this file.
-- (usr_uptime resolves a nick only
-- on its CT2 right-click path, which passes the prefixed %[userNI]; a
-- typed +uptime shows self and never resolves a base nick - so it is not
-- reachably broken and is deliberately excluded.)
----------------------------------------------------------------------

-- cmd_userinfo: `+userinfo nick <base nick>` must resolve, not "offline"
do
    local target = make_prefixed_target( )
    _G.cfg = {
        get = function( k )
            if k == "language" then return "en" end
            if k == "cmd_userinfo_permission" then return { [10] = 10, [20] = 20, [100] = 100 } end
            if k == "levels" then return { [20] = "REG", [100] = "Owner" } end
            return nil
        end,
        loadlanguage = function( ) return {} end,
    }
    _G.utf  = _utf
    _G.util = {
        getlowestlevel = function( tbl )
            local lo; for lvl in pairs( tbl ) do if not lo or lvl < lo then lo = lvl end end
            return lo or 0
        end,
    }
    _G.audit = _audit
    _G.hub   = make_hub( target )

    local p = assert( loadfile( "scripts/cmd_userinfo.lua" ) )( )
    check_helper( "cmd_userinfo", p, target )
end

-- cmd_sslinfo: `+sslinfo <base nick>` must resolve, not "user not found"
do
    local target = make_prefixed_target( )
    _G.cfg = {
        get = function( k )
            if k == "language" then return "en" end
            if k == "cmd_sslinfo_minlevel" then return 10 end
            return nil
        end,
        loadlanguage = function( ) return {} end,
    }
    _G.utf   = _utf
    _G.util  = {}
    _G.audit = _audit
    _G.hub   = make_hub( target )

    local p = assert( loadfile( "scripts/cmd_sslinfo.lua" ) )( )
    check_helper( "cmd_sslinfo", p, target )
    if type( p ) == "table" and type( p._onbmsg ) == "function" then
        local op = make_op( )
        local r = p._onbmsg( op, "sslinfo", BASE_NICK )
        ok( "cmd_sslinfo: handler returns PROCESSED", r == "PROCESSED" )
        ok( "cmd_sslinfo: resolves + shows the prefixed user's ssl info",
            type( op._last( ) ) == "string" and string.find( op._last( ), PREFIX_NICK, 1, true ) ~= nil )
        ok( "cmd_sslinfo: reply is NOT 'user not found'", op._last( ) ~= "User not found." )
    else
        ok( "cmd_sslinfo: exports _onbmsg (pre-fix plugin?)", false )
    end
end

-- cmd_myip: `+myip <base nick>` must show the TARGET's ip, not fall back
-- to the caller's own ip (the read-only self-fallback symptom).
do
    local target = make_prefixed_target( )
    _G.cfg = {
        get = function( k ) if k == "language" then return "en" end return nil end,
        loadlanguage = function( ) return {} end,
    }
    _G.utf   = _utf
    _G.util  = {}
    _G.audit = _audit
    _G.hub   = make_hub( target )

    local p = assert( loadfile( "scripts/cmd_myip.lua" ) )( )
    check_helper( "cmd_myip", p, target )
    if type( p ) == "table" and type( p._onbmsg ) == "function" then
        local op = make_op( )
        local r = p._onbmsg( op, "myip", BASE_NICK )
        ok( "cmd_myip: handler returns PROCESSED", r == "PROCESSED" )
        ok( "cmd_myip: shows the prefixed user's ip, not the caller's",
            type( op._last( ) ) == "string" and string.find( op._last( ), "192.0.2.7", 1, true ) ~= nil )
        ok( "cmd_myip: reply is NOT the caller's own ip",
            type( op._last( ) ) == "string" and string.find( op._last( ), "203.0.113.1", 1, true ) == nil )
    else
        ok( "cmd_myip: exports _onbmsg (pre-fix plugin?)", false )
    end
end

-- cmd_myinf: `+myinf <base nick>` resolution
do
    local target = make_prefixed_target( )
    _G.cfg = {
        get = function( k )
            if k == "language" then return "en" end
            if k == "cmd_myinf_permission" then return { [10] = 10, [20] = 20, [100] = 100 } end
            return nil
        end,
        loadlanguage = function( ) return {} end,
    }
    _G.utf  = _utf
    _G.util = {
        getlowestlevel = function( tbl )
            local lo; for lvl in pairs( tbl ) do if not lo or lvl < lo then lo = lvl end end
            return lo or 0
        end,
    }
    _G.audit = _audit
    _G.hub   = make_hub( target )

    local p = assert( loadfile( "scripts/cmd_myinf.lua" ) )( )
    check_helper( "cmd_myinf", p, target )
end

----------------------------------------------------------------------
io.write( string.format( "\n%d/%d checks passed\n", checks - failures, checks ) )
if failures > 0 then io.write( "FAIL nick_prefix_resolution_test\n" ); os.exit( 1 ) end
io.write( "OK nick_prefix_resolution_test\n" )
