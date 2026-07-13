--[[

    hub.lua by blastbeat

        v0.41: by pulsar
            - changes in login() function

        v0.40: by pulsar
            - fix #173 -> https://github.com/luadch/luadch/issues/173
                - changes in "BINF" function
                    - unregistered user could no longer log in

        v0.39: by pulsar
            - fix: #164 -> https://github.com/luadch/luadch/issues/164
                - convert "_cfg_min_share" in "_pingsup" from gigabyte to byte  / thx Tantrix

        v0.38: by blastbeat
            - enable IPv6
            - improve onFailedAuth listeners

        v0.37: by pulsar
            - changes in _i18n_login_message

        v0.36: by pulsar
            - added "updateusers" function
                - updates the users information during runtime
                    usage: hub.updateusers()

        v0.35: by pulsar
            - added "cid" to listener "onFailedAuth"

        v0.34: by pulsar
            - added "ip" to listener "onFailedAuth"
            - added "TL-1" (The client should never attempt to reconnect) to:
                - ISTA 220, 221, 223, 226, 240
            - changes in createbot()
                - added "hub_bot_email" to hubbot INF

        v0.33: by pulsar
            - added new listener "onFailedAuth"

        v0.32: by pulsar
            - added new listener "onReg"
            - added new listener "onDelreg"

        v0.31: by pulsar
            - added lastseen to _regex.reguser
            - added lastseen to disconnect function
            - added lastseen to _verify table

        v0.30: by pulsar
            - changes in login()
                - improved method to get tls version
            - fix #123 -> https://github.com/luadch/luadch/issues/123
                - changes in createbot()
                    - changed "I4" flag from "0.0.0.0" to ""
            - changes in "_verify", fixed login problem with announcer

        v0.29: by blastbeat
            - changes in insertreguser() function
            - remove reloadusers

        v0.28: by pulsar
            - changes in user.redirect() function

        v0.27: by pulsar
            - changes in login() function

        v0.26: by blastbeat
            - forward DSCH messages

        v0.25: by tarulas
            - added "hub_listen"

        v0.24: by pulsar
            - changes in loadusers() function
                - added cfg_checkusers()

        v0.23: by pulsar
            - changes in reghubbot() function
                - disabled the hubbot to mainchat bridge
            - changes in loadlanguage() function
                - added "hub_hubbot_response"
            - removed "_i18n_hub_is_full" double entry
            - small fix in user.kill() function
                - if the optional parameter is "TL-1" then the client don't try to reconnect

        v0.22: by blastbeat
            - fixed jucy I4 flag issue

        v0.21: by pulsar
            - improved out_put/out_error messages

        v0.20: by blastbeat
            - add user.sslinfo() function

        v0.19: by pulsar
            - add TLS info flag to login function

        v0.18: by blastbeat
            - changes in user.setlevel() function

        v0.17: by pulsar
            - improved BINF flags of bots in createbot()

        v0.16: by pulsar
            - using new luadch date style for:
                - lastlogout
                - lastconnect

        v0.15: by pulsar
            - improve "user.version"

        v0.14: by pulsar
            - add "AP" to "user.version"

        v0.13: by pulsar
            - change "profile.date" style, old: DD.MM.YYYY  new: YYYY-MM-DD

        v0.12: by blastbeat
            - fix v0.10

        v0.11: by blastbeat
            - added lastlogout to _regex.reguser
            - added lastlogout to disconnect function

        v0.10: by pulsar
            - fix missing escaping in "_normalsup" and "_pingsup"

        v0.09: by pulsar
            - changes in createbot() function
                - using "HubBot" TAG for the hubbot

        v0.08: by pulsar
            - fix missing "AP" in "IINF" / thx fly out to Derek (darekgal @ sourceforge)
                - fixes problems to detect hubsoft name at dchublist.org
            - fix "I4" in "BINF" function in the "_identify" table / thx fly out to scott (cottsay @ sourceforge)
                - fixes problems when luadch and a client both reside behind the same NAT

        v0.07: by pulsar
            - added "isiponline()" function / written by Night

        v0.06: by pulsar
            - added "insertreglevel()" function / thx fly out to Night for the idea an code improvement

        v0.05: by pulsar
            - changes in reloadusers() function

        v0.04: by pulsar
            - added "ADKEYP" in "_normalsup"
            - added "ADKEYP" in "_pingsup"

        v0.03: by pulsar
            - new "os.date()" output style, consistent output of date (win/linux/etc)

        v0.02: by pulsar
            - changed "level = tostring( level )"  to  "level = tonumber( level )"

        v0.01: by blastbeat

]]--

----------------------------------// DECLARATION //--

local clean = use "cleantable"
local doexit = use "doexit"
local tablesize = use "tablesize"
local requestexit = use "requestexit"

--// lua functions //--

local type = use "type"
local pcall = use "pcall"
local pairs = use "pairs"
local error = use "error"
local ipairs = use "ipairs"
local loadfile = use "loadfile"
local tostring = use "tostring"
local tonumber = use "tonumber"

--// lua libs //--

local io = use "io"
local os = use "os"
local table = use "table"
local string = use "string"
local coroutine = use "coroutine"

--// lua lib methods //--

local os_date = os.date
local os_time = os.time
local os_difftime = os.difftime
local table_concat = table.concat
local table_remove = table.remove

--// extern libs //--

local adclib = use "adclib"
local unicode = use "unicode"

--// extern lib methods //--

local utf = unicode.utf8

local utf_sub = utf.sub
local utf_gsub = utf.gsub
local utf_find = utf.find
local utf_match = utf.match
local utf_format = utf.format
local adclib_hash = adclib.hash
local adclib_escape = adclib.escape
local adclib_isutf8 = adclib.isutf8
local adclib_hashpas = adclib.hashpas
local adclib_unescape = adclib.unescape
local adclib_createsid = adclib.createsid
local adclib_createsalt = adclib.createsalt
local adclib_hasholdpas = adclib.hasholdpas

--// core scripts //--

local out = use "out"
local adc = use "adc"
local cfg = use "cfg"
local mem = use "mem"
local util = use "util"
local types = use "types"
local const = use "const"
local server = use "server"
local signal = use "signal"
local scripts = use "scripts"

-- User / bot factories and the ADC command dispatcher each live in
-- their own module since Phase 6d. All three use the bind_late()
-- pattern: hub.lua wires them in init() and re-binds whenever caches
-- are refreshed (loadsettings, loadlanguage, updateusers).
local _user_module     = use "hub_user_object"
local _bot_module      = use "hub_bot_object"
local _dispatch_module = use "hub_dispatch"

--// core methods //--

local types_utf8 = types.utf8

local cfg_get = cfg.get
local cfg_reload = cfg.reload
local cfg_saveusers = cfg.saveusers
local cfg_loadusers = cfg.loadusers
local cfg_checkusers = cfg.checkusers
local out_put = out.put
local out_error = out.error
local out_scriptmsg = out.scriptmsg
local signal_set = signal.set
local signal_get = signal.get
local scripts_import = scripts.import
local scripts_firelistener = scripts.firelistener
local mem_free = mem.free
local adc_parse = adc.parse
local types_check = types.check
local util_formatseconds = util.formatseconds
local util_date = util.date
local util_difftime = util.difftime

--// functions //--

local checkuser

local init
local loop
local incoming
local createhub
local createbot
local createuser
local disconnect
local loadsettings
local loadlanguage

local userisbot
local usernotregged

local featuretoken

local exit
local login
local debug
local import
local getbot
local regbot
local restart
local newuser
local reguser
local getuser
local shutdown
local getusers
local killuser
local escapeto
local reghubbot
local sendtoall
local broadcast
local usercount
local reloadcfg
local loadusers
local escapefrom
local insertuser
local delreguser
local featuresend
local killscripts
local iscidonline
local issidonline
local getregusers
local isnickonline
local isuseronline
local isuserregged
local loadregusers
local insertreguser
local restartscripts
local isuserconnected
local insertreglevel
local isiponline
local updateusers -- new
local add_server_handler

--// tables //--

local _luadch
local _verify
local _normal
local _protocol
local _identify
local _servers = { }

local _G
local _regex
local _regusers
local _usersids
local _usercids
local _usernicks
local _userclients
local _regusercids
local _regusernicks
local _matchreguser

local _nobot_normalstatesids
local _normalstatesids
local _bots

local _tmp

local _user_count

--// simple data types //--

local _
local _hubbot

local _pingsup
local _normalsup
local _normalsup_regonly
local _hubinf_regonly

--// language //--

local _i18n_hub_is_full
local _i18n_no_base_support
local _i18n_no_cid_nick_found
local _i18n_cid_taken
local _i18n_nick_taken
local _i18n_invalid_pid
local _i18n_invalid_ip
local _i18n_reg_only
local _i18n_invalid_pass
local _i18n_nick_or_cid_taken
local _i18n_login_message
local _i18n_unknown
local _i18n_max_bad_password
local _i18n_hubbot_response

--// caching config //--

local _cfg_hub_bot
local _cfg_hub_bot_desc
local _cfg_hub_name
local _cfg_hub_description
local _cfg_bot_rank
local _cfg_bot_level
local _cfg_reg_rank
local _cfg_reg_level
local _cfg_max_users
local _cfg_reg_only
--local _cfg_hub_pass
local _cfg_nick_change
local _cfg_hub_hostaddress
local _cfg_hub_website
local _cfg_hub_network
local _cfg_hub_owner
local _cfg_min_share
local _cfg_max_share
local _cfg_min_slots
local _cfg_max_slots
local _cfg_max_user_hubs
local _cfg_max_reg_hubs
local _cfg_max_op_hubs
local _cfg_min_user_hubs
local _cfg_min_reg_hubs
local _cfg_min_op_hubs
local _cfg_hub_redirect_protocols
local _cfg_hub_email
local _cfg_max_bad_password
local _cfg_bad_pass_timeout
local _cfg_kill_wrong_ips

--// constants //--

local NAME = const.PROGRAM_NAME
local VERSION = const.VERSION

-- Wires hub_dispatch with the current state / cfg cache / i18n /
-- format strings. Called from init() and from each cache rebuild
-- (loadsettings, loadlanguage, updateusers). Placed AFTER the forward
-- `local` declarations above so the closure captures every dep.
local function _bind_dispatch_module( )
    _dispatch_module.bind{
        isuserconnected      = isuserconnected,
        isuserregged         = isuserregged,
        insertuser           = insertuser,
        insertreguser        = insertreguser,
        login                = login,
        _regusers            = _regusers,
        _normalstatesids     = _normalstatesids,
        _get_user_count      = function() return _user_count end,
        VERSION              = VERSION,
        _hubinf_regonly      = _hubinf_regonly,
        _pingsup             = _pingsup,
        _normalsup           = _normalsup,
        _normalsup_regonly   = _normalsup_regonly,
        _cfg_reg_only        = _cfg_reg_only,
        _cfg_max_users       = _cfg_max_users,
        _cfg_kill_wrong_ips  = _cfg_kill_wrong_ips,
        _cfg_max_bad_password = _cfg_max_bad_password,
        _cfg_bad_pass_timeout = _cfg_bad_pass_timeout,
        _cfg_min_share       = _cfg_min_share,
        _cfg_max_share       = _cfg_max_share,
        _cfg_min_slots       = _cfg_min_slots,
        _cfg_max_slots       = _cfg_max_slots,
        _cfg_max_user_hubs   = _cfg_max_user_hubs,
        _cfg_max_reg_hubs    = _cfg_max_reg_hubs,
        _cfg_max_op_hubs     = _cfg_max_op_hubs,
        _cfg_min_user_hubs   = _cfg_min_user_hubs,
        _cfg_min_reg_hubs    = _cfg_min_reg_hubs,
        _cfg_min_op_hubs     = _cfg_min_op_hubs,
        _cfg_hub_redirect_protocols = _cfg_hub_redirect_protocols,
        _cfg_hub_email       = _cfg_hub_email,
        _cfg_hub_name        = _cfg_hub_name,
        _cfg_hub_description = _cfg_hub_description,
        _cfg_hub_hostaddress = _cfg_hub_hostaddress,
        _cfg_hub_website     = _cfg_hub_website,
        _cfg_hub_network     = _cfg_hub_network,
        _cfg_hub_owner       = _cfg_hub_owner,
        _i18n_unknown            = _i18n_unknown,
        _i18n_cid_taken          = _i18n_cid_taken,
        _i18n_hub_is_full        = _i18n_hub_is_full,
        _i18n_invalid_ip         = _i18n_invalid_ip,
        _i18n_invalid_pass       = _i18n_invalid_pass,
        _i18n_invalid_pid        = _i18n_invalid_pid,
        _i18n_max_bad_password   = _i18n_max_bad_password,
        _i18n_nick_taken         = _i18n_nick_taken,
        _i18n_no_base_support    = _i18n_no_base_support,
        _i18n_no_cid_nick_found  = _i18n_no_cid_nick_found,
        _i18n_reg_only           = _i18n_reg_only,
    }
end

----------------------------------// DEFINITION //--

_user_count = 0

-- IINF.RP (#147 T1.2 / ADC-EXT 3.32 RDEX) advertises the redirect URI
-- schemes the hub accepts. cfg-driven bitmask: 1 = ADC, 2 = ADCS,
-- 4 = NEODC (legacy), default 3 (ADC + ADCS).
_normalsup = "" ..
    "ISUP ADBAS0 ADBASE ADTIGR ADKEYP ADOSNR ".. --> ADKEYP (keyprint)
    "ADUCM0 ADUCMD\nISID %s\nIINF " ..
    "NI%s APLUADCH VE%s DE%s RP%s HU1 HI1 CT32\n"
_normalsup_regonly = "" ..
    "ISUP ADBAS0 ADBASE ADTIGR ADKEYP ADOSNR ".. --> ADKEYP (keyprint)
    "ADUCM0 ADUCMD\nISID %s\nIINF " ..
    "NILuadch APLUADCH VE%s RP%s HU1 HI1 CT32\n"
_hubinf_regonly = "IINF NI%s DE%s\n"
-- ADC-EXT PING fields. The XU/XR/XO (max hubs per user-class) and
-- the symmetric MU/MR/MO (min hubs) are all cfg-driven via
-- `_cfg_max/min_*_hubs`. The min defaults are 0 = "no federation
-- requirement", which is what most public ADC hubs advertise and
-- the most permissive baseline; operators wanting to enforce min-hub
-- policy can set `min_user_hubs` / `min_reg_hubs` / `min_op_hubs` in
-- cfg/cfg.tbl.
-- T1.3 / T1.4 of #147: PING now also emits SS (total bytes shared
-- across the hub), SF (total files shared), and HE (hub email /
-- contact). All three are spec-defined in ADC-EXT 3.4.1 and round
-- out the PING reply with the data hublist scrapers expect. SS/SF
-- are aggregated over online users at PING-time; HE comes from the
-- `hub_email` cfg key already used elsewhere.
_pingsup = "" ..
    "ISUP ADBAS0 ADBASE ADTIGR ADKEYP ADOSNR " .. --> ADKEYP (keyprint)
    "ADPING ADUCM0 ADUCMD\nISID %s\nIINF " ..
    "NI%s APLUADCH VE%s DE%s HH%s WS%s NE%s OW%s HE%s RP%s " ..
    "UC%s SS%s SF%s MS%s XS%s ML%s XL%s MU%s MR%s MO%s XU%s XR%s XO%s MC%s UP%s HU1 HI1 CT32\n"


_G = _G
_usersids = { }    -- keys: SIDs
_usernicks = { }    -- keys: nicks
_userclients = { }    -- keys: clients, users
_usercids = { TIGR = { } }    -- keys: sessions hashs (TIGR)
_regusernicks = { }    -- same as above...
_regusercids = { TIGR = { } }
_regex = {

    reguser = {    -- single-hash schema; multi-hash support tracked in issue #48

        cid = "^" .. string.rep( "[A-Z2-7]", 39 ) .. "$",
        hash = "^" .. string.rep( "[A-Z]", 3 ) .. "[A-Z0-9]$",
        nick = "^[^ \n]+$",
        password = "^[%S]+$",
        rank    = "^%d+$",
        level = "^%d+$",
        is_bot = "^%d+$",
        date = ".*",
        by = "^[^ \n]+$",
        badpassword = "^%d+$",
        lastconnect = "^%d+$",
        lastlogout = "^%d+$",
        lastseen = "^%d+$",
        is_online = "^%d+$",
        --speedinfo = "^[%S]+$",

    },

}

_matchreguser = _regex.reguser
_normalstatesids = { }    -- keys: SIDs
_nobot_normalstatesids = { }    -- keys: SIDs
_bots = { }    -- registered in-hub bots, keys: bot objects, values: SID

_tmp = { }

local finallisteners

featuretoken = function( s )
    _tmp[ utf_sub( s, 2, -1 ) ] = utf_sub( s, 1, 1 )
end

checkuser = function( data, traceback, noerror )
    local what = type( data )
    if not ( _userclients[ data ] or _bots[ data ] ) then
        _ = noerror or error( "wrong type: user expected, got " .. what, traceback or 3 )
        return false
    end
    return true
end

loadusers = function( )
    cfg_checkusers()
    local users, err = cfg_loadusers( )
    _ = err and out_error( "hub.lua: function 'loadusers': error while loading userdatabase: ", err )
    for i, usertbl in ipairs( users ) do
        for key, value in pairs( usertbl ) do
            local regex = _matchreguser[ tostring( key ) ]
            if not regex or not utf_match( tostring( value ), regex ) then
                out_error( "hub.lua: function 'loadusers': error while loading userdatabase: corrupt database, creating new one" )
                users = { }
                break
            end
        end
    end
    return users
end

updateusers = function( ) -- new
    local users, err = cfg_loadusers( )
    _ = err and out_error( "hub.lua: function 'updateusers': error while loading userdatabase: ", err )
    for i, usertbl in ipairs( users ) do
        for key, value in pairs( usertbl ) do
            local regex = _matchreguser[ tostring( key ) ]
            if not regex or not utf_match( tostring( value ), regex ) then
                out_error( "hub.lua: function 'updateusers': error while loading userdatabase: corrupt database, creating new one" )
                users = { }
                break
            end
        end
    end
    _regusers = users
    _regusernicks = { }
    _regusercids = { }
    _regusercids.TIGR = { }
    for i, usertbl in ipairs( _regusers ) do
        usertbl.is_online = 0
        local cid = usertbl.cid
        local hash = usertbl.hash or "TIGR"
        local nick = usertbl.nick
        if nick then
            _regusernicks[ nick ] = usertbl
        end
        if hash and cid then
            _regusercids[ hash ] = _regusercids[ hash ] or { }
            _regusercids[ hash ][ cid ] = usertbl
        end
    end
    -- Re-bind hub_user_object / hub_bot_object so the factories see the
    -- freshly-loaded _regusers / _regusernicks tables. Without this, the
    -- modules would still hold references to the previous tables and any
    -- subsequent setlevel / setrank / setpassword save would write the
    -- stale data back to user.tbl. bot.profile / bot.regid would also
    -- read the wrong state.
    _user_module.bind{
        checkuser        = checkuser,
        disconnect       = disconnect,
        isuserconnected  = isuserconnected,
        sendtoall        = sendtoall,
        usernotregged    = usernotregged,
        _regex           = _regex,
        _regusernicks    = _regusernicks,
        _regusers        = _regusers,
        _usernicks       = _usernicks,
        _cfg_reg_rank    = _cfg_reg_rank,
        _cfg_reg_level   = _cfg_reg_level,
    }
    _bot_module.bind{
        disconnect       = disconnect,
        reguser          = reguser,
        userisbot        = userisbot,
        _bots            = _bots,
        _regusernicks    = _regusernicks,
        _regusers        = _regusers,
        _cfg_bot_level   = _cfg_bot_level,
        _cfg_bot_rank    = _cfg_bot_rank,
        _i18n_unknown    = _i18n_unknown,
    }
    _bind_dispatch_module()
    mem_free( )
end

userisbot = function( traceback )
    error( "user is bot, method not supported", ( type( traceback ) == "number" and traceback ) or 3 )
end

usernotregged = function( traceback )
    error( "user not regged", ( type( traceback ) == "number" and traceback ) or 3 )
end

debug = out_scriptmsg    -- public

login = function( user, bot )
    if bot then
        sendtoall( user:inf( ):adcstring( ) )
    elseif user then
        local sendonly = user:sup( ):hasparam( "ADOSNR" )
        if not sendonly then
            for sid, onlineuser in pairs( _normalstatesids ) do
                user.write( onlineuser:inf( ):adcstring( ) )
            end
        end
        user:state "normal"
	    _user_count = _user_count + 1
        local sid = user:sid( )
        _normalstatesids[ sid ] = user
        _nobot_normalstatesids[ sid ] = user
        insertreglevel( user ) --> thx fly out to Night for the idea
        sendtoall( user:inf( ):adcstring( ) )
        if sendonly then user:sendonly( ) end
        local use_ssl = cfg_get( "use_ssl" )
        local ssl_params = cfg_get( "ssl_params" )
        local get_tls_mode = function()
            if use_ssl then
                return string.sub( ssl_params.protocol, 4 ):gsub( "_", "." )
            end
            return "NO"
        end
        local TLS = "[TLS: " .. get_tls_mode() .. "]"
        local msg = utf_format( _i18n_login_message, 
            util.decode( '8129587ede4c' ), 
            VERSION, 
            TLS, 
            util_formatseconds( os_difftime( os_time( ), signal_get "start" ), true )
        )
        user:reply( msg, _hubbot )
        scripts_firelistener( "onLogin", user )
    end
    return true
end    -- private

insertreglevel = function( user ) --> this function makes it unnecessary the use the "scripts/hub_user_ranks.lua", thx Night
    --> send INF string to REG levels
    if user:isregged( ) then
        local key_level = cfg_get "key_level" or 50
        local user_level = user:level( )
        if ( user_level >= key_level ) then
            user:inf( ):addnp( "OP", "1" )
        else
            user:inf( ):addnp( "RG", "1" )
        end
        if user_level == 100 then
            user:inf( ):addnp( "CT", "16" )
        elseif ( user_level >= 80 ) then
            user:inf( ):addnp( "CT", "8" )
        elseif ( user_level >= key_level ) then
            user:inf( ):addnp( "CT", "4" )
        else
            user:inf( ):addnp( "CT", "2" )
        end
    end
end

insertuser = function( nick, cid, hash, user )
    _usernicks[ nick ] = user
    _usercids[ hash ] = _usercids[ hash ] or { }
    _usercids[ hash ][ cid ] = user
end    -- private

insertreguser = function( user, profile, user_cid, user_hash, user_nick  )
    if profile then
        for key, value in pairs( profile ) do
            if not utf_match( value, _matchreguser[ key ] ) then
                return nil, "invalid profile" -----!
            end
        end
        local hash = profile.hash
        local cid = profile.cid
        local nick = profile.nick
        if not ( ( cid and hash ) or nick ) then
            return nil, "no cid/hash/nick"-----!
        end
        if user and _usersids[ user:sid( ) ] then
            if user:isregged( ) then
                return nil, "user already inserted in hub"-----!
            end
            user:addregmethods( profile )
            user.addregmethods = nil
            if user_cid and user_hash and (not _regusercids[user_hash][user_cid]) then
               _regusercids[user_hash][user_cid] = profile
            end
            if user_nick and (not _regusernicks[user_nick]) then
               _regusernicks[user_nick] = profile
            end
            return user
        else
            return nil, "invalid user object"-----!
        end
    else
        return nil, "no profile"-----!
    end
end    -- private

newuser = function( client )
    local sid
    repeat
        sid = adclib_createsid( )
    until not _usersids[ sid ] and sid ~= "AAAA"
    local user = createuser( client, sid )
    _usersids[ sid ] = user
    _userclients[ user ] = client
    _userclients[ client ] = user
    --_userclients[ client ] = true
    user.alive = true    -- experimental flag
    client.setlistener( finallisteners )
    out_put( "hub.lua: function 'newuser': sid of new user: ", sid )
    return user, sid
end    -- private

loadregusers = function( )
    for i, usertbl in ipairs( _regusers ) do
        usertbl.is_online = 0  -- users are supposed to be offline
        local cid = usertbl.cid
        local hash = usertbl.hash or "TIGR"
        local nick = usertbl.nick
        if nick then
            _regusernicks[ nick ] = usertbl
        end
        if hash and cid then
            _regusercids[ hash ] = _regusercids[ hash ] or { }
            _regusercids[ hash ][ cid ] = usertbl
        end
    end
    cfg_saveusers( _regusers )  -- save modified user.tbl
end    -- private

import = scripts_import    -- public

restartscripts = function( )
    killscripts( )
    scripts.start( _luadch )
end    -- public

killscripts = function( )
    scripts.kill( )
    for bot, sid in pairs( _bots ) do
        bot.kill( )
    end
    if _cfg_hub_bot and _cfg_hub_bot ~= "" then    --// mmh..
        reghubbot( _cfg_hub_bot, _cfg_hub_bot_desc )
    end
    mem_free( )
end    -- private

reloadcfg = function( )
    local _, err = cfg_reload( )
    _ = err and out_error( "hub.lua: function 'reloadcfg': error while loading settings: ", err )
    mem_free( )
end    -- public

reghubbot = function( name, desc )
    _hubbot = regbot{ nick = name, desc = desc,
        client = function( self, adccmd )
            local user = _nobot_normalstatesids[ adccmd:mysid( ) ]
            if user and adccmd:fourcc( ) == "EMSG" then
                -- AirDC++ and other clients route a leading "+", "!" or "#" as a
                -- "server command" via private message to the hubbot. Forward those
                -- to the broadcast/command pipeline so cmd_* scripts can pick them
                -- up. Anything else is a real PM to the bot — keep the polite
                -- deflection so users don't accidentally trigger handlers by chatting.
                local text = escapefrom( adccmd[ 8 ] ) or ""
                if text:match( "^[+!#]" ) then
                    scripts_firelistener( "onBroadcast", user, adccmd, text )
                else
                    user:reply( _i18n_hubbot_response, _hubbot, _hubbot )
                end
            end
            return true
        end,
    }
    return _hubbot
end    -- private

getbot = function( which )    -- "all" returns currently-running; offline-but-regged bots tracked in #48
    if which == "all" then
        return _bots
    end
    return _hubbot
end    -- public

regbot = function( profile )
    if type( profile ) ~= "table" then
        return nil, "invalid profile"-----!
    end
    local sid
    repeat
        sid = adclib_createsid( )
    until not _usersids[ sid ] and sid ~= "AAAA"
    local bot, err = createbot( sid, profile )
    if not bot then
        return nil, err
    else
        _usersids[ sid ] = bot
        _normalstatesids[ sid ] = bot
        insertuser( bot.nick( ), bot.cid( ), "TIGR", bot )
        login( bot, true )
        return bot
    end
end    -- public

do
    local firstrun = true
    shutdown = function()
        if firstrun then
            use"print"("\n\nHub shutdown, please wait...\n\n") -- todo: proper logging, i18n
            for s, _ in pairs( _servers ) do
                s.shutdown()
            end
            firstrun = false
        end
    end
end

restart = function( )
    scripts_firelistener "onExit"
    signal.set( "hub", "restart" )
    server.killall( )
    mem_free( )
end    -- public

exit = function( )
    scripts_firelistener "onExit"
    signal.set( "hub", "exit" )
    server.killall( )
end    -- public

reguser = function( profile )
    if type( profile ) ~= "table" then
        return nil, "invalid profile"-----!
    end
    for key, value in pairs( profile ) do
        local regex = _matchreguser[ tostring( key ) ]
        if not regex or not utf_match( tostring( value ), regex ) then
            return nil, "invalid profile"-----!
        end
    end
    local hash = profile.hash or "TIGR"
    local cid = profile.cid
    local nick = profile.nick
    if not ( ( cid and hash ) or nick ) then
        return false, "no cid/hash/nick"-----!
    end
    if hash and cid then
        _regusercids[ hash ] = _regusercids[ hash ] or { }
        if _regusercids[ hash ][ cid ] then
            return nil, "cid already regged"-----!
        end
        local onlineuser = _usercids[ hash ][ cid ]
        if onlineuser then
            onlineuser:kill( "ISTA 224 " .. _i18n_nick_or_cid_taken .. "\n" )
        end
    end
    if nick then
        if _regusernicks[ nick ] then
            return nil, "nick already regged"-----!
        end
        local onlineuser = _usernicks[ nick ]
        if onlineuser then
            onlineuser:kill( "ISTA 222 " .. _i18n_nick_or_cid_taken .. "\n" )
        end
    end
    profile.date = profile.date or os_date( "%Y-%m-%d / %H:%M:%S" )
    profile.by = profile.by or _i18n_unknown
    if nick then
        _regusernicks[ nick ] = profile
    end
    if cid then
        _regusercids[ hash ][ cid ] = profile
    end
    _regusers[ #_regusers + 1 ] = profile
    cfg_saveusers( _regusers )
    scripts_firelistener( "onReg", nick )
    return true
end    -- public

delreguser = function( nick, cid, hash )
    hash = hash or "TIGR"
    if nick then
        nick = tostring( nick )
        if utf_find( nick, " " ) then
            nick = escapeto( nick )
        end
    end
    if _regusercids[ hash ] then
        local profile = _regusernicks[ nick ] or _regusercids[ hash ][ cid ]
        if type( profile ) ~= "table" then
            return false, "wrong nick or cid"-----!
        end
        local cid = profile.cid
        local nick = profile.nick
        if nick then
            _regusernicks[ nick ] = nil
        end
        if cid then
            _regusercids[ hash ][ cid ] = nil
        end
        for i, tbl in ipairs( _regusers ) do
            if tbl == profile then
                table_remove( _regusers, i )
                cfg_saveusers( _regusers )
                scripts_firelistener( "onDelreg", nick )
                break
            end
        end
        return true
    end
end    -- public

isuseronline = function( nick, sid, cid, hash )
    hash = hash or "TIGR"
    local user
    if nick then
        local nick = tostring( nick )
        if utf_find( nick, " " ) then
            nick = escapeto( nick )
        end
        user = _usernicks[ nick ]
    elseif cid and _usercids[ hash ] then
        user = _usercids[ hash ][ cid ]
    elseif sid then
        return _normalstatesids[ sid ]
    end
    if user and user:state( ) == "normal" then
        return user
    end
    return nil
end    -- public

iscidonline = function( cid, hash )
    local user
    hash = hash or "TIGR"
    if _usercids[ hash ] then
        user =  _usercids[ hash ][ cid ]
    end
    if user and user:state( ) == "normal" then
        return user
    end
    return nil
end    -- public

isiponline = function( ip )
	local _user
    for sid, user in pairs( _nobot_normalstatesids ) do
		_user = user
		if _user:ip( ) == ip then
			return _user
		end
    end
	return nil
end

isnickonline = function( nick )
    local user
    if nick then
        local nick = tostring( nick )
        if utf_find( nick, " " ) then
            nick = escapeto( nick )
        end
        user =  _usernicks[ nick ]
    end
    if user and user:state( ) == "normal" then
        return user
    end
    return nil
end    -- public

issidonline = function( sid )
    return _normalstatesids[ sid ]
end

isuserconnected = function( nick, sid, cid, hash )
    hash = hash or "TIGR"
    if nick then
        local nick = tostring( nick )
        if utf_find( nick, " " ) then
            nick = escapeto( nick )
        end
        return _usernicks[ nick ]
    elseif cid and _usercids[ hash ] then
        return _usercids[ hash ][ cid ]
    elseif sid then
        return _usersids[ sid ]
    end
    return nil
end    -- public

isuserregged = function( nick )
    local nickuser
    local nick = tostring( nick )
    if nick and utf_find( nick, " " ) then
        nick = escapeto( nick )
    end
    return _regusernicks[ nick ]
end

escapeto = adclib_escape    -- public

escapefrom = adclib_unescape    -- public

getuser = function( sid )
    return _nobot_normalstatesids[ sid ], _normalstatesids[ sid ], _usersids[ sid ]
end    -- public

--[[killuser = function( user, client, adcstring, quitstring1, quitstring2 )    -- ugly
    user = user or ( client and _userclients[ client ] )
    client = client or ( user and _userclients[ user ] )
    _ = client and ( adcstring and client.write( adcstring ) )
    if user then
        local usersid = user:sid( )
        local usernick = user:nick( ) or { }    -- dangerous?! ugly?
        local usercid = user:cid( ) or { }
        local userhash = user:hash( ) or "TIGR"
        local userstate = user:state( )
        local ip, port = user:peer( )

        _usersids[ usersid ] = nil
        _usernicks[ usernick ] = nil
        _usercids[ userhash ][ usercid ] = nil
        _userclients[ user ] = nil
        _normalstatesids[ usersid ] = nil
        _nobot_normalstatesids[ usersid ] = nil

        local qui = "IQUI " .. usersid .. "\n"

        quitstring1 = quitstring1 or qui
        user.write( quitstring1 )
        if userstate == "normal" then
            quitstring2 = quitstring2 or qui
            sendtoall( quitstring2 )
            scripts_firelistener( "onLogout", user )
        end
        user.destroy( )
        out_put( "hub.lua: remove user ", usersid, " ", ip, ":", port )
    end
    if not client then
        return nil, "no client to close"-----!
    end
    client.dispatchdata( )
    client.close( )
    _userclients[ client ] = nil
    return true
end    -- private]]

sendtoall = function( adcstring )
    types_utf8( adcstring )    -- raises on non-utf8 input
    local counter = 0
    for sid, user in pairs( _nobot_normalstatesids ) do
        --if not user:isbot( ) then
            user.write( adcstring )
            counter = counter + 1
        --end
    end
    return counter
end    -- public

featuresend = function( adcstring, features )
    types_utf8( adcstring )    -- raises on non-utf8 input
    types_utf8( features )
    clean( _tmp )
    utf_gsub( features, "([+-][^+-]+)", featuretoken )
    local counter = 0
    for sid, user in pairs( _nobot_normalstatesids ) do
        local bol = true
        --if not user:isbot( ) then
            --if features then
                for feature, sign in pairs( _tmp ) do
                    local support = user:hasfeature( feature )
                    if sign == "-" and support then
                        bol = false
                        break
                    elseif sign == "+" and not support then
                        bol = false
                        break
                    end
                end
            --end
            if bol then
                user.write( adcstring )
                counter = counter + 1
            end
        --end
    end
    return counter
end    -- public

broadcast = function( msg, from, pm, me )    -- this function sends BMSGs to users
    local counter = 0
    --// the following ode works not as espected ( adding a pm flag to BMSG has no effect ), so i use user:reply instead of hub:sendToAll //--

   --[[
    if not msg then
        return false, "Invalid msg"
    end
    if ( from and type( from ) ~= "table" ) or ( type( from ) == "table" and not from.sid ) then
        return false, "Invalid user object \"from\""
    end
    if ( pm and type( pm ) ~= "table" ) or ( type( pm ) == "table" and not pm.sid ) then
        return false, "Invalid user object \"pm\""
    end
    local from_sid = " " .. ( ( from and from:sid( ) ) or ( pm and pm:sid( ) ) ) or ""
    local group_sid = ( pm and " PM" .. pm:sid( ) ) or ""
    local fourcc = ( features and ( "FMSG " .. tostring( features ) ) ) or ( ( from or pm ) and "BMSG" ) or "IMSG"
    msg = " " .. this:escapeTo( tostring( msg ) ) .. ( ( me == 1 and " ME1" ) or "" )
    return this:sendToAll( fourcc .. from_sid .. msg .. group_sid .. "\n", features )
    ]]

    for sid, user in pairs( _nobot_normalstatesids ) do
        --if not user:isbot( ) then
            user:reply( msg, from, pm, me, 4 )
            counter = counter + 1
        --end
    end
    return counter
end    -- public


getusers = function( )
    return _nobot_normalstatesids, _normalstatesids, _usersids
end    -- public

getregusers = function( )
  return _regusers, _regusernicks, _regusercids
end    -- public

createhub = function( )
    return {

        _VERSION = VERSION,

        exit = exit,
        --login = login,    -- private
        debug = debug,
        import = import,
        getbot = getbot,
        regbot = regbot,
        restart = restart,
        shutdown = shutdown,
        --newuser = newuser,    -- private
        reguser = reguser,
        getuser = getuser,
        getusers = getusers,
        --killuser = killuser,    -- private
        escapeto = escapeto,
        --reghubbot = reghubbot,    -- private
        sendtoall = sendtoall,
        broadcast = broadcast,
        usercount = usercount,
        reloadcfg = reloadcfg,
        escapefrom = escapefrom,
        --insertuser = insertuser,    -- private
        delreguser = delreguser,
        requestexit = requestexit,
        featuresend = featuresend,
        --killscripts = killscripts,    -- private
        iscidonline = iscidonline,
        issidonline = issidonline,
        getregusers = getregusers,
        isnickonline = isnickonline,
        isiponline = isiponline,
        --isuseronline = isuseronline,    -- private
        --isuserregged = isuserregged,    -- private
        --loadregusers = loadregusers,    -- private
        --insertreguser = insertreguser,    -- private
        restartscripts = restartscripts,
        --isuserconnected = isuserconnected,    -- private
        updateusers = updateusers,

    }
end    -- private

createbot = function( _sid, p )
    return _bot_module.createbot( _sid, p )
end    -- private


createuser = function( _client, _sid )
    return _user_module.createuser( _client, _sid )
end    -- private


incoming = function( client, data, err )
    local user = _userclients[ client ]
    local usersid = user.sid( )
    user.alive = true    -- experimental flag
    if data == "" or not data then    -- useless data, skip processing
        return true
    end
    if not adclib_isutf8( data ) then    -- check incoming data
        out_put( "hub.lua: function 'incoming': protocol error: no utf8 string" )
        return true
    end
    local adccmd, fourcc = adc_parse( data )
    if adccmd then    -- adc command, try to process
        local type = adccmd:type( )
        local cmd =  adccmd:cmd( )
        local mysid = adccmd:mysid( )
        local userstate = user.state( )
        local targetsid = adccmd:targetsid( )
        local targetuser = _normalstatesids[ targetsid ]
        out_put( "hub.lua: function 'incoming': user: ", usersid, ", state: ", userstate )
        if scripts_firelistener( "onIncoming", type, cmd, adccmd, user, targetuser ) then  -- generic script listener
            return true
        end
        if targetsid and not targetuser then    -- targetuser doesnt exist anymore
            user.write "ISTA 140\n"
        elseif ( not mysid ) or ( mysid == usersid ) then    -- match sids
            local bol, ret = pcall( _dispatch_module.states, user, adccmd, fourcc, userstate, targetuser )
            if not bol then     -- error happened
                out_error( "hub.lua: function 'incoming': lua error: ", ret )
            elseif not ret then     -- need to forward message
                if type == "B" then
                    sendtoall( adccmd:adcstring( ) )
                elseif type == "F" then
                    local features = adccmd[ 6 ]
                    featuresend( adccmd:adcstring( ), features )
                elseif type == "E" then
                    targetuser.write( adccmd:adcstring( ) )
                    if not targetuser.isbot( ) then user.write( adccmd:adcstring( ) ) end
                elseif type == "D" then
                    targetuser.write( adccmd:adcstring( ) )
                else    -- luadch only allows B, F, E, D atm
                    user.write( "ISTA 125 FC" .. fourcc .. "\n" )
                end
            end
        else    -- user sends with invalid sid -> kick
            user:kill( "ISTA 240\n", "TL-1" )
        end
        out_put( "hub.lua: function 'incoming': adc command processed" )
    end
    return true
end

disconnect = function( client, err, user, quitstring )
    if not client then    -- should not happen
        out_error( "hub.lua: function 'disconnect': no client! disconnect error: ", err )
        return false
    end
    local user = user or _userclients[ client ]
    --local user = client
    if user then
        local usersid = user.sid( )
        local usernick = user.nick( ) or { }    -- dangerous?! ugly?
        local usercid = user.cid( ) or { }
        local userhash = user.hash( ) or "TIGR"
        local userstate = user.state( )
        local ip, port = user.peer( )

        _usersids[ usersid ] = nil
        -- #91: a pending-takeover connection (reg_only nick collision,
        -- BINF stored ._takeover_target and skipped insertuser) does
        -- NOT own the _usernicks[nick] slot; that still belongs to the
        -- existing online user. If this user disconnects pre-HPAS
        -- (failed auth, network drop, race), we must not wipe the
        -- legitimate user's mapping. Only clear the slot if it is
        -- actually ours.
        if _usernicks[ usernick ] == user then
            _usernicks[ usernick ] = nil
        end
        _usercids[ userhash ][ usercid ] = nil
        _userclients[ user ] = nil
        _normalstatesids[ usersid ] = nil
        _nobot_normalstatesids[ usersid ] = nil
        if user:isregged() then _regusercids[userhash][usercid] = nil end

        if userstate == "normal" then
	    _user_count = _user_count - 1
            if user:isregged( ) then
                local profile = user:profile( )
                profile.lastlogout = util_date( )
                profile.lastseen = util_date( )
                profile.is_online = 0
                cfg_saveusers( _regusers )
            end
            sendtoall( quitstring or ( "IQUI " .. usersid .. "\n" ) )
            scripts_firelistener( "onLogout", user )
        end
        user.destroy( )
        out_put( "hub.lua: function 'disconnect': remove user ", usersid, " ", ip, ":", port )
    end
    _userclients[ client ] = nil
    return true
end

loadlanguage = function( )

    local i18n, err = cfg.loadlanguage( )

    _ = err and out_put( "hub.lua: function 'loadlanguage': error while loading language file: ", err )

    i18n = i18n or { }

    _i18n_unknown = adclib_escape( i18n.hub_unknown or "<UNKNOWN>" )
    _i18n_reg_only = adclib_escape( i18n.hub_reg_only or "Registered users only." )
    _i18n_cid_taken = adclib_escape( i18n.hub_cid_taken or "Your CID is taken." )
    _i18n_nick_taken = adclib_escape( i18n.hub_nick_taken or "Your nick is taken." )
    _i18n_invalid_ip = adclib_escape( i18n.hub_invalid_ip or "Your IP in INF does not match with your real IP. Real IP/Your IP: " )
    _i18n_hub_is_full = adclib_escape( i18n.hub_hub_is_full or "Hub is full." )
    _i18n_invalid_pid = adclib_escape( i18n.hub_invalid_pid or "Your PID is invalid." )
    _i18n_invalid_pass = adclib_escape( i18n.hub_invalid_pass or "Invalid password." )
    _i18n_login_message = i18n.hub_login_message or "This server is running %s %s %s (Uptime: %d days, %d hours, %d minutes, %d seconds)"
    _i18n_no_base_support = adclib_escape( i18n.hub_no_base_support or "Your client does not support BASE." )
    _i18n_max_bad_password = adclib_escape( i18n.hub_max_bad_password or "Max bad password exceeded. Timeout in seconds: " )
    _i18n_nick_or_cid_taken = adclib_escape( i18n.hub_nick_or_cid_taken or "Nick/CID taken." )
    _i18n_no_cid_nick_found = adclib_escape( i18n.hub_no_cid_nick_found or "No CID/PID/NICK/IP found in your INF." )
    _i18n_hubbot_response = i18n.hub_hubbot_response or "I am the Hubbot, do you really want to talk to me?"
    _bind_dispatch_module()
end

loadsettings = function( )    -- caching table lookups...
    _cfg_hub_bot = cfg_get "hub_bot"
    _cfg_hub_bot_desc = cfg_get "hub_bot_desc"
    _cfg_hub_name = escapeto( cfg_get "hub_name" )
    _cfg_hub_description = escapeto( cfg_get "hub_description" )
    _cfg_bot_rank = cfg_get "bot_rank"
    _cfg_bot_level = cfg_get "bot_level"
    _cfg_reg_rank = cfg_get "reg_rank"
    _cfg_reg_level = cfg_get "reg_level"
    _cfg_max_users = cfg_get "max_users"
    _cfg_reg_only = cfg_get "reg_only"
    --_cfg_hub_pass = cfg_get "hub_pass"
    _cfg_hub_hostaddress = escapeto( cfg_get "hub_hostaddress" )
    _cfg_hub_website = escapeto( cfg_get "hub_website" )
    _cfg_hub_network = escapeto( cfg_get "hub_network" )
    _cfg_hub_owner = escapeto( cfg_get "hub_owner" )
    _cfg_min_share = cfg_get "min_share"
    _cfg_max_share = cfg_get "max_share"
    _cfg_min_slots = cfg_get "min_slots"
    _cfg_max_slots = cfg_get "max_slots"
    _cfg_max_user_hubs = cfg_get "max_user_hubs"
    _cfg_max_reg_hubs = cfg_get "max_reg_hubs"
    _cfg_max_op_hubs = cfg_get "max_op_hubs"
    _cfg_min_user_hubs = cfg_get "min_user_hubs"
    _cfg_min_reg_hubs = cfg_get "min_reg_hubs"
    _cfg_min_op_hubs = cfg_get "min_op_hubs"
    _cfg_hub_redirect_protocols = cfg_get "hub_redirect_protocols"
    _cfg_hub_email = cfg_get "hub_email"
    _cfg_max_bad_password = cfg_get "max_bad_password"
    _cfg_bad_pass_timeout = cfg_get "bad_pass_timeout"
    _cfg_kill_wrong_ips = cfg_get "kill_wrong_ips" -- not in cfg.tbl
    _bind_dispatch_module()
end

add_server_handler = function( p )
    local hndl, err = server.addserver( p )
    if hndl then
        _servers[ hndl ] = true
    elseif err and err:find("address already in use") then
        local starttime = os.time()
        server.addtimer(
            coroutine.create(
                function( )
                    while true do
                        while os.difftime( os.time(), starttime ) < 30 do
                            coroutine.yield()
                        end
                        hndl, err = server.addserver( p )
                        if hndl then
                            _servers[ hndl ] = true
                            return
                        end
                        starttime = os.time()
                    end
                end
            )
        )
    end
end


init = function( )

    _regusers = loadusers( )

    loadsettings( )
    loadlanguage( )
    _luadch = createhub( )
    loadregusers( )
    -- Wire hub_user_object / hub_bot_object now that helpers, state
    -- tables and the cfg caches are all populated. createuser is invoked
    -- by newuser() on every incoming connection (listeners registered
    -- below kick in at server.addserver time); createbot is invoked
    -- below by reghubbot. Both must be wired before either runs.
    _user_module.bind{
        checkuser        = checkuser,
        disconnect       = disconnect,
        isuserconnected  = isuserconnected,
        sendtoall        = sendtoall,
        usernotregged    = usernotregged,
        _regex           = _regex,
        _regusernicks    = _regusernicks,
        _regusers        = _regusers,
        _usernicks       = _usernicks,
        _cfg_reg_rank    = _cfg_reg_rank,
        _cfg_reg_level   = _cfg_reg_level,
    }
    _bot_module.bind{
        disconnect       = disconnect,
        reguser          = reguser,
        userisbot        = userisbot,
        _bots            = _bots,
        _regusernicks    = _regusernicks,
        _regusers        = _regusers,
        _cfg_bot_level   = _cfg_bot_level,
        _cfg_bot_rank    = _cfg_bot_rank,
        _i18n_unknown    = _i18n_unknown,
    }
    _bind_dispatch_module()
    reghubbot( cfg_get "hub_bot", cfg_get "hub_bot_desc" )
    scripts.start( _luadch )
    for i, port in pairs( cfg_get "tcp_ports" ) do
        for j, ip in pairs( cfg_get "hub_listen" ) do
            add_server_handler{ listeners = { incoming = newuser, disconnect = disconnect }, port = port, ip = ip }
        end
    end
    for i, port in pairs( cfg_get "ssl_ports" ) do
        for j, ip in pairs( cfg_get "hub_listen" ) do
            add_server_handler{ listeners = { incoming = newuser, disconnect = disconnect }, port = port, ip = ip, sslctx = cfg_get "ssl_params", maxconnections = 10000, startssl = true }
        end
    end
    for i, port in pairs( cfg_get "tcp_ports_ipv6" ) do
        for j, ip in pairs( cfg_get "hub_listen" ) do
            add_server_handler{ listeners = { incoming = newuser, disconnect = disconnect }, port = port, ip = ip, family = "ipv6" }
        end
    end
    for i, port in pairs( cfg_get "ssl_ports_ipv6" ) do
        for j, ip in pairs( cfg_get "hub_listen" ) do
            add_server_handler{ listeners = { incoming = newuser, disconnect = disconnect }, port = port, ip  = ip, sslctx = cfg_get "ssl_params", maxconnections = 10000, startssl = true, family = "ipv6" }
        end
    end
    server.addtimer(
        function( )
            scripts_firelistener "onTimer"
        end
    )
    cfg.registerevent( "reload", loadlanguage )
    cfg.registerevent( "reload", loadsettings )
end

loop = function()
    signal_set( "external_exit_request", false )
    signal_set( "hub", "run" )
    -- One-time boot line: the compile-time select() capacity (luasocket
    -- FD_SETSIZE). server.tick() selects over every connected socket at once,
    -- so once the hub holds this many sockets socket.select raises "too many
    -- sockets" and this loop dies. On Windows this is the Winsock default 64
    -- unless the luasocket build raises it (luasocket/CMakeLists.txt, #416);
    -- on Linux glibc it is 1024. Logged (event.log) so operators can diagnose
    -- that class of crash; watching more sockets needs the select->poll port
    -- (#310).
    out_put( "hub.lua: select() capacity (FD_SETSIZE): ", ( use "socket" )._SETSIZE, " sockets" )
    while signal_get "hub" == "run" do
        server.tick()
        if not signal_get( "external_exit_request" ) then
            if doexit( ) then
                if not scripts_firelistener "onShutdown" then
                    shutdown( )
                end
                signal_set( "external_exit_request", true )
            end
        end
    end
    return signal_get "hub"
end

----------------------------------// BEGIN //--

use "setmetatable" ( _usernicks, { __mode = "v" } )
use "setmetatable" ( _userclients, { __mode = "kv" } )
use "setmetatable" ( _usercids.TIGR, { __mode = "v" } )
use "setmetatable" ( _normalstatesids, { __mode = "v" } )
use "setmetatable" ( _nobot_normalstatesids, { __mode = "v" } )

types.add( "user", checkuser )

finallisteners = { incoming = incoming, disconnect = disconnect }

----------------------------------// PUBLIC INTERFACE //--

return {

    init = init,
    loop = loop,

    object = _luadch,

}
