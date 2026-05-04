--[[

    hub_dispatch.lua - the ADC command dispatcher extracted from core/hub.lua

    Phase 6d-3 of the hub.lua decomposition. Contains:

      - the four state-machine handler tables _protocol, _identify,
        _verify, _normal (one per ADC connection state)
      - states(), which routes an incoming command to the right
        handler based on the user's current state

    These ~270 lines were the largest remaining chunk of "logic with many
    upvalues" in hub.lua after the createuser / createbot extractions.
    Moving them here drops hub.lua under the Phase 6 1500-line ceiling.

    The dispatcher reads HEAVILY from hub.lua's cfg cache (_cfg_*),
    i18n strings (_i18n_*), format strings (_pingsup, _normalsup,
    _normalsup_regonly, _hubinf_regonly), and the user-state count
    (_user_count). Same bind_late() pattern as cfg_defaults / cfg_users /
    cfg_lang / hub_user_object / hub_bot_object: hub.lua calls
    _dispatch_module.bind({...}) once after init() and again whenever
    any of these caches are refreshed (loadsettings, loadlanguage,
    updateusers).

    _user_count is incremented/decremented in hub.lua's incoming and
    disconnect; we receive it as a getter closure so the dispatcher
    sees the live value rather than a stale snapshot.

    Public surface:

        {
            bind   = function(deps)
            states = function(user, adccmd, fourcc, state, targetuser)
        }

]]--

local use = use

local tostring = use "tostring"
local tablesize = use "tablesize"

local adclib = use "adclib"
local cfg = use "cfg"
local ratelimit = use "ratelimit"
local scripts = use "scripts"
local signal = use "signal"
local unicode = use "unicode"
local util = use "util"
local os = use "os"

-- Stable upvalues - resolved once at file load.
local adclib_createsalt = adclib.createsalt
local adclib_escape = adclib.escape
local adclib_hash = adclib.hash
local adclib_hashpas = adclib.hashpas
local adclib_hasholdpas = adclib.hasholdpas
local escapeto = adclib_escape
local escapefrom = adclib.unescape

local cfg_get = cfg.get
local cfg_saveusers = cfg.saveusers

local ratelimit_user_msg = ratelimit.user_msg
local ratelimit_user_search = ratelimit.user_search
local ratelimit_record_authfail = ratelimit.record_authfail

local scripts_firelistener = scripts.firelistener
local signal_get = signal.get

local utf_format = unicode.utf8.format

local util_date = util.date
local util_difftime = util.difftime

local os_time = os.time
local os_difftime = os.difftime

-- Late-bound from hub.lua via bind(). Closures inside the four state
-- tables and states() pick these up via upvalue refs; hub.lua sets
-- them once init() has run, and re-binds after loadsettings,
-- loadlanguage, or updateusers refreshes anything.
--
-- Helpers and internal state
local isuserconnected
local isuserregged
local insertuser
local insertreguser
local login

local _regusers
local _normalstatesids
local _get_user_count   -- closure, returns current _user_count

-- The four state-machine tables and states() are file-local; the
-- bodies below assign to them. Forward-declare here so the sandbox env
-- recognises the assignments as local-writes rather than undeclared
-- globals.
local _protocol
local _identify
local _verify
local _normal
local states

-- VERSION (set once at hub start, but we late-bind to keep all the
-- "stamped-from-hub.lua" identifiers in one place).
local VERSION

-- Format strings (rebuilt on +reload via loadlanguage).
local _hubinf_regonly
local _pingsup
local _normalsup
local _normalsup_regonly

-- Cached cfg values (rebuilt by hub.lua's loadsettings on +reload).
local _cfg_reg_only
local _cfg_max_users
local _cfg_kill_wrong_ips
local _cfg_max_bad_password
local _cfg_bad_pass_timeout
local _cfg_min_share
local _cfg_max_share
local _cfg_min_slots
local _cfg_max_slots
local _cfg_max_user_hubs
local _cfg_max_reg_hubs
local _cfg_max_op_hubs
local _cfg_hub_name
local _cfg_hub_description
local _cfg_hub_hostaddress
local _cfg_hub_website
local _cfg_hub_network
local _cfg_hub_owner

-- i18n strings (rebuilt on +reload via loadlanguage).
local _i18n_unknown
local _i18n_cid_taken
local _i18n_hub_is_full
local _i18n_invalid_ip
local _i18n_invalid_pass
local _i18n_invalid_pid
local _i18n_max_bad_password
local _i18n_nick_taken
local _i18n_no_base_support
local _i18n_no_cid_nick_found
local _i18n_reg_only

local function bind( deps )
    -- helpers
    isuserconnected      = deps.isuserconnected
    isuserregged         = deps.isuserregged
    insertuser           = deps.insertuser
    insertreguser        = deps.insertreguser
    login                = deps.login
    -- state
    _regusers            = deps._regusers
    _normalstatesids     = deps._normalstatesids
    _get_user_count      = deps._get_user_count
    -- constants / cache
    VERSION              = deps.VERSION
    _hubinf_regonly      = deps._hubinf_regonly
    _pingsup             = deps._pingsup
    _normalsup           = deps._normalsup
    _normalsup_regonly   = deps._normalsup_regonly
    _cfg_reg_only        = deps._cfg_reg_only
    _cfg_max_users       = deps._cfg_max_users
    _cfg_kill_wrong_ips  = deps._cfg_kill_wrong_ips
    _cfg_max_bad_password = deps._cfg_max_bad_password
    _cfg_bad_pass_timeout = deps._cfg_bad_pass_timeout
    _cfg_min_share       = deps._cfg_min_share
    _cfg_max_share       = deps._cfg_max_share
    _cfg_min_slots       = deps._cfg_min_slots
    _cfg_max_slots       = deps._cfg_max_slots
    _cfg_max_user_hubs   = deps._cfg_max_user_hubs
    _cfg_max_reg_hubs    = deps._cfg_max_reg_hubs
    _cfg_max_op_hubs     = deps._cfg_max_op_hubs
    _cfg_hub_name        = deps._cfg_hub_name
    _cfg_hub_description = deps._cfg_hub_description
    _cfg_hub_hostaddress = deps._cfg_hub_hostaddress
    _cfg_hub_website     = deps._cfg_hub_website
    _cfg_hub_network     = deps._cfg_hub_network
    _cfg_hub_owner       = deps._cfg_hub_owner
    -- i18n
    _i18n_unknown            = deps._i18n_unknown
    _i18n_cid_taken          = deps._i18n_cid_taken
    _i18n_hub_is_full        = deps._i18n_hub_is_full
    _i18n_invalid_ip         = deps._i18n_invalid_ip
    _i18n_invalid_pass       = deps._i18n_invalid_pass
    _i18n_invalid_pid        = deps._i18n_invalid_pid
    _i18n_max_bad_password   = deps._i18n_max_bad_password
    _i18n_nick_taken         = deps._i18n_nick_taken
    _i18n_no_base_support    = deps._i18n_no_base_support
    _i18n_no_cid_nick_found  = deps._i18n_no_cid_nick_found
    _i18n_reg_only           = deps._i18n_reg_only
end

-- The four state-machine handler tables follow verbatim from hub.lua.
-- The only edits are: replace bare _user_count with _get_user_count(),
-- since _user_count mutates during normal hub operation and our cached
-- copy would go stale otherwise.

_protocol = {

    HSUP = function( user, adccmd )
        if adccmd:hasparam "ADBASE" or adccmd:hasparam "ADBAS0" then
            local response
            if (not _cfg_reg_only) and adccmd:hasparam "ADPING" then
                local min_share = _cfg_min_share[ 0 ] or 100
                local max_share = _cfg_max_share[ 0 ] or 100
                min_share = min_share * 1024^3
                max_share = max_share * 1024^4
                response = utf_format( _pingsup,
                    user.sid( ),
                    _cfg_hub_name,
                    adclib_escape( VERSION ),
                    _cfg_hub_description,
                    _cfg_hub_hostaddress,
                    _cfg_hub_website,
                    _cfg_hub_network,
                    _cfg_hub_owner,
                    tablesize( _normalstatesids ),
                    min_share,
                    max_share,
                    _cfg_min_slots[ 0 ] or 1,
                    _cfg_max_slots[ 0 ] or 100,
                    _cfg_max_user_hubs,
                    _cfg_max_reg_hubs,
                    _cfg_max_op_hubs,
                    _cfg_max_users,
                    os_difftime( os_time( ), signal_get( "start" ) )
                )
            elseif not _cfg_reg_only then
                response = utf_format( _normalsup,
                    user.sid( ),
                    _cfg_hub_name,
                    adclib_escape( VERSION ),
                    _cfg_hub_description
                )
            elseif _cfg_reg_only then
                response = utf_format( _normalsup_regonly,
                    user.sid( ),
                    adclib_escape( VERSION )
                )
            end
            user.write( response )
            if _cfg_max_users <= _get_user_count() then
                user:kill( "ISTA 211 " .. _i18n_hub_is_full .. "\n" )-----!
                return true
            end
            user:sup( adccmd )
            user:state "identify"
            user:hash "TIGR"    -- assume TIGR support^^
        else
            user:kill( "ISTA 220 " .. _i18n_no_base_support .. "\n", "TL-1" )-----!
        end
        return true
    end

}

_identify = {

    BINF = function( user, adccmd )
        local pid = adccmd:getnp "PD"
        local cid = adccmd:getnp "ID"
        local nick = adccmd:getnp "NI"
        local ipver = "I4"
        local infip = adccmd:getnp( ipver )
        if not infip then
            ipver = "I6"
            infip = adccmd:getnp( ipver )
        end
        local hash = user.hash( )
        if not ( cid and pid and nick and infip ) then
            user:kill( "ISTA 220 " .. _i18n_no_cid_nick_found .. "\n", "TL-1" )
            scripts_firelistener( "onFailedAuth", ( nick or _i18n_unknown ), ( infip or _i18n_unknown ), ( cid or _i18n_unknown ), escapefrom( _i18n_no_cid_nick_found ) )
            return true
        end
        local userip = user.ip( ) or ""
        if ( infip == "0.0.0.0" ) or ( infip == "::" ) then
            adccmd:setnp( ipver, userip )
        elseif infip ~= userip then
            if _cfg_kill_wrong_ips then
                user:kill( "ISTA 246 " .. _i18n_invalid_ip .. userip .. "/" .. infip .. "\n", "TL10" )
                scripts_firelistener( "onFailedAuth", nick, userip, cid,  escapefrom( _i18n_invalid_ip .. userip .. "/" .. infip ) )
                return true
            end
        end
        if cid ~= adclib_hash( pid ) then
            user:kill( "ISTA 227 " .. _i18n_invalid_pid .. "\n", "TL-1" )
            scripts_firelistener( "onFailedAuth", nick, userip, cid,  escapefrom( _i18n_invalid_pid ) )
            return true
        end
        local onlineuser = isuserconnected( nil, nil, cid, hash ) -- isuserconnected( nick, sid, cid, hash )
        if onlineuser then
            onlineuser:kill( "ISTA 224 " .. _i18n_cid_taken .. "\n", "TL-1" )
            --scripts_firelistener( "onFailedAuth", nick, userip, cid, escapefrom( _i18n_cid_taken ) )
        end
        onlineuser = isuserconnected( nick )
        if onlineuser then
            local quitmsg = "ISTA 222 " .. _i18n_nick_taken .. "\n"
            if cfg_get "reg_only" then
                onlineuser:kill(quitmsg, "TL-1") -- kill zombie client
            else
                user:kill(quitmsg, "TL-1") -- kill connecting client
                --scripts_firelistener( "onFailedAuth", nick, userip, cid, escapefrom( _i18n_nick_taken ) )
                return true
            end
        end
        local profile = isuserregged( nick )
        if not profile and cfg_get "reg_only" then -- reg only hub; unregged user will be disconnected
            user:kill( "ISTA 226 " .. _i18n_reg_only .. "\n", "TL-1" )
            scripts_firelistener( "onFailedAuth", nick, userip, cid,  escapefrom( _i18n_reg_only ) )
            return true
        --else
        elseif profile then
            local bol, err = insertreguser( user, profile, cid, hash, nick )
            if not bol then
                user:kill( "ISTA 220 " .. escapeto(err) .. "\n", "TL-1" )
                return true
            end
        end
        adccmd:deletenp "PD"
        user:inf( adccmd )
        if user:hasfeature "CCPM" then user:hasccpm( true ) end
        insertuser( nick, cid, hash, user )
        if scripts_firelistener( "onConnect", user ) or user.waskilled then
            return true
        end
        if profile then
            profile.lastconnect = profile.lastconnect or util_date()
            local lc = tostring( profile.lastconnect )
            if #lc ~= 14 then profile.lastconnect = util_date() end -- util.date() has allways 14 chars: yyyymmddhhmmss
            local sec, y, d, h, m, s = util_difftime( util_date(), profile.lastconnect )
            if ( ( profile.badpassword or 0 ) >= _cfg_max_bad_password ) and ( sec < _cfg_bad_pass_timeout ) then
                user:kill( "ISTA 223 " .. _i18n_max_bad_password .. sec .. "/" .. _cfg_bad_pass_timeout .. "\n" )
                scripts_firelistener( "onFailedAuth", nick, userip, cid, escapefrom( _i18n_max_bad_password .. sec .. "/" .. _cfg_bad_pass_timeout ) )
                return true
            end
            --[[profile.lastconnect = profile.lastconnect or os_time( )
            local diff = os_difftime( os_time( ), profile.lastconnect )
            if ( ( profile.badpassword or 0 ) >= _cfg_max_bad_password ) and ( diff < _cfg_bad_pass_timeout ) then
                user:kill( "ISTA 223 " .. _i18n_max_bad_password .. diff .. "/" .. _cfg_bad_pass_timeout .. "\n" )
                return true
            end ]]
            user:salt( adclib_createsalt( ) )
            user.write( "IGPA " .. user.salt( ) .. "\n" )
            user:state "verify"
        else
            login( user, false )
        end
        return true
    end,

}

_verify = {

    HPAS = function( user, adccmd )
        local salt = user.salt( )
        --local pass = _cfg_hub_pass
        local pass, reason
        local regged = user.isregged( )
        local usercid = user.cid( )
        local userip = user.ip( ) or _i18n_unknown
        local userhash = adccmd[ 4 ]
        if regged then
            pass = user.password( )
        end
        local profile = user.profile( )
        local hubhash = adclib_hashpas( pass, salt )
        local hubhashold = adclib_hasholdpas( pass, salt, usercid )
        if ( userhash ~= hubhash ) and ( userhash ~= hubhashold ) then
            profile.badpassword = ( profile.badpassword or 0 ) + 1
            -- Phase 7c F-AUTH-3: also count this against the offending
            -- IP so cross-account fishing is throttled, not just the
            -- per-account counter that an attacker can cycle through.
            ratelimit_record_authfail( userip )
            user:kill( "ISTA 223 " .. _i18n_invalid_pass .. "\n", "TL-1" )
            scripts_firelistener( "onFailedAuth", profile.nick, userip, usercid, escapefrom( _i18n_invalid_pass ) )
        else
            profile.badpassword = 0
            if not user:sup( ):hasparam( "ADOSNR" ) then
                user.write( utf_format( _hubinf_regonly, _cfg_hub_name, _cfg_hub_description ) )
            end
            login( user )
        end
        --[[
        if regged and cfg_get "nick_change" then        --// mhh.. the whole thing needs rework
            user:setregnick( user:nick( ) )
        end
        ]]--
        profile.lastconnect = util_date( )
        profile.lastseen = util_date( )
        profile.is_online = 1
        cfg_saveusers( _regusers )
        return true
    end,

}

-- Phase 7c F-RL-1 / F-RL-2 helpers. Token-bucket-protected entry points
-- to the BMSG / EMSG / DMSG / *SCH listeners. Returning `true` from the
-- handler tells incoming() the message has been handled (so the
-- broadcast / fan-out is suppressed) without disconnecting the user.
-- Op-level users (>= ratelimit_bypass_level) bypass the check inside
-- ratelimit.user_msg / user_search.
local function rl_msg_drop( user )
    return not ratelimit_user_msg( user.cid( ), user.level( ) )
end
local function rl_search_drop( user )
    return not ratelimit_user_search( user.cid( ), user.level( ) )
end

_normal = {
    -- ADC: 6.3.4. INF
    BINF = function( user, adccmd )
        return scripts_firelistener( "onInf", user, adccmd )
    end,
    -- ADC: 6.3.5. MSG
    BMSG = function( user, adccmd )
        if rl_msg_drop( user ) then return true end
        return scripts_firelistener( "onBroadcast", user, adccmd, escapefrom( adccmd[ 6 ] ) )
    end,
    --FMSG = function( user, adccmd )  -- cannot see a good scenario for FMSG; why should a user want to send mainchat messages to clients with specific features only?
    --    return scripts_firelistener( "onBroadcast", user, adccmd, escapefrom( adccmd[ 8 ] ) )
    --end,
    EMSG = function( user, adccmd, targetuser )
        if rl_msg_drop( user ) then return true end
        return scripts_firelistener( "onPrivateMessage", user, targetuser, adccmd, escapefrom( adccmd[ 8 ] ) )
    end,
    DMSG = function( user, adccmd, targetuser )
        if rl_msg_drop( user ) then return true end
        return scripts_firelistener( "onPrivateMessage", user, targetuser, adccmd, escapefrom( adccmd[ 8 ] ) )
    end,
    -- ADC: 6.3.8. CTM
    DCTM = function( user, adccmd, targetuser )
        return scripts_firelistener( "onConnectToMe", user, targetuser, adccmd )
    end,
    --ECTM = function( user, adccmd, targetuser ) -- new
    --    return scripts_firelistener( "onConnectToMe", user, targetuser, adccmd )
    --end,
    -- ADC: 6.3.9. RCM
    DRCM = function( user, adccmd, targetuser )
        return scripts_firelistener( "onRevConnectToMe", user, targetuser,adccmd )
    end,
    --ERCM = function( user, adccmd, targetuser ) -- new
    --    return scripts_firelistener( "onRevConnectToMe", user, targetuser,adccmd )
    --end,
    -- ADC: 6.3.6. SCH
    BSCH = function( user, adccmd )
        if rl_search_drop( user ) then return true end
        return scripts_firelistener( "onSearch", user, adccmd )
    end,
    FSCH = function( user, adccmd )
        if rl_search_drop( user ) then return true end
        return scripts_firelistener( "onSearch", user, adccmd )
     end,
    DSCH = function( user, adccmd, targetuser )
        if rl_search_drop( user ) then return true end
        return scripts_firelistener( "onSearch", user, adccmd )
    end,
    -- ADC: 6.3.7. RES
    DRES = function( user, adccmd, targetuser )
        return scripts_firelistener( "onSearchResult", user, targetuser, adccmd )
    end,
    --URES = function( user, adccmd, targetuser ) -- new
    --    return scripts_firelistener( "onSearchResult", user, targetuser, adccmd )
    --end,
    --CRES = function( user, adccmd, targetuser ) -- new
    --    return scripts_firelistener( "onSearchResult", user, targetuser, adccmd )
    --end,

}

states = function( user, adccmd, fourcc, state, targetuser )
    local ret
    if state == "normal" then
        ret = _normal[ fourcc ]
        if ret then
            return ret( user, adccmd, targetuser )  -- forward it with fireing script listeners
        end
        return false    --forward it later without fireing script listeners
    elseif state == "protocol" then
        ret = _protocol[ fourcc ]
    elseif state == "identify" then
        ret = _identify[ fourcc ]
    elseif state == "verify" then
        ret = _verify[ fourcc ]
    end
    if not ret then
        user.write( "ISTA 125 FC" .. fourcc .. "\n" )
    else
        ret( user, adccmd, targetuser )
    end
    return true
end


return {
    bind   = bind,
    states = states,
}
