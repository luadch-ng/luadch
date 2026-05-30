--[[

    hub_bot_object.lua - the bot-instance factory extracted from core/hub.lua

    Phase 6d-2 of the hub.lua decomposition. createbot is the constructor
    for in-hub bot objects (the hub bot, OpChat, RegChat, PmToOps, ...).
    Like createuser, it builds a table of closures that wrap private
    state (sid, cid, nick, level, rank, INF) and stamps it with the
    public bot-method API (bot.send, bot.kill, bot.nick, bot.profile,
    bot.regid, etc). Most setter methods point at the userisbot stub
    (bots are not regular users, can't have their level / password /
    rank changed through the user API).

    Same bind_late() pattern as cfg_defaults / cfg_users / cfg_lang /
    hub_user_object: hub.init() and hub.updateusers() each call
    _bot_module.bind({...}) once. Re-binding in updateusers is necessary
    because that function reassigns _regusers / _regusernicks to fresh
    tables; without it, bot.profile / bot.regid would read the stale
    references.

    Public surface returned to hub.lua:

        {
            bind      = function(deps)
            createbot = function(_sid, p)
        }

]]--

local use = use

local error = use "error"
local ipairs = use "ipairs"
local pairs = use "pairs"
local pcall = use "pcall"
local tostring = use "tostring"
local type = use "type"

-- Stable upvalues - resolved once at file load. By the time hub.lua
-- triggers `use "hub_bot_object"` (during its own body), these core
-- modules are already loaded.
local adc = use "adc"
local adclib = use "adclib"
local cfg = use "cfg"
local out = use "out"
local types = use "types"
local unicode = use "unicode"

local adc_parse = adc.parse
local adclib_escape = adclib.escape
local escapeto = adclib_escape
local cfg_get = cfg.get
local out_error = out.error
local types_utf8 = types.utf8
local utf = unicode.utf8
local utf_find = utf.find
local utf_sub = utf.sub

-- Late-bound from hub.lua via bind(). Closures inside createbot pick
-- these up via upvalue references; hub.lua sets them once init() has
-- run, and re-binds after any state-table reassignment (updateusers).
local disconnect
local reguser
local userisbot

local _bots
local _regusernicks
local _regusers

local _cfg_bot_level
local _cfg_bot_rank
-- #301: single i18n table (matches hub.lua / hub_dispatch.lua refactor).
-- DO NOT reassign `_i18n = {}` anywhere - hub.lua's loadlanguage mutates
-- the table in place on +reload, and we hold the same reference.
local _i18n = { }

local function bind( deps )
    disconnect       = deps.disconnect
    reguser          = deps.reguser
    userisbot        = deps.userisbot
    _bots            = deps._bots
    _regusernicks    = deps._regusernicks
    _regusers        = deps._regusers
    _cfg_bot_level   = deps._cfg_bot_level
    _cfg_bot_rank    = deps._cfg_bot_rank
    _i18n            = deps._i18n
end

local function createbot( _sid, p )

    --// private closures of the object //--

    local _client = p.client
    local _isreguser = false
    local _rank = _cfg_bot_rank or 5
    local _level = _cfg_bot_level or 0
    local _nick = escapeto( p.nick )
    local _desc = escapeto( p.desc )

    if type( _client ) ~= "function" then
        return nil, "invalid bot listener"-----!
    end

    --// create inf //--

    local profile, _pid, _cid = _regusernicks[ _nick ]
    if profile and profile.is_bot then
        _cid = profile.cid
    elseif not profile then
        _pid, _cid = adc.createid( )
        local profile, err = reguser{ nick = _nick, is_bot = 1, cid = _cid, hash = "TIGR", password = _pid, rank = _rank }
        if not profile then
            return nil, err
        end
    else
        return nil, "nick is already regged as user"-----!
    end
    local hubbot = cfg_get( "hub_bot" )
    local hub_email = cfg.get( "hub_email" )
    local hub_bot_email = cfg.get( "hub_bot_email" )
    --local hub_hostaddress = cfg_get( "hub_hostaddress" )
    local _inf
    if _nick == hubbot then
        _inf = "BINF " .. _sid ..
               " ID" .. _cid ..
               " NI" .. _nick ..
               " DE" .. _desc ..
               " OP1 CT5" ..
               " HN0 HR0 HO1" ..
               " SL0 SS0 SF0" ..
               " I4" .. "" .. --> maybe use external ip
               --" I4" .. "0.0.0.0" .. --> maybe use external ip
               --" I4" .. hub_hostaddress .. --"0.0.0.0" .. --> maybe use external ip
               --" AW" .. "2" ..
               " SU" .. "ADC0,ADCS,TCP4,UDP4" ..
               " VE" .. "HubBot"
               if hub_bot_email then _inf = _inf .. " EM" .. hub_email end
        _inf = adc_parse( _inf )
        if not _inf then
        return nil, "invalid inf"-----!
        end
    else
        _inf = "BINF " .. _sid ..
               " ID" .. _cid ..
               " NI" .. _nick ..
               " DE" .. _desc ..
               " OP1 CT5" ..
               " HN0 HR0 HO1" ..
               " SL0 SS0 SF0" ..
               " I4" .. "" .. --> maybe use external ip
               --" I4" .. "0.0.0.0" .. --> maybe use external ip
               --" I4" .. hub_hostaddress .. --"0.0.0.0" .. --> maybe use external ip
               --" AW" .. "2" ..
               " SU" .. "ADC0,ADCS,TCP4,UDP4" ..
               " VE" .. "Bot"

        _inf = adc_parse( _inf )
        if not _inf then
        return nil, "invalid inf"-----!
        end
    end

    --// public methods of the object //--

    local bot = { }

    bot.alive = true    -- experimental flag

    bot.salt = userisbot
    bot.sup = userisbot
    bot.supports = userisbot
    bot.updatenick = userisbot
    bot.sendsta = userisbot

    if _nick == hubbot then
        bot.version = function( _ )
            return "HubBot"
        end
    else
        bot.version = function( _ )
            return "Bot"
        end
    end
    bot.email = function( _ )
        return ""
    end
    bot.share = function( _ )
        return 0
    end
    bot.slots = function( _ )
        return 0
    end
    bot.hubs = function( _ )
        return 0, 0, 1
    end
    bot.client = function( _ )
        return _client
    end
    bot.state = function( _ )
        return "normal"
    end
    bot.isbot = function( _ )
        return true
    end
    bot.sid = function( _ )
        return _sid
    end
    bot.cid = function( _ )
        return _cid
    end
    bot.hash = function( _ )
        return "TIGR"
    end
    bot.send = function( _, msg )
        local adccmd = adc_parse( utf_sub( tostring( _ or msg ), 1, -2 ) )
        if adccmd then
            local bol, err = pcall( _client, bot, adccmd )
            _ = bol or out_error( "hub.lua: function 'createbot': botscript error: ", err )
        end
        return adccmd
    end
    bot.write = bot.send
    bot.inf = function( _ )
        return _inf
    end
    bot.nick = function( _ )
        return _inf:getnp "NI"
    end
    bot.features = function( _, feature )
       return _inf and _inf:getnp( "SU" )
    end

    bot.hasccpm = function(  )
        return nil
    end

    bot.firstnick = bot.nick

    bot.description = function( _ )
        return _inf:getnp "DE"
    end
    bot.kill = function( _ )
        _bots[ bot ] = nil
        --local qui = "IQUI " .. _sid .. "\n"
        disconnect( true, nil, bot, "IQUI " .. _sid .. "\n" )
    end
    bot.reply = function( _, p )    -- mhh.. do we need this? noooo...
        --p = p or { }
        --msg = tostring( p.msg ) or ""
        --bot:send( "IMSG " .. escapeto( msg ) .. "\n" )
    end
    bot.rank = function( _ )
        return _rank
    end
    bot.level = function( _ )
        return _level
    end
    bot.hasfeature = function( _, feature )
        types_utf8( feature )
        return utf_find( _inf:getnp( "SU" ) or "", feature ) ~= nil
    end

    bot.ip = function( )
        return _i18n.unknown
    end
    bot.clientport = function( )
        return _i18n.unknown
    end
    bot.peer = function( _ )
        return _i18n.unknown, _i18n.unknown
    end
    bot.isregged = function( )
        return true
    end
    bot.serverport = function( _ )
        return _i18n.unknown
    end
    bot.ssl = function( _ )
        return _i18n.unknown
    end
    bot.password = function( _ )
            return _pid
        end
    bot.profile = function( _ )
        return _regusernicks[ _nick ]
    end

    bot.setregnick = userisbot
    bot.setpassword = userisbot
    bot.setrank = userisbot
    bot.setlevel = userisbot

    bot.redirect = userisbot
    bot.destroy = function( ) end

    bot.regcid = function( _ )
        return profile.cid
    end
    bot.reghash = function( _ )
        return profile.hash
    end
    bot.regnick = function( _ )
        return profile.nick
    end
    bot.regid = function( _ )
        local num
        for i, usertbl in ipairs( _regusers ) do
            if usertbl == profile then
                return i
            end
        end
        error( "strange error, regid not found..", 2 )
    end
    _bots[ bot ] = _sid
    return bot
end

return {
    bind      = bind,
    createbot = createbot,
}
