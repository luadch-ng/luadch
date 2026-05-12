--[[

    hub_user_object.lua - the user-instance factory extracted from core/hub.lua

    Phase 6d-1 of the hub.lua decomposition. The function `createuser` was
    the largest single function in core/hub.lua (375 lines, ~17% of the
    file's volume). It is the constructor for the per-connection user
    object that the rest of the hub uses to talk to clients: it builds a
    table of closures around the client TCP/TLS handle and the user's
    private state (nick, cid, profile, level, sup features, ssl info, ...)
    and stamps it with public methods like user.write, user.kill,
    user.firstnick, user.profile, user.password, user.salt, user.setlevel,
    etc.

    The function uses many upvalues from hub.lua's file scope: helpers
    (checkuser, disconnect, isuserconnected, sendtoall, usernotregged),
    state tables (_regex, _regusers, _regusernicks, _usernicks), and
    cached config constants (_cfg_reg_rank, _cfg_reg_level). Rather than
    pass ~11 arguments at every createuser call, we use the same
    `bind_late()`-style pattern as cfg_defaults / cfg_users / cfg_lang:
    hub.init() and hub.updateusers() call _user_module.bind({...}) once
    each, after which the closures inside createuser see the bound values
    via Lua's by-reference upvalue capture.

    Public surface returned to hub.lua:

        {
            bind       = function(deps)        -- inject dependencies
            createuser = function(_client, _sid)  -- return a user object
        }

    NOTE ON STATE-TABLE REFERENCES: hub.updateusers() reassigns _regusers
    and _regusernicks to fresh tables (e.g. on +reload of the user
    database). hub.lua MUST call _user_module.bind(...) again after each
    such reassignment so this module sees the new tables; otherwise it
    would mutate / save the stale ones. updateusers in hub.lua does this
    explicitly at its tail.

]]--

local use = use

local error = use "error"
local ipairs = use "ipairs"
local pairs = use "pairs"
local tonumber = use "tonumber"
local tostring = use "tostring"
local type = use "type"

local table = use "table"
local table_concat = table.concat
local table_insert = table.insert
local table_remove = table.remove

local adclib = use "adclib"
local cfg = use "cfg"
local types = use "types"
local unicode = use "unicode"

-- These aliases are stable: the underlying functions don't move at
-- runtime, so we can resolve them once at file load time.
local adclib_escape = adclib.escape
local escapeto = adclib_escape
local cfg_saveusers = cfg.saveusers
local types_utf8 = types.utf8
local utf = unicode.utf8
local utf_find = utf.find
local utf_match = utf.match

-- Late-bound from hub.lua via bind(). Closures inside createuser pick
-- these up via upvalue references; hub.lua sets them once init() has
-- run, and re-binds after any state-table reassignment.
local checkuser
local disconnect
local isuserconnected
local sendtoall
local usernotregged

local _regex
local _regusernicks
local _regusers
local _usernicks

local _cfg_reg_rank
local _cfg_reg_level

local function bind( deps )
    checkuser        = deps.checkuser
    disconnect       = deps.disconnect
    isuserconnected  = deps.isuserconnected
    sendtoall        = deps.sendtoall
    usernotregged    = deps.usernotregged
    _regex           = deps._regex
    _regusernicks    = deps._regusernicks
    _regusers        = deps._regusers
    _usernicks       = deps._usernicks
    _cfg_reg_rank    = deps._cfg_reg_rank
    _cfg_reg_level   = deps._cfg_reg_level
end

local function createuser( _client, _sid )

    --// private closures of the object //--

    local _ip = _client.ip( )
    local _port = _client.clientport( )
    local _serverport = _client.serverport( )
    local _ssl = _client.ssl( )
    local _isreguser = false
    local _rank = 0
    local _level = 0
    local _inf = nil
    local _sup = nil
    local _salt = nil
    local _sessionhash = nil
    local _has_ccpm = nil

    local _firstnick    -- experimental

    local _state = "protocol"

    --// public methods of the object //--

    local user = { }
    --local user = _client

    user.firstnick = function( _ )
        return _firstnick
    end
    user.serverport = function( _ )
        return _serverport
    end
    user.ssl = function( _ )
        return _ssl
    end
    user.sslinfo = function( _ )
        if _ssl then
            return _client.getsslinfo( )
        end
        return nil, "not using ssl"
    end
    user.client = function( _ )
        return _client
    end
    user.state = function( _, state )
        _state = state or _state
        return _state
    end
    user.isbot = function( _ )
        return false
    end
    user.ip = function( _ )
        return _ip
    end
    user.clientport = function( _ )
        return _port
    end
    user.peer = function( _ )
            return _ip, _port
    end
    user.sid = function( _ )
        return _sid
    end

    local client_write = _client.write    -- caching table lookups...

    user.sendonly = function( )
        client_write = function( ) end
        _client.write = function( ) end
        user.write = function( ) end
        local tmp = _client.close
        _client.close = function( ) tmp( "disconnect OSNR bot" ) end
    end

    user.send = function( _, adcstring )
        return client_write( adcstring )
    end

    user.write = client_write

    local user_send = user.send    -- caching table lookups...

    user.sendsta = function( _, code, desc, flags )
        local code, desc = tostring( code ), escapeto( tostring( desc ) )
        if not utf_match( code, "^[012]%d%d$" ) then
            return false, "invalid code"-----!
        end
        local msg = "ISTA " .. code .. " " .. desc
        -- The original `type( flags == "table" )` was a long-standing
        -- typo: it called type() on a boolean (the result of comparing
        -- flags to the string "table"), which is always truthy, then
        -- pairs(nil) would crash whenever the caller omitted the flags
        -- argument. Pinning the parens makes the contract match the
        -- docstring: flags is optional, must be a table when present.
        if type( flags ) == "table" then
            for flag, value in pairs( flags ) do
                -- The NP name (e.g. "TL", "FC") is the on-wire field
                -- key and must be emitted verbatim - escape-encoding
                -- it would mangle non-alpha names that future spec
                -- extensions may introduce. Today's NP names are all
                -- alpha so this works by luck either way, but keep the
                -- escape on the value where it actually matters.
                msg = msg .. " " .. flag .. escapeto( value )
            end
        end
        msg =  msg .. "\n"
        return client_write( msg )
    end

    user.inf = function( _, adccmd )
        if adccmd then
            _inf = _inf or adccmd
            _firstnick = _firstnick or user.nick( )
        end
        return _inf
    end

    user.hasccpm = function( _, bol )
        _has_ccpm = _has_ccpm or bol
        return _has_ccpm
    end

    user.sup = function( _, adccmd )
        if adccmd then
            _sup = _sup or adccmd
        end
        return _sup
    end
    user.cid = function( _ )
        return _inf and _inf:getnp "ID"    -- dangerous...
    end
    user.nick = function( _ )
        return _inf and _inf:getnp "NI"
    end
    user.description = function( _ )
        return _inf and _inf:getnp "DE"
    end
    user.email = function( _ )
        return _inf and _inf:getnp "EM"
    end
    user.share = function( _ )
        return _inf and tonumber( _inf:getnp "SS" )
    end
    -- ADC INF.SF = number of shared files. Public for plugins and used
    -- by the hub itself to compute the aggregate SF field in PING
    -- replies (T1.3 of #147).
    user.files = function( _ )
        return _inf and tonumber( _inf:getnp "SF" )
    end
    user.slots = function( _ )
        return _inf and tonumber( _inf:getnp "SL" )
    end
    user.features = function( _ )
       return _inf and _inf:getnp "SU"
    end
    user.hubs = function( _ )
        if _inf then
            return tonumber( _inf:getnp "HN" ), tonumber( _inf:getnp "HR" ), tonumber( _inf:getnp "HO" )
        end
        return nil
    end
    user.version = function( _ )
        local ve = _inf and _inf:getnp "VE"
        local ap = _inf and _inf:getnp "AP"
        ve = ve or ""
        ap = ap or ""
        if ap ~= "" then return ap .. " " .. ve else return ve end
        --return _inf and _inf:getnp "VE"
    end
    user.updatenick = function( _, nick, notsend, bypass )
        if not _inf then
            return false, "user has no inf"    -- user is maybe not in normal state
        end
        types_utf8( nick )
        if utf_find( nick, " " ) then
            nick = escapeto( nick )
        end
        local oldnick = user.nick( )
        _firstnick = _firstnick or oldnick
        if not bypass then
            if nick == oldnick then
                return false, "no nick change"
            end
            if isuserconnected( nick ) then -- isuserconnected( nick, sid, cid, hash )
                return false, "nick taken"
            end
            if _regusernicks[ nick ] and not ( nick == _firstnick ) then
                return false, "nick is regged"
            end
        end
        if utf_match( nick, _regex.reguser.nick ) then
            _inf:setnp( "NI", nick )
            _usernicks[ oldnick ] = nil
            _usernicks[ nick ] = user
            if not notsend then
                sendtoall( "BINF " .. _sid .. " NI" .. nick .. "\n" )
            end
            return true
        end
        return false, "invalid nick"
    end
    user.kill = function( _, adcstring, quitstring1, quitstring2 )
        types_utf8( adcstring )                -- raises on non-utf8 input
        types_utf8( quitstring1 or "" )
        types_utf8( quitstring2 or "" )
        client_write( adcstring )
        local qui
        if quitstring1 and quitstring1:find( "TL" ) then
            qui = "IQUI " .. _sid .. " " .. quitstring1 .. "\n"
            client_write( qui )
        else
            qui = "IQUI " .. _sid .. "\n"
            client_write( quitstring1 or qui )
        end
        _client.close( )
        disconnect( _client, nil, user, quitstring2 or qui )
    end
    --[[
    user.redirect = function( _, url )
        types_utf8( url )
        user:kill( "IQUI " .. _sid .. " RD" .. adclib_escape( url ) .. "\n" )
    end
    ]]
    -- ADC-EXT 3.32 RDEX. Builds an IQUI redirect with RD (primary URL)
    -- plus optional RX (alternative URLs) and PT (permanent flag) NPs
    -- driven from cfg. The legacy MS quitmsg stays as the trailing
    -- field. Cfg is looked up at call time so a +reload picks up new
    -- alternatives / permanent toggle without a hub restart.
    -- Alternatives are iterated with ipairs so RX field order on the
    -- wire matches the operator's cfg table order across reloads
    -- (pairs() in Lua has implementation-defined iteration order).
    user.redirect = function( _, url, quitmsg )
        types_utf8( url )
        local parts = { "IQUI ", _sid, " RD", adclib_escape( url ) }
        local alts = cfg.get "hub_redirect_alternatives"
        if alts then
            for _, alt in ipairs( alts ) do
                types_utf8( alt )
                parts[ #parts + 1 ] = " RX"
                parts[ #parts + 1 ] = adclib_escape( alt )
            end
        end
        if cfg.get "hub_redirect_permanent" then
            parts[ #parts + 1 ] = " PT1"
        end
        if quitmsg then
            types_utf8( quitmsg )
            parts[ #parts + 1 ] = " MS"
            -- ADC requires whitespace / control-byte escaping in field
            -- values. The legacy MS path emitted quitmsg raw, so any
            -- caller passing a multi-word reason produced malformed
            -- ADC on the wire. Now escaped same as RD / RX above.
            parts[ #parts + 1 ] = adclib_escape( quitmsg )
        end
        parts[ #parts + 1 ] = "\n"
        user:kill( table_concat( parts ) )
    end
    user.salt = function( _, data )
        if data then
            _salt = _salt or data
        end
        return _salt
    end
    user.hash = function( _, data)
        if data then
            _sessionhash = _sessionhash or data
        end
        return _sessionhash
    end
    user.isregged = function( _ )
        return _isreguser
    end
    user.reply = function( _, msg, from, pm, me, traceback )
        types_utf8( msg, traceback )
        msg = escapeto( msg ) .. ( ( me == "1" and " ME1" ) or "" )    -- add flag for me-message
        local fromsid, groupsid
        if pm then
            checkuser( pm )
            fromsid = ( from and ( checkuser( from ) and from.sid( ) ) ) or pm.sid( )
            groupsid = pm.sid( )
            client_write( "DMSG " .. fromsid .. " " .. _sid .. " ".. msg .. " PM" .. groupsid .. "\n" )
        elseif not pm and from then
            checkuser( from )
            client_write( "BMSG " .. from.sid( ) .. " " .. msg .. "\n" )
        else
            client_write( "IMSG " .. msg .. "\n" )
        end
        return true
    end
    user.rank = function( _ )
        return _rank
    end
    user.level = function( _ )
        return _level
    end
    user.supports = function( _, feature )
        types_utf8( feature )
        if _sup and _sup:hasparam( "AD" .. tostring( feature ) ) then
            return true
        end
        return false
    end
    user.hasfeature = function( _, feature )
        types_utf8( feature )
        return utf_find( _inf:getnp( "SU" ) or "", feature ) ~= nil
    end

    user.destroy = function( )
        _client = nil
        client_write = nil
        user.waskilled = true    -- experimental flag
    end

    user.regcid = usernotregged
    user.reghash = usernotregged
    user.regnick = usernotregged
    user.password = usernotregged
    user.setregnick = usernotregged
    user.setpassword = usernotregged
    user.setrank = usernotregged
    user.setlevel = usernotregged
    user.regid = usernotregged
    user.profile = usernotregged

    user.addregmethods = function( _, profile )

        _isreguser = true

        user.regcid = function( _ )
            return profile.cid
        end
        user.reghash = function( _ )
            return profile.hash
        end
        user.regnick = function( _ )
            return profile.nick
        end
        user.password = function( _ )
            return profile.password
        end
        user.rank = function( _ )
            return tonumber( profile.rank ) or _cfg_reg_rank or 2
        end
        user.level = function( _ )
            return tonumber( profile.level ) or _cfg_reg_level or 20
        end
        user.setregnick = function( _, nick, update, notsend )
            types_utf8( nick )
            if utf_find( nick, " " ) then
                nick = escapeto( nick )
            end
            if profile.nick == nick then
                return false, "no nick change"
            end
            if _regusernicks[ nick ] then
                return false, "nick already regged"
            end
            local onlineuser = _usernicks[ nick ]
            if onlineuser and not ( user.cid( ) == onlineuser.cid( ) ) then
                return false, "nick taken"
            end
            if utf.match( nick, _regex.reguser.nick ) then
                _regusernicks[ profile.nick or "" ] = nil
                _regusernicks[ nick ] = user
                profile.nick = nick
                cfg_saveusers( _regusers )
                if update then
                    user:updatenick( nick, notsend )
                end
                return true
            end
            return false, "invalid Nick"
        end
        user.setpassword = function( _, password )
            password = tostring( password )
            if utf.match( password, _regex.reguser.password ) then
                profile.password = password
                cfg_saveusers( _regusers )
                return true
            end
            return false, "invalid pass"
        end
        user.setrank = function( _, rank )
            rank = tostring( rank )
            if utf.match( rank, _regex.reguser.rank ) then
                profile.rank = rank
                cfg_saveusers( _regusers )
                return true
            end
            return false, "invalid rank"
        end
        user.setlevel = function( _, level )
            level = tonumber( level )
            if utf.match( level, _regex.reguser.level ) then
                profile.level = level
                cfg_saveusers( _regusers )
                --return true
                return cfg_saveusers( _regusers )
            end
            return false, "invalid level"
        end
        user.regid = function( _ )
            local num
            for i, usertbl in ipairs( _regusers ) do
                if usertbl == profile then
                    return i
                end
            end
            error( "strange error, regid not found..", 2 )
        end
        user.profile = function( _ )
            return profile
        end
    end
    return user
end

return {
    bind       = bind,
    createuser = createuser,
}
