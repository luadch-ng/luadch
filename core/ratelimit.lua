--[[

    core/ratelimit.lua - DoS hardening rate limiter

    Phase 7c. Token-bucket counters keyed by IP or by user-CID,
    cfg-tunable, op-level bypass. Hooks:

    - server.lua  : accept_ip / release_ip / handshake_started /
                    handshake_finished / expired_handshakes
    - hub_dispatch: user_msg / user_search / record_authfail

    Storage:

        _perip_count[ip]   = active socket count
        _buckets[id][kind] = { tokens, ts }
        _hs_started[h]     = handshake start ts

    IDs:
        "ip:1.2.3.4"   for per-IP buckets
        "user:CID"     for per-user buckets (CID is stable per session)

    Cleanup:
        tick() walks _buckets and drops entries idle > 5 min. Per-IP
        counts drop to zero on release_ip; handshake table is cleaned
        explicitly on handshake_finished or via the periodic walk
        triggered by expired_handshakes.

]]--

----------------------------------// DECLARATION //--

--// lua functions //--

local pairs = use "pairs"
local ipairs = use "ipairs"

--// lua libs //--

local math = use "math"

--// lua lib methods //--

local math_min = math.min

--// extern libs //--

local socket = use "socket"

--// extern lib methods //--

local socket_gettime = socket.gettime

--// core modules //--

local cfg = use "cfg"

--// core methods //--

local cfg_get = cfg.get

--// functions //--

local init
local accept_ip
local release_ip
local handshake_started
local handshake_finished
local expired_handshakes
local user_msg
local user_search
local record_authfail
local tick

--// tables //--

local _perip_count
local _buckets
local _hs_started
local _ip_blocks    -- ip -> expiry-ts; F-AUTH-3 sticky lockout

--// scalars //--

local _activate
local _bypass_level
local _perip_max_conns
local _perip_conn_rate
local _perip_conn_burst
local _hs_timeout
local _authfail_rate_per_sec
local _authfail_burst
local _authfail_lockout
local _msg_rate
local _msg_burst
local _search_rate_per_sec
local _search_burst

local _last_cleanup
local _cleanup_interval
local _bucket_idle_max

----------------------------------// DEFINITION //--

_perip_count = { }
_buckets = { }
_hs_started = { }
_ip_blocks = { }

_last_cleanup = 0
_cleanup_interval = 60
_bucket_idle_max = 300

local function _bucket( id, kind, capacity )
    local b = _buckets[ id ]
    if not b then
        b = { }
        _buckets[ id ] = b
    end
    local tk = b[ kind ]
    if not tk then
        tk = { tokens = capacity, ts = socket_gettime( ) }
        b[ kind ] = tk
    end
    return tk
end

local function _consume( id, kind, capacity, fill_per_sec )
    local now = socket_gettime( )
    local tk = _bucket( id, kind, capacity )
    local elapsed = now - tk.ts
    if elapsed > 0 then
        tk.tokens = math_min( capacity, tk.tokens + elapsed * fill_per_sec )
        tk.ts = now
    end
    if tk.tokens >= 1 then
        tk.tokens = tk.tokens - 1
        return true
    end
    return false
end

local function _ip_blocked( ip )
    local until_ts = _ip_blocks[ ip ]
    if not until_ts then return false end
    if socket_gettime( ) >= until_ts then
        _ip_blocks[ ip ] = nil
        return false
    end
    return true
end

accept_ip = function( ip )
    if not _activate then return true end
    -- Sticky F-AUTH-3 IP block from prior bad-auth abuse.
    if _ip_blocked( ip ) then
        return false, "IP locked out due to repeated auth failures: " .. tostring( ip )
    end
    -- Parallel-socket cap (F-NET-1, parallel slot count)
    local count = _perip_count[ ip ] or 0
    if count >= _perip_max_conns then
        return false, "too many connections from " .. tostring( ip )
    end
    -- Connection-rate (F-NET-1, rate)
    if not _consume( "ip:" .. ip, "conn", _perip_conn_burst, _perip_conn_rate ) then
        return false, "connection rate exceeded for " .. tostring( ip )
    end
    _perip_count[ ip ] = count + 1
    return true
end

release_ip = function( ip )
    if not ip then return end
    local count = _perip_count[ ip ]
    if not count then return end
    if count <= 1 then
        _perip_count[ ip ] = nil
    else
        _perip_count[ ip ] = count - 1
    end
end

handshake_started = function( handler )
    if not _activate or _hs_timeout <= 0 then return end
    _hs_started[ handler ] = socket_gettime( )
end

handshake_finished = function( handler )
    _hs_started[ handler ] = nil
end

-- Returns array of handlers whose TLS handshake has been pending
-- longer than _hs_timeout. Caller (server.lua periodic timer) is
-- responsible for closing them.
expired_handshakes = function( )
    if not _activate or _hs_timeout <= 0 then return nil end
    local now = socket_gettime( )
    local result
    for h, ts in pairs( _hs_started ) do
        if ( now - ts ) >= _hs_timeout then
            result = result or { }
            result[ #result + 1 ] = h
        end
    end
    return result
end

-- Per-user chat-rate (F-RL-1). level >= bypass_level skips the check.
user_msg = function( cid, level )
    if not _activate then return true end
    if level and level >= _bypass_level then return true end
    if not cid or cid == "" then return true end
    return _consume( "user:" .. cid, "msg", _msg_burst, _msg_rate )
end

-- Per-user search-rate (F-RL-2). level >= bypass_level skips the check.
user_search = function( cid, level )
    if not _activate then return true end
    if level and level >= _bypass_level then return true end
    if not cid or cid == "" then return true end
    return _consume( "user:" .. cid, "search", _search_burst, _search_rate_per_sec )
end

-- Per-IP failed-auth tracking (F-AUTH-3). Consumes a token from the
-- per-IP authfail bucket; if the rate has been exceeded the IP is
-- added to the sticky lockout list for `_authfail_lockout` seconds.
-- accept_ip will refuse new connections from that IP for the duration.
-- Returns true if still under the rate, false if just locked out.
record_authfail = function( ip )
    if not _activate then return true end
    if not ip or ip == "" then return true end
    local ok = _consume( "ip:" .. ip, "authfail", _authfail_burst, _authfail_rate_per_sec )
    if not ok then
        _ip_blocks[ ip ] = socket_gettime( ) + _authfail_lockout
    end
    return ok
end

tick = function( )
    local now = socket_gettime( )
    if ( now - _last_cleanup ) < _cleanup_interval then return end
    _last_cleanup = now
    local stale_before = now - _bucket_idle_max
    for id, kinds in pairs( _buckets ) do
        local newest = 0
        for _, tk in pairs( kinds ) do
            if tk.ts > newest then newest = tk.ts end
        end
        if newest < stale_before then
            _buckets[ id ] = nil
        end
    end
    -- Drop expired IP locks so the table does not grow unboundedly.
    for ip, until_ts in pairs( _ip_blocks ) do
        if now >= until_ts then _ip_blocks[ ip ] = nil end
    end
end

init = function( )
    _activate = cfg_get "ratelimit_activate"
    _bypass_level = cfg_get "ratelimit_bypass_level"
    _perip_max_conns = cfg_get "ratelimit_perip_max_conns"
    _perip_conn_rate = cfg_get "ratelimit_perip_conn_rate"
    _perip_conn_burst = cfg_get "ratelimit_perip_conn_burst"
    _hs_timeout = cfg_get "ratelimit_handshake_timeout"
    -- authfail rate is configured per-minute for human-friendly tuning.
    _authfail_rate_per_sec = cfg_get "ratelimit_perip_authfail_rate" / 60
    _authfail_burst = cfg_get "ratelimit_perip_authfail_burst"
    _authfail_lockout = cfg_get "ratelimit_authfail_lockout"
    _msg_rate = cfg_get "ratelimit_user_msg_rate"
    _msg_burst = cfg_get "ratelimit_user_msg_burst"
    -- search is configured as "one per N seconds" for legibility; convert
    -- to fill-rate per second.
    local search_period = cfg_get "ratelimit_user_search_period"
    if not search_period or search_period <= 0 then search_period = 1 end
    _search_rate_per_sec = 1 / search_period
    _search_burst = cfg_get "ratelimit_user_search_burst"
    _last_cleanup = socket_gettime( )
end

----------------------------------// PUBLIC INTERFACE //--

return {

    init = init,

    accept_ip = accept_ip,
    release_ip = release_ip,
    handshake_started = handshake_started,
    handshake_finished = handshake_finished,
    expired_handshakes = expired_handshakes,
    user_msg = user_msg,
    user_search = user_search,
    record_authfail = record_authfail,
    tick = tick,

}
