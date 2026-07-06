--[[

    tests/unit/etc_proxydetect_test.lua

    Unit tests for scripts/etc_proxydetect.lua (#78 Phase F). Exercises:
      - query_ip SSRF validation: v4 / v6 / v4-mapped strip / reject
        URL-metachars + over-length / empty
      - classify (proxycheck v2 interpret): proxy+type -> type set,
        status denied -> provider error, clean -> {}, key-normalised record
      - matched_types intersect with the live block_types
      - onConnect cache-miss -> async request (URL carries IP + key),
        allow-pending
      - on_complete(200, proxy) block mode -> blocklist.add (source/cidr/
        stealth/expires_at/meta) + user:kill via SID re-resolve + cache set
      - on_complete(200, clean) -> no add, no kill, cache clean
      - cache hit -> synchronous kick, NO second request
      - level-exempt operator -> no request
      - log_only -> no store push, no kill, still audits
      - provider error / non-200 -> fail-open (no kick) vs fail-closed (kick)
      - unparseable IP -> no request; quota cap -> no request; in-flight guard
      - SID-reuse + user-left guards in the async callback
      - secrets.register / lookup; v6 -> /128; get_status shape

    Run: lua5.4 tests/unit/etc_proxydetect_test.lua

]]--

----------------------------------------------------------------------
-- Real dkjson so the interpret path runs the genuine decode.
----------------------------------------------------------------------
local dkjson = assert( loadfile( "dkjson/dkjson.lua" ) )( )

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
local function truthy( what, v ) if v then _pass = _pass + 1
    else _fail = _fail + 1; io.stderr:write( "FAIL: " .. what .. " got=" .. tostring( v ) .. "\n" ) end end
local function falsy( what, v ) if not v then _pass = _pass + 1
    else _fail = _fail + 1; io.stderr:write( "FAIL: " .. what .. " got=" .. tostring( v ) .. "\n" ) end end

----------------------------------------------------------------------
-- Mutable cfg + capture state. Plugins get NO `use`; every dependency
-- is a sandbox global stub.
----------------------------------------------------------------------
local _cfg = { }
local function reset_cfg( )
    _cfg = {
        language = "en",
        etc_proxydetect_enabled = true,
        etc_proxydetect_provider = "proxycheck",
        etc_proxydetect_api_key = "",       -- resolved via secrets stub instead
        etc_proxydetect_action = "block",
        etc_proxydetect_block_types = { proxy = true, vpn = true, tor = true },
        etc_proxydetect_check_levels = { [ 20 ] = true, [ 80 ] = false, [ 100 ] = true },
        etc_proxydetect_cache_ttl_sec = 86400,
        etc_proxydetect_query_timeout_sec = 5,
        etc_proxydetect_fail_open = true,
        etc_proxydetect_stealth = true,
        etc_proxydetect_max_queries_per_day = 1000,
        etc_proxydetect_kick_reason = "no proxies here",
        etc_proxydetect_oplevel = 80,
        etc_proxydetect_report = false,
        etc_proxydetect_report_hubbot = false,
        etc_proxydetect_report_opchat = false,
        etc_proxydetect_llevel = 60,
    }
end

local _now = 1000000
local _requests, _adds, _audit, _reports, _registered, _online, _persisted, _save_count
local _sync_reject
local function fresh( )
    _requests = { }; _adds = { }; _audit = { }; _reports = { }; _registered = { }
    _online = { }; _persisted = nil; _save_count = 0; _sync_reject = false
end
fresh( )

_G.use = nil
_G.PROCESSED = "PROCESSED"
_G.table = table
_G.string = string
_G.math = math
_G.type = type
_G.pairs = pairs
_G.ipairs = ipairs
_G.next = next
_G.tonumber = tonumber
_G.tostring = tostring
_G.pcall = pcall
_G.dkjson = dkjson
_G.socket = { gettime = function( ) return _now end }
-- Stub io.open (plugin cache file) but keep real io.stderr / io.write for
-- the harness via a metatable fallback. os is left real (the plugin uses
-- socket.gettime, not os) so os.exit at the end works.
local _real_io = io
_G.io = setmetatable(
    { open = function( ) if _persisted then return { close = function( ) end } end return nil end },
    { __index = _real_io } )
_G.util = {
    loadtable = function( ) return _persisted end,
    savetable = function( t, name, path ) _save_count = _save_count + 1 end,
}
_G.secrets = {
    lookup   = function( k ) return _cfg[ k ] ~= "" and _cfg[ k ] or _cfg._resolved_key end,
    register = function( k ) _registered[ k ] = true end,
}
_G.cfg = {
    get = function( k ) return _cfg[ k ] end,
    loadlanguage = function( ) return { } end,
}
_G.utf = { format = function( fmt, ... ) return string.format( fmt, ... ) end }
_G.audit = {
    build = function( action, actor, target, reason, meta )
        return { action = action, meta = meta or { } }
    end,
    fire = function( ev ) _audit[ #_audit + 1 ] = ev end,
}
_G.blocklist = {
    add = function( cidr, opts )
        _adds[ #_adds + 1 ] = { cidr = cidr, opts = opts }
        return true, #_adds
    end,
}
_G.http_client = {
    request = function( req )
        _requests[ #_requests + 1 ] = req
        if _sync_reject then return false, "in-flight cap" end
        return true
    end,
}
_G.hub = {
    setlistener = function( ev, _opts, fn ) _G._listeners[ ev ] = fn end,
    debug       = function( ) end,
    getbot      = function( ) return "bot" end,
    escapeto    = function( s ) return s end,
    issidonline = function( sid ) return _online[ sid ] end,
    http_register = function( ) end,
    import      = function( name )
        if name == "etc_hubcommands" then return { add = function( ) return true end } end
        if name == "cmd_help" then return { reg = function( ) end } end
        if name == "etc_usercommands" then return { add = function( ) end } end
        if name == "etc_report" then
            return { send = function( _a, _h, _o, _l, msg ) _reports[ #_reports + 1 ] = msg end }
        end
        return nil
    end,
}

local function mkuser( level, ip, sid, cid )
    local u
    u = {
        _killed = nil,
        level = function( ) return level end,
        ip    = function( ) return ip end,
        nick  = function( ) return "u" .. tostring( sid ) end,
        sid   = function( ) return sid end,
        cid   = function( ) return cid end,
        kill  = function( _, msg ) u._killed = msg end,
        reply = function( ) end,
    }
    return u
end

local function load_plugin( overrides )
    reset_cfg( )
    if overrides then for k, v in pairs( overrides ) do _cfg[ k ] = v end end
    fresh( )
    _G._listeners = { }
    local p = assert( loadfile( "scripts/etc_proxydetect.lua" ) )( )
    if _G._listeners.onStart then _G._listeners.onStart( ) end
    return p, _G._listeners
end

local function connect( u ) _online[ u:sid( ) ] = u; return _G._listeners.onConnect( u ) end
local function complete( status, body, headers )
    _requests[ #_requests ].on_complete{ status = status, headers = headers or { }, body = body }
end
local function error_cb( err ) _requests[ #_requests ].on_error( err ) end

local PROXY_JSON = '{"status":"ok","1.2.3.4":{"proxy":"yes","type":"VPN"}}'
local CLEAN_JSON = '{"status":"ok","1.2.3.4":{"proxy":"no","type":"Business"}}'

----------------------------------------------------------------------
-- query_ip SSRF validation
----------------------------------------------------------------------
do
    local p = load_plugin( )
    eq( "ip: valid v4",            ( p._query_ip( "8.8.8.8" ) ), "8.8.8.8" )
    local _, fam4 = p._query_ip( "8.8.8.8" ); eq( "ip: v4 family", fam4, 4 )
    eq( "ip: valid v6",            ( p._query_ip( "2001:db8::1" ) ), "2001:db8::1" )
    local _, fam6 = p._query_ip( "2001:db8::1" ); eq( "ip: v6 family", fam6, 6 )
    eq( "ip: v4-mapped stripped",  ( p._query_ip( "::ffff:1.2.3.4" ) ), "1.2.3.4" )
    local _, famm = p._query_ip( "::ffff:1.2.3.4" ); eq( "ip: mapped -> v4 family", famm, 4 )
    falsy( "ip: slash rejected",   p._query_ip( "1.2.3.4/foo" ) )
    falsy( "ip: query rejected",   p._query_ip( "1.2.3.4?x=1" ) )
    falsy( "ip: at rejected",      p._query_ip( "1.2.3.4@evil.com" ) )
    -- has a colon (passes the v6 structural gate) but a URL metachar ->
    -- only the charset guard rejects it. Guards the v6 SSRF path directly.
    falsy( "ip: v6 with metachar", p._query_ip( "2001:db8::?evil" ) )
    falsy( "ip: v6 with slash",    p._query_ip( "2001:db8::/@x" ) )
    falsy( "ip: space rejected",   p._query_ip( "1.2.3.4 5" ) )
    falsy( "ip: octet > 255",      p._query_ip( "1.2.3.999" ) )
    falsy( "ip: empty",            p._query_ip( "" ) )
    falsy( "ip: nil",              p._query_ip( nil ) )
    falsy( "ip: over-length v6",   p._query_ip( string.rep( "a", 46 ) .. ":" ) )
end

----------------------------------------------------------------------
-- classify (proxycheck v2 interpret)
----------------------------------------------------------------------
do
    local p = load_plugin( )
    local t = p.classify( { status = "ok", [ "1.2.3.4" ] = { proxy = "yes", type = "VPN" } }, "1.2.3.4" )
    truthy( "classify: proxy=yes -> proxy", t and t.proxy )
    truthy( "classify: type VPN -> vpn",    t and t.vpn )
    local t2 = p.classify( { status = "ok", [ "9.9.9.9" ] = { proxy = "yes", type = "TOR" } }, "9.9.9.9" )
    truthy( "classify: type TOR -> tor", t2 and t2.tor )
    local t3 = p.classify( { status = "ok", [ "1.2.3.4" ] = { proxy = "no" } }, "1.2.3.4" )
    truthy( "classify: clean -> empty table", type( t3 ) == "table" and not next( t3 ) )
    local denied = p.classify( { status = "denied" }, "1.2.3.4" )
    falsy( "classify: denied -> provider error (nil)", denied )
    -- record found by scan even if the top-level key differs from the query IP
    local t4 = p.classify( { status = "ok", [ "1.2.3.4" ] = { proxy = "yes", type = "VPN" } }, "0.0.0.0" )
    truthy( "classify: key-scan fallback finds the record", t4 and t4.proxy )
end

----------------------------------------------------------------------
-- matched_types intersect with block_types
----------------------------------------------------------------------
do
    local p = load_plugin( { etc_proxydetect_block_types = { proxy = true } } )
    local m = p._matched_types( { proxy = true, vpn = true } )
    eq( "matched: only proxy blocked", #m, 1 )
    eq( "matched: proxy present", m[ 1 ], "proxy" )
    local none = p._matched_types( { vpn = true } )
    eq( "matched: vpn not blocked -> none", #none, 0 )
end

----------------------------------------------------------------------
-- onConnect cache-miss -> async request, allow-pending
----------------------------------------------------------------------
do
    load_plugin( { _resolved_key = "SECRET42" } )
    local u = mkuser( 20, "1.2.3.4", "SID1", "CID1" )
    local r = connect( u )
    eq( "connect: one request queued", #_requests, 1 )
    truthy( "connect: url carries the IP", _requests[ 1 ].url:find( "1.2.3.4", 1, true ) ~= nil )
    -- the key MUST go in the POST body, never the URL (http_client logs
    -- req.url on failure -> a query-param key would leak into error.log)
    falsy( "connect: url does NOT carry the key", _requests[ 1 ].url:find( "SECRET42", 1, true ) )
    truthy( "connect: key in POST body", _requests[ 1 ].body and _requests[ 1 ].body:find( "SECRET42", 1, true ) ~= nil )
    eq( "connect: POST when key present", _requests[ 1 ].method, "POST" )
    truthy( "connect: response cap set", _requests[ 1 ].max_response ~= nil )
    eq( "connect: allow-pending (nil return)", r, nil )
    eq( "connect: not kicked yet", u._killed, nil )
    truthy( "connect: api key registered as secret", _registered.etc_proxydetect_api_key )
end

----------------------------------------------------------------------
-- on_complete(200, proxy) block mode -> add + kill + cache
----------------------------------------------------------------------
do
    load_plugin( )
    local u = mkuser( 20, "1.2.3.4", "SID1", "CID1" )
    connect( u )
    complete( 200, PROXY_JSON )
    eq( "positive: one store push", #_adds, 1 )
    eq( "positive: cidr /32", _adds[ 1 ].cidr, "1.2.3.4/32" )
    eq( "positive: source = provider", _adds[ 1 ].opts.source, "proxycheck" )
    truthy( "positive: stealth from cfg", _adds[ 1 ].opts.stealth == true )
    eq( "positive: expires_at = now + ttl", _adds[ 1 ].opts.expires_at, _now + 86400 )
    eq( "positive: meta.provider", _adds[ 1 ].opts.meta.provider, "proxycheck" )
    truthy( "positive: user killed", u._killed ~= nil )
    truthy( "positive: kick is ISTA 231", u._killed:find( "ISTA 231", 1, true ) ~= nil )
    truthy( "positive: audit fired", #_audit >= 1 )
end

----------------------------------------------------------------------
-- on_complete(200, clean) -> no add, no kill, cache set
----------------------------------------------------------------------
do
    load_plugin( )
    local u = mkuser( 20, "1.2.3.4", "SID1", "CID1" )
    connect( u )
    complete( 200, CLEAN_JSON )
    eq( "clean: no store push", #_adds, 0 )
    eq( "clean: not killed", u._killed, nil )
end

----------------------------------------------------------------------
-- cache hit -> synchronous kick, NO second request
----------------------------------------------------------------------
do
    local p, L = load_plugin( )
    local u1 = mkuser( 20, "1.2.3.4", "SID1", "CID1" )
    connect( u1 )
    complete( 200, PROXY_JSON )          -- caches proxy verdict
    eq( "cachehit: one request so far", #_requests, 1 )
    local u2 = mkuser( 20, "1.2.3.4", "SID2", "CID2" )
    local r = connect( u2 )
    eq( "cachehit: NO second request", #_requests, 1 )
    truthy( "cachehit: killed synchronously", u2._killed ~= nil )
    eq( "cachehit: returns PROCESSED (block mode)", r, "PROCESSED" )
end

----------------------------------------------------------------------
-- level-exempt operator -> no request
----------------------------------------------------------------------
do
    load_plugin( )
    local op = mkuser( 80, "1.2.3.4", "SIDOP", "CIDOP" )   -- [80]=false in check_levels
    connect( op )
    eq( "exempt: no request for exempt op", #_requests, 0 )
end

----------------------------------------------------------------------
-- log_only -> no store push, no kill, but audits
----------------------------------------------------------------------
do
    load_plugin( { etc_proxydetect_action = "log_only" } )
    local u = mkuser( 20, "1.2.3.4", "SID1", "CID1" )
    connect( u )
    complete( 200, PROXY_JSON )
    eq( "log_only: no store push", #_adds, 0 )
    eq( "log_only: not killed", u._killed, nil )
    truthy( "log_only: still audits the match", #_audit >= 1 )
end

----------------------------------------------------------------------
-- provider error -> fail-open (no kick) vs fail-closed (kick)
----------------------------------------------------------------------
do
    load_plugin( )                       -- fail_open = true (default)
    local u = mkuser( 20, "1.2.3.4", "SID1", "CID1" )
    connect( u )
    complete( 200, '{"status":"denied"}' )
    eq( "failopen: not killed on provider error", u._killed, nil )
    eq( "failopen: no store push", #_adds, 0 )
    truthy( "failopen: query.fail audited", #_audit >= 1 )
end
do
    load_plugin( { etc_proxydetect_fail_open = false } )
    local u = mkuser( 20, "1.2.3.4", "SID1", "CID1" )
    connect( u )
    complete( 500, "" )
    truthy( "failclosed: killed on provider error", u._killed ~= nil )
    eq( "failclosed: no store push (no verdict)", #_adds, 0 )
end

----------------------------------------------------------------------
-- unparseable IP -> no request; quota cap -> no request; in-flight guard
----------------------------------------------------------------------
do
    load_plugin( )
    local u = mkuser( 20, "1.2.3.4/evil", "SID1", "CID1" )
    connect( u )
    eq( "badip: no request", #_requests, 0 )
end
do
    load_plugin( { etc_proxydetect_max_queries_per_day = 1 } )
    connect( mkuser( 20, "1.1.1.1", "S1", "C1" ) )
    connect( mkuser( 20, "2.2.2.2", "S2", "C2" ) )   -- 2nd distinct IP over the cap
    eq( "quota: capped at 1 request", #_requests, 1 )
end
do
    load_plugin( )
    connect( mkuser( 20, "1.2.3.4", "S1", "C1" ) )
    connect( mkuser( 20, "1.2.3.4", "S2", "C2" ) )   -- same IP, first still in flight
    eq( "inflight: one request for concurrent same-IP", #_requests, 1 )
end

----------------------------------------------------------------------
-- SID-reuse + user-left guards in the async callback
----------------------------------------------------------------------
do
    load_plugin( )
    local u = mkuser( 20, "1.2.3.4", "SID1", "CID1" )
    connect( u )
    -- SID reused by a DIFFERENT client (different CID) by the time the reply lands
    _online[ "SID1" ] = mkuser( 20, "1.2.3.4", "SID1", "OTHERCID" )
    complete( 200, PROXY_JSON )
    eq( "sidreuse: original not killed", u._killed, nil )
    eq( "sidreuse: reused client not killed", _online[ "SID1" ]._killed, nil )
    truthy( "sidreuse: store push still happens", #_adds == 1 )
end
do
    load_plugin( )
    local u = mkuser( 20, "1.2.3.4", "SID1", "CID1" )
    connect( u )
    _online[ "SID1" ] = nil               -- user already left
    complete( 200, PROXY_JSON )
    eq( "left: nobody killed", u._killed, nil )
    truthy( "left: store push still happens (future pre-handshake block)", #_adds == 1 )
end

----------------------------------------------------------------------
-- v6 -> /128 store push
----------------------------------------------------------------------
do
    load_plugin( )
    local u = mkuser( 20, "2001:db8::5", "SID1", "CID1" )
    connect( u )
    complete( 200, '{"status":"ok","2001:db8::5":{"proxy":"yes","type":"VPN"}}' )
    eq( "v6: one store push", #_adds, 1 )
    eq( "v6: cidr /128", _adds[ 1 ].cidr, "2001:db8::5/128" )
end

----------------------------------------------------------------------
-- get_status shape
----------------------------------------------------------------------
do
    local p = load_plugin( )
    local s = p.get_status( )
    eq( "status: enabled", s.enabled, true )
    eq( "status: provider", s.provider, "proxycheck" )
    eq( "status: provider_ok", s.provider_ok, true )
    eq( "status: action", s.action, "block" )
    truthy( "status: blocked_types is a list", type( s.blocked_types ) == "table" )
    eq( "status: fail_open", s.fail_open, true )
    eq( "status: max_per_day", s.max_per_day, 1000 )
end

----------------------------------------------------------------------
-- unknown provider -> inert (no request, no crash)
----------------------------------------------------------------------
do
    load_plugin( { etc_proxydetect_provider = "vpnapi" } )   -- not implemented in F1
    connect( mkuser( 20, "1.2.3.4", "S1", "C1" ) )
    eq( "unknown provider: no request", #_requests, 0 )
end

----------------------------------------------------------------------
-- disabled -> inert
----------------------------------------------------------------------
do
    load_plugin( { etc_proxydetect_enabled = false } )
    connect( mkuser( 20, "1.2.3.4", "S1", "C1" ) )
    eq( "disabled: no request", #_requests, 0 )
end

----------------------------------------------------------------------
-- on_error (network failure) -> fail-open, inflight cleared
----------------------------------------------------------------------
do
    load_plugin( )                       -- fail_open default true
    local u = mkuser( 20, "1.2.3.4", "S1", "C1" )
    connect( u )
    error_cb( "connection refused" )
    eq( "on_error: fail-open, not killed", u._killed, nil )
    eq( "on_error: no store push", #_adds, 0 )
    truthy( "on_error: query.fail audited", #_audit >= 1 )
    connect( mkuser( 20, "1.2.3.4", "S2", "C2" ) )
    eq( "on_error: inflight cleared -> re-query", #_requests, 2 )
end

----------------------------------------------------------------------
-- synchronous request rejection -> inflight cleared + quota refunded
----------------------------------------------------------------------
do
    local p = load_plugin( )
    _sync_reject = true
    connect( mkuser( 20, "1.2.3.4", "S1", "C1" ) )      -- request() returns false
    eq( "sync-reject: request attempted", #_requests, 1 )
    _sync_reject = false
    connect( mkuser( 20, "5.6.7.8", "S2", "C2" ) )       -- distinct IP, real dispatch
    eq( "sync-reject: inflight cleared, next IP queries", #_requests, 2 )
    eq( "sync-reject: quota slot refunded (only 1 real query)", p.get_status( ).queries_today, 1 )
end

----------------------------------------------------------------------
-- cache expiry via time-advance -> re-query after TTL
----------------------------------------------------------------------
do
    local p = load_plugin( )
    connect( mkuser( 20, "1.2.3.4", "S1", "C1" ) )
    complete( 200, CLEAN_JSON )
    eq( "expiry: one cached verdict", p.get_status( ).cached, 1 )
    _now = _now + 86401                                  -- past cache_ttl (86400)
    connect( mkuser( 20, "1.2.3.4", "S2", "C2" ) )
    eq( "expiry: expired entry -> re-query", #_requests, 2 )
    _now = 1000000
end

----------------------------------------------------------------------
-- cache-hit block does NOT duplicate the store push
----------------------------------------------------------------------
do
    load_plugin( )
    connect( mkuser( 20, "1.2.3.4", "S1", "C1" ) )
    complete( 200, PROXY_JSON )
    eq( "dedup: first detection pushes once", #_adds, 1 )
    connect( mkuser( 20, "1.2.3.4", "S2", "C2" ) )       -- cache hit, block mode
    eq( "dedup: cache-hit does NOT re-push", #_adds, 1 )
end

----------------------------------------------------------------------
-- verdict cache is hard-capped (bounds max_queries_per_day=0)
----------------------------------------------------------------------
do
    local p = load_plugin( )
    p._set_cache_cap( 2 )
    for i, ip in ipairs( { "1.1.1.1", "2.2.2.2", "3.3.3.3" } ) do
        connect( mkuser( 20, ip, "S" .. i, "C" .. i ) )
        complete( 200, '{"status":"ok"}' )              -- clean verdict, cached
    end
    eq( "cap: cache evicts past the ceiling", p.get_status( ).cached, 2 )
end

----------------------------------------------------------------------
-- flush purges idle-expired rows even when the cache is not dirty
----------------------------------------------------------------------
do
    local p, L = load_plugin( )
    connect( mkuser( 20, "1.2.3.4", "S1", "C1" ) )
    complete( 200, CLEAN_JSON )
    _now = _now + 61; L.onTimer( )                       -- dirty flush -> save
    eq( "flush: entry retained pre-expiry", p.get_status( ).cached, 1 )
    _now = _now + 86401                                  -- entry now expired (no set/get -> not dirty)
    _save_count = 0
    _now = _now + 61; L.onTimer( )                       -- Fix G: purge + save despite not-dirty
    eq( "flush: idle-expired entry purged", p.get_status( ).cached, 0 )
    truthy( "flush: idle purge still persisted", _save_count >= 1 )
    _now = 1000000
end

----------------------------------------------------------------------
io.write( string.format( "\n%d passed, %d failed\n", _pass, _fail ) )
os.exit( _fail == 0 and 0 or 1 )
