--[[

    tests/unit/etc_status_push_test.lua

    Unit tests for scripts/etc_status_push.lua (public-status heartbeat).

    Exercises (plugins get NO `use`; every dependency is a sandbox-global
    stub captured at file-load time):
      - activate=false -> onTimer never sends
      - happy path -> one POST with url / method / timeout / verify / the
        Authorization: Bearer <token> + Content-Type headers, and a JSON
        body of exactly { name, users, uptime } with correct values
        (users = humans-only count, uptime = os.time()-start, integer)
      - tls_verify false -> verify "none"; cafile set/empty -> passed/nil
      - interval throttle: two ticks within interval -> ONE beat; after
        interval -> a second beat
      - in_flight guard: a tick while a beat is outstanding does NOT send
      - non-2xx / on_error / not-queued -> only clears in_flight, the next
        interval sends again (heartbeat: no give-up)
      - missing token / missing url / missing http_client -> inert, never
        sends, never crashes
      - secrets.register is called for the token key

    Run: lua5.4 tests/unit/etc_status_push_test.lua

]]--

-- Real dkjson so encode-in-plugin / decode-in-test runs the genuine codec.
local dkjson = assert( loadfile( "dkjson/dkjson.lua" ) )( )

----------------------------------------------------------------------
-- tiny harness
----------------------------------------------------------------------
local checks, failures = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-58s got=%s want=%s\n", label, tostring( got ), tostring( want ) ) )
    else
        io.write( "ok   " .. label .. "\n" )
    end
end
local function truthy( label, v )
    checks = checks + 1
    if not v then failures = failures + 1; io.write( "FAIL " .. label .. " (got " .. tostring( v ) .. ")\n" )
    else io.write( "ok   " .. label .. "\n" ) end
end

----------------------------------------------------------------------
-- mutable state the stubs close over
----------------------------------------------------------------------
local _now, _start, _users, _cfg, _requests, _registered, _sync_reject

local function base_cfg( )
    return {
        hub_name                   = "MyHub",
        etc_status_push_activate   = true,
        etc_status_push_url        = "https://status.example.org/api/hub-status/ingest",
        etc_status_push_token      = "secrettoken123",
        etc_status_push_interval   = 300,
        etc_status_push_tls_verify = true,
        etc_status_push_cafile     = "",
    }
end

----------------------------------------------------------------------
-- sandbox-global stubs (installed once; state reset per load)
----------------------------------------------------------------------
_G.type = type; _G.pairs = pairs; _G.tostring = tostring
_G.table = table; _G.string = string; _G.math = math
_G.dkjson = dkjson

local _real_os = os
_G.os = setmetatable( { time = function( ) return _now end }, { __index = _real_os } )
_G.signal = { get = function( k ) if k == "start" then return _start end return nil end }
_G.cfg = { get = function( k ) return _cfg[ k ] end }
_G.secrets = {
    register = function( k ) _registered[ k ] = true end,
    lookup   = function( k ) local v = _cfg[ k ]; if v == nil or v == "" then return nil end return v end,
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
    getusers    = function( ) return _users end,
}

----------------------------------------------------------------------
-- helpers
----------------------------------------------------------------------
local function load_plugin( overrides, mutate )
    _cfg = base_cfg( )
    if overrides then for k, v in pairs( overrides ) do _cfg[ k ] = v end end
    if mutate then mutate( _cfg ) end        -- for deleting keys (nil can't ride in `overrides`)
    _now = 1000000; _start = _now - 500     -- uptime 500s
    _users = { [ 1 ] = true, [ 2 ] = true, [ 3 ] = true }   -- 3 humans-only
    _requests = { }; _registered = { }; _sync_reject = false
    _G._listeners = { }
    assert( loadfile( "scripts/etc_status_push.lua" ) )( )
    if _G._listeners.onStart then _G._listeners.onStart( ) end
    return _G._listeners
end
local function tick( ) return _G._listeners.onTimer( ) end
local function last_req( ) return _requests[ #_requests ] end
local function complete( status ) last_req( ).on_complete{ status = status } end
local function error_cb( e ) last_req( ).on_error( e ) end
local function body_of( req ) return ( dkjson.decode( req.body ) ) end

----------------------------------------------------------------------
-- 1. activate=false -> never sends
----------------------------------------------------------------------
do
    load_plugin{ etc_status_push_activate = false }
    tick( )
    eq( "activate=false: no request", #_requests, 0 )
end

----------------------------------------------------------------------
-- 2. happy path: one POST, correct headers + body
----------------------------------------------------------------------
do
    load_plugin( )
    tick( )
    eq( "happy: one request", #_requests, 1 )
    local r = last_req( )
    eq( "happy: url",     r.url,     "https://status.example.org/api/hub-status/ingest" )
    eq( "happy: method",  r.method,  "POST" )
    eq( "happy: timeout", r.timeout, 10 )
    eq( "happy: verify peer (default)", r.verify, "peer" )
    eq( "happy: Authorization header", r.headers[ "Authorization" ], "Bearer secrettoken123" )
    eq( "happy: Content-Type header",  r.headers[ "Content-Type" ], "application/json" )
    truthy( "happy: has on_complete", r.on_complete )
    truthy( "happy: has on_error",    r.on_error )
    eq( "happy: token key registered as secret", _registered[ "etc_status_push_token" ], true )
    local b = body_of( r )
    eq( "happy: body.name",   b.name,   "MyHub" )
    eq( "happy: body.users",  b.users,  3 )
    eq( "happy: body.uptime", b.uptime, 500 )
    -- uptime must serialise as an INTEGER (`500`, not `500.0`) - lock the
    -- wire form, not just the decoded value (decode gives 500 for both).
    truthy( "happy: uptime is integer-encoded (no .0)", r.body:find( '"uptime":%s*500[,}]' ) )
    -- fixed contract: exactly three keys, no timestamp
    local nkeys = 0; for _ in pairs( b ) do nkeys = nkeys + 1 end
    eq( "happy: body has exactly 3 keys (no ts)", nkeys, 3 )
end

----------------------------------------------------------------------
-- 2b. tls_verify unset (nil) -> defaults to "peer" (token must not leak)
----------------------------------------------------------------------
do
    load_plugin( nil, function( c ) c.etc_status_push_tls_verify = nil end )
    tick( )
    eq( "tls_verify nil: defaults to peer", last_req( ).verify, "peer" )
end

----------------------------------------------------------------------
-- 2c. secret is registered whenever LOADED, even while inactive, so a
--     cfg.tbl token is redacted from /v1/config before activation.
----------------------------------------------------------------------
do
    load_plugin{ etc_status_push_activate = false, etc_status_push_token = "sometoken" }
    eq( "secret registered even when inactive", _registered[ "etc_status_push_token" ], true )
end

----------------------------------------------------------------------
-- 3. tls_verify false -> verify "none"
----------------------------------------------------------------------
do
    load_plugin{ etc_status_push_tls_verify = false }
    tick( )
    eq( "verify off: verify none", last_req( ).verify, "none" )
end

----------------------------------------------------------------------
-- 4. cafile: set -> passed; empty -> nil
----------------------------------------------------------------------
do
    load_plugin{ etc_status_push_cafile = "certs/my-ca.pem" }
    tick( )
    eq( "cafile set: passed through", last_req( ).cafile, "certs/my-ca.pem" )

    load_plugin( )   -- cafile ""
    tick( )
    eq( "cafile empty: nil (use bundle)", last_req( ).cafile, nil )
end

----------------------------------------------------------------------
-- 5. interval throttle: two ticks within interval -> one beat; after -> two
----------------------------------------------------------------------
do
    load_plugin( )
    tick( ); complete( 200 )               -- beat 1, cleared
    eq( "throttle: first tick sends", #_requests, 1 )
    _now = _now + 100; tick( )             -- still within interval (300)
    eq( "throttle: within interval no 2nd beat", #_requests, 1 )
    _now = _now + 300; tick( )             -- now past next_beat
    eq( "throttle: after interval a 2nd beat", #_requests, 2 )
end

----------------------------------------------------------------------
-- 6. in_flight guard: outstanding beat blocks the next tick
----------------------------------------------------------------------
do
    load_plugin( )
    tick( )                                -- beat 1, in_flight (not completed)
    eq( "in_flight: first beat sent", #_requests, 1 )
    _now = _now + 300; tick( )             -- due, but in_flight -> blocked
    eq( "in_flight: blocked while outstanding", #_requests, 1 )
    complete( 200 )                        -- clears in_flight
    tick( )                                -- now due + free -> sends
    eq( "in_flight: sends after completion", #_requests, 2 )
end

----------------------------------------------------------------------
-- 7. non-2xx -> clears in_flight, next interval retries (no give-up)
----------------------------------------------------------------------
do
    load_plugin( )
    tick( ); complete( 503 )               -- server error, no crash, cleared
    _now = _now + 300; tick( )
    eq( "non-2xx: retries next interval", #_requests, 2 )
end

----------------------------------------------------------------------
-- 8. on_error -> clears in_flight, retries next interval
----------------------------------------------------------------------
do
    load_plugin( )
    tick( ); error_cb( "connection refused" )
    _now = _now + 300; tick( )
    eq( "on_error: retries next interval", #_requests, 2 )
end

----------------------------------------------------------------------
-- 9. request not queued (ok=false) -> in_flight cleared, retries
----------------------------------------------------------------------
do
    load_plugin( )
    _sync_reject = true
    tick( )                                -- request returns false, no callbacks
    eq( "not-queued: attempt captured", #_requests, 1 )
    _sync_reject = false
    _now = _now + 300; tick( )             -- in_flight was cleared -> retries
    eq( "not-queued: in_flight cleared, retries", #_requests, 2 )
end

----------------------------------------------------------------------
-- 10. missing token -> inert
----------------------------------------------------------------------
do
    load_plugin{ etc_status_push_token = "" }
    tick( )
    eq( "no token: inert", #_requests, 0 )
end

----------------------------------------------------------------------
-- 11. missing url -> inert
----------------------------------------------------------------------
do
    load_plugin{ etc_status_push_url = "" }
    tick( )
    eq( "no url: inert", #_requests, 0 )
end

----------------------------------------------------------------------
-- 12. missing http_client -> inert, no crash
----------------------------------------------------------------------
do
    local saved = _G.http_client
    _G.http_client = nil
    load_plugin( )
    tick( )
    local sent = #_requests
    _G.http_client = saved
    eq( "no http_client: inert, no crash", sent, 0 )
end

----------------------------------------------------------------------
-- 13. uptime negative clock skew -> clamped to 0
----------------------------------------------------------------------
do
    load_plugin( )
    _start = _now + 100          -- start in the "future"
    tick( )
    eq( "clock skew: uptime clamped >= 0", body_of( last_req( ) ).uptime, 0 )
end

----------------------------------------------------------------------
io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures > 0 and 1 or 0 )
