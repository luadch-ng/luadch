--[[

    tests/unit/http_router_test.lua

    Unit tests for the pure-Lua-bit functions of core/http_router.lua
    (constant_time_eq, validate_schema, envelope helpers, token
    resolution, schema validator, request-id shape). Dispatch is
    smoke-tested end-to-end against a real hub.

    The router uses `use "cfg"` and `use "out"` and `use "dkjson"`
    at file scope; we stub them here so the module can load in a
    standalone interpreter.

    Run: lua5.4 tests/unit/http_router_test.lua
    Exit 0 = all pass, 1 = a failure (CI-friendly).

]]--

-- minimal `use` shim, lockstep with http_router.lua's imports.
-- http_router.lua snapshots `cfg.get` to a local at module-load
-- time (`local cfg_get = cfg.get`), so we MUST NOT swap the
-- _mock_cfg.get field after the module loads - the local won't
-- track the swap. Instead, the original closure reads tunable
-- module-locals so per-test config (e.g. shrunk idempotency cap)
-- can be applied without reassigning the function.
local _stub_cfg_tokens = { }
local _stub_cfg_idem_cap = nil    -- nil = use default; integer overrides
local _last_audit_args = nil
local _mock_cfg = {
    get = function( key )
        if key == "http_api_tokens" then return _stub_cfg_tokens end
        if key == "log_api_audit" then return true end
        if key == "http_api_log_reads" then return false end
        if key == "http_api_idempotency_max_entries" then return _stub_cfg_idem_cap end
        return nil
    end,
}
local _mock_out = {
    put       = function() end,
    error     = function() end,
    api_audit = function( ... ) _last_audit_args = { ... } end,
}
local _mock_dkjson = {
    encode = function( v )
        -- minimal stub: just stringify with type discrimination.
        -- Real dkjson is bundled and gets exercised by smoke; here
        -- we only verify the router CALLS encode with the right
        -- shape. Returns the table as a sentinel.
        return { _encoded = v }
    end,
    decode = function( s )
        if type( s ) ~= "string" then return nil, nil, "not a string" end
        if s == "BAD" then return nil, nil, "stub: forced bad json" end
        -- the stub accepts the special prefix "OBJ:" + lua syntax
        if s:sub( 1, 4 ) == "OBJ:" then
            local fn, err = loadstring and loadstring( "return " .. s:sub( 5 ) )
                or load( "return " .. s:sub( 5 ) )
            if not fn then return nil, nil, err end
            local ok, t = pcall( fn )
            if not ok then return nil, nil, t end
            return t
        end
        return nil, nil, "stub: only OBJ:{...} accepted"
    end,
}

-- Phase 1c: http_router now also calls `use "socket"` (idempotency
-- cache TTL) and `use "adclib"` (constant_time_eq C binding).
-- `socket.gettime` is the only field touched at module load; a
-- minimal stub backed by os.time() is enough for unit tests.
-- `adclib = false` exercises the pure-Lua constant_time_eq fallback;
-- the C binding is covered by the smoke harness which runs against
-- a real build.
local _mock_socket = { gettime = function( ) return os.time( ) end }

local _real = {
    string = string, table = table, os = os, io = io, math = math,
    pairs = pairs, ipairs = ipairs, tostring = tostring, tonumber = tonumber,
    type = type, pcall = pcall, select = select, error = error,
    cfg = _mock_cfg, out = _mock_out, dkjson = _mock_dkjson,
    socket = _mock_socket, adclib = false,
}
_G.use = function( name )
    local v = _real[ name ]
    assert( v ~= nil, "http_router_test shim missing dep: use \"" .. name .. "\"" )
    return v
end

local router = assert( loadfile( "core/http_router.lua" ) )( )

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-50s got=%q want=%q\n",
            label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

----------------------------------------------------------------------
-- constant_time_eq
----------------------------------------------------------------------

eq( "cte: equal strings",          router._constant_time_eq( "abc", "abc" ), true )
eq( "cte: different strings",      router._constant_time_eq( "abc", "abd" ), false )
eq( "cte: different lengths",      router._constant_time_eq( "abc", "abcd" ), false )
eq( "cte: empty equal",            router._constant_time_eq( "", "" ), true )
eq( "cte: non-string a",           router._constant_time_eq( nil, "x" ), false )
eq( "cte: non-string b",           router._constant_time_eq( "x", 42 ), false )
eq( "cte: byte-precise difference at position 1",
    router._constant_time_eq( "abc", "abx" ), false )

----------------------------------------------------------------------
-- validate_schema
----------------------------------------------------------------------

do
    local schema = {
        target = { type = "string", required = true, max_length = 64 },
        duration_minutes = { type = "integer", min = 1, max = 525600 },
        scope = { type = "string", enum = { "all", "hub", "level" } },
    }
    local ok, err
    ok = router._validate_schema( schema, { target = "x", scope = "all" } )
    eq( "schema: minimum valid", ok, true )

    ok, err = router._validate_schema( schema, { } )
    eq( "schema: missing required", ok, false )

    ok, err = router._validate_schema( schema, { target = 42 } )
    eq( "schema: wrong type", ok, false )

    ok = router._validate_schema( schema,
        { target = "x", duration_minutes = 60 } )
    eq( "schema: integer ok", ok, true )

    ok, err = router._validate_schema( schema,
        { target = "x", duration_minutes = 1.5 } )
    eq( "schema: integer rejects float", ok, false )

    ok, err = router._validate_schema( schema,
        { target = "x", scope = "everyone" } )
    eq( "schema: enum mismatch", ok, false )

    ok, err = router._validate_schema( schema,
        { target = string.rep( "x", 65 ) } )
    eq( "schema: max_length exceeded", ok, false )

    ok, err = router._validate_schema( schema,
        { target = "x", duration_minutes = 0 } )
    eq( "schema: below min", ok, false )

    eq( "schema: nil schema -> ok",
        router._validate_schema( nil, { } ), true )
end

----------------------------------------------------------------------
-- envelope helpers
----------------------------------------------------------------------

do
    local e = router._envelope_success( { x = 1 } )
    -- mock dkjson.encode returns { _encoded = v }; we assert the
    -- shape the router built.
    eq( "envelope: success ok flag", e._encoded.ok, true )
    eq( "envelope: success data x", e._encoded.data.x, 1 )

    local f = router._envelope_error( "E_BAD_INPUT", "bad field" )
    eq( "envelope: error ok flag", f._encoded.ok, false )
    eq( "envelope: error code", f._encoded.error.code, "E_BAD_INPUT" )
    eq( "envelope: error message", f._encoded.error.message, "bad field" )
end

----------------------------------------------------------------------
-- resolve_token
----------------------------------------------------------------------

do
    _stub_cfg_tokens = {
        [ "admin-tokens-here-which-is-long-enough" ] = { scope = "admin", comment = "ops cli" },
        [ "readonlytoken99-also-long-enough" ]       = { scope = "read",  comment = "grafana" },
        [ "shorty7" ]                                = { scope = "read",  comment = "tiny" },
    }
    local label, scope, bid = router._resolve_token( "Bearer admin-tokens-here-which-is-long-enough" )
    eq( "resolve: admin scope", scope, "admin" )
    eq( "resolve: admin label has comment", label:find( "ops cli", 1, true ) ~= nil, true )
    eq( "resolve: admin label NO full secret",
        label:find( "tokens-here-which-is", 1, true ), nil )
    eq( "resolve: bucket_id is 16 chars for long token", #bid, 16 )
    eq( "resolve: bucket_id is non-empty", #bid > 0, true )

    -- Two distinct tokens with the same comment + same first4 +
    -- same last4 would have collided in the PR-B label-as-bucket
    -- scheme. Confirm their bucket_ids differ here.
    _stub_cfg_tokens = {
        [ "abcd-XXXX-aaaaaaaa-wxyz" ] = { scope = "read", comment = "dup" },
        [ "abcd-YYYY-bbbbbbbb-wxyz" ] = { scope = "read", comment = "dup" },
    }
    local lbl1, _, bid1 = router._resolve_token( "Bearer abcd-XXXX-aaaaaaaa-wxyz" )
    local lbl2, _, bid2 = router._resolve_token( "Bearer abcd-YYYY-bbbbbbbb-wxyz" )
    eq( "resolve: label collides (audit only)", lbl1, lbl2 )
    eq( "resolve: bucket_id does NOT collide", bid1 == bid2, false )

    -- Short token (< 16 chars): bucket_id falls back to full token
    _stub_cfg_tokens = {
        [ "shorty7" ] = { scope = "read", comment = "tiny" },
    }
    local _, _, bid_s = router._resolve_token( "Bearer shorty7" )
    eq( "resolve: short token bucket_id == full token", bid_s, "shorty7" )

    -- restore for the unknown-token tests below
    _stub_cfg_tokens = { }
    local nil_l, err = router._resolve_token( "Bearer nope-not-a-token" )
    eq( "resolve: unknown -> nil", nil_l, nil )
    eq( "resolve: unknown -> error code", err, "unknown" )

    nil_l, err = router._resolve_token( "MalformedHeader" )
    eq( "resolve: no Bearer -> malformed", err, "malformed" )

    nil_l, err = router._resolve_token( nil )
    eq( "resolve: missing -> missing", err, "missing" )
end

----------------------------------------------------------------------
-- generate_request_id shape (8-4-4-4-12 hex)
----------------------------------------------------------------------

do
    local id = router._generate_request_id( )
    eq( "req-id: length",
        #id, 36 )
    eq( "req-id: pattern matches UUIDv4-shape",
        id:match( "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-4%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$" ) ~= nil,
        true )
end

----------------------------------------------------------------------
-- register + unregister_all + duplicate rejection
----------------------------------------------------------------------

do
    router.unregister_all( )

    -- Register fresh; succeeds.
    local handler = function( ) return { status = 200, data = { } } end
    local ok = pcall( router.register, "GET", "/v1/foo", "read", handler )
    eq( "register: fresh route ok", ok, true )

    -- Duplicate same method+path rejects.
    local ok2 = pcall( router.register, "GET", "/v1/foo", "read", handler )
    eq( "register: duplicate route rejected", ok2, false )

    -- Different method on same path: ok.
    local ok3 = pcall( router.register, "POST", "/v1/foo", "admin", handler )
    eq( "register: same path different method ok", ok3, true )

    -- Lowercase method rejected.
    local ok4 = pcall( router.register, "get", "/v1/bar", "read", handler )
    eq( "register: lowercase method rejected", ok4, false )

    -- Invalid scope rejected.
    local ok5 = pcall( router.register, "GET", "/v1/bar", "guest", handler )
    eq( "register: invalid scope rejected", ok5, false )

    -- Path must start with /
    local ok6 = pcall( router.register, "GET", "v1/baz", "read", handler )
    eq( "register: path without / rejected", ok6, false )

    -- Non-function handler rejected.
    local ok7 = pcall( router.register, "GET", "/v1/qux", "read", "not-a-function" )
    eq( "register: non-function handler rejected", ok7, false )

    router.unregister_all( )
end

----------------------------------------------------------------------
-- idempotency cache (FIFO + TTL + replace-in-place + clear)
----------------------------------------------------------------------

do
    router._idem_clear( )

    -- miss on cold cache
    local status, body, headers = router._idem_lookup( "label", "k1" )
    eq( "idem: cold miss", status, nil )

    -- store + hit
    router._idem_store( "label", "k1", 201, "BODY1", { foo = "bar" } )
    local st, bd, hd = router._idem_lookup( "label", "k1" )
    eq( "idem: hit status", st, 201 )
    eq( "idem: hit body",   bd, "BODY1" )
    eq( "idem: hit header keeps foo", hd and hd.foo, "bar" )

    -- different label, same key -> miss (per-token isolation)
    local st2 = router._idem_lookup( "other_label", "k1" )
    eq( "idem: per-token isolation", st2, nil )

    -- replace in place (same key)
    router._idem_store( "label", "k1", 409, "CONFLICT", { } )
    local st3, bd3 = router._idem_lookup( "label", "k1" )
    eq( "idem: replace status", st3, 409 )
    eq( "idem: replace body",   bd3, "CONFLICT" )

    -- empty / missing key -> no-op (not cached, not looked up)
    router._idem_store( "label", "", 200, "X", { } )
    local stN = router._idem_lookup( "label", "" )
    eq( "idem: empty key never hits", stN, nil )
    local stN2 = router._idem_lookup( "label", nil )
    eq( "idem: nil key never hits", stN2, nil )

    -- clear
    router._idem_clear( )
    local stC = router._idem_lookup( "label", "k1" )
    eq( "idem: cleared", stC, nil )

    -- Cap-eviction: shrink cap to 2 via mock cfg, store 3 entries,
    -- confirm oldest insert was evicted FIFO. Also confirms the
    -- replace-in-place + ord-bump path: replacing k1 between k2
    -- and k3 stores does NOT evict the live k1 when k3 trips cap.
    _stub_cfg_idem_cap = 2
    router._idem_clear( )
    router._idem_store( "L", "k1", 200, "B1", { } )
    router._idem_store( "L", "k2", 200, "B2", { } )
    eq( "idem-cap: pre-evict k1 alive", router._idem_lookup( "L", "k1" ), 200 )
    eq( "idem-cap: pre-evict k2 alive", router._idem_lookup( "L", "k2" ), 200 )
    router._idem_store( "L", "k3", 200, "B3", { } )
    eq( "idem-cap: oldest k1 evicted", router._idem_lookup( "L", "k1" ), nil )
    eq( "idem-cap: k2 survives", router._idem_lookup( "L", "k2" ), 200 )
    eq( "idem-cap: k3 alive", router._idem_lookup( "L", "k3" ), 200 )

    -- Replace-in-place + cap: store k1+k2, then replace k1, then
    -- store k3 (would trigger 1 eviction). The replaced k1 must
    -- survive because its ord is the NEWEST; k2 should be evicted.
    router._idem_clear( )
    router._idem_store( "L", "k1", 200, "B1-old", { } )
    router._idem_store( "L", "k2", 200, "B2",     { } )
    router._idem_store( "L", "k1", 200, "B1-new", { } )    -- replace; k1.ord becomes newest
    router._idem_store( "L", "k3", 200, "B3",     { } )    -- evict cycle: pops k1-stale, sees ord mismatch, keeps live k1; pops k2 next, evicts.
    local k1_st, k1_bd = router._idem_lookup( "L", "k1" )
    eq( "idem-cap-replace: replaced k1 alive", k1_st, 200 )
    eq( "idem-cap-replace: replaced k1 body is NEW", k1_bd, "B1-new" )
    eq( "idem-cap-replace: k2 evicted (older ord)", router._idem_lookup( "L", "k2" ), nil )
    eq( "idem-cap-replace: k3 alive", router._idem_lookup( "L", "k3" ), 200 )

    -- restore default cap (other tests don't care, but be tidy)
    _stub_cfg_idem_cap = nil
end

----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
