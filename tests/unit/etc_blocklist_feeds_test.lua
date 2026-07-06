--[[

    tests/unit/etc_blocklist_feeds_test.lua

    Unit tests for scripts/etc_blocklist_feeds.lua (#78 Phase E). Exercises:
      - parse_line_list: CRLF, blank lines, whole-line + inline #/; comments,
        bare IP and CIDR, IPv6 untouched
      - parse_spamhaus_json: real dkjson decode of JSONL, .cidr extraction,
        .sblid -> meta, metadata-line + malformed-line skip
      - refresh flow: onTimer past the deadline -> http_client.request ->
        on_complete(200) -> parse -> blocklist.bulk_replace with the right
        source/feed/entries + TTL (2x interval) + stealth
      - failure paths: non-200 status, http on_error, synchronous request
        rejection -> feed.refresh.fail audit, NO bulk_replace
      - in-flight overlap guard, disabled short-circuit
      - interval clamp up to the adapter minimum
      - get_status() snapshot shape

    Run: lua5.4 tests/unit/etc_blocklist_feeds_test.lua

]]--

----------------------------------------------------------------------
-- Real dkjson so parse_spamhaus_json runs the genuine decode path.
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
-- Mutable cfg + capture state, then the sandbox-global stubs the plugin
-- reads. Plugins get NO `use`.
----------------------------------------------------------------------
local _cfg = {
    language = "en",
    etc_blocklist_feeds_enabled = true,
    etc_blocklist_feeds_tor_enabled = true,
    etc_blocklist_feeds_tor_url = "https://feed.test/tor",
    etc_blocklist_feeds_tor_refresh_interval_sec = 3600,
    etc_blocklist_feeds_tor_stealth = false,
    etc_blocklist_feeds_spamhaus_enabled = false,
    etc_blocklist_feeds_spamhaus_url = "https://feed.test/spamhaus",
    etc_blocklist_feeds_spamhaus_refresh_interval_sec = 86400,
    etc_blocklist_feeds_spamhaus_stealth = true,
    etc_blocklist_feeds_spamhaus_v6_enabled = false,
    etc_blocklist_feeds_spamhaus_v6_url = "https://feed.test/spamhaus6",
    etc_blocklist_feeds_abuseipdb_enabled = false,
    etc_blocklist_feeds_abuseipdb_url = "https://feed.test/abuseipdb",
    etc_blocklist_feeds_abuseipdb_refresh_interval_sec = 86400,
    etc_blocklist_feeds_abuseipdb_stealth = false,
    etc_blocklist_feeds_generic_enabled = false,
    etc_blocklist_feeds_generic_url = "https://feed.test/generic",
    etc_blocklist_feeds_generic_refresh_interval_sec = 3600,
    etc_blocklist_feeds_generic_stealth = false,
    etc_blocklist_feeds_oplevel = 80,
    etc_blocklist_feeds_report = false,
    etc_blocklist_feeds_report_hubbot = false,
    etc_blocklist_feeds_report_opchat = false,
    etc_blocklist_feeds_llevel = 80,
}

local _now = 100000
local _bulk_ok = true    -- flip false to simulate a bulk_replace store failure
local _secrets = { }     -- key -> value, drives secrets.lookup
local _listeners, _requests, _bulk, _store, _audit, _reports, _registered
local function fresh( )
    _listeners = { }; _requests = { }; _bulk = { }; _store = { }; _audit = { }; _reports = { }
    _registered = { }
    _bulk_ok = true; _G._sync_reject = false
end
fresh( )

_G.use = nil
_G.PROCESSED = "PROCESSED"
_G.os = { time = function( ) return _now end }
_G.math = math
_G.table = table
_G.string = string
_G.type = type
_G.pairs = pairs
_G.ipairs = ipairs
_G.tonumber = tonumber
_G.tostring = tostring
_G.dkjson = dkjson
_G.secrets = {
    lookup   = function( key ) return _secrets[ key ] end,
    register = function( key ) _registered[ key ] = true end,
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
_G.http_client = {
    -- Capture the request; a test drives on_complete / on_error. Default
    -- returns true (queued); a test can set _sync_reject to force the
    -- (false, err) synchronous-rejection branch.
    request = function( req )
        _requests[ #_requests + 1 ] = req
        if _G._sync_reject then return false, "in-flight cap" end
        return true
    end,
}
_G.blocklist = {
    bulk_replace = function( source, feed, entries, opts )
        _bulk[ #_bulk + 1 ] = { source = source, feed = feed, entries = entries, opts = opts }
        if not _bulk_ok then return false, nil, "save failed (test)" end
        _store[ feed ] = entries
        return true, { added = #entries, removed = 0, skipped = 0, capped = 0, too_broad = 0 }
    end,
    list = function( _filter )
        local rows = { }
        for feed, entries in pairs( _store ) do
            for _, e in ipairs( entries ) do
                rows[ #rows + 1 ] = { source = "external",
                    meta = { feed = feed }, cidr = ( type( e ) == "table" and e.cidr or e ) }
            end
        end
        return rows
    end,
}
_G.hub = {
    setlistener = function( ev, _opts, fn ) _listeners[ ev ] = fn end,
    debug       = function( ) end,
    getbot      = function( ) return "bot" end,
    http_register = function( ) end,
    import      = function( name )
        if name == "etc_hubcommands" then
            return { add = function( ) return true end }
        end
        if name == "etc_report" then
            return { send = function( _act, _hb, _oc, _ll, msg )
                _reports[ #_reports + 1 ] = { msg = msg }
            end }
        end
        return nil    -- no cmd_help / etc_usercommands
    end,
}

local function load_plugin( )
    fresh( )
    local p = assert( loadfile( "scripts/etc_blocklist_feeds.lua" ) )( )
    if _listeners.onStart then _listeners.onStart( ) end
    return p
end

local function last_bulk( ) return _bulk[ #_bulk ] end
local function fire_complete( status, body, headers )
    _requests[ #_requests ].on_complete{ status = status, headers = headers or { }, body = body }
end
local function fire_error( err ) _requests[ #_requests ].on_error( err ) end
local function last_audit( ) return _audit[ #_audit ] end

----------------------------------------------------------------------
-- parse_line_list
----------------------------------------------------------------------
do
    local p = load_plugin( )
    local body = "1.2.3.4\r\n" ..
                 "# a comment line\n" ..
                 "\n" ..
                 "  5.6.7.0/24  \n" ..
                 "9.9.9.9 ; SBL inline\n" ..
                 "; whole-line semicolon comment\n" ..
                 "2001:db8::/32\n"
    local out = p._parse_line_list( body )
    eq( "line: count", #out, 4 )
    eq( "line: bare v4",         out[ 1 ], "1.2.3.4" )
    eq( "line: trimmed cidr",    out[ 2 ], "5.6.7.0/24" )
    eq( "line: inline ; comment stripped", out[ 3 ], "9.9.9.9" )
    eq( "line: ipv6 untouched",  out[ 4 ], "2001:db8::/32" )

    eq( "line: empty body -> 0", #p._parse_line_list( "" ), 0 )
    eq( "line: only comments -> 0", #p._parse_line_list( "# a\n; b\n" ), 0 )
end

----------------------------------------------------------------------
-- parse_spamhaus_json (real dkjson)
----------------------------------------------------------------------
do
    local p = load_plugin( )
    local body = table.concat( {
        '{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}',
        '{"cidr":"2.56.0.0/24","sblid":"SBL999"}',
        '{"type":"metadata","timestamp":123}',       -- no .cidr -> skip
        'this is not json',                            -- decode fail -> skip
        '{"sblid":"SBL-no-cidr"}',                     -- no .cidr -> skip
    }, "\n" )
    local out = p._parse_spamhaus_json( body )
    eq( "spamhaus: count (only rows with .cidr)", #out, 2 )
    eq( "spamhaus: cidr 1", out[ 1 ].cidr, "1.10.16.0/20" )
    eq( "spamhaus: sblid -> meta", out[ 1 ].meta.sblid, "SBL256894" )
    eq( "spamhaus: cidr 2", out[ 2 ].cidr, "2.56.0.0/24" )
    eq( "spamhaus: empty body -> 0", #p._parse_spamhaus_json( "" ), 0 )
end

----------------------------------------------------------------------
-- refresh flow: onTimer -> request -> on_complete(200) -> bulk_replace
----------------------------------------------------------------------
do
    load_plugin( )   -- tor enabled, interval 3600, stealth false
    -- onStart staggered next_refresh to _now + 3; advance the clock past it
    _now = _now + 10
    _listeners.onTimer( )
    eq( "flow: one http request queued", #_requests, 1 )
    eq( "flow: request url", _requests[ 1 ].url, "https://feed.test/tor" )
    truthy( "flow: request has a response cap", _requests[ 1 ].max_response ~= nil )

    fire_complete( 200, "11.11.11.11\n22.22.22.0/24\n" )
    local b = last_bulk( )
    truthy( "flow: bulk_replace called", b ~= nil )
    eq( "flow: source external", b.source, "external" )
    eq( "flow: feed tor", b.feed, "tor" )
    eq( "flow: entries parsed", #b.entries, 2 )
    eq( "flow: first entry", b.entries[ 1 ], "11.11.11.11" )
    eq( "flow: stealth from cfg", b.opts.stealth, false )
    -- TTL = now + 2 * interval (3600) ; now was advanced to 100010
    eq( "flow: TTL backstop = now + 2*interval", b.opts.expires_at, _now + 2 * 3600 )
    eq( "flow: success audit fired", _audit[ #_audit ].action, "feed.refresh.success" )
end

----------------------------------------------------------------------
-- overlap guard: a second timer tick while in_flight does not re-request
----------------------------------------------------------------------
do
    load_plugin( )
    _now = _now + 10
    _listeners.onTimer( )                 -- fires request 1 (in_flight = true)
    eq( "overlap: first request", #_requests, 1 )
    _now = _now + 3600 + 10               -- past the next deadline
    _listeners.onTimer( )                 -- must NOT fire while in_flight
    eq( "overlap: no second request while in-flight", #_requests, 1 )
    fire_complete( 200, "1.2.3.4\n" )     -- clears in_flight
    _now = _now + 3600 + 10
    _listeners.onTimer( )                 -- now it may fire again
    eq( "overlap: fires again after completion", #_requests, 2 )
end

----------------------------------------------------------------------
-- failure paths: non-200, on_error, sync reject -> fail audit, no bulk
----------------------------------------------------------------------
do
    load_plugin( )
    _now = _now + 10
    _listeners.onTimer( )
    fire_complete( 500, "oops" )
    eq( "fail: non-200 fires refresh.fail", _audit[ #_audit ].action, "feed.refresh.fail" )
    eq( "fail: non-200 does NOT bulk_replace", #_bulk, 0 )
end

do
    load_plugin( )
    _now = _now + 10
    _listeners.onTimer( )
    fire_error( "connect timeout" )
    eq( "fail: on_error fires refresh.fail", _audit[ #_audit ].action, "feed.refresh.fail" )
    eq( "fail: on_error no bulk_replace", #_bulk, 0 )
end

do
    load_plugin( )
    _G._sync_reject = true
    _now = _now + 10
    _listeners.onTimer( )
    _G._sync_reject = false
    eq( "fail: sync-reject fires refresh.fail", _audit[ #_audit ].action, "feed.refresh.fail" )
    eq( "fail: sync-reject no bulk_replace", #_bulk, 0 )
    -- and the feed is not stuck in_flight: a later tick retries
    _now = _now + 3600 + 10
    _listeners.onTimer( )
    eq( "fail: sync-reject did not stick in_flight", #_requests, 2 )
end

----------------------------------------------------------------------
-- disabled short-circuit: master toggle off -> onTimer does nothing
----------------------------------------------------------------------
do
    _cfg.etc_blocklist_feeds_enabled = false
    load_plugin( )
    _now = _now + 100
    _listeners.onTimer( )
    eq( "disabled: no request when master toggle off", #_requests, 0 )
    _cfg.etc_blocklist_feeds_enabled = true
end

----------------------------------------------------------------------
-- interval clamp: operator value below the Tor 1800s floor is raised
----------------------------------------------------------------------
do
    _cfg.etc_blocklist_feeds_tor_refresh_interval_sec = 60   -- below the 1800 floor
    load_plugin( )
    _now = _now + 10
    _listeners.onTimer( )
    fire_complete( 200, "1.2.3.4\n" )
    -- TTL = now + 2*clamped-interval; clamped to 1800, not 60
    eq( "clamp: interval raised to floor (TTL reflects 1800)",
        last_bulk( ).opts.expires_at, _now + 2 * 1800 )
    _cfg.etc_blocklist_feeds_tor_refresh_interval_sec = 3600
end

----------------------------------------------------------------------
-- get_status snapshot shape
----------------------------------------------------------------------
do
    local p = load_plugin( )
    local st = p.get_status( )
    eq( "status: enabled", st.enabled, true )
    truthy( "status: feeds array", type( st.feeds ) == "table" )
    -- tor / spamhaus / spamhaus_v6 / abuseipdb / generic all registered
    -- (with test urls); only tor enabled -> 5 feed rows
    eq( "status: five feed rows", #st.feeds, 5 )
    local by = { }
    for _, f in ipairs( st.feeds ) do by[ f.name ] = f end
    truthy( "status: tor present", by.tor )
    eq( "status: tor enabled", by.tor.enabled, true )
    eq( "status: spamhaus disabled", by.spamhaus.enabled, false )
    eq( "status: tor interval", by.tor.interval_sec, 3600 )
    truthy( "status: abuseipdb present", by.abuseipdb )
    truthy( "status: generic present", by.generic )
end

----------------------------------------------------------------------
-- BLOCKER regression: an empty / degenerate 200 must NOT wipe the feed
----------------------------------------------------------------------
do
    load_plugin( )
    _now = _now + 10
    _listeners.onTimer( )
    fire_complete( 200, "1.2.3.4\n5.6.7.8\n" )        -- seed 2 entries
    eq( "empty-guard: seeded 2", #last_bulk( ).entries, 2 )
    local seeded = #_bulk
    _now = _now + 3600 + 10
    _listeners.onTimer( )
    fire_complete( 200, "" )                            -- empty 200 body
    eq( "empty-guard: empty 200 did NOT bulk_replace again", #_bulk, seeded )
    eq( "empty-guard: empty 200 -> refresh.fail", last_audit( ).action, "feed.refresh.fail" )
end

-- format drift: Spamhaus shipping ONE JSON array (not JSONL) -> zero
-- rows with .cidr -> empty parse -> soft failure, never a wipe
do
    _cfg.etc_blocklist_feeds_tor_enabled = false
    _cfg.etc_blocklist_feeds_spamhaus_enabled = true
    load_plugin( )
    _now = _now + 10
    _listeners.onTimer( )
    fire_complete( 200, '[{"cidr":"1.2.3.0/24"},{"cidr":"4.5.6.0/24"}]' )
    eq( "format-drift: JSON-array body -> refresh.fail", last_audit( ).action, "feed.refresh.fail" )
    eq( "format-drift: no bulk_replace (would have wiped)", #_bulk, 0 )
    _cfg.etc_blocklist_feeds_tor_enabled = true
    _cfg.etc_blocklist_feeds_spamhaus_enabled = false
end

----------------------------------------------------------------------
-- sblid coercion: untrusted feed sblid must reach meta only as a bounded
-- scalar (a nested/large value would poison the store .tbl)
----------------------------------------------------------------------
do
    local p = load_plugin( )
    local body = table.concat( {
        '{"cidr":"1.2.3.0/24","sblid":[1,2,[3,4]]}',                   -- nested -> nil
        '{"cidr":"2.3.4.0/24","sblid":12345}',                         -- number -> nil
        '{"cidr":"3.4.5.0/24","sblid":"' .. string.rep( "X", 200 ) .. '"}', -- oversize -> 64
    }, "\n" )
    local out = p._parse_spamhaus_json( body )
    eq( "sblid: 3 rows parsed", #out, 3 )
    eq( "sblid: nested table -> nil", out[ 1 ].meta.sblid, nil )
    eq( "sblid: number -> nil", out[ 2 ].meta.sblid, nil )
    eq( "sblid: oversize string truncated to 64", #out[ 3 ].meta.sblid, 64 )
    local out2 = p._parse_spamhaus_json( '{"cidr":123}\n{"cidr":"9.9.9.0/24"}' )
    eq( "sblid: non-string cidr skipped", #out2, 1 )
    eq( "sblid: valid cidr kept", out2[ 1 ].cidr, "9.9.9.0/24" )
    -- over-long cidr string skipped (bounds the parse value)
    local out3 = p._parse_spamhaus_json( '{"cidr":"' .. string.rep( "1", 200 ) .. '"}\n{"cidr":"8.8.8.0/24"}' )
    eq( "cidr: over-long cidr skipped", #out3, 1 )
    eq( "cidr: valid cidr kept", out3[ 1 ].cidr, "8.8.8.0/24" )
    -- a deeply-nested line (dkjson may THROW on stack overflow or return
    -- nil) must be skipped without crashing, and parsing must continue
    local deep = string.rep( "[", 500 ) .. string.rep( "]", 500 )
    local out4 = p._parse_spamhaus_json( deep .. '\n{"cidr":"7.7.7.0/24"}' )
    eq( "decode-throw: deep-nesting line skipped, parse continues", #out4, 1 )
    eq( "decode-throw: valid cidr after it survives", out4[ 1 ].cidr, "7.7.7.0/24" )
end

----------------------------------------------------------------------
-- Content-Length short-read guard (RAM mode has no built-in check)
----------------------------------------------------------------------
do
    load_plugin( )
    _now = _now + 10
    _listeners.onTimer( )
    fire_complete( 200, "1.2.3.4\n", { ["content-length"] = "100" } )   -- body << declared
    eq( "truncation: short body -> refresh.fail", last_audit( ).action, "feed.refresh.fail" )
    eq( "truncation: no bulk_replace", #_bulk, 0 )
end
do
    load_plugin( )
    _now = _now + 10
    _listeners.onTimer( )
    local body = "1.2.3.4\n"
    fire_complete( 200, body, { ["content-length"] = tostring( #body ) } )   -- exact
    eq( "truncation: matching content-length proceeds", last_audit( ).action, "feed.refresh.success" )
end

----------------------------------------------------------------------
-- bulk_replace store failure -> refresh.fail (last-good kept)
----------------------------------------------------------------------
do
    load_plugin( )
    _bulk_ok = false
    _now = _now + 10
    _listeners.onTimer( )
    fire_complete( 200, "1.2.3.4\n" )
    eq( "bulk-fail: store failure -> refresh.fail", last_audit( ).action, "feed.refresh.fail" )
end

----------------------------------------------------------------------
-- op-chat report debounce (success on first/recovery only; fail on ok->fail)
----------------------------------------------------------------------
do
    _cfg.etc_blocklist_feeds_report = true
    load_plugin( )
    _now = _now + 10; _listeners.onTimer( ); fire_complete( 200, "1.2.3.4\n" )
    eq( "report: first success reports", #_reports, 1 )
    _now = _now + 3600 + 10; _listeners.onTimer( ); fire_complete( 200, "1.2.3.4\n" )
    eq( "report: steady-state success does NOT report", #_reports, 1 )
    _now = _now + 3600 + 10; _listeners.onTimer( ); fire_complete( 500, "x" )
    eq( "report: ok->fail reports", #_reports, 2 )
    _now = _now + 3600 + 10; _listeners.onTimer( ); fire_complete( 500, "x" )
    eq( "report: repeated fail does NOT report", #_reports, 2 )
    _now = _now + 3600 + 10; _listeners.onTimer( ); fire_complete( 200, "1.2.3.4\n" )
    eq( "report: recovery (fail->ok) reports", #_reports, 3 )
    _cfg.etc_blocklist_feeds_report = false
end

----------------------------------------------------------------------
-- entry_count reflects actual stored rows (assert VALUES, not just shape)
----------------------------------------------------------------------
do
    local p = load_plugin( )
    _now = _now + 10; _listeners.onTimer( ); fire_complete( 200, "1.2.3.4\n2.3.4.5\n3.4.5.6\n" )
    local tor, spam
    for _, f in ipairs( p.get_status( ).feeds ) do
        if f.name == "tor" then tor = f elseif f.name == "spamhaus" then spam = f end
    end
    eq( "entry_count: tor reflects 3 fetched entries", tor.entries, 3 )
    eq( "entry_count: unpopulated spamhaus is 0", spam.entries, 0 )
end

----------------------------------------------------------------------
-- AbuseIPDB adapter: API key via secrets -> Key header; keyless disable
----------------------------------------------------------------------
do
    _cfg.etc_blocklist_feeds_tor_enabled = false
    _cfg.etc_blocklist_feeds_abuseipdb_enabled = true
    _secrets[ "etc_blocklist_feeds_abuseipdb_key" ] = "SECRET-KEY-123"
    load_plugin( )
    -- secrets.register called in onStart so GET /v1/config redacts it
    eq( "abuseipdb: key registered as secret", _registered[ "etc_blocklist_feeds_abuseipdb_key" ], true )
    _now = _now + 10
    _listeners.onTimer( )
    eq( "abuseipdb: request queued", #_requests, 1 )
    eq( "abuseipdb: url from cfg", _requests[ 1 ].url, "https://feed.test/abuseipdb" )
    truthy( "abuseipdb: Key header present", _requests[ 1 ].headers and _requests[ 1 ].headers.Key == "SECRET-KEY-123" )
    eq( "abuseipdb: Accept text/plain", _requests[ 1 ].headers.Accept, "text/plain" )
    fire_complete( 200, "203.0.113.5\n203.0.113.6\n" )
    eq( "abuseipdb: bulk_replace feed=abuseipdb", last_bulk( ).feed, "abuseipdb" )
    eq( "abuseipdb: parsed 2 IPs", #last_bulk( ).entries, 2 )
    -- interval clamped UP to the 6h (21600s) floor even though cfg said 86400 (>floor, so stays 86400)
    eq( "abuseipdb: TTL = 2 * interval", last_bulk( ).opts.expires_at, _now + 2 * 86400 )
    _secrets[ "etc_blocklist_feeds_abuseipdb_key" ] = nil
    _cfg.etc_blocklist_feeds_abuseipdb_enabled = false
    _cfg.etc_blocklist_feeds_tor_enabled = true
end

-- keyless abuseipdb: enabled but no key -> feed disabled, no request
do
    _cfg.etc_blocklist_feeds_tor_enabled = false
    _cfg.etc_blocklist_feeds_abuseipdb_enabled = true
    -- no _secrets key set
    load_plugin( )
    _now = _now + 100
    _listeners.onTimer( )
    eq( "abuseipdb keyless: no request (feed disabled)", #_requests, 0 )
    _cfg.etc_blocklist_feeds_abuseipdb_enabled = false
    _cfg.etc_blocklist_feeds_tor_enabled = true
end

-- abuseipdb interval clamp: cfg below the 6h floor is raised
do
    _cfg.etc_blocklist_feeds_tor_enabled = false
    _cfg.etc_blocklist_feeds_abuseipdb_enabled = true
    _cfg.etc_blocklist_feeds_abuseipdb_refresh_interval_sec = 3600   -- 1h, below the 6h floor
    _secrets[ "etc_blocklist_feeds_abuseipdb_key" ] = "K"
    load_plugin( )
    _now = _now + 10
    _listeners.onTimer( )
    fire_complete( 200, "1.2.3.4\n" )
    eq( "abuseipdb: interval clamped to 6h floor (TTL reflects 21600)",
        last_bulk( ).opts.expires_at, _now + 2 * 21600 )
    _cfg.etc_blocklist_feeds_abuseipdb_refresh_interval_sec = 86400
    _secrets[ "etc_blocklist_feeds_abuseipdb_key" ] = nil
    _cfg.etc_blocklist_feeds_abuseipdb_enabled = false
    _cfg.etc_blocklist_feeds_tor_enabled = true
end

----------------------------------------------------------------------
-- generic adapter: operator URL -> shared line parser -> bulk_replace
----------------------------------------------------------------------
do
    _cfg.etc_blocklist_feeds_tor_enabled = false
    _cfg.etc_blocklist_feeds_generic_enabled = true
    load_plugin( )
    _now = _now + 10
    _listeners.onTimer( )
    eq( "generic: request queued", #_requests, 1 )
    eq( "generic: no auth header", _requests[ 1 ].headers, nil )
    fire_complete( 200, "198.51.100.7\n# comment\n198.51.100.0/24\n" )
    eq( "generic: bulk_replace feed=generic", last_bulk( ).feed, "generic" )
    eq( "generic: parsed 2 (comment skipped)", #last_bulk( ).entries, 2 )
    _cfg.etc_blocklist_feeds_generic_enabled = false
    _cfg.etc_blocklist_feeds_tor_enabled = true
end

-- generic with empty url -> feed not registered at all
do
    _cfg.etc_blocklist_feeds_tor_enabled = false
    _cfg.etc_blocklist_feeds_generic_enabled = true
    _cfg.etc_blocklist_feeds_generic_url = ""
    local p = load_plugin( )
    local has_generic = false
    for _, f in ipairs( p.get_status( ).feeds ) do if f.name == "generic" then has_generic = true end end
    falsy( "generic: empty url -> feed not registered", has_generic )
    _now = _now + 100
    _listeners.onTimer( )
    eq( "generic: empty url -> no request", #_requests, 0 )
    _cfg.etc_blocklist_feeds_generic_url = "https://feed.test/generic"
    _cfg.etc_blocklist_feeds_generic_enabled = false
    _cfg.etc_blocklist_feeds_tor_enabled = true
end

----------------------------------------------------------------------

if _fail > 0 then
    io.stderr:write( string.format( "\nFAIL: %d/%d checks failed\n", _fail, _pass + _fail ) )
    os.exit( 1 )
end
print( string.format( "OK: %d checks passed", _pass ) )
