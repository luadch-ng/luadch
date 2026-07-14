--[[

    tests/unit/blocklist_test.lua

    Unit tests for core/blocklist.lua (#78 Phase A). Coverage:

      - add / remove / list / count round-trip
      - check_ip: bucket-routed match (v4 + v6) + non-match
      - decision priority: manual > geoip > external when multiple
        entries cover the same IP
      - stealth flag plumbing through to check_ip meta
      - expires_at: expired entries treated as non-matching
      - reload from stub store reconstructs cache + bucket index
      - persistence round-trip via stubbed util.savetable /
        loadtable
      - hex_encode / hex_decode round-trip (used for the .tbl
        text-safe network-bytes encoding)
      - disabled engine: check_ip always false

    Run: lua5.4 tests/unit/blocklist_test.lua

]]--

----------------------------------------------------------------------
-- Stub harness: replace util.savetable / loadtable with in-memory
-- table so tests don't touch disk. Plus a controllable clock so the
-- aggregated-log rollup + expires_at are deterministic.
----------------------------------------------------------------------

local _disk = { }    -- path -> table
local _now = 1000
local _save_count = 0    -- number of savetable calls (proves one-write batching)
local _fail_save = false  -- flip true to simulate a disk-save failure

local function _stub_use_factory( opts )
    opts = opts or { }
    local cfg_values = opts.cfg or { }
    return function( name )
        if name == "type" then return type end
        if name == "pcall" then return pcall end
        if name == "next" then return next end
        if name == "pairs" then return pairs end
        if name == "ipairs" then return ipairs end
        if name == "tostring" then return tostring end
        if name == "tonumber" then return tonumber end
        if name == "string" then return string end
        if name == "table" then return table end
        if name == "math" then return math end
        if name == "error" then return error end
        if name == "socket" then return { gettime = function() return _now end } end
        if name == "util" then
            return {
                loadtable = function( path ) return _disk[ path ] end,
                savetable = function( tbl, _name, path )
                    _save_count = _save_count + 1
                    if _fail_save then return false, "disk full (test)" end
                    -- Deep-copy so subsequent mutations don't leak.
                    local copy = { }
                    for i, row in ipairs( tbl ) do
                        local rcopy = { }
                        for k, v in pairs( row ) do rcopy[ k ] = v end
                        copy[ i ] = rcopy
                    end
                    _disk[ path ] = copy
                    return true
                end,
            }
        end
        if name == "cfg" then
            return {
                get = function( k ) return cfg_values[ k ] end,
                registerevent = function( ) end,
            }
        end
        if name == "out" then
            return { put = function( ) end, error = function( ) end }
        end
        if name == "io" then
            -- Existence probe stub: io.open(path,"r") succeeds iff the
            -- stubbed `_disk` knows the path. Matches the real-hub
            -- behaviour that on first boot the file is missing and
            -- reload() must skip the load-from-disk branch quietly.
            return {
                open = function( path, _mode )
                    if _disk[ path ] ~= nil then
                        return { close = function( ) end }
                    end
                    return nil, "No such file or directory"
                end,
            }
        end
        if name == "ipmatch" then
            return _G._loaded_ipmatch
        end
        error( "blocklist_test shim: missing dep " .. tostring( name ) )
    end
end

_G.use = _stub_use_factory( )
_G._loaded_ipmatch = assert( loadfile( "core/ipmatch.lua" ) )( )
local bl = assert( loadfile( "core/blocklist.lua" ) )( )

----------------------------------------------------------------------
-- Tiny harness
----------------------------------------------------------------------

local _passes, _fails = 0, 0
local function eq( what, got, want )
    if got == want then _passes = _passes + 1
    else
        _fails = _fails + 1
        io.stderr:write( string.format( "FAIL: %s\n  got:  %s\n  want: %s\n",
            what, tostring( got ), tostring( want ) ) )
    end
end
local function truthy( what, v )
    if v then _passes = _passes + 1
    else _fails = _fails + 1; io.stderr:write( "FAIL: " .. what .. " got=" .. tostring( v ) .. "\n" ) end
end
local function falsy( what, v )
    if not v then _passes = _passes + 1
    else _fails = _fails + 1; io.stderr:write( "FAIL: " .. what .. " got=" .. tostring( v ) .. "\n" ) end
end

local function reset_state( opts )
    _disk = { }
    _now = 1000
    _save_count = 0
    _fail_save = false
    _G.use = _stub_use_factory( opts )
    bl = assert( loadfile( "core/blocklist.lua" ) )( )
    bl.init( )
end

----------------------------------------------------------------------
-- add + check_ip basic round-trip
----------------------------------------------------------------------

reset_state{}
do
    local ok, id = bl.add( "1.2.3.0/24", { reason = "test", source = "manual" } )
    eq( "add returns ok", ok, true )
    truthy( "add returns id", id )

    local blocked, source, meta = bl.check_ip( "1.2.3.50" )
    eq( "check_ip in-range returns blocked", blocked, true )
    eq( "check_ip source", source, "manual" )
    truthy( "check_ip meta",  meta )
    eq( "check_ip meta cidr", meta and meta.cidr, "1.2.3.0/24" )

    eq( "check_ip out-of-range", bl.check_ip( "1.2.4.50" ), false )
end

----------------------------------------------------------------------
-- count + list
----------------------------------------------------------------------

do
    bl.add( "10.0.0.0/8", { source = "geoip" } )
    bl.add( "172.16.0.0/12", { source = "external" } )
    local c = bl.count( )
    eq( "count total", c.total, 3 )
    eq( "count by_source manual",   c.by_source.manual, 1 )
    eq( "count by_source geoip",    c.by_source.geoip, 1 )
    eq( "count by_source external", c.by_source.external, 1 )

    eq( "list all length", #bl.list( ), 3 )
    eq( "list filter source=geoip length", #bl.list{ source = "geoip" }, 1 )
end

----------------------------------------------------------------------
-- Priority order: manual > geoip > external when overlapping
----------------------------------------------------------------------

reset_state{}
do
    bl.add( "192.0.2.0/24", { source = "external", reason = "feed-x" } )
    bl.add( "192.0.2.42",  { source = "manual",   reason = "operator-pin" } )
    bl.add( "192.0.2.0/24", { source = "geoip",    reason = "CN" } )

    local _, source, meta = bl.check_ip( "192.0.2.42" )
    eq( "priority: manual wins overlap", source, "manual" )
    eq( "priority: meta reason from manual entry", meta and meta.reason, "operator-pin" )

    local _, source2 = bl.check_ip( "192.0.2.50" )
    eq( "priority: geoip beats external when manual /32 doesn't cover",
        source2, "geoip" )
end

----------------------------------------------------------------------
-- Stealth flag
----------------------------------------------------------------------

reset_state{}
do
    bl.add( "5.6.7.0/24", { source = "manual", stealth = true, reason = "quiet" } )
    local _, _, meta = bl.check_ip( "5.6.7.99" )
    eq( "stealth flag carried through to meta", meta and meta.stealth, true )

    bl.add( "8.9.10.0/24", { source = "manual", stealth = false } )
    local _, _, meta2 = bl.check_ip( "8.9.10.99" )
    eq( "non-stealth meta.stealth", meta2 and meta2.stealth, false )
end

----------------------------------------------------------------------
-- expires_at
----------------------------------------------------------------------

reset_state{}
do
    bl.add( "11.22.33.0/24", { source = "manual", expires_at = 500 } )
    eq( "expired (past) not matched", bl.check_ip( "11.22.33.50" ), false )

    bl.add( "44.55.66.0/24", { source = "manual", expires_at = 9999 } )
    local b, _ = bl.check_ip( "44.55.66.50" )
    eq( "expires_at in future still matches", b, true )

    -- Move clock past the second entry's expires_at.
    _now = 10000
    local b2 = bl.check_ip( "44.55.66.50" )
    eq( "match expires when now passes expires_at", b2, false )
end

----------------------------------------------------------------------
-- remove
----------------------------------------------------------------------

reset_state{}
do
    local _, id1 = bl.add( "100.0.0.0/8", { source = "manual" } )
    local _, id2 = bl.add( "101.0.0.0/8", { source = "manual" } )

    eq( "remove returns ok", bl.remove( id1 ), true )
    eq( "count after remove", bl.count( ).total, 1 )

    local ok, err = bl.remove( 99999 )
    eq( "remove not_found returns false", ok, false )
    eq( "remove not_found err", err, "not_found" )

    eq( "remaining entry still matched", bl.check_ip( "101.99.99.99" ), true )
    eq( "removed entry no longer matched", bl.check_ip( "100.99.99.99" ), false )
end

----------------------------------------------------------------------
-- IPv6 routing
----------------------------------------------------------------------

reset_state{}
do
    bl.add( "2001:db8::/32", { source = "external" } )
    eq( "v6 in /32",  bl.check_ip( "2001:db8::42" ), true )
    eq( "v6 out /32", bl.check_ip( "2001:db9::42" ), false )

    bl.add( "::1", { source = "manual" } )
    eq( "v6 /128 single IP match", bl.check_ip( "::1" ), true )
    eq( "v6 /128 non-match",       bl.check_ip( "::2" ), false )
end

----------------------------------------------------------------------
-- v4-mapped v6 lookup. Hubs listening on IPv6 (or dual-stack via
-- `::`) receive incoming v4 clients as v4-mapped v6 addresses
-- (`::ffff:37.46.199.70`, RFC 4291 §2.5.5.2). Without the
-- normalisation in _resolve_decision, a plain-v4 blocklist entry
-- for that same IP would never match because the address bytes
-- go through the v6 bucket (16 bytes) while the entry lives in
-- the v4 bucket (4 bytes). This regression demonstrably FAILS
-- on the unpatched code.
----------------------------------------------------------------------

reset_state{}
do
    bl.add( "37.46.199.70/32", { source = "manual" } )
    eq( "v4-mapped v6 /full matches v4 entry",
        bl.check_ip( "::ffff:37.46.199.70" ), true )

    bl.add( "10.0.0.0/8", { source = "manual" } )
    eq( "v4-mapped v6 in v4 /8 range",
        bl.check_ip( "::ffff:10.20.30.40" ), true )
    eq( "v4-mapped v6 outside v4 /8 range",
        bl.check_ip( "::ffff:11.20.30.40" ), false )

    -- Explicit ::ffff:.../128 v6 entries still work for operators
    -- who deliberately target the mapped form only. This confirms
    -- the mapped-normalisation doesn't accidentally break the
    -- narrower-scope semantic.
    reset_state{}
    bl.add( "::ffff:1.2.3.4/128", { source = "manual" } )
    -- Note: after the normalisation, `::ffff:1.2.3.4` looks up as
    -- v4 1.2.3.4 which is NOT in _buckets_v4. So an operator who
    -- wrote the entry in v6-mapped form and expects it to match
    -- the same v6-mapped incoming address needs to write the v4
    -- form instead. Documented tradeoff; the far more common case
    -- (operator writes plain v4, dual-stack hub receives mapped
    -- v6) is the one the fix enables.
    eq( "explicit ::ffff:1.2.3.4/128 does NOT catch mapped incoming (docs)",
        bl.check_ip( "::ffff:1.2.3.4" ), false )
    -- Same operator can still catch pure v4 incoming; the entry
    -- was normalised to v6 at add() and only sits in _buckets_v6.
    eq( "explicit ::ffff:1.2.3.4/128 non-match for pure v4",
        bl.check_ip( "1.2.3.4" ), false )
end

----------------------------------------------------------------------
-- Reload from stub disk: persistence + cache rebuild
----------------------------------------------------------------------

reset_state{}
do
    bl.add( "55.66.77.0/24", { source = "manual", reason = "for reload test" } )
    bl.add( "2001:db8::/32", { source = "geoip" } )

    -- Build a fresh module + reload from disk.
    _G.use = _stub_use_factory( )
    local bl2 = assert( loadfile( "core/blocklist.lua" ) )( )
    bl2.init( )

    eq( "post-reload count", bl2.count( ).total, 2 )
    eq( "post-reload v4 match", bl2.check_ip( "55.66.77.99" ), true )
    eq( "post-reload v6 match", bl2.check_ip( "2001:db8::1" ), true )
    eq( "post-reload non-match", bl2.check_ip( "1.2.3.4" ), false )
end

----------------------------------------------------------------------
-- Fresh-install: reload() with no .tbl on disk is silent + clean
-- (regression for the "util.lua: function 'checkfile': error in
-- cfg/blocklist.tbl: No such file or directory" testhub finding).
-- The io-stub returns nil for any path the _disk has never seen, so
-- this exercises the same branch as a literal first-boot.
----------------------------------------------------------------------

reset_state{}
do
    local err_count = 0
    -- Override the out stub so we can count error invocations during
    -- this reload-from-empty scenario.
    _G.use = function( name )
        if name == "out" then
            return {
                put   = function( ) end,
                error = function( ) err_count = err_count + 1 end,
            }
        end
        return _stub_use_factory( )( name )
    end
    local bl_fresh = assert( loadfile( "core/blocklist.lua" ) )( )
    bl_fresh.init( )
    eq( "fresh-install reload emits no out.error",  err_count, 0 )
    eq( "fresh-install reload leaves zero entries", bl_fresh.count( ).total, 0 )
    -- Restore the standard stub for subsequent tests.
    _G.use = _stub_use_factory( )
end

----------------------------------------------------------------------
-- Engine disabled: check_ip false even with entries present
----------------------------------------------------------------------

reset_state{ cfg = { blocklist_enabled = false } }
do
    bl.add( "1.2.3.0/24", { source = "manual" } )
    eq( "disabled engine returns false", bl.check_ip( "1.2.3.50" ), false )
end

----------------------------------------------------------------------
-- hex_encode / hex_decode round-trip
----------------------------------------------------------------------

reset_state{}
do
    local samples = { "\1\2\3\4", "\xff\x00\xab\xcd", string.rep( "\0", 16 ),
                      "\1\2\3\4\5\6\7\8\9\10\11\12\13\14\15\16" }
    for _, s in ipairs( samples ) do
        eq( "hex round-trip (len " .. #s .. ")", bl._hex_decode( bl._hex_encode( s ) ), s )
    end
    eq( "hex_decode odd length nil", bl._hex_decode( "abc" ), nil )
    eq( "hex_decode bad chars nil",  bl._hex_decode( "zz" ), nil )
end

----------------------------------------------------------------------
-- Priority table integrity
----------------------------------------------------------------------

eq( "_priority manual",     bl._priority( "manual" ),     100 )
eq( "_priority geoip",      bl._priority( "geoip" ),      50 )
eq( "_priority proxycheck", bl._priority( "proxycheck" ), 40 )
eq( "_priority external",   bl._priority( "external" ),   20 )
eq( "_priority unknown",    bl._priority( "rando-source" ), 0 )
eq( "_priority nil",        bl._priority( nil ),          0 )

----------------------------------------------------------------------
-- _resolve_decision direct (NIT 1 from review)
----------------------------------------------------------------------

reset_state{}
do
    bl.add( "1.2.3.0/24", { source = "external", reason = "feed" } )
    bl.add( "1.2.3.42",   { source = "manual",   reason = "pin" } )

    -- Direct decision: returns the winning entry table, not the
    -- public check_ip tuple. Validates priority resolution at the
    -- internal level (no aggregated-log side effects).
    local d = bl._resolve_decision( "1.2.3.42" )
    truthy( "_resolve_decision returns entry", d )
    eq( "_resolve_decision picks manual",   d and d.source, "manual" )
    eq( "_resolve_decision picks reason",   d and d.reason, "pin" )

    -- Non-match path
    eq( "_resolve_decision out-of-range nil", bl._resolve_decision( "9.9.9.9" ), nil )
    eq( "_resolve_decision bad input nil",    bl._resolve_decision( "garbage" ), nil )
    eq( "_resolve_decision nil input nil",    bl._resolve_decision( nil ),       nil )
end

----------------------------------------------------------------------
-- Returned meta is a shallow copy (NIT 2 from review)
----------------------------------------------------------------------

reset_state{}
do
    bl.add( "8.8.8.0/24", { source = "manual", meta = { country = "US" } } )

    local _, _, r1 = bl.check_ip( "8.8.8.8" )
    truthy( "check_ip returned meta copy", r1 and r1.meta )
    -- Mutate the returned meta - must NOT affect later check_ip calls.
    if r1 and r1.meta then r1.meta.country = "TAMPERED" end

    local _, _, r2 = bl.check_ip( "8.8.8.8" )
    eq( "second check_ip meta unaffected by caller mutation",
        r2 and r2.meta and r2.meta.country, "US" )

    -- Same shape via list():
    local rows = bl.list( )
    if rows[ 1 ] and rows[ 1 ].meta then rows[ 1 ].meta.country = "ALSO_TAMPERED" end
    local rows2 = bl.list( )
    eq( "second list() meta unaffected by caller mutation",
        rows2[ 1 ] and rows2[ 1 ].meta and rows2[ 1 ].meta.country, "US" )
end

----------------------------------------------------------------------
-- Unknown filter_spec key logs a warning (NIT 3 from review)
----------------------------------------------------------------------

reset_state{}
do
    -- Track out.put calls via a stub. Need to reset_state with a
    -- captured-out shim.
    local captured = { }
    _G.use = function( name )
        if name == "out" then
            return {
                put = function( ... ) captured[ #captured + 1 ] = table.concat({...}, "") end,
                error = function( ) end,
            }
        end
        return _stub_use_factory( )( name )
    end
    bl = assert( loadfile( "core/blocklist.lua" ) )( )
    bl.init( )
    bl.add( "1.2.3.0/24", { source = "manual" } )
    captured = { }    -- discard add-time logs

    bl.list( { source = "manual", unknown_key = "x", another_unknown = true } )

    local saw_warning = false
    for _, line in ipairs( captured ) do
        if line:find( "unknown filter key" ) then saw_warning = true; break end
    end
    truthy( "unknown filter key triggers warning", saw_warning )
end

----------------------------------------------------------------------
-- bulk_replace (Phase E feed ingest): atomic O(N) feed-set replacement
-- in ONE disk write. The per-CIDR add() rewrites the whole store each
-- call (O(N^2)); a feed with thousands of CIDRs must not do that.
----------------------------------------------------------------------

-- count entries belonging to a (source, feed) pair (list() has no meta filter)
local function feed_count( source, feed )
    local n = 0
    for _, r in ipairs( bl.list{ source = source } ) do
        if r.meta and r.meta.feed == feed then n = n + 1 end
    end
    return n
end

reset_state{}
do
    _save_count = 0
    local ok, stats = bl.bulk_replace( "external", "tor", {
        "1.1.1.1", "2.2.2.0/24", "3.3.3.3", "4.4.0.0/16", "5.5.5.5",
    } )
    eq( "bulk_replace ok", ok, true )
    eq( "bulk_replace ONE disk write for 5 entries", _save_count, 1 )
    eq( "bulk_replace added 5", stats.added, 5 )
    eq( "bulk_replace removed 0 (none pre-existing)", stats.removed, 0 )
    eq( "bulk_replace total 5", bl.count( ).total, 5 )
    eq( "bulk_replace feed-tagged 5", feed_count( "external", "tor" ), 5 )

    local b, src, r = bl.check_ip( "2.2.2.42" )
    eq( "bulk entry blocks (bucket cache correct)", b, true )
    eq( "bulk entry source", src, "external" )
    eq( "bulk entry meta.feed", r.meta and r.meta.feed, "tor" )
end

do
    -- refresh: old rows dropped, new rows in, still exactly one write
    _save_count = 0
    local ok, stats = bl.bulk_replace( "external", "tor", { "3.3.3.3", "9.9.9.0/24" } )
    eq( "refresh ok", ok, true )
    eq( "refresh ONE write", _save_count, 1 )
    eq( "refresh removed old 5", stats.removed, 5 )
    eq( "refresh added 2", stats.added, 2 )
    eq( "refresh feed now 2", feed_count( "external", "tor" ), 2 )
    eq( "dropped feed IP no longer blocks", bl.check_ip( "2.2.2.42" ), false )
    eq( "new feed IP blocks", bl.check_ip( "9.9.9.1" ), true )
    eq( "kept-across-refresh IP still blocks", bl.check_ip( "3.3.3.3" ), true )
end

reset_state{}
do
    -- other feeds + manual pins untouched by a feed replace
    bl.add( "100.100.100.100", { source = "manual", reason = "pin" } )
    bl.bulk_replace( "external", "spamhaus", { "50.50.0.0/16" } )
    bl.bulk_replace( "external", "tor", { "60.60.60.60" } )
    bl.bulk_replace( "external", "tor", { "61.61.61.61" } )   -- replace tor again
    eq( "manual pin survives feed churn", bl.check_ip( "100.100.100.100" ), true )
    eq( "other feed (spamhaus) survives", bl.check_ip( "50.50.1.2" ), true )
    eq( "old tor entry replaced", bl.check_ip( "60.60.60.60" ), false )
    eq( "new tor entry present", bl.check_ip( "61.61.61.61" ), true )
    eq( "spamhaus feed count", feed_count( "external", "spamhaus" ), 1 )
    eq( "tor feed count", feed_count( "external", "tor" ), 1 )
end

reset_state{}
do
    -- dedup within the input + malformed skip
    local ok, stats = bl.bulk_replace( "external", "generic", {
        "1.2.3.4", "1.2.3.4/32", "1.2.3.4",   -- same canonical form -> 1 kept, 2 skipped
        "not-a-cidr",                          -- malformed -> skipped
        "5.6.7.0/24",                          -- valid distinct
    } )
    eq( "dedup+malformed ok", ok, true )
    eq( "dedup+malformed added 2", stats.added, 2 )
    eq( "dedup+malformed skipped 3", stats.skipped, 3 )
    eq( "dedup+malformed feed count 2", feed_count( "external", "generic" ), 2 )
end

reset_state{}
do
    -- cap enforced; overflow counted (non-silent)
    local items = { }
    for i = 1, 5 do items[ i ] = "10.0." .. i .. ".0/24" end
    local ok, stats = bl.bulk_replace( "external", "big", items, { max = 3 } )
    eq( "cap ok", ok, true )
    eq( "cap added == max 3", stats.added, 3 )
    eq( "cap capped == overflow 2", stats.capped, 2 )
    eq( "cap feed count 3", feed_count( "external", "big" ), 3 )
end

reset_state{}
do
    -- per-item metadata preserved; feed key is authoritative (not spoofable)
    bl.bulk_replace( "external", "spamhaus", {
        { cidr = "77.88.99.0/24", meta = { sblid = "SBL123", feed = "SPOOF" } },
    } )
    local _, _, r = bl.check_ip( "77.88.99.5" )
    eq( "per-item meta preserved (sblid)", r.meta and r.meta.sblid, "SBL123" )
    eq( "feed key authoritative", r.meta and r.meta.feed, "spamhaus" )
end

reset_state{}
do
    -- feed-wide expires_at via opts + expired-sweep on a later bulk_replace
    bl.bulk_replace( "external", "ttl", { "120.0.0.0/8" }, { expires_at = 2000 } )
    eq( "ttl entry blocks before expiry", bl.check_ip( "120.1.2.3" ), true )
    _now = 3000
    eq( "ttl entry filtered after expiry", bl.check_ip( "120.1.2.3" ), false )
    bl.bulk_replace( "external", "other", { "130.0.0.0/8" } )
    eq( "expired row swept by later bulk_replace", feed_count( "external", "ttl" ), 0 )
end

reset_state{}
do
    -- save-failure rollback: no partial write, previous feed intact
    bl.bulk_replace( "external", "tor", { "200.0.0.0/8", "201.0.0.0/8" } )
    eq( "pre-rollback tor blocks", bl.check_ip( "200.1.2.3" ), true )
    _fail_save = true
    local ok, _, err = bl.bulk_replace( "external", "tor", { "222.0.0.0/8" } )
    _fail_save = false
    eq( "save-fail returns false", ok, false )
    truthy( "save-fail err names save", err and err:find( "save failed" ) )
    eq( "rollback: old feed IP still blocks", bl.check_ip( "200.1.2.3" ), true )
    eq( "rollback: 2nd old feed IP still blocks", bl.check_ip( "201.1.2.3" ), true )
    eq( "rollback: attempted-new IP does NOT block", bl.check_ip( "222.1.2.3" ), false )
    eq( "rollback: feed count unchanged (2)", feed_count( "external", "tor" ), 2 )
end

reset_state{}
do
    -- input validation + empty-list clears the feed
    local ok1, _, e1 = bl.bulk_replace( "", "tor", { } )
    eq( "empty source rejected", ok1, false )
    truthy( "empty source err", e1 and e1:find( "source" ) )
    local ok2, _, e2 = bl.bulk_replace( "external", "", { } )
    eq( "empty feed rejected", ok2, false )
    truthy( "empty feed err", e2 and e2:find( "feed" ) )
    local ok3, _, e3 = bl.bulk_replace( "external", "tor", "not-a-table" )
    eq( "non-table entries rejected", ok3, false )
    truthy( "non-table entries err", e3 and e3:find( "entries" ) )

    bl.bulk_replace( "external", "tor", { "9.8.7.0/24" } )
    eq( "feed present before clear", bl.check_ip( "9.8.7.1" ), true )
    local okc, statsc = bl.bulk_replace( "external", "tor", { } )
    eq( "empty-list replace ok", okc, true )
    eq( "empty-list removed the row", statsc.removed, 1 )
    eq( "empty-list cleared the feed", bl.check_ip( "9.8.7.1" ), false )
end

reset_state{}
do
    -- persistence: a bulk-added feed survives a reload from disk
    bl.bulk_replace( "external", "tor", { "150.0.0.0/8", "151.0.0.0/8" } )
    local bl2 = assert( loadfile( "core/blocklist.lua" ) )( )
    bl2.init( )
    eq( "post-reload feed total", bl2.count( ).total, 2 )
    eq( "post-reload feed IP blocks", bl2.check_ip( "150.1.2.3" ), true )
    local _, _, r = bl2.check_ip( "150.1.2.3" )
    eq( "post-reload meta.feed survives", r.meta and r.meta.feed, "tor" )
end

reset_state{}
do
    -- per-item stealth override, incl. an explicit false against a
    -- stealthy feed default (the `a and b or c` idiom would drop it)
    bl.bulk_replace( "external", "s", {
        { cidr = "70.0.0.0/8", stealth = false },   -- explicit false must win
        { cidr = "71.0.0.0/8" },                     -- inherits opts.stealth = true
    }, { stealth = true } )
    local _, _, r1 = bl.check_ip( "70.1.2.3" )
    eq( "per-item stealth=false honored (not overridden by opts)", r1.stealth, false )
    local _, _, r2 = bl.check_ip( "71.1.2.3" )
    eq( "item inherits opts.stealth=true", r2.stealth, true )
end

reset_state{}
do
    -- kept entries (manual pin + other feed) stay consistent through a
    -- rolled-back bulk_replace: _rebuild_indices reassigns their _buckets
    -- then the rollback restores the old bucket tables. A later match AND
    -- a later remove() on a kept row must still work (bucket index intact).
    bl.add( "88.88.88.88", { source = "manual", reason = "pin" } )
    bl.bulk_replace( "external", "spamhaus", { "89.0.0.0/8" } )
    bl.bulk_replace( "external", "tor", { "90.0.0.0/8" } )
    _fail_save = true
    local ok = bl.bulk_replace( "external", "tor", { "91.0.0.0/8" } )
    _fail_save = false
    eq( "rollback-with-kept returns false", ok, false )
    eq( "kept manual pin still blocks after rollback", bl.check_ip( "88.88.88.88" ), true )
    eq( "kept other-feed still blocks after rollback", bl.check_ip( "89.1.2.3" ), true )
    eq( "old tor still blocks (new not committed)", bl.check_ip( "90.1.2.3" ), true )
    eq( "attempted-new tor does NOT block", bl.check_ip( "91.1.2.3" ), false )
    local rows = bl.list{ source = "manual" }
    local pin_id = rows[ 1 ] and rows[ 1 ].id
    eq( "kept entry removable after rollback (bucket index intact)", bl.remove( pin_id ), true )
    eq( "manual pin gone after remove", bl.check_ip( "88.88.88.88" ), false )
end

reset_state{}
do
    -- over-broad prefixes rejected (bucket-cache-bomb guard). At/above
    -- the floor (/8 v4, /16 v6) each entry is one bucket; below it a
    -- single entry could enumerate tens of thousands of buckets.
    local ok, stats = bl.bulk_replace( "external", "mix", {
        "2001:db8::/32",     -- v6 /32  -> OK
        "8000::/1",          -- v6 /1   -> too broad
        "10.0.0.0/8",        -- v4 /8   -> OK (at floor)
        "128.0.0.0/1",       -- v4 /1   -> too broad
        "5.5.5.5",           -- v4 /32  -> OK
    } )
    eq( "over-broad ok", ok, true )
    eq( "over-broad added 3", stats.added, 3 )
    eq( "over-broad too_broad 2", stats.too_broad, 2 )
    eq( "v6 /32 accepted blocks", bl.check_ip( "2001:db8::5" ), true )
    eq( "v6 /1 rejected does NOT block", bl.check_ip( "8000::5" ), false )
    eq( "v4 /8 at floor blocks", bl.check_ip( "10.1.2.3" ), true )
    eq( "v4 /1 rejected does NOT block", bl.check_ip( "128.1.2.3" ), false )
end

reset_state{}
do
    -- a non-empty input that parses to ZERO valid rows must NOT wipe the
    -- last-good feed (broken parser guard) and must not touch disk
    bl.bulk_replace( "external", "tor", { "140.0.0.0/8" } )
    eq( "good feed present", bl.check_ip( "140.1.2.3" ), true )
    _save_count = 0
    local ok, _, err = bl.bulk_replace( "external", "tor", { "garbage", "also-bad", "" } )
    eq( "all-invalid refused", ok, false )
    truthy( "all-invalid err mentions zero valid", err and err:find( "0 valid" ) )
    eq( "all-invalid did NOT write to disk", _save_count, 0 )
    eq( "good feed intact after refused refresh", bl.check_ip( "140.1.2.3" ), true )
end

----------------------------------------------------------------------

if _fails > 0 then
    io.stderr:write( string.format( "\nFAIL: %d/%d checks failed\n",
        _fails, _passes + _fails ) )
    os.exit( 1 )
end
print( string.format( "OK: %d checks passed", _passes ) )
