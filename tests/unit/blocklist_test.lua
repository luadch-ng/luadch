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

local function _stub_use_factory( opts )
    opts = opts or { }
    local cfg_values = opts.cfg or { }
    return function( name )
        if name == "type" then return type end
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

if _fails > 0 then
    io.stderr:write( string.format( "\nFAIL: %d/%d checks failed\n",
        _fails, _passes + _fails ) )
    os.exit( 1 )
end
print( string.format( "OK: %d checks passed", _passes ) )
