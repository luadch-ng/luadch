--[[

    tests/unit/whitelist_test.lua

    Unit tests for core/whitelist.lua (#78 allowlist). Coverage:

      - add / remove / list / count round-trip
      - is_whitelisted: bucket-routed match (v4 + v6) + non-match
      - NO priority: any active match = allowed (source is a label)
      - CIDR + exact IP; IPv6 /32 /64 /128
      - v4-mapped v6 lookup (a plain-v4 entry matches a v4-over-v6
        client - the dual-stack pinger case)
      - expires_at: expired entries treated as non-matching
      - reload from stub store rebuilds cache + bucket index
      - fresh-install: reload with no .tbl is silent + clean
      - disabled engine: is_whitelisted always false
      - hex round-trip
      - empty-store fast path
      - INTEGRATION with core/blocklist.lua: Model-A precedence -
        a whitelisted IP overrides an AUTOMATED block but NOT a
        manual pin. This block provably FAILS against a blocklist
        without the whitelist hook (§1a.7).

    Run: lua5.4 tests/unit/whitelist_test.lua

]]--

local _disk = { }    -- path -> table
local _now = 1000
local _save_count = 0
local _fail_save = false

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
        if name == "socket" then return { gettime = function() return _now end } end
        if name == "util" then
            return {
                loadtable = function( path ) return _disk[ path ] end,
                savetable = function( tbl, _name, path )
                    _save_count = _save_count + 1
                    if _fail_save then return false, "disk full (test)" end
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
        error( "whitelist_test shim: missing dep " .. tostring( name ) )
    end
end

_G.use = _stub_use_factory( )
_G._loaded_ipmatch = assert( loadfile( "core/ipmatch.lua" ) )( )
local wl = assert( loadfile( "core/whitelist.lua" ) )( )

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

local function reset_state( opts )
    _disk = { }
    _now = 1000
    _save_count = 0
    _fail_save = false
    _G.use = _stub_use_factory( opts )
    wl = assert( loadfile( "core/whitelist.lua" ) )( )
    wl.init( )
end

----------------------------------------------------------------------
-- add + is_whitelisted basic round-trip
----------------------------------------------------------------------

reset_state{}
do
    local ok, id = wl.add( "1.2.3.0/24", { reason = "test", source = "manual" } )
    eq( "add returns ok", ok, true )
    truthy( "add returns id", id )

    eq( "is_whitelisted in-range true",  wl.is_whitelisted( "1.2.3.50" ), true )
    eq( "is_whitelisted out-of-range false", wl.is_whitelisted( "1.2.4.50" ), false )

    local ok2, id2 = wl.add( "9.9.9.9", { source = "manual" } )    -- bare IP -> /32
    truthy( "add bare IP ok", ok2 and id2 )
    eq( "is_whitelisted exact /32", wl.is_whitelisted( "9.9.9.9" ), true )
    eq( "is_whitelisted /32 neighbour false", wl.is_whitelisted( "9.9.9.10" ), false )
end

----------------------------------------------------------------------
-- count + list + source filter
----------------------------------------------------------------------

do
    wl.add( "10.0.0.0/8", { source = "pinger" } )
    wl.add( "172.16.0.0/12", { source = "pinger" } )
    local c = wl.count( )
    eq( "count total", c.total, 4 )
    eq( "count by_source manual", c.by_source.manual, 2 )
    eq( "count by_source pinger", c.by_source.pinger, 2 )

    eq( "list all length", #wl.list( ), 4 )
    eq( "list filter source=pinger length", #wl.list{ source = "pinger" }, 2 )
end

----------------------------------------------------------------------
-- NO priority: overlapping entries both count as a match; either
-- source label being present is enough to allow.
----------------------------------------------------------------------

reset_state{}
do
    wl.add( "192.0.2.0/24", { source = "pinger", reason = "range" } )
    wl.add( "192.0.2.42",   { source = "manual", reason = "pin" } )
    eq( "overlap: covered IP allowed", wl.is_whitelisted( "192.0.2.42" ), true )
    eq( "overlap: other in-range IP allowed", wl.is_whitelisted( "192.0.2.99" ), true )
    -- Remove the /32; the /24 still covers .42 (no priority, just any match)
    local rows = wl.list{ source = "manual" }
    wl.remove( rows[ 1 ].id )
    eq( "after removing /32, /24 still covers", wl.is_whitelisted( "192.0.2.42" ), true )
end

----------------------------------------------------------------------
-- IPv6 /32 /64 /128 (the pinger v6 ranges)
----------------------------------------------------------------------

reset_state{}
do
    wl.add( "2001:41d0:a:f8b3::/64", { source = "pinger" } )   -- DCpinger range
    eq( "v6 /64 covers rotating host",   wl.is_whitelisted( "2001:41d0:a:f8b3::1" ), true )
    eq( "v6 /64 covers other host",      wl.is_whitelisted( "2001:41d0:a:f8b3::dead" ), true )
    eq( "v6 /64 outside range false",    wl.is_whitelisted( "2001:41d0:a:f8b4::1" ), false )

    wl.add( "2001:db8::/32", { source = "manual" } )
    eq( "v6 /32 in range",  wl.is_whitelisted( "2001:db8:1234::5" ), true )
    eq( "v6 /32 out range", wl.is_whitelisted( "2001:db9::5" ), false )

    wl.add( "2602:fed2:731b:25::a", { source = "pinger" } )     -- exact /128
    eq( "v6 /128 exact match", wl.is_whitelisted( "2602:fed2:731b:25::a" ), true )
    eq( "v6 /128 neighbour false", wl.is_whitelisted( "2602:fed2:731b:25::b" ), false )
end

----------------------------------------------------------------------
-- v4-mapped v6: a plain-v4 whitelist entry must match a v4-over-v6
-- client (the dual-stack pinger case, e.g. 142.54.190.133 arriving as
-- ::ffff:142.54.190.133). Provably FAILS without the normalisation.
----------------------------------------------------------------------

reset_state{}
do
    wl.add( "142.54.190.133", { source = "pinger" } )
    eq( "v4-mapped v6 matches plain-v4 entry",
        wl.is_whitelisted( "::ffff:142.54.190.133" ), true )

    wl.add( "5.252.102.0/24", { source = "pinger" } )
    eq( "v4-mapped v6 in v4 /24 range",
        wl.is_whitelisted( "::ffff:5.252.102.106" ), true )
    eq( "v4-mapped v6 outside v4 /24 range",
        wl.is_whitelisted( "::ffff:5.252.103.1" ), false )
end

----------------------------------------------------------------------
-- expires_at
----------------------------------------------------------------------

reset_state{}
do
    wl.add( "11.22.33.0/24", { source = "manual", expires_at = 500 } )    -- already past
    eq( "expired (past) not whitelisted", wl.is_whitelisted( "11.22.33.50" ), false )

    wl.add( "44.55.66.0/24", { source = "manual", expires_at = 9999 } )
    eq( "future expiry still whitelisted", wl.is_whitelisted( "44.55.66.50" ), true )
    _now = 10000
    eq( "expires when now passes expires_at", wl.is_whitelisted( "44.55.66.50" ), false )
end

----------------------------------------------------------------------
-- remove
----------------------------------------------------------------------

reset_state{}
do
    local _, id1 = wl.add( "100.0.0.0/8", { source = "manual" } )
    wl.add( "101.0.0.0/8", { source = "manual" } )
    eq( "remove ok", wl.remove( id1 ), true )
    eq( "count after remove", wl.count( ).total, 1 )
    local ok, err = wl.remove( 99999 )
    eq( "remove not_found false", ok, false )
    eq( "remove not_found err", err, "not_found" )
    eq( "removed no longer whitelisted", wl.is_whitelisted( "100.9.9.9" ), false )
    eq( "remaining still whitelisted", wl.is_whitelisted( "101.9.9.9" ), true )
end

----------------------------------------------------------------------
-- reload from stub disk: persistence + cache rebuild
----------------------------------------------------------------------

reset_state{}
do
    wl.add( "55.66.77.0/24", { source = "pinger", reason = "reload test" } )
    wl.add( "2001:db8::/32", { source = "manual" } )

    _G.use = _stub_use_factory( )
    local wl2 = assert( loadfile( "core/whitelist.lua" ) )( )
    wl2.init( )
    eq( "post-reload count", wl2.count( ).total, 2 )
    eq( "post-reload v4 match", wl2.is_whitelisted( "55.66.77.99" ), true )
    eq( "post-reload v6 match", wl2.is_whitelisted( "2001:db8::1" ), true )
    eq( "post-reload non-match", wl2.is_whitelisted( "1.2.3.4" ), false )
    eq( "post-reload source label survives", wl2.list{ source = "pinger" }[ 1 ].reason, "reload test" )
end

----------------------------------------------------------------------
-- fresh-install: reload() with no .tbl is silent + clean
----------------------------------------------------------------------

reset_state{}
do
    local err_count = 0
    _G.use = function( name )
        if name == "out" then
            return { put = function( ) end, error = function( ) err_count = err_count + 1 end }
        end
        return _stub_use_factory( )( name )
    end
    local wl_fresh = assert( loadfile( "core/whitelist.lua" ) )( )
    wl_fresh.init( )
    eq( "fresh-install reload emits no out.error", err_count, 0 )
    eq( "fresh-install reload zero entries", wl_fresh.count( ).total, 0 )
    _G.use = _stub_use_factory( )
end

----------------------------------------------------------------------
-- Engine disabled: is_whitelisted false even with entries present
----------------------------------------------------------------------

reset_state{ cfg = { whitelist_enabled = false } }
do
    wl.add( "1.2.3.0/24", { source = "manual" } )
    eq( "disabled engine is_whitelisted false", wl.is_whitelisted( "1.2.3.50" ), false )
end

----------------------------------------------------------------------
-- Empty-store fast path + nil/garbage input
----------------------------------------------------------------------

reset_state{}
do
    eq( "empty store is_whitelisted false", wl.is_whitelisted( "1.2.3.4" ), false )
    eq( "nil input false", wl.is_whitelisted( nil ), false )
    wl.add( "1.2.3.0/24", { source = "manual" } )
    eq( "garbage input false", wl.is_whitelisted( "not-an-ip" ), false )
    eq( "empty string input false", wl.is_whitelisted( "" ), false )
end

----------------------------------------------------------------------
-- _resolve_match direct + hex round-trip
----------------------------------------------------------------------

reset_state{}
do
    wl.add( "8.8.8.0/24", { source = "manual", reason = "dns" } )
    local m = wl._resolve_match( "8.8.8.8" )
    truthy( "_resolve_match returns entry", m )
    eq( "_resolve_match entry source", m and m.source, "manual" )
    eq( "_resolve_match out-of-range nil", wl._resolve_match( "9.9.9.9" ), nil )
    eq( "_resolve_match garbage nil", wl._resolve_match( "garbage" ), nil )
    eq( "_resolve_match nil nil", wl._resolve_match( nil ), nil )

    local samples = { "\1\2\3\4", "\xff\x00\xab\xcd", string.rep( "\0", 16 ) }
    for _, s in ipairs( samples ) do
        eq( "hex round-trip (len " .. #s .. ")", wl._hex_decode( wl._hex_encode( s ) ), s )
    end
    eq( "hex_decode odd length nil", wl._hex_decode( "abc" ), nil )
end

----------------------------------------------------------------------
-- INTEGRATION: whitelist <-> blocklist Model-A precedence.
--
-- Load BOTH engines with a shared use-stub where blocklist's
-- `use "whitelist"` resolves to the live whitelist module. Separate
-- store paths (blocklist default / whitelist default). This exercises
-- the check_ip hook: whitelist overrides an AUTOMATED block, a manual
-- pin still wins. The "automated block + whitelisted -> allowed" case
-- FAILS on a blocklist without the hook (§1a.7).
----------------------------------------------------------------------

do
    _disk = { }
    _now = 1000
    _save_count = 0
    _fail_save = false

    local BL_PATH = "scripts/data/etc_blocklist.tbl"
    local WL_PATH = "scripts/data/etc_whitelist.tbl"
    local wl_mod, bl_mod

    local function int_use( name )
        if name == "whitelist" then return wl_mod end
        -- everything else via the standard stub
        return _stub_use_factory( )( name )
    end

    _G.use = int_use
    wl_mod = assert( loadfile( "core/whitelist.lua" ) )( )
    bl_mod = assert( loadfile( "core/blocklist.lua" ) )( )
    wl_mod.init( )
    bl_mod.init( )    -- captures wl_mod.is_whitelisted via `use "whitelist"`

    -- 1. AUTOMATED block (external feed) on an IP; NOT whitelisted -> blocked.
    bl_mod.add( "203.0.113.10", { source = "external", reason = "tor" } )
    eq( "automated block, not whitelisted -> blocked",
        bl_mod.check_ip( "203.0.113.10" ), true )

    -- 2. Whitelist that same IP -> the automated block is overridden.
    --    THIS is the assertion that fails on the unpatched blocklist.
    wl_mod.add( "203.0.113.10", { source = "manual", reason = "trusted" } )
    eq( "automated block + whitelisted -> ALLOWED (hook)",
        bl_mod.check_ip( "203.0.113.10" ), false )

    -- 3. A MANUAL pin on a whitelisted IP still wins (deliberate block).
    bl_mod.add( "203.0.113.20", { source = "manual", reason = "operator ban" } )
    wl_mod.add( "203.0.113.20", { source = "manual", reason = "also trusted" } )
    eq( "manual pin + whitelisted -> STILL blocked (manual wins)",
        bl_mod.check_ip( "203.0.113.20" ), true )

    -- 4. Whitelisted range covering an automated /24 feed entry.
    bl_mod.add( "198.51.100.0/24", { source = "geoip", reason = "CN" } )
    eq( "automated /24, mid-range not whitelisted -> blocked",
        bl_mod.check_ip( "198.51.100.5" ), true )
    wl_mod.add( "198.51.100.0/24", { source = "pinger" } )
    eq( "automated /24 fully whitelisted -> allowed",
        bl_mod.check_ip( "198.51.100.5" ), false )

    -- 5. v4-mapped-v6 client is whitelisted against a plain-v4 allow
    --    entry even though the block entry is also plain v4.
    bl_mod.add( "192.0.2.77", { source = "external" } )
    eq( "mapped-v6 automated block pre-whitelist -> blocked",
        bl_mod.check_ip( "::ffff:192.0.2.77" ), true )
    wl_mod.add( "192.0.2.77", { source = "pinger" } )
    eq( "mapped-v6 automated block + v4 whitelist -> allowed",
        bl_mod.check_ip( "::ffff:192.0.2.77" ), false )

    -- 6. Whitelisted IP that is NOT blocked at all -> still just allowed
    --    (no crash, no false-block).
    eq( "whitelisted but not blocked -> allowed",
        bl_mod.check_ip( "203.0.113.10" ), false )
end

----------------------------------------------------------------------

if _fails > 0 then
    io.stderr:write( string.format( "\nFAIL: %d/%d checks failed\n",
        _fails, _passes + _fails ) )
    os.exit( 1 )
end
print( string.format( "OK: %d checks passed", _passes ) )
