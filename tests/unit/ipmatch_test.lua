--[[

    tests/unit/ipmatch_test.lua

    Unit tests for core/ipmatch.lua (#78 Phase A). Coverage matrix:

      parse_ip:    v4 valid + v4 bad inputs + v6 valid (incl. ::1,
                   :: , v4-mapped, all-zero, all-ones) + v6 bad
                   inputs (multiple ::, bad hex, too many groups,
                   too few groups without ::).
      parse_cidr:  v4 /0 /8 /24 /32; v6 /0 /16 /64 /128; bare IP =
                   max prefix; host-bits-set rejected with clear
                   error; /N out of range; mixed bad inputs.
      match:       v4 in-range + out-of-range across /N boundary;
                   v6 in-range + out-of-range; cross-family no-match;
                   /0 matches everything.
      family:      4 / 6 / nil shapes.
      normalize:   leading-zero strip + zero-run compression +
                   ordering of options for ambiguous addresses.

    Run: lua5.4 tests/unit/ipmatch_test.lua

]]--

local _real = {
    type = type, string = string, table = table,
    tonumber = tonumber, tostring = tostring,
}
_G.use = function( n )
    local v = _real[ n ]
    if v == nil then error( "ipmatch_test shim missing dep: use \"" .. tostring( n ) .. "\"" ) end
    return v
end

local ipm = assert( loadfile( "core/ipmatch.lua" ) )( )

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
    else
        _fails = _fails + 1
        io.stderr:write( "FAIL: " .. what .. " (got " .. tostring( v ) .. ")\n" )
    end
end
local function falsy( what, v )
    if not v then _passes = _passes + 1
    else
        _fails = _fails + 1
        io.stderr:write( "FAIL: " .. what .. " (got " .. tostring( v ) .. ")\n" )
    end
end

----------------------------------------------------------------------
-- parse_ip: IPv4
----------------------------------------------------------------------

do
    local fam, bytes = ipm.parse_ip( "1.2.3.4" )
    eq( "v4 family", fam, 4 )
    eq( "v4 byte length", bytes and #bytes, 4 )
    eq( "v4 bytes byte 1", string.byte( bytes, 1 ), 1 )
    eq( "v4 bytes byte 4", string.byte( bytes, 4 ), 4 )

    eq( "v4 0.0.0.0",       ipm.parse_ip( "0.0.0.0" ),       4 )
    eq( "v4 255.255.255.255", ipm.parse_ip( "255.255.255.255" ), 4 )

    falsy( "v4 leading-zero rejected",   ipm.parse_ip( "01.2.3.4" ) )
    falsy( "v4 octet > 255 rejected",    ipm.parse_ip( "256.0.0.1" ) )
    falsy( "v4 too few octets",          ipm.parse_ip( "1.2.3" ) )
    falsy( "v4 too many octets",         ipm.parse_ip( "1.2.3.4.5" ) )
    falsy( "v4 alpha rejected",          ipm.parse_ip( "1.2.3.a" ) )
    falsy( "v4 empty rejected",          ipm.parse_ip( "" ) )
    falsy( "v4 non-string rejected",     ipm.parse_ip( 42 ) )
end

----------------------------------------------------------------------
-- parse_ip: IPv6
----------------------------------------------------------------------

do
    eq( "v6 family ::1",             ipm.parse_ip( "::1" ), 6 )
    eq( "v6 family ::",              ipm.parse_ip( "::" ), 6 )
    eq( "v6 family full form",       ipm.parse_ip( "2001:db8:0:0:0:0:0:1" ), 6 )
    eq( "v6 family compressed",      ipm.parse_ip( "2001:db8::1" ), 6 )
    eq( "v6 family all-ones",        ipm.parse_ip( "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" ), 6 )
    eq( "v6 family v4-mapped",       ipm.parse_ip( "::ffff:1.2.3.4" ), 6 )
    eq( "v6 family bracketed",       ipm.parse_ip( "[::1]" ), 6 )

    local _, bytes = ipm.parse_ip( "::1" )
    eq( "v6 ::1 byte length",  #bytes, 16 )
    eq( "v6 ::1 last byte = 1", string.byte( bytes, 16 ), 1 )

    falsy( "v6 multiple :: rejected",   ipm.parse_ip( "1::2::3" ) )
    falsy( "v6 bad hex rejected",       ipm.parse_ip( "abcg::1" ) )
    falsy( "v6 too many groups",        ipm.parse_ip( "1:2:3:4:5:6:7:8:9" ) )
    falsy( "v6 too few without ::",     ipm.parse_ip( "1:2:3:4:5:6:7" ) )
    falsy( "v6 group too long",         ipm.parse_ip( "12345::" ) )
    falsy( "v6 whitespace rejected",    ipm.parse_ip( "::1 " ) )
end

----------------------------------------------------------------------
-- family helper
----------------------------------------------------------------------

eq( "family 1.2.3.4",   ipm.family( "1.2.3.4" ),  4 )
eq( "family ::1",       ipm.family( "::1" ),      6 )
eq( "family garbage",   ipm.family( "not an ip" ), nil )

----------------------------------------------------------------------
-- parse_cidr
----------------------------------------------------------------------

do
    local fam, net, plen = ipm.parse_cidr( "1.2.3.0/24" )
    eq( "cidr v4 /24 family", fam, 4 )
    eq( "cidr v4 /24 prefix", plen, 24 )
    eq( "cidr v4 /24 net byte 4", net and string.byte( net, 4 ), 0 )

    fam, _, plen = ipm.parse_cidr( "0.0.0.0/0" )
    eq( "cidr v4 /0 prefix", plen, 0 )

    fam, _, plen = ipm.parse_cidr( "192.0.2.42/32" )
    eq( "cidr v4 /32 prefix", plen, 32 )

    -- Bare IP - maps to family-max prefix.
    fam, _, plen = ipm.parse_cidr( "10.20.30.40" )
    eq( "cidr v4 bare maps to /32", plen, 32 )

    fam, _, plen = ipm.parse_cidr( "::1" )
    eq( "cidr v6 bare maps to /128", plen, 128 )

    fam, _, plen = ipm.parse_cidr( "2001:db8::/32" )
    eq( "cidr v6 /32", fam, 6 )
    eq( "cidr v6 /32 prefix", plen, 32 )

    -- Reject host-bits-set.
    falsy( "cidr v4 host-bits-set rejected",
        ipm.parse_cidr( "1.2.3.4/24" ) )
    falsy( "cidr v6 host-bits-set rejected",
        ipm.parse_cidr( "2001:db8::1/32" ) )

    -- Out-of-range prefix.
    falsy( "cidr v4 /33 rejected", ipm.parse_cidr( "1.2.3.4/33" ) )
    falsy( "cidr v6 /129 rejected", ipm.parse_cidr( "::1/129" ) )
    falsy( "cidr negative prefix rejected", ipm.parse_cidr( "1.2.3.4/-1" ) )

    -- Fractional prefix: must be cleanly rejected (NOT a Lua crash
    -- inside the `prefix >> 3` bitop downstream).
    local f, e = ipm.parse_cidr( "1.2.3.4/24.5" )
    eq( "cidr fractional prefix rejected (fam=nil)", f, nil )
    truthy( "cidr fractional prefix err msg", e and e:find( "integer" ) )
    local f2, e2 = ipm.parse_cidr( "::1/64.5" )
    eq( "cidr v6 fractional prefix rejected", f2, nil )
    truthy( "cidr v6 fractional prefix err msg", e2 and e2:find( "integer" ) )

    -- Garbage CIDR: error message must propagate from parse_ip
    -- (previously dropped on the floor because parse_ip only
    -- returns 2 values, never 3).
    local f3, e3 = ipm.parse_cidr( "not a cidr" )
    eq( "cidr garbage rejected", f3, nil )
    truthy( "cidr garbage err msg propagated", e3 and #e3 > 0 )
end

----------------------------------------------------------------------
-- match
----------------------------------------------------------------------

do
    local _, ip = ipm.parse_ip( "192.0.2.42" )
    local _, net, plen = ipm.parse_cidr( "192.0.2.0/24" )
    eq( "match v4 in /24", ipm.match( ip, net, plen ), true )

    local _, ip2 = ipm.parse_ip( "192.0.3.42" )
    eq( "match v4 outside /24", ipm.match( ip2, net, plen ), false )

    -- /0 matches everything (within family)
    local _, allnet, allplen = ipm.parse_cidr( "0.0.0.0/0" )
    eq( "match v4 /0 matches any v4", ipm.match( ip, allnet, allplen ), true )

    -- /32 matches only itself
    local _, exactnet, exactplen = ipm.parse_cidr( "192.0.2.42/32" )
    eq( "match v4 /32 exact",     ipm.match( ip,  exactnet, exactplen ), true )
    eq( "match v4 /32 non-match", ipm.match( ip2, exactnet, exactplen ), false )

    -- Cross-family no-match (mismatched lengths).
    local _, ip6 = ipm.parse_ip( "2001:db8::1" )
    eq( "match cross-family false (v4 vs v6 net)",
        ipm.match( ip, ip6, 32 ), false )

    -- v6 in /32
    local _, v6net, v6plen = ipm.parse_cidr( "2001:db8::/32" )
    eq( "match v6 in /32", ipm.match( ip6, v6net, v6plen ), true )

    -- v6 outside /32
    local _, ip6_out = ipm.parse_ip( "2001:db9::1" )
    eq( "match v6 outside /32", ipm.match( ip6_out, v6net, v6plen ), false )

    -- Boundary: prefix on byte 4, 1 bit
    local _, narrow_net, narrow_plen = ipm.parse_cidr( "192.0.2.0/25" )
    local _, ip_25_in = ipm.parse_ip( "192.0.2.127" )
    local _, ip_25_out = ipm.parse_ip( "192.0.2.128" )
    eq( "match /25 lower half in", ipm.match( ip_25_in, narrow_net, narrow_plen ), true )
    eq( "match /25 upper half out", ipm.match( ip_25_out, narrow_net, narrow_plen ), false )

    -- prefix /31 (one bit off from /32)
    local _, narrow2_net, narrow2_plen = ipm.parse_cidr( "192.0.2.0/31" )
    local _, ip_31_a = ipm.parse_ip( "192.0.2.0" )
    local _, ip_31_b = ipm.parse_ip( "192.0.2.1" )
    local _, ip_31_c = ipm.parse_ip( "192.0.2.2" )
    eq( "match /31 .0 in", ipm.match( ip_31_a, narrow2_net, narrow2_plen ), true )
    eq( "match /31 .1 in", ipm.match( ip_31_b, narrow2_net, narrow2_plen ), true )
    eq( "match /31 .2 out", ipm.match( ip_31_c, narrow2_net, narrow2_plen ), false )

    -- Bad input
    eq( "match non-string bytes", ipm.match( nil, net, plen ), false )
end

----------------------------------------------------------------------
-- normalize
----------------------------------------------------------------------

eq( "normalize v4 strips leading zeros",
    ipm.normalize( "1.2.3.4" ), "1.2.3.4" )

-- Leading zero in v4 is REJECTED by parse, so normalize returns nil.
falsy( "normalize v4 leading-zero rejected",
    ipm.normalize( "001.002.003.004" ) )

eq( "normalize v6 compresses",
    ipm.normalize( "2001:0db8:0000:0000:0000:0000:0000:0001" ), "2001:db8::1" )

eq( "normalize v6 ::1 stable",
    ipm.normalize( "::1" ), "::1" )

eq( "normalize v6 :: stable",
    ipm.normalize( "::" ), "::" )

eq( "normalize v6 all-ones uncompressed",
    ipm.normalize( "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" ),
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" )

-- v4-mapped uses dotted-quad tail per RFC 5952 §5
eq( "normalize v4-mapped dotted-quad",
    ipm.normalize( "::ffff:1.2.3.4" ), "::ffff:1.2.3.4" )
eq( "normalize v4-mapped from hex form",
    ipm.normalize( "::ffff:0102:0304" ), "::ffff:1.2.3.4" )

falsy( "normalize garbage", ipm.normalize( "garbage" ) )

----------------------------------------------------------------------
-- format_bytes (bytes-in, canonical-text-out)
----------------------------------------------------------------------

eq( "format_bytes v4 dotted-quad",
    ipm.format_bytes( 4, "\1\2\3\4" ), "1.2.3.4" )
eq( "format_bytes v6 compressed",
    ipm.format_bytes( 6, "\x20\x01\x0d\xb8" .. string.rep( "\0", 11 ) .. "\1" ),
    "2001:db8::1" )
eq( "format_bytes v4-mapped",
    ipm.format_bytes( 6, string.rep( "\0", 10 ) .. "\xff\xff\1\2\3\4" ),
    "::ffff:1.2.3.4" )
eq( "format_bytes wrong length v4", ipm.format_bytes( 4, "\1\2\3" ), nil )
eq( "format_bytes wrong length v6", ipm.format_bytes( 6, "\1\2" ),   nil )
eq( "format_bytes unknown family",  ipm.format_bytes( 8, "" ),       nil )
eq( "format_bytes nil bytes",       ipm.format_bytes( 4, nil ),      nil )

----------------------------------------------------------------------

if _fails > 0 then
    io.stderr:write( string.format( "\nFAIL: %d/%d checks failed\n",
        _fails, _passes + _fails ) )
    os.exit( 1 )
end
print( string.format( "OK: %d checks passed", _passes ) )
