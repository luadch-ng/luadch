--[[

    tests/unit/http_client_test.lua

    Unit tests for the pure helpers of core/http_client.lua:
    parse_url, build_request, parse_response. The non-blocking state
    machine (drive / request) needs the live select loop + real
    sockets and is exercised by the smoke harness against a loopback
    server; here we cover the byte-level parsing/building only.

    Run: lua5.4 tests/unit/http_client_test.lua

]]--

-- `use` shim. The pure helpers only touch string/table/tonumber/etc;
-- socket/ssl/out/io are referenced at module load but not called by
-- the functions under test, so minimal stubs suffice. `io` is the
-- real stdlib so the cafile-existence-probe (Precursor 0b of #78
-- arc) inside the TLS-handshake branch works during smoke; the unit
-- tests here never reach that branch.
local _real = {
    type = type, tostring = tostring, tonumber = tonumber,
    pcall = pcall, pairs = pairs, ipairs = ipairs,
    string = string, table = table,
    socket = { gettime = function() return 0 end },
    ssl = {},
    out = { put = function() end, error = function() end },
    io = io,
    coroutine = coroutine,
}
_G.use = function( name )
    local v = _real[ name ]
    assert( v ~= nil, "http_client_test shim missing dep: use \"" .. name .. "\"" )
    return v
end

local hc = assert( loadfile( "core/http_client.lua" ) )( )

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-50s got=%q want=%q\n", label, tostring( got ), tostring( want ) ) )
    else
        io.write( "ok   " .. label .. "\n" )
    end
end
local function ok( label, cond )
    checks = checks + 1
    if cond then io.write( "ok   " .. label .. "\n" )
    else failures = failures + 1; io.write( "FAIL " .. label .. "\n" ) end
end

----------------------------------------------------------------------
-- parse_url
----------------------------------------------------------------------

do
    local s, h, p, path = hc._parse_url( "https://hub.example.org:1511/register" )
    eq( "url: https scheme", s, "https" )
    eq( "url: host", h, "hub.example.org" )
    eq( "url: explicit port", p, 1511 )
    eq( "url: path", path, "/register" )

    s, h, p, path = hc._parse_url( "http://example.com/x" )
    eq( "url: http default port", p, 80 )
    eq( "url: http scheme", s, "http" )

    s, h, p, path = hc._parse_url( "https://example.com" )
    eq( "url: https default port", p, 443 )
    eq( "url: empty path -> /", path, "/" )

    s, h, p = hc._parse_url( "https://1.2.3.4:8080/" )
    eq( "url: ipv4 host", h, "1.2.3.4" )
    eq( "url: ipv4 port", p, 8080 )

    local bad, err = hc._parse_url( "ftp://example.com/x" )
    ok( "url: rejects ftp", bad == nil and err ~= nil )

    bad = hc._parse_url( "not-a-url" )
    ok( "url: rejects garbage", bad == nil )

    bad = hc._parse_url( 12345 )
    ok( "url: rejects non-string", bad == nil )

    -- #275-style security hardening: reject injection / unsupported forms
    bad = hc._parse_url( "https://host/x\r\nEvil: 1" )
    ok( "url: rejects CRLF (smuggling)", bad == nil )

    bad = hc._parse_url( "https://user:pass@host/x" )
    ok( "url: rejects embedded credentials", bad == nil )

    bad = hc._parse_url( "https://host:99999/x" )
    ok( "url: rejects port out of range", bad == nil )

    -- IPv6 literals (bracketed) are supported; host returned unbracketed
    local s6, h6, p6, path6 = hc._parse_url( "https://[2001:db8::1]:1337/register" )
    eq( "url: ipv6 scheme", s6, "https" )
    eq( "url: ipv6 host unbracketed", h6, "2001:db8::1" )
    eq( "url: ipv6 port", p6, 1337 )
    eq( "url: ipv6 path", path6, "/register" )

    local _, h6b, p6b = hc._parse_url( "http://[::1]/x" )
    eq( "url: ipv6 loopback host", h6b, "::1" )
    eq( "url: ipv6 default port", p6b, 80 )

    bad = hc._parse_url( "https://[not:valid:hex:zzzz]/x" )
    ok( "url: rejects non-hex IPv6 literal", bad == nil )

    -- Host header re-brackets an IPv6 literal
    local r6 = hc._build_request( "GET", "2001:db8::1", 1337, "/", nil, nil )
    ok( "build: ipv6 Host bracketed", r6:match( "\r\nHost: %[2001:db8::1%]:1337\r\n" ) ~= nil )
    local r6d = hc._build_request( "GET", "::1", 443, "/", nil, nil )
    ok( "build: ipv6 Host default port no :port", r6d:match( "\r\nHost: %[::1%]\r\n" ) ~= nil )
end

----------------------------------------------------------------------
-- has_ctrl (CRLF / control-byte guard)
----------------------------------------------------------------------

do
    ok( "ctrl: plain string clean", hc._has_ctrl( "Luadch-NG Hub" ) == false )
    ok( "ctrl: CR flagged", hc._has_ctrl( "a\rb" ) == true )
    ok( "ctrl: LF flagged", hc._has_ctrl( "a\nb" ) == true )
    ok( "ctrl: NUL flagged", hc._has_ctrl( "a\0b" ) == true )
    ok( "ctrl: non-string flagged", hc._has_ctrl( 42 ) == true )
end

----------------------------------------------------------------------
-- build_request
----------------------------------------------------------------------

do
    local r = hc._build_request( "POST", "h.example", 443, "/register",
        "IINF NIHub HHadc://x:1", { [ "X-Test" ] = "yes" } )
    ok( "build: request line", r:match( "^POST /register HTTP/1%.1\r\n" ) ~= nil )
    ok( "build: host header (no :443)", r:match( "\r\nHost: h%.example\r\n" ) ~= nil )
    ok( "build: connection close", r:match( "\r\nConnection: close\r\n" ) ~= nil )
    ok( "build: content-length set", r:match( "\r\nContent%-Length: 22\r\n" ) ~= nil )
    ok( "build: extra header passed", r:match( "\r\nX%-Test: yes\r\n" ) ~= nil )
    ok( "build: blank line before body", r:match( "\r\n\r\nIINF NIHub HHadc://x:1$" ) ~= nil )

    -- non-default port shows in Host
    local r2 = hc._build_request( "GET", "h", 8080, "/", nil, nil )
    ok( "build: non-default port in Host", r2:match( "\r\nHost: h:8080\r\n" ) ~= nil )
    ok( "build: GET no content-length", r2:match( "Content%-Length" ) == nil )

    -- caller cannot override Connection/Host (spoof guard)
    local r3 = hc._build_request( "GET", "h", 80, "/",
        nil, { Host = "evil", Connection = "keep-alive" } )
    ok( "build: Host not overridable", r3:match( "Host: evil" ) == nil )
    ok( "build: Connection not overridable", r3:match( "keep%-alive" ) == nil )
end

----------------------------------------------------------------------
-- parse_response
----------------------------------------------------------------------

do
    local res = hc._parse_response(
        "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nX-Foo: bar\r\n\r\n{\"ok\":true}" )
    eq( "resp: status", res.status, 202 )
    eq( "resp: header content-type", res.headers[ "content-type" ], "application/json" )
    eq( "resp: header lowercased custom", res.headers[ "x-foo" ], "bar" )
    eq( "resp: body", res.body, '{"ok":true}' )

    local res2 = hc._parse_response( "HTTP/1.0 200 OK\r\n\r\n" )
    eq( "resp: empty body", res2.body, "" )
    eq( "resp: 200", res2.status, 200 )

    local res3 = hc._parse_response( "garbage no http" )
    ok( "resp: non-http status nil", res3.status == nil )
end

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
