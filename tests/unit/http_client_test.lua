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
-- Capture out.put / out.error so the log_url redaction test (Precursor F0
-- of the #78 arc) can assert what reached the log. out_put / out_error are
-- bound as module-load-time locals, so the capturing functions must be in
-- the shim BEFORE the module is loaded below.
local _logged = {}
local function _cap( ... )
    local parts = {}
    for i = 1, select( "#", ... ) do parts[ i ] = tostring( ( select( i, ... ) ) ) end
    _logged[ #_logged + 1 ] = table.concat( parts )
end

local _real = {
    type = type, tostring = tostring, tonumber = tonumber,
    pcall = pcall, pairs = pairs, ipairs = ipairs,
    string = string, table = table,
    socket = { gettime = function() return 0 end },
    ssl = {},
    out = { put = _cap, error = _cap },
    io = io,
    os = os,     -- download_to_file mode uses os.remove / os.rename
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

----------------------------------------------------------------------
-- download_to_file mode (Precursor 0a): stream_transfer + stream_to_file
--
-- The stream-to-disk state machine needs a socket + coroutine but NOT
-- a real network: a scripted mock socket feeds receive() results and a
-- coroutine driver resumes through the yields the real hub timer would
-- drive. Bodies land in a real temp file so the header/body split,
-- caps, atomic rename and cleanup are all exercised end-to-end.
----------------------------------------------------------------------

-- Scripted non-blocking socket. `script[i]` = { data, err, partial };
-- once exhausted it reports EOF ("closed") forever.
local function mock_sock( script )
    local i = 0
    local m = { closed = false }
    m.receive = function( self, n )
        i = i + 1
        local step = script[ i ]
        if not step then return nil, "closed" end
        return step.data, step.err, step.partial
    end
    m.close = function( self ) m.closed = true end
    return m
end

-- Drive a yielding function to completion inside a coroutine and return
-- its final results (the hub's server.addtimer loop plays this role).
local function drive_coro( fn )
    local co = coroutine.create( fn )
    while true do
        local r = { coroutine.resume( co ) }
        if coroutine.status( co ) == "dead" then
            if not r[ 1 ] then error( "coro error: " .. tostring( r[ 2 ] ) ) end
            return table.unpack( r, 2 )
        end
    end
end

-- As drive_coro but also returns how many times the function yielded
-- (first return value), so a test can prove the bounded-drain cadence.
local function drive_coro_count( fn )
    local co = coroutine.create( fn )
    local yields = 0
    while true do
        local r = { coroutine.resume( co ) }
        if coroutine.status( co ) == "dead" then
            if not r[ 1 ] then error( "coro error: " .. tostring( r[ 2 ] ) ) end
            return yields, table.unpack( r, 2 )
        end
        yields = yields + 1
    end
end

local function never_expired() return false end

-- Run stream_transfer against a scripted socket, capturing the bytes it
-- wrote to a real temp file. Returns ok, res, nbytes, file_content.
local ST_PATH = "http_client_st_test.out"
local function run_transfer( script, max_body, max_head, expired_fn, tick_budget, follow )
    os.remove( ST_PATH )
    local f = assert( io.open( ST_PATH, "wb" ) )
    local sock = mock_sock( script )
    local ok_, res, nbytes = drive_coro( function()
        return hc._stream_transfer( sock, expired_fn or never_expired, f, max_body, max_head, tick_budget, follow )
    end )
    f:close()
    local fh = io.open( ST_PATH, "rb" )
    local content = fh and fh:read( "*a" ) or ""
    if fh then fh:close() end
    os.remove( ST_PATH )
    return ok_, res, nbytes, content
end

do
    -- happy path: headers + body in a single read that also EOFs
    local ok_, res, n, content = run_transfer{
        { data = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nline1\nline2\n", err = "closed" },
    }
    ok( "st: single-chunk success", ok_ == true )
    eq( "st: single-chunk status", res.status, 200 )
    ok( "st: single-chunk body nil (on disk)", res.body == nil )
    eq( "st: single-chunk bytes", n, 12 )
    eq( "st: single-chunk file content", content, "line1\nline2\n" )

    -- header/body terminator straddles two reads (\r\n\r + \n)
    local ok2, res2, n2, c2 = run_transfer{
        { data = "HTTP/1.1 200 OK\r\nX: y\r\n\r", err = nil },
        { data = "\nBODYBYTES", err = "closed" },
    }
    ok( "st: straddled terminator success", ok2 == true )
    eq( "st: straddled status", res2.status, 200 )
    eq( "st: straddled bytes", n2, 9 )
    eq( "st: straddled body", c2, "BODYBYTES" )

    -- body split across several body-phase reads
    local ok3, _, n3, c3 = run_transfer{
        { data = "HTTP/1.1 200 OK\r\n\r\nAAAA", err = nil },
        { data = "BBBB", err = nil },
        { data = "CCCC", err = "closed" },
    }
    ok( "st: multi-chunk body success", ok3 == true )
    eq( "st: multi-chunk bytes", n3, 12 )
    eq( "st: multi-chunk body", c3, "AAAABBBBCCCC" )

    -- empty body (204-style): terminator, then immediate EOF
    local ok4, res4, n4, c4 = run_transfer{
        { data = "HTTP/1.1 204 No Content\r\n\r\n", err = "closed" },
    }
    ok( "st: empty body success", ok4 == true )
    eq( "st: empty body status", res4.status, 204 )
    eq( "st: empty body bytes", n4, 0 )
    eq( "st: empty body file", c4, "" )

    -- non-2xx: rejected BEFORE any byte is written (protects good file)
    local ok5, err5, _, c5 = run_transfer{
        { data = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found", err = "closed" },
    }
    ok( "st: 404 rejected", ok5 == false )
    ok( "st: 404 err names status", tostring( err5 ):match( "404" ) ~= nil )
    eq( "st: 404 wrote nothing", c5, "" )

    -- body cap exceeded
    local ok6, err6 = run_transfer( {
        { data = "HTTP/1.1 200 OK\r\n\r\n" .. string.rep( "X", 100 ), err = "closed" },
    }, 10 )
    ok( "st: body cap rejected", ok6 == false )
    ok( "st: body cap err mentions cap", tostring( err6 ):match( "cap" ) ~= nil )

    -- header cap exceeded (no terminator, headers grow past max_head)
    local ok7, err7 = run_transfer( {
        { data = "HTTP/1.1 200 OK\r\nHHHHHHHHHHHHHHHHHHHHHHHHHHHH", err = nil },
        { data = "closed-next", err = "closed" },
    }, nil, 20 )
    ok( "st: header cap rejected", ok7 == false )
    ok( "st: header cap err mentions cap", tostring( err7 ):match( "cap" ) ~= nil )

    -- connection closed mid-headers (no \r\n\r\n ever)
    local ok8, err8 = run_transfer{
        { data = "HTTP/1.1 200 OK\r\nPartial", err = "closed" },
    }
    ok( "st: closed-before-headers rejected", ok8 == false )
    ok( "st: closed-before-headers err", tostring( err8 ):match( "closed before" ) ~= nil )

    -- read timeout during body
    local ok9, err9 = run_transfer( {
        { data = "HTTP/1.1 200 OK\r\n\r\nA", err = nil },
    }, nil, nil, function() return true end )
    ok( "st: timeout rejected", ok9 == false )
    ok( "st: timeout err names timeout", tostring( err9 ):match( "timeout" ) ~= nil )
end

do
    -- Content-Length satisfied -> success
    local okA, _, nA, cA = run_transfer{
        { data = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nFEEDDATA", err = "closed" },
    }
    ok( "st: content-length satisfied", okA == true )
    eq( "st: content-length bytes", nA, 8 )
    eq( "st: content-length body", cA, "FEEDDATA" )

    -- Content-Length short (server closed mid-body) -> truncation, rejected
    local okB, errB = run_transfer{
        { data = "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nSHORT", err = "closed" },
    }
    ok( "st: truncated download rejected", okB == false )
    ok( "st: truncated err names truncation", tostring( errB ):match( "truncated" ) ~= nil )

    -- Transfer-Encoding: chunked -> rejected before any byte written
    local okC, errC, _, cC = run_transfer{
        { data = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", err = "closed" },
    }
    ok( "st: chunked rejected", okC == false )
    ok( "st: chunked err names chunked", tostring( errC ):match( "chunked" ) ~= nil )
    eq( "st: chunked wrote nothing", cC, "" )

    -- body cap boundary: exactly-at-cap accepted, one-over rejected
    local okD, _, nD, cD = run_transfer( {
        { data = "HTTP/1.1 200 OK\r\n\r\n" .. string.rep( "Z", 10 ), err = "closed" },
    }, 10 )
    ok( "st: body exactly at cap accepted", okD == true )
    eq( "st: body exactly at cap bytes", nD, 10 )
    eq( "st: body exactly at cap content", cD, string.rep( "Z", 10 ) )

    local okE, errE = run_transfer( {
        { data = "HTTP/1.1 200 OK\r\n\r\n" .. string.rep( "Z", 11 ), err = "closed" },
    }, 10 )
    ok( "st: body one over cap rejected", okE == false )
    ok( "st: body over-cap err names cap", tostring( errE ):match( "cap" ) ~= nil )

    -- header cap boundary: header size == cap accepted, cap-1 rejected.
    -- minimal_head's \r\n\r\n terminator ends at exactly #minimal_head.
    local minimal_head = "HTTP/1.1 200 OK\r\n\r\n"
    local okF = run_transfer( {
        { data = minimal_head .. "B", err = "closed" },
    }, nil, #minimal_head )
    ok( "st: header exactly at cap accepted", okF == true )

    local okG, errG = run_transfer( {
        { data = minimal_head .. "B", err = "closed" },
    }, nil, #minimal_head - 1 )
    ok( "st: header one over cap rejected", okG == false )
    ok( "st: header over-cap err names cap", tostring( errG ):match( "cap" ) ~= nil )

    -- bounded-drain cadence: a full-chunk (err=nil) read does NOT yield
    -- until the per-tick budget is reached. Same 3 chunks, two budgets.
    local drain_script = {
        { data = "HTTP/1.1 200 OK\r\n\r\nAAAA", err = nil },
        { data = "BBBB", err = nil },
        { data = "CCCC", err = "closed" },
    }
    local function count_yields( budget )
        os.remove( ST_PATH )
        local f = assert( io.open( ST_PATH, "wb" ) )
        local y = drive_coro_count( function()
            return hc._stream_transfer( mock_sock( drain_script ), never_expired, f, nil, nil, budget )
        end )
        f:close(); os.remove( ST_PATH )
        return y
    end
    ok( "st: large budget drains full chunks without yielding", count_yields( 1024 * 1024 ) == 0 )
    ok( "st: tiny budget yields per full chunk", count_yields( 1 ) >= 2 )

    -- a would-block ("timeout") read yields even under budget, and the
    -- partial bytes are kept and the transfer resumes correctly
    os.remove( ST_PATH )
    local fW = assert( io.open( ST_PATH, "wb" ) )
    local yW, okW, _, nW = drive_coro_count( function()
        return hc._stream_transfer( mock_sock{
            { data = "HTTP/1.1 200 OK\r\n\r\nAA", err = "timeout" },
            { data = "BB", err = "closed" },
        }, never_expired, fW, nil, nil, 1024 * 1024 )
    end )
    fW:close()
    local fhW = io.open( ST_PATH, "rb" ); local cW = fhW:read( "*a" ); fhW:close(); os.remove( ST_PATH )
    ok( "st: would-block yields even under budget", yW >= 1 )
    ok( "st: would-block success", okW == true )
    eq( "st: would-block bytes", nW, 4 )
    eq( "st: would-block body", cW, "AABB" )
end

-- stream_to_file: the file lifecycle wrapper (tmp -> atomic rename /
-- cleanup). Uses a real path in the CWD; cleaned up after each case.
local DL_PATH = "http_client_dl_test.out"
local function cleanup_dl()
    os.remove( DL_PATH )
    os.remove( DL_PATH .. ".tmp" )
end

do
    cleanup_dl()

    -- happy path: body written, tmp renamed to final, res carries meta
    local sock = mock_sock{ { data = "HTTP/1.1 200 OK\r\n\r\nFEEDDATA", err = "closed" } }
    local ok_, res = drive_coro( function()
        return hc._stream_to_file( sock, { download_to_file = DL_PATH }, never_expired )
    end )
    ok( "dl: success", ok_ == true )
    eq( "dl: status", res.status, 200 )
    eq( "dl: downloaded_path", res.downloaded_path, DL_PATH )
    eq( "dl: downloaded_bytes", res.downloaded_bytes, 8 )
    ok( "dl: body nil", res.body == nil )
    ok( "dl: socket closed", sock.closed == true )
    local fh = io.open( DL_PATH, "rb" )
    ok( "dl: final file exists", fh ~= nil )
    local content = fh and fh:read( "*a" ) or nil
    if fh then fh:close() end
    eq( "dl: final content", content, "FEEDDATA" )
    ok( "dl: tmp removed", io.open( DL_PATH .. ".tmp", "rb" ) == nil )

    -- replace an existing file (exercises the Windows remove-then-rename)
    local pf = assert( io.open( DL_PATH, "wb" ) ); pf:write( "OLDDATA" ); pf:close()
    local sock2 = mock_sock{ { data = "HTTP/1.1 200 OK\r\n\r\nNEWDATA", err = "closed" } }
    local ok2 = drive_coro( function()
        return hc._stream_to_file( sock2, { download_to_file = DL_PATH }, never_expired )
    end )
    ok( "dl: replace success", ok2 == true )
    local fh2 = io.open( DL_PATH, "rb" ); local c2 = fh2:read( "*a" ); fh2:close()
    eq( "dl: existing file replaced", c2, "NEWDATA" )

    -- failure (404): existing good file preserved, tmp removed
    local pf3 = assert( io.open( DL_PATH, "wb" ) ); pf3:write( "GOODFEED" ); pf3:close()
    local sock3 = mock_sock{ { data = "HTTP/1.1 404 Not Found\r\n\r\nnope", err = "closed" } }
    local ok3, err3 = drive_coro( function()
        return hc._stream_to_file( sock3, { download_to_file = DL_PATH }, never_expired )
    end )
    ok( "dl: 404 fails", ok3 == false )
    ok( "dl: 404 err names status", tostring( err3 ):match( "404" ) ~= nil )
    local fh3 = io.open( DL_PATH, "rb" ); local c3 = fh3:read( "*a" ); fh3:close()
    eq( "dl: existing file preserved on failure", c3, "GOODFEED" )
    ok( "dl: tmp removed after failure", io.open( DL_PATH .. ".tmp", "rb" ) == nil )

    cleanup_dl()

    -- production path: a multi-read download that YIELDS inside
    -- stream_to_file's pcall wrapper (the real hub always runs the
    -- transfer under that pcall while the coroutine yields). Uses a
    -- would-block read so the yield fires regardless of the tick budget.
    local sockY = mock_sock{
        { data = "HTTP/1.1 200 OK\r\n\r\nPART", err = "timeout" },
        { data = "IAL2", err = "closed" },
    }
    local okY, resY = drive_coro( function()
        return hc._stream_to_file( sockY, { download_to_file = DL_PATH }, never_expired )
    end )
    ok( "dl: yield-across-pcall success", okY == true )
    eq( "dl: yield-across-pcall bytes", resY.downloaded_bytes, 8 )
    local fhY = io.open( DL_PATH, "rb" ); local cY = fhY:read( "*a" ); fhY:close()
    eq( "dl: yield-across-pcall content", cY, "PARTIAL2" )

    cleanup_dl()
end

----------------------------------------------------------------------
-- log_url redaction (Precursor F0 of #78 arc): request() logs the request
-- URL on failure/crash; a key in the query string or path would leak into
-- error.log / event.log. A caller-supplied log_url is logged instead.
----------------------------------------------------------------------
do
    -- request() resolves `server` via use"server" at call time; give it an
    -- addtimer that captures the coroutine so the test can drive it.
    local captured
    _real.server = { addtimer = function( co ) captured = co end }

    local start = #_logged
    local queued = hc.request{
        url      = "https://vpnapi.io/api/1.2.3.4?key=SECRETKEY123",
        log_url  = "https://vpnapi.io/api/1.2.3.4",
        on_error = function() end,
    }
    ok( "log_url: request queued", queued == true )
    ok( "log_url: coroutine captured", captured ~= nil )
    -- Drive the coroutine to completion: drive() fails (the socket stub has
    -- no tcp), request()'s pcall wrapper catches it, and the failure log
    -- line fires - now with log_url instead of the key-bearing url.
    if captured then
        for _ = 1, 100 do
            if coroutine.status( captured ) == "dead" then break end
            local o = coroutine.resume( captured )
            if not o then break end
        end
    end
    local blob = table.concat( _logged, "\n", start + 1 )
    ok( "log_url: something logged on failure", #_logged > start )
    ok( "log_url: API key NOT in the log", blob:find( "SECRETKEY123", 1, true ) == nil )
    ok( "log_url: redacted url IS logged", blob:find( "vpnapi.io/api/1.2.3.4", 1, true ) ~= nil )

    -- validation: control bytes + non-string log_url rejected synchronously
    local badc = hc.request{ url = "https://h/x", log_url = "https://h/\r\nx", on_error = function() end }
    ok( "log_url: rejects control bytes", badc == false )
    local badt = hc.request{ url = "https://h/x", log_url = 123, on_error = function() end }
    ok( "log_url: rejects non-string", badt == false )

    -- Also cover the "failed" log line (out_put): stub socket.tcp so drive()
    -- RETURNS a clean (false, err) instead of throwing (the crash test above
    -- only exercised out_error). Both lines must redact symmetrically.
    _real.socket.tcp = function() return nil, "stub: no tcp" end
    local start2 = #_logged
    local captured2
    _real.server = { addtimer = function( co ) captured2 = co end }
    hc.request{
        url      = "https://vpnapi.io/api/9.9.9.9?key=FAILKEY456",
        log_url  = "https://vpnapi.io/api/9.9.9.9",
        on_error = function() end,
    }
    if captured2 then
        for _ = 1, 100 do
            if coroutine.status( captured2 ) == "dead" then break end
            if not coroutine.resume( captured2 ) then break end
        end
    end
    local blob2 = table.concat( _logged, "\n", start2 + 1 )
    ok( "log_url: failed-line key NOT in the log", blob2:find( "FAILKEY456", 1, true ) == nil )
    ok( "log_url: failed-line redacted url logged", blob2:find( "vpnapi.io/api/9.9.9.9", 1, true ) ~= nil )
    _real.socket.tcp = nil

    -- empty-string log_url is treated as unset -> falls back to req.url
    local start3 = #_logged
    local captured3
    _real.server = { addtimer = function( co ) captured3 = co end }
    hc.request{ url = "https://host.example/path", log_url = "", on_error = function() end }
    if captured3 then
        for _ = 1, 100 do
            if coroutine.status( captured3 ) == "dead" then break end
            if not coroutine.resume( captured3 ) then break end
        end
    end
    local blob3 = table.concat( _logged, "\n", start3 + 1 )
    ok( "log_url: empty string falls back to url", blob3:find( "host.example/path", 1, true ) ~= nil )
end

----------------------------------------------------------------------
-- Redirect following (opt-in max_redirects) - the GeoIP 302 fix.
-- MaxMind's download endpoint 302s to a signed Cloudflare-R2 URL on a
-- DIFFERENT host; the client must follow it AND drop the Basic-auth
-- header on that cross-origin hop so the credential never leaks.
----------------------------------------------------------------------

-- resolve_location: pure reference-resolution of a Location value.
do
    eq( "rl: absolute passes through",
        hc._resolve_location( "https", "h.example", 443, "/download", "https://cdn.example/x?y=1" ),
        "https://cdn.example/x?y=1" )
    eq( "rl: absolute-path, default port omitted",
        hc._resolve_location( "https", "h.example", 443, "/a/b", "/c/d" ),
        "https://h.example/c/d" )
    eq( "rl: absolute-path, non-default port kept",
        hc._resolve_location( "https", "h.example", 8443, "/a/b", "/c" ),
        "https://h.example:8443/c" )
    eq( "rl: scheme-relative inherits scheme",
        hc._resolve_location( "https", "h", 443, "/x", "//cdn.example/y" ),
        "https://cdn.example/y" )
    eq( "rl: relative replaces last path segment",
        hc._resolve_location( "https", "h.example", 443, "/dir/file", "next" ),
        "https://h.example/dir/next" )
    eq( "rl: relative from root path",
        hc._resolve_location( "http", "h", 80, "/", "x" ),
        "http://h/x" )
    eq( "rl: ipv6 authority re-bracketed",
        hc._resolve_location( "https", "2001:db8::1", 443, "/a", "/b" ),
        "https://[2001:db8::1]/b" )
    ok( "rl: empty Location rejected", ( hc._resolve_location( "https", "h", 443, "/", "" ) ) == nil )
    ok( "rl: control-byte Location rejected", ( hc._resolve_location( "https", "h", 443, "/", "/a\r\nb" ) ) == nil )
end

-- strip_sensitive: drops auth/cookie headers case-insensitively.
do
    local h = { Authorization = "Basic xxx", [ "X-Keep" ] = "1", Cookie = "a=b" }
    local s = hc._strip_sensitive( h )
    ok( "ss: Authorization dropped", s.Authorization == nil )
    ok( "ss: Cookie dropped", s.Cookie == nil )
    eq( "ss: unrelated header kept", s[ "X-Keep" ], "1" )
    ok( "ss: original table not mutated", h.Authorization == "Basic xxx" )

    local h2 = { [ "authorization" ] = "x", [ "PROXY-AUTHORIZATION" ] = "y", z = "keep" }
    local s2 = hc._strip_sensitive( h2 )
    ok( "ss: lowercase authorization dropped", s2[ "authorization" ] == nil )
    ok( "ss: uppercase proxy-authorization dropped", s2[ "PROXY-AUTHORIZATION" ] == nil )
    eq( "ss: other kept", s2.z, "keep" )

    ok( "ss: nil passes through", hc._strip_sensitive( nil ) == nil )
    local h3 = { a = 1 }
    ok( "ss: nothing sensitive returns same table", hc._strip_sensitive( h3 ) == h3 )
end

-- prepare_redirect: resolve + validate + cross-origin auth-strip.
do
    local hdr = { Authorization = "Basic SECRET", [ "User-Agent" ] = "x" }

    -- the real MaxMind case: cross-host -> Basic auth stripped
    local nurl, nh = hc._prepare_redirect(
        "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz.sha256",
        hdr,
        "https://mm-prod-geoip-databases.r2.cloudflarestorage.com/downloads/x.tar.gz.sha256?X-Amz-Signature=abc" )
    eq( "pr: cross-host target url",
        nurl, "https://mm-prod-geoip-databases.r2.cloudflarestorage.com/downloads/x.tar.gz.sha256?X-Amz-Signature=abc" )
    ok( "pr: cross-host strips Authorization", nh.Authorization == nil )
    eq( "pr: cross-host keeps User-Agent", nh[ "User-Agent" ], "x" )
    ok( "pr: original header table untouched", hdr.Authorization == "Basic SECRET" )

    -- same-host absolute -> auth kept
    local nurl2, nh2 = hc._prepare_redirect( "https://h.example/a", hdr, "https://h.example/b" )
    eq( "pr: same-host target url", nurl2, "https://h.example/b" )
    eq( "pr: same-host keeps auth", nh2.Authorization, "Basic SECRET" )

    -- same-host relative -> resolved, auth kept
    local nurl3, nh3 = hc._prepare_redirect( "https://h.example/dir/a", hdr, "b" )
    eq( "pr: relative resolved", nurl3, "https://h.example/dir/b" )
    eq( "pr: relative keeps auth", nh3.Authorization, "Basic SECRET" )

    -- different port same host -> cross-origin -> auth stripped
    local _, nh4 = hc._prepare_redirect( "https://h.example/a", hdr, "https://h.example:8443/a" )
    ok( "pr: different port strips auth", nh4.Authorization == nil )

    -- absolute IPv6 target resolves + validates through parse_url
    local nurl6, nh6 = hc._prepare_redirect( "https://h.example/a", hdr, "https://[2001:db8::5]/b" )
    eq( "pr: ipv6 absolute target url", nurl6, "https://[2001:db8::5]/b" )
    ok( "pr: ipv6 cross-host strips auth", nh6.Authorization == nil )

    -- https -> http downgrade refused
    local bad, berr = hc._prepare_redirect( "https://h.example/a", hdr, "http://h.example/a" )
    ok( "pr: downgrade refused", bad == nil )
    ok( "pr: downgrade err names downgrade", tostring( berr ):match( "downgrade" ) ~= nil )

    -- unsupported-scheme target refused
    ok( "pr: ftp target refused", ( hc._prepare_redirect( "https://h.example/a", hdr, "ftp://h.example/a" ) ) == nil )

    -- an error string must NEVER echo the signature-bearing target URL
    local _, berr2 = hc._prepare_redirect( "https://h.example/a", hdr, "http://cdn.example/x?X-Amz-Signature=LEAK" )
    ok( "pr: downgrade err omits signature", tostring( berr2 ):find( "LEAK", 1, true ) == nil )
end

-- download mode: stream_transfer surfaces the 302 as a redirect signal
-- when follow is on; without follow a 302 is a plain non-2xx failure
-- (unchanged behaviour). This is the download-side of the fix.
do
    local ok_, sig = run_transfer( {
        { data = "HTTP/1.1 302 Found\r\nLocation: https://cdn.example/x\r\nContent-Length: 0\r\n\r\n", err = "closed" },
    }, nil, nil, nil, nil, true )
    eq( "st: 302 with follow returns redirect signal", ok_, "redirect" )
    eq( "st: 302 redirect location surfaced", sig, "https://cdn.example/x" )

    local okN, errN = run_transfer{
        { data = "HTTP/1.1 302 Found\r\nLocation: https://cdn.example/x\r\n\r\n", err = "closed" },
    }
    ok( "st: 302 without follow still fails (unchanged)", okN == false )
    ok( "st: 302 no-follow err names status", tostring( errN ):match( "302" ) ~= nil )

    -- follow on, but a 3xx with NO Location cannot be followed -> failure
    local okL = run_transfer( {
        { data = "HTTP/1.1 304 Not Modified\r\n\r\n", err = "closed" },
    }, nil, nil, nil, nil, true )
    ok( "st: 3xx without Location not followed", okL == false )
end

-- stream_to_file propagates the redirect signal, drops the empty temp,
-- and leaves any existing good file untouched.
do
    cleanup_dl()
    local pf = assert( io.open( DL_PATH, "wb" ) ); pf:write( "GOODFEED" ); pf:close()
    local sock = mock_sock{
        { data = "HTTP/1.1 302 Found\r\nLocation: https://cdn.example/x\r\nContent-Length: 0\r\n\r\n", err = "closed" },
    }
    local ok_, sig = drive_coro( function()
        return hc._stream_to_file( sock, { download_to_file = DL_PATH }, never_expired, true )
    end )
    eq( "dl: redirect signal propagated", ok_, "redirect" )
    eq( "dl: redirect location", sig, "https://cdn.example/x" )
    local fh = io.open( DL_PATH, "rb" ); local c = fh:read( "*a" ); fh:close()
    eq( "dl: existing file preserved on redirect", c, "GOODFEED" )
    ok( "dl: tmp removed after redirect", io.open( DL_PATH .. ".tmp", "rb" ) == nil )
    ok( "dl: socket closed after redirect", sock.closed == true )
    cleanup_dl()
end

-- full drive() loop via a scripted mock tcp: prove the loop RE-ISSUES
-- each hop and completes a 302 -> 200, and that it CAPS at max_redirects.
-- http:// avoids the TLS branch. (This is the integration-level fix
-- demonstration: pre-fix, request() returned the 302 to on_complete.)
do
    -- 302 -> 200 completes with the final body
    local which = 0
    _real.socket.tcp = function()
        which = which + 1
        local first = ( which == 1 )
        local served = false
        return {
            settimeout = function() end, setoption = function() end,
            connect = function() return 1 end,
            send = function( self, p ) return #p end,
            receive = function()
                if not served then
                    served = true
                    if first then
                        return "HTTP/1.1 302 Found\r\nLocation: http://h.example/final\r\nContent-Length: 0\r\n\r\n", nil
                    end
                    return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nHI", nil
                end
                return nil, "closed"
            end,
            close = function() end,
        }
    end
    local captured, res
    _real.server = { addtimer = function( co ) captured = co end }
    hc.request{
        url = "http://h.example/a", max_redirects = 3,
        on_complete = function( r ) res = r end,
        on_error = function( e ) res = { err = e } end,
    }
    if captured then
        for _ = 1, 200 do
            if coroutine.status( captured ) == "dead" then break end
            if not coroutine.resume( captured ) then break end
        end
    end
    ok( "loop: 302 -> 200 completes", res ~= nil and res.status == 200 )
    eq( "loop: final body returned", res and res.body, "HI" )

    -- always-302 (same host) trips the hop cap; count the re-issues
    local sends = 0
    _real.socket.tcp = function()
        local served = false
        return {
            settimeout = function() end, setoption = function() end,
            connect = function() return 1 end,
            send = function( self, p ) sends = sends + 1; return #p end,
            receive = function()
                if not served then
                    served = true
                    return "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n", nil
                end
                return nil, "closed"
            end,
            close = function() end,
        }
    end
    local captured2, err2
    _real.server = { addtimer = function( co ) captured2 = co end }
    hc.request{
        url = "http://h.example/a", max_redirects = 2,
        on_complete = function() err2 = "UNEXPECTED COMPLETE" end,
        on_error = function( e ) err2 = e end,
    }
    if captured2 then
        for _ = 1, 200 do
            if coroutine.status( captured2 ) == "dead" then break end
            if not coroutine.resume( captured2 ) then break end
        end
    end
    ok( "loop: redirect cap enforced", tostring( err2 ):match( "too many redirects" ) ~= nil )
    ok( "loop: re-issued initial + 2 follows before cap", sends == 3 )
    _real.socket.tcp = nil
end

-- Finding-1 regression: an intermediate 3xx whose headers (a big signed
-- Location) exceed the caller's SMALL max_response must STILL be followed
-- (read up to MAX_HEADER_SIZE), while the final response stays capped.
-- The geoip sidecar runs exactly this shape (max_response = 4 KiB).
do
    local bigloc = "http://h.example/final?sig=" .. string.rep( "x", 400 )
    local which = 0
    _real.socket.tcp = function()
        which = which + 1
        local first = ( which == 1 )
        local served = false
        return {
            settimeout = function() end, setoption = function() end,
            connect = function() return 1 end,
            send = function( self, p ) return #p end,
            receive = function()
                if not served then
                    served = true
                    if first then
                        return "HTTP/1.1 302 Found\r\nLocation: " .. bigloc .. "\r\nContent-Length: 0\r\n\r\n", nil
                    end
                    return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nHI", nil
                end
                return nil, "closed"
            end,
            close = function() end,
        }
    end
    local captured, res
    _real.server = { addtimer = function( co ) captured = co end }
    hc.request{
        url = "http://h.example/a", max_redirects = 3, max_response = 100,
        on_complete = function( r ) res = r end,
        on_error = function( e ) res = { err = e } end,
    }
    if captured then
        for _ = 1, 200 do
            if coroutine.status( captured ) == "dead" then break end
            if not coroutine.resume( captured ) then break end
        end
    end
    ok( "loop: 3xx headers over small max_response still followed", res ~= nil and res.status == 200 )
    _real.socket.tcp = nil
end

-- download_to_file end-to-end across a redirect: 302 -> 200 streams the
-- FINAL body to disk (the loop is mode-agnostic; this closes the gap
-- between the stream_to_file signal test and the RAM loop test).
do
    local DL2 = "http_client_dlredir_test.out"
    os.remove( DL2 ); os.remove( DL2 .. ".tmp" )
    local which = 0
    _real.socket.tcp = function()
        which = which + 1
        local first = ( which == 1 )
        local served = false
        return {
            settimeout = function() end, setoption = function() end,
            connect = function() return 1 end,
            send = function( self, p ) return #p end,
            receive = function()
                if not served then
                    served = true
                    if first then
                        return "HTTP/1.1 302 Found\r\nLocation: http://h.example/final\r\nContent-Length: 0\r\n\r\n", nil
                    end
                    return "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nFEEDDATA", nil
                end
                return nil, "closed"
            end,
            close = function() end,
        }
    end
    local captured, res
    _real.server = { addtimer = function( co ) captured = co end }
    hc.request{
        url = "http://h.example/a", max_redirects = 3, download_to_file = DL2,
        on_complete = function( r ) res = r end,
        on_error = function( e ) res = { err = e } end,
    }
    if captured then
        for _ = 1, 200 do
            if coroutine.status( captured ) == "dead" then break end
            if not coroutine.resume( captured ) then break end
        end
    end
    ok( "dl-loop: 302 -> 200 download completes", res ~= nil and res.downloaded_bytes == 8 )
    local fh = io.open( DL2, "rb" ); local c = fh and fh:read( "*a" ); if fh then fh:close() end
    eq( "dl-loop: final file content", c, "FEEDDATA" )
    os.remove( DL2 ); os.remove( DL2 .. ".tmp" )
    _real.socket.tcp = nil
end

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
