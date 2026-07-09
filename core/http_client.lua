--[[

    http_client.lua - non-blocking outbound HTTP(S) client.

    luadch is single-threaded: one select() event loop in
    core/server.lua. A blocking socket.http / ssl.https call would
    freeze the WHOLE hub (every connected user) until it returned.
    This module makes outbound requests WITHOUT blocking, by driving
    a non-blocking socket through a coroutine registered on the
    existing `server.addtimer` (the same ~1s timer the HTTP-API event
    long-poll uses). It touches NO server.lua internals - only the
    public `server.addtimer` - so the inbound connection hot path is
    untouched.

    Latency note: the timer fires ~once per second, so each I/O step
    that must WAIT (connect-completion, more-data) costs up to ~1s. The
    RAM path reads one chunk per tick and yields, so a small response
    completes in 1-3 ticks (it is sized for small BACKGROUND outbound -
    hublist announce, webhooks - where a few seconds of latency is
    irrelevant, NOT a user-facing path). Stream-to-disk mode instead
    drains up to a per-tick budget before yielding so a multi-MB feed
    completes in a bounded number of ticks rather than at one chunk per
    tick (see DOWNLOAD_TICK_BUDGET).

    Security / trust model:
      - Plugins are trusted (docs/SECURITY.md s2); `socket` + `ssl`
        are already exposed to the sandbox, so this grants no new
        capability - it is the SAFE, non-blocking way to use it.
      - The helper does NOT allowlist URLs. Callers MUST NOT pass a
        URL derived from untrusted (ADC-client) input (SSRF). The
        bundled callers use operator-configured cfg URLs only.
      - Hard bounds: per-request deadline (timeout), response size
        cap, and a global in-flight cap so a buggy caller cannot
        spawn unbounded timer coroutines.
      - TLS verification: default is verify="peer" against the bundled
        Mozilla CA bundle at `certs/ca-bundle.pem` (Precursor 0b + 0d
        of #78 arc - renamed from `certs/cacert.pem` to avoid the
        path collision with cert_bootstrap.lua's inbound TLS cafile).
        Callers can pass verify="none" to opt out (self-signed
        endpoints, ephemeral test setups). When verify="peer" is in
        effect and the resolved cafile is missing on disk the request
        FAILS CLOSED with a clear error - we never silently downgrade
        to unauthenticated.

    API:
      http_client.request{
          url         = "https://host[:port]/path",  -- http:// or https://
          method      = "POST",        -- default "GET"
          body        = "...",         -- optional request body
          headers     = { ... },       -- optional extra request headers
          timeout     = 15,            -- seconds (default 15, clamped 1..120)
          max_response = 65536,        -- response byte cap (default 64 KiB)
          verify      = "peer",        -- "peer" (default) | "none" (TLS only)
          cafile      = "certs/ca-bundle.pem", -- CA bundle path; default = bundled
          max_redirects = 5,           -- optional: follow up to N HTTP
                                       -- redirects (default 0 = do not
                                       -- follow; see "Redirects" below)
          download_to_file = "cfg/feed.json", -- optional: stream the body
                                       -- to this path instead of RAM (see below)
          log_url     = "https://host/path",  -- optional: a key-free URL to
                                       -- log on failure INSTEAD of `url`. The
                                       -- failure/crash log lines below print
                                       -- the request URL; if the real `url`
                                       -- carries an API key in its query string
                                       -- or path, pass a redacted `log_url` so
                                       -- the key never reaches error.log /
                                       -- event.log. Caller builds it key-free.
          on_complete = function( res ) end,  -- res = { status, headers, body }
          on_error    = function( err ) end,  -- err = string
      }
      Returns true if the request was queued, or (false, err) if it
      was rejected synchronously (bad url / in-flight cap reached).

    Stream-to-disk mode (Precursor 0a of the #78 blocklist arc):
    pass download_to_file = "<path>" to write the response BODY straight
    to that file instead of buffering it in RAM. This lifts the response
    size from the 1 MiB RAM ceiling to a 50 MiB on-disk ceiling for
    large external feeds. In this mode:
      - only a 2xx response is written; a non-2xx status FAILS the
        request (on_error) and leaves any existing file untouched, so a
        404 / 500 error page never clobbers the last good feed file.
      - a `Transfer-Encoding: chunked` response is REJECTED (we do not
        de-chunk; writing the chunk framing would corrupt the file). Use
        an endpoint that serves a plain body with Content-Length.
      - when the response carries a Content-Length, a short read (server
        closed mid-body) is reported as a truncation and NOT committed.
      - the body is written to "<path>.tmp" and renamed onto "<path>"
        only after a complete, in-cap download (atomic on POSIX; on
        Windows a move-aside-and-rollback via "<path>.bak" keeps the last
        good file if the swap fails). A failed or partial download removes
        the temp and never replaces the file. Concurrent downloads to the
        same path are refused (the second request returns (false, err)).
        The module owns the "<path>.tmp" and "<path>.bak" siblings - do
        not point download_to_file at a path whose .tmp/.bak you rely on.
      - `max_response` does NOT apply; the body cap is MAX_DOWNLOAD_CEIL.
      - on_complete receives res = { status, headers,
        downloaded_path = "<path>", downloaded_bytes = N } and res.body
        is nil (the bytes are on disk, not in RAM).
      - throughput is bounded by the timer cadence (see the latency note
        above); pass a generous `timeout` for large feeds.
    The caller owns the path (same trust model as the URL - do NOT
    derive it from untrusted input).

    Redirects (opt-in):
    pass max_redirects = N (N > 0) to follow up to N HTTP 3xx redirects
    that carry a Location header. Default is 0 - a 3xx is then returned
    as-is in RAM mode (res.status = 302) / fails a download, exactly as
    before, so this is a non-breaking addition. Needed because some
    endpoints 302 to a signed CDN URL on a DIFFERENT host (MaxMind's
    GeoLite2 download redirects to a Cloudflare-R2 pre-signed URL). Both
    RAM and download_to_file modes follow. Security rules on every hop:
      - the target is re-parsed with the same validation as the initial
        url (http/https only, no control bytes, no embedded credentials);
      - a Location that DOWNGRADES https -> http is refused (never leak a
        request that started encrypted onto cleartext);
      - the `Authorization` / `Cookie` / `Proxy-Authorization` headers are
        DROPPED when the redirect crosses to a different origin
        (scheme/host/port), so a credential (e.g. the MaxMind Basic auth)
        is never sent to the third-party host it redirects to. NOTE: only
        those three header names are dropped - a credential carried in a
        custom header (e.g. `X-Api-Key`) would SURVIVE a cross-origin hop,
        so do not combine such a header with max_redirects;
      - the request method + body are RE-SENT unchanged on every hop
        (correct for 307/308; a 303/POST->GET rewrite is NOT performed).
        No current caller combines max_redirects with a POST body; add
        that handling before doing so;
      - hops are capped at max_redirects (and a hard MAX_REDIRECT_CEIL).
    RAM-mode size note: an intermediate 3xx is read up to MAX_HEADER_SIZE,
    NOT the caller's max_response, so a signed-CDN Location that is larger
    than a small max_response is still followed; the FINAL response is
    still bounded by max_response. (download_to_file mode already bounds
    headers separately, so it is unaffected.)
    SSRF note: a redirect TARGET is chosen by the server, not the caller,
    so following redirects widens the trust boundary from "caller passes a
    trusted url" to "that url's server picks the next host". Keep this
    opt-in and only for operator-configured endpoints; do NOT enable it
    for a url derived from untrusted (ADC-client) input.

]]--

local use = use

local type     = use "type"
local tostring = use "tostring"
local tonumber = use "tonumber"
local pcall    = use "pcall"
local pairs    = use "pairs"

local string    = use "string"
local table     = use "table"
local socket    = use "socket"
local ssl       = use "ssl"
local out       = use "out"
local io        = use "io"
local os        = use "os"
local coroutine = use "coroutine"

local coroutine_create = coroutine.create
local coroutine_yield  = coroutine.yield
local string_match     = string.match
local string_lower     = string.lower
local string_len       = string.len
local string_find      = string.find
local string_sub       = string.sub
local table_concat     = table.concat
local socket_gettime   = socket.gettime
local io_open          = io.open
local os_remove        = os.remove
local os_rename        = os.rename
local out_put          = out.put
local out_error        = out.error

-- // bounds //
local DEFAULT_TIMEOUT   = 15
local MIN_TIMEOUT       = 1
local MAX_TIMEOUT       = 120
local DEFAULT_MAX_RESP  = 64 * 1024
local MAX_RESP_CEIL     = 1024 * 1024   -- hard ceiling even if caller asks for more
local MAX_INFLIGHT      = 16            -- global cap on concurrent requests
local MAX_REDIRECT_CEIL = 10            -- hard cap on followed redirects even if caller asks for more

-- // TLS defaults (Precursor 0b + 0d of #78 arc) //
-- Bundled CA bundle ships at `<install>/certs/ca-bundle.pem` (Mozilla
-- snapshot extracted by curl.se from Firefox's NSS certdata.txt).
-- Default verify mode flipped from "none" -> "peer" so outbound
-- HTTPS authenticates the remote against trusted CAs out of the
-- box; callers can still opt out explicitly with verify="none".
--
-- Renamed from `certs/cacert.pem` in Precursor 0d to avoid the path
-- collision with cert_bootstrap.lua, which writes the self-signed
-- TLS-listener cert AT THAT PATH as a satisfy-existence-check for
-- ssl_params.cafile (the INBOUND mutual-TLS use case). Two roles,
-- two paths now.
local DEFAULT_VERIFY    = "peer"
local DEFAULT_CAFILE    = "certs/ca-bundle.pem"
local READ_CHUNK        = 16 * 1024

-- // stream-to-disk download mode (Precursor 0a of #78 arc) //
-- A caller passing download_to_file streams the response BODY straight
-- to a file instead of buffering it in RAM, so feeds far larger than
-- MAX_RESP_CEIL (e.g. AbuseIPDB ships a ~10 MB JSON blacklist) can be
-- fetched in-hub without RAM pressure. The body is bounded by
-- MAX_DOWNLOAD_CEIL; the response HEADERS are still buffered in RAM (to
-- find the header/body boundary + parse the status line) and bounded
-- SEPARATELY by MAX_HEADER_SIZE, so a server that never sends the
-- \r\n\r\n terminator cannot grow the RAM buffer without limit.
local MAX_DOWNLOAD_CEIL = 50 * 1024 * 1024   -- body cap for download_to_file mode
local MAX_HEADER_SIZE   = 64 * 1024          -- response-header cap (download mode)
-- Bytes the download loop may drain per timer resume before it yields.
-- The hub timer resumes a background coroutine at most ~once per second
-- (core/server.lua), so yielding after every 16 KiB READ_CHUNK (what the
-- RAM path does) would cap a download at ~16 KiB/s and make a multi-MB
-- feed time out. Instead the download loop keeps reading while the socket
-- still has a full chunk buffered and only yields when the socket would
-- block OR this budget is reached - so effective throughput rises to
-- roughly the socket-buffer refill per tick, while a fast/local peer that
-- can refill the buffer indefinitely still cannot pin the single hub
-- thread for more than one budget's worth of work per tick.
local DOWNLOAD_TICK_BUDGET = 1024 * 1024

local _inflight = 0
-- final paths with a download in flight; guards against two concurrent
-- download_to_file requests writing/renaming the same target (their
-- shared <path>.tmp would otherwise interleave into a corrupt file).
local _dl_active = { }

-- Reject CR/LF (and other control bytes) in any value that gets
-- interpolated into the request line / headers - otherwise a caller
-- (or an operator-cfg value) carrying "\r\n" could split the request
-- or smuggle extra headers. Network-I/O input validation per
-- CLAUDE.md s1a.1, regardless of the trusted-caller model.
local function has_ctrl( s )
    return type( s ) ~= "string" or string_find( s, "[%c]" ) ~= nil
end

-- Parse a URL into ( scheme, host, port, path ) or ( nil, err ).
-- `host` is returned WITHOUT brackets for IPv6 literals; the caller
-- detects v6 by a ":" in host (a hostname / IPv4 literal never has
-- one). Deliberately small: we control the URLs (operator cfg). No
-- auth / query / fragment handling beyond passing the path through.
-- Does NOT allowlist the host (caller's responsibility - see SSRF
-- note in the header); but DOES reject control bytes + embedded
-- credentials.
--
-- DNS caveat: a HOSTNAME url makes the later sock:connect() do a
-- synchronous getaddrinfo (luasocket has no async resolver), i.e. a
-- brief block while the OS resolves it. IP literals (v4 or bracketed
-- v6) skip DNS entirely and are fully non-blocking. For the
-- background-announce use case a brief resolver hit is acceptable;
-- operators wanting strict non-blocking can use an IP literal.
local function parse_url( url )
    if type( url ) ~= "string" then return nil, "url must be a string" end
    if has_ctrl( url ) then return nil, "url contains control bytes" end
    local scheme, hostport, path = string_match( url, "^(%w+)://([^/]+)(/?.*)$" )
    if not scheme then return nil, "malformed url" end
    scheme = string_lower( scheme )
    if scheme ~= "http" and scheme ~= "https" then
        return nil, "unsupported scheme '" .. scheme .. "' (http/https only)"
    end
    if string_find( hostport, "@" ) then
        return nil, "embedded credentials in url not supported"
    end
    local host, port
    if string_find( hostport, "^%[" ) then
        -- bracketed IPv6 literal: [2001:db8::1]:443
        host, port = string_match( hostport, "^%[([%x:]+)%]:?(%d*)$" )
        if not host then return nil, "malformed IPv6 literal" end
    else
        host, port = string_match( hostport, "^([^:]+):?(%d*)$" )
    end
    if not host or host == "" then return nil, "missing host" end
    port = tonumber( port )
    if not port then port = ( scheme == "https" ) and 443 or 80 end
    if port < 1 or port > 65535 then return nil, "port out of range" end
    if path == "" then path = "/" end
    return scheme, host, port, path
end

-- Build the raw HTTP/1.1 request bytes. Connection: close so the
-- server closes after the response and our read loop ends on EOF.
-- IPv6-literal hosts are re-bracketed in the Host header.
local function build_request( method, host, port, path, body, headers )
    local host_hdr = string_find( host, ":", 1, true ) and ( "[" .. host .. "]" ) or host
    local lines = {
        method .. " " .. path .. " HTTP/1.1",
        "Host: " .. host_hdr .. ( ( port ~= 80 and port ~= 443 ) and ( ":" .. port ) or "" ),
        "Connection: close",
        "User-Agent: luadch-http-client",
    }
    local have = { host = true, connection = true, [ "user-agent" ] = true, [ "content-length" ] = true }
    if headers then
        for k, v in pairs( headers ) do
            if not have[ string_lower( k ) ] then
                lines[ #lines + 1 ] = k .. ": " .. v
            end
        end
    end
    if body and body ~= "" then
        lines[ #lines + 1 ] = "Content-Length: " .. string_len( body )
    end
    return table_concat( lines, "\r\n" ) .. "\r\n\r\n" .. ( body or "" )
end

-- Parse a complete raw HTTP response into { status, headers, body }.
local function parse_response( raw )
    local head, body = string_match( raw, "^(.-)\r\n\r\n(.*)$" )
    if not head then
        -- No header terminator seen (truncated / non-HTTP). Treat the
        -- whole thing as head, empty body.
        head, body = raw, ""
    end
    local status = tonumber( string_match( head, "^HTTP/%d%.%d%s+(%d%d%d)" ) )
    local headers = {}
    local first = true
    for line in head:gmatch( "([^\r\n]+)" ) do
        if first then
            first = false
        else
            local k, v = string_match( line, "^([^:]+):%s*(.*)$" )
            if k then headers[ string_lower( k ) ] = v end
        end
    end
    return { status = status, headers = headers, body = body }
end

-- Request headers that must NOT survive a redirect to a DIFFERENT origin
-- (RFC 9110 s15.4 / browser + curl behaviour). Forwarding the MaxMind
-- Basic credential to the Cloudflare-R2 signed URL it 302s to would leak
-- it to a third party. Keys are compared case-insensitively.
local SENSITIVE_HEADERS = {
    [ "authorization" ]       = true,
    [ "cookie" ]              = true,
    [ "proxy-authorization" ] = true,
}

-- Return a copy of `headers` with the sensitive keys removed. If nothing
-- sensitive was present the original table is returned unchanged (a nil
-- table passes straight through).
local function strip_sensitive( headers )
    if type( headers ) ~= "table" then return headers end
    local kept, dropped = {}, false
    for k, v in pairs( headers ) do
        if SENSITIVE_HEADERS[ string_lower( k ) ] then
            dropped = true
        else
            kept[ k ] = v
        end
    end
    if not dropped then return headers end
    return kept
end

-- Resolve a redirect Location against the base request URL into an
-- absolute URL string, or (nil, err). Handles the four forms our feeds
-- actually emit: absolute (scheme://...), scheme-relative (//host/path),
-- absolute-path (/path) and a plain relative path. Deliberately minimal -
-- just enough RFC 3986 reference resolution for operator endpoints.
local function resolve_location( scheme, host, port, path, loc )
    if type( loc ) ~= "string" or loc == "" then return nil, "empty Location" end
    if has_ctrl( loc ) then return nil, "Location contains control bytes" end
    if string_find( loc, "^%w+://" ) then return loc end          -- absolute
    local authority = string_find( host, ":", 1, true ) and ( "[" .. host .. "]" ) or host
    if ( scheme == "https" and port ~= 443 ) or ( scheme == "http" and port ~= 80 ) then
        authority = authority .. ":" .. port
    end
    if string_find( loc, "^//" ) then return scheme .. ":" .. loc end          -- scheme-relative
    if string_sub( loc, 1, 1 ) == "/" then return scheme .. "://" .. authority .. loc end   -- absolute path
    local dir = string_match( path, "^(.*/)" ) or "/"             -- relative path
    return scheme .. "://" .. authority .. dir .. loc
end

-- Given the current hop's url + headers and a raw Location value, produce
-- the ( next_url, next_headers ) to request, or ( nil, err ). Re-validates
-- the target with parse_url, refuses an https->http downgrade, and drops
-- the sensitive headers on a cross-origin hop. Error strings deliberately
-- name only the host, never the full (possibly signature-bearing) target
-- URL, so nothing sensitive reaches the log.
local function prepare_redirect( cur_url, headers, loc )
    local cs, ch, cp, cpath = parse_url( cur_url )
    if not cs then return nil, "cannot parse current url for redirect" end
    local nurl, rerr = resolve_location( cs, ch, cp, cpath, loc )
    if not nurl then return nil, "bad redirect Location: " .. tostring( rerr ) end
    local ns, nh, np = parse_url( nurl )
    if not ns then return nil, "invalid redirect target (" .. tostring( nh ) .. ")" end
    if cs == "https" and ns == "http" then
        return nil, "refusing https->http redirect downgrade to host " .. nh
    end
    local nheaders = headers
    if ns ~= cs or nh ~= ch or np ~= cp then
        nheaders = strip_sensitive( headers )
    end
    return nurl, nheaders
end

local function safe_cb( fn, arg )
    if type( fn ) == "function" then
        local ok, err = pcall( fn, arg )
        if not ok then
            out_error( "http_client: callback raised: " .. tostring( err ) )
        end
    end
end

-- Receive an HTTP response and stream its BODY into the open file
-- handle `f` (download_to_file mode).
--
-- Two phases in one loop:
--   header phase - accumulate bytes in RAM until the \r\n\r\n terminator
--     is seen (the header portion is bounded by max_head), then parse the
--     status line + headers. The terminator may straddle a read boundary,
--     so we search the whole accumulated buffer, not the latest chunk.
--   body phase   - write every subsequent byte straight to `f`, counting
--     toward max_body.
--
-- Integrity: only a 2xx response is accepted (a non-2xx status returns an
-- error BEFORE any byte is written, so the caller leaves the last good
-- file in place); a `Transfer-Encoding: chunked` response is rejected
-- (we do not de-chunk, and writing the chunk framing would silently
-- corrupt the file); and when the response carries a Content-Length a
-- short read (server closed mid-body) is reported as a truncation rather
-- than committed. A response with neither Content-Length nor chunked is
-- close-delimited and EOF is taken as complete (best effort - that is all
-- the framing offers).
--
-- Throughput: the loop keeps reading while the socket still hands back a
-- full chunk and only yields when the socket would block or the per-tick
-- DOWNLOAD_TICK_BUDGET is reached; see the constant for why.
--
-- Returns:
--   true, res, body_bytes   on success (res = { status, headers },
--                           res.body = nil)
--   false, err              on any handled failure
-- Does NOT close `f` / the socket and does NOT rename - the caller
-- (stream_to_file) owns those so cleanup is guaranteed on every path.
local function stream_transfer( sock, expired, f, max_body, max_head, tick_budget, follow )
    max_body     = max_body or MAX_DOWNLOAD_CEIL
    max_head     = max_head or MAX_HEADER_SIZE
    tick_budget  = tick_budget or DOWNLOAD_TICK_BUDGET

    local head_buf = {}
    local head_done = false
    local res
    local body_bytes = 0
    local expected_len          -- Content-Length, or nil (close-delimited)
    local tick_bytes = 0        -- bytes drained since the last yield

    local function write_body( piece )
        body_bytes = body_bytes + string_len( piece )
        if body_bytes > max_body then
            return false, "download exceeds " .. max_body .. " byte cap"
        end
        local wok, werr = f:write( piece )
        if not wok then return false, "file write failed: " .. tostring( werr ) end
        return true
    end

    while true do
        if expired( ) then
            return false, head_done and "read timeout (body)" or "read timeout (headers)"
        end
        local data, rerr, partial = sock:receive( READ_CHUNK )
        local piece = data or partial
        if piece and piece ~= "" then
            tick_bytes = tick_bytes + string_len( piece )
            if not head_done then
                head_buf[ #head_buf + 1 ] = piece
                local joined = table_concat( head_buf )
                local _, he = string_find( joined, "\r\n\r\n", 1, true )
                if he then
                    -- header portion is `he` bytes (incl. the terminator);
                    -- body bytes past it do NOT count against the header cap
                    if he > max_head then
                        return false, "response headers exceed " .. max_head .. " byte cap"
                    end
                    head_done = true
                    res = parse_response( string_sub( joined, 1, he ) )
                    res.body = nil
                    local st = res.status
                    -- follow a redirect (opt-in) BEFORE the 2xx gate: a
                    -- 3xx with a Location is not a failure, it is the next
                    -- hop. Signalled up so the caller re-issues; no byte of
                    -- the (empty) 3xx body is written, so the last-good file
                    -- is untouched.
                    if follow and type( st ) == "number" and st >= 300 and st <= 399 then
                        local loc = res.headers[ "location" ]
                        if loc and loc ~= "" then
                            return "redirect", loc
                        end
                    end
                    if type( st ) ~= "number" or st < 200 or st > 299 then
                        return false, "server returned HTTP status " .. tostring( st )
                    end
                    local te = res.headers[ "transfer-encoding" ]
                    if te and string_find( string_lower( te ), "chunked", 1, true ) then
                        return false, "chunked transfer-encoding not supported in download mode"
                    end
                    local cl = tonumber( res.headers[ "content-length" ] )
                    if cl and cl >= 0 then expected_len = cl end
                    local leftover = string_sub( joined, he + 1 )
                    if leftover ~= "" then
                        local wok, werr = write_body( leftover )
                        if not wok then return false, werr end
                    end
                elseif #joined > max_head then
                    -- still accumulating headers and already over the cap
                    return false, "response headers exceed " .. max_head .. " byte cap"
                end
            else
                local wok, werr = write_body( piece )
                if not wok then return false, werr end
            end
        end
        if rerr == "closed" then
            if not head_done then
                return false, "connection closed before response headers were complete"
            end
            if expected_len and body_bytes ~= expected_len then
                return false, "truncated download: got " .. body_bytes ..
                    " of " .. expected_len .. " body bytes"
            end
            break    -- EOF: complete body received
        elseif rerr == nil then
            -- a full READ_CHUNK was read and more may be buffered. Keep
            -- draining within this tick until the per-tick budget is hit,
            -- THEN yield - so a multi-MB feed finishes in a bounded number
            -- of 1 Hz timer ticks instead of at 16 KiB/tick, while a peer
            -- that can refill the buffer indefinitely (loopback) cannot
            -- pin the hub thread for more than one budget's work per tick.
            if tick_bytes >= tick_budget then
                tick_bytes = 0
                coroutine_yield( )
            end
        elseif rerr == "wantread" or rerr == "wantwrite" or rerr == "timeout" then
            -- socket has nothing more buffered right now: yield and let the
            -- timer resume us (with a fresh budget) once data has arrived
            tick_bytes = 0
            coroutine_yield( )
        else
            return false, "read failed: " .. tostring( rerr )
        end
    end

    return true, res, body_bytes
end

-- Wrap stream_transfer with the file lifecycle: open <path>.tmp, run the
-- transfer under pcall (a leaked file handle keeps a lock on the temp on
-- Windows and blocks the cleanup remove), then close + rename on success
-- or close + remove on any failure. Concurrent downloads to the same
-- final path are refused up front in request(), so the fixed .tmp name is
-- collision-free.
local function stream_to_file( sock, req, expired, follow )
    local final_path = req.download_to_file
    local tmp_path   = final_path .. ".tmp"
    local f, ferr = io_open( tmp_path, "wb" )
    if not f then
        sock:close( )
        return false, "cannot open download temp '" .. tmp_path .. "': " .. tostring( ferr )
    end

    local pok, ok, res_or_err, nbytes = pcall( stream_transfer, sock, expired, f, nil, nil, nil, follow )

    -- Always release the handle. A failed flush at close (e.g. the disk
    -- filled and the last buffered bytes never landed) must FAIL the
    -- download, not commit a silently-truncated file - so capture the
    -- close result and treat it as a transfer failure below.
    local cok, cerr = f:close( )
    sock:close( )

    if not pok then
        os_remove( tmp_path )
        return false, "download crashed: " .. tostring( ok )
    end
    -- redirect: nothing was written (the 3xx is caught before the body),
    -- so drop the empty temp and hand the Location up for the caller to
    -- follow - the existing file on disk is left untouched.
    if ok == "redirect" then
        os_remove( tmp_path )
        return "redirect", res_or_err
    end
    if not ok then
        os_remove( tmp_path )
        return false, res_or_err
    end
    if not cok then
        os_remove( tmp_path )
        return false, "flushing download to '" .. tmp_path .. "' failed: " .. tostring( cerr )
    end

    -- Atomic move tmp -> final. POSIX rename replaces the target
    -- atomically. Windows rename refuses an existing target, so we move
    -- the current file aside first and roll it back if the swap then
    -- fails (a transient AV / indexer lock on tmp must not lose the last
    -- good file - the failure mode of a plain remove-then-rename).
    local rok, rerr = os_rename( tmp_path, final_path )
    if not rok then
        local bak = final_path .. ".bak"
        os_remove( bak )
        local had_final = os_rename( final_path, bak )    -- nil if final absent
        rok, rerr = os_rename( tmp_path, final_path )
        if rok then
            if had_final then os_remove( bak ) end
        elseif had_final then
            -- swap failed; put the previous file back. If even that fails
            -- (final slot still locked) the good copy is stranded at .bak -
            -- log it so the operator can recover it manually.
            if not os_rename( bak, final_path ) then
                out_error( "http_client: download swap for '", final_path,
                    "' failed and the previous file could not be restored; ",
                    "it is preserved at '", bak, "'" )
            end
        end
    end
    if not rok then
        os_remove( tmp_path )
        return false, "rename '" .. tmp_path .. "' -> '" .. final_path .. "' failed: " .. tostring( rerr )
    end

    res_or_err.downloaded_path  = final_path
    res_or_err.downloaded_bytes = nbytes
    return true, res_or_err
end

-- One HTTP exchange to `url` with `headers`, driven by the shared
-- `expired` deadline. Never blocks. Returns one of:
--   true, res            success (RAM: res.body set / download: res meta)
--   false, err           handled failure
--   "redirect", location  a 3xx with a Location header, when the caller
--                        opted into following (req.max_redirects > 0) - the
--                        outer drive() loop resolves + re-issues.
-- Splitting the single exchange out of the redirect loop keeps ONE
-- deadline across all hops (a chain cannot exceed req.timeout total).
local function drive_once( req, url, headers, expired )
    local follow = ( req.max_redirects or 0 ) > 0

    local scheme, host, port, path = parse_url( url )
    -- (parse already validated by request()/prepare_redirect; cheap to redo)

    -- IPv6 literal (host carries a ":") needs an AF_INET6 socket;
    -- everything else (IPv4 literal / hostname) uses AF_INET.
    local is_v6 = string_find( host, ":", 1, true ) ~= nil
    local sock, err
    if is_v6 then
        if type( socket.tcp6 ) ~= "function" then
            return false, "IPv6 literal given but luasocket has no tcp6"
        end
        sock, err = socket.tcp6( )
    else
        sock, err = socket.tcp( )
    end
    if not sock then return false, "socket create failed: " .. tostring( err ) end
    sock:settimeout( 0 )

    -- Stream-to-disk downloads are drained at most once per ~1 s timer
    -- tick, so throughput is bounded by how much the OS buffers between
    -- ticks. Ask for a larger receive buffer up front (before connect, so
    -- window scaling can use it) to raise that per-tick ceiling toward the
    -- drain budget. Best-effort: the OS may clamp it and setoption is only
    -- valid on the plain socket, so wrap it - a failure only means the
    -- default (smaller) buffer, i.e. a slower download, never incorrect.
    if req.download_to_file then
        pcall( function( ) sock:setoption( "recv-buffer-size", 4 * 1024 * 1024 ) end )
    end

    -- // connect (non-blocking) //
    local ok
    ok, err = sock:connect( host, port )
    while not ok and ( err == "timeout" or err == "Operation already in progress" ) do
        if expired( ) then sock:close( ); return false, "connect timeout" end
        coroutine_yield( )
        ok, err = sock:connect( host, port )
        -- a completed non-blocking connect re-reports as this:
        if err == "already connected" then ok, err = true, nil end
    end
    if not ok and err ~= "already connected" then
        sock:close( ); return false, "connect failed: " .. tostring( err )
    end

    -- // TLS handshake (https) //
    if scheme == "https" then
        -- Floor at TLS 1.2: protocol="any" but disable SSLv3 / TLS 1.0
        -- / TLS 1.1 via options, so a downgrade to a broken protocol
        -- is not silently accepted even with verify="none".
        --
        -- Precursor 0b + 0d of #78 arc: default verify mode is "peer"
        -- with the bundled Mozilla CA bundle at `certs/ca-bundle.pem`
        -- (managed by core/cacert_bootstrap.lua at boot time). Callers
        -- pass verify="none" explicitly to opt out (e.g. self-signed
        -- internal endpoints). If verify resolves to "peer" but the
        -- caller passed neither verify=none nor a cafile AND the
        -- bundled file is missing on disk, we FAIL CLOSED with a clear
        -- error rather than silently falling back to verify=none -
        -- the whole point of bundling the CA file is to make verified
        -- the default outcome.
        -- Empty-string treated as unset; otherwise `cafile = ""`
        -- silently lands a bogus path in resolved_cafile and the
        -- probe below fails with an uninformative error message.
        local caller_cafile = ( req.cafile and req.cafile ~= "" ) and req.cafile or nil
        local resolved_verify = req.verify or DEFAULT_VERIFY
        local resolved_cafile = caller_cafile or DEFAULT_CAFILE
        if resolved_verify == "peer" then
            local f = io_open( resolved_cafile, "r" )
            if not f then
                sock:close( )
                local hint
                if caller_cafile then
                    -- Caller supplied an explicit path that is missing on disk.
                    hint = "verify=peer; the supplied cafile path does not exist"
                else
                    -- No caller cafile -> we resolved to the bundled default.
                    hint = "verify=peer; the bundled ca-bundle.pem is missing - " ..
                        "let core/cacert_bootstrap restore it on next boot, " ..
                        "pass cafile=<path> for a custom bundle, or " ..
                        "pass verify=\"none\" to opt out of authentication"
                end
                return false, "cafile not found: " .. resolved_cafile .. " (" .. hint .. ")"
            end
            f:close( )
        end
        local params = {
            mode     = "client",
            protocol = "any",
            verify   = resolved_verify,
            options  = { "all", "no_sslv3", "no_tlsv1", "no_tlsv1_1" },
            -- LuaSec ignores cafile when verify="none"; drop it so the
            -- params table reflects the actual security posture exactly.
            cafile   = ( resolved_verify == "peer" ) and resolved_cafile or nil,
        }
        local wrapped
        wrapped, err = ssl.wrap( sock, params )
        if not wrapped then sock:close( ); return false, "ssl.wrap failed: " .. tostring( err ) end
        sock = wrapped
        sock:settimeout( 0 )
        if sock.sni then pcall( function( ) sock:sni( host ) end ) end
        local hok
        hok, err = sock:dohandshake( )
        while not hok and ( err == "wantread" or err == "wantwrite" or err == "timeout" ) do
            if expired( ) then sock:close( ); return false, "tls handshake timeout" end
            coroutine_yield( )
            hok, err = sock:dohandshake( )
        end
        if not hok then sock:close( ); return false, "tls handshake failed: " .. tostring( err ) end
    end

    -- // send request (handle partial writes) //
    local payload = build_request( req.method, host, port, path, req.body, headers )
    local sent = 0
    local total = string_len( payload )
    while sent < total do
        if expired( ) then sock:close( ); return false, "send timeout" end
        local n, serr, partial = sock:send( payload, sent + 1 )
        if n then
            sent = n
        elseif serr == "wantwrite" or serr == "wantread" or serr == "timeout" then
            sent = partial or sent
            coroutine_yield( )
        else
            sock:close( ); return false, "send failed: " .. tostring( serr )
        end
    end

    -- // receive: stream the body to disk, or accumulate in RAM //
    if req.download_to_file then
        return stream_to_file( sock, req, expired, follow )
    end

    -- // receive response (accumulate until close or cap) //
    -- When following redirects, read an intermediate 3xx up to
    -- MAX_HEADER_SIZE rather than the caller's max_response: a signed CDN
    -- Location plus provider headers can exceed a small body cap (the
    -- geoip sidecar sets max_response = 4 KiB), and that 3xx is not the
    -- body the caller asked to size. The FINAL (non-redirect) response is
    -- re-checked against the caller's real max_response after parsing.
    local read_cap = req.max_response
    if follow and MAX_HEADER_SIZE > read_cap then read_cap = MAX_HEADER_SIZE end
    local chunks = {}
    local got = 0
    while true do
        if expired( ) then sock:close( ); return false, "read timeout" end
        local data, rerr, partial = sock:receive( READ_CHUNK )
        local piece = data or partial
        if piece and piece ~= "" then
            got = got + string_len( piece )
            if got > read_cap then
                sock:close( ); return false, "response exceeds max_response cap"
            end
            chunks[ #chunks + 1 ] = piece
        end
        if rerr == "closed" then
            break    -- EOF: full response received
        elseif rerr == nil or rerr == "wantread" or rerr == "wantwrite" or rerr == "timeout" then
            -- Always yield back to the select loop between reads -
            -- including after a full READ_CHUNK (rerr == nil). Never
            -- loop on the socket without yielding, so a fast / large
            -- response can never pin the single hub thread. Total
            -- bytes are still bounded by max_response.
            coroutine_yield( )
        else
            sock:close( ); return false, "read failed: " .. tostring( rerr )
        end
    end
    sock:close( )

    local res = parse_response( table_concat( chunks ) )
    -- follow a redirect (opt-in): a 3xx with a Location is the next hop,
    -- not the final response. Without follow, the 3xx is returned as-is
    -- (unchanged behaviour). A 3xx WITHOUT a Location (e.g. 304) falls
    -- through and is returned to the caller.
    if follow then
        local st = res.status
        if type( st ) == "number" and st >= 300 and st <= 399 then
            local loc = res.headers[ "location" ]
            if loc and loc ~= "" then
                return "redirect", loc
            end
        end
        -- not a redirect: this is the final response, so the raised
        -- read_cap no longer applies - re-assert the caller's real cap.
        if got > req.max_response then
            return false, "response exceeds max_response cap"
        end
    end
    return true, res
end

-- Redirect-following wrapper around drive_once. Owns the shared deadline
-- (so a redirect chain cannot exceed req.timeout in total), the hop
-- counter, and the per-hop URL resolution + cross-origin auth-strip. Only
-- ever returns the true/false outcomes drive_once yields - a "redirect"
-- signal is consumed here, never escapes to request()'s coroutine wrapper.
local function drive( req )
    local deadline = socket_gettime( ) + req.timeout
    local function expired( ) return socket_gettime( ) > deadline end

    local url          = req.url
    local headers      = req.headers
    local max_redirects = req.max_redirects or 0
    local hops = 0
    while true do
        local outcome, a, b = drive_once( req, url, headers, expired )
        if outcome ~= "redirect" then
            return outcome, a, b
        end
        hops = hops + 1
        if hops > max_redirects then
            return false, "too many redirects (limit " .. max_redirects .. ")"
        end
        local nurl, nheaders = prepare_redirect( url, headers, a )
        if not nurl then return false, nheaders end   -- nheaders is the err string
        url, headers = nurl, nheaders
    end
end

local request

request = function( req )
    if type( req ) ~= "table" then return false, "request: arg must be a table" end
    if type( req.url ) ~= "string" then return false, "request: url required" end

    -- validate url synchronously so the caller gets immediate feedback
    local scheme, perr = parse_url( req.url )
    if not scheme then return false, perr end

    -- CRLF / control-byte guard on everything that gets interpolated
    -- into the request line + headers (anti request-smuggling).
    req.method = req.method or "GET"
    if has_ctrl( req.method ) then return false, "method contains control bytes" end
    if req.body ~= nil and type( req.body ) ~= "string" then
        return false, "body must be a string"
    end
    if req.headers ~= nil then
        if type( req.headers ) ~= "table" then return false, "headers must be a table" end
        for k, v in pairs( req.headers ) do
            if has_ctrl( k ) or has_ctrl( tostring( v ) ) then
                return false, "header contains control bytes"
            end
        end
    end
    if req.download_to_file ~= nil then
        if type( req.download_to_file ) ~= "string" or req.download_to_file == "" then
            return false, "download_to_file must be a non-empty path string"
        end
        if has_ctrl( req.download_to_file ) then
            return false, "download_to_file path contains control bytes"
        end
    end
    if req.log_url ~= nil then
        -- Optional key-free URL logged in place of req.url on failure /
        -- crash (the two out.* lines below), so an API key carried in the
        -- real url's query string or path never reaches the log. Caller-
        -- built; validated for type + control bytes only (it is only ever
        -- logged, never used for the connection).
        if type( req.log_url ) ~= "string" then return false, "log_url must be a string" end
        if has_ctrl( req.log_url ) then return false, "log_url contains control bytes" end
    end

    if _inflight >= MAX_INFLIGHT then
        return false, "http_client: in-flight cap (" .. MAX_INFLIGHT .. ") reached"
    end
    if req.download_to_file and _dl_active[ req.download_to_file ] then
        return false, "http_client: a download to '" .. req.download_to_file .. "' is already in progress"
    end

    -- normalise + clamp
    local t = tonumber( req.timeout ) or DEFAULT_TIMEOUT
    if t < MIN_TIMEOUT then t = MIN_TIMEOUT elseif t > MAX_TIMEOUT then t = MAX_TIMEOUT end
    req.timeout = t
    local m = tonumber( req.max_response ) or DEFAULT_MAX_RESP
    if m < 1 then m = DEFAULT_MAX_RESP elseif m > MAX_RESP_CEIL then m = MAX_RESP_CEIL end
    req.max_response = m
    -- redirect following: opt-in, default 0 (no follow = unchanged
    -- behaviour), clamped to a hard ceiling.
    local rd = tonumber( req.max_redirects ) or 0
    if rd < 0 then rd = 0 elseif rd > MAX_REDIRECT_CEIL then rd = MAX_REDIRECT_CEIL end
    req.max_redirects = rd

    local server = use "server"
    if type( server.addtimer ) ~= "function" then
        return false, "http_client: server.addtimer unavailable"
    end

    _inflight = _inflight + 1
    if req.download_to_file then _dl_active[ req.download_to_file ] = true end
    -- URL to show in the failure/crash logs: the redacted log_url when the
    -- caller supplied a NON-EMPTY one (key in the real url), else the url
    -- itself. "" is treated as unset (mirrors the cafile handling) so a
    -- blank log_url never yields a useless empty URL in the log.
    local log_url = req.url
    if req.log_url and req.log_url ~= "" then log_url = req.log_url end
    local co = coroutine_create( function( )
        -- pcall so a thrown error in drive() still decrements
        -- _inflight (otherwise a crash leaks an in-flight slot and,
        -- after MAX_INFLIGHT crashes, the helper jams). server.lua's
        -- timer loop ignores coroutine.resume errors, so we MUST
        -- handle them here.
        local pok, a, b = pcall( drive, req )
        _inflight = _inflight - 1
        if req.download_to_file then _dl_active[ req.download_to_file ] = nil end
        if not pok then
            out_error( "http_client: request to ", tostring( log_url ), " crashed: ", tostring( a ) )
            safe_cb( req.on_error, "internal error" )
        elseif a == true then
            safe_cb( req.on_complete, b )
        else
            out_put( "http_client: request to ", tostring( log_url ), " failed: ", tostring( a == false and b or a ) )
            safe_cb( req.on_error, ( a == false and b ) or a )
        end
    end )
    server.addtimer( co )
    return true
end

return {
    request        = request,
    -- exposed for unit tests
    _parse_url     = parse_url,
    _build_request = build_request,
    _parse_response = parse_response,
    _has_ctrl      = has_ctrl,
    _stream_transfer = stream_transfer,
    _stream_to_file  = stream_to_file,
    _strip_sensitive   = strip_sensitive,
    _resolve_location  = resolve_location,
    _prepare_redirect  = prepare_redirect,
}
