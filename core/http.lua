--[[

        http.lua - HTTP transport interface (Phase 8 S3 + Phase 1b of #82).

        This module is the THIN transport-level interface to the
        server.lua listener wiring and the iostream.newhttpstage
        framer. It owns HTTP-bytes-level concerns:
          - status code -> reason phrase table
          - low-level response builder (headers + body, no envelope)
          - log line sanitisation
          - listener-spec factory for server.addserver
          - the listener entrypoint (server.lua -> http.incoming)

        ROUTE DISPATCH + AUTH + ENVELOPE + JSON + RATE-LIMIT + AUDIT
        + ALL THE API LOGIC live in core/http_router.lua. This file
        is intentionally minimal so transport hardening stays small,
        focused and testable while the API surface grows over later
        phases. Mirrors the hub.lua / hub_dispatch.lua split.

        Phase-8 S3 backward compat: NOT preserved. /health is now a
        registered endpoint in http_router.lua (still unversioned,
        still unauthenticated, still text/plain "ok"). The 3.2.x
        release line means we are free to swap the dispatch path
        wholesale.

        Security notes (still apply, defence in depth on top of
        what the framer + router enforce):
          - no `Server` header (no version fingerprint pre-auth)
          - fixed minimal headers, explicit Content-Length, always
            Connection: close
          - transport hardening already happened in the framer; a
            { reject = <status> } unit is forwarded to the router
            which renders the canned response
          - log lines sanitise via logsafe (control bytes already
            rejected upstream - defence in depth, no log injection)

]]--

----------------------------------// DECLARATION //--

local use = use

local type = use "type"
local string = use "string"
local iostream = use "iostream"
local http_router = use "http_router"

local string_sub = string.sub
local string_gsub = string.gsub
local string_rep = string.rep
local tostring = use "tostring"
local tonumber = use "tonumber"
local pairs = use "pairs"

local _status
local response
local logsafe
local http_incoming
local http_disconnect

----------------------------------// DEFINITION //--

-- Status code -> reason phrase. The full set the router can emit;
-- if a future error code lands here, this table needs the row.
_status = {
    [ 200 ] = "200 OK",
    [ 201 ] = "201 Created",
    -- 202 only appears in audit-log lines today (deferred long-poll
    -- handlers return status="deferred" and audit_log writes 202;
    -- the real wire reply is emitted via the handler's defer callback
    -- once the wait resolves). Keep the row here for completeness so
    -- a future endpoint that emits 202 directly does not fall back to
    -- the default "202 Status" reason line. (#275 CON-N4 / C4)
    [ 202 ] = "202 Accepted",
    [ 204 ] = "204 No Content",
    [ 400 ] = "400 Bad Request",
    [ 401 ] = "401 Unauthorized",
    [ 403 ] = "403 Forbidden",
    [ 404 ] = "404 Not Found",
    [ 405 ] = "405 Method Not Allowed",
    [ 409 ] = "409 Conflict",
    [ 413 ] = "413 Payload Too Large",
    [ 414 ] = "414 URI Too Long",
    [ 415 ] = "415 Unsupported Media Type",
    [ 429 ] = "429 Too Many Requests",
    [ 431 ] = "431 Request Header Fields Too Large",
    [ 500 ] = "500 Internal Server Error",
    [ 505 ] = "505 HTTP Version Not Supported",
}

-- Low-level response builder. `extra_headers` is an optional table
-- of additional header lines (e.g. Allow, Retry-After, X-Request-
-- ID). `content_type` overrides the default application/json (the
-- router uses text/plain for /health and for framer-reject pages).
-- If `headonly` is true, body is omitted from the wire (HEAD); the
-- declared Content-Length still matches what GET would have sent.
response = function( status, body, content_type, extra_headers, headonly )
    local line = _status[ status ] or ( tostring( status ) .. " Status" )
    body = body or ""
    local ct = content_type or "application/json; charset=utf-8"
    local head = "HTTP/1.1 " .. line .. "\r\n"
        .. "Content-Type: " .. ct .. "\r\n"
        .. "Content-Length: " .. #body .. "\r\n"
        .. "Connection: close\r\n"
    if extra_headers then
        for k, v in pairs( extra_headers ) do
            -- skip the synthetic CL-override marker the router uses
            -- to tell us "this is a HEAD response; CL=N but body
            -- empty".
            if k ~= "Content-Length-Override" then
                head = head .. k .. ": " .. tostring( v ) .. "\r\n"
            end
        end
    end
    head = head .. "\r\n"
    if headonly then
        return head
    end
    return head .. body
end

-- defence in depth: the framer already rejects any control byte in
-- the target, but never interpolate request data into a log line
-- without neutralising CR/LF and capping length.
logsafe = function( s )
    s = string_gsub( tostring( s or "" ), "%c", "?" )
    if #s > 80 then
        s = string_sub( s, 1, 80 ) .. "..."
    end
    return s
end

-- server.lua calls the listener's `incoming` once at accept with no
-- data (we ignore that), then once per framed unit (parsed request
-- OR reject) with the unit table. No hub user object is created for
-- an HTTP connection.
http_incoming = function( handler, framer_unit )
    if not framer_unit then
        return true
    end

    -- source_ip: server.lua's handler exposes .ip() - if not
    -- available (older API), fall back to "127.0.0.1" since the
    -- listener is loopback-bound anyway.
    local source_ip = ( handler.ip and handler.ip( ) ) or "127.0.0.1"

    local status, body, extra_headers = http_router.dispatch( framer_unit, source_ip )

    -- #263 PR-B: deferred response (long-poll). The handler asked
    -- to keep the connection open; `body` is a defer function that
    -- takes the connection handler. We hand it the handler, the
    -- defer function registers the connection in http_events'
    -- waiter list, and we return WITHOUT writing or closing.
    -- http_events.emit / tick will complete the response later
    -- (write+close happens then).
    if status == "deferred" then
        if type( body ) == "function" then
            body( handler )
        end
        return true
    end

    -- Content-Type: router signals via Content-Type header in
    -- extra_headers if it wants to override (e.g. /health -> plain
    -- text). Default is application/json (set by response()).
    local content_type = extra_headers and extra_headers[ "Content-Type" ]
    if extra_headers then
        extra_headers[ "Content-Type" ] = nil    -- consumed
    end

    -- HEAD: router signals via Content-Length-Override that the
    -- body should be omitted but the declared CL must match the
    -- would-be GET body length.
    local headonly = framer_unit.method == "HEAD"
    local effective_body = body
    if headonly then
        local cl_override = extra_headers and extra_headers[ "Content-Length-Override" ]
        if cl_override then
            -- build a fake body of the right length to drive
            -- response()'s #body calculation; headonly = true
            -- strips the body bytes off the wire.
            effective_body = string_rep( "x", tonumber( cl_override ) or 0 )
        end
    end

    handler.write( response( status, effective_body, content_type, extra_headers, headonly ) )
    handler.close( )    -- graceful: flush the response, then close
    return true
end

http_disconnect = function( )
    -- no per-connection state to tear down (router state is global +
    -- request-scoped; framer state dies with the handler closure).
end

----------------------------------// PUBLIC INTERFACE //--

return {

    -- listener spec for server.addserver: the `pipeline` field makes
    -- server.lua build the hardened HTTP framer pipeline for these
    -- connections instead of the default ADC-line one.
    listeners = function( )
        return {
            incoming   = http_incoming,
            disconnect = http_disconnect,
            pipeline   = iostream.newhttppipeline,
        }
    end,

    -- low-level building blocks; the router uses these to render
    -- responses, but plugins go through http_router.dispatch +
    -- envelope helpers, not through here.
    response = response,
    logsafe  = logsafe,
    status   = _status,

}
