--[[

        iostream.lua - Phase 8 IO layer, steps S1 + S2 + S3 + S4a

        Per-connection inbound + outbound transform pipelines, extracted
        out of server.lua so the server loop no longer relies on
        LuaSocket's "*l" line pattern. server.lua reads raw bytes and
        feeds them to a per-connection INBOUND pipeline; its terminal
        stage reassembles them into newline-delimited ADC frames (or
        hardened HTTP request units, on the HTTP listener) across
        reads. Writes go through a per-connection OUTBOUND pipeline
        before they hit the socket. The buffer LuaSocket used to own
        internally now lives in our stages.

        S2 generalised S1's fixed framer into a composable pipeline of
        stages. S3 added the hardened HTTP request-framer stage.

        S4a (this step) is again behaviour-neutral: it changes the
        pipeline CONTRACT from "feed bytes -> get all frames" to a
        lazy one-frame-at-a-time iterator, and adds an OUTBOUND
        pipeline mirror (default = passthrough = byte-identical). The
        old contract returned every frame an input chunk could
        produce, which is wrong the moment a mid-stream stage swap is
        possible: an input chunk "ZON\n<compressed bytes>" would have
        the ADC-line stage read past the "\n" and emit garbage
        "frames" out of the compressed suffix BEFORE the ZON
        dispatcher gets a chance to splice in an inflate stage. S4b
        will rely on this: the ZON handler calls
        `pipeline:prepend( inflate_stage )` immediately after
        dispatching the ZON frame, the residual suffix the ADC-line
        stage had buffered gets re-fed through the new front stage,
        and no garbage was emitted because the outer loop only asks
        for the next frame AFTER each dispatch returns.

        Inbound stage contract (S4a):

            stage:push( chunk ) -> unit, overflow

          - `chunk`    : bytes from the previous stage (raw socket
                         bytes for stage 1). Empty string means
                         "drain: do not consume new input, but emit a
                         unit from current state if possible".
          - `unit`     : the single unit this stage produces this
                         call, or nil if nothing is available yet.
                         The ADC-line stage emits complete frame
                         strings (without the terminating "\n" and
                         with every "\r" dropped, matching LuaSocket
                         "*l" recvline - see CR note below). The HTTP
                         stage emits a parsed-request table or a
                         { reject = <status> } table.
          - `overflow` : bool; set by framing / terminal stages when a
                         size cap is breached. The caller closes the
                         connection.

            stage:residual( ) -> bytes

          - Returns this stage's unprocessed input bytes and clears
                         that internal buffer. Used by
                         pipeline:prepend to re-route a residual
                         suffix through a newly inserted upstream
                         stage. Stateless stages (passthrough) return
                         "".

        Outbound stage contract (S4a, mirrors inbound):

            stage:write( bytes ) -> bytes

          - Transforms outgoing bytes synchronously (passthrough = same
                         bytes; S4b deflate_stream = Z_SYNC_FLUSH'd
                         zlib output). No internal buffering across
                         calls is required for the passthrough
                         default; stateful outbound stages (deflate)
                         own their own state.

        Inbound pipeline contract:

            pipeline:feed( bytes )
                Append bytes to the head of the pipeline. No return.

            pipeline:next( ) -> frame, overflow
                Lazy pull: returns the next dispatchable frame from
                the terminal stage, or nil if nothing is available
                yet. `overflow` is true at most once per overflow
                event - the caller MUST close the connection.

            pipeline:drain( ) -> frames, overflow
                Convenience: calls :next() until it yields nil and
                collects the frames. The S1/S2/S3 contract was
                effectively "feed + drain" combined - keeping this
                helper preserves byte-identical behaviour for unit
                tests and lets dispatcher code stay an explicit while-
                next loop (which is required for mid-stream reshape).

            pipeline:prepend( stage )
                Insert a stage at the FRONT. The current front
                stage's residual unprocessed bytes are routed back
                through the new stage. The rebuild seam for S4b's
                ZON-prepends-inflate; first defined in S2.

        Outbound pipeline contract:

            outpipeline:write( bytes ) -> bytes
                Runs bytes through every outbound stage left-to-right
                and returns the transformed bytes. Empty pipeline
                (current default) is identity. Order matches a write
                that travels stage[1] -> stage[2] -> ... -> socket.

            outpipeline:prepend( stage )
                Insert a stage at the FRONT (closest to the writer);
                the existing stages then transform the new stage's
                output. S4b prepends a deflate_stream stage on
                outbound ZON.

        ADC-line stage CR handling: LuaSocket "*l" recvline
        (luasocket/src/buffer.c:231-234, "we ignore all \r's") strips
        EVERY "\r" in the line, not just a trailing one. ADC is
        "\n"-only and the Phase-7 parser rejects embedded CR, so
        stripping only a trailing CR would flip a previously-accepted
        "a\rb" line into a hard parser reject - a real behaviour
        change. S1+ reproduce "*l"'s strip-all-CR verbatim.

        No sockets, no IO, no globals here - pure byte -> unit logic so
        every stage is unit-testable in isolation.

]]--

----------------------------------// DECLARATION //--

local use = use

local string = use "string"
local tonumber = use "tonumber"
local setmetatable = use "setmetatable"

local string_find = string.find
local string_sub = string.sub
local string_gsub = string.gsub
local string_len = string.len
local string_lower = string.lower
local string_match = string.match
local string_gmatch = string.gmatch

local newadclinestage
local newpassthroughstage
local newhttpstage

local newpipeline
local newhttppipeline

local newoutpassthroughstage
local newoutpipeline

----------------------------------// DEFINITION //--

-- ADC-line framer stage (S1 logic carried through S4a; emits AT MOST
-- ONE frame per push() call so the lazy pipeline can reshape between
-- frames).
newadclinestage = function( maxlen )

    local buf = ""

    local push = function( _, chunk )
        if chunk and chunk ~= "" then
            buf = buf .. chunk
        end
        local nlpos = string_find( buf, "\n", 1, true )    -- plain find, no patterns
        if not nlpos then
            -- No frame yet; signal overflow if the unterminated
            -- remainder exceeded the cap so the caller closes the
            -- connection (mirrors the S1 `_maxreadlen` guard).
            if string_len( buf ) > maxlen then
                return nil, true
            end
            return nil, false
        end
        -- Take bytes up to (not including) "\n", then drop EVERY
        -- "\r" (recvline ignores all CRs in the line).
        local frame = ( string_gsub( string_sub( buf, 1, nlpos - 1 ), "\r", "" ) )
        buf = string_sub( buf, nlpos + 1 )
        if string_len( frame ) > maxlen then
            return frame, true    -- emit so the caller sees what was rejected, then close
        end
        return frame, false
    end

    local residual = function( )
        local r = buf
        buf = ""
        return r
    end

    return setmetatable( { }, { __index = { push = push, residual = residual } } )

end    -- newadclinestage

-- Inbound passthrough stage: re-emits its input chunk as a single
-- unit, no internal buffering, stateless. Identity element for
-- pipeline composition (a passthrough before an ADC-line stage is
-- byte-equivalent to the ADC-line stage alone).
newpassthroughstage = function( )

    local pending = nil

    local push = function( _, chunk )
        if chunk and chunk ~= "" then
            pending = chunk
        end
        local u = pending
        pending = nil
        return u, false
    end

    local residual = function( )
        local r = pending or ""
        pending = nil
        return r
    end

    return setmetatable( { }, { __index = { push = push, residual = residual } } )

end    -- newpassthroughstage

-- Build a pipeline shared between newpipeline (terminal = ADC-line)
-- and newhttppipeline (terminal = HTTP). The terminal stage is
-- passed in; the input buffer + lazy pull machinery + reshape seam
-- are common.
local _newpipeline = function( terminalstage )

    local stages = { terminalstage }
    local input_buf = ""
    local sticky_overflow = false

    -- Drive one unit out of stage i, top-down lazy: stage i first
    -- tries to emit from its own buffered state; if that fails, ask
    -- stage i-1 for a unit and feed it. Stage 1 reads from
    -- input_buf. Returns (unit, overflow); unit may be nil.
    local _pull
    _pull = function( i )
        if i == 1 then
            local input
            if input_buf ~= "" then
                input = input_buf
                input_buf = ""
            else
                input = ""
            end
            local unit, ov = stages[ 1 ]:push( input )
            return unit, ov
        end
        local prev_unit, prev_ov = _pull( i - 1 )
        if prev_ov then
            -- Latch overflow so the caller still sees the unit (so
            -- e.g. the oversized frame can be logged) AND the
            -- overflow flag on the next next() call. Single flag is
            -- enough because the caller is contractually required to
            -- close on overflow.
            sticky_overflow = true
        end
        local input = prev_unit or ""
        if input == "" and prev_unit == nil then
            -- Upstream dry: drain pending state of this stage with
            -- empty push, but don't claim more input than we have.
            local unit, ov = stages[ i ]:push( "" )
            return unit, ov
        end
        local unit, ov = stages[ i ]:push( input )
        return unit, ov
    end

    local feed = function( _, bytes )
        if bytes and bytes ~= "" then
            input_buf = input_buf .. bytes
        end
    end

    local next_frame = function( _ )
        local unit, ov = _pull( #stages )
        if sticky_overflow then
            ov = true
            sticky_overflow = false
        end
        return unit, ov
    end

    local drain = function( self )
        local frames, n = { }, 0
        local overflow = false
        while true do
            local frame, ov = next_frame( self )
            if ov then overflow = true end
            if frame == nil then
                return frames, overflow
            end
            n = n + 1
            frames[ n ] = frame
        end
    end

    local prepend = function( _, stage )
        -- 1. The CURRENT front stage may have buffered unprocessed
        --    bytes (e.g. the ADC-line stage's `buf` containing the
        --    bytes that arrived after a `ZON\n` and were not yet
        --    drained because the dispatcher loop exited after the
        --    ZON frame). Pull them out before inserting the new
        --    stage so they go through the new front instead.
        local residual = stages[ 1 ].residual and stages[ 1 ]:residual( ) or ""
        local shifted = { stage }
        for i = 1, #stages do
            shifted[ i + 1 ] = stages[ i ]
        end
        stages = shifted
        if residual ~= "" then
            input_buf = residual .. input_buf
        end
    end

    return setmetatable( { }, {
        __index = {
            feed    = feed,
            next    = next_frame,
            drain   = drain,
            prepend = prepend,
        }
    } )

end

-- newpipeline( maxlen ) -> pipeline whose single (terminal) stage is
-- the ADC-line framer. Default for ADC listeners. The 1-stage default
-- + lazy pull is byte-for-byte equivalent to S1/S2/S3 inbound
-- behaviour, asserted by the unit-test parity suite.
newpipeline = function( maxlen )
    return _newpipeline( newadclinestage( maxlen ) )
end

-- Hardened HTTP/1.x request-framer stage (Phase 8 S3, drives #82).
--
-- Emits exactly ONE unit then goes inert (one request per connection;
-- the caller responds with Connection: close and closes - this kills
-- keep-alive request smuggling and slowloris-via-many-requests). The
-- unit is either a parsed request
--   { method=, target=, version=, headers={lowercased name -> value} }
-- or a transport-level rejection { reject = <http status int> }. The
-- router (core/http.lua) maps a reject status to a canned response and
-- otherwise decides path/method semantics (404/405). This stage does
-- ONLY transport hardening; it never reads a body (read-only S3:
-- GET/HEAD only, any body/Content-Length>0/Transfer-Encoding -> 400).
--
-- Every limit lives here so it is unit-testable in isolation.
newhttpstage = function( )

    local MAXREQ      = 16384    -- total request-line + headers cap
    local MAXLINE     = 8192     -- request-line cap
    local MAXTARGET   = 2048     -- request-target cap
    local MAXHDRS     = 100      -- header count cap
    local MAXHDRLINE  = 8192     -- single header line cap

    local buf = ""
    local done = false

    local emit = function( unit )
        done = true
        return unit, false
    end

    local push = function( _, chunk )
        if done then
            return nil, false    -- single request already produced; ignore trailing bytes
        end
        if chunk and chunk ~= "" then
            buf = buf .. chunk
        end

        local hdrend = string_find( buf, "\r\n\r\n", 1, true )
        if not hdrend then
            -- headers not complete yet; bound the wait (slowloris /
            -- unbounded buffer): oversize before terminator -> 431.
            if string_len( buf ) > MAXREQ then
                return emit{ reject = 431 }
            end
            return nil, false
        end
        if hdrend > MAXREQ then
            return emit{ reject = 431 }
        end

        local head = string_sub( buf, 1, hdrend - 1 )    -- request-line + header lines, no trailing CRLFCRLF

        -- request-line
        local rlend = string_find( head, "\r\n", 1, true )
        local requestline = ( rlend and string_sub( head, 1, rlend - 1 ) ) or head
        if string_len( requestline ) > MAXLINE then
            return emit{ reject = 414 }
        end
        if string_find( requestline, "%c" ) then    -- no NUL / control (CR/LF already split out)
            return emit{ reject = 400 }
        end
        local method, target, version = string_match( requestline, "^(%u+) (%S+) (HTTP/%d%.%d)$" )
        if not method then
            return emit{ reject = 400 }
        end
        if version ~= "HTTP/1.0" and version ~= "HTTP/1.1" then
            return emit{ reject = 505 }
        end
        if string_len( target ) > MAXTARGET then
            return emit{ reject = 414 }
        end
        if string_sub( target, 1, 1 ) ~= "/" then
            return emit{ reject = 400 }
        end
        if string_find( target, "..", 1, true ) then    -- path traversal
            return emit{ reject = 400 }
        end

        -- header lines
        local headers = { }
        local count = 0
        local cl_count = 0
        local te_seen = false
        local rest = ( rlend and string_sub( head, rlend + 2 ) ) or ""
        if rest ~= "" then
            for line in string_gmatch( rest .. "\r\n", "(.-)\r\n" ) do
                if line ~= "" then
                    count = count + 1
                    if count > MAXHDRS then
                        return emit{ reject = 431 }
                    end
                    if string_len( line ) > MAXHDRLINE then
                        return emit{ reject = 431 }
                    end
                    -- name = token with NO whitespace and no control
                    -- (RFC 7230 forbids OWS before the colon; allowing
                    -- it - e.g. "Content-Length : 5" - would let a
                    -- spaced name dodge the CL/TE smuggling classifier
                    -- below, which compares the lowercased name to the
                    -- exact strings).
                    local name, value = string_match( line, "^([^:%c ]+):[ \t]*(.-)[ \t]*$" )
                    if not name then
                        return emit{ reject = 400 }
                    end
                    if string_find( value, "%c" ) then    -- no NUL / control in value
                        return emit{ reject = 400 }
                    end
                    name = string_lower( name )
                    if name == "content-length" then
                        cl_count = cl_count + 1
                    elseif name == "transfer-encoding" then
                        te_seen = true
                    end
                    headers[ name ] = value
                end
            end
        end

        -- body / request-smuggling rules (read-only S3: no body at all)
        if te_seen then
            return emit{ reject = 400 }    -- any Transfer-Encoding (incl. chunked) rejected outright
        end
        if cl_count > 1 then
            return emit{ reject = 400 }    -- multiple Content-Length
        end
        local cl = headers[ "content-length" ]
        if cl then
            if not string_match( cl, "^%d+$" ) then
                return emit{ reject = 400 }
            end
            if tonumber( cl ) ~= 0 then
                return emit{ reject = 400 }    -- non-zero body not allowed
            end
        end

        return emit{ method = method, target = target, version = version, headers = headers }
    end

    local residual = function( )
        -- HTTP stage never carries unprocessed bytes across a
        -- pipeline reshape - one request per connection, the only
        -- caller (http.lua) closes immediately after dispatch.
        return ""
    end

    return setmetatable( { }, { __index = { push = push, residual = residual } } )

end    -- newhttpstage

-- newhttppipeline( maxlen ) -> pipeline whose single (terminal) stage
-- is the hardened HTTP request framer. Same object shape as
-- newpipeline so server.lua selects it via `listeners.pipeline`
-- without any other change. `maxlen` is accepted for call-site
-- symmetry; the HTTP stage enforces its own (tighter) caps.
newhttppipeline = function( maxlen )    -- luacheck: ignore (maxlen unused; symmetry)
    return _newpipeline( newhttpstage( ) )
end

-- Outbound passthrough stage: identity transform. Stateless. The
-- default outbound pipeline is exactly one of these so writes are
-- byte-for-byte unchanged from the legacy / S3 path.
newoutpassthroughstage = function( )

    local write = function( _, bytes )
        return bytes
    end

    return setmetatable( { }, { __index = { write = write } } )

end    -- newoutpassthroughstage

-- newoutpipeline( ) -> outbound pipeline. Default = one passthrough
-- stage = identity. S4b prepends a deflate_stream stage on outbound
-- ZON. Stage order: stage[1] is closest to the writer, stage[#] is
-- closest to the socket - the order data travels.
newoutpipeline = function( )

    local stages = { newoutpassthroughstage( ) }

    local write = function( _, bytes )
        local out = bytes or ""
        for i = 1, #stages do
            out = stages[ i ]:write( out )
            if out == "" then
                return ""
            end
        end
        return out
    end

    local prepend = function( _, stage )
        local shifted = { stage }
        for i = 1, #stages do
            shifted[ i + 1 ] = stages[ i ]
        end
        stages = shifted
    end

    return setmetatable( { }, {
        __index = {
            write   = write,
            prepend = prepend,
        }
    } )

end    -- newoutpipeline

----------------------------------// PUBLIC INTERFACE //--

return {

    newpipeline            = newpipeline,
    newadclinestage        = newadclinestage,
    newpassthroughstage    = newpassthroughstage,
    newhttpstage           = newhttpstage,
    newhttppipeline        = newhttppipeline,

    newoutpipeline         = newoutpipeline,
    newoutpassthroughstage = newoutpassthroughstage,

}
