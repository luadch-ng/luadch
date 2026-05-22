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
local table = use "table"    -- S5: newcountedstage uses table.concat
local tonumber = use "tonumber"
local setmetatable = use "setmetatable"
-- Phase 8 S4b: the inflate stage pcalls the C binding so that the
-- 4 MiB bomb cap or a malformed compressed stream surfaces as the
-- pipeline overflow signal instead of crashing the hub. Core scripts
-- run in a sandboxed env (see core/init.lua setenv) where global
-- pcall is not in scope - must `use` it explicitly.
local pcall = use "pcall"

local string_find = string.find
local string_sub = string.sub
local string_gsub = string.gsub
local string_len = string.len
local string_lower = string.lower
local string_match = string.match
local string_gmatch = string.gmatch

local table_concat = table.concat

local newadclinestage
local newpassthroughstage
local newhttpstage

local newpipeline
local newhttppipeline

local newoutpassthroughstage
local newoutpipeline

-- S4b ADC-EXT ZLIF.
local newinflatestage
local newdeflatestage

-- S5 ADC-EXT BLOM (counted-binary capture stage).
local newcountedstage

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

    -- Queue of pre-emitted units that surfaced during a mid-pipeline
    -- splice (insert_before_terminal). next_frame returns them
    -- before driving _pull again. Empty in the common path; only
    -- populated when the inserted stage emitted enough output for
    -- the (old) terminal to immediately produce a frame (or several
    -- frames, if the residual contained a multi-frame tail) from a
    -- residual that arrived in the same TCP chunk as the splice
    -- trigger. Head / tail indices give O(1) enqueue + dequeue;
    -- both indices reset to 0 when the queue empties so they stay
    -- small even across many splices.
    local deferred = { }
    local deferred_head = 1
    local deferred_tail = 0    -- last filled index; 0 = empty

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
            -- Latch an upstream overflow so it survives until the next
            -- :next() call surfaces it. The caller is contractually
            -- required to close on overflow, so it is correct that any
            -- unit we still bubble up gets dropped server-side; this
            -- flag is the close signal, not a "ignore the unit too"
            -- signal. Single flag is enough because one overflow event
            -- per connection is fatal anyway.
            sticky_overflow = true
        end
        local input = prev_unit or ""
        local unit, ov = stages[ i ]:push( input )
        return unit, ov
    end

    local feed = function( _, bytes )
        if bytes and bytes ~= "" then
            input_buf = input_buf .. bytes
        end
    end

    local next_frame = function( _ )
        if deferred_head <= deferred_tail then
            -- One-overflow-per-connection is fatal anyway (see the
            -- sticky_overflow contract in _pull's comment below), so
            -- surfacing the latched flag on the FIRST deferred return
            -- and clearing it here is correct: by the time the caller
            -- processes any subsequent deferred entries the close has
            -- been requested.
            local first = deferred[ deferred_head ]
            deferred[ deferred_head ] = nil
            deferred_head = deferred_head + 1
            if deferred_head > deferred_tail then
                deferred_head = 1
                deferred_tail = 0
            end
            local ov = sticky_overflow
            sticky_overflow = false
            return first, ov
        end
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

    -- Splice `stage` at position N-1 - immediately before the current
    -- terminal. For a 1-stage pipeline this degenerates to prepend
    -- (no terminal to insert before). Required by Phase 8 S5 BLOM
    -- when ZLIF is also active: counted-binary capture must sit
    -- AFTER inflate so it sees decompressed payload bytes, not raw
    -- deflated wire bytes.
    --
    -- Residual transfer:
    --   The OLD terminal's residual is bytes that were already
    --   pushed through every upstream stage but the terminal did
    --   not yet consume them (e.g. ADC-line's `buf` holding the
    --   bytes that arrived in the SAME TCP segment as the HSND
    --   `\n`). After the splice these bytes belong logically to the
    --   inserted stage's input - they have already been processed
    --   by stages 1..N-2, so feeding them back into input_buf would
    --   re-run them through (e.g.) the inflate stage and corrupt
    --   the stream. Instead drive them synchronously through the
    --   inserted stage. If the inserted stage emits anything (e.g.
    --   counted's >budget tail), feed it onward to the terminal in
    --   the same synchronous step and EAGERLY drain every frame the
    --   terminal can immediately produce from that output (a
    --   multi-frame tail otherwise has frames #2..N stranded in the
    --   terminal's internal buffer until the next TCP-read tick - a
    --   latency cliff). All drained frames are parked in the
    --   `deferred` queue so next_frame() surfaces them in order
    --   before resuming _pull. Empty frames (terminal emitting ""
    --   on a leading-`\n` tail) are not enqueued - routing a
    --   zero-length ADC frame to the dispatcher would be a protocol
    --   error.
    local insert_before_terminal = function( self, stage )
        if #stages < 2 then
            return prepend( self, stage )
        end
        local n = #stages
        local terminal = stages[ n ]
        local residual = terminal.residual and terminal:residual( ) or ""
        -- Splice in front of terminal: stages[n] stays terminal,
        -- the new stage becomes stages[n] and terminal shifts to n+1.
        stages[ n + 1 ] = terminal
        stages[ n ] = stage
        if residual ~= "" then
            local out, ov = stage:push( residual )
            if ov then sticky_overflow = true end
            if out and out ~= "" then
                -- Eager drain: feed the inserted stage's output to
                -- the terminal, then keep pushing "" until the
                -- terminal stops producing frames (nil = needs more
                -- input). Each non-empty frame goes into deferred.
                local chunk = out
                while true do
                    local term_out, term_ov = terminal:push( chunk )
                    if term_ov then sticky_overflow = true end
                    if term_out == nil then break end
                    if term_out ~= "" then
                        deferred_tail = deferred_tail + 1
                        deferred[ deferred_tail ] = term_out
                    end
                    chunk = ""
                end
            end
        end
    end

    return setmetatable( { }, {
        __index = {
            feed                    = feed,
            next                    = next_frame,
            drain                   = drain,
            prepend                 = prepend,
            insert_before_terminal  = insert_before_terminal,
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

-- Hardened HTTP/1.x request-framer stage (Phase 8 S3 baseline +
-- phase 1 of #82 body extension - see docs/HTTP_API.md §2.1).
--
-- Emits exactly ONE unit then goes inert (one request per connection;
-- the caller responds with Connection: close and closes - this kills
-- keep-alive request smuggling and slowloris-via-many-requests). The
-- unit is either a parsed request
--   { method=, target=, version=, headers={lowercased name -> value},
--     body=<string of exactly Content-Length bytes, or ""> }
-- or a transport-level rejection { reject = <http status int> }. The
-- router (core/http.lua) maps a reject status to a canned response and
-- otherwise decides path/method semantics (404/405). This stage does
-- ONLY transport hardening; the router parses the body (if any) per
-- Content-Type.
--
-- State machine (§2.1 of docs/HTTP_API.md):
--   [parsing-headers] -- headers complete, CL == 0 or absent ----> emit{...,body=""}; done
--                     -- headers complete, 0 < CL <= MAXBODY ----> [collecting-body]
--                     -- CL > MAXBODY --------------------------> emit{reject=413}; done
--                     -- HEAD with CL > 0 -----------------------> emit{reject=400}; done
--                     -- any smuggling-defence trigger ----------> emit{reject=400}; done
--   [collecting-body] -- CL bytes received -----------------------> emit{...,body=<bytes>}; done
--                     -- (push returns nil while waiting for more)
--   [done]            any further push -> returns nil, false (trailing bytes discarded)
--
-- A mid-body connection close leaves the stage in [collecting-body]
-- with no emitted unit; the server.lua read loop tears down the
-- handler when the underlying socket reports EOF, the framer state
-- is GC'd along with the handler. No response is sent (the client
-- crashed first - this matches RFC 7230 §3.4 implicit recovery).
--
-- Every limit lives here so it is unit-testable in isolation.
newhttpstage = function( )

    local MAXREQ      = 16384    -- total request-line + headers cap
    local MAXLINE     = 8192     -- request-line cap
    local MAXTARGET   = 2048     -- request-target cap
    local MAXHDRS     = 100      -- header count cap
    local MAXHDRLINE  = 8192     -- single header line cap
    local MAXBODY     = 65536    -- Content-Length cap; rejects PRE-read on CL value

    local buf = ""
    local done = false

    -- [collecting-body] state. Set when the header parse succeeded
    -- and a non-zero Content-Length is declared; cleared on emit.
    -- buf is append-only across pushes (the body bytes get added at
    -- the top of push()), so string_len(buf) is the running total -
    -- no separate accumulator needed. Body lookup against
    -- body_target on each push decides emit-or-keep-waiting.
    local body_pending = false
    local body_unit              -- the success unit shell, body filled when complete
    local body_target  = 0       -- target Content-Length

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

        -- [collecting-body] - the header parse already succeeded;
        -- buf contains body bytes only (header substring was sliced
        -- off when we transitioned in). Wait until buf is at least
        -- body_target bytes long, then emit.
        --
        -- NOTE on slowloris-on-body: there is no wall-clock or
        -- chunk-count bound on how long the framer waits for the
        -- declared bytes to arrive. server.lua's per-connection
        -- idle timeout bounds it externally; if that proves
        -- insufficient under hostile load, add a chunk-count
        -- cap here (deferred until real client behaviour shows up).
        if body_pending then
            if string_len( buf ) < body_target then
                return nil, false    -- still waiting for more bytes
            end
            -- body complete. On a one-request-per-connection
            -- contract there is no trailing data, but
            -- defence-in-depth: take only the first body_target
            -- bytes - any trailing is discarded along with `done`.
            body_unit.body = string_sub( buf, 1, body_target )
            return emit( body_unit )
        end

        -- [parsing-headers] - look for end of headers (CRLFCRLF).
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
        local body_start = hdrend + 4                    -- byte after CRLFCRLF

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

        -- smuggling-defence ordering: TE / multi-CL FIRST, before any
        -- body-state transition. Preserves S3 rejection ordering.
        if te_seen then
            return emit{ reject = 400 }    -- any Transfer-Encoding (incl. chunked) rejected outright
        end
        if cl_count > 1 then
            return emit{ reject = 400 }    -- multiple Content-Length
        end

        local cl_str = headers[ "content-length" ]
        local cl_num = 0
        if cl_str then
            if not string_match( cl_str, "^%d+$" ) then
                return emit{ reject = 400 }    -- malformed CL (negative / non-digit / empty)
            end
            cl_num = tonumber( cl_str )
        end

        -- HEAD with a body is a protocol error (RFC 9110 §15.4.1).
        -- GET with a body is technically permitted by RFC but
        -- semantically meaningless for our API (no GET endpoint in
        -- the catalog accepts one) and a known smuggling vector;
        -- reject. Only POST / PUT / PATCH / DELETE bodies are
        -- accepted.
        if cl_num > 0
           and method ~= "POST" and method ~= "PUT"
           and method ~= "PATCH" and method ~= "DELETE" then
            return emit{ reject = 400 }
        end

        -- 413 fires on the DECLARED CL value, not on accumulated
        -- byte count. Prevents per-request memory amplification - we
        -- refuse before reading any body bytes.
        if cl_num > MAXBODY then
            return emit{ reject = 413 }
        end

        -- body defaults to "" for the CL=0 / no-body path; the
        -- collecting-body path overwrites it with the actual bytes
        -- before emit.
        local success_unit = {
            method = method, target = target, version = version,
            headers = headers, body = "",
        }

        if cl_num == 0 then
            -- no body declared; success immediately, drop any trailing
            -- bytes after CRLFCRLF (defence-in-depth on a one-request
            -- connection - the router will Connection: close anyway).
            return emit( success_unit )
        end

        -- transition into [collecting-body]: replace buf with the
        -- post-header tail (the first `body_start - 1` bytes of the
        -- original buf were the header; we want bytes >= body_start).
        buf = string_sub( buf, body_start )
        body_unit    = success_unit
        body_target  = cl_num
        body_pending = true

        if string_len( buf ) >= body_target then
            -- body arrived in the same chunk as the header.
            body_unit.body = string_sub( buf, 1, body_target )
            return emit( body_unit )
        end
        -- otherwise the next push() will continue accumulating.
        return nil, false
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

-- Inbound inflate stage (Phase 8 S4b, ADC-EXT ZLIF).
--
-- Holds an inflate_stream userdata across calls; decompresses each
-- input chunk with Z_SYNC_FLUSH. The C binding caps decompressed
-- output per push at 4 MiB (decompression-bomb guard) and raises a
-- Lua error on malformed input. We pcall around it so a hostile or
-- corrupt compressed stream surfaces as the pipeline's overflow
-- signal -> server.lua closes the connection (no half-decompressed
-- garbage ever reaches the ADC parser).
--
-- :residual() returns "" because inflate has no notion of
-- "unprocessed bytes that can be moved": Z_SYNC_FLUSH consumes every
-- input byte per push, the internal history buffer is zlib state not
-- byte content. The pipeline reshape seam is only ever used to
-- INSERT this stage ahead of the ADC-line stage on ZON; ZOF closes
-- the connection (see hub_dispatch.lua), so no removal-side
-- reshape is needed.
newinflatestage = function( )
    local zlib_stream = use "zlib_stream"
    if not zlib_stream then
        error( "iostream.newinflatestage: zlib_stream module not loaded" )
    end
    local strm = zlib_stream.inflate( )

    local push = function( _, chunk )
        if chunk and chunk ~= "" then
            local ok, out = pcall( strm.push, strm, chunk )
            if not ok then
                return nil, true    -- malformed input / bomb guard -> close
            end
            if out and out ~= "" then
                return out, false
            end
        end
        return nil, false
    end

    local residual = function( ) return "" end

    return setmetatable( { }, { __index = { push = push, residual = residual } } )
end

-- Outbound deflate stage (Phase 8 S4b, ADC-EXT ZLIF).
--
-- Symmetric to the inbound inflate stage: compresses each chunk of
-- outbound bytes with Z_SYNC_FLUSH so the peer can decompress
-- promptly (spec mandates partial flush per chunk). `level` defaults
-- to the C module's Z_DEFAULT_COMPRESSION; callers may pass 1-9 for
-- speed / size tradeoff (out of scope for S4b - cfg knob is binary
-- enable/disable, level is hardcoded default).
--
-- No :residual() on outbound stages by contract - the outbound
-- pipeline only prepends, never strips.
newdeflatestage = function( level )
    local zlib_stream = use "zlib_stream"
    if not zlib_stream then
        error( "iostream.newdeflatestage: zlib_stream module not loaded" )
    end
    local strm = zlib_stream.deflate( level )

    local write = function( _, bytes )
        if bytes and bytes ~= "" then
            return strm:push( bytes )
        end
        return ""
    end

    return setmetatable( { }, { __index = { write = write } } )
end

-- Counted-binary capture stage (Phase 8 S5, ADC-EXT BLOM).
--
-- Captures exactly `byte_count` bytes from the input stream
-- (regardless of any `\n` they contain), invokes `callback` once
-- with the captured bytes as a single string, then becomes a
-- transparent passthrough for any subsequent input.
--
-- The post-capture passthrough mode keeps the design simple: no
-- mid-pipeline stage removal is needed. Each BLOM filter refresh
-- adds one inert counted stage to the inbound pipeline (the
-- previous one stays in passthrough mode and the new one captures
-- the next m/8 bytes); growth is O(refresh count), bounded by
-- client behaviour - real clients refresh on share-size change,
-- not continuously. The dead-stage overhead is ~50 bytes per
-- refresh, negligible against the connection lifetime.
--
-- Caller wires this up via:
--
--     handler.inframer_prepend( newcountedstage( bytes, function( blob )
--         user.setblom( blob )
--     end ) )
--
-- The S4a prepend reshape carries adcline's residual bytes (any
-- binary payload that arrived in the SAME TCP chunk as the HSND
-- header) into this new front stage, so the counted stage sees
-- the binary data on its very first push().
--
-- Notes / non-goals:
--   - No size cap inside the stage; the caller is expected to gate
--     the HSND `bytes` field against a cfg-defined ceiling before
--     constructing this stage. Otherwise a malicious client could
--     advertise an arbitrarily large HSND and force the pipeline
--     to buffer it all before the callback fires.
--   - No timeout: a slowloris that stops sending mid-binary keeps
--     the stage waiting. server.lua's per-connection idle timeout
--     (_max_idle_time) bounds this externally.
newcountedstage = function( byte_count, callback )

    local remaining = byte_count
    local pieces, n = { }, 0
    local fired = false

    local push = function( _, chunk )
        if chunk == nil or chunk == "" then
            return nil, false
        end
        if fired then
            -- Post-capture passthrough: relay every chunk as a
            -- single unit to the next stage unchanged.
            return chunk, false
        end
        local clen = string_len( chunk )
        if clen <= remaining then
            n = n + 1
            pieces[ n ] = chunk
            remaining = remaining - clen
            if remaining == 0 then
                local blob = table_concat( pieces, "", 1, n )
                pieces = nil    -- drop the captured pieces from the closure
                fired = true
                callback( blob )
            end
            return nil, false
        end
        -- chunk exceeds the budget: take the first `remaining`
        -- bytes as the tail of the captured blob, fire the
        -- callback, and emit the post-budget tail to the next
        -- stage. Subsequent push()es enter passthrough mode.
        n = n + 1
        pieces[ n ] = string_sub( chunk, 1, remaining )
        local tail = string_sub( chunk, remaining + 1 )
        local blob = table_concat( pieces, "", 1, n )
        pieces = nil
        remaining = 0
        fired = true
        callback( blob )
        return tail, false
    end

    -- Counted-binary stage has no movable "residual" - by the time
    -- prepend()'s residual transfer fires this constructor has not
    -- yet been wired in. Once wired it consumes all input it sees.
    local residual = function( ) return "" end

    return setmetatable( { }, { __index = { push = push, residual = residual } } )

end    -- newcountedstage

----------------------------------// PUBLIC INTERFACE //--

return {

    newpipeline            = newpipeline,
    newadclinestage        = newadclinestage,
    newpassthroughstage    = newpassthroughstage,
    newhttpstage           = newhttpstage,
    newhttppipeline        = newhttppipeline,

    newoutpipeline         = newoutpipeline,
    newoutpassthroughstage = newoutpassthroughstage,

    -- S4b ADC-EXT ZLIF (zlib stream compression).
    newinflatestage        = newinflatestage,
    newdeflatestage        = newdeflatestage,

    -- S5 ADC-EXT BLOM (counted-binary capture stage).
    newcountedstage        = newcountedstage,

}
