--[[

        iostream.lua - Phase 8 IO layer, steps S1 + S2

        Per-connection inbound framing, extracted out of server.lua so
        the server loop no longer relies on LuaSocket's "*l" line
        pattern. server.lua reads raw bytes and feeds them to a
        per-connection PIPELINE; the pipeline reassembles them into
        newline-delimited ADC frames across reads (the buffer LuaSocket
        used to own internally now lives here).

        S2 generalises the S1 fixed framer into a composable pipeline of
        STAGES. This is a behaviour-neutral proof step: the default
        pipeline is exactly one stage (the ADC-line framer carrying the
        S1 logic verbatim), so a 1-stage pipeline is byte-for-byte
        identical to the old framer. The seam exists so later steps slot
        in as stages without touching server.lua again:

          - S3 HTTP: an HTTP framer stage (bytes -> request units)
          - S4 ZLIF: an inflate stage prepended ahead of the ADC-line
            stage on ZON (bytes -> decompressed bytes)
          - S5 BLOM: a counted-binary capture stage

        Stage contract:

            stage:push( chunk ) -> units, overflow

          - `chunk`    : a byte string from the previous stage (raw
                         socket bytes for stage 1).
          - `units`    : ordered array of whatever this stage emits.
                         The ADC-line stage emits complete frame
                         strings (each WITHOUT the terminating "\n" and
                         with every "\r" dropped, exactly as LuaSocket
                         "*l" recvline does - see below). A passthrough
                         stage re-emits its input as a single unit.
          - `overflow` : bool; only a framing/terminal stage sets it
                         (size-cap breach -> caller closes the
                         connection, mirroring the old
                         `len > maxreadlen` guard).

        Pipeline contract (unchanged from S1's framer so server.lua is
        a ~2-line change):

            pipeline:feed( bytes ) -> frames, overflow

        ADC-line stage CR handling: LuaSocket "*l" recvline
        (luasocket/src/buffer.c:231-234, "we ignore all \r's") strips
        EVERY "\r" in the line, not just a trailing one. ADC is
        "\n"-only and the Phase-7 parser rejects embedded CR, so
        stripping only a trailing CR would flip a previously-accepted
        "a\rb" line into a hard parser reject - a real behaviour
        change. S1/S2 reproduce "*l"'s strip-all-CR verbatim.

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
local newpipeline
local newhttpstage
local newhttppipeline

----------------------------------// DEFINITION //--

-- ADC-line framer stage. Holds the cross-push unterminated remainder
-- in a closure. Logic is the S1 framer verbatim (so the default
-- 1-stage pipeline is byte-identical to S1).
newadclinestage = function( maxlen )

    local buf = ""

    local push = function( _, chunk )
        local units, n = { }, 0
        local overflow = false

        if chunk and chunk ~= "" then
            buf = buf .. chunk
        end

        local startpos = 1
        while true do
            local nlpos = string_find( buf, "\n", startpos, true )    -- plain find, no patterns
            if not nlpos then
                break
            end
            -- take bytes up to (not including) "\n", then drop EVERY
            -- "\r" (recvline ignores all CRs in the line).
            local frame = ( string_gsub( string_sub( buf, startpos, nlpos - 1 ), "\r", "" ) )
            if string_len( frame ) > maxlen then
                overflow = true
            end
            n = n + 1
            units[ n ] = frame
            startpos = nlpos + 1
        end

        if startpos > 1 then
            buf = string_sub( buf, startpos )
        end
        if string_len( buf ) > maxlen then
            overflow = true
        end

        return units, overflow
    end

    return setmetatable( { }, { __index = { push = push } } )

end    -- newadclinestage

-- Passthrough stage: re-emits its input chunk as a single unit,
-- stateless, never overflows. Identity element for pipeline
-- composition; `[passthrough, adcline]` behaves exactly like
-- `[adcline]`.
newpassthroughstage = function( )

    local push = function( _, chunk )
        return { chunk }, false
    end

    return setmetatable( { }, { __index = { push = push } } )

end    -- newpassthroughstage

-- newpipeline( maxlen ) -> pipeline object.
--
--   pipeline:feed( bytes ) -> frames, overflow
--       runs bytes through stage 1, its units through stage 2, ... ;
--       the terminal stage's units are the dispatchable ADC frames.
--       `overflow` is the OR of every stage's overflow signal.
--
--   pipeline:prepend( stage )
--       insert a stage at the FRONT (the rebuild seam: S4's ZON
--       handler splices an inflate stage ahead of the ADC-line stage
--       mid-stream). Defined here, first exercised in S4.
--
-- The default pipeline is a single ADC-line stage, so feed() is
-- byte-for-byte identical to S1's framer (one consumer: server.lua).
newpipeline = function( maxlen )

    local stages = { newadclinestage( maxlen ) }

    local feed = function( _, bytes )
        local units = { bytes or "" }
        local overflow = false
        for s = 1, #stages do
            local stage = stages[ s ]
            local out, m = { }, 0
            for u = 1, #units do
                local produced, ov = stage:push( units[ u ] )
                if ov then
                    overflow = true
                end
                for i = 1, #produced do
                    m = m + 1
                    out[ m ] = produced[ i ]
                end
            end
            units = out
        end
        return units, overflow
    end

    local prepend = function( _, stage )
        local shifted = { stage }
        for i = 1, #stages do
            shifted[ i + 1 ] = stages[ i ]
        end
        stages = shifted
    end

    return setmetatable( { }, { __index = { feed = feed, prepend = prepend } } )

end    -- newpipeline

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
        return { unit }, false
    end

    local push = function( _, chunk )
        if done then
            return { }, false    -- single request already produced; ignore trailing bytes
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
            return { }, false
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

    return setmetatable( { }, { __index = { push = push } } )

end    -- newhttpstage

-- newhttppipeline( maxlen ) -> pipeline whose single stage is the
-- hardened HTTP request framer. Same object shape / :feed contract as
-- newpipeline so server.lua selects it via `listeners.pipeline`
-- without any other change. `maxlen` is accepted for call-site
-- symmetry; the HTTP stage enforces its own (tighter) caps.
newhttppipeline = function( maxlen )

    local stages = { newhttpstage( ) }

    local feed = function( _, bytes )
        local units = { bytes or "" }
        local overflow = false
        for s = 1, #stages do
            local stage = stages[ s ]
            local out, m = { }, 0
            for u = 1, #units do
                local produced, ov = stage:push( units[ u ] )
                if ov then
                    overflow = true
                end
                for i = 1, #produced do
                    m = m + 1
                    out[ m ] = produced[ i ]
                end
            end
            units = out
        end
        return units, overflow
    end

    return setmetatable( { }, { __index = { feed = feed } } )

end    -- newhttppipeline

----------------------------------// PUBLIC INTERFACE //--

return {

    newpipeline         = newpipeline,
    newadclinestage     = newadclinestage,
    newpassthroughstage = newpassthroughstage,
    newhttpstage        = newhttpstage,
    newhttppipeline     = newhttppipeline,

}
