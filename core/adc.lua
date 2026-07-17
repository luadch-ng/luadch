--[[

        adc.lua by blastbeat

        - ADC stuff

            v0.08: by blastbeat
                - add SEGA support (Grouping of file extensions in SCH)

            v0.07: by pulsar
                - improved out_put messages

            v0.06: by pulsar
                - add missing "AP" client flag in INF

            v0.05: by pulsar
                - add SUDP support (encrypting UDP traffic)
                    - added: "KY" to "SCH"

            v0.04: by pulsar
                - add support for ASCH (Extended searching capability)
                    - added: "FC", "TO", "RC" to "STA"
                    - added: "MC", "PP", "OT", "NT", "MR", "PA", "RE" to "SCH"
                    - added: "FI", "FO", "DA" to "RES"

            v0.03: by pulsar
                - set "nonpclones" to "false" in "commands.SCH"

            v0.02: by pulsar
                - add support for KEYP (Keyprint)
                    - added: "KP" to "INF"
]]--

----------------------------------// DECLARATION //--

--// lua functions //--

local type = use "type"
local ipairs = use "ipairs"
local tostring = use "tostring"

--// lua libs //--

local os = use "os"
local math = use "math"
local table = use "table"
local debug = use "debug"
local string = use "string"

--// lua lib methods //--

local os_date = os.date
local os_time = os.time
local os_clock = os.clock
local string_sub = string.sub
local string_gsub = string.gsub
local string_find = string.find
local string_match = string.match
local table_insert = table.insert
local table_concat = table.concat
local table_remove = table.remove
local debug_traceback = debug.traceback

--// extern libs //--

local adclib = use "adclib"
local unicode = use "unicode"

--// extern lib methods //--

local utf_find = unicode.utf8.find

local adclib_hash = adclib.hash
local adclib_isutf8 = adclib.isutf8
local adclib_hashpas = adclib.hashpas
local adclib_random_bytes = adclib.random_bytes
local string_byte = string.byte

--// core scripts //--

local out = use "out"
local mem = use "mem"
local types = use "types"

--// core methods //--

local types_utf8 = types.utf8

local out_put = out.put
local types_check = types.check

--// functions //--

local parse
local createid

local checkadccmd
local checkadcstr
local checkadcstring

--// exported adc object methods //--

local adccmd_pos
local adccmd_mysid
local adccmd_getnp
local adccmd_addnp
local adccmd_setnp
local adccmd_type
local adccmd_cmd
local adccmd_fourcc
local adccmd_deletenp
local adccmd_getallnp
local adccmd_hasparam
local adccmd_targetsid
local adccmd_adcstring

--// tables //--

local _base32

local _regex    -- some regex patterns
local _protocol    -- adc specs

local _protocol_types    -- caching..
local _protocol_commands

local _adccmds    -- collection of all created adc commands

--// simple data types //--

-- Phase 7d F-PRS-5: parser-side cap. server.lua already enforces
-- _maxreadlen = 1 MiB at the socket layer; 64 KiB here gives a much
-- tighter limit at the protocol layer where every command is parsed.
local MAX_COMMAND_SIZE = 65536

local _th    -- pattern strings..
local _su
local _sid
local _sup
local _sta
local _bool
local _onetwo
local _integer
local _feature

local _contextsend
local _contextdirect

local _

----------------------------------// DEFINITION //--

_adccmds = { }

_th = "^" .. string.rep( "[A-Z2-7]", 39 ) .. "$"
_su = "[A-Z]" .. string.rep( "[A-Z0-9]", 3 ) .. ","
_sta = "^[012]%d%d$"
_sid = "^" .. string.rep( "[A-Z2-7]", 4 ) .. "$"
_sup = "^" .. string.rep( "[A-Z]", 3 ) .. "[A-Z0-9]$"
_bool = "^[1]?$"
_onetwo = "^[12]?$"
_integer = "^%d*$"
_feature = "[%+%-][A-Z]" .. string.rep( "[A-Z0-9]", 3 )

_regex = {

    th = function( str )
        return string_match( str, _th )
    end,
    sid = function( str )
        return string_match( str, _sid )
    end,
    bool = function( str )
        return string_match( str, _bool )
    end,
    -- Accept empty (NP key with no value), or any signed decimal
    -- integer. Per ADC spec, fields like DS / US / SS / SF should be
    -- unsigned, but some buggy clients (notably certain DC++ builds)
    -- emit negative DS in INF; the previous "^%d*$" pattern rejected
    -- such NPs, which made the parser drop the entire BINF and
    -- prevented those clients from logging in. Closes upstream
    -- luadch/luadch#241. Bare "-" without digits is still rejected.
    integer = function( str )
        if str == "" then return true end
        return string_match( str, "^%-?%d+$" )
    end,
    sta = function( str )
        return string_match( str, _sta )
    end,
    onetwo = function( str )
        return string_match( str, _onetwo )
    end,
    su = function( str )
        str = str .. ","
        for i = 1, #str, 5 do
            if not string_match( string_sub( str, i, i + 5 ), _su ) then
                return false
            end
        end
        return true
    end,
    sup = function( str )
        return string_match( str, _sup )
    end,
    feature = function( str )
        for i = 1, #str, 5 do
            if not string_match( string_sub( str, i, i + 5 ), _feature ) then
                return false
            end
        end
        return true
    end,
    -- Phase 7d F-PRS-2: was `function() return true end` - a no-op
    -- that accepted any value. Now rejects raw C0 control bytes
    -- (NUL, TAB, CR, LF, VT, FF, ...) and DEL. ADC values must never
    -- contain raw control bytes; protocol-significant chars (space,
    -- newline, backslash) must be escape-encoded as \s / \n / \\.
    -- The token splitter already strips space-separated tokens, so by
    -- the time we get here `str` is a single token.
    default = function( str )
        return not string_find( str, "%c" )
    end,
    -- Phase 7d F-PRS-1: was checking for the LITERAL two-byte escape
    -- sequences "\n" / "\s" (backslash-N / backslash-S) instead of
    -- raw whitespace bytes. `%c` covers \t \n \r \v \f (the
    -- whitespace bytes that survive tokenisation) plus NUL and DEL.
    -- Used for fields like INF.NI that must never contain whitespace.
    --
    -- Issue #265: the 7d rewrite dropped the escape-sequence check.
    -- Per ADC §2.4 a spec-compliant receiver decodes `\s` / `\n` to
    -- real space / LF in the field value; so a NI containing the
    -- escaped forms still ends up as a nick with whitespace once
    -- decoded, violating the field's "no whitespace" contract. Restore
    -- the escape-sequence rejection ON TOP OF the 7d raw-byte check.
    -- The pattern is unanchored - matches the pre-7d behaviour exactly.
    -- A nick legitimately carrying `\\s` (escaped literal backslash
    -- followed by `s`) trips this too; backslash-bearing nicks are
    -- exotic and were rejected by the pre-7d validator equally.
    nowhitespace = function( str )
        return not string_find( str, "%c" )
           and not string_find( str, "\\[sn]" )
    end,
    context = {

        hub = "[H]",
        send = "[BFDE]",
        bcast = "[BF]",
        direct = "[DE]",
        hubdirect = "[HDE]",
        result = "[FD]",        -- ADC 5.3.6 RES: D (direct) + F (feature-filtered)
        streamctl = "[BIH]",    -- Phase 8 S4b ADC-EXT ZLIF ZON / ZOF; spec is
                                -- ambiguous on the fourcc class, real clients
                                -- vary (BZON / IZON / HZON have all been seen),
                                -- so accept any of them in the framer and let
                                -- hub.lua's incoming intercept decide.

    },

}

_protocol = {

    types = {

        I = { len = 0, },
        H = { len = 0, },
        B = {

            _regex.sid,

            len = 1,

        },
        F = {

            _regex.sid,
            _regex.feature,

            len = 2,

        },
        D = {

            _regex.sid,
            _regex.sid,

            len = 2,

        },
        E = {

            _regex.sid,
            _regex.sid,

            len = 2,

        },

    },
    commands = {

        SUP = {

            pp = { len = 0, },
            np = {

                AD = _regex.sup,
                RM = _regex.sup,

            },
            nonpclones = false,    -- doesnt remove named parameters when parameter with same name already was found (for example ADBAS0, ADBASE)

        },
        MSG = {

            pp = {

                _regex.default,

                len = 1,

            },
            np = {

                PM = _regex.sid,
                ME = _regex.bool,

            },
            nonpclones = true,    -- removes named parameters when parameter with same name already was found (for example ME1, ME)

        },
        STA = {

            pp = {

                _regex.sta,
                _regex.default,

                len = 2,

            },
            np = {

                PR = _regex.default,
                FC = _regex.default,
                TL = _regex.default,
                TO = _regex.default,
                I4 = _regex.default,
                I6 = _regex.default,
                FM = _regex.default,
                FB = _regex.default,
                --// ASCH - Extended searching capability //--  http://adc.sourceforge.net/ADC-EXT.html#_asch_extended_searching_capability
                -- ASCH also uses FC and TO; both are already declared
                -- above in this same STA np table, so they are not
                -- repeated here.
                RC = _regex.default,


            },
            nonpclones = true,    -- removes named parameters when parameter with same name already was found (for example ME1, ME)

        },
        INF = {

            pp = { len = 0, },
            np = {

                ID = _regex.th,
                PD = _regex.th,
                I4 = _regex.default,    -- ip string will be compared with real ip later, so no need for checking here..
                I6 = _regex.default,
                U4 = _regex.integer,
                U6 = _regex.integer,
                SS = _regex.integer,
                SF = _regex.integer,
                US = _regex.integer,
                DS = _regex.integer,
                SL = _regex.integer,
                AS = _regex.integer,
                AM = _regex.integer,
                NI = _regex.nowhitespace,
                HN = _regex.integer,
                HR = _regex.integer,
                HO = _regex.integer,
                OP = _regex.bool,
                AW = _regex.onetwo,
                BO = _regex.bool,
                HI = _regex.bool,
                HU = _regex.bool,
                SU = _regex.su,
                CT = _regex.integer,
                DE = _regex.default,
                EM = _regex.default,
                AP = _regex.default,
                VE = _regex.default,
                --// KEYP - Certificate substitution protection //--  http://adc.sourceforge.net/ADC-EXT.html#_keyp_certificate_substitution_protection_in_conjunction_with_adcs
                KP = _regex.default,

            },
            nonpclones = true,    -- removes named parameters when parameter with same name already was found (for example HN1, HN4)

        },
        CTM = {

            pp = {

                _regex.default,
                _regex.integer,
                _regex.default,

                len = 3,

            },
            np = { },
            nonpclones = false,

        },
        RCM = {

            pp = {

                _regex.default,
                _regex.default,

                len = 2,

            },
            np = { },
            nonpclones = false,

        },
        -- ADC-EXT 3.9 NATT. Hub-relay-only NAT-traversal. NAT is the
        -- initiator-to-target request, RNT is the target-to-initiator
        -- response; both share the same wire shape as CTM (protocol /
        -- port / token). D-class only per spec.
        NAT = {

            pp = {

                _regex.default,
                _regex.integer,
                _regex.default,

                len = 3,

            },
            np = { },
            nonpclones = false,

        },
        RNT = {

            pp = {

                _regex.default,
                _regex.integer,
                _regex.default,

                len = 3,

            },
            np = { },
            nonpclones = false,

        },
        -- #214 HBRI side-channel validation. The client opens a second
        -- connection on the opposite IP family and sends HTCP carrying
        -- the claimed secondary address (I4 / I6, plus optional U4 / U6)
        -- and the token (TO) the hub minted in its ITCP. Hub-direction
        -- (H) only on our side; the ITCP the hub sends is built by
        -- string concat in core/hbri.lua and never parsed here. No
        -- positional params; P4 / P6 are accepted for symmetry with the
        -- hub-sent frame even though the client does not echo them.
        TCP = {

            pp = { len = 0, },
            np = {

                I4 = _regex.default,
                I6 = _regex.default,
                U4 = _regex.integer,
                U6 = _regex.integer,
                P4 = _regex.integer,
                P6 = _regex.integer,
                TO = _regex.default,

            },
            nonpclones = true,

        },
        SCH = {

            pp = { len = 0, },
            np = {

                AN = _regex.default,
                NO = _regex.default,
                EX = _regex.default,
                LE = _regex.integer,
                GE = _regex.integer,
                EQ = _regex.integer,
                TO = _regex.default,
                TY = _regex.onetwo,
                TR = _regex.th,
                TD = _regex.integer,
                --// ASCH - Extended searching capability //--  http://adc.sourceforge.net/ADC-EXT.html#_asch_extended_searching_capability
                MT = _regex.default,
                PP = _regex.default,
                OT = _regex.default,
                NT = _regex.default,
                MR = _regex.default,
                PA = _regex.default,
                RE = _regex.default,
                --// SUDP - Encrypting UDP traffic //--  http://adc.sourceforge.net/ADC-EXT.html#_sudp_encrypting_udp_traffic
                KY = _regex.default,
                --// SEGA - Grouping of file extensions in SCH //--  http://adc.sourceforge.net/ADC-EXT.html#_sega_grouping_of_file_extensions_in_sch
                GR = _regex.integer,
                RX = _regex.default,

            },
            nonpclones = false,

        },
        RES = {

            pp = { len = 0, },
            np = {

                FN = _regex.default,
                SI = _regex.integer,
                SL = _regex.integer,
                TO = _regex.default,
                TR = _regex.th,
                TD = _regex.integer,
                --// ASCH - Extended searching capability //--  http://adc.sourceforge.net/ADC-EXT.html#_asch_extended_searching_capability
                FI = _regex.default,
                FO = _regex.default,
                DA = _regex.default,

            },
            nonpclones = true,

        },
        PAS = {

            pp = {

                _regex.th,

                len = 1,

            },
            nonpclones = true,

        },
        -- ADC 6.3.10 QUI. Hub-direction (IQUI) is built directly via
        -- string concat in disconnect() and user.kill, but the
        -- parser also needs the shape so client-direction (HQUI =
        -- "I'm leaving") parses through to the dispatcher instead
        -- of being dropped as unknown. pp is the leaving user's SID;
        -- np = empty lets the default validator pass any spec-defined
        -- flag (RD / TL / MS / ID / RDEX RX-PT-RP) without enumerating
        -- them here. T1.7 of #147.
        QUI = {

            pp = {

                _regex.sid,

                len = 1,

            },
            np = { },
            nonpclones = false,

        },
        -- Phase 8 S4b ADC-EXT ZLIF stream-on / stream-off. The fourcc
        -- class can be B / I / H (per the streamctl context above);
        -- there are no positional or named parameters in the spec.
        -- Empty pp/np shape so adc_parse accepts the message; the
        -- actual transport-level handling (install inflate / close
        -- connection) lives in hub.lua's incoming intercept.
        ZON = {

            pp = { len = 0, },
            np = { },
            nonpclones = false,

        },
        ZOF = {

            pp = { len = 0, },
            np = { },
            nonpclones = false,

        },
        -- Phase 8 S5 ADC-EXT BLOM + ZLIG. GET/SND share the same
        -- 4-positional shape (type, identifier, start, bytes); GET
        -- adds optional named-params (BK=k, BH=h for BLOM; ZL=1 for
        -- ZLIG opt-in inside the transfer). SND also accepts ZL=1
        -- to indicate the binary phase is zlib-deflated (read-only
        -- support: the hub never uses ZLIG on these GET/SND today,
        -- but the parser must accept the param so a future ZLIG
        -- patch can be hub-side-only). GFI carries 2 positionals
        -- (type, identifier) and no parameters of interest here.
        --
        -- The H-class context for GET/SND/GFI is already declared
        -- in the contexts table further down; this just teaches
        -- adc_parse the body shape so HSND (the only one luadch
        -- currently dispatches on) is not silently rejected as
        -- "command unknown" (the ZON/ZOF lesson from S4b).
        GET = {

            pp = {

                _regex.default,
                _regex.default,
                _regex.integer,
                _regex.integer,

                len = 4,

            },
            np = {

                BK = _regex.integer,
                BH = _regex.integer,
                ZL = _regex.bool,

            },
            nonpclones = false,

        },
        SND = {

            pp = {

                _regex.default,
                _regex.default,
                _regex.integer,
                _regex.integer,

                len = 4,

            },
            np = {

                ZL = _regex.bool,

            },
            nonpclones = false,

        },
        GFI = {

            pp = {

                _regex.default,
                _regex.default,

                len = 2,

            },
            np = { },
            nonpclones = false,

        },

    },
    contexts = {

        STA = _regex.context.hubdirect,
        SUP = _regex.context.hub,
        SID = _regex.context.hub,
        INF = _regex.context.bcast,
        MSG = _regex.context.send,
        SCH = _regex.context.send,
        RES = _regex.context.result,
        CTM = _regex.context.direct,
        RCM = _regex.context.direct,
        NAT = _regex.context.direct,    -- ADC-EXT NATT
        RNT = _regex.context.direct,    -- ADC-EXT NATT
        GPA = _regex.context.hub,
        PAS = _regex.context.hub,
        QUI = _regex.context.hub,
        GET = _regex.context.hub,
        GFI = _regex.context.hub,
        SND = _regex.context.hub,
        ZON = _regex.context.streamctl,    -- Phase 8 S4b ADC-EXT ZLIF stream-on
        ZOF = _regex.context.streamctl,    -- Phase 8 S4b ADC-EXT ZLIF stream-off
        TCP = _regex.context.hub,          -- #214 HBRI HTCP (client -> hub)

    }

}

_base32 = {

    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",

}

_protocol_types = _protocol.types
_protocol_commands = _protocol.commands

_contextsend = "[BFDE]"
_contextdirect = "[DE]"

-- CSPRNG-backed: 256 % 32 == 0, so (byte & 31) is a uniform draw from
-- [0, 31] without modulo bias. Random source is OpenSSL RAND_bytes via
-- the adclib C module (Phase 7 F-AUTH-2 fix).
adclib.createsid = function( )
    local b = adclib_random_bytes( 4 )
    return _base32[ ( string_byte( b, 1 ) % 32 ) + 1 ] ..
           _base32[ ( string_byte( b, 2 ) % 32 ) + 1 ] ..
           _base32[ ( string_byte( b, 3 ) % 32 ) + 1 ] ..
           _base32[ ( string_byte( b, 4 ) % 32 ) + 1 ]
end

adclib.createsalt = function( num )
    num = num or 10
    local b = adclib_random_bytes( num )
    local out = { }
    for i = 1, num do
        out[ i ] = _base32[ ( string_byte( b, i ) % 32 ) + 1 ]
    end
    return table_concat( out )
end

checkadccmd = function( data, traceback, noerror )
    local what = type( data )
    if not _adccmds[ data ] then
        _ = noerror or error( "wrong type: adccmd expected, got " .. what, traceback or 3 )
        return false
    end
    return true
end

checkadcstring = function( data, traceback, noerror )
    local what = type( data )
    if what ~= "string" or not adclib_isutf8( data ) or not parse( data ) then
        _ = noerror or error( "wrong type: adcstring expected, got " .. what, traceback or 3 )
        return false
    end
    return true
end

checkadcstr = function( data, traceback, noerror )
    local what = type( data )
    if what ~= "string" or not adclib_isutf8( data ) or utf_find( data, " " ) or utf_find( data, "\n" ) then
        _ = noerror or error( "wrong type: adcstr expected, got " .. what, traceback or 3 )
        return false
    end
    return true
end

createid = function( )
    local str = os_date( ) .. os_clock( ) .. os_time( )
    local pass = adclib.createsalt( )
    local pid = adclib_hashpas( pass .. str, str .. pass )
    return pid, adclib_hash( pid )
end

adccmd_pos = function( self, pos )
    types_check( pos, "number" )
    if pos == 1 then
        return self[ 1 ] .. self[ 2 ]
    else
        return self[ 2 * pos ]
    end
end

adccmd_getallnp = function( self )
    local length = self.length
    local namedstart = self.namedstart
    if namedstart then
        local i = namedstart - 3
        return function( )
            i = i + 3
            if i < length then
                return self[ i ], self[ i + 1 ]
            end
        end
    else
        return function( )
        end
    end
end

adccmd_getnp = function( self, target )
    types_utf8( target )
    local namedstart = self.namedstart
    if namedstart then
        for i = namedstart, self.length, 3 do
            if target == self[ i ] then
                return self[ i + 1 ]
            end
        end
    end
    return nil
end

adccmd_addnp = function( self, target, value )
    types_utf8( target )
    types_utf8( value )
    local length = self.length
    self[ length ] = " "
    self[ length + 1 ] = target
    self[ length + 2 ] = value
    self[ length + 3 ] = "\n"
    self.namedstart = self.namedstart or length + 1
    local namedend = self.namedend
    if namedend then
        self.namedend = namedend + 3
    else
        self.namedend = length + 2
    end
    self.length = length + 3
    self.cache = nil
    --types_check( self:adcstring( ), "adcstring" )
    return true
end

adccmd_setnp = function( self, target, value )
    types_utf8( target )
    types_utf8( value )
    local namedstart = self.namedstart
    local len = self.length
    if namedstart then
        for i = namedstart, len, 3 do
            if target == self[ i ] then
                self[ i + 1 ] = value
                self.cache = nil
                return true
            end
        end
    end
    --types_check( self:adcstring( ), "adcstring" )
    return adccmd_addnp( self, target, value )    -- add new np
end

adccmd_deletenp = function( self, target )
    types_utf8( target )
    local length = self.length
    local namedstart = self.namedstart
    if namedstart then
        for i = namedstart, length, 3 do
            if target == self[ i ] then
                table_remove( self, i - 1 )
                table_remove( self, i - 1 )
                table_remove( self, i - 1 )
                local namedend = self.namedend - 3
                self.namedend = namedend
                self.length = length - 3
                if namedend <= namedstart then
                    self.namedstart, self.namedend = nil, nil
                end
                self.cache = nil
                return true
            end
        end
    end
    return false
end

adccmd_hasparam = function( self, target )
    types_utf8( target )
    for i = 1, self.length - 1 do
        local param = self[ i ]
        if target == param .. self[ i + 1 ] or target == param then
            return true
        end
    end
    return false
end

adccmd_adcstring = function( self )
    local adcstring = self.cache
    if not adcstring then
        adcstring = table_concat( self, "", 1, self.length )
        --self.cache = adcstring -- disable cache; it doesn't do any good, but has caused at least one subtle bug
    end
    return adcstring
end

adccmd_mysid = function( self )
    return string_match( self[ 1 ], _contextsend ) and self[ 4 ]
end

adccmd_targetsid = function( self )
    return string_match( self[ 1 ], _contextdirect ) and self[ 6 ]
end

adccmd_fourcc = function( self )
    return self[ 1 ] .. self[ 2 ]
end

adccmd_type = function( self )
    return self[ 1 ]
end

adccmd_cmd = function( self )
    return self[ 2 ]
end

parse = function( data )

    -- Phase 7d F-PRS-3: was commented out, leaving the parser entry
    -- gate dependent on every caller remembering to call adclib_isutf8
    -- first. Defence-in-depth: re-enable here so non-UTF-8 / NUL-bearing
    -- input can never reach string_gsub / string_sub below.
    types_utf8( data )

    -- Phase 7d F-PRS-5: cap individual command size at the parser
    -- layer (separate from server.lua's per-connection 1 MiB read
    -- buffer).
    if #data > MAX_COMMAND_SIZE then
        out_put( "adc.lua: function 'parse': command exceeds MAX_COMMAND_SIZE (", #data, " > ", MAX_COMMAND_SIZE, ")" )
        return nil
    end

    -- ADC 1.0 section 3.1: the only defined escapes are \s (space), \n
    -- (newline) and \\ (backslash); "any message containing unknown escapes
    -- must be discarded" (#419). Validate PAIRWISE - strip the valid escapes
    -- first, and any leftover backslash is then an unknown escape (\q) or an
    -- unescaped/trailing backslash. A naive "\ not followed by s/n/\" scan is
    -- wrong: it false-positives on \\q (an escaped backslash followed by a
    -- literal q, i.e. the valid wire form of the text "\q") and misses a lone
    -- trailing backslash. A backslash-free message (most protocol commands)
    -- skips the gsub via the single plain find; a message with escapes (e.g.
    -- any multi-word chat, which carries \s) takes one bounded O(n) gsub -
    -- both cheap.
    if string_find( data, "\\", 1, true )
       and string_find( ( string_gsub( data, "\\[sn\\]", "" ) ), "\\", 1, true ) then
        out_put( "adc.lua: function 'parse': message contains an unknown escape sequence (ADC 3.1), discarding: '", data, "'" )
        return nil
    end

    out_put( "adc.lua: try to parse '", data, "'" )

    local command = { }    -- array with parsed and checked message params (includes seperators and "\n"); is used also as adc command object with methods

    -- Phase 7d F-PRS-4: buffer / clone / eol are now parse-locals
    -- instead of module-globals. Makes parse() reentrant and frees
    -- intermediate slot references for GC at end of parse rather than
    -- keeping them alive until the next call.
    local buffer = { }
    local clone = { }
    local eol = 0

    string_gsub( data, "([^ ]+)", function( s )
        eol = eol + 1
        buffer[ eol ] = s
    end )    -- extract message data into buffer; seperators wont be saved

    if eol < 2 then
        out_put( "adc.lua: function 'parse': adc message to short" )
        return nil
    end

    --// extract type, command from message header; check context //--

    local fourcc = buffer[ 1 ]

    local msgtype = string_sub( fourcc, 1, 1 )

    local header = _protocol_types[ msgtype ]

    if not header then
        out_put( "adc.lua: function 'parse': type '", msgtype, "' is invalid, unknown or unsupported" )
        return nil
    end
    local msgcmd = string_sub( fourcc, 2, -1 )
    local context = _protocol.contexts[ msgcmd ]
    if not context or not string_match( msgtype, context ) then
        out_put( "adc.lua: function 'parse': invalid message header: type/cmd mismatch, unknown or unsupported ('", fourcc, "')" )
        return nil
    end

    --// parse message header, body and parameters //--

    command[ 1 ] = msgtype
    command[ 2 ] = msgcmd

    local length = 2

    --// header //--

    local len = header.len

    if eol < len then
        out_put( "adc.lua: function 'parse': adc message to short" )
        return nil
    end

    for i, regex in ipairs( header ) do
        local param = buffer[ i + 1 ]
        if not regex( param ) then
            out_put( "adc.lua: function 'parse': invalid value in header '", fourcc, "': ", param )
            return nil
        end
        length = length + 2
        command[ length - 1 ] = " "
        command[ length ] = param
    end

    --// body //--

    local cmd = _protocol_commands[ msgcmd ]
    if not cmd then
        out_put( "adc.lua: function 'parse': command '", msgcmd, "' is unknown or unsupported" )
        return nil
    end

    --// positional parameters //--

    local paramstart = 2 + len    -- start of message params in buffer
    local positionalstart    -- start of positional parameters in array "command"
    local positionalend    -- end of positional parameters in array "command"
    local namedstart    -- start of named parameters in array "command"
    local namedend    -- end of named parameters in array "command"

    local ppregex = cmd.pp

    len = paramstart + ppregex.len - 1

    for i = paramstart, len do
        local param = buffer[ i ]
        -- Phase 8a F-PRS-7: a malformed command can be missing positional
        -- parameters the cmd descriptor declares (e.g. BMSG without a
        -- body). buffer[i] is then nil, and the validators were called
        -- with nil and crashed on string_find/string_match. Treat
        -- missing as parse failure same as an invalid value would be.
        if param == nil or not ppregex[ i - paramstart + 1 ]( param ) then
            out_put( "adc.lua: function 'parse': invalid positional parameter in '", fourcc, "' on position ", i, ": ", tostring( param ) )
            return nil
        end
        length = length + 2
        command[ length - 1 ] = " "
        command[ length ] = param
        positionalstart = positionalstart or length
    end
    positionalend = positionalstart and length

    --// named paramters //--

    local noclones = cmd.nonpclones

    local np = cmd.np

    -- Phase 7g F-PRS-6: unknown two-letter named parameters used to be
    -- forwarded verbatim - the corridor a future protocol-confusion
    -- bug would use. Apply the safe-charset default validator (rejects
    -- raw control bytes) to anything not in cmd.np so an attacker
    -- cannot smuggle CR / NL / NUL via "XX" the parser does not
    -- recognise. Forwards-compat with future ADC extensions still
    -- works for clean ASCII / UTF-8 payloads.
    local default_validator = _regex.default

    for i = len + 1, eol do
        local param = buffer[ i ]
        local name = string_sub( param, 1, 2 ) or ""
        local npregex = np[ name ] or default_validator
        local body = string_sub( param, 3, -1 ) or ""
        if clone[ name ] ~= true and clone[ name ] ~= body then
            if npregex( body ) then
                length = length + 3
                command[ length - 2 ] = " "
                command[ length - 1 ] = name
                command[ length ] = body
                if noclones then
                    clone[ name ] = true
                else
                    clone[ name ] = body
                end
                namedstart = namedstart or length - 1
            else
                out_put( "adc.lua: function 'parse': invalid named parameter in '", fourcc, "': ", body )
                return nil
            end
        else
            out_put( "adc.lua: function 'parse': removed clone named parameter in '", fourcc, "': ", body )
        end
    end
    -- `clone` is now parse-local; the explicit clean() call from the
    -- module-global era is no longer needed (closure goes out of
    -- scope at function return).

    namedend = namedstart and length

    length = length + 1

    command[ length ] = "\n"

    --// create adc command object //--

    local contextsend = "[BFDE]"
    local contextdirect = "[DE]"

    --// public methods of the object //--

    command.length = length
    command.namedend = namedend
    command.namedstart = namedstart

    --// this saves creating closures, but you have to use "self" //--

    command.pos = adccmd_pos
    command.mysid = adccmd_mysid
    command.getnp = adccmd_getnp
    command.addnp = adccmd_addnp
    command.setnp = adccmd_setnp
    command.fourcc = adccmd_fourcc
    command.type = adccmd_type
    command.cmd = adccmd_cmd
    command.getallnp = adccmd_getallnp
    command.deletenp = adccmd_deletenp
    command.hasparam = adccmd_hasparam
    command.adcstring = adccmd_adcstring
    command.targetsid = adccmd_targetsid

    out_put( "adc.lua: function 'parse': parsed '", command:adcstring( ), "'" )

    _adccmds[ command ] = fourcc

    return command, fourcc
end

----------------------------------// BEGIN //--

use "setmetatable" ( _adccmds, { __mode = "k" } )

types.add( "adcstr", checkadcstr )
types.add( "adccmd", checkadccmd )
types.add( "adcstring", checkadcstring )

----------------------------------// PUBLIC INTERFACE //--

return {

    parse = parse,
    createid = createid,

}
