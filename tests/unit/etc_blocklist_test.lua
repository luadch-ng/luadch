--[[

    tests/unit/etc_blocklist_test.lua

    Unit tests for scripts/etc_blocklist.lua (#78 Phase B).

    Coverage:
      - parse_add_args: cidr-only, +stealth flag, reason="quoted",
                       expires=YYYY-MM-DD, all-three-options together
      - parse_expires_date: YYYY-MM-DD -> end-of-day timestamp, bad
                       date returns nil
      - do_add_entry: happy path, bad cidr surfaces engine err,
                       bad expires surfaces date err
      - do_del_entry: not_found, hierarchy block (op-level too low),
                       happy path
      - _sanitize_import_row: control-byte stripping on every field
      - format_show / format_count: basic shape

    The core blocklist engine is stubbed with an in-memory list so
    the test isolates the plugin's mutation/dispatch logic from the
    Phase A bucketed-cache behaviour (which has its own test file).

    Run: lua5.4 tests/unit/etc_blocklist_test.lua
    Exit 0 = all pass, 1 = a failure (CI-friendly).

]]--

----------------------------------------------------------------------
-- Stub the core engine in a tiny in-memory replica. Mirrors the
-- public API the plugin uses: add / remove / list / count.
----------------------------------------------------------------------

local _entries = { }
local _next_id = 1

_G.blocklist = {
    add = function( cidr, opts )
        if type( cidr ) ~= "string" or cidr == "" then
            return false, nil, "bad cidr"
        end
        if cidr:find( "INVALID" ) then
            return false, nil, "synthetic-bad"
        end
        opts = opts or { }
        local e = {
            id         = _next_id,
            cidr       = cidr,
            source     = opts.source or "manual",
            stealth    = opts.stealth and true or false,
            reason     = opts.reason or "",
            by_nick    = opts.by_nick,
            by_level   = opts.by_level,
            expires_at = opts.expires_at,
            created_at = 1000,
        }
        _entries[ #_entries + 1 ] = e
        _next_id = _next_id + 1
        return true, e.id
    end,
    remove = function( id )
        for i, e in ipairs( _entries ) do
            if e.id == id then
                table.remove( _entries, i )
                return true
            end
        end
        return false, "not_found"
    end,
    list = function( filter )
        filter = filter or { }
        local out = { }
        for _, e in ipairs( _entries ) do
            if ( not filter.source ) or e.source == filter.source then
                out[ #out + 1 ] = {
                    id = e.id, cidr = e.cidr, source = e.source,
                    stealth = e.stealth, reason = e.reason,
                    by_nick = e.by_nick, by_level = e.by_level,
                    expires_at = e.expires_at, created_at = e.created_at,
                }
            end
        end
        return out
    end,
    count = function( )
        local by_source = { }
        for _, e in ipairs( _entries ) do
            by_source[ e.source ] = ( by_source[ e.source ] or 0 ) + 1
        end
        return { total = #_entries, by_source = by_source }
    end,
}

----------------------------------------------------------------------
-- Stub the remaining sandbox globals the plugin reads.
----------------------------------------------------------------------

local _registered = { onStart = nil, hub = { } }
local _audit_fired = { }
local _reports_sent = { }

_G.hub = {
    setlistener = function( event, opts, fn ) _registered[ event ] = fn end,
    debug = function( ) end,
    getbot = function( ) return "stub-bot" end,
    import = function( name )
        if name == "etc_hubcommands" then
            return {
                add = function( cmd, fn )
                    _registered.hub[ cmd ] = fn
                    return true
                end,
                has  = function( ) return false end,
                list = function( ) return { } end,
            }
        end
        if name == "etc_report" then
            return {
                send = function( a, h, o, l, m )
                    _reports_sent[ #_reports_sent + 1 ] = m
                end,
            }
        end
        return nil
    end,
}

_G.cfg = {
    get = function( key )
        if key == "language" then return "en" end
        if key == "etc_blocklist_oplevel" then return 80 end
        if key == "etc_blocklist_show_limit" then return 200 end
        if key == "etc_blocklist_report" then return true end
        if key == "etc_blocklist_report_hubbot" then return false end
        if key == "etc_blocklist_report_opchat" then return true end
        if key == "etc_blocklist_llevel" then return 60 end
        return nil
    end,
    loadlanguage = function( ) return { }, nil end,
}

_G.util = {
    strip_control_bytes = function( s )
        if type( s ) ~= "string" then return s end
        return ( s:gsub( "[%c]", "" ) )
    end,
    safe_path = function( p )
        if type( p ) ~= "string" or p == "" then return false, "empty path" end
        if p:find( "%.%." ) then return false, "parent-dir blocked" end
        return true
    end,
}

_G.utf = { match = string.match, format = string.format }
_G.PROCESSED = 1

-- In-memory io.open stub backing the export/import round-trip
-- test. write-mode returns a sink that captures bytes; read-mode
-- returns a reader that yields the captured bytes line-by-line.
-- The unit test only ever round-trips a single path; sufficient
-- to model that path correctly.
local _vfs = { }    -- path -> string

local _real_io_open = io.open
local _vfs_active = false
local function _vfs_enable( ) _vfs_active = true end
local function _vfs_disable( ) _vfs_active = false end

io.open = function( path, mode )
    if not _vfs_active then return _real_io_open( path, mode ) end
    mode = mode or "r"
    if mode == "w" or mode == "wb" then
        local buf = { }
        local handle
        handle = {
            write = function( _self, ... )
                for _, s in ipairs{ ... } do
                    buf[ #buf + 1 ] = tostring( s )
                end
                return handle
            end,
            close = function( ) _vfs[ path ] = table.concat( buf ) end,
        }
        return handle
    end
    local content = _vfs[ path ]
    if not content then return nil, "No such file or directory" end
    local pos = 1
    local handle
    handle = {
        read = function( _self, fmt )
            if fmt == "*l" or fmt == "l" then
                if pos > #content then return nil end
                local newline = content:find( "\n", pos, true )
                if newline then
                    local line = content:sub( pos, newline - 1 )
                    pos = newline + 1
                    return line
                else
                    local line = content:sub( pos )
                    pos = #content + 1
                    return line
                end
            end
        end,
        close = function( ) end,
    }
    return handle
end

_G.audit = {
    build = function( action, actor, target, reason, meta )
        return { action = action, actor = actor, target = target,
                 reason = reason, meta = meta }
    end,
    fire = function( ev ) _audit_fired[ #_audit_fired + 1 ] = ev end,
}

-- Minimal dkjson stub for JSONL round-trip tests. Real encode
-- behaviour is irrelevant to the plugin logic; we just need
-- decode(encode(x)) == x for a flat table.
_G.dkjson = {
    encode = function( t )
        -- Toy encoder: sufficient for the entry-shape we serialise.
        local parts = { }
        for k, v in pairs( t ) do
            local vs
            if type( v ) == "string" then
                vs = string.format( "%q", v )
            elseif type( v ) == "boolean" then
                vs = v and "true" or "false"
            elseif v == nil then
                vs = "null"
            else
                vs = tostring( v )
            end
            parts[ #parts + 1 ] = string.format( "%q:%s", k, vs )
        end
        return "{" .. table.concat( parts, "," ) .. "}"
    end,
    decode = function( s )
        -- Toy decoder: parse the toy encoder's output back.
        local t = { }
        for k, v in s:gmatch( '"([^"]+)":([^,}]+)' ) do
            if v:match( '^".*"$' ) then
                t[ k ] = v:sub( 2, -2 )
            elseif v == "true"  then t[ k ] = true
            elseif v == "false" then t[ k ] = false
            elseif v == "null"  then t[ k ] = nil
            else t[ k ] = tonumber( v ) or v
            end
        end
        return t
    end,
}

----------------------------------------------------------------------
-- Tiny test harness
----------------------------------------------------------------------

local passes, fails = 0, 0
local function eq( label, got, want )
    if got == want then passes = passes + 1
    else
        fails = fails + 1
        io.stderr:write( string.format(
            "FAIL: %s\n  got:  %s\n  want: %s\n",
            label, tostring( got ), tostring( want ) ) )
    end
end
local function truthy( label, v )
    if v then passes = passes + 1
    else fails = fails + 1
        io.stderr:write( "FAIL: " .. label .. " got=" .. tostring( v ) .. "\n" )
    end
end
local function falsy( label, v )
    if not v then passes = passes + 1
    else fails = fails + 1
        io.stderr:write( "FAIL: " .. label .. " got=" .. tostring( v ) .. "\n" )
    end
end

----------------------------------------------------------------------
-- Load plugin + fire onStart so commands register
----------------------------------------------------------------------

local plugin = assert( loadfile( "scripts/etc_blocklist.lua" ) )( )
assert( _registered.onStart, "onStart not registered" )
_registered.onStart( )
assert( _registered.hub.blocklist, "+blocklist hubcmd not registered" )

----------------------------------------------------------------------
-- parse_add_args
----------------------------------------------------------------------

do
    local a = plugin._parse_add_args( "1.2.3.0/24" )
    truthy( "parse: cidr-only ok",   a )
    eq( "parse: cidr",                a and a.cidr,    "1.2.3.0/24" )
    eq( "parse: cidr-only stealth=false", a and a.stealth, false )
    eq( "parse: cidr-only reason=nil",    a and a.reason,  nil )
    eq( "parse: cidr-only expires=nil",   a and a.expires, nil )

    local b = plugin._parse_add_args( "1.2.3.0/24 stealth" )
    eq( "parse: stealth flag captured", b and b.stealth, true )

    local c = plugin._parse_add_args( '1.2.3.0/24 reason="bad guys"' )
    eq( "parse: quoted reason", c and c.reason, "bad guys" )

    local d = plugin._parse_add_args( '1.2.3.0/24 stealth reason="abc def" expires=2026-12-31' )
    eq( "parse: full-spec cidr",    d and d.cidr,    "1.2.3.0/24" )
    eq( "parse: full-spec stealth", d and d.stealth, true )
    eq( "parse: full-spec reason",  d and d.reason,  "abc def" )
    eq( "parse: full-spec expires", d and d.expires, "2026-12-31" )

    local e = plugin._parse_add_args( "" )
    falsy( "parse: empty rejected", e )

    -- Smuggling guard: a malicious reason value containing an
    -- `expires=YYYY-MM-DD` literal must NOT influence the parsed
    -- expires field. The quoted reason is consumed FIRST against
    -- a working copy; the unquoted fallback then runs against the
    -- stripped copy so any key= inside the quoted reason cannot
    -- leak out as a sibling field.
    local s1 = plugin._parse_add_args(
        '1.2.3.0/24 reason="benign expires=2099-12-31 text"' )
    eq( "smuggle: quoted reason consumed",
        s1 and s1.reason, "benign expires=2099-12-31 text" )
    eq( "smuggle: no expires bled through",
        s1 and s1.expires, nil )

    -- And the reverse: an unquoted `expires=...` after a quoted
    -- reason still parses correctly (the strip leaves the unquoted
    -- portion intact).
    local s2 = plugin._parse_add_args(
        '1.2.3.0/24 reason="just a reason" expires=2026-12-31' )
    eq( "smuggle: sibling expires after stripped reason",
        s2 and s2.expires, "2026-12-31" )

    -- Coverage: unquoted reason (single-token fallback).
    local u1 = plugin._parse_add_args( "1.2.3.0/24 reason=spam" )
    eq( "parse: unquoted reason", u1 and u1.reason, "spam" )

    -- Coverage: quoted expires form (operators may also quote
    -- single-token values for consistency with reason).
    local u2 = plugin._parse_add_args(
        '1.2.3.0/24 expires="2026-12-31"' )
    eq( "parse: quoted expires", u2 and u2.expires, "2026-12-31" )
end

----------------------------------------------------------------------
-- parse_expires_date
----------------------------------------------------------------------

do
    local ts = plugin._parse_expires_date( "2026-12-31" )
    truthy( "expires: YYYY-MM-DD ok", ts )
    truthy( "expires: returns number",  type( ts ) == "number" )
    -- End-of-day semantics: the time-of-day part should be 23:59:59
    -- local. We can't assert the exact unix-ts (depends on local TZ)
    -- but we can assert the date components round-trip.
    local back = os.date( "*t", ts )
    eq( "expires: year roundtrip",  back.year,  2026 )
    eq( "expires: month roundtrip", back.month, 12 )
    eq( "expires: day roundtrip",   back.day,   31 )
    eq( "expires: hour=23",         back.hour,  23 )

    falsy( "expires: bad format rejected", plugin._parse_expires_date( "2026/12/31" ) )
    falsy( "expires: empty rejected",      plugin._parse_expires_date( "" ) )
    falsy( "expires: nil rejected",        plugin._parse_expires_date( nil ) )
end

----------------------------------------------------------------------
-- do_add_entry: happy + bad-cidr + bad-expires
----------------------------------------------------------------------

do
    -- Reset engine state
    _entries = { }; _next_id = 1

    local ok, id = plugin._do_add_entry( "192.0.2.0/24",
        { reason = "test entry" }, "alice", 80 )
    truthy( "add: ok", ok )
    eq(     "add: id=1", id, 1 )
    eq(     "add: engine got 1 entry", #_entries, 1 )
    eq(     "add: engine entry by_nick",  _entries[ 1 ].by_nick, "alice" )
    eq(     "add: engine entry by_level", _entries[ 1 ].by_level, 80 )

    local ok2, err_code = plugin._do_add_entry( "INVALID/foo", { }, "alice", 80 )
    falsy(  "add: bad cidr returns false", ok2 )
    eq(     "add: bad cidr err_code", err_code, "bad_cidr" )

    local ok3, err_code3 = plugin._do_add_entry( "10.0.0.0/8",
        { expires = "2026/13/40" }, "alice", 80 )
    falsy( "add: bad expires returns false", ok3 )
    eq(    "add: bad expires err_code", err_code3, "bad_expires" )
end

----------------------------------------------------------------------
-- do_del_entry: not_found + hierarchy block + happy path
----------------------------------------------------------------------

do
    _entries = { }; _next_id = 1
    -- Seed an entry added by a level-90 master
    plugin._do_add_entry( "10.0.0.0/8", { }, "master", 90 )

    -- Level-80 op cannot remove a level-90 entry
    local ok, err_code, msg = plugin._do_del_entry( 1, "midop", 80 )
    falsy( "del: hierarchy block fires", ok )
    eq(    "del: hierarchy err_code",     err_code, "hierarchy" )
    truthy( "del: hierarchy msg includes id",
        msg and msg:find( "#1", 1, true ) )

    -- Level-100 op CAN remove
    local ok2 = plugin._do_del_entry( 1, "owner", 100 )
    truthy( "del: higher-level op succeeds", ok2 )
    eq( "del: engine entry gone", #_entries, 0 )

    -- not_found path
    local ok3, err_code3 = plugin._do_del_entry( 99, "owner", 100 )
    falsy( "del: not_found returns false", ok3 )
    eq(    "del: not_found err_code", err_code3, "not_found" )

    -- bad-id path
    local ok4, err_code4 = plugin._do_del_entry( "abc", "owner", 100 )
    falsy( "del: bad-id returns false", ok4 )
    eq(    "del: bad-id err_code", err_code4, "bad_id" )
end

----------------------------------------------------------------------
-- _sanitize_import_row: control-byte stripping
----------------------------------------------------------------------

do
    local cidr, opts = plugin._sanitize_import_row{
        cidr   = "10.0.0.0/8\1\2\3",
        source = "manual\31",
        reason = "hello\0world",
        stealth = true,
        by_level = 50,
    }
    eq( "sanitize: cidr stripped",   cidr,           "10.0.0.0/8" )
    eq( "sanitize: source stripped", opts.source,    "manual" )
    eq( "sanitize: reason stripped", opts.reason,    "helloworld" )
    eq( "sanitize: stealth carried", opts.stealth,   true )
    eq( "sanitize: by_level kept",   opts.by_level,  50 )

    local nil_cidr = plugin._sanitize_import_row{ }
    falsy( "sanitize: missing cidr rejected", nil_cidr )
end

----------------------------------------------------------------------
-- format_show / format_count: basic shape
----------------------------------------------------------------------

do
    _entries = { }; _next_id = 1
    plugin._do_add_entry( "10.0.0.0/8",    { reason = "test1" }, "a", 80 )
    plugin._do_add_entry( "172.16.0.0/12", { stealth = true },   "b", 80 )

    local body = plugin._format_show( nil )
    truthy( "show: header present", body:find( "BLOCKLIST", 1, true ) )
    truthy( "show: cidr1 present",  body:find( "10.0.0.0/8", 1, true ) )
    truthy( "show: cidr2 present",  body:find( "172.16.0.0/12", 1, true ) )
    truthy( "show: stealth marker", body:find( "STEALTH", 1, true ) )

    local empty = plugin._format_show( "geoip" )
    truthy( "show: empty-filter shows no-entries text",
        empty:find( "no entries", 1, true ) )

    local cnt = plugin._format_count( )
    truthy( "count: total present", cnt:find( "2 entries", 1, true ) )
    truthy( "count: source line",   cnt:find( "manual:", 1, true ) )
end

----------------------------------------------------------------------
-- JSONL export / import round-trip via the in-memory io stub.
-- Demonstrates: export writes a per-line JSON file; re-import
-- against an empty engine restores the same entries (with the
-- importer's by_nick attribution; original by_level preserved in
-- the file as audit metadata but the engine's by_level is
-- re-attributed at insert).
----------------------------------------------------------------------

do
    _entries = { }; _next_id = 1
    plugin._do_add_entry( "192.0.2.0/24",
        { reason = "export round-trip test" }, "alice", 100 )
    plugin._do_add_entry( "203.0.113.0/24",
        { stealth = true, reason = "stealth row" }, "alice", 100 )

    _vfs_enable( )

    -- Real plugin code does `do_export_jsonl` which is not
    -- exposed; exercise via the dispatcher. Add a fake user
    -- minimally for the level / nick getters.
    local export_replied
    local fake_master = {
        level = function( ) return 100 end,
        nick  = function( ) return "alice" end,
        reply = function( _self, msg ) export_replied = msg end,
    }
    _registered.hub.blocklist( fake_master, nil, "export" )
    truthy( "export: reply mentions exported count",
        export_replied and export_replied:find( "exported 2", 1, true ) )

    -- Identify the on-disk path the export wrote (format:
    -- cfg/blocklist-export-YYYYMMDD-HHMMSS.jsonl).
    local exported_path
    for path in pairs( _vfs ) do
        if path:find( "blocklist%-export%-" ) then exported_path = path end
    end
    truthy( "export: file written to vfs", exported_path )

    -- Reset engine and re-import.
    _entries = { }; _next_id = 1

    local import_replied
    local fake_importer = {
        level = function( ) return 100 end,
        nick  = function( ) return "bob" end,
        reply = function( _self, msg ) import_replied = msg end,
    }
    _registered.hub.blocklist( fake_importer, nil, "import " .. exported_path )
    truthy( "import: reply mentions imported count",
        import_replied and import_replied:find( "imported 2", 1, true ) )

    eq( "import: engine has 2 entries again", #_entries, 2 )
    eq( "import: re-attributed by_nick",  _entries[ 1 ].by_nick,  "bob" )
    eq( "import: re-attributed by_level", _entries[ 1 ].by_level, 100 )

    _vfs_disable( )
end

----------------------------------------------------------------------
-- Import level guard: a mid-tier operator below the import
-- min-level cannot run import even if above oplevel.
----------------------------------------------------------------------

do
    _entries = { }; _next_id = 1
    _vfs[ "any/path.jsonl" ] = '{"cidr":"10.0.0.0/8"}\n'
    _vfs_enable( )
    local replied
    local mid_user = {
        level = function( ) return 80 end,    -- == oplevel, < import_min_level
        nick  = function( ) return "midop" end,
        reply = function( _self, msg ) replied = msg end,
    }
    _registered.hub.blocklist( mid_user, nil, "import any/path.jsonl" )
    truthy( "import-guard: blocked at level 80 (< 100)",
        replied and replied:find( "Import requires", 1, true ) )
    eq( "import-guard: no entries added", #_entries, 0 )
    _vfs_disable( )
end

----------------------------------------------------------------------
-- Dispatcher: unknown verb path goes to msg_unknown_verb
----------------------------------------------------------------------

do
    _entries = { }; _next_id = 1
    local replied
    local fake_user = {
        level = function( ) return 80 end,
        nick  = function( ) return "op" end,
        reply = function( _self, msg ) replied = msg end,
    }
    _registered.hub.blocklist( fake_user, nil, "frobnicate" )
    truthy( "dispatch: unknown verb -> msg_unknown_verb",
        replied and replied:find( "Unknown verb", 1, true ) )
end

----------------------------------------------------------------------
-- Dispatcher: denied path when user under oplevel
----------------------------------------------------------------------

do
    local replied
    local low_user = {
        level = function( ) return 50 end,
        nick  = function( ) return "lowop" end,
        reply = function( _self, msg ) replied = msg end,
    }
    _registered.hub.blocklist( low_user, nil, "show" )
    truthy( "dispatch: under oplevel -> denied",
        replied and replied:find( "not allowed", 1, true ) )
end

----------------------------------------------------------------------
-- Result
----------------------------------------------------------------------

if fails == 0 then
    io.write( string.format( "OK: %d checks passed\n", passes ) )
    os.exit( 0 )
else
    io.write( string.format( "FAILED: %d failures / %d total\n", fails, passes + fails ) )
    os.exit( 1 )
end
