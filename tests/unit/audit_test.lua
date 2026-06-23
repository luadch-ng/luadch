--[[

    tests/unit/audit_test.lua

    Unit tests for core/audit.lua (#84). Covers:
      - audit.build event-shape contract
      - actor snapshot (user-object / flat table / string / nil)
      - target snapshot (user-object / flat table / nil)
      - reason / meta normalization (control-byte strip + length cap)
      - rejection of malformed action argument
      - audit.fire delegates to scripts.firelistener("onAudit", ...)

    Run: lua5.4 tests/unit/audit_test.lua
    Exit 0 = all pass, 1 = a failure.

]]--

----------------------------------------------------------------------
-- minimal `use` shim. audit.lua loads util.strip_control_bytes at
-- module top, then lazy-binds scripts + cfg + out via use inside
-- fire() / init(). We stub all four.
----------------------------------------------------------------------

local _real = {
    type = type, pairs = pairs, tostring = tostring, tonumber = tonumber,
    string = string,
}

-- Configurable cfg cap (so retention / length tests can tweak them).
local cfg_caps = {
    audit_log_max_reason_chars     = 1000,
    audit_log_max_meta_value_chars = 1000,
}

-- Last fired event (set by fire()).
local _last_fired

local mocks = {
    util = {
        strip_control_bytes = function( s )
            -- Strip ASCII control bytes (0x00-0x1F, 0x7F) but keep
            -- everything else. Mirrors core/util.lua's pure-Lua impl.
            if type( s ) ~= "string" then return s end
            return ( s:gsub( "[%z\1-\31\127]", "" ) )
        end,
    },
    scripts = {
        firelistener = function( ltype, event )
            _last_fired = { ltype = ltype, event = event }
        end,
    },
    cfg = {
        get = function( key )
            return cfg_caps[ key ]
        end,
    },
    out = {
        error = function( ... ) end,    -- swallow error log lines
    },
}

_G.use = function( name )
    local v = _real[ name ] or mocks[ name ]
    assert( v ~= nil, "audit_test shim missing dep: use \"" .. name .. "\"" )
    return v
end

----------------------------------------------------------------------
-- Load the module under test.
----------------------------------------------------------------------

local audit = assert( loadfile( "core/audit.lua" ) )( )
audit.init( )    -- binds cfg + out

----------------------------------------------------------------------
-- Minimal test framework.
----------------------------------------------------------------------

local failures, checks = 0, 0
local function check( label, ok, detail )
    checks = checks + 1
    if not ok then
        failures = failures + 1
        io.write( string.format( "FAIL %s%s\n", label,
            detail and ( "  -- " .. detail ) or "" ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

local function eq( label, got, want )
    check( label, got == want,
        string.format( "got=%s want=%s", tostring( got ), tostring( want ) ) )
end

----------------------------------------------------------------------
-- Helpers to build mock user-objects matching the hub's contract.
-- core/audit.lua detects user-objects by `type(nick) == "function"`.
----------------------------------------------------------------------

local function mock_user( fields )
    fields = fields or {}
    return {
        nick      = function( ) return fields.nick      or fields.firstnick or "alice" end,
        firstnick = function( ) return fields.firstnick or fields.nick      or "alice" end,
        level     = function( ) return fields.level     or 80                          end,
        sid       = function( ) return fields.sid       or "ABCD"                      end,
        cid       = function( ) return fields.cid       or "CID1234"                   end,
        ip        = function( ) return fields.ip        or "1.2.3.4"                   end,
    }
end

----------------------------------------------------------------------
-- build(): action validation
----------------------------------------------------------------------

do
    local ev = audit.build( "", mock_user( ) )
    check( "build: rejects empty action", ev == nil )
end

do
    local ev = audit.build( nil, mock_user( ) )
    check( "build: rejects nil action", ev == nil )
end

do
    local ev = audit.build( 42, mock_user( ) )
    check( "build: rejects non-string action", ev == nil )
end

----------------------------------------------------------------------
-- build(): actor snapshot
----------------------------------------------------------------------

do
    local ev = audit.build( "test.action", mock_user{ firstnick = "admin", level = 100, sid = "AAAA", cid = "C1", ip = "10.0.0.1" } )
    check( "actor user-object: event built", type( ev ) == "table" )
    eq( "actor user-object: action", ev.action, "test.action" )
    eq( "actor user-object: nick",   ev.actor.nick,  "admin" )
    eq( "actor user-object: level",  ev.actor.level, 100     )
    eq( "actor user-object: sid",    ev.actor.sid,   "AAAA"  )
    eq( "actor user-object: cid",    ev.actor.cid,   "C1"    )
    eq( "actor user-object: ip",     ev.actor.ip,    "10.0.0.1" )
    check( "actor user-object: no display_nick when firstnick == nick",
        ev.actor.display_nick == nil )
end

do
    -- Level-prefixed display name: `nick()` returns "[OP]bob" while
    -- `firstnick()` returns "bob". audit.nick = firstnick; the
    -- visible form lands in display_nick.
    local ev = audit.build( "test.action",
        mock_user{ firstnick = "bob", nick = "[OP]bob", level = 60 } )
    eq( "actor prefixed: nick = firstnick",         ev.actor.nick,         "bob"     )
    eq( "actor prefixed: display_nick = visible",   ev.actor.display_nick, "[OP]bob" )
end

do
    local ev = audit.build( "test.action", { nick = "tok-label", sid = "<http>" } )
    eq( "actor flat table: nick",  ev.actor.nick,  "tok-label" )
    eq( "actor flat table: sid",   ev.actor.sid,   "<http>"    )
    eq( "actor flat table: level (default)", ev.actor.level, 0 )
    eq( "actor flat table: cid (default)",   ev.actor.cid,   "" )
end

do
    local ev = audit.build( "test.action", "just-a-nick" )
    eq( "actor string: nick",  ev.actor.nick,  "just-a-nick" )
    eq( "actor string: level", ev.actor.level, 0 )
end

do
    local ev = audit.build( "test.action", nil )
    check( "actor nil: actor table present", type( ev.actor ) == "table" )
    eq( "actor nil: nick = empty", ev.actor.nick, "" )
end

----------------------------------------------------------------------
-- build(): target snapshot
----------------------------------------------------------------------

do
    local victim = mock_user{ firstnick = "victim", level = 20, sid = "ZZZZ", cid = "C2", ip = "5.5.5.5" }
    local ev = audit.build( "user.kick", mock_user( ), victim )
    eq( "target user-object: nick",  ev.target.nick,  "victim" )
    eq( "target user-object: level", ev.target.level, 20       )
    eq( "target user-object: ip",    ev.target.ip,    "5.5.5.5" )
end

do
    local ev = audit.build( "ban.add", mock_user( ), { nick = "bad", ip = "1.1.1.1" } )
    eq( "target flat table: nick", ev.target.nick, "bad" )
    eq( "target flat table: ip",   ev.target.ip,   "1.1.1.1" )
    check( "target flat table: missing field absent",
        ev.target.cid == nil or ev.target.cid == "" )
end

do
    local ev = audit.build( "hub.reload", mock_user( ), nil )
    check( "target nil: target is nil in event", ev.target == nil )
end

do
    -- Control-byte strip on flat target.
    local ev = audit.build( "ban.add", mock_user( ),
        { nick = "with\x01ctrl\x07bytes", ip = "1.1.1.1" } )
    eq( "target flat table: ctrl bytes stripped from nick",
        ev.target.nick, "withctrlbytes" )
end

----------------------------------------------------------------------
-- build(): reason normalization
----------------------------------------------------------------------

do
    local ev = audit.build( "ban.add", mock_user( ), nil, "spam\x00with\x1fctrl" )
    eq( "reason: ctrl bytes stripped", ev.reason, "spamwithctrl" )
end

do
    local ev = audit.build( "ban.add", mock_user( ), nil, nil )
    check( "reason nil: reason is nil in event", ev.reason == nil )
end

do
    -- Cap reason at the configured length.
    cfg_caps.audit_log_max_reason_chars = 20
    local long = string.rep( "x", 100 )
    local ev = audit.build( "ban.add", mock_user( ), nil, long )
    eq( "reason: capped to 20 chars", #ev.reason, 20 )
    cfg_caps.audit_log_max_reason_chars = 1000    -- restore
end

----------------------------------------------------------------------
-- build(): meta normalization
----------------------------------------------------------------------

do
    local ev = audit.build( "ban.add", mock_user( ), nil, nil,
        { duration_sec = 86400, online = true, by = "nick" } )
    eq( "meta: number passes through",  ev.meta.duration_sec, 86400  )
    eq( "meta: boolean passes through", ev.meta.online,       true   )
    eq( "meta: string passes through",  ev.meta.by,           "nick" )
end

do
    -- Meta values get the SAME control-byte strip as reason / target.
    local ev = audit.build( "ban.add", mock_user( ), nil, nil,
        { note = "ctrl\x05inside" } )
    eq( "meta string: ctrl bytes stripped", ev.meta.note, "ctrlinside" )
end

do
    local ev = audit.build( "ban.add", mock_user( ), nil, nil, nil )
    check( "meta nil: meta is nil in event", ev.meta == nil )
end

do
    -- Empty meta table collapses to nil so dkjson does not emit
    -- an ambiguous `[]` (Lua empties serialize as arrays). Fix for
    -- the `meta: []` artifact spotted in the first smoke run.
    local ev = audit.build( "ban.add", mock_user( ), nil, nil, { } )
    check( "meta empty table: collapses to nil", ev.meta == nil )
end

do
    -- Likewise for a table whose entries all happen to be nil
    -- (Lua-collapsed at construction time).
    local ev = audit.build( "ban.add", mock_user( ), nil, nil, { x = nil, y = nil } )
    check( "meta all-nil collapses: nil in event", ev.meta == nil )
end

----------------------------------------------------------------------
-- fire(): delegates to scripts.firelistener("onAudit", event)
----------------------------------------------------------------------

do
    _last_fired = nil
    local ev = audit.build( "test.fire", mock_user( ) )
    audit.fire( ev )
    check( "fire: listener invoked",            _last_fired ~= nil )
    eq(    "fire: listener type = 'onAudit'",   _last_fired and _last_fired.ltype, "onAudit" )
    check( "fire: event payload pass-through",  _last_fired and _last_fired.event == ev )
end

do
    -- A non-table event must not fire (defensive: audit.build returns
    -- nil on bad action, callers should guard but we don't crash if
    -- they don't).
    _last_fired = nil
    audit.fire( nil )
    check( "fire: nil event does NOT fire", _last_fired == nil )
end

do
    _last_fired = nil
    audit.fire( "not a table" )
    check( "fire: string event does NOT fire", _last_fired == nil )
end

----------------------------------------------------------------------
-- Final summary.
----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
