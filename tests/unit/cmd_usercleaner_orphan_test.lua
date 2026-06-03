--[[

    tests/unit/cmd_usercleaner_orphan_test.lua

    Unit tests for #311 - the sweep_orphan_descriptions() helper in
    scripts/cmd_usercleaner.lua. The function itself depends on hub
    runtime (hub.getregusers, util.load/savetable) so the test
    inlines a verbatim copy of the logic against in-memory stubs;
    if the plugin file diverges from the body below, update both.

    Coverage:
      - empty desc table -> 0 removed, no save
      - all entries match a user -> 0 removed, no save
      - mixed (orphans + live) -> orphans removed, live preserved, save fired
      - all orphans (empty user.tbl) -> all removed, save fired
      - regression for the pairs+modify hazard (collect-then-mutate)

    Run: lua5.4 tests/unit/cmd_usercleaner_orphan_test.lua
    Exit 0 = all pass, 1 = a failure.

]]--

-- In-memory file stub. `saved_count` lets the test assert that
-- savetable is called exactly when the function should persist.
local fake_storage = nil
local saved_count = 0
local function reset_fakes()
    fake_storage = nil
    saved_count = 0
end

local fake_util = {
    loadtable = function( _path )
        if fake_storage == nil then return nil end
        -- shallow clone so the implementation can't mutate our seed
        local copy = {}
        for k, v in pairs( fake_storage ) do copy[ k ] = v end
        return copy
    end,
    savetable = function( tbl, _name, _path )
        saved_count = saved_count + 1
        fake_storage = {}
        for k, v in pairs( tbl ) do fake_storage[ k ] = v end
        return true
    end,
}

local fake_users = {}
local fake_hub = {
    getregusers = function() return fake_users end,
}

-- Verbatim copy of sweep_orphan_descriptions() from
-- scripts/cmd_usercleaner.lua. Keep in sync with the plugin.
local description_file = "scripts/data/cmd_reg_descriptions.tbl"
local util = fake_util
local hub = fake_hub
local sweep_orphan_descriptions = function()
    local description_tbl = util.loadtable( description_file ) or {}
    local user_tbl = hub.getregusers()
    local valid_nicks = {}
    for _, u in ipairs( user_tbl ) do
        if u.nick then valid_nicks[ u.nick ] = true end
    end
    local orphans = {}
    for nick in pairs( description_tbl ) do
        if not valid_nicks[ nick ] then orphans[ #orphans + 1 ] = nick end
    end
    if #orphans == 0 then return 0 end
    for _, nick in ipairs( orphans ) do description_tbl[ nick ] = nil end
    util.savetable( description_tbl, "description_tbl", description_file )
    return #orphans
end

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-60s got=%q want=%q\n",
            label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

local function table_keys( t )
    local k, n = {}, 0
    for key in pairs( t ) do n = n + 1; k[ n ] = key end
    table.sort( k )
    return table.concat( k, "," )
end

-- ============================================================
-- Case 1: empty description table -> 0 removed, no save
-- ============================================================
reset_fakes()
fake_storage = {}
fake_users   = {}
local removed = sweep_orphan_descriptions()
eq( "c1: empty tbl -> 0 removed",  removed, 0 )
eq( "c1: empty tbl -> no save",    saved_count, 0 )

-- ============================================================
-- Case 2: all 3 entries match a regged user -> 0 removed, no save
-- ============================================================
reset_fakes()
fake_storage = {
    Alice = { tBy = "op", tReason = "founder" },
    Bob   = { tBy = "op", tReason = "regular" },
    Carol = { tBy = "op", tReason = "regular" },
}
fake_users = {
    { nick = "Alice" }, { nick = "Bob" }, { nick = "Carol" },
}
removed = sweep_orphan_descriptions()
eq( "c2: all live -> 0 removed",   removed, 0 )
eq( "c2: all live -> no save",     saved_count, 0 )
eq( "c2: all live -> tbl intact",  table_keys( fake_storage ), "Alice,Bob,Carol" )

-- ============================================================
-- Case 3: mixed (2 orphans + 3 live) -> 2 removed, 3 preserved, save fired
-- ============================================================
reset_fakes()
fake_storage = {
    Alice   = { tBy = "op", tReason = "founder" },
    Bob     = { tBy = "op", tReason = "regular" },
    Carol   = { tBy = "op", tReason = "regular" },
    OldDude = { tBy = "op", tReason = "left in 2022" },
    GhostX  = { tBy = "op", tReason = "deleted by pre-f87c861 usercleaner" },
}
fake_users = {
    { nick = "Alice" }, { nick = "Bob" }, { nick = "Carol" },
}
removed = sweep_orphan_descriptions()
eq( "c3: mixed -> 2 removed",      removed, 2 )
eq( "c3: mixed -> save fired",     saved_count, 1 )
eq( "c3: mixed -> survivors",      table_keys( fake_storage ), "Alice,Bob,Carol" )
eq( "c3: mixed -> orphan gone (OldDude)", fake_storage.OldDude, nil )
eq( "c3: mixed -> orphan gone (GhostX)",  fake_storage.GhostX, nil )
eq( "c3: mixed -> live preserved (Alice)", fake_storage.Alice.tReason, "founder" )

-- ============================================================
-- Case 4: all orphans (empty user.tbl) -> all removed, save fired
-- ============================================================
reset_fakes()
fake_storage = {
    A = { tBy = "op", tReason = "x" },
    B = { tBy = "op", tReason = "y" },
    C = { tBy = "op", tReason = "z" },
}
fake_users = {}
removed = sweep_orphan_descriptions()
eq( "c4: all orphans -> 3 removed", removed, 3 )
eq( "c4: all orphans -> save fired", saved_count, 1 )
eq( "c4: all orphans -> tbl empty", table_keys( fake_storage ), "" )

-- ============================================================
-- Case 5: regression - pairs+modify hazard.
-- 50 orphans collected at once. If a naive implementation set
-- entries to nil during the pairs() iteration, Lua 5.4 still
-- visits the remaining keys but the order is implementation-
-- defined; the collect-then-mutate split below makes the test
-- result deterministic.
-- ============================================================
reset_fakes()
fake_storage = {}
for i = 1, 50 do
    fake_storage[ "old_" .. i ] = { tBy = "op", tReason = "stale" }
end
fake_storage[ "Live" ] = { tBy = "op", tReason = "active" }
fake_users = { { nick = "Live" } }
removed = sweep_orphan_descriptions()
eq( "c5: 50 orphans + 1 live -> 50 removed", removed, 50 )
eq( "c5: 50 orphans + 1 live -> save fired", saved_count, 1 )
eq( "c5: 50 orphans + 1 live -> survivor",   table_keys( fake_storage ), "Live" )

-- ============================================================
-- Case 6: defensive - user entry with nil nick is ignored, not
-- treated as a valid match for empty-keyed orphans.
-- ============================================================
reset_fakes()
fake_storage = { Alice = { tBy = "op", tReason = "x" } }
fake_users = { { nick = nil }, { nick = "Alice" } }
removed = sweep_orphan_descriptions()
eq( "c6: nil-nick user skipped, Alice preserved", removed, 0 )

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
