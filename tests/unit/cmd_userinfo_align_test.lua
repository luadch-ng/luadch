--[[

    tests/unit/cmd_userinfo_align_test.lua

    Regression test for scripts/cmd_userinfo.lua v0.24 (#459): the
    `+userinfo` value column must line up. The labels live in the
    (translatable) lang file with ragged widths and the value used to get
    a fixed tab count, so the value column jumped by label length and by
    the client's tab-stop width. v0.24 adds `align_labels`, which pads
    every value line's label to one width computed from the actual labels
    (so it is correct in any language) and lets the value follow directly.

    This drives the real `align_labels` against the REAL msg_userinfo of
    BOTH shipped lang files and asserts:
      - the raw (shipped) format is ragged - the value column is NOT at a
        single position (this is the bug, and it fails "provably" in the
        §1a.7 sense: the shipped input really is misaligned), and
      - the aligned format is uniform - every value line's first "%s" is
        at the same column, in each language independently.

    The plugin gets NO `use`; the few load-time globals are stubbed so we
    can reach its `_align_labels` test seam. The lang files are plain
    `return { ... }` tables loaded directly (Lua 5.4 skips their BOM).

    Run: lua5.4 tests/unit/cmd_userinfo_align_test.lua

]]--

local checks, failures = 0, 0
local function ok( label, cond, extra )
    checks = checks + 1
    if not cond then failures = failures + 1
        io.write( "FAIL " .. label .. ( extra and ( " - " .. tostring( extra ) ) or "" ) .. "\n" )
    else io.write( "ok   " .. label .. "\n" ) end
end
local function contains( hay, needle ) return type( hay ) == "string" and hay:find( needle, 1, true ) ~= nil end

----------------------------------------------------------------------
-- load-time sandbox-global stubs (enough to reach _align_labels)
----------------------------------------------------------------------
_G.type = type; _G.pairs = pairs; _G.ipairs = ipairs
_G.tonumber = tonumber; _G.tostring = tostring
_G.string = string; _G.table = table; _G.math = math

_G.cfg = {
    get = function( k ) if k == "cmd_userinfo_permission" then return { } end return nil end,
    loadlanguage = function( ) return { } end,   -- {} -> plugin uses its in-code fallback
}
_G.util = { getlowestlevel = function( ) return 10 end }
_G.hub  = { setlistener = function( ) end, debug = function( ) end, getbot = function( ) return { } end, import = function( ) return nil end }
_G.utf  = { format = string.format }

local plugin = assert( loadfile( "scripts/cmd_userinfo.lua" ) )( )
local align  = plugin and plugin._align_labels
ok( "plugin exports the _align_labels test seam", type( align ) == "function" )

----------------------------------------------------------------------
-- helpers
----------------------------------------------------------------------
-- byte column of the first "%s" on each value line (label lines only)
local function value_columns( fmt )
    local cols = { }
    for line in ( fmt .. "\n" ):gmatch( "(.-)\n" ) do
        local before = line:match( "^(.-)%%s" )
        if before then cols[ #cols + 1 ] = #before end
    end
    return cols
end
local function all_equal( t )
    if #t == 0 then return false end
    for i = 2, #t do if t[ i ] ~= t[ 1 ] then return false end end
    return true
end
local function count_sub( s, sub )
    local n, i = 0, 1
    while true do local j = s:find( sub, i, true ); if not j then break end; n = n + 1; i = j + 1 end
    return n
end
local function load_lang( path )
    return ( assert( loadfile( path ) )( ) ).msg_userinfo
end

----------------------------------------------------------------------
-- per-language: raw is ragged, aligned is uniform, nothing lost
----------------------------------------------------------------------
local function check_lang( name, path, sample_label )
    local raw = load_lang( path )
    ok( name .. ": lang file provides msg_userinfo", type( raw ) == "string" )

    local raw_cols = value_columns( raw )
    ok( name .. ": has multiple value lines", #raw_cols > 5, #raw_cols )
    ok( name .. ": raw value column is ragged (the bug)", not all_equal( raw_cols ), table.concat( raw_cols, "," ) )

    local aligned = align( raw )
    local al_cols = value_columns( aligned )
    ok( name .. ": aligned value column is uniform", all_equal( al_cols ), table.concat( al_cols, "," ) )
    ok( name .. ": aligned keeps every value line", #al_cols == #raw_cols, #al_cols .. " vs " .. #raw_cols )
    ok( name .. ": aligned keeps the total %s count", count_sub( aligned, "%s" ) == count_sub( raw, "%s" ) )
    ok( name .. ": banner preserved", contains( aligned, "=== USERINFO" ) )
    ok( name .. ": Level second-%s tail preserved", contains( aligned, "[ %s ]" ) )
    ok( name .. ": translated label preserved (" .. sample_label .. ")", contains( aligned, sample_label ) )
end

check_lang( "EN", "scripts/lang/cmd_userinfo.lang.en", "Received:" )
check_lang( "DE", "scripts/lang/cmd_userinfo.lang.de", "Empfangen:" )

----------------------------------------------------------------------
-- guard the OTHER half of the fix: the value args must carry no fixed
-- tab prefix anymore (alignment is align_labels' job). A source scan
-- keeps a future edit from silently re-introducing a "\t" and going
-- ragged again without a heavyweight end-to-end render stub.
----------------------------------------------------------------------
local src = assert( io.open( "scripts/cmd_userinfo.lua", "r" ) ):read( "*a" )
ok( "no tab-in-string-literal remains in the plugin", not src:find( '"\\t', 1, true ) )

----------------------------------------------------------------------
io.write( string.format( "\n%d/%d checks passed\n", checks - failures, checks ) )
if failures > 0 then io.write( "FAIL cmd_userinfo_align_test\n" ); os.exit( 1 ) end
io.write( "OK cmd_userinfo_align_test\n" )
