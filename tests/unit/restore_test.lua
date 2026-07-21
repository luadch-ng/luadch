--[[

    tests/unit/restore_test.lua

    Unit tests for core/restore.lua's pure decision logic (the offline-restore
    entry, #480 PR-B), loaded through its RESTORE_TEST seam so no adclib C
    module, no real filesystem and no `--restore` run is needed:
      - _safe_rel(): the SECURITY guard - reject absolute paths / ".." / drive
        / UNC, normalise separators, strip "." (path-traversal defence the
        backup_archive.unpack note demands before any write)
      - _resolve_masterkey_dest(): override > manifest path > in-tree default
      - _build_plan(): __masterkey__ sentinel + secret-mode classification +
        unsafe entries routed to rejects, never to the write plan
      - _verify_sidecar(): sha256 sidecar match / mismatch / missing

    A fake _G.adclib lets backup_archive load without the built C module
    (its sha256 checksum path is pure Lua, so _verify_sidecar is exercised
    for real).

    Run: lua5.4 tests/unit/restore_test.lua   (exit 0 = pass, 1 = fail)

]]--

-- backup_archive loads via restore.lua's loadscript; a minimal fake adclib
-- skips the require() and the C-vs-Lua pbkdf2 cross-check at load.
_G.adclib = { }
_G.RESTORE_TEST = true

local R = assert( loadfile( "core/restore.lua" ) )( )
assert( type( R ) == "table", "restore.lua did not return its test seam" )

----------------------------------------------------------------------
-- harness
----------------------------------------------------------------------

local passes, fails = 0, 0
local function ok( label, cond )
    if cond then passes = passes + 1
    else fails = fails + 1; io.stderr:write( "FAIL: " .. label .. "\n" ) end
end
local function eq( label, got, want )
    if got == want then passes = passes + 1
    else
        fails = fails + 1
        io.stderr:write( string.format( "FAIL: %s\n  got:  %s\n  want: %s\n",
            label, tostring( got ), tostring( want ) ) )
    end
end
local function find_dest( plan, dest )
    for _, p in ipairs( plan ) do if p.dest == dest then return p end end
end

----------------------------------------------------------------------
-- _safe_rel: accept in-tree relative paths
----------------------------------------------------------------------

eq( "plain relative kept",        R._safe_rel( "cfg/cfg.tbl" ),          "cfg/cfg.tbl" )
eq( "nested relative kept",       R._safe_rel( "scripts/data/x.tbl" ),   "scripts/data/x.tbl" )
eq( "leading ./ stripped",        R._safe_rel( "./cfg/x.tbl" ),          "cfg/x.tbl" )
eq( "backslash normalised",       R._safe_rel( "scripts\\data\\x.tbl" ), "scripts/data/x.tbl" )
eq( "single file kept",           R._safe_rel( "cfg.tbl" ),              "cfg.tbl" )

----------------------------------------------------------------------
-- _safe_rel: reject anything that could escape the install root
----------------------------------------------------------------------

ok( "reject empty",               R._safe_rel( "" ) == nil )
ok( "reject nil",                 R._safe_rel( nil ) == nil )
ok( "reject POSIX absolute",      R._safe_rel( "/etc/passwd" ) == nil )
ok( "reject drive absolute",      R._safe_rel( "C:\\Windows\\x" ) == nil )
ok( "reject UNC backslash",       R._safe_rel( "\\\\host\\share\\x" ) == nil )
ok( "reject leading ..",          R._safe_rel( "../../etc/cron.d/x" ) == nil )
ok( "reject mid-path ..",         R._safe_rel( "cfg/../../etc/x" ) == nil )
ok( "reject bare ..",             R._safe_rel( ".." ) == nil )
ok( "reject backslash ..",        R._safe_rel( "cfg\\..\\..\\x" ) == nil )
ok( "reject dot-only",            R._safe_rel( "." ) == nil )
-- Windows normalises trailing dots/spaces, so a dot/space-only segment could
-- collapse onto "." / ".." after the check - refuse the whole class.
ok( "reject dot-dot-space",       R._safe_rel( "cfg/.. /x" ) == nil )
ok( "reject triple-dot",          R._safe_rel( "a/.../b" ) == nil )
ok( "reject space-only segment",  R._safe_rel( "a/ /b" ) == nil )
-- but a leading-dot filename is legitimate and kept
eq( "leading-dot filename kept",  R._safe_rel( "cfg/..foo" ), "cfg/..foo" )

----------------------------------------------------------------------
-- _resolve_masterkey_dest: override > manifest > default
----------------------------------------------------------------------

eq( "mk override wins", R._resolve_masterkey_dest( { master_key_path = "/a/b" }, "/override/mk" ), "/override/mk" )
eq( "mk from manifest", R._resolve_masterkey_dest( { master_key_path = "/etc/luadch/master.key" }, nil ),
    "/etc/luadch/master.key" )
eq( "mk default",       R._resolve_masterkey_dest( { }, nil ),      "cfg/master.key" )
eq( "mk empty override ignored", R._resolve_masterkey_dest( { master_key_path = "/m" }, "" ), "/m" )

----------------------------------------------------------------------
-- _build_plan: sentinel, secret classification, reject routing
----------------------------------------------------------------------

do
    local files = {
        { name = "cfg/cfg.tbl",           body = "c",  kind = "tree" },
        { name = "cfg/user.tbl",          body = "u",  kind = "tree" },
        { name = "certs/serverkey.pem",   body = "k",  kind = "tree" },
        { name = "certs/servercert.pem",  body = "cc", kind = "tree" },
        { name = "scripts/data/a.tbl",    body = "a",  kind = "tree" },
        { name = "__masterkey__",         body = "MK", kind = "masterkey" },
        { name = "../../etc/cron.d/evil", body = "x",  kind = "tree" },
    }
    local plan, rejects = R._build_plan( files, { master_key_path = "cfg/master.key" }, nil )

    ok( "cfg.tbl in plan",          find_dest( plan, "cfg/cfg.tbl" ) ~= nil )
    ok( "user.tbl in plan",         find_dest( plan, "cfg/user.tbl" ) ~= nil )
    ok( "serverkey in plan",        find_dest( plan, "certs/serverkey.pem" ) ~= nil )
    ok( "servercert in plan",       find_dest( plan, "certs/servercert.pem" ) ~= nil )

    local mk = find_dest( plan, "cfg/master.key" )
    ok( "masterkey sentinel -> in-tree dest", mk ~= nil )
    eq( "masterkey body carried",     mk and mk.body, "MK" )
    eq( "masterkey flagged",          mk and mk.masterkey, true )
    ok( "non-mk entry unflagged",     find_dest( plan, "cfg/cfg.tbl" ).masterkey == nil )

    ok( "unsafe entry NOT in plan",   find_dest( plan, "../../etc/cron.d/evil" ) == nil )
    eq( "one reject recorded",        #rejects, 1 )
    eq( "reject names the entry",     rejects[ 1 ] and rejects[ 1 ].name, "../../etc/cron.d/evil" )
end

-- master.key override redirects the sentinel dest (operator opted in, absolute OK)
do
    local plan = R._build_plan( { { name = "__masterkey__", body = "MK", kind = "masterkey" } },
        { master_key_path = "cfg/master.key" }, "/secure/mk" )
    ok( "override redirects sentinel", find_dest( plan, "/secure/mk" ) ~= nil )
end

-- F1: an out-of-tree manifest master_key_path is NOT honoured without an
-- explicit --master-key-path (a foreign archive must not steer an absolute write)
do
    local plan, rejects = R._build_plan(
        { { name = "__masterkey__", body = "PWN", kind = "masterkey" } },
        { master_key_path = "/etc/cron.d/evil" }, nil )
    eq( "out-of-tree mk -> nothing in plan", #plan, 0 )
    eq( "out-of-tree mk -> rejected",        #rejects, 1 )
    ok( "reject mentions --master-key-path",
        rejects[ 1 ] and rejects[ 1 ].reason:match( "master%-key%-path" ) ~= nil )
end

-- F1: the SAME out-of-tree path IS honoured when the operator passes it explicitly
do
    local plan = R._build_plan(
        { { name = "__masterkey__", body = "MK", kind = "masterkey" } },
        { master_key_path = "/etc/cron.d/evil" }, "/etc/luadch/master.key" )
    ok( "explicit override honours absolute", find_dest( plan, "/etc/luadch/master.key" ) ~= nil )
end

----------------------------------------------------------------------
-- _verify_sidecar: real sha256 via the loaded archive module
----------------------------------------------------------------------

do
    local blob = "the sealed bytes"
    local hex  = R.archive.checksum( blob )
    eq( "sidecar match -> ok",       R._verify_sidecar( blob, hex .. "  luadch-backup.ldbk\n" ), "ok" )
    eq( "sidecar wrong -> mismatch", R._verify_sidecar( blob, string.rep( "0", 64 ) .. "  x\n" ), "mismatch" )
    eq( "no hex token -> mismatch",  R._verify_sidecar( blob, "not-a-hash\n" ), "mismatch" )
    eq( "nil sidecar -> missing",    R._verify_sidecar( blob, nil ), "missing" )
    eq( "empty sidecar -> missing",  R._verify_sidecar( blob, "" ), "missing" )
    -- case-insensitive hex compare
    eq( "uppercase hex still ok",    R._verify_sidecar( blob, string.upper( hex ) .. "  x\n" ), "ok" )
end

----------------------------------------------------------------------
-- output
----------------------------------------------------------------------

if fails > 0 then
    io.stderr:write( string.format( "\nFAIL: %d/%d checks failed\n", fails, passes + fails ) )
    os.exit( 1 )
end
print( string.format( "OK: %d checks passed", passes ) )
