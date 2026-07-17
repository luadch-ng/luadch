--[[

    tests/unit/plugin_lang_test.lua

    Repo-wide lang-key consistency check for the bundled plugins.

    Every plugin binds its language table as `local lang, err =
    cfg.loadlanguage( scriptlang, scriptname )` and then reads keys with
    the `local msg_x = lang.some_key or "<english fallback>"` idiom. If the
    source reads a key the lang file does not define, the lookup returns
    nil, the `or` fallback fires, and the plugin silently serves the
    hardcoded English literal forever - the translation is dead and no
    error is ever raised. cfg.language makes no difference. That failure is
    invisible at runtime, which is exactly why it needs a test.

    This has now bitten twice:
      - #301 PR-2: scripts/usr_share.lua read `lang.msg_minmax` while the
        lang files defined `msg_sharelimits`.
      - scripts/etc_cmdlog.lua read `lang.failmsg1` / `lang.failmsg2` while
        the lang files defined `msg_denied` / `msg_nofile`.
    The first was fixed with a one-plugin test (usr_share_lang_test.lua),
    and the bug promptly reappeared in a plugin that test did not look at.
    So this supersedes it with a sweep over EVERY bundled plugin - per
    CLAUDE.md §1a.1, fix the pattern everywhere, not just where it was
    noticed. usr_share is one of the plugins scanned here, so coverage is a
    strict superset of the test this replaces.

    The same rot runs the other way. A key the lang files define but no
    plugin ever reads is worse than useless: translators keep maintaining
    it, reviewers keep reading it as live surface, and it fires never. That
    direction is invisible to the check above - which is exactly how 22 of
    them accumulated undetected until #447 PR 6 swept them out.

    Method: enumerate the shipped plugins from `examples/cfg/cfg.tbl`'s
    `scripts` whitelist, and for each one that ships lang files, load both
    the .en and .de table, scan the plugin source for every `lang.X`
    reference, then assert BOTH directions:
      - every X referenced by the source exists in .en and .de, and
      - every key defined in .en / .de is referenced by the source.

    Four traps this deliberately avoids:
      - Do NOT assert the value is a string. Plenty of legitimate keys are
        TABLES (`ucmd_menu*` right-click menu structures, `month_name`,
        cmd_ascii's `pics`). An earlier draft asserted `type(v)=="string"`
        and produced 149 false positives out of 151 hits. Existence is the
        invariant; the type is the plugin's business.
      - Comments are stripped first, so a `lang.X` mentioned in a header
        changelog cannot trip a false positive.
      - No shell/`io.popen` globbing. A native Windows Lua routes popen
        through cmd.exe, where `ls` does not exist - the enumeration would
        silently yield nothing and the whole test would pass vacuously.
        Reading the cfg whitelist is pure `loadfile` and works everywhere,
        and it ties this test to the plugin set we actually ship.
      - The scan pattern tolerates whitespace after the dot. Lua accepts
        `lang. msg_notfound` as a field access, and usr_uptime.lua:143 is
        written exactly that way. A strict `lang%.([%w_]+)` skips it, so the
        forward check silently under-scanned that key, and the reverse check
        would have reported a live key as orphaned. Both directions need the
        `%s*`.

    Provably fails pre-fix (CLAUDE.md §1a.7): on the unpatched tree the
    forward direction reports etc_cmdlog lang.failmsg1 / lang.failmsg2 and
    cmd_delreg lang.msg_reason as missing; the reverse direction reports
    cmd_reg ucmd_passwort and etc_userlogininfo msg_ccpm_1/2/3 as unread.

    Run: lua tests/unit/plugin_lang_test.lua   (any Lua 5.4, from repo root)
    Exit code 0 = pass, 1 = failure (CI-friendly).

]]--

local CFG_TBL    = "examples/cfg/cfg.tbl"
local LANG_DIR   = "scripts/lang/"
local PLUGIN_DIR = "scripts/"

-- Vacuity guard. If the cfg whitelist ever fails to load or its shape
-- changes, this test would scan nothing and every assertion below would
-- pass trivially - a green test that checks nothing is worse than no test.
-- The tree ships ~78 plugins, ~68 of them with lang files. Fail loudly if
-- we ever see implausibly few. Lower only alongside a real drop.
local MIN_PLUGINS   = 60
local MIN_WITH_LANG = 50
-- Reverse-direction floor. An all-empty `return {}` lang file is a valid
-- table that would make the reverse loop iterate nothing and pass silently,
-- invisible to the two counts above. The tree carries ~2000 defined keys
-- (en + de), so a plausible floor catches a systemic load failure. Lower
-- only alongside a real drop.
local MIN_REVERSE_KEYS = 1000

local function read_text( path )
    local f = io.open( path, "rb" )
    if not f then return nil end
    local s = f:read( "*a" )
    f:close( )
    return s
end

local function load_table( path )
    local chunk = loadfile( path )
    if not chunk then return nil, "cannot load" end
    local ok, t = pcall( chunk )
    if not ok or type( t ) ~= "table" then return nil, "did not return a table" end
    return t
end

-- Strip block comments `--[[ ... ]]` and line comments so a `lang.X` in a
-- header changelog or an explanatory note cannot register as a lookup.
local function strip_comments( s )
    s = s:gsub( "%-%-%[%[.-%]%]", "" )
    s = s:gsub( "%-%-[^\n]*", "" )
    return s
end

local failures, checks = 0, 0
local function check( label, ok )
    checks = checks + 1
    if not ok then
        failures = failures + 1
        io.write( "FAIL " .. label .. "\n" )
    end
end

-- cfg.scripts entries come in two shapes: a bare "name.lua" string, and a
-- `{ "name.lua", enabled = true }` table (the per-plugin toggle form).
local function entry_name( v )
    local file = ( type( v ) == "table" ) and v[ 1 ] or v
    if type( file ) ~= "string" then return nil end
    return file:match( "^(.+)%.lua$" )
end

local cfg, cfg_err = load_table( CFG_TBL )
check( CFG_TBL .. " loads (" .. tostring( cfg_err ) .. ")", cfg ~= nil )

local names = { }
if cfg and type( cfg.scripts ) == "table" then
    for _, v in ipairs( cfg.scripts ) do
        local n = entry_name( v )
        if n then names[ #names + 1 ] = n end
    end
end
table.sort( names )

check( string.format( "cfg.scripts lists at least %d plugins (found %d)",
                      MIN_PLUGINS, #names ),
       #names >= MIN_PLUGINS )

local scanned, total_refs, reverse_checks = 0, 0, 0

for _, name in ipairs( names ) do
    local en_path = LANG_DIR .. name .. ".lang.en"
    -- Not every plugin ships lang files; those are simply out of scope
    -- here (nothing to be inconsistent with).
    if read_text( en_path ) then
        local source = read_text( PLUGIN_DIR .. name .. ".lua" )
        local en, en_err = load_table( en_path )
        local de, de_err = load_table( LANG_DIR .. name .. ".lang.de" )

        check( name .. ": plugin source exists", source ~= nil )
        check( name .. ": .lang.en loads (" .. tostring( en_err ) .. ")", en ~= nil )
        check( name .. ": .lang.de exists and loads (" .. tostring( de_err ) .. ")", de ~= nil )

        if source and en and de then
            scanned = scanned + 1
            local seen = { }
            for key in strip_comments( source ):gmatch( "lang%.%s*([%w_]+)" ) do
                if not seen[ key ] then
                    seen[ key ] = true
                    total_refs = total_refs + 1
                    check( name .. ": lang." .. key .. " defined in .lang.en", en[ key ] ~= nil )
                    check( name .. ": lang." .. key .. " defined in .lang.de", de[ key ] ~= nil )
                end
            end
            -- Reverse direction. A key no plugin reads is invisible rot:
            -- translators keep maintaining it, reviewers keep reading it as
            -- live, and nothing ever fires. The forward check above cannot
            -- see it, which is how 22 of them accumulated by #447 PR 6.
            --
            -- This assumes every read is a literal `lang.<key>` - that is
            -- what `seen` collected. The tree has no `lang[ "key" ]` and no
            -- `local L = lang` alias today; the day one appears, its keys
            -- will look orphaned here and this loop must learn that access
            -- form, or it will report a live key as dead.
            for key in pairs( en ) do
                reverse_checks = reverse_checks + 1
                check( name .. ": .lang.en key '" .. key .. "' is read by the plugin", seen[ key ] == true )
            end
            for key in pairs( de ) do
                reverse_checks = reverse_checks + 1
                check( name .. ": .lang.de key '" .. key .. "' is read by the plugin", seen[ key ] == true )
            end
        end
    end
end

check( string.format( "scanned at least %d plugins with lang files (scanned %d)",
                      MIN_WITH_LANG, scanned ),
       scanned >= MIN_WITH_LANG )

check( string.format( "reverse-checked at least %d lang keys (checked %d)",
                      MIN_REVERSE_KEYS, reverse_checks ),
       reverse_checks >= MIN_REVERSE_KEYS )

io.write( string.format( "\n%d/%d checks passed (%d plugins scanned, %d distinct lang.X references)\n",
                         checks - failures, checks, scanned, total_refs ) )
if failures > 0 then
    io.write( "FAIL " .. failures .. " check(s) failed\n" )
    os.exit( 1 )
end
io.write( "OK plugin_lang_test\n" )
