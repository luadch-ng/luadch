--[[

    tests/unit/lang_test.lua

    Coverage test for the bundled language tables (lang/de/hub.json,
    lang/en/hub.json - migrated from .tbl to JSON and moved into a
    per-language subdir in the #301 P3 Weblate move; the runtime loads
    them via the dual-format cfg_lang.loadlanguage). Verifies that

      (a) every key required by core (see _REQUIRED below) exists in EN,
          the source of truth; DE is checked only where present, since a
          Weblate-managed translation may legitimately be incomplete and
          the runtime falls back to the hardcoded English literal;
      (b) no ORPHAN de keys (every de key must exist in en) - a de key the
          source dropped is dead weight; the reverse is NOT required (an
          untranslated en key is expected in the Weblate era); and
      (c) placeholder parity: every translated de string carries the same
          ordered printf-conversion signature (type AND order, not just
          count) as its en source, so a reordered or dropped %s / %d
          cannot break string.format at runtime.

    #301 (i18n PR-1) adds 13 new keys (hbri x5 + zlif x2 + reg x5 + tls
    label). This test FAILS on master (those keys are absent) and PASSES on
    PR-1, which is the falsifiable-regression-test requirement from
    CLAUDE.md §1a.7.

    Run: lua tests/unit/lang_test.lua   (any Lua 5.4)
    Exit code 0 = all pass, 1 = a failure (CI-friendly).

]]--

-- Core lang files are JSON now (#301 P3). Decode with the same bundled
-- dkjson the runtime uses, so this test validates exactly what the hub
-- will parse - not a re-implementation.
local dkjson = assert( loadfile( "dkjson/dkjson.lua" ) )( )

local function load_lang( path )
    local f, ferr = io.open( path, "rb" )
    if not f then
        io.stderr:write( "FATAL: cannot open " .. path .. ": " .. tostring( ferr ) .. "\n" )
        os.exit( 1 )
    end
    local s = f:read( "*a" )
    f:close( )
    local t, _, err = dkjson.decode( s or "", 1, nil )
    if err or type( t ) ~= "table" then
        io.stderr:write( "FATAL: " .. path .. " is not a valid JSON object: " .. tostring( err ) .. "\n" )
        os.exit( 1 )
    end
    return t
end

-- Per-language subdir layout (#301 P3): lang/<lng>/hub.json.
local de = load_lang( "lang/de/hub.json" )
local en = load_lang( "lang/en/hub.json" )

-- Keys core/hub.lua reads via i18n.* (must exist in BOTH tables, else
-- the runtime silently falls back to the hardcoded English literal).
-- Keep in lockstep with core/hub.lua loadlanguage().
local _REQUIRED = {
    -- pre-#301 (existing) keys
    "hub_login_message",
    "hub_nick_or_cid_taken",
    "hub_hub_is_full",
    "hub_no_base_support",
    "hub_no_cid_nick_found",
    "hub_cid_taken",
    "hub_nick_taken",
    "hub_invalid_pid",
    "hub_invalid_ip",
    "hub_reg_only",
    "hub_invalid_pass",
    "hub_unknown",
    "hub_max_bad_password",
    "hub_hubbot_response",
    -- #301 new keys: HBRI ISTA reasons
    "hub_hbri_unknown_token",
    "hub_hbri_wrong_protocol",
    "hub_hbri_address_mismatch",
    "hub_hbri_succeed",
    "hub_hbri_timeout",
    -- #301 new keys: ZLIF reject reasons
    "hub_zlif_before_hsup",
    "hub_zlif_zof_unsupported",
    -- #301 new keys: login [TLS:] label + insertreguser failure modes
    "hub_login_tls_label",
    "hub_reg_invalid_profile",
    "hub_reg_no_cid_hash_nick",
    "hub_reg_already_inserted",
    "hub_reg_invalid_user",
    "hub_reg_no_profile",
}

local failures, checks = 0, 0
local function check( label, ok )
    checks = checks + 1
    if not ok then
        failures = failures + 1
        io.write( "FAIL " .. label .. "\n" )
    else
        io.write( "ok   " .. label .. "\n" )
    end
end

-- (a) EN is the source of truth: every required key must exist and be a
-- non-empty string in EN. DE is translator-managed (Weblate) and may be
-- INCOMPLETE - an untranslated key is simply absent, and core/hub.lua
-- falls back to its hardcoded English literal - so DE is checked only
-- where it actually carries the key.
for _, key in ipairs( _REQUIRED ) do
    check( "en." .. key .. " present (source)",
           type( en[ key ] ) == "string" and en[ key ] ~= "" )
    if de[ key ] ~= nil then
        check( "de." .. key .. " (if translated) is a non-empty string",
               type( de[ key ] ) == "string" and de[ key ] ~= "" )
    end
end

-- (b) No orphan translations: every DE key must exist in EN. A DE key the
-- source no longer defines is dead weight a translator keeps maintaining.
-- The reverse (an EN key missing in DE) is NOT required post-Weblate -
-- that is just an untranslated string, covered by the English fallback.
for key in pairs( de ) do
    check( "no orphan: en has de key " .. key, en[ key ] ~= nil )
end

-- (c) + (d) Placeholder safety. `fmt_sig` returns the ORDERED sequence of
-- printf conversion-type letters (`%s`->"s", `%-20d`->"d") after removing
-- the literal `%%`. Lua string.format fills arguments positionally, so a
-- translation must keep not just the COUNT but the exact TYPE and ORDER: a
-- German word-order swap of `"%s ... %d"` into `"%d ... %s"` has the same
-- count yet crashes ("number expected, got string"). EN's login banner
-- label carries a single %s; every DE string that is actually translated
-- must share EN's signature (Weblate flags this too; CI is the backstop).
local function fmt_sig( s )
    s = ( s:gsub( "%%%%", "" ) )
    local out = { }
    for spec in s:gmatch( "%%[%-+ #0-9.]*([%a])" ) do
        out[ #out + 1 ] = spec
    end
    return table.concat( out )
end
check( "en.hub_login_tls_label signature is a single %s",
       fmt_sig( en.hub_login_tls_label or "" ) == "s" )
for key, v in pairs( en ) do
    if type( v ) == "string" and type( de[ key ] ) == "string" and de[ key ] ~= "" then
        check( "de." .. key .. " placeholder signature matches en",
               fmt_sig( de[ key ] ) == fmt_sig( v ) )
    end
end

-- (e) Extra translator-managed languages (the Weblate funnel gate).
-- Unset in the normal smoke run, so ONLY de is checked above (the current
-- behaviour, and Windows-portable - no directory globbing here). The Weblate
-- funnel workflow enumerates the languages it is importing on its Linux runner
-- and passes them via LANG_TEST_EXTRA_CODES (comma/space separated) so each
-- gets exactly the orphan + placeholder-signature checks de gets: an imported
-- translation with an orphan key or a reordered/dropped %s never reaches dev.
-- Empty (untranslated) values are skipped, mirroring the runtime's
-- checklanguage, so a partially-translated language passes on what it HAS.
local extra = os.getenv( "LANG_TEST_EXTRA_CODES" )
if extra and extra ~= "" then
    for lng in extra:gmatch( "[^,%s]+" ) do
        if lng ~= "en" and lng ~= "de" then
            local path = "lang/" .. lng .. "/hub.json"
            local f = io.open( path, "rb" )
            if f then
                f:close( )
                local t = load_lang( path )
                for key, v in pairs( t ) do
                    check( lng .. ": no orphan, en has key " .. key, en[ key ] ~= nil )
                    if type( v ) == "string" and v ~= "" and type( en[ key ] ) == "string" then
                        check( lng .. "." .. key .. " placeholder signature matches en",
                               fmt_sig( v ) == fmt_sig( en[ key ] ) )
                    end
                end
            end
        end
    end
end

io.write( string.format( "\n%d/%d checks passed\n", checks - failures, checks ) )
if failures > 0 then
    io.write( "FAIL " .. failures .. " check(s) failed\n" )
    os.exit( 1 )
end
io.write( "OK lang_test\n" )
