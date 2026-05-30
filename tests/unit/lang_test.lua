--[[

    tests/unit/lang_test.lua

    Coverage test for the bundled language tables (examples/lang/de.tbl,
    examples/lang/en.tbl). Verifies that

      (a) every key required by core (see _REQUIRED below) exists in both
          tables - missing a key would silently fall through to the hardcoded
          English literal in core/hub.lua at runtime, defeating the i18n
          migration; and
      (b) de and en have full key parity (any key in one must exist in the
          other) - the Weblate-readiness invariant called out in #301.

    #301 (i18n PR-1) adds 13 new keys (hbri x5 + zlif x2 + reg x5 + tls
    label). This test FAILS on master (those keys are absent) and PASSES on
    PR-1, which is the falsifiable-regression-test requirement from
    CLAUDE.md §1a.7.

    Run: lua tests/unit/lang_test.lua   (any Lua 5.4)
    Exit code 0 = all pass, 1 = a failure (CI-friendly).

]]--

local function load_tbl( path )
    local chunk, err = loadfile( path )
    if not chunk then
        io.stderr:write( "FATAL: cannot load " .. path .. ": " .. tostring( err ) .. "\n" )
        os.exit( 1 )
    end
    local ok, t = pcall( chunk )
    if not ok or type( t ) ~= "table" then
        io.stderr:write( "FATAL: " .. path .. " did not return a table: " .. tostring( t ) .. "\n" )
        os.exit( 1 )
    end
    return t
end

local de = load_tbl( "examples/lang/de.tbl" )
local en = load_tbl( "examples/lang/en.tbl" )

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

-- (a) Every required key present in BOTH tables, non-empty string.
for _, key in ipairs( _REQUIRED ) do
    check( "de." .. key .. " present",
           type( de[ key ] ) == "string" and de[ key ] ~= "" )
    check( "en." .. key .. " present",
           type( en[ key ] ) == "string" and en[ key ] ~= "" )
end

-- (b) Full key parity: every key in one must exist in the other. Weblate
-- and any future translation tooling depend on this.
for key in pairs( de ) do
    check( "parity: en has key " .. key, en[ key ] ~= nil )
end
for key in pairs( en ) do
    check( "parity: de has key " .. key, de[ key ] ~= nil )
end

-- (c) login_tls_label MUST contain a single %s - hub.lua formats the TLS
-- mode through it. A translator dropping the placeholder would silently
-- break the login banner. (Other format-bearing keys are validated by
-- the existing en.hub_login_message convention.)
local function count_pct_s( s )
    local n = 0
    for _ in s:gmatch( "%%s" ) do n = n + 1 end
    return n
end
check( "de.hub_login_tls_label has exactly one %s",
       count_pct_s( de.hub_login_tls_label or "" ) == 1 )
check( "en.hub_login_tls_label has exactly one %s",
       count_pct_s( en.hub_login_tls_label or "" ) == 1 )

io.write( string.format( "\n%d/%d checks passed\n", checks - failures, checks ) )
if failures > 0 then
    io.write( "FAIL " .. failures .. " check(s) failed\n" )
    os.exit( 1 )
end
io.write( "OK lang_test\n" )
