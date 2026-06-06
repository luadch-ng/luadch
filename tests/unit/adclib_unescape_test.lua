--[[

    tests/unit/adclib_unescape_test.lua

    Regression test for #315 - the C++ unescape() function in
    adclib/adclib.cpp silently dropped unrecognized escape sequences
    (both the backslash AND the following byte were consumed without
    output). The fix preserves unknown sequences as literal '\' +
    byte, matching the no-data-loss interpretation of ADC §2.4.

    Coverage:
      - documented escapes still decode (\s \n \\)
      - unknown escapes preserved literal (\q \x \z \? \1)
      - trailing backslash preserved (was silently dropped pre-fix)
      - impersonation vector defeated (\X visible in display)
      - chat-text not mangled (was silent filter-bypass pre-fix)
      - mix of valid + invalid escapes
      - escape() / unescape() roundtrip safety

    Requires the built adclib shared object (and its libssl /
    libcrypto deps to be loadable). Must therefore be run from
    inside the install tree so the dynamic linker can resolve them:

      cd build/install/luadch
      lua5.4 ../../../tests/unit/adclib_unescape_test.lua

    CI runs this after `cmake --install build` (added in #315).
    Exit 0 = all pass, 1 = a failure.

]]--

-- CWD-relative cpath - the install tree has lib/adclib/adclib.<so|dll>.
local filetype = ( os.getenv "COMSPEC" and os.getenv "WINDIR" and ".dll" ) or ".so"
package.cpath = "lib/?/?" .. filetype .. ";lib/?" .. filetype .. ";" .. package.cpath
local adclib = require("adclib")
local unescape = adclib.unescape
local escape   = adclib.escape

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-65s got=%q want=%q\n",
            label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

-- ============================================================
-- BASELINE: documented escapes (must always work)
-- ============================================================
eq( "no-escape identity",        unescape( "hello" ),    "hello" )
eq( "empty string",              unescape( "" ),         "" )
eq( "single \\s -> space",       unescape( "a\\sb" ),    "a b" )
eq( "single \\n -> newline",     unescape( "a\\nb" ),    "a\nb" )
eq( "single \\\\ -> backslash",  unescape( "a\\\\b" ),   "a\\b" )
eq( "multiple valid escapes",    unescape( "x\\sy\\nz" ),"x y\nz" )

-- ============================================================
-- BUG #315 part 1: unknown escape mid-string is silently dropped.
-- Pre-fix:  unescape("admin\\q") -> "admin"  (both \ and q lost)
-- Post-fix: unescape("admin\\q") -> "admin\\q" (literal preservation)
-- ============================================================
eq( "unknown escape \\q (mid)",  unescape( "admin\\q" ),    "admin\\q" )
eq( "unknown escape \\x (mid)",  unescape( "test\\xstr" ),  "test\\xstr" )
eq( "unknown escape \\z (mid)",  unescape( "a\\zb" ),       "a\\zb" )
eq( "unknown escape \\? (mid)",  unescape( "a\\?b" ),       "a\\?b" )
eq( "unknown escape \\1 (mid)",  unescape( "a\\1b" ),       "a\\1b" )

-- ============================================================
-- BUG #315 part 2: trailing backslash silently dropped.
-- Pre-fix:  unescape("abc\\") -> "abc" (trailing \ gone)
-- Post-fix: unescape("abc\\") -> "abc\\" (literal preserved)
-- ============================================================
eq( "trailing \\ alone",         unescape( "abc\\" ),       "abc\\" )
eq( "trailing \\ on empty",      unescape( "\\" ),          "\\" )

-- ============================================================
-- IMPERSONATION: the canonical attack vector from the issue.
-- An attacker registers nick "HubSecurity\q" hoping it renders as
-- "HubSecurity". Post-fix it renders as "HubSecurity\q" so the
-- forgery is visible.
-- ============================================================
eq( "impersonation defeated",
    unescape( "HubSecurity\\q" ),
    "HubSecurity\\q" )

-- ============================================================
-- DATA CORRUPTION: chat message text containing unknown escapes
-- gets silently mangled, breaking plugins doing keyword filters.
-- Pre-fix:  unescape("bad\\qword") -> "badword" (filter-bypass)
-- ============================================================
eq( "chat-text not mangled",
    unescape( "bad\\qword" ),
    "bad\\qword" )

-- ============================================================
-- MIX: valid + invalid escapes in one string.
-- Post-fix: valid escapes still decode, invalid preserved.
-- ============================================================
eq( "mix \\s + \\q + \\n",
    unescape( "\\s\\q\\n" ),
    " \\q\n" )

-- ============================================================
-- ROUNDTRIP: escape(x) followed by unescape() recovers x for any
-- ASCII text. Verifies that the fix does not break the inverse
-- relationship that callers rely on.
-- ============================================================
local roundtrip_cases = {
    "hello",
    "hello world",
    "line1\nline2",
    "back\\slash",      -- Lua "back\slash" = back + \ + slash (7 chars)
    "tab\tchar",
    "mixed back\\slash and\nnewline",
    "",
}
for _, input in ipairs( roundtrip_cases ) do
    local round = unescape( escape( input ) )
    eq( "roundtrip: " .. string.format( "%q", input ),
        round, input )
end

-- ============================================================
-- ESCAPE function is unchanged: it never produces unknown escapes
-- itself, so the fix doesn't affect outbound encoding.
-- ============================================================
eq( "escape: space",       escape( " " ),        "\\s" )
eq( "escape: newline",     escape( "\n" ),       "\\n" )
eq( "escape: backslash",   escape( "\\" ),       "\\\\" )
eq( "escape: identity",    escape( "abc" ),      "abc" )

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
