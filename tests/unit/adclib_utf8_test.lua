--[[

    tests/unit/adclib_utf8_test.lua

    Regression test for the adclib UTF-8 handling hardening:

      1. is_valid_utf8 / sanitize_utf8 built their std::string via the
         const char* path, which stops at the first embedded NUL and
         discards the fetched length. isutf8 is the incoming-data gate,
         so a NUL-truncated validation passed a line whose post-NUL
         bytes were never checked (F-C-3 class - the hash_* functions
         already used the length-aware ctor).

      2. utf8ToWc accepted overlong encodings (e.g. C0 80 for NUL).
         Besides being invalid UTF-8, an overlong sequence advances the
         source index by more bytes than it re-encodes, which desynced
         sanitizeUtf8's target index and made a later
         `tgt.insert(i, ...)` throw std::out_of_range across a noexcept
         boundary -> std::terminate. Reachable via adclib.sanitize_utf8
         (etc_webhook), and a crash on any future caller fed net data.

    Coverage:
      - isutf8 validates the WHOLE string, not the pre-NUL prefix   [NUL bypass]
      - isutf8 rejects an overlong C0 80                             [overlong]
      - isutf8 still accepts ASCII / 2-byte / 3-byte valid UTF-8     [no over-reject]
      - sanitize_utf8 does not abort on an overlong+error frame      [the crash]
      - sanitize_utf8 passes valid input through and returns a string

    Pre-fix: the NUL and overlong checks return `true` (FAIL), and the
    sanitize_utf8 overlong+error case aborts the process (std::terminate,
    not a Lua error - pcall cannot catch it), so the run dies with a
    non-zero exit.

    Requires the built adclib shared object (and its libssl / libcrypto
    deps loadable) plus the bundled liblua, so it runs from the install
    tree with LD_LIBRARY_PATH=. :

      cd build/install/luadch
      LD_LIBRARY_PATH=. lua5.4 ../../../tests/unit/adclib_utf8_test.lua

    CI runs this after `cmake --install build` on the Linux leg only
    (the bundled adclib.dll segfaults under msys2 lua via ABI clash,
    per the adclib_unescape / adclib_hashpas tests).

    Exit 0 = all pass, 1 = a failure.

]]--

-- CWD-relative cpath - the install tree has lib/adclib/adclib.<so|dll>.
local filetype = ( os.getenv "COMSPEC" and os.getenv "WINDIR" and ".dll" ) or ".so"
package.cpath = "lib/?/?" .. filetype .. ";lib/?" .. filetype .. ";" .. package.cpath
local adclib = require("adclib")

-- Unbuffered: the pre-fix sanitize_utf8 case aborts the process
-- (std::terminate), so buffered "ok"/"FAIL" lines would be lost. With
-- no buffering a future regression still shows which checks passed
-- before the crash.
io.stdout:setvbuf( "no" )

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-52s got=%q want=%q\n", label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

-- NUL bypass: "valid" + NUL + 0xFF (an invalid lead byte). The whole
-- string must be validated; pre-fix the const-char* ctor truncates at
-- the NUL and validates only "valid" -> true.
eq( "isutf8 validates past embedded NUL", adclib.isutf8( "valid\0\255" ), false )

-- Overlong: C0 80 encodes U+0000 in two bytes (canonical is one). Invalid
-- UTF-8; pre-fix utf8ToWc accepted it -> true.
eq( "isutf8 rejects overlong C0 80", adclib.isutf8( "\192\128" ), false )

-- No over-rejection: real valid UTF-8 must still pass.
eq( "isutf8 accepts ASCII", adclib.isutf8( "hello" ), true )
eq( "isutf8 accepts 2-byte (C3 A9)", adclib.isutf8( "\195\169" ), true )
eq( "isutf8 accepts 3-byte (E2 82 AC)", adclib.isutf8( "\226\130\172" ), true )
-- Valid 4-byte UTF-8 (U+1F600) must NOT be rejected: the overlong check is
-- deliberately bounded to 2/3 bytes so it never over-rejects here.
eq( "isutf8 accepts 4-byte (F0 9F 98 80)", adclib.isutf8( "\240\159\152\128" ), true )

-- The crash: overlong (C0 80) followed by a lone continuation byte (80).
-- Pre-fix this aborts the process (std::terminate); post-fix it returns
-- a sanitized string. pcall cannot catch std::terminate, so reaching the
-- assertion at all already means no abort.
local s = adclib.sanitize_utf8( "\192\128\128" )
eq( "sanitize_utf8 survives overlong+error frame", type( s ), "string" )

-- Valid input passes through unchanged; a lone invalid byte is replaced,
-- not crashed on.
eq( "sanitize_utf8 passes valid ASCII", adclib.sanitize_utf8( "hello" ), "hello" )
eq( "sanitize_utf8 replaces lone invalid byte", type( adclib.sanitize_utf8( "\255" ) ), "string" )
-- sanitize_utf8 must process the WHOLE value, not truncate at the NUL:
-- "a" + NUL + 0xFF -> "a" + NUL + "_" (3 bytes). Pre-fix truncates to "a".
eq( "sanitize_utf8 processes past embedded NUL", #adclib.sanitize_utf8( "a\0\255" ), 3 )

-- escape / unescape must keep bytes past an embedded NUL (length-aware).
-- "a\0b" has nothing to (un)escape, so both return the 3 bytes unchanged;
-- pre-fix the const char* path truncated the value to "a" (1 byte).
eq( "escape keeps bytes past embedded NUL", #adclib.escape( "a\0b" ), 3 )
eq( "unescape keeps bytes past embedded NUL", #adclib.unescape( "a\0b" ), 3 )

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
