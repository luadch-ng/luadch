--[[

    tests/unit/adclib_hashpas_test.lua

    Regression test for #483 - the salt-length guard in adclib's ADC
    password hashers formatted its diagnostic with %zu:

        return luaL_error(L, "hashpas: salt length %zu out of range", ...)

    luaL_error routes through lua_pushvfstring, whose conversion set is
    fixed (%s %d %f %p %c %I %%) and does NOT include %zu. So when the
    guard tripped, the interpreter raised "invalid option '%z' to
    'lua_pushfstring'" instead of the intended "salt length N out of
    range" message - masking the real cause on an auth error path.

    The fix casts saltBytes to lua_Integer and uses %I (matching the
    gen_self_signed_cert diagnostic in the same file).

    Coverage:
      - hashpas   lower-bound guard (empty salt -> saltBytes 0)
      - hashpas   upper-bound guard (oversized salt -> saltBytes > 64)
      - hasholdpas lower- and upper-bound guards
      - the rendered integer is correct ("salt length 0")   [proves %I]
      - a valid salt still hashes (guard not over-triggering)

    Pre-fix, every guard check FAILS: the raised message is the
    "invalid conversion '%z'" format error, not "salt length ...".

    Requires the built adclib shared object (and its libssl / libcrypto
    deps loadable), so it must run from inside the install tree:

      cd build/install/luadch
      lua5.4 ../../../tests/unit/adclib_hashpas_test.lua

    CI runs this after `cmake --install build` on the Linux leg only
    (the bundled adclib.dll segfaults under msys2 lua via ABI clash,
    per the adclib_unescape test).

    Exit 0 = all pass, 1 = a failure.

]]--

-- CWD-relative cpath - the install tree has lib/adclib/adclib.<so|dll>.
local filetype = ( os.getenv "COMSPEC" and os.getenv "WINDIR" and ".dll" ) or ".so"
package.cpath = "lib/?/?" .. filetype .. ";lib/?" .. filetype .. ";" .. package.cpath
local adclib = require("adclib")

local failures, checks = 0, 0

-- Assert the call raises, and the raised message is the INTENDED
-- salt-length diagnostic (not the "%z" format error from the bug).
local function guard_ok( label, fn, ... )
    checks = checks + 1
    local ok, err = pcall( fn, ... )
    err = tostring( err )
    if ok then
        failures = failures + 1
        io.write( string.format( "FAIL %-46s expected error, got success\n", label ) )
    elseif err:find( "salt length", 1, true ) and err:find( "out of range", 1, true ) then
        io.write( string.format( "ok   %-46s (%s)\n", label, err ) )
    else
        failures = failures + 1
        io.write( string.format( "FAIL %-46s err=%q\n", label, err ) )
    end
end

local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-46s got=%q want=%q\n", label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

-- ============================================================
-- hashpas: salt-length guard, both bounds.
-- ""          -> salt_len 0   -> saltBytes 0        (lower bound)
-- 104 chars   -> salt_len 104 -> saltBytes 65 > 64  (upper bound)
-- ============================================================
guard_ok( "hashpas lower-bound (empty salt)",      adclib.hashpas, "password", "" )
guard_ok( "hashpas upper-bound (oversized salt)",  adclib.hashpas, "password", string.rep( "A", 104 ) )

-- ============================================================
-- hasholdpas: same guard (3-arg variant; cid is 3rd arg).
-- ============================================================
guard_ok( "hasholdpas lower-bound (empty salt)",     adclib.hasholdpas, "password", "", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" )
guard_ok( "hasholdpas upper-bound (oversized salt)", adclib.hasholdpas, "password", string.rep( "A", 104 ), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" )

-- ============================================================
-- The rendered integer must be correct - proves %I actually formats
-- the value (a bare "salt length  out of range" would pass the guard
-- check above but not this one).
-- ============================================================
do
    checks = checks + 1
    local ok, err = pcall( adclib.hashpas, "password", "" )
    err = tostring( err )
    if not ok and err:find( "salt length 0 out of range", 1, true ) then
        io.write( "ok   hashpas message renders 'salt length 0'\n" )
    else
        failures = failures + 1
        io.write( string.format( "FAIL %-46s err=%q\n", "hashpas message renders 'salt length 0'", err ) )
    end
end

-- ============================================================
-- A valid salt (16 base32 chars -> saltBytes 10, in range) still
-- hashes to a non-empty base32 result. Confirms the guard is not
-- over-triggering and the happy path is intact.
-- ============================================================
do
    local h = adclib.hashpas( "password", "MFRGGZDFMZTWQ2LK" )
    eq( "valid salt hashes to string", type( h ), "string" )
    checks = checks + 1
    if type( h ) == "string" and #h > 0 then
        io.write( "ok   valid salt hash is non-empty\n" )
    else
        failures = failures + 1
        io.write( string.format( "FAIL valid salt hash is non-empty len=%s\n", tostring( h and #h ) ) )
    end
end

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
