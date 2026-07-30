--[[

    tests/unit/cfg_secret_perms_test.lua

    Pure-Lua unit test for core/cfg_secret.lua's master.key permission
    classifier `_mode_is_secure`. A secret file is secure iff group and
    other have no access (the last two octal digits of `stat -c '%a'`
    are "00"); owner bits are unrestricted.

    Regression target: the old check tested `mode ~= "600"` literally, so
    a correctly-locked-down 0400 (owner read-only, MORE hardened than
    0600) was wrongly classified insecure and refused hub boot with the
    advice to LOOSEN it to 0600. See the RED case below.

    Loading cfg_secret.lua only needs its load-time `use` deps satisfied;
    init() (which does file I/O) is never called here.

    Run: lua5.4 tests/unit/cfg_secret_perms_test.lua
    Exit 0 = all pass, 1 = a failure.

]]--

----------------------------------------------------------------------
-- `use` shim: satisfy cfg_secret.lua's load-time dependencies only.
----------------------------------------------------------------------

local _real = {
    type = type, error = error, pcall = pcall,
    string = string, tostring = tostring,
    io = io, os = os,
    adclib = {
        random_bytes = function( n ) return string.rep( "R", n ) end,
        aes_gcm_seal = function( _k, _n, pt ) return pt end,
        aes_gcm_open = function( _k, _n, ct ) return ct end,
    },
    const = { CONFIG_PATH = "cfg/" },
}
_G.use = function( name )
    local v = _real[ name ]
    if v == nil then error( "cfg_secret_perms_test shim missing dep: use \"" .. tostring( name ) .. "\"" ) end
    return v
end

local S = assert( loadfile( "core/cfg_secret.lua" ) )( )

----------------------------------------------------------------------
-- Tiny harness
----------------------------------------------------------------------

local passes, fails = 0, 0
local function eq( label, got, want )
    if got == want then passes = passes + 1
    else
        fails = fails + 1
        io.stderr:write( string.format( "FAIL: %s\n  got:  %s\n  want: %s\n",
            label, tostring( got ), tostring( want ) ) )
    end
end

----------------------------------------------------------------------
-- RED: the pre-fix predicate (exact-"600") misclassified owner-only
-- modes. Self-contained proof of the regression this fix removes.
----------------------------------------------------------------------

local function old_secure( mode ) return mode == "600" end
eq( "RED: old exact-600 logic rejected owner-only 400", old_secure( "400" ), false )
eq( "RED: old exact-600 logic rejected owner-rwx 700",  old_secure( "700" ), false )

----------------------------------------------------------------------
-- GREEN: secure = group/other have no access (last two digits "00").
----------------------------------------------------------------------

-- owner-only modes: all secure
eq( "600 owner rw",        S._mode_is_secure( "600" ), true )
eq( "400 owner read-only", S._mode_is_secure( "400" ), true )
eq( "700 owner rwx",       S._mode_is_secure( "700" ), true )
eq( "500 owner rx",        S._mode_is_secure( "500" ), true )
eq( "200 owner write",     S._mode_is_secure( "200" ), true )
eq( "2600 setgid+ownerrw", S._mode_is_secure( "2600" ), true )

-- group and/or other has access: all insecure
eq( "640 group read",  S._mode_is_secure( "640" ), false )
eq( "660 group rw",    S._mode_is_secure( "660" ), false )
eq( "604 other read",  S._mode_is_secure( "604" ), false )
eq( "644 group+other", S._mode_is_secure( "644" ), false )
eq( "666 world rw",    S._mode_is_secure( "666" ), false )
eq( "700+2 setgid grp",S._mode_is_secure( "2640" ), false )

-- degenerate / unrecognisable forms never block boot (treated secure)
eq( "nil mode",   S._mode_is_secure( nil ),   true )
eq( "empty mode", S._mode_is_secure( "" ),    true )
eq( "1-digit",    S._mode_is_secure( "0" ),   true )
eq( "2-digit",    S._mode_is_secure( "60" ),  true )
eq( "non-string", S._mode_is_secure( 600 ),   true )

----------------------------------------------------------------------

io.write( string.format( "cfg_secret_perms_test: %d passed, %d failed\n", passes, fails ) )
os.exit( fails == 0 and 0 or 1 )
