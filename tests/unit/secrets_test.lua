--[[

    tests/unit/secrets_test.lua

    Unit tests for core/secrets.lua (#78 Precursor 0c). Covers:
      - registry: register / is_secret_key / list_secret_keys
      - baseline registrations after init()
      - _derive_env_name shape (prefix + uppercase)
      - lookup: env-var precedence over cfg.get
      - lookup: cfg.get fallback when env var unset / empty
      - lookup: empty cfg returns nil (not the empty string)
      - lookup: nil / non-string input -> nil
      - re-registration is idempotent
      - register rejects non-string / empty input

    Run:  C:\lua-5.4.8_Win64_bin\lua54.exe tests/unit/secrets_test.lua
    Exit 0 = all pass, 1 = a failure.

]]--

----------------------------------------------------------------------
-- `use` shim. secrets.lua follows the core-module pattern: every
-- stdlib / library it touches comes via use("X") under init.lua's
-- restricted env. The shim hands back the real stdlib values for
-- type / pairs / tostring / string / table / os; cfg is mocked.
----------------------------------------------------------------------

local _cfg_store = { }

local _real = {
    type     = type,
    pairs    = pairs,
    tostring = tostring,
    string   = string,
    table    = table,
    os       = os,
    cfg      = {
        get = function( key )
            return _cfg_store[ key ]
        end,
    },
}

_G.use = function( name )
    local m = _real[ name ]
    if m == nil then
        error( "secrets_test shim missing dep: use \"" .. tostring( name ) .. "\"" )
    end
    return m
end

local secrets = assert( loadfile( "core/secrets.lua" ) )( )

----------------------------------------------------------------------
-- Tiny test harness.
----------------------------------------------------------------------

local _passes, _fails = 0, 0

local function assert_eq( what, got, expected )
    if got == expected then
        _passes = _passes + 1
    else
        _fails = _fails + 1
        io.stderr:write( string.format(
            "FAIL: %s\n  got: %s\n  expected: %s\n",
            what, tostring( got ), tostring( expected )
        ) )
    end
end

local function assert_true( what, got )
    assert_eq( what, not not got, true )
end

local function assert_false( what, got )
    assert_eq( what, not got, true )
end

----------------------------------------------------------------------
-- _derive_env_name
----------------------------------------------------------------------

assert_eq( "_derive_env_name: simple cfg key",
    secrets._derive_env_name( "etc_geoip_license_key" ),
    "LUADCH_ETC_GEOIP_LICENSE_KEY" )

assert_eq( "_derive_env_name: short key",
    secrets._derive_env_name( "api_token" ),
    "LUADCH_API_TOKEN" )

assert_eq( "_derive_env_name: nil input -> nil",
    secrets._derive_env_name( nil ), nil )

assert_eq( "_derive_env_name: empty string -> nil",
    secrets._derive_env_name( "" ), nil )

assert_eq( "_derive_env_name: non-string -> nil",
    secrets._derive_env_name( 42 ), nil )

-- Fail-loud guard: any cfg key with chars outside [A-Za-z0-9_] gets
-- nil rather than an unreliable env-var name. POSIX shells accept
-- only [A-Z0-9_] in env-var names; producing `LUADCH_FOO-BAR`
-- silently would create shell-dependent lookup behaviour.
assert_eq( "_derive_env_name: dash rejected",
    secrets._derive_env_name( "foo-bar" ), nil )

assert_eq( "_derive_env_name: dot rejected",
    secrets._derive_env_name( "foo.bar" ), nil )

assert_eq( "_derive_env_name: space rejected",
    secrets._derive_env_name( "foo bar" ), nil )

assert_eq( "_derive_env_name: slash rejected",
    secrets._derive_env_name( "foo/bar" ), nil )

----------------------------------------------------------------------
-- register / is_secret_key / list_secret_keys (fresh registry)
----------------------------------------------------------------------

assert_false( "is_secret_key: unknown key pre-init",
    secrets.is_secret_key( "etc_geoip_license_key" ) )

assert_true( "register: returns true on success",
    secrets.register( "etc_geoip_license_key" ) )

assert_true( "is_secret_key: registered key -> true",
    secrets.is_secret_key( "etc_geoip_license_key" ) )

assert_false( "is_secret_key: still-unknown key -> false",
    secrets.is_secret_key( "etc_proxydetect_api_key" ) )

assert_true( "register: re-registration is idempotent",
    secrets.register( "etc_geoip_license_key" ) )

assert_false( "register: nil input rejected",
    secrets.register( nil ) )

assert_false( "register: empty string rejected",
    secrets.register( "" ) )

assert_false( "register: non-string rejected",
    secrets.register( 42 ) )

local list = secrets.list_secret_keys( )
assert_eq( "list_secret_keys: count = 1 after one register",
    #list, 1 )
assert_eq( "list_secret_keys: contains registered key",
    list[ 1 ], "etc_geoip_license_key" )

----------------------------------------------------------------------
-- init() seeds the baseline registry
----------------------------------------------------------------------

secrets.init( )

assert_true( "init: http_api_tokens registered",
    secrets.is_secret_key( "http_api_tokens" ) )

assert_true( "init: master_key_path registered",
    secrets.is_secret_key( "master_key_path" ) )

local list_after = secrets.list_secret_keys( )
assert_true( "list_secret_keys: returns sorted array",
    list_after[ 1 ] <= list_after[ #list_after ] )

----------------------------------------------------------------------
-- lookup: env-var precedence (mock os.getenv via _G replacement)
----------------------------------------------------------------------

-- Stash + replace os.getenv with a controllable mock. The module
-- captured `os` at load time via `local os = os`, so we mutate the
-- shared `os` table's `getenv` field instead of rebinding the local.
local _real_getenv = os.getenv
local _env = { }
os.getenv = function( name ) return _env[ name ] end

-- Case 1: env var set + cfg unset -> env wins
_env[ "LUADCH_TESTKEY_ALPHA" ] = "from-env"
_cfg_store[ "testkey_alpha" ] = nil
assert_eq( "lookup: env-var precedence over unset cfg",
    secrets.lookup( "testkey_alpha" ),
    "from-env" )

-- Case 2: env var set + cfg also set -> env still wins
_env[ "LUADCH_TESTKEY_BETA" ] = "from-env"
_cfg_store[ "testkey_beta" ] = "from-cfg"
assert_eq( "lookup: env wins over populated cfg",
    secrets.lookup( "testkey_beta" ),
    "from-env" )

-- Case 3: env unset + cfg set -> cfg fallback
_env[ "LUADCH_TESTKEY_GAMMA" ] = nil
_cfg_store[ "testkey_gamma" ] = "from-cfg"
assert_eq( "lookup: cfg fallback when env unset",
    secrets.lookup( "testkey_gamma" ),
    "from-cfg" )

-- Case 4: env set to empty + cfg set -> cfg wins (empty env != set)
_env[ "LUADCH_TESTKEY_DELTA" ] = ""
_cfg_store[ "testkey_delta" ] = "from-cfg"
assert_eq( "lookup: empty env does NOT mask populated cfg",
    secrets.lookup( "testkey_delta" ),
    "from-cfg" )

-- Case 5: both unset -> nil
_env[ "LUADCH_TESTKEY_EPSILON" ] = nil
_cfg_store[ "testkey_epsilon" ] = nil
assert_eq( "lookup: both unset -> nil",
    secrets.lookup( "testkey_epsilon" ),
    nil )

-- Case 6: cfg has empty string -> nil (treated as unset)
_env[ "LUADCH_TESTKEY_ZETA" ] = nil
_cfg_store[ "testkey_zeta" ] = ""
assert_eq( "lookup: cfg empty string treated as unset",
    secrets.lookup( "testkey_zeta" ),
    nil )

-- Case 7: cfg has non-string value (e.g. table) -> nil
_env[ "LUADCH_TESTKEY_ETA" ] = nil
_cfg_store[ "testkey_eta" ] = { "not", "a", "string" }
assert_eq( "lookup: cfg non-string treated as unset",
    secrets.lookup( "testkey_eta" ),
    nil )

-- Case 8: lookup() with bad input
assert_eq( "lookup: nil input -> nil",
    secrets.lookup( nil ), nil )

assert_eq( "lookup: empty string input -> nil",
    secrets.lookup( "" ), nil )

assert_eq( "lookup: non-string input -> nil",
    secrets.lookup( 42 ), nil )

-- Restore os.getenv
os.getenv = _real_getenv

----------------------------------------------------------------------
-- Result
----------------------------------------------------------------------

if _fails > 0 then
    io.stderr:write( string.format(
        "\nFAIL: %d/%d checks failed\n",
        _fails, _passes + _fails
    ) )
    os.exit( 1 )
end

print( string.format( "OK: %d checks passed", _passes ) )
