--[[

    core/secrets.lua - sensitive-key registry + env-var-first lookup.

    Two responsibilities, both pre-requisites for the unified
    blocklist arc (#78 Precursor 0c) - Phase D (etc_geoip) needs a
    MaxMind license-key lookup that survives both Docker (env var)
    and bare-metal (cfg.tbl) deployments; Phase F (etc_proxydetect)
    needs the same shape for proxycheck.io / VPNAPI.io / IPQS API
    keys. The redaction registry is also used today by
    GET /v1/config (#262) which previously hardcoded its denylist.

    1. Registry of cfg keys that are "secrets" (API tokens, license
       keys, encryption-master-key paths). Consumers consult
       `is_secret_key(cfg_key)` before displaying / logging /
       exporting a cfg value. Single source of truth - GET /v1/config
       redaction, future +showcfg, audit-body redaction all consult
       this module instead of carrying their own denylist copies.

    2. Env-var-first lookup helper (`lookup`): for API-keyed plugins
       and any cfg key that should travel via Docker env section
       instead of cfg.tbl. Checks `LUADCH_<UPPER_CFG_KEY>` env var
       first; falls back to cfg.get on miss. Empty string in either
       location counts as "unset" so an empty env var does NOT mask
       a populated cfg value.

    Lazy-binds cfg via `use "cfg"` at call time so module load order
    in init.lua is straightforward (cfg -> secrets -> rest of core).

    Baseline registry (pre-loaded by init()):
      - http_api_tokens (HTTP API auth tokens; existed pre-arc)
      - master_key_path (cfg_secret encryption key path; existed pre-arc)

    Plugins / other modules register additional keys at onStart /
    init time:

        local secrets = use "secrets"
        secrets.register( "etc_geoip_license_key" )

    Re-registration is idempotent. No unregister() - sensitive keys
    stay sensitive for the process lifetime.

]]--

local type        = type
local pairs       = pairs
local tostring    = tostring
local string      = string
local table       = table
local os          = os
local use         = use

local _registry = { }

local _env_prefix = "LUADCH_"

local _derive_env_name = function( cfg_key )
    if type( cfg_key ) ~= "string" or cfg_key == "" then return nil end
    -- cfg keys in this repo are [a-z0-9_]+ (per cfg_defaults.lua
    -- convention); a plain upper() suffices and the POSIX / Windows
    -- env-var name charset accepts all of [A-Z0-9_]. Fail-loud on
    -- any future cfg key that contains chars outside that set
    -- rather than silently producing an unreliable env-var name
    -- (e.g. `LUADCH_FOO-BAR` reads differ across shells).
    if cfg_key:find( "[^%a%d_]" ) then return nil end
    return _env_prefix .. string.upper( cfg_key )
end

local register = function( cfg_key )
    if type( cfg_key ) ~= "string" or cfg_key == "" then return false end
    _registry[ cfg_key ] = true
    return true
end

local is_secret_key = function( cfg_key )
    return _registry[ cfg_key ] == true
end

local lookup = function( cfg_key )
    if type( cfg_key ) ~= "string" or cfg_key == "" then return nil end

    -- 1. Env var first (Docker-friendly).
    local env_name = _derive_env_name( cfg_key )
    if env_name then
        local v = os.getenv( env_name )
        if type( v ) == "string" and v ~= "" then
            return v
        end
    end

    -- 2. cfg.tbl fallback (bare-metal friendly; chmod 600 by Phase
    -- 7c hardening).
    local cfg_mod = use "cfg"
    if cfg_mod and type( cfg_mod.get ) == "function" then
        local v = cfg_mod.get( cfg_key )
        if type( v ) == "string" and v ~= "" then
            return v
        end
    end

    return nil
end

local list_secret_keys = function( )
    local out = { }
    for k in pairs( _registry ) do
        out[ #out + 1 ] = k
    end
    table.sort( out )
    return out
end

local init = function( )
    -- Baseline registry - sensitive keys that existed before this
    -- module landed. Migrated from the hardcoded denylist at
    -- core/http_router.lua _config_denylist (#262 / #272).
    register( "http_api_tokens" )
    register( "master_key_path" )
end

return {
    register         = register,
    is_secret_key    = is_secret_key,
    lookup           = lookup,
    list_secret_keys = list_secret_keys,
    _derive_env_name = _derive_env_name,    -- exposed for tests
    init             = init,
}
