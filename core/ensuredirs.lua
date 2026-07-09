--[[

    core/ensuredirs.lua - create the runtime directories the hub writes
    into but does not otherwise create.

    Packaged deploys get these from the CMake install tree + the Docker
    entrypoint; a bare-metal or wiped-bind-mount install can lack them,
    and `cfg/geoip/` (the in-hub GeoIP DB destination, #78 Phase D3) is
    created by NOTHING else today. This is the boot-time self-heal: the
    makedir primitive is mkdir -p + EEXIST-tolerant, so re-creating an
    existing dir is a silent no-op.

    Only the FIXED default locations live here. Operator-relocatable cfg
    paths (log_path, master_key_path, the GeoIP *_db_path, ...) all
    DEFAULT into these dirs, so the common case is fully covered; a path
    an operator moves to a custom (possibly absolute) dir is ensured at
    its own writer instead - core/cfg_secret.lua for master.key,
    core/geoip_update.lua for the GeoIP DB.

    Called EARLY by core/init.lua - before the _core init loop writes
    into any of these - so it depends on NOTHING but the raw makedir
    primitive (a hub.c global reachable via `use`); no other core module
    is loaded/inited yet at that point.

]]--

local use = use

local type   = use "type"
local pcall  = use "pcall"
local ipairs = use "ipairs"

-- Relative to the hub's working directory (hub.c chdir's to the install
-- root at startup). mkdir -p semantics mean "scripts/data" also creates
-- "scripts" and "cfg/geoip" also creates "cfg"; the parents are listed
-- explicitly anyway so the set is self-documenting.
local DIRS = { "log", "cfg", "certs", "scripts/data", "cfg/geoip" }

-- Create every DIR (idempotent). Returns a { dir = true | errmsg }
-- result table, or (nil, err) if the makedir primitive is unavailable
-- (a standalone lua / an older launcher) - best-effort, never throws.
local function ensure( )
    local ok, mkdir = pcall( use, "makedir" )
    if not ok or type( mkdir ) ~= "function" then
        return nil, "makedir primitive unavailable"
    end
    local result = { }
    for _, d in ipairs( DIRS ) do
        local made, err = mkdir( d )
        result[ d ] = made and true or ( err or false )
    end
    return result
end

return {
    ensure = ensure,
    _DIRS  = DIRS,   -- exposed for the unit test
}
