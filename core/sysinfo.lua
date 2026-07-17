--[[

        sysinfo.lua

            Host-OS detection helpers (OS name, CPU model, RAM
            total / free). All `io.popen` calls in the hub live
            HERE - extracted from `scripts/cmd_hubinfo.lua` so the
            plugin sandbox no longer needs `io.popen` reach. Bundled
            plugins call `sysinfo.os_name()` etc. via the
            whitelisted `sysinfo` global (see core/scripts.lua
            SANDBOX_GLOBALS).

            Rationale (#206 Tier-2 Sub-PR-3): `io.popen` is the
            single most dangerous primitive a plugin could reach -
            it shells arbitrary commands. cmd_hubinfo only ever
            used it for read-only system-info probes (uname,
            /proc/cpuinfo, PowerShell CIM cmdlets); centralising
            those calls here means the plugin sandbox can drop
            `io.popen` entirely while preserving the
            +hubinfo UX.

            The popen targets and parsing logic are unchanged from
            cmd_hubinfo's v0.29; semantic regressions on the
            +hubinfo cmd should not happen as long as the host's
            command output format also stays the same.

]]--

----------------------------------// DECLARATION //--

local use = use

local io = use "io"
local tonumber = use "tonumber"
local string = use "string"

local util = use "util"

local io_popen = io.popen

local string_find = string.find
local string_match = string.match
local string_sub = string.sub

----------------------------------// HELPERS //--

-- Trim whitespace from both ends. The `or ""` on the match is
-- defensive only - the upstream `capture()` helper already
-- filters nil / empty-string popen output before invoking trim,
-- so the only input shape that reaches here is a non-empty
-- string containing at least one non-whitespace char (the
-- `string.find(s, "^%s*$")` branch returns "" for the
-- whitespace-only case anyway). Kept identical-to-defensive
-- so a future caller without the capture() filter cannot
-- crash on a nil-from-match.
local trim = function( s )
    if not s then return "" end
    return string_find( s, "^%s*$" ) and "" or ( string_match( s, "^%s*(.*%S)" ) or "" )
end

-- Run a shell command, read its stdout, return trimmed string or
-- nil if the popen failed / output was empty. Caller owns the
-- "is the result sensible" check.
local capture = function( cmd )
    local f = io_popen( cmd )
    if not f then return nil end
    local s = f:read( "*a" )
    f:close( )
    if not s or s == "" then return nil end
    return trim( s )
end

-- Windows: Get-CimInstance is PowerShell 3.0+ and is ABSENT on the
-- PowerShell 2.0 that ships with Server 2008 R2 / Windows 7 (it raises
-- a catchable CommandNotFoundException there). Get-WmiObject exists in
-- EVERY Windows PowerShell (2.0 through 5.1); `powershell.exe` is
-- Windows PowerShell, not the PS-7/Core `pwsh` where the WMI cmdlets
-- were dropped. So try the modern CIM cmdlet and fall back to WMI in
-- one popen: PS 3.0+ takes the try branch, PS 2.0 the catch. Both expose
-- the identical `(<query>).<Property>` shape. Fixes "<UNKNOWN>" OS/CPU/RAM
-- (and the pre-refactor cmd_hubinfo nil-concat crash) on old Windows.
local win_cim = function( wmi_class, property )
    return capture(
        'powershell -NoProfile -Command "try { (Get-CimInstance '
        .. wmi_class .. ').' .. property
        .. ' } catch { (Get-WmiObject '
        .. wmi_class .. ').' .. property .. ' }"'
    )
end

-- Pull a colon-delimited field from /proc/cpuinfo-style output.
-- Matches cmd_hubinfo's old `split( s, ":", "\n" )` shape:
-- take the first line, strip everything up to and including the
-- first ":", trim whitespace.
local first_colon_field = function( s )
    if not s or s == "" then return nil end
    local i = string_find( s, ":" )
    if not i then return nil end
    local j = string_find( s, "\n", i + 1 )
    local field = string_sub( s, i + 1, j and ( j - 1 ) or -1 )
    return trim( field )
end

----------------------------------// PUBLIC //--

-- Returns "win", "unix", or "unknown" based on the host path
-- separator. Cached at module load (path-sep cannot change
-- mid-process).
local _os_kind
do
    local sep = util.path_sep( )
    if sep == "\\" then _os_kind = "win"
    elseif sep == "/" then _os_kind = "unix"
    else _os_kind = "unknown" end
end
local os_kind = function( ) return _os_kind end

local os_name = function( )
    if _os_kind == "win" then
        -- CIM with a WMI fallback (see win_cim) so PS 2.0 hosts
        -- (Server 2008 R2 / Win7) report a real caption, not the default.
        local s = win_cim( "Win32_OperatingSystem", "Caption" )
        return s or "Microsoft Windows"
    elseif _os_kind == "unix" then
        local s = capture( "uname -s -r -v -m" )
        return s or "Unknown Unix/Linux"
    else
        return "Unknown Operating System"
    end
end

local cpu_info = function( )
    if _os_kind == "win" then
        local s = win_cim( "Win32_Processor", "Name" )
        return s
    elseif _os_kind == "unix" then
        -- Try /proc/cpuinfo with three known label variants:
        -- "Processor" (older ARM), "model name" (x86/x64), "Model" (Pi).
        local s = capture( "grep \"Processor\" /proc/cpuinfo" )
        if s then return first_colon_field( s ) end
        s = capture( "grep \"model name\" /proc/cpuinfo" )
        if s then return first_colon_field( s ) end
        s = capture( "grep \"Model\" /proc/cpuinfo" )
        if s then
            if string_find( s, "Raspberry Pi 4" ) then
                return "Broadcom Quad core Cortex-A72 (ARM v8) 64-bit SoC @ 1.5GHz"
            end
            return first_colon_field( s )
        end
        return nil
    else
        return nil
    end
end

local ram_total = function( )
    if _os_kind == "win" then
        local s = win_cim( "Win32_ComputerSystem", "TotalPhysicalMemory" )
        if not s then return nil end
        return util.formatbytes( tonumber( s ) or s )
    elseif _os_kind == "unix" then
        local s = capture( "grep MemTotal /proc/meminfo | awk '{ print $2 }'" )
        if not s then return nil end
        return util.formatbytes( ( tonumber( s ) or 0 ) * 1024 )
    else
        return nil
    end
end

-- NOTE: ram_free re-shells on every call (intended: free-RAM is
-- volatile so a startup-cached value would be stale by the time
-- `+hubinfo` is invoked). cmd_hubinfo's pre-refactor v0.29 had
-- the same shape - `check_ram_free` was NOT in the onStart
-- cache list alongside `check_os` / `check_cpu` /
-- `check_ram_total`. Preserved deliberately.
local ram_free = function( )
    if _os_kind == "win" then
        -- FreePhysicalMemory is in KiB on both the CIM and WMI paths.
        local s = win_cim( "Win32_OperatingSystem", "FreePhysicalMemory" )
        if not s then return nil end
        return util.formatbytes( ( tonumber( s ) or 0 ) * 1024 )
    elseif _os_kind == "unix" then
        local s = capture( "grep MemFree /proc/meminfo | awk '{ print $2 }'" )
        if not s then return nil end
        return util.formatbytes( ( tonumber( s ) or 0 ) * 1024 )
    else
        return nil
    end
end

----------------------------------// PUBLIC INTERFACE //--

return {

    os_kind   = os_kind,
    os_name   = os_name,
    cpu_info  = cpu_info,
    ram_total = ram_total,
    ram_free  = ram_free,

}
