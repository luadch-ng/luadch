--[[

    tests/unit/sysinfo_test.lua

    Unit tests for core/sysinfo.lua (host OS / CPU / RAM probes).

    Coverage:
      - Windows path: os_name / cpu_info / ram_total / ram_free parse a
        stubbed popen result; each Windows popen command carries the
        Get-CimInstance -> Get-WmiObject fallback (regression guard: PS
        2.0 hosts - Server 2008 R2 / Win7 - have no Get-CimInstance, so
        the fallback MUST stay in the command).
      - Windows query failure (empty popen) degrades: os_name -> default,
        ram_total -> nil (the caller wraps nil with msg_unknown).
      - Unix path: uname / /proc/meminfo / /proc/cpuinfo parsing.

    io.popen is stubbed to record the command + return canned output, so
    the test is platform-independent (forces os_kind via util.path_sep).

    Run: lua5.4 tests/unit/sysinfo_test.lua

]]--

local _cmds                 -- recorded popen commands (this load)
local _canned               -- substring -> output ("" = empty = capture nil)
local _path_sep = "\\"      -- "\\" -> win, "/" -> unix (read once at load)

local function _stub_use( name )
    if name == "io" then
        return { popen = function( cmd )
            _cmds[ #_cmds + 1 ] = cmd
            local out
            for sub, val in pairs( _canned ) do
                if cmd:find( sub, 1, true ) then out = val; break end
            end
            if not out or out == "" then
                -- emulate a handle whose read yields "" (capture -> nil)
                return { read = function() return out or "" end, close = function() end }
            end
            local done = false
            return { read = function() if done then return nil end done = true; return out end,
                     close = function() end }
        end }
    end
    if name == "tostring" then return tostring end
    if name == "tonumber" then return tonumber end
    if name == "string"   then return string end
    if name == "util" then
        return {
            path_sep = function() return _path_sep end,
            formatbytes = function( b )
                local n = tonumber( b )
                if not n then return nil end
                return string.format( "%.2f GB", n / 1073741824 )
            end,
        }
    end
    error( "sysinfo_test stub: missing dep " .. tostring( name ) )
end

local function load_sysinfo( )
    _cmds = { }
    _G.use = _stub_use
    return assert( loadfile( "core/sysinfo.lua" ) )( )
end

----------------------------------------------------------------------
-- harness
----------------------------------------------------------------------

local _passes, _fails = 0, 0
local function eq( what, got, want )
    if got == want then _passes = _passes + 1
    else _fails = _fails + 1
        io.stderr:write( string.format( "FAIL: %s\n  got:  %s\n  want: %s\n",
            what, tostring( got ), tostring( want ) ) ) end
end
local function truthy( what, v )
    if v then _passes = _passes + 1
    else _fails = _fails + 1; io.stderr:write( "FAIL: " .. what .. "\n" ) end
end

local function any_cmd_has( needle )
    for _, c in ipairs( _cmds ) do if c:find( needle, 1, true ) then return true end end
    return false
end

----------------------------------------------------------------------
-- Windows path + the CIM/WMI fallback regression guard
----------------------------------------------------------------------

_path_sep = "\\"
_canned = {
    Caption            = "Windows 10 Pro",
    Win32_Processor    = "Intel(R) Core(TM) i7",
    TotalPhysicalMemory = "17179869184",   -- 16 GiB in bytes
    FreePhysicalMemory  = "8388608",        -- 8 GiB in KiB
}
do
    local si = load_sysinfo( )
    eq( "win os_kind", si.os_kind(), "win" )
    eq( "win os_name parsed", si.os_name(), "Windows 10 Pro" )
    eq( "win cpu_info parsed", si.cpu_info(), "Intel(R) Core(TM) i7" )
    eq( "win ram_total formatted", si.ram_total(), "16.00 GB" )
    eq( "win ram_free formatted", si.ram_free(), "8.00 GB" )

    -- The load-bearing regression: every Windows probe must try
    -- Get-CimInstance AND carry the Get-WmiObject fallback.
    truthy( "os command has Get-CimInstance", any_cmd_has( "Get-CimInstance Win32_OperatingSystem" ) )
    truthy( "os command has Get-WmiObject fallback", any_cmd_has( "Get-WmiObject Win32_OperatingSystem" ) )
    truthy( "cpu command has WMI fallback", any_cmd_has( "Get-WmiObject Win32_Processor" ) )
    truthy( "ram_total command has WMI fallback", any_cmd_has( "Get-WmiObject Win32_ComputerSystem" ) )
    -- ram_free re-shells on call, so its command lands in _cmds too
    truthy( "ram_free command has WMI fallback",
        any_cmd_has( "(Get-WmiObject Win32_OperatingSystem).FreePhysicalMemory" ) )
    truthy( "commands wrapped in try/catch", any_cmd_has( "try {" ) and any_cmd_has( "catch {" ) )
end

----------------------------------------------------------------------
-- Windows query failure degrades cleanly (no crash, nil for RAM)
----------------------------------------------------------------------

_path_sep = "\\"
_canned = { }   -- every popen yields "" -> capture returns nil
do
    local si = load_sysinfo( )
    eq( "win os_name default on empty", si.os_name(), "Microsoft Windows" )
    eq( "win ram_total nil on empty", si.ram_total(), nil )
    eq( "win ram_free nil on empty", si.ram_free(), nil )
    eq( "win cpu_info nil on empty", si.cpu_info(), nil )
end

----------------------------------------------------------------------
-- Unix path
----------------------------------------------------------------------

_path_sep = "/"
_canned = {
    ["uname"]      = "Linux host 5.4.0 x86_64",
    ["MemTotal"]   = "16384000",   -- KiB
    ["MemFree"]    = "8192000",    -- KiB
    ["model name"] = "model name\t: Intel(R) Core(TM) i5",
}
do
    local si = load_sysinfo( )
    eq( "unix os_kind", si.os_kind(), "unix" )
    eq( "unix os_name", si.os_name(), "Linux host 5.4.0 x86_64" )
    eq( "unix cpu_info (first_colon_field)", si.cpu_info(), "Intel(R) Core(TM) i5" )
    eq( "unix ram_total", si.ram_total(), string.format( "%.2f GB", 16384000 * 1024 / 1073741824 ) )
    eq( "unix ram_free", si.ram_free(), string.format( "%.2f GB", 8192000 * 1024 / 1073741824 ) )
    truthy( "unix uses no powershell", not any_cmd_has( "powershell" ) )
end

----------------------------------------------------------------------

if _fails > 0 then
    io.stderr:write( string.format( "\nFAIL: %d/%d checks failed\n", _fails, _passes + _fails ) )
    os.exit( 1 )
end
print( string.format( "OK: %d checks passed", _passes ) )
