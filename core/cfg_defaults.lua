--[[

    cfg_defaults.lua - default settings table extracted from core/cfg.lua

    Extracted in Phase 6c-1 to bring core/cfg.lua under the Phase 6
    1500-line ceiling. The default settings table accounts for ~80%
    of cfg.lua's volume (3000+ lines of value/validator pairs); moving
    it here leaves cfg.lua with just the orchestration logic.

    NOTE ON LINE COUNT: This file deliberately exceeds the Phase 6
    1500-line module ceiling (CLAUDE.md §5). It is a flat data table
    of around 700 cfg-key entries shaped { <default>, <validator-fn> },
    not procedural code with branches and state. CLAUDE.md §5 Phase 6
    review-gate explicitly exempts data tables from the ceiling on the
    grounds that cognitive load on a repetitive lookup is materially
    different from 1500 lines of branching logic. If this file ever
    starts holding logic instead of data, that exception no longer
    applies and it must be split.

    Public surface returned to cfg.lua:

        {
            settings  = { <key> = { <default-value>, <validator-fn> }, ... },
            bind_late = function()  -- see comment below
        }

    Each entry's validator is a closure over the local types_X
    upvalues declared at the top of this file. types_adcstr is
    deliberately late-bound: types.add("adcstr", ...) is registered
    by core/adc.lua, which loads AFTER us during init.lua's core-load
    loop. Lua captures upvalues by reference, so once cfg.init()
    calls bind_late(), every validator that references types_adcstr
    sees the new value automatically.

]]--

local type = use "type"
local pairs = use "pairs"
local ipairs = use "ipairs"

local const = use "const"
local types = use "types"

local CONFIG_PATH = const.CONFIG_PATH

local types_utf8 = types.utf8
local types_table = types.get "table"
local types_number = types.get "number"
local types_boolean = types.get "boolean"

-- Late-bound: types.add("adcstr", ...) is registered by core/adc.lua,
-- which loads after us. cfg.init() calls bind_late() at the right
-- time, after which all closures referencing types_adcstr see it.
local types_adcstr

local function bind_late()
    types_adcstr = types.get "adcstr"
end

local defaults = {


    ---------------------------------------------------------------------------------------------------------------------------------
    --// Basic Settings

    hub_name = { "Luadch Hub",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    hub_description = { "your hub description",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    hub_bot = { "[BOT]HubSecurity",
        function( value )
            if not types_adcstr( value, nil, true ) or #value == 0 then
                return false
            end
            return true
        end
    },
    hub_bot_desc = { "[ BOT ] hub security",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    hub_hostaddress = { "your.host.addy.org",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    tcp_ports = { { 5000 },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not types_number( k, nil, true ) then
                        return false
                    end
                end
            end
            return true
        end
    },
    ssl_ports = { { 5001 },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not types_number( k, nil, true ) then
                        return false
                    end
                end
            end
            return true
        end
    },
    tcp_ports_ipv6 = { { 5002 },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not types_number( k, nil, true ) then
                        return false
                    end
                end
            end
            return true
        end
    },
    ssl_ports_ipv6 = { { 5003 },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not types_number( k, nil, true ) then
                        return false
                    end
                end
            end
            return true
        end
    },
    use_ssl = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    use_keyprint = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    keyprint_type = { "/?kp=SHA256/",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    keyprint_hash = { "<your_kp>",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    hub_listen = { { "*" },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not types_utf8( k, nil, true ) then
                        return false
                    end
                end
            end
            return true
        end
    },
    hub_website = { "http://yourwebsite.org",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    hub_network = { "your hubnetwork name",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    hub_email = { "hub@mail.com",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    hub_bot_email = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    hub_owner = { "you",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    reg_only = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    nick_change = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    max_users = { 3000,
        function( value )
            return types_number( value, nil, true )
        end
    },
    user_path = { CONFIG_PATH,
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    --[[
        Path to the master key that decrypts cfg/user.tbl
        (Phase 7f F-AUTH-1, AES-256-GCM at rest).

        IMPORTANT:
            Empty string falls back to "<install>/cfg/master.key", which
            sits next to the encrypted user.tbl. That default exists for
            backwards compatibility and zero-config first-boot, but it
            is NOT the recommended production setup: anyone who exfiltrates
            a routine `tar czf backup.tar.gz cfg/` gets BOTH the encrypted
            blob AND its decryption key, and can decrypt offline. The
            at-rest encryption then provides zero protection.

        SET THIS to an absolute path OUTSIDE the install directory before
        you put real users in user.tbl, e.g.:

            master_key_path = "/etc/luadch/master.key"     -- POSIX
            master_key_path = "C:/ProgramData/luadch/master.key"  -- Windows

        Then exclude that path from your routine backup, or back it up to
        a separate destination (different host / encrypted-with-passphrase
        archive). Same handling as your TLS private key. See
        docs/SECURITY.md §3 for the backup-separation rationale.

        On POSIX the hub refuses to start if the file mode is not 0600.
        On Windows use icacls (see docs/BUILDING.md).
    ]]--
    master_key_path = { "",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    reg_level = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },
    key_level = { 50,
        function( value )
            return types_number( value, nil, true )
        end
    },
    bot_level = { 55,
        function( value )
            return types_number( value, nil, true )
        end
    },
    debug = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    log_errors = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    log_events = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    log_scripts = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    log_path = { "././log/",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    language = { "en",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    core_lang_path = { "lang/",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    scripts_lang_path = { "././scripts/lang/",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    --[[
    hub_pass = { "jsjfjs87374737472374jdjdfj384",
        function( value )
            return types_boolean( value, nil, true ) or types_adcstr( value, nil, true )
        end
    },
    ]]
    max_bad_password = { 5,
        function( value )
            return types_number( value, nil, true )
        end
    },
    bad_pass_timeout = { 300,
        function( value )
            return types_number( value, nil, true )
        end
    },
    min_password_length = { 10,
        function( value )
            return types_number( value, nil, true )
        end
    },
    max_password_length = { 30,
        function( value )
            return types_number( value, nil, true )
        end
    },
    min_nickname_length = { 3,
        function( value )
            return types_number( value, nil, true )
        end
    },
    max_nickname_length = { 30,
        function( value )
            return types_number( value, nil, true )
        end
    },
    no_cid_taken = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    ranks = { {

        "Bot",
        "Reg",
        "Op",
        "Admin",
        "Owner",

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in ipairs( value ) do
                    if not types_utf8( k, nil, true ) then
                        return false
                    end
                end
            end
            return true
        end
    },
    bot_rank = { 1,
        function( value )
            return types_number( value, nil, true )
        end
    },
    reg_rank = { 2,
        function( value )
            return types_number( value, nil, true )
        end
    },
    op_rank = { 4,
        function( value )
            return types_number( value, nil, true )
        end
    },
    admin_rank = { 8,
        function( value )
            return types_number( value, nil, true )
        end
    },
    owner_rank = { 16,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// Your hub levels with level names (array of strings)

    levels = { {

        [ 0 ] = "UNREG",
        [ 10 ] = "GUEST",
        [ 20 ] = "REG",
        [ 30 ] = "VIP",
        [ 40 ] = "SVIP",
        [ 50 ] = "SERVER",
        [ 55 ] = "SBOT",
        [ 60 ] = "OPERATOR",
        [ 70 ] = "SUPERVISOR",
        [ 80 ] = "ADMIN",
        [ 100 ] = "HUBOWNER",

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_utf8( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// bot_regchat.lua settings

    bot_regchat_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    bot_regchat_nick = { "[CHAT]RegChat",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    bot_regchat_desc = { "[ CHAT ] chatroom for reg users",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    bot_regchat_history = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    bot_regchat_max_entrys = { 300,
        function( value )
            return types_number( value, nil, true )
        end
    },
    bot_regchat_oplevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },
    bot_regchat_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = true,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// bot_opchat.lua settings

    bot_opchat_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    bot_opchat_nick = { "[CHAT]OpChat",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    bot_opchat_desc = { "[ CHAT ] chatroom for operators",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    bot_opchat_history = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    bot_opchat_max_entrys = { 300,
        function( value )
            return types_number( value, nil, true )
        end
    },
    bot_opchat_oplevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },
    bot_opchat_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// bot_pm2ops.lua settings

    bot_pm2ops_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    bot_pm2ops_nick = { "[CHAT]PmToOps",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    bot_pm2ops_desc = { "[ CHAT ] send msg to all ops",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    bot_pm2ops_permission = { {

        [ 0 ] = false,
        [ 10 ] = true,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = false,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_accinfo.lua settings

    cmd_accinfo_permission = { {

    [ 0 ] = 0,
    [ 10 ] = 0,
    [ 20 ] = 0,
    [ 30 ] = 0,
    [ 40 ] = 0,
    [ 50 ] = 0,
    [ 55 ] = 0,
    [ 60 ] = 50,
    [ 70 ] = 60,
    [ 80 ] = 70,
    [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_accinfo_advanced_rc = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_ascii.lua settings

    cmd_ascii_minlevel = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_slots.lua settings

    cmd_slots_minlevel = { 0,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_ban.lua settings

    cmd_ban_default_time = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_ban_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_ban_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_ban_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_ban_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 50,
        [ 70 ] = 60,
        [ 80 ] = 70,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_ban_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_delreg.lua settings

    cmd_delreg_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_delreg_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_delreg_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_delreg_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_delreg_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 0,
        [ 70 ] = 0,
        [ 80 ] = 0,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_disconnect.lua settings

    cmd_disconnect_minlevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_disconnect_sendmainmsg = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_disconnect_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_disconnect_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_disconnect_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_disconnect_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_errors.lua settings

    cmd_errors_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_mass.lua settings

    cmd_mass_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = true,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_mass_oplevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_reg.lua settings

    cmd_reg_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_reg_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_reg_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_reg_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_reg_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 20,
        [ 70 ] = 30,
        [ 80 ] = 60,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_reload.lua settings

    cmd_reload_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = false,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_restart.lua settings

    cmd_restart_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = false,
        [ 70 ] = false,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_restart_toggle_countdown = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_rules.lua settings

    cmd_rules_minlevel = { 0,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_rules_destination_main = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_rules_destination_pm = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_setpass.lua settings

    cmd_setpass_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 0,
        [ 70 ] = 0,
        [ 80 ] = 0,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_setpass_permission_own_pw = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = true,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_setpass_advanced_rc = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_nickchange.lua settings

    cmd_nickchange_minlevel = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_nickchange_oplevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_nickchange_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_nickchange_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_nickchange_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_nickchange_advanced_rc = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_shutdown.lua settings

    cmd_shutdown_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = false,
        [ 70 ] = false,
        [ 80 ] = false,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_shutdown_toggle_countdown = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_talk.lua settings

    cmd_talk_minlevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_pm2offliners.lua settings

    cmd_pm2offliners_minlevel = { 30,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_pm2offliners_oplevel = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_pm2offliners_delay = { 7,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_pm2offliners_advanced_rc = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_unban.lua settings

    cmd_unban_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 60,
        [ 70 ] = 70,
        [ 80 ] = 80,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_upgrade.lua settings

    cmd_upgrade_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_upgrade_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_upgrade_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_upgrade_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_upgrade_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 0,
        [ 70 ] = 0,
        [ 80 ] = 0,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_upgrade_advanced_rc = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_userinfo.lua settings

    cmd_userinfo_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 50,
        [ 70 ] = 60,
        [ 80 ] = 70,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_userlist.lua settings

    cmd_userlist_minlevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_usersearch.lua settings

    cmd_usersearch_minlevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_usersearch_max_limit = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_hubinfo.lua settings

    cmd_hubinfo_minlevel = { 10,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_hubinfo_onlogin = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_uptime.lua settings

    cmd_uptime_minlevel = { 0,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_banner.lua settings

    etc_banner_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_banner_time = { 1,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_banner_destination_main = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_banner_destination_pm = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_banner_permission = { {

        [ 0 ] = true,
        [ 10 ] = true,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = false,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_chatlog.lua settings

    etc_chatlog_min_level_adv = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_chatlog_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = false,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    etc_chatlog_max_lines = { 200,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_chatlog_default_lines = { 5,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_blacklist.lua settings

    etc_blacklist_oplevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_blacklist_masterlevel = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_cmdlog.lua settings

    etc_cmdlog_minlevel = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_cmdlog_command_tbl = { {

        [ "reg" ] = true,
        [ "delreg" ] = true,
        [ "disconnect" ] = true,
        [ "ban" ] = true,
        [ "unban" ] = true,
        [ "upgrade" ] = true,
        [ "accinfo" ] = true,
        [ "nickchange" ] = true,
        [ "reload" ] = true,
        [ "restart" ] = true,
        [ "shutdown" ] = true,
        [ "trafficmanager" ] = true,
    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_utf8( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    -- #96: command names whose post-command-name argument string is
    -- replaced with `<redacted>` in log/cmd.log. Prevents passwords
    -- supplied via +setpass / +newpw from landing on disk in plaintext
    -- through etc_cmdlog's audit trail.
    etc_cmdlog_redact_args = { {

        [ "setpass" ] = true,
        [ "newpw" ] = true,
    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_utf8( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_log_cleaner.lua settings

    etc_log_cleaner_minlevel = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_log_cleaner_activate_error = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_log_cleaner_activate_cmd = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_motd.lua settings

    etc_motd_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_motd_permission = { {

        [ 0 ] = true,
        [ 10 ] = true,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = false,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    etc_motd_destination_main = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_motd_destination_pm = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_usercommands.lua settings

    etc_usercommands_toplevelmenu = { "Luadch Commands",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_userlogininfo.lua settings

    etc_userlogininfo_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_userlogininfo_permission = { {

        [ 0 ] = false,
        [ 10 ] = true,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = false,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },


    ---------------------------------------------------------------------------------------------------------------------------------
    --// usr_nick_prefix.lua settings

    usr_nick_prefix_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    usr_nick_prefix_prefix_table = { {

        [ 0 ] = "[UNREG]",
        [ 10 ] = "[GUEST]",
        [ 20 ] = "[REG]",
        [ 30 ] = "[VIP]",
        [ 40 ] = "[SVIP]",
        [ 50 ] = "[SERVER]",
        [ 55 ] = "[SBOT]",
        [ 60 ] = "[OPERATOR]",
        [ 70 ] = "[SUPERVISOR]",
        [ 80 ] = "[ADMIN]",
        [ 100 ] = "[HUBOWNER]",

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_utf8( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    usr_nick_prefix_permission = { {

        [ 0 ] = false,
        [ 10 ] = true,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = true,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// usr_desc_prefix.lua settings

    usr_desc_prefix_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    usr_desc_prefix_prefix_table = { {

        [ 0 ] = "[ UNREG ] ",
        [ 10 ] = "[ GUEST ] ",
        [ 20 ] = "[ REG ] ",
        [ 30 ] = "[ VIP ] ",
        [ 40 ] = "[ SVIP ] ",
        [ 50 ] = "[ SERVER ] ",
        [ 55 ] = "[ SBOT ] ",
        [ 60 ] = "[ OPERATOR ] ",
        [ 70 ] = "[ SUPERVISOR ] ",
        [ 80 ] = "[ ADMIN ] ",
        [ 100 ] = "[ HUBOWNER ] ",

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_utf8( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    usr_desc_prefix_permission = { {

        [ 0 ] = false,
        [ 10 ] = true,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = true,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// usr_slots.lua settings

    min_slots = { {

        [ 0 ] = 2,
        [ 10 ] = 2,
        [ 20 ] = 2,
        [ 30 ] = 2,
        [ 40 ] = 2,
        [ 50 ] = 2,
        [ 55 ] = 0,
        [ 60 ] = 0,
        [ 70 ] = 0,
        [ 80 ] = 0,
        [ 100 ] = 0,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    max_slots = { {

        [ 0 ] = 20,
        [ 10 ] = 20,
        [ 20 ] = 20,
        [ 30 ] = 20,
        [ 40 ] = 20,
        [ 50 ] = 20,
        [ 55 ] = 20,
        [ 60 ] = 20,
        [ 70 ] = 20,
        [ 80 ] = 20,
        [ 100 ] = 20,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    usr_slots_redirect = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// usr_share.lua settings

    min_share = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 0,
        [ 70 ] = 0,
        [ 80 ] = 0,
        [ 100 ] = 0,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    max_share = { {

        [ 0 ] = 200,
        [ 10 ] = 200,
        [ 20 ] = 200,
        [ 30 ] = 200,
        [ 40 ] = 200,
        [ 50 ] = 200,
        [ 55 ] = 200,
        [ 60 ] = 200,
        [ 70 ] = 200,
        [ 80 ] = 200,
        [ 100 ] = 200,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    usr_share_redirect = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// usr_hubs.lua settings

    max_hubs = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    max_user_hubs = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    max_reg_hubs = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    max_op_hubs = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    usr_hubs_godlevel = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = true,
        [ 55 ] = true,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    usr_hubs_block_time = { 15,
        function( value )
            return types_number( value, nil, true )
        end
    },

    usr_hubs_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    usr_hubs_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    usr_hubs_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    usr_hubs_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    usr_hubs_redirect = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// usr_topic.lua settings

    cmd_topic_minlevel = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_topic_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_topic_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_topic_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_topic_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_trafficmanager.lua settings

    etc_trafficmanager_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 40,
        [ 70 ] = 60,
        [ 80 ] = 70,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    etc_trafficmanager_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_trafficmanager_blocklevel_tbl = { {

        [ 0 ] = true,
        [ 10 ] = true,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = false,
        [ 70 ] = false,
        [ 80 ] = false,
        [ 100 ] = false,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    etc_trafficmanager_sharecheck = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_check_minshare = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_oplevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_trafficmanager_login_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_report_main = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_report_pm = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_send_loop = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_loop_time = { 6,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_trafficmanager_flag_blocked = { "[BLOCKED]",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_msgmanager.lua settings

    etc_msgmanager_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_msgmanager_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 40,
        [ 70 ] = 60,
        [ 80 ] = 70,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    etc_msgmanager_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_msgmanager_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_msgmanager_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_msgmanager_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_msgmanager_permission_pm = { {

        [ 0 ] = true,
        [ 10 ] = true,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = true,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    etc_msgmanager_permission_main = { {

        [ 0 ] = true,
        [ 10 ] = true,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = true,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// usr_hide_share.lua settings

    usr_hide_share_activate = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    usr_hide_share_restrictions = { {

        [ 0 ] = true,
        [ 10 ] = true,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = false,
        [ 70 ] = false,
        [ 80 ] = false,
        [ 100 ] = false,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    usr_hide_share_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 40,
        [ 70 ] = 60,
        [ 80 ] = 70,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_gag.lua settings

    cmd_gag_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_gag_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_gag_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_gag_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_gag_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 50,
        [ 70 ] = 60,
        [ 80 ] = 70,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_gag_user_notifiy = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_records.lua settings

    etc_records_min_level = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_records_whereto_main = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_records_whereto_pm = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_records_reportlvl = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_records_sendMain = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_records_sendPM = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_records_delay = { 300,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_records_min_level_reset = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// bot_session_chat.lua settings

    bot_session_chat_minlevel = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    bot_session_chat_masterlevel = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    bot_session_chat_chatprefix = { "[SESSION-CHAT]",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_hubstats.lua settings

    cmd_hubstats_oplevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_dhtblocker.lua settings

    etc_dhtblocker_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_dhtblocker_block_level = { {

        [ 0 ] = true,
        [ 10 ] = true,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = true,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    etc_dhtblocker_block_time = { 15,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_dhtblocker_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_dhtblocker_report_toopchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_dhtblocker_report_tohubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_dhtblocker_report_level = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_redirect.lua settings

    cmd_redirect_activate = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_redirect_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 50,
        [ 70 ] = 60,
        [ 80 ] = 70,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_redirect_level = { {

        [ 0 ] = true,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = false,
        [ 70 ] = false,
        [ 80 ] = false,
        [ 100 ] = false,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_redirect_url = { "adc://addy:port",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    cmd_redirect_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_redirect_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_redirect_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_redirect_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_sslinfo.lua settings

    cmd_sslinfo_minlevel = { 10,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_myinf.lua settings

    cmd_myinf_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// hub_runtime.lua settings

    hub_runtime_minlevel = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    hub_runtime_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    hub_runtime_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    hub_runtime_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    hub_runtime_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// usr_uptime.lua settings

    usr_uptime_minlevel = { 10,
        function( value )
            return types_number( value, nil, true )
        end
    },

    usr_uptime_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_usercleaner.lua settings | this script shows and removes no longer used and never used accounts from "cfg/users.tbl"

    cmd_usercleaner_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_usercleaner_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = false,
        [ 70 ] = false,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_usercleaner_protected_levels = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = false,
        [ 70 ] = false,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_usercleaner_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_usercleaner_report_opchat = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_usercleaner_report_hubbot = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_usercleaner_report_llevel = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_gag.lua settings

    etc_onfailedauth_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_onfailedauth_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_onfailedauth_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_onfailedauth_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// user scripts (string array); scripts will be executed in this order!

    scripts = { {

        "hub_cmd_manager.lua",  -- must be the first script in the table!
        "etc_cmdlog.lua",  -- must be the second script in the table!
        "bot_opchat.lua", -- must be above all other scripts who wants to use the opchat import
        "etc_report.lua", -- must be above all other scripts who wants to use the report import / needs opchat
        "cmd_ban.lua", -- must be above all other scripts who wants to use the ban import / needs report
        "usr_uptime.lua", -- must be above all other scripts who wants to use the usersuptime import

        "hub_inf_manager.lua",
        "hub_runtime.lua",
        "bot_regchat.lua",
        "bot_session_chat.lua",
        "bot_pm2ops.lua",
        "usr_slots.lua",
        "usr_share.lua",
        "usr_hubs.lua",
        "usr_nick_prefix.lua",
        "usr_desc_prefix.lua",
        "usr_hide_share.lua",
        "cmd_help.lua",
        "cmd_redirect.lua",
        "cmd_uptime.lua",
        "cmd_hubinfo.lua",
        "cmd_hubstats.lua",
        "cmd_myip.lua",
        "cmd_myinf.lua",
        "cmd_rules.lua",
        "cmd_userinfo.lua",
        "cmd_usersearch.lua",
        "cmd_slots.lua",
        "cmd_accinfo.lua",
        "cmd_setpass.lua",
        "cmd_nickchange.lua",
        "cmd_mass.lua",
        "cmd_talk.lua",
        "cmd_pm2offliners.lua",
        "cmd_topic.lua",
        "cmd_userlist.lua",
        "cmd_disconnect.lua",
        "cmd_reg.lua",
        "cmd_upgrade.lua",
        "cmd_delreg.lua",
        "cmd_usercleaner.lua",
        "cmd_errors.lua",
        "cmd_reload.lua",
        "cmd_restart.lua",
        "cmd_shutdown.lua",
        "cmd_ascii.lua",
        "cmd_gag.lua",
        "cmd_sslinfo.lua",
        "etc_hubcommands.lua",
        "etc_usercommands.lua",
        "etc_blacklist.lua",
        "etc_log_cleaner.lua",
        "etc_motd.lua",
        "etc_userlogininfo.lua",
        "etc_banner.lua",
        "etc_chatlog.lua",
        "etc_msgmanager.lua",
        "etc_trafficmanager.lua",
        "etc_records.lua",
        "etc_dhtblocker.lua",

        "hub_bot_cleaner.lua",
        "etc_unknown_command.lua",

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in ipairs( value ) do
                    if not types_utf8( k, nil, true ) then
                        return false
                    end
                end
            end
            return true
        end
    },
    script_path = { "././scripts/",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    ssl_params = { {

        mode = "server",  -- do not touch this
        key = "certs/serverkey.pem",  -- your ssl key
        certificate = "certs/servercert.pem",  -- your cert
        cafile = "certs/cacert.pem",  -- your ca file
        options = { "no_sslv2", "no_sslv3" },  -- do not touch this
        curve = "prime256v1",  -- do not touch this

        protocol = "tlsv1_3",
        ciphers = "HIGH+kEDH:HIGH+kEECDH:HIGH:!PSK:!SRP:!3DES:!aNULL", -- TLSv1.3

    }, function( ) return true end },
    scripts_cfg_profile = { "default",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    scripts_cfg_path = { "././scripts/cfg/",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    no_global_scripting = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    -- #97: default kept off historically because some NAT setups
    -- legitimately advertise a different IP than the TCP source
    -- (clients behind symmetric NAT, IPv6 fallback weirdness). The
    -- legitimate "I40.0.0.0" passive-mode case is handled separately
    -- in core/hub_dispatch.lua (the hub fills in the real IP); the
    -- only branch this gate fires on is "client claims a real but
    -- different IP". Per-IP rate limits, GeoIP rules, abuse logs, and
    -- the unified blocklist all rely on the IP being trustworthy, so
    -- the default is now true. NAT-weird deployments opt out by
    -- setting kill_wrong_ips = false in their cfg/cfg.tbl.
    kill_wrong_ips = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    --// RATE-LIMIT / DOS-HARDENING //--
    --
    -- Phase 7c. All defaults are conservative; tune to traffic profile.
    -- Op-level users (level >= ratelimit_bypass_level) bypass every
    -- per-user check below. Per-IP checks always apply.
    --
    -- Each "rate" key is integer per-second tokens (or bursts/window
    -- where noted). The "burst" key is the bucket capacity, allowing
    -- short spikes above the steady rate.

    ratelimit_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    ratelimit_bypass_level = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- Per-IP parallel-socket cap. Connection refused at accept time.
    -- Default 16 accommodates small-office NAT / CGNAT deployments
    -- where many users share one public IP. Lower for tighter hubs.
    ratelimit_perip_max_conns = { 16,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- Per-IP new-connection rate (tokens/second + burst).
    -- Defaults sized for NAT bursts (e.g. an office reconnecting after
    -- internet flap). Burst >= max_conns so the parallel-cap is the
    -- binding limit at steady-state, not the rate-bucket.
    ratelimit_perip_conn_rate = { 10,
        function( value )
            return types_number( value, nil, true )
        end
    },
    ratelimit_perip_conn_burst = { 30,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- TLS handshake wallclock deadline (seconds). 0 disables.
    ratelimit_handshake_timeout = { 10,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- Per-IP bad-auth attempts. Per-account counter still applies on
    -- top of this (max_bad_password / bad_pass_timeout).
    ratelimit_perip_authfail_rate = { 10,
        function( value )
            return types_number( value, nil, true )
        end
    },
    ratelimit_perip_authfail_burst = { 5,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- When an IP exceeds the per-IP authfail rate above, block all
    -- further accepts from it for this many seconds (independent of
    -- the per-account bad_pass_timeout).
    ratelimit_authfail_lockout = { 300,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- Per-user chat (BMSG / EMSG / DMSG) rate.
    ratelimit_user_msg_rate = { 5,
        function( value )
            return types_number( value, nil, true )
        end
    },
    ratelimit_user_msg_burst = { 10,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- Per-user search (BSCH / FSCH / DSCH) cooldown. The bucket fills
    -- at one token every ratelimit_user_search_period seconds.
    ratelimit_user_search_period = { 2,
        function( value )
            return types_number( value, nil, true )
        end
    },
    ratelimit_user_search_burst = { 3,
        function( value )
            return types_number( value, nil, true )
        end
    },

    --// PING //--

    use_ping = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },


}

return {
    settings  = defaults,
    bind_late = bind_late,
}
