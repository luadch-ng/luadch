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

-- Strict-positive number validator. Used by ratelimit cfg keys where a
-- value of 0 or negative would silently put the hub into a degraded
-- mode that's hard to diagnose - msg_rate=0 leaves users connected but
-- unable to chat after the burst is exhausted, msg_burst=-1 mutes
-- every non-op user, NaN poisons the token-bucket math for that
-- bucket. Rejecting at cfg-load time means cfg.lua's checkcfg() logs
-- a clear error and falls back to the default, instead of operators
-- discovering the problem from confused users.
local function ratelimit_pos_number( value )
    return types_number( value, nil, true ) and value > 0
end

-- Tier-table inner field whitelist. Operator typos like `msg_brust = 5`
-- used to pass the type-check and then silently get ignored (scalar
-- fallback) - operators only noticed when their tier didn't behave.
-- A whitelist makes the typo a cfg-load error, surfaced via out_error
-- + default-fallback in cfg.lua:checkcfg(). Keep this list in sync
-- with the field names consumed by core/ratelimit.lua's user_X
-- functions and the _tier_or_scalar helper.
local _RATELIMIT_TIER_FIELDS = {
    msg_rate = true, msg_burst = true,
    pm_rate = true, pm_burst = true,
    inf_rate = true, inf_burst = true,
    ctm_rate = true, ctm_burst = true,
    search_period = true, search_burst = true,
}

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

    hub_name = { "Luadch-NG Hub",
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
    -- #77 TLS-only by default: tcp_ports / tcp_ports_ipv6 default to
    -- empty arrays (no plain ADC listener). ssl_ports / ssl_ports_ipv6
    -- keep their port numbers; cert is auto-generated on first boot
    -- by core/cert_bootstrap.lua. Operators who want plain ADC
    -- alongside opt in via cfg/cfg.tbl with explicit port lists.
    tcp_ports = { { },
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
    tcp_ports_ipv6 = { { },
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
    ssl_ports_ipv6 = { { 5001 },
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
    -- #214 HBRI (Hub-Bridged Reverse Initiation). Opt-in. When a
    -- dual-stack client logs in, the hub can only authenticate the IP
    -- family matching the TCP source; the secondary family is stripped
    -- before broadcast (DDoS-amplification safety). With HBRI enabled
    -- the hub asks such a client to validate its secondary address over
    -- a second-family side-channel connection and, on success, restores
    -- the verified secondary to the broadcast INF. Effective ONLY when
    -- the hub has a plain listener on BOTH families AND both public
    -- advertise addresses below are set (otherwise the hub does not
    -- advertise ADHBRI / never initiates - the secondary just stays
    -- stripped).
    hbri_enabled = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    -- Seconds the hub waits for the side-channel validation before
    -- giving up and letting the client into the hub without the
    -- secondary (adchpp default is 5).
    hbri_timeout = { 5,
        function( value )
            return types_number( value, nil, true )
                and value >= 1 and value <= 60 and value % 1 == 0
        end
    },
    -- The hub's PUBLIC IPv4 / IPv6 address that an HBRI client connects
    -- to for the side-channel. Required when hbri_enabled (the hub
    -- cannot reliably auto-detect its routable address behind NAT /
    -- a "::" bind). Empty = do not advertise / initiate HBRI.
    hbri_advertise_v4 = { "",
        function( value )
            if not types_utf8( value, nil, true ) then return false end
            -- Reject whitespace / control bytes: this value is
            -- concatenated raw into the ITCP frame sent to clients, so a
            -- space or newline would inject extra params / frames.
            return value == "" or not value:find( "[%s%c]" )
        end
    },
    hbri_advertise_v6 = { "",
        function( value )
            if not types_utf8( value, nil, true ) then return false end
            return value == "" or not value:find( "[%s%c]" )
        end
    },
    use_ssl = { true,
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
    -- Phase 8 S3 (#82): local read-only HTTP API port. `false` (the
    -- default) = no HTTP listener bound at all. A number = bind the
    -- hardened HTTP framer on http_bind_addr:<n> (default 127.0.0.1;
    -- #82 assumes a reverse proxy for any non-loopback exposure). S3
    -- serves only /health; auth + data endpoints land in a separate
    -- #82 follow-up PR.
    http_port = { false,
        function( value )
            if value == false then
                return true
            end
            -- integer in the valid TCP port range only: types_number
            -- has no range/integer check, so 0 (OS-assigned ephemeral
            -- on all interfaces) and floats would otherwise slip
            -- through.
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 1 and value <= 65535
        end
    },
    -- HTTP API bind address. Default "127.0.0.1" keeps the listener
    -- on loopback - the security premise for shipping the API without
    -- TLS/auth at the transport layer. Set to "0.0.0.0" (or "::") ONLY
    -- in container setups where the API is reachable to sibling
    -- containers via a private Docker network and the port is NOT
    -- published to the host. Never bind to a public interface
    -- directly - put a reverse proxy in front and bind to the address
    -- the proxy lives on (typically still loopback, or a Docker-
    -- network address). See docs/HTTP_API.md §2.
    -- Init-time only: the listener binds once during boot. Changing
    -- this value via cfg.tbl + `+reload` does NOT re-bind the
    -- listener; a full hub restart is required (mirrors the
    -- `http_port` behaviour). Validator rejects whitespace + control
    -- bytes (mirrors hbri_advertise_v4 / v6) to prevent injection
    -- into the addserver call.
    http_bind_addr = { "127.0.0.1",
        function( value )
            return types_utf8( value, nil, true )
                and #value > 0
                and not value:find( "[%s%c]" )
        end
    },
    -- Phase 1b of #82 HTTP API: token table for bearer-auth, map-
    -- form so the cfg key IS the token and the value carries the
    -- scope ("read" | "admin") + free-form comment surfaced in
    -- api_audit.log. Default {} (no tokens) keeps the HTTP listener
    -- DOWN even when http_port is set; the first-boot path writes a
    -- sample token to cfg/api_token.first chmod 600 for the operator
    -- to copy into this table - until that copy happens, the
    -- listener does NOT bind (#231). See docs/HTTP_API.md §4 for
    -- the auth model and §4.7 for the activation flow.
    http_api_tokens = { { },
        function( value )
            if not types_table( value ) then return false end
            for token, spec in pairs( value ) do
                if type( token ) ~= "string" or #token == 0 then
                    return false
                end
                if type( spec ) ~= "table" then return false end
                if spec.scope ~= "read" and spec.scope ~= "admin" then
                    return false
                end
                if spec.comment ~= nil and type( spec.comment ) ~= "string" then
                    return false
                end
            end
            return true
        end
    },
    -- Phase 1b of #82: log every GET request to api_audit.log too
    -- (off by default - WebUI polling would otherwise spam the
    -- log). Operators enable for forensic sessions.
    http_api_log_reads = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    -- Phase 1c of #82 HTTP API rate-limit (docs/HTTP_API.md §6.3).
    -- Read default is doubled (120/min) because WebUI polling shares
    -- the read scope; admin (60/min) is the operator/CI surface.
    -- Burst is shared across scopes - a quiet WebUI does not block
    -- a sudden admin batch. Values are requests per MINUTE; the
    -- ratelimit module converts to per-second internally.
    -- X-Confirm endpoints are exempt regardless of this setting
    -- (operator recovery must succeed under load).
    http_api_rate_read = { 120,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    http_api_rate_admin = { 60,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    http_api_burst = { 10,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    -- Per-prefix failed-auth bucket (docs/HTTP_API.md §4.8). Keyed
    -- on the first 4 chars of the Bearer token; defaults rate 10/min
    -- burst 5 cap walk-the-token-space attacks without affecting
    -- legitimate WebUI restarts (token unchanged -> bucket unrelated).
    http_api_authfail_prefix_rate = { 10,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    http_api_authfail_prefix_burst = { 5,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    -- Idempotency-key cache cap (docs/HTTP_API.md §6.2). Cache is
    -- always bounded by both the 5-min TTL AND this entry count;
    -- FIFO eviction on cap hit. Default 1024 fits comfortably even
    -- on a hub with thousands of admin actions per hour.
    http_api_idempotency_max_entries = { 1024,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 1
                and value <= 1048576
        end
    },
    -- #263: ringbuffer cap for the GET /v1/events event stream.
    -- Each entry is ~200 bytes (JSON-encoded); 1000 -> ~200 KB.
    -- Events older than the cap are evicted; clients whose `since`
    -- cursor falls below the buffer's minimum id get `cursor_lost:
    -- true` in the response and must catch up via the per-resource
    -- GET endpoints. PR-B will add the long-poll wait/yield path.
    http_events_buffer_size = { 1000,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 16
                and value <= 100000
        end
    },
    -- #84: audit-log per-field caps applied by core/audit.lua at
    -- event build time. Caps reason strings and per-meta string
    -- values to prevent a malicious actor from blowing up a log
    -- line. The cap applies BEFORE the writer plugin serializes
    -- so the on-disk JSONL also stays bounded. Apply to both core
    -- audit events AND the corresponding /v1/events ringbuffer
    -- entries (sanitised once at build time, propagated as-is).
    audit_log_max_reason_chars = { 1000,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 32
                and value <= 100000
        end
    },
    audit_log_max_meta_value_chars = { 1000,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 32
                and value <= 100000
        end
    },
    -- Phase 8 S4b: ADC-EXT ZLIF (zlib stream compression). Off by
    -- default - operator opt-in, matches the S3 http_port pattern.
    -- When enabled and the client also advertises ADZLIF in HSUP, the
    -- hub initiates compression (sends IZON, installs an outbound
    -- deflate stage) and decompresses inbound after the client's own
    -- ZON. Spec is per-direction; the hub advertises only when
    -- enabled. See docs/SECURITY.md for the CRIME-class chosen-
    -- plaintext-length leak discussion that gates ZLIF over TLS
    -- behind the separate zlif_over_tls flag below.
    zlif_enabled = { false,
        function( value )
            return value == false or value == true
        end
    },
    -- TLS+ZLIF is theoretically vulnerable to CRIME-class length-leak
    -- attacks (chosen-plaintext PM mixed with victim's other traffic
    -- on the same TLS-then-compressed wire). Practical exploitability
    -- is low (eavesdropper needed, broadcast noise masks length
    -- deltas) but the mitigation cost is one cfg flag. Plain-ADC
    -- connections see ZLIF when `zlif_enabled` is true regardless of
    -- this flag.
    zlif_over_tls = { false,
        function( value )
            return value == false or value == true
        end
    },
    -- Phase 8 S5: ADC-EXT BLOM hash-search routing. Off by default
    -- (operator opt-in). When enabled, the hub advertises ADBLOM in
    -- SUP, requests a per-user bloom filter via HGET on entry to
    -- NORMAL state, and routes HASH-search SCH (those carrying a TR
    -- field) only to clients whose filter has all k bits set for
    -- the TTH. KEYWORD-search SCH (AN/NO/EX/TY/etc.) is broadcast
    -- to all clients unchanged regardless of `blom_enabled`; the
    -- filter cannot distinguish keyword matches by design.
    blom_enabled = { false,
        function( value )
            return value == false or value == true
        end
    },
    -- BLOM parameters. Spec restrictions (validated below):
    --   k >= 1
    --   h % 8 == 0       (byte-aligned hash slice per ADC-EXT 3.20)
    --   k * h <= 192     (TTH is 192 bits, the slice source)
    --   m % 64 == 0      (filter byte-aligned to 8-byte words)
    --   2^h > m          (slice must span the filter index space)
    --
    -- Defaults (k=6, h=16, m=32768) give a 4 KiB filter per user
    -- and ~39% false-positive rate at a 10k-file share. Operators
    -- with larger shares should raise `blom_m` (and possibly
    -- `blom_h`); raising `blom_k` past 6 buys little extra
    -- accuracy at typical hub-share sizes.
    blom_k = { 6,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 1 and value <= 24
        end
    },
    blom_h = { 16,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 8 and value <= 64
                and value % 8 == 0
        end
    },
    blom_m = { 32768,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 64
                and value % 64 == 0
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

    --[[
        Encrypt cfg/user.tbl at rest (Phase 7f F-AUTH-1).

        Default: true. New deployments and existing v3.1.x deployments
        keep AES-256-GCM at-rest encryption with the master key at
        master_key_path. user.tbl on disk starts with the four-byte
        magic "LDC1" followed by a per-write nonce + ciphertext + GCM
        auth tag.

        Set to false (#128) to write user.tbl as plaintext Lua source
        instead. Use cases for the operator opting out:
            - Single-user home hub on a private host where the disk-
              level threat model is "if my disk leaves my house I have
              bigger problems".
            - Operator tooling that reads user.tbl directly (custom
              backup scripts, third-party admin UIs, ad-hoc inspection
              with a text editor) and cannot be retrofitted with the
              decrypt path.
            - Recovery-without-master.key as a hard requirement.

        What you give up:
            - Backup confidentiality. A routine `tar czf cfg.tar.gz cfg/`
              exfiltrates plaintext user passwords (ADC mandates the
              hub holds password-equivalents in RAM and on disk, so
              "passwords" in user.tbl are the actual values clients
              type at login).
            - Stolen-disk protection. An attacker who walks off with
              the host's disk reads user.tbl directly.
            - The forced-confidentiality default that makes a casual
                tar/scp/cloud-sync transfer non-leaky.

        What you keep regardless:
            - chmod 600 on user.tbl on POSIX (still set by saveusers).
            - The .bak atomic-refresh + auto-recovery flow.
            - Sandboxed loadtable on the plain-Lua-source path.

        Migration is automatic in both directions:
            - true -> false: the next save writes user.tbl as plain
              Lua source. Until then, the encrypted file on disk still
              decrypts via the existing master.key.
            - false -> true: the next save writes an LDC1 blob using
              master.key (auto-generated if missing).
            - Existing user.tbl files in either format auto-detect on
              load via the LDC1 magic prefix.

        See docs/SECURITY.md §3 for the threat-model trade-off.
    ]]--
    encrypt_usertbl = { true,
        function( value )
            return types_boolean( value, nil, true )
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
    -- Phase 1b of #82 HTTP API: audit log of API writes (and reads
    -- if http_api_log_reads is also true). Default true because the
    -- write surface is admin-scoped and operators want forensics by
    -- default; disable via cfg if a deployment has a different
    -- audit sink upstream of the hub.
    log_api_audit = { true,
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

    etc_usercommands_toplevelmenu = { "Luadch-NG Commands",
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

    -- Op-chat report when a nick-prefix conflict causes the kick. The
    -- onConnect listener can NOT fire onFailedAuth (the prefix kick
    -- happens inside the same listener chain, causing recursion) so
    -- the plugin sends a direct report.send instead. Same defaults
    -- as sibling reporting plugins.
    usr_nick_prefix_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    usr_nick_prefix_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    usr_nick_prefix_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    usr_nick_prefix_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
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

    -- max/min_*_hubs cap how many OTHER hubs a user may be connected
    -- to while present here, broken down by their role at THIS hub.
    -- The values are policy advertisements: the PING extension reports
    -- them as `XU / XR / XO` (max) and `MU / MR / MO` (min) so hublist
    -- scrapers and ping bots can show "this hub requires you to be in
    -- 1-20 other hubs as a registered user" before a client connects.
    -- Enforcement at login / on INF update happens in usr_hubs.lua.
    --
    --   user = unregistered visitor       -> max_user_hubs / min_user_hubs
    --   reg  = registered user (any role) -> max_reg_hubs  / min_reg_hubs
    --   op   = operator-level user        -> max_op_hubs   / min_op_hubs
    --
    -- Typical settings:
    --   * public hubs: max = 20 (block multi-hub crawlers), min = 0
    --     (no federation requirement) - the bundled defaults below.
    --   * federation / "anti-leech" hubs: min_reg_hubs = 1+ so regs
    --     must be present in other hubs too.
    --   * private hubs: leave at defaults.
    --
    -- Operator-side sanity: keep `min_*_hubs <= max_*_hubs` for each
    -- role. The validators here are per-key (no cross-key check), so
    -- a contradiction like `min_user_hubs = 50, max_user_hubs = 20`
    -- loads without error but advertises nonsensical MU > XU in the
    -- PING reply. usr_hubs.lua enforcement runs on both fields
    -- independently so a user satisfying the max but not the min
    -- still gets disconnected. Cross-validation is a future
    -- candidate if the foot-gun ever bites in practice.
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

    min_user_hubs = { 0,
        function( value )
            return types_number( value, nil, true )
        end
    },

    min_reg_hubs = { 0,
        function( value )
            return types_number( value, nil, true )
        end
    },

    min_op_hubs = { 0,
        function( value )
            return types_number( value, nil, true )
        end
    },

    -- ADC-EXT RDEX (3.32) - rich redirect.
    --
    -- hub_redirect_protocols: bitmask of redirect URI schemes this hub
    -- advertises support for. Emitted as IINF.RP so clients (and other
    -- hubs redirecting users here) know which URL scheme to use.
    --   1 = ADC, 2 = ADCS, 4 = NEODC (legacy), sum for combinations.
    --   Default 3 = ADC + ADCS (what luadch itself speaks).
    -- hub_redirect_alternatives: list of alternative redirect URLs
    -- attached as IQUI.RX on every kick/redirect (cmd_redirect etc).
    -- Clients use these as fallback targets if the primary RD URL is
    -- unreachable. Default empty (RX field omitted).
    -- hub_redirect_permanent: if true, IQUI carries PT1 so the client
    -- treats the redirect as permanent (e.g. updates its bookmark).
    -- Default false.
    hub_redirect_protocols = { 3,
        function( value )
            return types_number( value, nil, true ) and value >= 0 and value <= 7
        end
    },
    hub_redirect_alternatives = { { },
        function( value )
            if not types_table( value ) then return false end
            for _, v in pairs( value ) do
                if type( v ) ~= "string" then return false end
            end
            return true
        end
    },
    hub_redirect_permanent = { false,
        function( value )
            return types_boolean( value, nil, true )
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
    --// etc_aliases.lua settings (#327)

    etc_aliases_minlevel = { 80,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_aliases_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_aliases_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_aliases_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_aliases_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_auditlog.lua settings (#84)

    -- Master kill-switch. When false the plugin loads but writes
    -- nothing to disk and the HTTP read endpoint returns an empty
    -- list. The /v1/events audit stream remains populated either
    -- way (driven by core/http_events.lua's tap, not this plugin)
    -- - operators who want to disable the live stream entirely
    -- should drop the plugin from cfg.scripts instead.
    etc_auditlog_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    -- Directory for the JSONL files. Created on first write if
    -- missing. The plugin chmods every file 0600 (POSIX) since
    -- audit content is sensitive (target nicks / IPs / CIDs).
    etc_auditlog_dir = { "log/",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    -- File-name prefix. Final form: <dir><prefix><YYYY-MM-DD>.jsonl
    -- Default produces log/audit-2026-06-23.jsonl.
    etc_auditlog_prefix = { "audit-",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    -- Days to retain. On rollover (first write past UTC midnight)
    -- the plugin unlinks any matching file whose date is older
    -- than this many days. Set 0 to disable retention sweep
    -- (operator owns the cleanup manually).
    etc_auditlog_retention_days = { 90,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 0
                and value <= 36500
        end
    },

    -- GET /v1/log/audit?lines=N defaults + cap (same envelope as
    -- /v1/log/cmd and /v1/errors per HTTP_API.md §6.4).
    etc_auditlog_http_lines_default = { 200,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 1
                and value <= 1000
        end
    },

    etc_auditlog_http_lines_max = { 1000,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 1
                and value <= 10000
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_clientblocker.lua settings (#81)

    -- Operator level that can run `+blocker add / del` (read is open
    -- to anyone authorised on the ADC cmd, gated by etc_hubcommands).
    -- Mirrors the etc_blacklist convention (oplevel = the write floor).
    etc_clientblocker_oplevel = { 80,
        function( value )
            return types_number( value, nil, true )
        end
    },

    -- Which user levels the client check applies to. Operators (60+)
    -- are exempt by default so an operator who adds a pattern that
    -- inadvertently matches their own client does not self-lockout.
    -- HUBOWNER (100) is kept in scope so the maintainer is not given
    -- a quiet bypass - a hub-owner who really wants to test from a
    -- blocked client can flip [100] to false at runtime.
    etc_clientblocker_check_levels = { {
        [ 0 ]   = true,
        [ 10 ]  = true,
        [ 20 ]  = true,
        [ 30 ]  = true,
        [ 40 ]  = true,
        [ 50 ]  = true,
        [ 60 ]  = false,
        [ 70 ]  = false,
        [ 80 ]  = false,
        [ 100 ] = true,
    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for level, allowed in pairs( value ) do
                    if not ( types_number( level, nil, true )
                             and types_boolean( allowed, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    -- Fallback reason emitted when an operator adds a pattern via
    -- `+blocker add <pattern>` without a custom reason argument.
    -- Per-pattern overrides live in scripts/data/etc_clientblocker.tbl.
    etc_clientblocker_default_reason = { "Your client is not allowed",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    -- Hard cap on operator-supplied pattern length. Lua patterns do
    -- not backtrack the way PCRE does, but `.- ` chains + nested
    -- captures can still produce expensive `string.find` runs on
    -- every onConnect. 200 chars is comfortably larger than any
    -- legitimate AP/VE rule (the v0.2 upstream patterns are <40).
    etc_clientblocker_max_pattern_len = { 200,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 1
                and value <= 4096
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_trafficmanager.lua settings

    etc_trafficmanager_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    -- etc_regserver_announce: opt-in hublist registration (default OFF
    -- = private hub). See scripts/etc_regserver_announce.lua.
    etc_regserver_announce_activate = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    -- string (one regserver) OR array of strings (announce to several)
    etc_regserver_announce_url = { "https://your.regserver.org/register",
        function( value )
            if types_utf8( value, nil, true ) then return true end
            if type( value ) == "table" then
                for _, v in ipairs( value ) do
                    if not types_utf8( v, nil, true ) then return false end
                end
                return true
            end
            return false
        end
    },
    etc_regserver_announce_tls_verify = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_regserver_announce_cafile = { "",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    etc_regserver_announce_retry_interval = { 300,
        function( value )
            return types_number( value, nil, true ) and value > 0
        end
    },
    etc_regserver_announce_max_attempts = { 12,
        function( value )
            return types_number( value, nil, true ) and value >= 0
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
        "etc_aliases.lua",
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
        -- #261: each entry is EITHER a plain string `"name.lua"`
        -- (operator-managed, API-protected) OR a table
        -- `{ "name.lua", enabled = bool }` (API-toggleable). String
        -- entries are equivalent to `{ name, enabled = true }` for
        -- load-time semantics; the form distinguishes operator
        -- intent for the management API.
        function( value )
            if not types_table( value ) then
                return false
            end
            for i, entry in ipairs( value ) do
                if type( entry ) == "string" then
                    if not types_utf8( entry, nil, true ) then
                        return false
                    end
                elseif type( entry ) == "table" then
                    local name = entry[ 1 ]
                    if type( name ) ~= "string" or not types_utf8( name, nil, true ) then
                        return false
                    end
                    if entry.enabled ~= nil and type( entry.enabled ) ~= "boolean" then
                        return false
                    end
                else
                    return false
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
        -- TLS-1.3-only by design: protocol = "tlsv1_3" pins the
        -- SSL_CTX min == max == TLS1_3_VERSION (verified in luasec
        -- src/context.c), so nothing can negotiate down to <= 1.2.
        -- "no_renegotiation" is defense-in-depth for the case an
        -- operator manually downgrades protocol to "tlsv1_2"
        -- (unsupported - see examples/cfg/cfg.tbl); TLS 1.3 has no
        -- renegotiation anyway (RFC 8446). Requires OpenSSL >= 1.1.0h
        -- (project bundles 3.x; luasec raises "invalid option" on a
        -- flag the linked OpenSSL does not define).
        options = { "no_sslv2", "no_sslv3", "no_tlsv1", "no_tlsv1_1", "no_renegotiation" },  -- do not touch this
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
    -- #97 (default true since v3.1.4), flipped back to false in
    -- v3.2.x: with the #214 Gap 2 fix in place, kill_wrong_ips=false
    -- no longer broadcasts a client-claimed (potentially spoofed) IP
    -- - the hub overrides the claim with the authenticated TCP source
    -- in core/hub_dispatch.lua before any broadcast, so the
    -- DDoS-amplification vector that motivated the strict default
    -- is closed by construction regardless of this toggle.
    --
    -- The practical effect of the strict default was kicking users
    -- with legitimate IP mismatches (VPN clients with stale cached
    -- IPs, CGNAT users with manual WAN-IP misconfiguration, dual-
    -- stack users where the kernel picked a different outbound family
    -- than the user's configured advertise). Per-IP rate limits, GeoIP
    -- rules, abuse logs, and the unified blocklist all operate on the
    -- TCP source IP anyway, so the gate is purely defence-in-depth -
    -- and post-Gap-2 there is nothing left to depend on.
    --
    -- Operators who prefer the loud "tell the user to fix their client"
    -- kick over the silent IP-override can opt in via cfg.tbl:
    --     kill_wrong_ips = true
    -- The improved kick message (PR #331) includes a config hint
    -- pointing the user at their client's 'External / WAN IP' setting.
    kill_wrong_ips = { false,
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
            return ratelimit_pos_number( value )
        end
    },
    ratelimit_perip_conn_burst = { 30,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    -- TLS handshake wallclock deadline (seconds). 0 disables.
    ratelimit_handshake_timeout = { 10,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- #207: cadence of the dedicated "kill stuck TLS handshakes"
    -- sweep. Decoupled from the broader _checkinterval (120s) so a
    -- handshake whose `ratelimit_handshake_timeout` expired gets
    -- reaped within roughly `sweep_interval` seconds rather than
    -- waiting for the next 120s sweep. Worst-case stuck-handshake
    -- lifetime = handshake_timeout + sweep_interval (default
    -- 10 + 10 = ~20s). Setting to 0 effectively disables the fast
    -- sweep and falls back to the broader 120s cadence.
    ratelimit_handshake_sweep_interval = { 10,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- Per-IP bad-auth attempts. Per-account counter still applies on
    -- top of this (max_bad_password / bad_pass_timeout).
    ratelimit_perip_authfail_rate = { 10,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    ratelimit_perip_authfail_burst = { 5,
        function( value )
            return ratelimit_pos_number( value )
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
    -- Per-user mainchat (BMSG) rate.
    ratelimit_user_msg_rate = { 5,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    ratelimit_user_msg_burst = { 10,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    -- Per-user PM (DMSG / EMSG) rate. Split out of the mainchat bucket
    -- in #80 so DMs and broadcasts can be tuned independently. Defaults
    -- match user_msg for behaviour-equivalence with v3.1.7.
    ratelimit_user_pm_rate = { 5,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    ratelimit_user_pm_burst = { 10,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    -- Per-user BINF-update rate (#80, post-login only). Defaults are
    -- deliberately lenient: watch-folders emit a BINF on every share-
    -- size change, and starting N parallel downloads emits N quick
    -- slot-count updates. burst=20 absorbs that without flagging
    -- legitimate users; rate=2/s lets steady-state churn through and
    -- caps any flood at ~120/min after the burst is exhausted.
    ratelimit_user_inf_rate = { 2,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    ratelimit_user_inf_burst = { 20,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    -- Per-user connection-setup rate (#80). Shared bucket for DCTM and
    -- DRCM since they are alternatives for the same primitive (peer
    -- connection initiation, choice depends on NAT routing). burst=30
    -- tolerates the explicit use case from the issue: a user firing
    -- many CTMs when their search results resolve to lots of peers,
    -- or kicking off a deep download queue. rate=2/s caps a malicious
    -- crawler at ~120 attempts per minute after the burst.
    ratelimit_user_ctm_rate = { 2,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    ratelimit_user_ctm_burst = { 30,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    -- Per-user search (BSCH / FSCH / DSCH) cooldown. The bucket fills
    -- at one token every ratelimit_user_search_period seconds.
    ratelimit_user_search_period = { 2,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    ratelimit_user_search_burst = { 3,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    -- #80 PR 4/4: per-userlevel tier overlay. Optional. Default empty
    -- tables = behaviour identical to the global scalars above. To use:
    -- 1) define one or more named tiers in `ratelimit_tiers`, each with
    --    any subset of the per-bucket fields (msg_rate / msg_burst /
    --    pm_rate / pm_burst / inf_rate / inf_burst / ctm_rate /
    --    ctm_burst / search_period / search_burst); missing fields fall
    --    back to the corresponding global scalar.
    -- 2) map user levels to tier names in `ratelimit_tier_for_level`;
    --    levels not listed in the map use the global scalars.
    -- Op-level users (>= ratelimit_bypass_level) bypass both tiers and
    -- scalars, same as before.
    -- Example:
    --   ratelimit_tiers = {
    --     strict   = { msg_rate = 2, msg_burst = 5, pm_rate = 2, pm_burst = 5 },
    --     generous = { msg_rate = 10, msg_burst = 20, ctm_burst = 60 },
    --   },
    --   ratelimit_tier_for_level = { [0] = "strict", [10] = "strict",
    --     [55] = "generous" },
    ratelimit_tiers = { { },
        function( value )
            if not types_table( value ) then return false end
            for tier_name, tier in pairs( value ) do
                if type( tier_name ) ~= "string" then return false end
                if not types_table( tier ) then return false end
                for k, v in pairs( tier ) do
                    if type( k ) ~= "string" then return false end
                    -- Typo guard: only the 10 known field names from
                    -- _RATELIMIT_TIER_FIELDS get through. msg_brust=5
                    -- (typo) raises here instead of silently falling
                    -- back to the global scalar.
                    if not _RATELIMIT_TIER_FIELDS[ k ] then return false end
                    -- Inner values feed the token bucket directly; same
                    -- strict-positive guard as the global scalar keys
                    -- above. msg_rate=0 / msg_burst=-1 in a tier would
                    -- silent-mute every user mapped to it.
                    if not ratelimit_pos_number( v ) then return false end
                end
            end
            return true
        end
    },
    ratelimit_tier_for_level = { { },
        function( value )
            if not types_table( value ) then return false end
            for level, tier_name in pairs( value ) do
                if not types_number( level, nil, true ) then return false end
                if type( tier_name ) ~= "string" then return false end
            end
            return true
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
