--[[

    core/backup_archive.lua - encrypted backup archive format (LDBK1).

    Format-level core primitive for the automatic-backup arc (#480). Pure
    in-memory: the caller reads the files off disk and hands their bytes
    in; this module bundles them into a single POSIX ustar tar, derives an
    AES-256 key from an operator passphrase via PBKDF2-HMAC-SHA256, and
    seals the tar with AES-256-GCM (adclib / OpenSSL). unpack() reverses
    it. Disk I/O, file collection, rotation and scheduling live one layer
    up in core/backup.lua (PR-A); the offline restore path (PR-B) reuses
    unpack() so the read and write halves can never drift.

    Why a real ustar tar and not a bespoke container: the decrypted inner
    blob is a standard `.tar` an operator can `tar xf` for manual disaster
    recovery, independent of the hub. Uncompressed for now (zlib_stream
    has no gzip writer); the backup set excludes the large/log data so the
    artifact stays small.

    Why the backup passphrase is independent of cfg/master.key: a backup
    exists precisely for the case where master.key is lost with the host,
    so the archive cannot be keyed on it. The passphrase is stretched with
    PBKDF2 (salt + iteration count stored in the header) so an operator can
    keep a memorable secret in a password manager.

    LDBK1 wire format:
        offset  bytes            field
          0     4                magic "LDBK"
          4     1                format version (1)
          5     1                KDF id (1 = PBKDF2-HMAC-SHA256)
          6     4                PBKDF2 iterations (big-endian uint32)
         10     1                salt length S
         11     S                salt (16 bytes)
         11+S   12               AES-GCM nonce (96-bit)
         23+S   N                ciphertext || 16-byte GCM tag
    The outer header (salt / iters / nonce) is not GCM-authenticated
    directly - adclib exposes no AAD parameter - but tampering any of it
    yields a wrong key or wrong nonce, so open() fails closed either way.
    The authoritative metadata (per-file dest, mode, kind) rides inside the
    tar, which IS inside the authenticated ciphertext.

    Public surface:
        pack(files, meta, passphrase [, opts])  -> ldbk_bytes | nil, err
        unpack(ldbk_bytes, passphrase)          -> { meta, files } | nil, err
        checksum(bytes)                         -> 64-char lowercase hex
        sidecar_line(hex, filename)             -> "<hex>  <name>\n"
        MAGIC / VERSION / DEFAULT_ITERS constants
      files (pack input) / result.files: array of
        { name = string, mode = int (octal perms), body = string, kind = string? }

    A PBKDF2 known-answer + ustar round-trip self-test runs at load (same
    fail-loud discipline as sha256.lua / hmac.lua): a silent KDF regression
    would derive wrong keys = unrecoverable backups.

]]--

----------------------------------// DECLARATION //--

local use = use

local type         = use "type"
local error        = use "error"
local pcall        = use "pcall"
local tostring     = use "tostring"
local tonumber     = use "tonumber"
local load         = use "load"
local pairs        = use "pairs"
local ipairs       = use "ipairs"

local string       = use "string"
local string_sub    = string.sub
local string_byte   = string.byte
local string_char   = string.char
local string_rep    = string.rep
local string_format = string.format
local string_pack   = string.pack
local string_unpack = string.unpack
local string_match  = string.match

local table        = use "table"
local table_concat = table.concat
local table_sort   = table.sort

-- debug.sethook is used ONLY to bound the manifest-eval work (see
-- _manifest_parse); the standard way to cap untrusted Lua execution.
local debug_sethook = ( use "debug" ).sethook

--// extern libs //--

local adclib = use "adclib"
local adclib_random_bytes = adclib.random_bytes
local adclib_aes_gcm_seal = adclib.aes_gcm_seal
local adclib_aes_gcm_open = adclib.aes_gcm_open
-- OpenSSL PBKDF2 (fast). nil on a standalone lua / stubbed adclib, where
-- _derive_key falls back to the pure-Lua PBKDF2 below.
local adclib_pbkdf2 = adclib.pbkdf2_sha256

--// core scripts //--

local hmac = use "hmac"
local hmac_bytes = hmac.sha256_bytes

local sha256 = use "sha256"
local sha256_hash = sha256.hash

----------------------------------// CONSTANTS //--

local MAGIC              = "LDBK"
local VERSION            = 1
local KDF_PBKDF2_SHA256  = 1

local KEY_SIZE           = 32       -- AES-256
local NONCE_SIZE         = 12       -- GCM 96-bit nonce
local TAG_SIZE           = 16       -- GCM 128-bit tag
local SALT_SIZE          = 16
local DEFAULT_ITERS      = 200000
local MAX_ITERS          = 10000000   -- KDF work ceiling: guards unpack()
                                      -- against a crafted header demanding
                                      -- billions of pre-auth HMAC rounds.

local TAR_BLOCK          = 512
local MAX_TAR_ENTRIES    = 100000   -- parse-side bomb guard
local MAX_NAME           = 100      -- ustar name field (no prefix-split yet)

local MANIFEST_NAME      = "MANIFEST"
local MANIFEST_MAX_BYTES = 65536    -- a real manifest is a handful of scalars
local MANIFEST_MAX_INSTR = 200000   -- eval work ceiling (real parse ~dozens)
local MODE_0644          = 420      -- rw-r--r-- (caller passes per-file modes)

local ZERO_BLOCK         = string_rep( "\0", TAR_BLOCK )

----------------------------------// PBKDF2 //--

-- XOR two 32-byte strings (Lua 5.4 native integer XOR).
local function _xor32( a, b )
    local out = { }
    for i = 1, 32 do
        out[ i ] = string_char( string_byte( a, i ) ~ string_byte( b, i ) )
    end
    return table_concat( out )
end

-- PBKDF2-HMAC-SHA256, RFC 2898. Only dklen <= 32 (one output block) is
-- needed here (a 256-bit AES key), so a single block index (1) suffices:
-- DK = U1 XOR U2 XOR ... XOR Uc, Ui = HMAC(pass, U(i-1)), U1 = HMAC(pass,
-- salt || INT32_BE(1)).
local function _pbkdf2_lua( password, salt, iters, dklen )
    dklen = dklen or KEY_SIZE
    if dklen > 32 then
        error( "backup_archive._pbkdf2_lua: dklen > 32 unsupported", 2 )
    end
    if type( iters ) ~= "number" or iters < 1 then
        error( "backup_archive._pbkdf2_lua: iters must be a number >= 1", 2 )
    end
    local u = hmac_bytes( password, salt .. string_pack( ">I4", 1 ) )
    local t = u
    for _ = 2, iters do
        u = hmac_bytes( password, u )
        t = _xor32( t, u )
    end
    return string_sub( t, 1, dklen )
end

-- Derive the AES key. Prefer OpenSSL's PBKDF2 via adclib: the pure-Lua one
-- is correct but runs ~tens of seconds at the default iteration count, which
-- would freeze the single-threaded hub for the whole backup. Both produce
-- the SAME key (PBKDF2 is deterministic), so artifacts stay interoperable
-- regardless of which path sealed / opens them; the Lua path is the
-- standalone / no-adclib fallback (unit tests, a broken build).
local function _derive_key( password, salt, iters, dklen )
    if type( adclib_pbkdf2 ) == "function" then
        return adclib_pbkdf2( password, salt, iters, dklen or KEY_SIZE )
    end
    return _pbkdf2_lua( password, salt, iters, dklen )
end

----------------------------------// USTAR //--

-- Right-pad (or truncate) a string to exactly `w` bytes with NUL.
local function _pad( s, w )
    if #s >= w then return string_sub( s, 1, w ) end
    return s .. string_rep( "\0", w - #s )
end

-- Octal ASCII numeric field: (w-1) zero-padded octal digits + trailing
-- NUL, exactly `w` bytes. Errors if the value does not fit.
local function _octal( n, w )
    local s = string_format( "%0" .. ( w - 1 ) .. "o", n )
    if #s > w - 1 then
        return nil, "tar: numeric field overflow (" .. n .. ")"
    end
    return s .. "\0"
end

-- Parse an octal numeric field: strip everything but octal digits and
-- read as base 8. Returns nil on a field with no digits.
local function _read_octal( block, start, w )
    local raw = string_sub( block, start, start + w - 1 )
    local digits = string_match( raw, "[0-7]+" )
    if not digits then return nil end
    return tonumber( digits, 8 )
end

-- Read a NUL-terminated (or full-width) string field.
local function _read_str( block, start, w )
    local raw = string_sub( block, start, start + w - 1 )
    return ( string_match( raw, "^[^%z]*" ) )
end

-- Build one 512-byte ustar header for a regular file. Deterministic
-- (uid/gid/mtime = 0, no owner names) so identical inputs produce a
-- byte-identical archive - the round-trip test relies on it.
local function _tar_header( name, mode, size )
    if #name > MAX_NAME then
        return nil, "tar: name too long (" .. #name .. " > " .. MAX_NAME .. "): " .. name
    end
    local mode_f, e1 = _octal( mode & 0x1FF, 8 )
    if not mode_f then return nil, e1 end
    local size_f, e2 = _octal( size, 12 )
    if not size_f then return nil, e2 end
    local zero8  = _octal( 0, 8 )
    local zero12 = _octal( 0, 12 )
    local parts = {
        _pad( name, 100 ),   -- name
        mode_f,              -- mode
        zero8,               -- uid
        zero8,               -- gid
        size_f,              -- size
        zero12,              -- mtime (0 = reproducible)
        "        ",          -- chksum placeholder: 8 spaces
        "0",                 -- typeflag: regular file
        _pad( "", 100 ),     -- linkname
        "ustar\0",           -- magic
        "00",                -- version
        _pad( "", 32 ),      -- uname
        _pad( "", 32 ),      -- gname
        zero8,               -- devmajor
        zero8,               -- devminor
        _pad( "", 155 ),     -- prefix
        _pad( "", 12 ),      -- pad to 512
    }
    local header = table_concat( parts )
    -- Checksum: unsigned sum of all 512 bytes with the chksum field taken
    -- as ASCII spaces (still spaces at this point). Written as 6 octal
    -- digits + NUL + space.
    local sum = 0
    for i = 1, TAR_BLOCK do
        sum = sum + string_byte( header, i )
    end
    local chk = string_format( "%06o", sum ) .. "\0 "
    return string_sub( header, 1, 148 ) .. chk .. string_sub( header, 157 )
end

-- Verify a header's stored checksum (validates our own writer, and any
-- corruption a wrong passphrase would NOT catch - defence in depth on top
-- of the GCM tag).
local function _verify_checksum( block )
    local stored = _read_octal( block, 149, 8 )
    if not stored then return false end
    local sum = 0
    for i = 1, TAR_BLOCK do
        local b = string_byte( block, i )
        if i >= 149 and i <= 156 then b = 32 end   -- chksum field = spaces
        sum = sum + b
    end
    return sum == stored
end

local function _build_tar( entries )
    local parts = { }
    for _, e in ipairs( entries ) do
        local hdr, err = _tar_header( e.name, e.mode or MODE_0644, #e.body )
        if not hdr then return nil, err end
        parts[ #parts + 1 ] = hdr
        parts[ #parts + 1 ] = e.body
        local rem = ( -#e.body ) % TAR_BLOCK
        if rem > 0 then parts[ #parts + 1 ] = string_rep( "\0", rem ) end
    end
    parts[ #parts + 1 ] = ZERO_BLOCK
    parts[ #parts + 1 ] = ZERO_BLOCK    -- two zero blocks terminate the archive
    return table_concat( parts )
end

-- Parse a ustar stream into { {name, mode, size, body}, ... }. Defensive
-- per DEVELOPMENT.md S5: bound every read, cap the entry count, degrade to
-- (nil, err) rather than erroring. (The stream is GCM-authenticated by the
-- time we get here, but corrupt-degradation stays cheap and correct.)
local function _parse_tar( bytes )
    local entries = { }
    local off, n = 1, #bytes
    local terminated = false
    while off + TAR_BLOCK - 1 <= n do
        local block = string_sub( bytes, off, off + TAR_BLOCK - 1 )
        if block == ZERO_BLOCK then terminated = true; break end
        if not _verify_checksum( block ) then
            return nil, "tar: header checksum mismatch"
        end
        local name = _read_str( block, 1, 100 )
        local mode = _read_octal( block, 101, 8 ) or MODE_0644
        local size = _read_octal( block, 125, 12 )
        if not size then return nil, "tar: bad size field" end
        off = off + TAR_BLOCK
        if off + size - 1 > n then return nil, "tar: truncated file content" end
        local body = string_sub( bytes, off, off + size - 1 )
        off = off + size + ( ( -size ) % TAR_BLOCK )
        entries[ #entries + 1 ] = { name = name, mode = mode, size = size, body = body }
        if #entries > MAX_TAR_ENTRIES then
            return nil, "tar: too many entries"
        end
    end
    -- A well-formed archive ends on the zero terminator block. Reaching the
    -- end of input without one means the stream is truncated or not a tar.
    if not terminated then
        return nil, "tar: unterminated / truncated stream"
    end
    return entries
end

----------------------------------// MANIFEST //--

-- Serialise the flat metadata table (scalars + a string->string `kinds`
-- map) to a deterministic `return { ... }` Lua chunk. %q keeps arbitrary
-- paths / versions safe to load back.
local function _manifest_serialize( meta )
    local keys = { }
    for k in pairs( meta ) do keys[ #keys + 1 ] = k end
    table_sort( keys )
    local lines = { "return {" }
    for _, k in ipairs( keys ) do
        local v = meta[ k ]
        if k == "kinds" and type( v ) == "table" then
            local kk = { }
            for name in pairs( v ) do kk[ #kk + 1 ] = name end
            table_sort( kk )
            lines[ #lines + 1 ] = "  kinds = {"
            for _, name in ipairs( kk ) do
                lines[ #lines + 1 ] = string_format( "    [%q] = %q,", name, tostring( v[ name ] ) )
            end
            lines[ #lines + 1 ] = "  },"
        elseif type( v ) == "string" then
            lines[ #lines + 1 ] = string_format( "  [%q] = %q,", k, v )
        elseif type( v ) == "number" or type( v ) == "boolean" then
            lines[ #lines + 1 ] = string_format( "  [%q] = %s,", k, tostring( v ) )
        end
    end
    lines[ #lines + 1 ] = "}"
    return table_concat( lines, "\n" )
end

-- Parse a manifest chunk in a sandboxed empty environment (text only, no
-- globals) - same protection as util.loadtable_string, PLUS a work bound.
-- The empty _ENV blocks code execution, but a crafted manifest (a foreign
-- archive whose passphrase the operator holds) could still `while true do end`
-- and hang the offline restore. An instruction-count hook aborts any chunk
-- that runs past a budget far above a real table construction; because the
-- env is empty the chunk cannot reach a long-running C call that would slip
-- the hook, so the count bound is sufficient (DEVELOPMENT.md §5: bound the
-- WORK, not just the depth).
local function _manifest_parse( str )
    if type( str ) ~= "string" or #str > MANIFEST_MAX_BYTES then
        return nil, "manifest: missing or too large"
    end
    local fn, err = load( str, "backup_manifest", "t", { } )
    if not fn then return nil, "manifest: " .. tostring( err ) end
    debug_sethook( function( ) error( "manifest: instruction budget exceeded", 0 ) end, "", MANIFEST_MAX_INSTR )
    local ok, tbl = pcall( fn )
    debug_sethook( )   -- always clear the hook, success or not
    if not ok or type( tbl ) ~= "table" then
        return nil, "manifest: invalid table"
    end
    return tbl
end

----------------------------------// PACK / UNPACK //--

local function pack( files, meta, passphrase, opts )
    if type( passphrase ) ~= "string" or passphrase == "" then
        return nil, "backup_archive: passphrase required"
    end
    if type( files ) ~= "table" then
        return nil, "backup_archive: files must be a table"
    end
    opts = opts or { }
    -- `opts.iters or DEFAULT` cannot default a literal 0 (0 is truthy in
    -- Lua), so validate the resolved value explicitly.
    local iters = opts.iters or DEFAULT_ITERS
    if type( iters ) ~= "number" or iters < 1 or iters > MAX_ITERS then
        return nil, "backup_archive: iterations out of range (1.." .. MAX_ITERS .. ")"
    end

    -- Validate every file up front so a malformed caller entry degrades to
    -- (nil, err) instead of raising deeper in _manifest_serialize / _build_tar.
    for _, f in ipairs( files ) do
        if type( f.name ) ~= "string" or type( f.body ) ~= "string" then
            return nil, "backup_archive: each file needs a string name and body"
        end
        if f.name == MANIFEST_NAME then
            return nil, "backup_archive: file name '" .. MANIFEST_NAME .. "' is reserved"
        end
        if f.mode ~= nil and type( f.mode ) ~= "number" then
            return nil, "backup_archive: file mode must be a number (octal perms)"
        end
        if f.kind ~= nil and type( f.kind ) ~= "string" then
            return nil, "backup_archive: file kind must be a string"
        end
    end

    -- Build the manifest: caller meta + our format version + per-file kind.
    local m = { format_version = VERSION }
    if type( meta ) == "table" then
        for k, v in pairs( meta ) do
            if k ~= "format_version" and k ~= "kinds" then m[ k ] = v end
        end
    end
    local kinds = { }
    for _, f in ipairs( files ) do
        if f.kind then kinds[ f.name ] = f.kind end
    end
    m.kinds = kinds

    local entries = { { name = MANIFEST_NAME, mode = MODE_0644, body = _manifest_serialize( m ) } }
    for _, f in ipairs( files ) do
        entries[ #entries + 1 ] = { name = f.name, mode = f.mode or MODE_0644, body = f.body }
    end

    local tar, terr = _build_tar( entries )
    if not tar then return nil, terr end

    local salt = adclib_random_bytes( SALT_SIZE )
    if type( salt ) ~= "string" or #salt ~= SALT_SIZE then
        return nil, "backup_archive: RNG failed (salt)"
    end
    local key = _derive_key( passphrase, salt, iters, KEY_SIZE )
    local nonce = adclib_random_bytes( NONCE_SIZE )
    if type( nonce ) ~= "string" or #nonce ~= NONCE_SIZE then
        return nil, "backup_archive: RNG failed (nonce)"
    end
    local ok, ct_tag = pcall( adclib_aes_gcm_seal, key, nonce, tar )
    if not ok then
        return nil, "backup_archive: seal failed: " .. tostring( ct_tag )
    end

    local header = MAGIC
        .. string_char( VERSION )
        .. string_char( KDF_PBKDF2_SHA256 )
        .. string_pack( ">I4", iters )
        .. string_char( SALT_SIZE )
        .. salt
        .. nonce
    return header .. ct_tag
end

local function unpack( blob, passphrase )
    if type( passphrase ) ~= "string" or passphrase == "" then
        return nil, "backup_archive: passphrase required"
    end
    if type( blob ) ~= "string" or #blob < 12 then
        return nil, "backup_archive: not an LDBK archive (too short)"
    end
    if string_sub( blob, 1, 4 ) ~= MAGIC then
        return nil, "backup_archive: bad magic (not an LDBK archive)"
    end
    local version = string_byte( blob, 5 )
    if version ~= VERSION then
        return nil, "backup_archive: unsupported format version " .. tostring( version )
    end
    local kdf_id = string_byte( blob, 6 )
    if kdf_id ~= KDF_PBKDF2_SHA256 then
        return nil, "backup_archive: unsupported KDF id " .. tostring( kdf_id )
    end
    local iters = string_unpack( ">I4", blob, 7 )
    -- iters comes straight off an attacker/corruptible header. Bound it: 0
    -- would make _pbkdf2 raise (breaking the (nil,err) contract), and ~2^32
    -- would spin billions of pre-auth HMAC rounds (DoS on the restore path).
    if iters < 1 or iters > MAX_ITERS then
        return nil, "backup_archive: bad iteration count in header"
    end
    local salt_len = string_byte( blob, 11 )
    if not salt_len or salt_len < 8 or salt_len > 64 then
        return nil, "backup_archive: bad salt length"
    end
    local salt_start  = 12
    local nonce_start = salt_start + salt_len
    local ct_start    = nonce_start + NONCE_SIZE
    if #blob < ct_start + TAG_SIZE - 1 then
        return nil, "backup_archive: truncated header/ciphertext"
    end
    local salt  = string_sub( blob, salt_start, nonce_start - 1 )
    local nonce = string_sub( blob, nonce_start, ct_start - 1 )
    local ct_tag = string_sub( blob, ct_start )

    local key = _derive_key( passphrase, salt, iters, KEY_SIZE )
    local ok, tar, oerr = pcall( adclib_aes_gcm_open, key, nonce, ct_tag )
    if not ok then
        return nil, "backup_archive: decrypt error: " .. tostring( tar )
    end
    if not tar then
        return nil, "backup_archive: decrypt failed (wrong passphrase or corrupt archive: "
            .. tostring( oerr ) .. ")"
    end

    local entries, perr = _parse_tar( tar )
    if not entries then return nil, perr end

    local meta, files = nil, { }
    for _, e in ipairs( entries ) do
        if e.name == MANIFEST_NAME then
            local m, merr = _manifest_parse( e.body )
            if not m then return nil, merr end
            meta = m
        else
            files[ #files + 1 ] = { name = e.name, mode = e.mode, body = e.body }
        end
    end
    if not meta then
        return nil, "backup_archive: archive is missing its MANIFEST"
    end
    local kinds = ( type( meta.kinds ) == "table" ) and meta.kinds or { }
    for _, f in ipairs( files ) do
        f.kind = kinds[ f.name ]
    end
    -- NOTE for the restore writer (PR-B): file names here are GCM-
    -- authenticated but NOT trusted paths. A valid-yet-crafted archive can
    -- carry names like "../../etc/cron.d/x". Sanitize every name against the
    -- target root (reject absolute / "..") before writing to disk.
    return { meta = meta, files = files }
end

----------------------------------// SIDECAR //--

-- SHA-256 of the whole artifact, hex. The caller already holds the sealed
-- bytes in memory, so hashing them here avoids a re-read.
local function checksum( bytes )
    return sha256_hash( bytes )
end

-- One line in the standard `sha256sum` format ("<hex><space><space><name>")
-- so an operator can verify with `sha256sum -c <name>.sha256`, passphrase-free.
local function sidecar_line( hex, filename )
    return hex .. "  " .. filename .. "\n"
end

----------------------------------// SELF-TEST (load-time) //--

do
    -- PBKDF2-HMAC-SHA256 known-answer (P="password", S="salt", c=1),
    -- cross-checked with Python hashlib.pbkdf2_hmac at authoring time -
    -- never trust memory for crypto vectors. A silent regression in the
    -- XOR / iteration / block-index logic derives wrong keys, i.e.
    -- unrecoverable backups, so fail loud at load like sha256 / hmac.
    local dk = _pbkdf2_lua( "password", "salt", 1, KEY_SIZE )
    local hex = { }
    for i = 1, KEY_SIZE do hex[ i ] = string_format( "%02x", string_byte( dk, i ) ) end
    if table_concat( hex ) ~= "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b" then
        error( "backup_archive self-test FAILED: PBKDF2-HMAC-SHA256 c=1 vector mismatch", 2 )
    end
    -- If the OpenSSL PBKDF2 is present it MUST agree with the vetted pure-Lua
    -- one - a mismatch would silently make artifacts sealed by one path
    -- unreadable by the other.
    if type( adclib_pbkdf2 ) == "function" and adclib_pbkdf2( "password", "salt", 1, KEY_SIZE ) ~= dk then
        error( "backup_archive self-test FAILED: adclib pbkdf2_sha256 disagrees with the PBKDF2 KAT", 2 )
    end
    -- ustar build -> parse fidelity on a tiny fixture (also proves the
    -- checksum our writer emits validates).
    local tar = _build_tar( { { name = "a.txt", mode = MODE_0644, body = "hello" } } )
    local ents = _parse_tar( tar )
    if not ents or #ents ~= 1 or ents[ 1 ].name ~= "a.txt" or ents[ 1 ].body ~= "hello" then
        error( "backup_archive self-test FAILED: ustar round-trip", 2 )
    end
end

----------------------------------// PUBLIC INTERFACE //--

return {
    pack         = pack,
    unpack       = unpack,
    checksum     = checksum,
    sidecar_line = sidecar_line,

    MAGIC         = MAGIC,
    VERSION       = VERSION,
    DEFAULT_ITERS = DEFAULT_ITERS,

    -- test seams
    _pbkdf2             = _pbkdf2_lua,
    _derive_key        = _derive_key,
    _build_tar          = _build_tar,
    _parse_tar          = _parse_tar,
    _manifest_serialize = _manifest_serialize,
    _manifest_parse     = _manifest_parse,
}
