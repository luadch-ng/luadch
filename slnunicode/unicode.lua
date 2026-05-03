--[[

    unicode.lua

    Pure-Lua replacement for the slnunicode C module that luadch shipped
    with the Lua 5.1 era runtime. The original library is unmaintained
    (last upstream activity ~2008) and uses Lua C API constants and
    functions that were removed in Lua 5.2/5.3 (LUA_QL, luaL_register,
    LUA_GLOBALSINDEX, LUA_INTFRMLEN, …).

    luadch's actual usage of the old `unicode` table — verified by an
    audit of every call site in `core/` and `scripts/` during the Phase 3
    Lua-5.4 migration — is:

      * `unicode.utf8.{format,match,find,gsub,gmatch,upper,lower,rep,
                       reverse,byte,char}` — all driven by ASCII patterns
        only, so byte-level `string.X` is bit-identical in behaviour.
      * `unicode.utf8.{len,sub}` — char-aware. Implemented here against
        the Lua 5.4 builtin `utf8` library so multibyte prefixes still
        slice correctly (e.g. `utf.sub(s, utf.len(prefix) + 1, -1)`
        for "Über:"-style prefixes).
      * `unicode.ascii.{sub}` — only used for BOM stripping in
        `core/util.lua`, byte-level by definition.

    The module is loaded via `require("unicode")` from `core/init.lua`,
    which finds `lib/unicode/unicode.lua` through `package.path`. The
    legacy slnunicode `.so`/`.dll` is no longer built or installed; see
    `compile` and `compile_with_mingw.bat`.

    If a future call site needs Unicode-class-aware pattern matching
    (e.g. `%l` matching German umlauts) — which luadch does not do today —
    a dedicated function should be added here rather than re-introducing
    the C dependency.

]]--

local string = string
local utf8 = utf8

-- Char-aware sub: indices count Unicode codepoints, not bytes.
-- Mirrors slnunicode's utf.sub(s, i, j) behaviour. Negative indices
-- count from the end; out-of-range silently clamps. Falls back to
-- byte semantics if the input is not valid UTF-8.
local function utf_sub( s, i, j )
    local clen = utf8.len( s ) or #s
    if not j then j = clen end
    if i < 0 then i = clen + i + 1 end
    if j < 0 then j = clen + j + 1 end
    if i < 1 then i = 1 end
    if j > clen then j = clen end
    if i > j then return "" end
    local b = utf8.offset( s, i )
    local e = utf8.offset( s, j + 1 )
    if not b then return "" end
    return string.sub( s, b, e and ( e - 1 ) or -1 )
end

-- Char-aware len: codepoints, not bytes.
local function utf_len( s )
    return utf8.len( s ) or #s
end

local utf8_table = {
    -- byte-safe (luadch patterns are ASCII-only, audit confirmed)
    format  = string.format,
    match   = string.match,
    find    = string.find,
    gsub    = string.gsub,
    gmatch  = string.gmatch,
    rep     = string.rep,
    upper   = string.upper,
    lower   = string.lower,
    reverse = string.reverse,
    byte    = string.byte,
    char    = string.char,
    -- char-aware via Lua 5.4 utf8 builtin
    len     = utf_len,
    sub     = utf_sub,
}

local ascii_table = {
    sub     = string.sub,
    format  = string.format,
    match   = string.match,
    find    = string.find,
    gsub    = string.gsub,
    gmatch  = string.gmatch,
    rep     = string.rep,
    upper   = string.upper,
    lower   = string.lower,
    reverse = string.reverse,
    byte    = string.byte,
    char    = string.char,
    len     = function( s ) return #s end,
}

return {
    utf8  = utf8_table,
    ascii = ascii_table,
}
