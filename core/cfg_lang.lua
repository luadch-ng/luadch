--[[

    cfg_lang.lua - language file loader extracted from core/cfg.lua

    Phase 6c-3 of the cfg.lua decomposition. Moves loadlanguage and
    its private checklanguage helper out of cfg.lua. cfg.lua keeps a
    thin wrapper that resolves the relevant cfg keys (language /
    core_lang_path / scripts_lang_path) and forwards them.

    Public surface returned to cfg.lua:

        {
            bind_late    = function()  -- see comment below
            loadlanguage = function(language, name, core_lang_path, scripts_lang_path)
        }

    out_error is late-bound for the same reason as in cfg_users:
    out.lua does `use "cfg"` at file scope, so loading it at our own
    file-load time would create a cycle. cfg.init() calls bind_late()
    after out is up; closures pick up the value via Lua's by-reference
    upvalue capture.

]]--

local use = use
local util = use "util"

local util_loadtable = util.loadtable
local util_loadjsontable = util.loadjsontable

local tostring = use "tostring"
local pairs = use "pairs"

-- Late-bound: see header comment.
local out_error

local function bind_late()
    out_error = use("out").error
end

-- Drop keys whose value is an empty string. Weblate writes "" for an
-- UNTRANSLATED string in a monolingual JSON file; without this an empty
-- de value would shadow the English fallback, because every call site
-- uses `lang.key or "<english>"` and in Lua "" is truthy (so "" or "x"
-- is ""), which would show a blank line instead of the English text.
-- Removing the key makes lang.key nil, so the fallback fires. No bundled
-- lang string is legitimately empty (verified), and an empty user-facing
-- string would be meaningless anyway. Nested tables (ucmd_menu*,
-- month_name) are left untouched. Setting an existing field to nil during
-- pairs() is allowed in Lua 5.4 (only ADDING keys mid-traversal is not).
local function checklanguage( lang )
    for k, v in pairs( lang ) do
        if v == "" then lang[ k ] = nil end
    end
    return lang
end

-- Dual-format language loader (#301 P3, lang Lua->JSON / Weblate
-- migration). JSON is the migration target: it is translation-tool
-- friendly and, unlike the executable .tbl / .lang.X, cannot carry code.
-- We probe the .json path first and fall back to the legacy Lua table so
-- the migration is incremental - a not-yet-converted file still ships
-- only .tbl / .lang.X and keeps working. util_loadjsontable is silent on
-- a missing file (returns "not found" without logging), so the probe for
-- an un-migrated file costs one failed io.open and no log noise.
--
-- JSON files live in a per-language SUBDIRECTORY (#301 P3), the standard
-- i18n layout Weblate expects (mask `<dir>/*/<file>.json`, `*` = language)
-- and one that stays tidy as languages are added - a flat dir would grow
-- to (plugins x languages) entries. The legacy Lua fallback keeps its old
-- FLAT path, so a not-yet-migrated third-party plugin still loads:
--   core:   <core_lang_path><language>/hub.json         e.g. lang/en/hub.json
--           (legacy fallback: <core_lang_path><language>.tbl)
--   plugin: <scripts_lang_path><language>/<name>.json   e.g. scripts/lang/en/cmd_reg.json
--           (legacy fallback: <scripts_lang_path><name>.lang.<language>)
local function loadlanguage( language, name, core_lang_path, scripts_lang_path )
    language = tostring( language )
    local lua_path, json_path
    if not name then
        lua_path  = core_lang_path .. language .. ".tbl"
        json_path = core_lang_path .. language .. "/hub.json"
    else
        name = tostring( name )
        lua_path  = scripts_lang_path .. name .. ".lang." .. language
        json_path = scripts_lang_path .. language .. "/" .. name .. ".json"
    end
    local ret, err = util_loadjsontable( json_path )
    if not ret then
        ret, err = util_loadtable( lua_path )
    end
    if err then
        if name then
            out_error( "cfg_lang.lua: function 'loadlanguage': error while loading language (" .. name .. "): ", err )
        else
            out_error( "cfg_lang.lua: function 'loadlanguage': error while loading language: ", err )
        end
    end
    return checklanguage( ret or { } ), err
end

return {
    bind_late    = bind_late,
    loadlanguage = loadlanguage,
}
