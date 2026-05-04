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

local tostring = use "tostring"

local _

-- Late-bound: see header comment.
local out_error

local function bind_late()
    out_error = use("out").error
end

-- Currently a no-op pass-through. The original cfg.lua had a commented
-- out per-key utf-8 validator; preserving the function shape here
-- means future validation can be re-added without touching callers.
local function checklanguage( lang )
    return lang
end

local function loadlanguage( language, name, core_lang_path, scripts_lang_path )
    language = tostring( language )
    local path
    if not name then
        path = core_lang_path .. language .. ".tbl"
    else
        path = scripts_lang_path .. tostring( name ) .. ".lang." .. language
    end
    local ret, err = util_loadtable( path )
    if name then
        _ = err and out_error( "cfg_lang.lua: function 'loadlanguage': error while loading language (" .. tostring( name ) .. "): ", err )
    else
        _ = err and out_error( "cfg_lang.lua: function 'loadlanguage': error while loading language: ", err )
    end
    return checklanguage( ret or { } ), err
end

return {
    bind_late    = bind_late,
    loadlanguage = loadlanguage,
}
