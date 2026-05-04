# Build the embedded Lua 5.4 interpreter as a shared library.
#
# Output names:
#   Linux/BSD :  liblua.so
#   Windows   :  lua.dll
#
# Source list mirrors Lua 5.4's upstream Makefile CORE_O + LIB_O (without
# the lua / luac standalone executables — luadch only needs the library).

set(LUA_CORE_SOURCES
    lapi.c lcode.c lctype.c ldebug.c ldo.c ldump.c lfunc.c lgc.c llex.c
    lmem.c lobject.c lopcodes.c lparser.c lstate.c lstring.c ltable.c
    ltm.c lundump.c lvm.c lzio.c
)
set(LUA_LIB_SOURCES
    lauxlib.c lbaselib.c lcorolib.c ldblib.c liolib.c lmathlib.c
    loadlib.c loslib.c lstrlib.c ltablib.c lutf8lib.c linit.c
)

add_library(lua SHARED ${LUA_CORE_SOURCES} ${LUA_LIB_SOURCES})

# Match the Phase 1 build-output spec exactly:
#   Windows  →  lua.dll       (CMake/MinGW would default to liblua.dll)
#   Linux    →  liblua.so     (default, no override needed)
# The import library on Windows stays at its default liblua.dll.a, which is
# the MinGW convention for an import lib targeting lua.dll.
if(WIN32)
    set_target_properties(lua PROPERTIES PREFIX "")
endif()

# Public headers — downstream targets (adclib, luasec, hub, ...) -I this dir
target_include_directories(lua PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Platform compile flags, mirroring the legacy build:
#   - Linux/BSD: LUA_USE_POSIX (POSIX APIs), LUA_USE_DLOPEN (require C modules)
#   - Windows : LUA_BUILD_AS_DLL (export the public Lua API from lua.dll)
target_compile_definitions(lua PUBLIC
    $<$<NOT:$<PLATFORM_ID:Windows>>:LUA_USE_POSIX>
    $<$<NOT:$<PLATFORM_ID:Windows>>:LUA_USE_DLOPEN>
    $<$<PLATFORM_ID:Windows>:LUA_BUILD_AS_DLL>
)

# Link math + dlopen on Unix
if(UNIX)
    target_link_libraries(lua PRIVATE m ${CMAKE_DL_LIBS})
endif()

# Match Phase 1 build-output spec: liblua.so / lua.dll at install root.
# We deliberately do NOT install ARCHIVE (the MinGW import lib
# liblua.dll.a) - it is a build-time linker input, not a runtime
# artefact, and our in-tree consumers (adclib, luasocket, luasec, hub)
# link via the `lua` CMake target rather than the installed import lib.
install(TARGETS lua
    RUNTIME DESTINATION .         # lua.dll on Windows
    LIBRARY DESTINATION .         # liblua.so on Linux
)
