# Build the LuaSocket plugins (socket, mime) and a small static helper
# library used by luasec.
#
# This replaces the *.c.not rename trick from compile_with_mingw.bat by
# using per-platform source lists directly.
#
# Outputs:
#   lib/luasocket/socket/socket.so / .dll       (C module)
#   lib/luasocket/mime/mime.so   / .dll         (C module)
#   plus the Lua-side helpers under lib/luasocket/lua/, in the canonical
#   LuaSocket layout (closes luadch-ng/luadch#88):
#     lib/luasocket/lua/socket.lua              (entrypoint)
#     lib/luasocket/lua/mime.lua    , ltn12.lua , mbox.lua  (top-level helpers)
#     lib/luasocket/lua/socket/http.lua   , url.lua  , headers.lua
#     lib/luasocket/lua/socket/ftp.lua    , smtp.lua , tp.lua
#   so plugins can `require "socket.http"` / `require "ssl.https"` per the
#   standard Lua convention; http.lua's own internal `require "socket.url"`
#   etc. resolve in the same layout.

set(LSOCKET_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# ---- common (used by socket plugin AND luasec's static linker) -------------
set(LSOCKET_COMMON_SOURCES
    ${LSOCKET_SRC}/io.c
    ${LSOCKET_SRC}/buffer.c
    ${LSOCKET_SRC}/timeout.c
    ${LSOCKET_SRC}/compat.c
)

# ---- socket plugin (cross-platform pieces + per-platform sockets) ----------
set(LSOCKET_CORE_SOURCES
    ${LSOCKET_SRC}/luasocket.c
    ${LSOCKET_SRC}/auxiliar.c
    ${LSOCKET_SRC}/options.c
    ${LSOCKET_SRC}/inet.c
    ${LSOCKET_SRC}/except.c
    ${LSOCKET_SRC}/select.c
    ${LSOCKET_SRC}/tcp.c
    ${LSOCKET_SRC}/udp.c
)

if(WIN32)
    list(APPEND LSOCKET_CORE_SOURCES
        ${LSOCKET_SRC}/wsocket.c    # Win32 socket layer
    )
else()
    list(APPEND LSOCKET_CORE_SOURCES
        ${LSOCKET_SRC}/usocket.c       # POSIX socket layer
        ${LSOCKET_SRC}/serial.c        # serial port (Unix-only)
        ${LSOCKET_SRC}/unix.c          # Unix-domain socket
        ${LSOCKET_SRC}/unixstream.c
        ${LSOCKET_SRC}/unixdgram.c
    )
endif()

add_library(socket MODULE
    ${LSOCKET_COMMON_SOURCES}
    ${LSOCKET_CORE_SOURCES}
)
target_compile_definitions(socket PRIVATE LUASOCKET_NODEBUG LUASOCKET_INET_PTON)
if(WIN32)
    # FD_SETSIZE (Winsock default 64) is the hard cap on how many sockets a
    # single select() call can watch: select.c raises "too many sockets" at
    # n >= FD_SETSIZE. The hub event loop (core/server.lua tick()) selects
    # over EVERY connected socket at once, so the default 64 crashes the hub
    # once it holds ~64 sockets (users + v4/v6 listeners + HBRI + HTTP).
    # Raise to 1024 = parity with the Linux glibc fd_set. On Windows fd_set
    # is a SOCKET array sized by this macro, so bumping it genuinely enlarges
    # the set; the -D lands before <winsock2.h> (which defines FD_SETSIZE
    # only #ifndef). WINDOWS-ONLY: on Linux, glibc's fd_set is a fixed 1024-
    # bit buffer, so redefining FD_SETSIZE would overflow it - the >1024 case
    # there needs the select->poll port (#310). See luadch-ng/luadch#416.
    target_compile_definitions(socket PRIVATE WINVER=0x0501 FD_SETSIZE=1024)
    target_link_libraries(socket PRIVATE ws2_32)
endif()
target_include_directories(socket PRIVATE ${LSOCKET_SRC})
target_link_libraries(socket PRIVATE lua)
set_target_properties(socket PROPERTIES PREFIX "")
if(WIN32)
    set_target_properties(socket PROPERTIES SUFFIX ".dll")
endif()

# ---- mime plugin (small, cross-platform) -----------------------------------
add_library(mime MODULE
    ${LSOCKET_SRC}/mime.c
    ${LSOCKET_SRC}/compat.c
)
target_include_directories(mime PRIVATE ${LSOCKET_SRC})
target_link_libraries(mime PRIVATE lua)
set_target_properties(mime PROPERTIES PREFIX "")
if(WIN32)
    set_target_properties(mime PROPERTIES SUFFIX ".dll")
endif()

# ---- static helper for luasec ----------------------------------------------
# luasec links against a subset of luasocket's object files (the buffer/io/
# timeout glue PLUS the platform socket layer — wsocket on Windows, usocket
# on POSIX) so its TLS sockets share LuaSocket's read/write/wait semantics.
# We expose this as a static library; luasec's CMakeLists pulls it in.
set(LSOCKET_STATIC_SOURCES ${LSOCKET_COMMON_SOURCES})
if(WIN32)
    list(APPEND LSOCKET_STATIC_SOURCES ${LSOCKET_SRC}/wsocket.c)
else()
    list(APPEND LSOCKET_STATIC_SOURCES ${LSOCKET_SRC}/usocket.c)
endif()
add_library(luasocket_static STATIC ${LSOCKET_STATIC_SOURCES})
target_compile_definitions(luasocket_static PRIVATE LUASOCKET_NODEBUG LUASOCKET_INET_PTON)
if(WIN32)
    # Match the `socket` module's FD_SETSIZE (see above) so wsocket.c's
    # socket_waitfd / socket_select agree on the fd_set size across the
    # luasec link. luadch-ng/luadch#416.
    target_compile_definitions(luasocket_static PRIVATE WINVER=0x0501 FD_SETSIZE=1024)
endif()
target_include_directories(luasocket_static PUBLIC ${LSOCKET_SRC})
target_link_libraries(luasocket_static PUBLIC lua)

# ---- install ---------------------------------------------------------------
install(TARGETS socket LIBRARY DESTINATION lib/luasocket/socket
                       RUNTIME DESTINATION lib/luasocket/socket)
install(TARGETS mime   LIBRARY DESTINATION lib/luasocket/mime
                       RUNTIME DESTINATION lib/luasocket/mime)

# Copy the Lua-side helpers into the runtime tree, split into the canonical
# LuaSocket layout: top-level entrypoints + a nested `socket/` subdir for
# the `socket.X` submodules. See the header comment for why - closes #88.
set(LSOCKET_LUA_TOPLEVEL
    ${LSOCKET_SRC}/socket.lua    # entrypoint loaded by `require "socket"`
    ${LSOCKET_SRC}/mime.lua      # top-level per LuaSocket convention
    ${LSOCKET_SRC}/ltn12.lua     # top-level per LuaSocket convention
    ${LSOCKET_SRC}/mbox.lua      # top-level per LuaSocket convention
)
set(LSOCKET_LUA_SUBMODULES
    ${LSOCKET_SRC}/http.lua      # `require "socket.http"`
    ${LSOCKET_SRC}/url.lua       # `require "socket.url"`
    ${LSOCKET_SRC}/headers.lua   # `require "socket.headers"`
    ${LSOCKET_SRC}/ftp.lua       # `require "socket.ftp"`
    ${LSOCKET_SRC}/smtp.lua      # `require "socket.smtp"`
    ${LSOCKET_SRC}/tp.lua        # `require "socket.tp"`
)
install(FILES ${LSOCKET_LUA_TOPLEVEL}    DESTINATION lib/luasocket/lua)
install(FILES ${LSOCKET_LUA_SUBMODULES}  DESTINATION lib/luasocket/lua/socket)
