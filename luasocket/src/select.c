/*=========================================================================*\
* Select implementation
* LuaSocket toolkit
*
* luadch-ng: on POSIX the event-loop primitive (socket.select) is backed by
* poll() instead of select(), removing the fixed FD_SETSIZE=1024 ceiling that
* crashes the hub's single event loop (core/server.lua tick()) once it watches
* ~1024 sockets at once. The Lua-facing contract is byte-for-byte identical on
* both backends, so the hub side is untouched. Windows keeps the fd_set/select()
* path (FD_SETSIZE=1024, see luasocket/CMakeLists.txt + luadch-ng/luadch#416).
* See luadch-ng/luadch#310.
\*=========================================================================*/
#include "luasocket.h"

#include "socket.h"
#include "timeout.h"
#include "select.h"

#include <string.h>

#if !defined(_WIN32)
#include <poll.h>
#include <errno.h>
#endif

/* Backend selection: both bodies register under the same Lua name "select";
 * only one is compiled per platform. */
#if defined(_WIN32)
#define LS_SELECT_IMPL global_select
#else
#define LS_SELECT_IMPL global_poll
#endif

/*=========================================================================*\
* Internal function prototypes.
\*=========================================================================*/
static t_socket getfd(lua_State *L);
static int dirty(lua_State *L);
static void make_assoc(lua_State *L, int tab);
#if defined(_WIN32)
static void collect_fd(lua_State *L, int tab, int itab,
        fd_set *set, t_socket *max_fd);
static int check_dirty(lua_State *L, int tab, int dtab, fd_set *set);
static void return_fd(lua_State *L, fd_set *set, t_socket max_fd,
        int itab, int tab, int start);
static int global_select(lua_State *L);
#else
static void collect_read(lua_State *L, int tab, int itab, int rtab,
        struct pollfd *pfds, int *nfds, int *ndirty);
static void collect_write(lua_State *L, int tab, int itab,
        struct pollfd *pfds, int *nfds);
static int global_poll(lua_State *L);
#endif

/* functions in library namespace */
static luaL_Reg func[] = {
    {"select", LS_SELECT_IMPL},
    {NULL,     NULL}
};

/*-------------------------------------------------------------------------*\
* Initializes module
\*-------------------------------------------------------------------------*/
int select_open(lua_State *L) {
    lua_pushstring(L, "_SETSIZE");
    lua_pushinteger(L, FD_SETSIZE);
    lua_rawset(L, -3);
    lua_pushstring(L, "_SOCKETINVALID");
    lua_pushinteger(L, SOCKET_INVALID);
    lua_rawset(L, -3);
    /* luadch-ng: which event-loop backend this build uses - "poll" on POSIX,
     * "select" on Windows. The hub boot log reads this; _SETSIZE is only a
     * hard socket cap on the select backend (poll has none). See #310. */
    lua_pushstring(L, "_EVENTBACKEND");
#if defined(_WIN32)
    lua_pushstring(L, "select");
#else
    lua_pushstring(L, "poll");
#endif
    lua_rawset(L, -3);
    luaL_setfuncs(L, func, 0);
    return 0;
}

/*=========================================================================*\
* Shared helpers (backend-independent)
\*=========================================================================*/
static t_socket getfd(lua_State *L) {
    t_socket fd = SOCKET_INVALID;
    lua_pushstring(L, "getfd");
    lua_gettable(L, -2);
    if (!lua_isnil(L, -1)) {
        lua_pushvalue(L, -2);
        lua_call(L, 1, 1);
        if (lua_isnumber(L, -1)) {
            double numfd = lua_tonumber(L, -1);
            fd = (numfd >= 0.0)? (t_socket) numfd: SOCKET_INVALID;
        }
    }
    lua_pop(L, 1);
    return fd;
}

static int dirty(lua_State *L) {
    int is = 0;
    lua_pushstring(L, "dirty");
    lua_gettable(L, -2);
    if (!lua_isnil(L, -1)) {
        lua_pushvalue(L, -2);
        lua_call(L, 1, 1);
        is = lua_toboolean(L, -1);
    }
    lua_pop(L, 1);
    return is;
}

/* Turn an array result table into one that is ALSO indexable by socket
 * object (result[sock] = i), and return that augmented table on the stack
 * top - the value the Lua caller receives. Backend-independent. */
static void make_assoc(lua_State *L, int tab) {
    int i = 1, atab;
    lua_newtable(L); atab = lua_gettop(L);
    for ( ;; ) {
        lua_pushnumber(L, i);
        lua_gettable(L, tab);
        if (!lua_isnil(L, -1)) {
            lua_pushnumber(L, i);
            lua_pushvalue(L, -2);
            lua_settable(L, atab);
            lua_pushnumber(L, i);
            lua_settable(L, atab);
        } else {
            lua_pop(L, 1);
            break;
        }
        i = i+1;
    }
}

#if defined(_WIN32)
/*=========================================================================*\
* Windows backend: fd_set + select()
*
* fd_set here is a Winsock SOCKET array sized by FD_SETSIZE (raised to 1024 in
* luasocket/CMakeLists.txt, #416). Unchanged from upstream LuaSocket.
\*=========================================================================*/
/*-------------------------------------------------------------------------*\
* Waits for a set of sockets until a condition is met or timeout.
\*-------------------------------------------------------------------------*/
static int global_select(lua_State *L) {
    int rtab, wtab, itab, ret, ndirty;
    t_socket max_fd = SOCKET_INVALID;
    fd_set rset, wset;
    t_timeout tm;
    double t = luaL_optnumber(L, 3, -1);
    FD_ZERO(&rset); FD_ZERO(&wset);
    lua_settop(L, 3);
    lua_newtable(L); itab = lua_gettop(L);
    lua_newtable(L); rtab = lua_gettop(L);
    lua_newtable(L); wtab = lua_gettop(L);
    collect_fd(L, 1, itab, &rset, &max_fd);
    collect_fd(L, 2, itab, &wset, &max_fd);
    ndirty = check_dirty(L, 1, rtab, &rset);
    t = ndirty > 0? 0.0: t;
    timeout_init(&tm, t, -1);
    timeout_markstart(&tm);
    ret = socket_select(max_fd+1, &rset, &wset, NULL, &tm);
    if (ret > 0 || ndirty > 0) {
        return_fd(L, &rset, max_fd+1, itab, rtab, ndirty);
        return_fd(L, &wset, max_fd+1, itab, wtab, 0);
        make_assoc(L, rtab);
        make_assoc(L, wtab);
        return 2;
    } else if (ret == 0) {
        lua_pushstring(L, "timeout");
        return 3;
    } else {
        luaL_error(L, "select failed");
        return 3;
    }
}

static void collect_fd(lua_State *L, int tab, int itab,
        fd_set *set, t_socket *max_fd) {
    int i = 1, n = 0;
    /* nil is the same as an empty table */
    if (lua_isnil(L, tab)) return;
    /* otherwise we need it to be a table */
    luaL_checktype(L, tab, LUA_TTABLE);
    for ( ;; ) {
        t_socket fd;
        lua_pushnumber(L, i);
        lua_gettable(L, tab);
        if (lua_isnil(L, -1)) {
            lua_pop(L, 1);
            break;
        }
        /* getfd figures out if this is a socket */
        fd = getfd(L);
        if (fd != SOCKET_INVALID) {
            /* make sure we don't overflow the fd_set */
            if (n >= FD_SETSIZE)
                luaL_argerror(L, tab, "too many sockets");
            FD_SET(fd, set);
            n++;
            /* keep track of the largest descriptor so far */
            if (*max_fd == SOCKET_INVALID || *max_fd < fd)
                *max_fd = fd;
            /* make sure we can map back from descriptor to the object */
            lua_pushnumber(L, (lua_Number) fd);
            lua_pushvalue(L, -2);
            lua_settable(L, itab);
        }
        lua_pop(L, 1);
        i = i + 1;
    }
}

static int check_dirty(lua_State *L, int tab, int dtab, fd_set *set) {
    int ndirty = 0, i = 1;
    if (lua_isnil(L, tab))
        return 0;
    for ( ;; ) {
        t_socket fd;
        lua_pushnumber(L, i);
        lua_gettable(L, tab);
        if (lua_isnil(L, -1)) {
            lua_pop(L, 1);
            break;
        }
        fd = getfd(L);
        if (fd != SOCKET_INVALID && dirty(L)) {
            lua_pushnumber(L, ++ndirty);
            lua_pushvalue(L, -2);
            lua_settable(L, dtab);
            FD_CLR(fd, set);
        }
        lua_pop(L, 1);
        i = i + 1;
    }
    return ndirty;
}

static void return_fd(lua_State *L, fd_set *set, t_socket max_fd,
        int itab, int tab, int start) {
    t_socket fd;
    for (fd = 0; fd < max_fd; fd++) {
        if (FD_ISSET(fd, set)) {
            lua_pushnumber(L, ++start);
            lua_pushnumber(L, (lua_Number) fd);
            lua_gettable(L, itab);
            lua_settable(L, tab);
        }
    }
}

#else
/*=========================================================================*\
* POSIX backend: poll()
*
* poll() takes a variable-length pollfd array instead of the fixed 1024-bit
* fd_set, so there is no FD_SETSIZE ceiling on how many sockets the single
* hub event loop can watch (bounded only by the process fd limit; hub/hub.c
* raises RLIMIT_NOFILE at boot). See luadch-ng/luadch#310.
*
* Contract parity with global_select (the hub relies on all of these):
*  - Returns two array-iterable tables (read-ready, write-ready), each also
*    indexable by socket object via make_assoc; EMPTY (never nil) on timeout,
*    so tick()'s ipairs() never sees nil.
*  - Preserves the check_dirty() force-include: a socket whose :dirty() is
*    true (LuaSec TLS record already decrypted/buffered at the SSL layer, with
*    no fresh kernel readable event) is pre-recorded as readable and NOT
*    polled - without this every TLS client with buffered app-data stalls.
*  - The same fd may be reported in BOTH lists in one tick (TLS want-write /
*    partial-send re-arm): one POLLIN pollfd and one POLLOUT pollfd carry it.
*  - An errored fd (POLLERR/POLLHUP/POLLNVAL) surfaces into every list it was
*    watched in, so the hub reads/writes it, gets the error, and cleans up.
\*=========================================================================*/

/* Collect the read watch-set. One POLLIN pollfd per live socket in `tab`,
 * appended before any write entry. A socket whose :dirty() returns true is
 * pre-recorded into `rtab` (result read table) and NOT polled - this fuses
 * collect + check_dirty for the read side into one pass. Stack-neutral. */
static void collect_read(lua_State *L, int tab, int itab, int rtab,
        struct pollfd *pfds, int *nfds, int *ndirty) {
    int i = 1;
    if (lua_isnil(L, tab)) return;
    luaL_checktype(L, tab, LUA_TTABLE);
    for ( ;; ) {
        t_socket fd;
        lua_pushnumber(L, i);
        lua_gettable(L, tab);
        if (lua_isnil(L, -1)) {
            lua_pop(L, 1);
            break;
        }
        fd = getfd(L);
        if (fd != SOCKET_INVALID) {
            /* map descriptor back to the object for the result tables */
            lua_pushnumber(L, (lua_Number) fd);
            lua_pushvalue(L, -2);
            lua_settable(L, itab);
            if (dirty(L)) {
                /* already-ready: pre-include as readable, do not poll it
                 * (mirrors select.c check_dirty + FD_CLR) */
                lua_pushnumber(L, ++(*ndirty));
                lua_pushvalue(L, -2);
                lua_settable(L, rtab);
            } else {
                pfds[*nfds].fd = fd;
                pfds[*nfds].events = POLLIN;
                pfds[*nfds].revents = 0;
                *nfds = *nfds + 1;
            }
        }
        lua_pop(L, 1);
        i = i + 1;
    }
}

/* Collect the write watch-set. One POLLOUT pollfd per live socket in `tab`,
 * appended after all read entries. Stack-neutral. */
static void collect_write(lua_State *L, int tab, int itab,
        struct pollfd *pfds, int *nfds) {
    int i = 1;
    if (lua_isnil(L, tab)) return;
    luaL_checktype(L, tab, LUA_TTABLE);
    for ( ;; ) {
        t_socket fd;
        lua_pushnumber(L, i);
        lua_gettable(L, tab);
        if (lua_isnil(L, -1)) {
            lua_pop(L, 1);
            break;
        }
        fd = getfd(L);
        if (fd != SOCKET_INVALID) {
            lua_pushnumber(L, (lua_Number) fd);
            lua_pushvalue(L, -2);
            lua_settable(L, itab);
            pfds[*nfds].fd = fd;
            pfds[*nfds].events = POLLOUT;
            pfds[*nfds].revents = 0;
            *nfds = *nfds + 1;
        }
        lua_pop(L, 1);
        i = i + 1;
    }
}

/*-------------------------------------------------------------------------*\
* Waits for a set of sockets until a condition is met or timeout.
\*-------------------------------------------------------------------------*/
static int global_poll(lua_State *L) {
    int itab, rtab, wtab, ret, ndirty = 0, nfds = 0;
    int rcount, wcount, k;
    size_t cap = 0;
    struct pollfd *pfds;
    t_timeout tm;
    double t = luaL_optnumber(L, 3, -1);
    lua_settop(L, 3);
    /* Upper bound on pollfd entries = array length of both watch tables (a
     * socket watched for both read and write gets two entries; getfd filters
     * out non-socket rows, so this only over-allocates, never under). */
    if (!lua_isnil(L, 1)) cap += lua_rawlen(L, 1);
    if (!lua_isnil(L, 2)) cap += lua_rawlen(L, 2);
    /* GC-managed scratch buffer: survives the luaL_error longjmp below and is
     * reclaimed by the collector (unlike malloc, which would leak on error).
     * lua_newuserdata never returns NULL (it raises on OOM). */
    pfds = (struct pollfd *) lua_newuserdata(L,
            (cap ? cap : 1) * sizeof(struct pollfd));
    lua_newtable(L); itab = lua_gettop(L);
    lua_newtable(L); rtab = lua_gettop(L);
    lua_newtable(L); wtab = lua_gettop(L);
    collect_read(L, 1, itab, rtab, pfds, &nfds, &ndirty);
    collect_write(L, 2, itab, pfds, &nfds);
    /* dirty sockets are already known-ready: poll immediately, don't block */
    t = ndirty > 0 ? 0.0 : t;
    timeout_init(&tm, t, -1);
    timeout_markstart(&tm);
    do {
        double s = timeout_getretry(&tm);
        int ms = (s >= 0.0) ? (int)(s * 1.0e3) : -1;
        ret = poll(pfds, (nfds_t) nfds, ms);
    } while (ret < 0 && errno == EINTR);
    if (ret > 0 || ndirty > 0) {
        /* read results start after the pre-included dirty sockets */
        rcount = ndirty;
        wcount = 0;
        for (k = 0; k < nfds; k++) {
            short re = pfds[k].revents;
            if (re == 0) continue;
            if (pfds[k].events & POLLIN) {
                /* read watch entry: readable, or errored while read-watched */
                if (re & (POLLIN | POLLERR | POLLHUP | POLLNVAL)) {
                    lua_pushnumber(L, ++rcount);
                    lua_pushnumber(L, (lua_Number) pfds[k].fd);
                    lua_gettable(L, itab);
                    lua_settable(L, rtab);
                }
            } else {
                /* write watch entry: writable, or errored while write-watched */
                if (re & (POLLOUT | POLLERR | POLLHUP | POLLNVAL)) {
                    lua_pushnumber(L, ++wcount);
                    lua_pushnumber(L, (lua_Number) pfds[k].fd);
                    lua_gettable(L, itab);
                    lua_settable(L, wtab);
                }
            }
        }
        make_assoc(L, rtab);
        make_assoc(L, wtab);
        return 2;
    } else if (ret == 0) {
        lua_pushstring(L, "timeout");
        return 3;
    } else {
        luaL_error(L, "poll failed");
        return 3;
    }
}
#endif
