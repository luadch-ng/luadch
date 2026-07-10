/*

    hub.c by blastbeat

*/

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#ifdef __unix__
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <libgen.h>
#include <limits.h>
#endif
#ifdef _WIN32
#include <windows.h>
#include <direct.h>   /* _mkdir */
#include <errno.h>
#include <string.h>
#endif

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

static volatile sig_atomic_t do_exit = 0;
static int do_daemonization = 0;

static void log_error(const char *msg)
{
  // Write to log/exception.txt next to the binary. chdir_to_binary_dir
  // (called from main) anchored the CWD there at startup, so this
  // resolves to <install>/log/exception.txt regardless of where the
  // user invoked the hub from. If log/ does not exist, fopen returns
  // NULL and we just rely on the stderr write below - non-fatal.
  FILE *file = NULL;
  file = fopen("log/exception.txt", "a+");
  if (file)
  {
    fprintf(file, "%s\n", msg);
    fclose(file);
  }
  fprintf(stderr, "%s\n", msg);
  fflush(stderr);
}

// Anchor relative paths inside the hub (./core/init.lua, ./cfg/cfg.tbl,
// ./scripts/...) to the binary's own directory rather than whatever CWD
// the user happened to be in when they invoked us. Issue #12.
//
// Done via chdir() rather than threading a base-dir variable through
// every Lua module: the existing "././X" pattern in core/cfg.lua,
// core/init.lua, core/scripts.lua etc. continues to work unchanged
// once CWD is correct, and there is no behavioural change for
// deployments that already chdir into the install tree (systemd
// WorkingDirectory=/opt/luadch, manual `cd /opt/luadch && ./luadch`).
//
// Returns 0 on success, -1 on any failure. We do not bail out on
// failure: init.lua will then error with a clear "could not load
// core/init.lua" message which is more diagnostic than a silent abort.
static int chdir_to_binary_dir(void)
{
#ifdef _WIN32
  char path[MAX_PATH];
  DWORD len = GetModuleFileNameA(NULL, path, sizeof(path));
  if (len == 0 || len == sizeof(path))
  {
    return -1;
  }
  // Strip the trailing filename so `path` becomes the directory.
  for (DWORD i = len; i > 0; i--)
  {
    if (path[i - 1] == '\\' || path[i - 1] == '/')
    {
      path[i - 1] = '\0';
      break;
    }
  }
  return SetCurrentDirectoryA(path) ? 0 : -1;
#elif defined(__unix__)
  char buf[PATH_MAX];
  ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (len < 0)
  {
    return -1;
  }
  buf[len] = '\0';
  // dirname() may modify its argument and may return a pointer into a
  // static buffer on some libcs; chdir copies the string so the lifetime
  // is not an issue here.
  return chdir(dirname(buf));
#else
  return -1;
#endif
}

#ifdef _WIN32
static BOOL WINAPI signal_handler(DWORD event)
{
  // This runs in an extra thread.
  do_exit = 1;
  Sleep(10); // We need to wait here, because windows will end the process after "return TRUE".
  return TRUE;
}
#endif
#ifdef __unix__
static void signal_handler(int sig)
{
  do_exit = 1;
  return;
}
#endif

static void handle_signals(void)
{
#ifdef _WIN32
  SetConsoleCtrlHandler(signal_handler, TRUE);
#endif
#ifdef __unix__
  struct sigaction sa;
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = signal_handler;
  sa.sa_flags = 0;
  sigaction(SIGINT,  &sa, 0);
  sigaction(SIGTERM, &sa, 0);
  sigaction(SIGHUP,  &sa, 0);
  sigaction(SIGABRT, &sa, 0);
#endif
}

static int tablesize(lua_State *L)
{
  lua_pushnil(L);
  lua_Number i = 0;
  while (lua_next(L, 1) != 0)
  {
    lua_pop(L,1);
    i++;
  }
  lua_pushnumber(L, i);
  return 1;
}

static int cleantable(lua_State *L)
{
  lua_pushnil(L);
  while (lua_next(L, 1) != 0)
  {
    lua_pop(L, 1);
    lua_pushnil(L);
    lua_rawset(L, 1);
    lua_pushnil(L);
  }
  return 0;
}

static int requestexit(lua_State *L)
{
  do_exit = 1;
  return 0;
}

static int doexit(lua_State *L)
{
  lua_pushboolean(L, (int)do_exit);
  return 1;
}

/*
 * makedir(path) -> true | nil, errmsg
 *
 * Creates `path` and every missing parent component (mkdir -p semantics);
 * an already-existing component is not an error (EEXIST is tolerated).
 * Registered as a global so core Lua can materialise its own runtime
 * directories (log/, cfg/, certs/, scripts/data/, cfg/geoip/, an operator's
 * master.key dir) instead of relying on the CMake install / Docker
 * entrypoint to have created them. A Windows drive root ("C:") component is
 * skipped rather than passed to _mkdir. Path length is bounded.
 */
static int makedir(lua_State *L)
{
  const char *path = luaL_checkstring(L, 1);
  size_t len = strlen(path);
  char buf[1024];
  size_t i;
  if (len == 0 || len >= sizeof(buf))
  {
    lua_pushnil(L);
    lua_pushstring(L, "makedir: path empty or too long");
    return 2;
  }
  memcpy(buf, path, len + 1);   /* copy including the terminating NUL */
  for (i = 1; i <= len; i++)
  {
    if (buf[i] == '/' || buf[i] == '\\' || i == len)
    {
      char sep = buf[i];
      buf[i] = '\0';
      /* skip a Windows drive root ("C:") - _mkdir would fail on it. The
         loop starts at i=1, so a leading separator never yields an empty
         segment (no mkdir("")). */
      if (!(i >= 2 && buf[i - 1] == ':'))
      {
#ifdef _WIN32
        int mkrc = _mkdir(buf);
#else
        int mkrc = mkdir(buf, 0777);   /* 0777 & umask */
#endif
        int e = errno;   /* capture immediately: only valid right after the call */
        if (mkrc != 0 && e != EEXIST)
        {
          lua_pushnil(L);
          lua_pushfstring(L, "makedir: cannot create '%s' (errno %d)", buf, e);
          return 2;
        }
      }
      buf[i] = sep;
    }
  }
  lua_pushboolean(L, 1);
  return 1;
}

static void run_lua(void);

static int restart(lua_State *L)
{
  lua_close(L);
  /*
   * Phase 7g F-C-4: every restart pushes another run_lua onto the
   * atexit stack. POSIX guarantees only 32 registrations; further
   * atexit calls return non-zero and were silently ignored. After
   * ~32 +reload cycles the next restart would just exit cleanly
   * without re-entering run_lua, leaving the operator with a dead
   * hub. Check the return value and log loudly so the failure mode
   * is visible. Treating as fatal is the conservative choice -
   * better to refuse the +reload than pretend it worked.
   */
  if (atexit(run_lua) != 0)
  {
    log_error(
      "cannot register atexit handler for restart "
      "(atexit limit reached after many +reloads); "
      "exiting without re-entering Lua. Restart the hub process manually."
    );
    exit(EXIT_FAILURE);
  }
  exit(EXIT_SUCCESS);
  return 0;
}

static void run_lua(void)
{
  lua_State *L = luaL_newstate();
  if (!L)
  {
    log_error("cannot create Lua state: not enough memory");
    exit(EXIT_FAILURE);
  }
  luaL_openlibs(L);
  lua_register(L, "restartluadch", restart);
  lua_register(L, "cleantable", cleantable);
  lua_register(L, "tablesize", tablesize);
  lua_register(L, "doexit", doexit);
  lua_register(L, "requestexit", requestexit);
  lua_register(L, "makedir", makedir);
  int err = luaL_loadfile(L, "core/init.lua") || lua_pcall(L, 0, 0, 0);
  if (err)
  {
    log_error(lua_tostring(L, -1));
  }
  lua_close(L);
  exit(EXIT_SUCCESS);
}

static void daemonize(void)
{
  if (!do_daemonization)
  {
    return;
  }
#ifdef __unix__
  pid_t pid = fork();
  if (pid < 0)
  {
    exit(EXIT_FAILURE);
  }
  if (pid > 0)
  {
    exit(EXIT_SUCCESS);
  }
  // Restrict the file-creation mask so the hub's OWN writes are not
  // world-accessible in daemon mode. The classic daemon idiom umask(0)
  // makes every file the hub creates 0666 and every directory 0777 -
  // world-readable/writable. That matters now that the hub self-heals
  // its runtime directories (core/ensuredirs.lua etc.): a 0777 cfg/ or
  // certs/ lets a local user replace user.tbl / the TLS key / master.key
  // regardless of those files' own 0600 mode. 027 -> files 0640, dirs
  // 0750 (owner full, group read, no world); master.key / serverkey.pem
  // are additionally chmod 600 by their writers.
  umask(027);
  if (setsid() < 0)
  {
    exit(EXIT_FAILURE);
  }
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
#else
  fprintf(stderr, "Daemonization is not implemented for your OS.\n");
  fflush(stderr);
#endif
}

static void print_help(void)
{
  fprintf(stderr,
  "usage: luadch [option]\n"
  "available options are:\n"
  "  -h       show this help\n"
  "  -d       execute luadch as background daemon\n");
  fflush(stderr);
  exit(EXIT_SUCCESS);
}

static void handle_args(int argc, char **argv)
{
  if (argc > 1 && argv[1][0] == '-')
  {
    switch(argv[1][1])
    {
      case 'h': print_help(); break;
      case 'd': do_daemonization = 1; break;
    }
  }
}

int main(int argc, char **argv)
{
  handle_signals();
  handle_args(argc, argv);
  if (chdir_to_binary_dir() != 0)
  {
    // Non-fatal: continue and let luaL_loadfile report a clear "no such
    // file" error if the surrounding environment cannot supply
    // core/init.lua via the inherited CWD either.
    fprintf(stderr, "warning: could not anchor cwd to binary directory; "
                    "falling back to inherited cwd\n");
  }
  daemonize();
  run_lua();
  return EXIT_SUCCESS;
}
