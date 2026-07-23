/*

    hub.c by blastbeat

*/

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#ifdef __unix__
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>   /* flock */
#include <sys/resource.h>   /* getrlimit / setrlimit RLIMIT_NOFILE */
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <libgen.h>
#include <limits.h>
#include <dirent.h>   /* opendir / readdir - listdir() */
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

/* Offline-restore mode (#480 PR-B): set by handle_args from --restore and
 * friends, consumed by run_restore() before the hub would ever boot. */
static int do_restore = 0;
static int restore_verify = 0;
static int restore_force = 0;
static const char *restore_file = NULL;
static const char *restore_mk_path = NULL;

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

/*
 * listdir(path) -> { "name1", "name2", ... } | nil, errmsg
 *
 * Lists the entries of a directory (excluding "." and ".."), as a Lua array
 * in readdir / FindNextFile order. Registered as a global so core Lua can
 * enumerate the operator state directories (scripts/data/, scripts/cfg/)
 * for the backup engine (#480) - the tree ships no lfs / readdir otherwise.
 * Core-only, like makedir; NOT exposed to the plugin sandbox. Returns
 * (nil, message) when the directory cannot be opened (missing, not a
 * directory, permission). An empty directory yields an empty table.
 */
static int listdir(lua_State *L)
{
  const char *path = luaL_checkstring(L, 1);
#ifdef _WIN32
  char pattern[MAX_PATH];
  int n = snprintf(pattern, sizeof(pattern), "%s\\*", path);
  if (n < 0 || n >= (int)sizeof(pattern))
  {
    lua_pushnil(L);
    lua_pushstring(L, "listdir: path too long");
    return 2;
  }
  WIN32_FIND_DATAA fd;
  HANDLE h = FindFirstFileA(pattern, &fd);
  if (h == INVALID_HANDLE_VALUE)
  {
    lua_pushnil(L);
    /* lua_pushfstring understands only %d/%s/%f/%p/%c/%% - NOT %lu; feeding it
     * %lu raises "invalid option '%l'" and breaks the (nil, err) contract, so
     * the DWORD error is cast to int (codes are small, positive). */
    lua_pushfstring(L, "listdir: cannot open '%s' (error %d)",
                    path, (int)GetLastError());
    return 2;
  }
  lua_newtable(L);
  int i = 0;
  do
  {
    if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
    {
      continue;
    }
    lua_pushstring(L, fd.cFileName);
    lua_rawseti(L, -2, ++i);
  } while (FindNextFileA(h, &fd));
  /* A clean end is ERROR_NO_MORE_FILES; anything else means the enumeration
   * was cut short. Surface it rather than returning a partial listing - a
   * truncated scripts/data listing would silently under-collect a backup. */
  DWORD ferr = GetLastError();
  FindClose(h);
  if (ferr != ERROR_NO_MORE_FILES)
  {
    lua_pop(L, 1);
    lua_pushnil(L);
    lua_pushfstring(L, "listdir: enumeration failed for '%s' (error %d)",
                    path, (int)ferr);
    return 2;
  }
  return 1;
#elif defined(__unix__)
  DIR *d = opendir(path);
  if (!d)
  {
    lua_pushnil(L);
    lua_pushfstring(L, "listdir: cannot open '%s' (errno %d)", path, errno);
    return 2;
  }
  lua_newtable(L);
  int i = 0;
  struct dirent *e;
  while ((e = readdir(d)) != NULL)
  {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
    {
      continue;
    }
    lua_pushstring(L, e->d_name);
    lua_rawseti(L, -2, ++i);
  }
  closedir(d);
  return 1;
#else
  lua_pushnil(L);
  lua_pushstring(L, "listdir: unsupported platform");
  return 2;
#endif
}

/* Resulting soft RLIMIT_NOFILE after raise_fd_limit(): the practical
 * concurrent-socket ceiling on the POSIX poll backend. 0 = unknown (Windows,
 * or getrlimit failed), -1 = unlimited (RLIM_INFINITY), else the fd count.
 * Exposed to Lua via getfdlimit() for the hub boot log. */
static long g_fd_limit = 0;

/* Raise the open-file-descriptor soft limit to the hard limit at boot.
 *
 * The POSIX poll() event-loop backend (luasocket/src/select.c, #310) can watch
 * as many sockets as the process may open, so the concurrent-connection
 * ceiling is RLIMIT_NOFILE, not FD_SETSIZE. Distros default the SOFT limit to
 * 1024 while the HARD limit is far higher; raising soft->hard needs no
 * privilege and lifts the ceiling with zero operator action, right where the
 * poll port removed the old 1024 select cap - otherwise `ulimit -n = 1024`
 * would silently become the new cap. Going beyond the hard limit still needs
 * the OS (ulimit -Hn as root / systemd LimitNOFILE / Docker --ulimit nofile).
 * No-op on Windows: the select backend is FD_SETSIZE-bound (1024, #416), not
 * fd-limit-bound. Best-effort: a probe/set failure warns and leaves the limit
 * at the OS default rather than aborting the hub. */
static void raise_fd_limit(void)
{
#ifdef __unix__
  struct rlimit rl;
  if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
  {
    fprintf(stderr, "warning: getrlimit(RLIMIT_NOFILE) failed (%s); "
                    "file-descriptor limit left at the OS default\n",
                    strerror(errno));
    fflush(stderr);
    return;
  }
  if (rl.rlim_cur < rl.rlim_max)
  {
    rl.rlim_cur = rl.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
    {
      fprintf(stderr, "warning: setrlimit(RLIMIT_NOFILE) failed (%s); "
                      "concurrent-socket ceiling stays at the soft limit\n",
                      strerror(errno));
      fflush(stderr);
    }
  }
  /* Re-read ground truth: the soft limit may or may not have moved. */
  if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
  {
    g_fd_limit = (rl.rlim_cur == RLIM_INFINITY) ? -1 : (long)rl.rlim_cur;
  }
#endif
}

/*
 * getfdlimit() -> integer
 *
 * The concurrent-socket ceiling established by raise_fd_limit(): the soft
 * RLIMIT_NOFILE on POSIX (-1 = unlimited), or 0 when unknown (Windows, or the
 * probe failed). Read once by the hub boot log so operators see the real
 * limit the poll backend gives them. Set before the first run_lua and static,
 * so it survives +reload (run_lua re-entry) unchanged.
 */
static int getfdlimit(lua_State *L)
{
  lua_pushinteger(L, (lua_Integer)g_fd_limit);
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
  lua_register(L, "listdir", listdir);
  lua_register(L, "getfdlimit", getfdlimit);
  int err = luaL_loadfile(L, "core/init.lua") || lua_pcall(L, 0, 0, 0);
  if (err)
  {
    log_error(lua_tostring(L, -1));
  }
  lua_close(L);
  exit(EXIT_SUCCESS);
}

/* Offline restore (#480 PR-B). Mirrors run_lua's state setup (openlibs + the
 * makedir C primitive core/restore.lua needs) but loads core/restore.lua
 * instead of the hub, hands it the CLI options as globals, and returns the
 * integer exit code the script yields. adclib is required dynamically inside
 * restore.lua, exactly as init.lua requires it - no static registration here.
 * Never daemonizes and never enters the event loop. */
static int run_restore(void)
{
  lua_State *L = luaL_newstate();
  if (!L)
  {
    log_error("cannot create Lua state: not enough memory");
    return EXIT_FAILURE;
  }
#ifdef __unix__
  /* Restore does not go through daemonize()'s umask(027), so without this the
   * files it writes take the operator's interactive umask (often 022 -> 0644),
   * leaving the freshly-restored PLAINTEXT master.key / user.tbl / TLS key
   * group/world-readable. 077 makes every restored file owner-only (0600) at
   * creation - no post-write chmod window - and satisfies cfg_secret's
   * mandatory 0600 on master.key. No-op on Windows. */
  umask(077);
#endif
  luaL_openlibs(L);
  lua_register(L, "makedir", makedir);

  lua_pushstring(L, restore_file ? restore_file : "");
  lua_setglobal(L, "RESTORE_FILE");
  lua_pushboolean(L, restore_verify);
  lua_setglobal(L, "RESTORE_VERIFY");
  lua_pushboolean(L, restore_force);
  lua_setglobal(L, "RESTORE_FORCE");
  if (restore_mk_path)
  {
    lua_pushstring(L, restore_mk_path);
    lua_setglobal(L, "RESTORE_MASTER_KEY_PATH");
  }

  int rc = EXIT_FAILURE;
  if (luaL_loadfile(L, "core/restore.lua") || lua_pcall(L, 0, 1, 0))
  {
    log_error(lua_tostring(L, -1));
  }
  else
  {
    /* restore.lua returns 0 on success, 1 on failure. Anything non-integer
     * (a script bug) is treated as failure. */
    rc = lua_isinteger(L, -1) ? (int)lua_tointeger(L, -1) : EXIT_FAILURE;
  }
  lua_close(L);
  return rc;
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
  "  -h                       show this help\n"
  "  -d                       execute luadch as background daemon\n"
  "  --restore <file>         restore an encrypted .ldbk backup, then exit\n"
  "  --verify                 with --restore: check the archive, write nothing\n"
  "  --force                  with --restore: overwrite existing files\n"
  "  --master-key-path <p>    with --restore: place master.key at <p>\n");
  fflush(stderr);
  exit(EXIT_SUCCESS);
}

/* Parse argv. Keeps the legacy single-letter -h/-d and adds the --restore
 * family (offline restore, #480 PR-B). --restore consumes the next argv as the
 * archive path; --master-key-path consumes the next argv as an override. */
static void handle_args(int argc, char **argv)
{
  for (int i = 1; i < argc; i++)
  {
    const char *a = argv[i];
    if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0)
    {
      print_help();
    }
    else if (strcmp(a, "-d") == 0)
    {
      do_daemonization = 1;
    }
    else if (strcmp(a, "--restore") == 0)
    {
      if (i + 1 >= argc)
      {
        fprintf(stderr, "luadch: --restore needs a backup file argument\n");
        exit(EXIT_FAILURE);
      }
      do_restore = 1;
      restore_file = argv[++i];
    }
    else if (strcmp(a, "--verify") == 0)
    {
      restore_verify = 1;
    }
    else if (strcmp(a, "--force") == 0)
    {
      restore_force = 1;
    }
    else if (strcmp(a, "--master-key-path") == 0)
    {
      if (i + 1 >= argc)
      {
        fprintf(stderr, "luadch: --master-key-path needs a path argument\n");
        exit(EXIT_FAILURE);
      }
      restore_mk_path = argv[++i];
    }
  }
}

/* ---- single-instance lock -------------------------------------------
 *
 * Refuse to start a second hub against the same install tree. Two hubs
 * sharing one cfg/ race on user.tbl, master.key, the plugin .tbl stores
 * and the logs; interleaved saveusers()/savetable() writes can corrupt
 * them (data loss). The guard is a lock FILE in the install directory -
 * chdir_to_binary_dir() anchored the CWD there, so a relative name
 * resolves per-install automatically: a second hub in a DIFFERENT
 * directory has its own lock and starts fine (a test hub + a prod hub on
 * one box is a supported setup). The lock is held open for the whole
 * process lifetime:
 *   - unix:    flock(LOCK_EX | LOCK_NB). The kernel releases it when the
 *              process dies, so a crash never leaves a blocking stale
 *              lock. fork() shares the open file description, so the
 *              daemon child keeps the lock after the parent exits.
 *   - windows: CreateFile with dwShareMode = 0 (deny sharing) - a second
 *              open fails with ERROR_SHARING_VIOLATION. FILE_FLAG_DELETE_
 *              ON_CLOSE removes the file on exit/crash.
 *
 * Fail-open: if the lock file cannot even be created (read-only fs and
 * the like) we warn and continue rather than brick the hub over a
 * missing convenience guard - only a definitive "already held" refuses
 * startup. Survives +reload: restart() re-enters run_lua via atexit
 * without closing this fd/handle, so the lock persists with no gap. */
#define LOCKFILE_NAME "luadch.lock"

#ifdef _WIN32
static HANDLE g_lock_handle = INVALID_HANDLE_VALUE;
#elif defined(__unix__)
static int g_lock_fd = -1;
#endif

/* 0 = we hold the lock (or the guard degraded to a no-op; continue).
 * 1 = another instance already holds it (caller must abort startup). */
static int acquire_single_instance_lock(void)
{
#ifdef _WIN32
  HANDLE h = CreateFileA(
    LOCKFILE_NAME,
    GENERIC_READ | GENERIC_WRITE,
    0,                                  /* dwShareMode = 0 -> exclusive */
    NULL,
    OPEN_ALWAYS,
    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE,
    NULL);
  if (h == INVALID_HANDLE_VALUE)
  {
    DWORD e = GetLastError();
    /* A concurrent instance holding the file with dwShareMode = 0 ALWAYS
     * surfaces as ERROR_SHARING_VIOLATION - that is the only definitive
     * "already running" signal. ERROR_ACCESS_DENIED means something else
     * (a read-only or ACL-denied stale lock file, a directory of that
     * name) with no instance necessarily running, so it must fail-open
     * rather than wrongly refuse startup. */
    if (e == ERROR_SHARING_VIOLATION)
    {
      return 1;   /* another instance holds the exclusive handle */
    }
    fprintf(stderr, "warning: cannot create lock file '%s' (error %lu); "
                    "single-instance guard disabled\n",
                    LOCKFILE_NAME, (unsigned long)e);
    fflush(stderr);
    return 0;     /* fail-open */
  }
  g_lock_handle = h;
  return 0;
#elif defined(__unix__)
  /* O_CLOEXEC so a fork+exec child (io.popen / os.execute) does NOT
   * inherit this fd: an inherited fd that outlives the hub would keep the
   * flock held and wrongly refuse the next restart. daemonize() forks
   * WITHOUT exec, so the daemon child still shares the open file
   * description and correctly retains the lock. */
  int fd = open(LOCKFILE_NAME, O_CREAT | O_RDWR | O_CLOEXEC, 0640);
  if (fd < 0)
  {
    fprintf(stderr, "warning: cannot create lock file '%s' (%s); "
                    "single-instance guard disabled\n",
                    LOCKFILE_NAME, strerror(errno));
    fflush(stderr);
    return 0;     /* fail-open */
  }
  if (flock(fd, LOCK_EX | LOCK_NB) != 0)
  {
    if (errno == EWOULDBLOCK)
    {
      close(fd);
      return 1;   /* another instance holds the lock */
    }
    fprintf(stderr, "warning: cannot lock '%s' (%s); "
                    "single-instance guard disabled\n",
                    LOCKFILE_NAME, strerror(errno));
    fflush(stderr);
    close(fd);
    return 0;     /* fail-open */
  }
  g_lock_fd = fd;
  return 0;
#else
  return 0;       /* unknown platform: no guard */
#endif
}

/* Record the running process's PID in the (already-held) lock file for
 * operator diagnostics. Called AFTER daemonize() so the value is the
 * surviving process, not the pre-fork parent. Best-effort: a write
 * failure is not fatal - the lock is the open handle, not the content. */
static void write_lock_pid(void)
{
  char buf[32];
  int n;
#ifdef _WIN32
  if (g_lock_handle == INVALID_HANDLE_VALUE) return;
  n = snprintf(buf, sizeof(buf), "%lu\n",
               (unsigned long)GetCurrentProcessId());
  if (n > 0)
  {
    DWORD written = 0;
    if (n >= (int)sizeof(buf)) n = (int)sizeof(buf) - 1;   /* clamp */
    SetFilePointer(g_lock_handle, 0, NULL, FILE_BEGIN);
    WriteFile(g_lock_handle, buf, (DWORD)n, &written, NULL);
    SetEndOfFile(g_lock_handle);   /* truncate: OPEN_ALWAYS may reopen a
                                    * survived-hard-crash file with a
                                    * longer stale PID */
  }
#elif defined(__unix__)
  if (g_lock_fd < 0) return;
  n = snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
  if (n > 0 && lseek(g_lock_fd, 0, SEEK_SET) == 0)
  {
    ssize_t w;
    if (n >= (int)sizeof(buf)) n = (int)sizeof(buf) - 1;   /* clamp */
    w = write(g_lock_fd, buf, (size_t)n);
    if (w > 0)
    {
      int t = ftruncate(g_lock_fd, w);
      (void)t;
    }
  }
#endif
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
  // Acquire BEFORE daemonize() so a foreground start reports the refusal
  // straight to the invoking shell (non-zero exit), and a second `-d`
  // start is rejected before it forks.
  if (acquire_single_instance_lock() != 0)
  {
    log_error("luadch: another instance is already running in this "
              "directory; refusing to start.");
    return EXIT_FAILURE;
  }
  // Offline restore runs HERE - after the lock (so it can never race a running
  // hub over cfg/user.tbl/master.key) but before any hub boot - and exits.
  if (do_restore)
  {
    return run_restore();
  }
  // Lift the fd soft limit to the hard limit so the POSIX poll() event loop
  // (#310) is not silently re-capped at the default ulimit -n. Inherited
  // across the daemonize() fork, so raising it here (once, in the parent) is
  // enough. No-op on Windows.
  raise_fd_limit();
  daemonize();
  write_lock_pid();
  run_lua();
  return EXIT_SUCCESS;
}
