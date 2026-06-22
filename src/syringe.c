/**
 * syringe.c — ptrace-based shared-library injector
 *
 * Technique (see syringe.h for details):
 *   ptrace-attach → find dlopen() → write shellcode stub → redirect RIP → run → restore
 *
 * Arch-agnostic core. Per-CPU backends live in src/arch/arch_<arch>.c.
 *
 * Public API (syringe.h): syringe_inject()
 * Internal escape hatch:  syringe_build_shellcode() (exposed for unit tests)
 *
 * The in-process hooker (syringe_hook_install etc.) is header-only —
 * see syringe_hook.h. libsyringe.so does NOT link against it.
 */

#define _GNU_SOURCE
#include "syringe.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dirent.h>
#include <dlfcn.h>
// clang-format off
#include <sys/ptrace.h>
#include <linux/ptrace.h> /* struct ptrace_syscall_info — must be after sys/ptrace.h on newer glibc */
// clang-format on
#include <sys/socket.h> /* socklen_t for PTRACE_GET_SYSCALL_INFO */
#include <sys/time.h>   /* ualarm */
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "syringe.h"                  /* syringe_inject, syringe_inject_with_retry, dotnet */
#include "arch.h"                     /* per-architecture shellcode + register backend */

/* ── internal prototype (not in public header) ────────────────────────────
 *
 * syringe_build_shellcode is intentionally not declared in syringe.h.
 * Most callers should use syringe_inject() which calls it internally.
 * It's left as a non-static symbol so unit tests can extern it, but
 * consumers of libsyringe.so should NOT rely on it being present.
 */
size_t syringe_build_shellcode(unsigned char *buf, size_t bufsz, unsigned long dlopen_addr, const char *so_path,
                               unsigned long inject_addr);

/* ── logging macros ─────────────────────────────────────────────────────── */

/* ── Logging ──────────────────────────────────────────────────────────────
 *
 * INJ_LOG / INJ_OK: info messages, suppressed unless verbose mode.
 * INJ_ERR: error messages, always printed.
 *
 * Verbose mode is controlled by the global `syringe_verbose` flag,
 * set by the CLI via -v/--verbose, or by library callers directly.
 * Default: 0 (silent — clean stderr for normal operation).
 */
int syringe_verbose = 0;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#define INJ_LOG(fmt, ...)                                                                                              \
  do {                                                                                                                 \
    if (syringe_verbose)                                                                                               \
      fprintf(stderr, "[*] " fmt "\n", ##__VA_ARGS__);                                                                 \
  } while (0)
#define INJ_OK(fmt, ...)                                                                                               \
  do {                                                                                                                 \
    if (syringe_verbose)                                                                                               \
      fprintf(stderr, "[+] " fmt "\n", ##__VA_ARGS__);                                                                 \
  } while (0)
/* INJ_ERR always prints — but still uses [!] prefix for consistency.
 * NOTE: INJ_ERR includes `return -1` — use INJ_ERR_PRINT for error logs
 * that don't return (e.g., in void functions, or when you need custom
 * return values). */
#define INJ_ERR(fmt, ...)                                                                                              \
  do {                                                                                                                 \
    fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__);                                                                   \
    return -1;                                                                                                         \
  } while (0)
#define INJ_ERR_PRINT(fmt, ...)                                                                                        \
  do {                                                                                                                 \
    fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__);                                                                   \
  } while (0)
#pragma GCC diagnostic pop

/* ── helpers ────────────────────────────────────────────────────────────── */

/* Read a word from remote process memory */
static long remote_read_word(pid_t pid, unsigned long addr) {
  errno = 0;
  long val = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
  if (val == -1 && errno) {
    perror("ptrace PEEKDATA");
    return -1;
  }
  return val;
}

/* Write a word into remote process memory */
static void remote_write_word(pid_t pid, unsigned long addr, long data) {
  if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)data) < 0) {
    perror("ptrace POKEDATA");
  }
}

/* Write arbitrary bytes into remote memory word-by-word */
static void remote_write_bytes(pid_t pid, unsigned long addr, const unsigned char *buf, size_t len) {
  size_t i = 0;
  while (i + sizeof(long) <= len) {
    long word;
    memcpy(&word, buf + i, sizeof(long));
    remote_write_word(pid, addr + i, word);
    i += sizeof(long);
  }
  if (i < len) { /* partial last word */
    long word = remote_read_word(pid, addr + i);
    memcpy(&word, buf + i, len - i);
    remote_write_word(pid, addr + i, word);
  }
}

/* Read arbitrary bytes from remote memory */
static void remote_read_bytes(pid_t pid, unsigned long addr, unsigned char *buf, size_t len) {
  size_t i = 0;
  while (i < len) {
    long word = remote_read_word(pid, addr + i);
    size_t chunk = (len - i < sizeof(long)) ? (len - i) : sizeof(long);
    memcpy(buf + i, &word, chunk);
    i += chunk;
  }
}

/* ── /proc parsing ──────────────────────────────────────────────────────── */

typedef struct {
  unsigned long start;
  unsigned long end;
  char perms[8];
  char name[PATH_MAX];
} MapEntry;

/*
 * Find the first mapping whose name contains `needle` and has all the
 * permission chars in `perms_must` (e.g. "rx").
 * Returns 1 on success.
 */
static int find_map(pid_t pid, const char *needle, const char *perms_must, MapEntry *out) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE *f = fopen(path, "r");
  if (!f) {
    perror("fopen maps");
    return 0;
  }

  char line[512];
  while (fgets(line, sizeof(line), f)) {
    MapEntry e = {0};
    char perms[8];
    /* addr-addr perms offset dev inode [name] */
    int n = sscanf(line, "%lx-%lx %7s %*s %*s %*s %[^\n]", &e.start, &e.end, perms, e.name);
    if (n < 3)
      continue;
    if (n < 4)
      e.name[0] = '\0';
    memcpy(e.perms, perms, sizeof(e.perms));

    /* check permissions */
    int ok = 1;
    for (const char *p = perms_must; *p; p++)
      if (!strchr(perms, *p)) {
        ok = 0;
        break;
      }
    if (!ok)
      continue;

    /* check name — match by basename prefix to avoid false positives.
     *
     * BUG: strstr(name, "libc") matches libcoreclr.so, libcrypto.so,
     * libcom_err.so, etc. because they all contain "libc" as substring.
     * .NET apps like osu! load libcoreclr.so, which caused syringe to
     * resolve dlopen from the wrong library → SIGSEGV.
     *
     * Fix: extract basename, check it starts with needle followed by
     * '.' or end-of-string. So "libc" matches "libc.so.6" but NOT
     * "libcoreclr.so" (which starts with "libcore", not "libc."). */
    if (needle) {
      const char *base = strrchr(e.name, '/');
      base = base ? base + 1 : e.name;
      size_t nlen = strlen(needle);
      if (strncmp(base, needle, nlen) != 0)
        continue;
      if (base[nlen] != '.' && base[nlen] != '\0')
        continue;
    }

    *out = e;
    fclose(f);
    return 1;
  }
  fclose(f);
  return 0;
}

/*
 * Find ALL mappings matching `perms_must`. Returns a malloc'd array
 * (caller frees) and sets *count. Returns NULL if none found.
 *
 * Used by syringe_inject_with_retry to try injecting into different
 * executable regions when the first one fails (e.g., W^X enforcement,
 * read-only text segment, or region already in use by another injector).
 *
 * Regions are returned in /proc/<pid>/maps order (lowest address first),
 * which typically means: main binary text → libc → ld-linux → other libs.
 * The main binary is usually the safest to patch, so we preserve that order.
 */
static MapEntry *find_all_maps(pid_t pid, const char *perms_must, size_t *count) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE *f = fopen(path, "r");
  if (!f) {
    perror("fopen maps");
    return NULL;
  }

  /* First pass: count matches */
  size_t n = 0;
  char line[512];
  while (fgets(line, sizeof(line), f)) {
    char perms[8];
    unsigned long dummy_start, dummy_end;
    if (sscanf(line, "%lx-%lx %7s", &dummy_start, &dummy_end, perms) < 3)
      continue;
    int ok = 1;
    for (const char *p = perms_must; *p; p++)
      if (!strchr(perms, *p)) {
        ok = 0;
        break;
      }
    if (ok)
      n++;
  }
  if (n == 0) {
    fclose(f);
    return NULL;
  }

  /* Second pass: collect */
  MapEntry *arr = malloc(n * sizeof(MapEntry));
  if (!arr) {
    fclose(f);
    return NULL;
  }
  rewind(f);
  size_t i = 0;
  while (fgets(line, sizeof(line), f) && i < n) {
    MapEntry e = {0};
    char perms[8];
    int parsed = sscanf(line, "%lx-%lx %7s %*s %*s %*s %[^\n]", &e.start, &e.end, perms, e.name);
    if (parsed < 3)
      continue;
    if (parsed < 4)
      e.name[0] = '\0';
    memcpy(e.perms, perms, sizeof(e.perms));

    int ok = 1;
    for (const char *p = perms_must; *p; p++)
      if (!strchr(perms, *p)) {
        ok = 0;
        break;
      }
    if (!ok)
      continue;

    arr[i++] = e;
  }
  fclose(f);
  *count = i;
  return arr;
}

/*
 * Enumerate all thread IDs in /proc/<pid>/task/.
 * Returns malloc'd array (caller frees) and sets *count.
 * Returns NULL on failure.
 */
static pid_t *find_all_threads(pid_t pid, size_t *count) {
  char task_path[64];
  snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);
  DIR *td = opendir(task_path);
  if (!td) {
    perror("opendir task");
    return NULL;
  }

  size_t n = 0;
  struct dirent *de;
  while ((de = readdir(td))) {
    if (de->d_name[0] >= '0' && de->d_name[0] <= '9')
      n++;
  }
  rewinddir(td);

  if (n == 0) {
    closedir(td);
    return NULL;
  }

  pid_t *tids = malloc(n * sizeof(pid_t));
  if (!tids) {
    closedir(td);
    return NULL;
  }

  size_t i = 0;
  while ((de = readdir(td)) && i < n) {
    if (de->d_name[0] >= '0' && de->d_name[0] <= '9') {
      tids[i++] = (pid_t)atoi(de->d_name);
    }
  }
  closedir(td);
  *count = i;
  return tids;
}

/*
 * Check if a thread is currently blocked in a syscall.
 *
 * Reads /proc/<tid>/syscall:
 *   - "running"    → thread is on CPU, NOT in a syscall
 *   - "" (empty)   → thread is stopped, NOT in a syscall
 *   - "<num> ..."  → thread is blocked in syscall number <num>
 *
 * Why this matters: when a thread is in a blocking syscall (poll, futex,
 * epoll_wait, read, etc.), PTRACE_SETREGS changing RIP has NO EFFECT —
 * the kernel ignores RIP changes until the syscall returns. The shellcode
 * never executes, and the thread stays blocked → eventually gets SIGSEGV
 * → injection fails.
 *
 * Returns 1 if in syscall, 0 if not (or can't tell).
 *
 * NOTE: this reads /proc BEFORE ptrace attach. After attach, the thread
 * is stopped and /proc/<tid>/syscall may return "running" or empty
 * regardless of pre-stop state. For post-attach syscall detection, use
 * wait_for_syscall_exit() which uses PTRACE_SYSCALL + PTRACE_GET_SYSCALL_INFO.
 */
static int thread_in_syscall(pid_t tid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/syscall", tid);
  FILE *f = fopen(path, "r");
  if (!f)
    return 0; /* can't tell — assume not in syscall */

  char buf[256];
  if (!fgets(buf, sizeof(buf), f)) {
    fclose(f);
    return 0; /* empty = stopped, not in syscall */
  }
  fclose(f);

  /* "running" = on CPU, not in syscall */
  if (strncmp(buf, "running", 7) == 0)
    return 0;

  /* Anything else (a syscall number) = in syscall */
  return 1;
}

/*
 * Wait for a thread to exit its current syscall, then return it stopped
 * at syscall-exit (ready for RIP modification).
 *
 * Uses PTRACE_SYSCALL + PTRACE_GET_SYSCALL_INFO (Linux 5.3+):
 *   1. PTRACE_SYSCALL — continue thread until next syscall entry/exit
 *   2. waitpid with timeout (via SIGALRM) — block until syscall boundary
 *   3. PTRACE_GET_SYSCALL_INFO — check if at entry or exit
 *   4. If at entry, PTRACE_SYSCALL again to continue to exit
 *
 * This is the correct way to wait for syscall exit on a ptrace-attached
 * thread. Reading /proc/<tid>/syscall after attach is unreliable because
 * the thread is already stopped.
 *
 * timeout_ms: max time to wait. 0 = blocking (no timeout). If the thread
 * is stuck in a truly blocking syscall (e.g., futex with no timeout),
 * this prevents hanging forever.
 *
 * Returns 0 on success (thread stopped at syscall-exit, ready for SETREGS),
 * -1 on failure (timeout, error, or thread died).
 */
static volatile sig_atomic_t g_syscall_wait_timed_out = 0;

static void syscall_wait_alarm_handler(int sig) {
  (void)sig;
  g_syscall_wait_timed_out = 1;
}

static int wait_for_syscall_exit(pid_t tid, int timeout_ms) {
  /* Set up SIGALRM timeout if requested. */
  struct sigaction old_sa;
  int has_alarm = 0;
  if (timeout_ms > 0) {
    struct sigaction sa = {0};
    sa.sa_handler = syscall_wait_alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* no SA_RESTART — we want EINTR */
    if (sigaction(SIGALRM, &sa, &old_sa) == 0) {
      g_syscall_wait_timed_out = 0;
      ualarm((useconds_t)timeout_ms * 1000, 0);
      has_alarm = 1;
    }
  }

  /* Continue until next syscall boundary. */
  if (ptrace(PTRACE_SYSCALL, tid, NULL, NULL) < 0) {
    if (has_alarm) {
      alarm(0);
      sigaction(SIGALRM, &old_sa, NULL);
    }
    return -1;
  }

  /* Block until the syscall boundary is hit (or timeout). */
  int status;
  int wp = waitpid(tid, &status, __WALL);
  if (has_alarm) {
    alarm(0);
    sigaction(SIGALRM, &old_sa, NULL);
  }

  if (g_syscall_wait_timed_out || wp < 0) {
    return -1; /* timeout or error */
  }

  if (!WIFSTOPPED(status)) {
    return -1; /* thread died or unexpected status */
  }

  int sig = WSTOPSIG(status);
  /* SIGTRAP | 0x80 indicates a syscall stop (PTRACE_O_TRACESYSGOOD) */
  if (sig != (SIGTRAP | 0x80)) {
    /* Got a different signal (real signal, not syscall trap). */
    return -1;
  }

  /* Check if at syscall entry or exit. */
  struct ptrace_syscall_info info;
  socklen_t infolen = sizeof(info);
  if (ptrace(PTRACE_GET_SYSCALL_INFO, tid, infolen, &info) < 0) {
    /* Fallback: assume we're at the right place. Older kernels
     * without PTRACE_GET_SYSCALL_INFO (Linux < 5.3) will hit this. */
    return 0;
  }

  if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
    return 0; /* ready for RIP modification */
  }

  if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
    /* At syscall-entry. Continue once more to reach syscall-exit.
     * Re-arm timeout for this second wait. */
    if (timeout_ms > 0) {
      struct sigaction sa = {0};
      sa.sa_handler = syscall_wait_alarm_handler;
      sigemptyset(&sa.sa_mask);
      sa.sa_flags = 0;
      if (sigaction(SIGALRM, &sa, &old_sa) == 0) {
        g_syscall_wait_timed_out = 0;
        ualarm((useconds_t)timeout_ms * 1000, 0);
        has_alarm = 1;
      }
    }
    if (ptrace(PTRACE_SYSCALL, tid, NULL, NULL) < 0) {
      if (has_alarm) {
        alarm(0);
        sigaction(SIGALRM, &old_sa, NULL);
      }
      return -1;
    }
    wp = waitpid(tid, &status, __WALL);
    if (has_alarm) {
      alarm(0);
      sigaction(SIGALRM, &old_sa, NULL);
    }
    if (g_syscall_wait_timed_out || wp < 0)
      return -1;
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != (SIGTRAP | 0x80)) {
      return -1;
    }
    return 0;
  }

  /* Unknown state — proceed anyway, best effort. */
  return 0;
}

/* ── symbol resolution in target process ───────────────────────────────── */

/*
 * Find the address of `sym` exported by `lib_path` as it is mapped in
 * the target process.
 *
 * Strategy:
 *   a) Load the library in our own process to get our_base -> sym_offset
 *   b) Find where the same library is mapped in the target -> their_base
 *   c) target_addr = their_base + sym_offset
 */
static unsigned long find_remote_sym(pid_t pid, const char *lib_substr, const char *sym) {
  /* Resolve the library path (e.g. /lib/.../libc.so.6) from /proc maps */
  char lib_path[PATH_MAX] = {0};
  unsigned long lib_base = 0;
  char mapfile[64];
  snprintf(mapfile, sizeof(mapfile), "/proc/%d/maps", getpid());
  FILE *f = fopen(mapfile, "r");
  char line[512];
  while (f && fgets(line, sizeof(line), f)) {
    unsigned long s, e;
    char perms[8], name[PATH_MAX];
    int n = sscanf(line, "%lx-%lx %7s %*s %*s %*s %[^\n]", &s, &e, perms, name);
    if (n < 4)
      continue;
    if (strstr(name, lib_substr)) {
      /* pick the lowest address mapping (true base of the library) */
      if (!lib_base || s < lib_base) {
        lib_base = s;
        snprintf(lib_path, sizeof(lib_path), "%s", name);
      }
    }
  }
  if (f)
    fclose(f);
  if (!lib_path[0]) {
    INJ_ERR_PRINT("Cannot find '%s' in our maps\n", lib_substr);
    return 0;
  }

  /* resolve symbol offset in our process */
  void *h = dlopen(lib_path, RTLD_LAZY);
  if (!h) {
    INJ_ERR_PRINT("dlopen '%s': %s\n", lib_path, dlerror());
    return 0;
  }

  void *sym_addr = dlsym(h, sym);
  if (!sym_addr) {
    INJ_ERR_PRINT("dlsym '%s': %s\n", sym, dlerror());
    return 0;
  }

  unsigned long offset = (unsigned long)sym_addr - lib_base;
  INJ_LOG("'%s' offset in %s: 0x%lx (base 0x%lx)", sym, lib_path, offset, lib_base);

  /* find the same library in the target */
  MapEntry their_map = {0};
  if (!find_map(pid, lib_substr, "r", &their_map)) {
    INJ_ERR_PRINT("'%s' not mapped in pid %d\n", lib_substr, pid);
    return 0;
  }

  unsigned long remote_addr = their_map.start + offset;
  INJ_LOG("Remote '%s' @ 0x%lx (their base 0x%lx + offset 0x%lx)", sym, remote_addr, their_map.start, offset);
  return remote_addr;
}

/* ── shellcode builder (arch-dispatched) ────────────────────────────────── */
/*
 * syringe_build_shellcode is the documented escape-hatch symbol (see the
 * note in syringe.h and the README). The real, per-architecture
 * implementation lives in src/arch/arch_<arch>.c as
 * syringe_arch_build_shellcode(). This non-static wrapper just forwards so
 * that existing callers — unit tests that extern it, and advanced consumers
 * driving ptrace themselves — keep resolving the symbol without code
 * changes.
 */
size_t syringe_build_shellcode(unsigned char *buf, size_t bufsz, unsigned long dlopen_addr, const char *so_path,
                               unsigned long inject_addr) {
  return syringe_arch_build_shellcode(buf, bufsz, dlopen_addr, so_path, inject_addr);
}

/* ── main injection logic ───────────────────────────────────────────────── */

/*
 * Core injection at a specific address. Called by syringe_inject_with_retry
 * for each candidate region. Returns 0 on success, -1 on failure.
 *
 * All the ptrace attach/restore logic lives here so the retry loop stays
 * clean. The caller is responsible for picking inject_addr (via
 * find_all_maps or similar).
 *
 * NOTE: Even on SIGSEGV (signal 11), we return 0 if the library may have
 * loaded (dlopen often completes before the crash). The caller can check
 * /proc/<pid>/maps to verify. This matches the pre-retry behavior where
 * we always restored + detached on any signal.
 */
static int syringe_inject_at(pid_t pid, const char *abs_path, unsigned long dlopen_addr, unsigned long inject_addr,
                             const char *region_name, int thread_wait_ms) {
  INJ_LOG("Injection site: 0x%lx (%s)", inject_addr, region_name ? region_name : "?");

  /* ── Build shellcode ── */
  unsigned char sc[512] = {0};
  size_t sc_len = syringe_arch_build_shellcode(sc, sizeof(sc), dlopen_addr, abs_path, inject_addr);
  if (sc_len == 0) {
    INJ_ERR("Failed to build shellcode");
    return -1;
  }
  INJ_LOG("Shellcode size: %zu bytes", sc_len);

  /* ── Attach to process ── */
  INJ_LOG("Attaching to pid %d ...", pid);

  /* Use PTRACE_SEIZE (Linux 3.0+) instead of PTRACE_ATTACH.
   *
   * Why: PTRACE_ATTACH sends SIGSTOP to the MAIN thread only. If the
   * target is multithreaded (runtimes with anti-debug like .NET CoreCLR,
   * Wayland compositor, eglgears),
   * the OTHER threads keep running while we write shellcode → they hit
   * the half-written code → SIGSEGV → "Process stopped with signal 11".
   *
   * PTRACE_SEIZE + PTRACE_INTERRUPT stops ALL threads atomically without
   * sending SIGSTOP. We then explicitly attach to each thread in
   * /proc/<pid>/task/ to make sure they're all stopped before we touch
   * memory. This is the same approach used by gdb and strace.
   *
   * Fallback: if SEIZE fails (old kernel, or already-traced), retry
   * with classic ATTACH. Maintains backward compat. */
  int *all_tids = NULL;
  size_t n_tids = 0;

  if (ptrace(PTRACE_SEIZE, pid, NULL, PTRACE_O_TRACECLONE | PTRACE_O_TRACESYSGOOD) == 0) {
    /* INTERRUPT stops ALL threads atomically. */
    if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) < 0) {
      INJ_LOG("PTRACE_INTERRUPT failed: %s — proceeding anyway", strerror(errno));
    }
    /* Wait for main thread to stop (sync point — all threads are
     * stopped by this point). Use __WALL to handle clone children. */
    if (waitpid(pid, NULL, __WALL) < 0) {
      INJ_ERR("waitpid (seize): %s", strerror(errno));
      ptrace(PTRACE_DETACH, pid, NULL, NULL);
      return -1;
    }

    /* Enumerate all threads via helper. */
    all_tids = find_all_threads(pid, &n_tids);
    INJ_OK("Attached via SEIZE (stopped %zu thread%s)", n_tids, n_tids == 1 ? "" : "s");
  } else {
    /* Fallback: classic ATTACH (single-thread stop only).
     * If SEIZE failed with EPERM (Operation not permitted), the target
     * likely has anti-debug protection (e.g., prctl PR_SET_DUMPABLE 0,
     * seccomp, or runtime anti-debug). ATTACH will also fail with EPERM.
     * Return special error code -2 to tell the retry loop to ABORT
     * (no point trying 666 regions if ptrace is blocked). */
    if (errno == EPERM) {
      INJ_ERR("PTRACE_SEIZE: %s — ptrace blocked by target (seccomp/PR_SET_DUMPABLE)", strerror(errno));
      return -2; /* special: abort retry loop */
    }
    INJ_LOG("PTRACE_SEIZE failed: %s — falling back to ATTACH", strerror(errno));
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
      if (errno == EPERM) {
        INJ_ERR("ptrace ATTACH: %s — ptrace blocked by target", strerror(errno));
        return -2; /* special: abort retry loop */
      }
      INJ_ERR("ptrace ATTACH: %s", strerror(errno));
      return -1;
    }
    if (waitpid(pid, NULL, __WALL) < 0) {
      INJ_ERR("waitpid: %s", strerror(errno));
      return -1;
    }
    /* Single-thread fallback — only the main thread is available. */
    all_tids = malloc(sizeof(pid_t));
    if (all_tids) {
      all_tids[0] = pid;
      n_tids = 1;
    }
    INJ_OK("Attached via ATTACH (single-thread — multithread targets may SIGSEGV)");
  }

  /* ── Pick the best thread for injection ──
   * Skip threads in blocking syscalls — PTRACE_SETREGS can't redirect
   * RIP while a thread is in a syscall. The kernel ignores RIP changes
   * until the syscall returns, so the shellcode would never execute.
   * This is the root cause of the "Process stopped with signal 11"
   * failures on multithreaded targets like eglgears_wayland and osu!.
   *
   * Strategy:
   *   1. Pick the first thread NOT in a syscall (via /proc/<tid>/syscall,
   *      read BEFORE attach — post-attach reads are unreliable).
   *   2. If ALL threads appear to be in syscalls, use wait_for_syscall_exit()
   *      on the main thread — this uses PTRACE_SYSCALL + PTRACE_GET_SYSCALL_INFO
   *      to block until the thread hits a syscall boundary, no polling.
   *      The thread will be stopped at syscall-exit, ready for SETREGS.
   *   3. If wait_for_syscall_exit() fails, fall back to main thread
   *      (best effort — the retry loop will try another region). */
  pid_t inj_tid = pid; /* default: main thread */
  size_t n_in_syscall = 0;
  int syscall_wait_done = 0;

  if (all_tids && n_tids > 0) {
    for (size_t i = 0; i < n_tids; i++) {
      if (thread_in_syscall(all_tids[i])) {
        n_in_syscall++;
        continue;
      }
      inj_tid = all_tids[i];
      break;
    }
  }

  /* If all threads are in syscall, use PTRACE_SYSCALL to wait for
   * ANY thread to exit its syscall. Try each thread until one succeeds.
   * This is the correct ptrace way — polling /proc/<tid>/syscall doesn't
   * work post-attach because the thread is already stopped.
   *
   * PTRACE_SYSCALL + waitpid blocks until the next syscall boundary,
   * which is usually within a few ms for event-loop apps. We try each
   * thread with a short timeout so we don't hang on truly blocking
   * syscalls (e.g., futex with no timeout).
   *
   * NOTE: all_tids[0] is usually == pid (main thread), so if it succeeds
   * we set inj_tid = pid but mark syscall_wait_done = 1 to distinguish
   * from the "no thread succeeded" fallback case. */
  if (n_in_syscall == n_tids && n_tids > 0 && thread_wait_ms > 0) {
    INJ_LOG("All %zu thread(s) in syscall — trying PTRACE_SYSCALL on each "
            "(timeout %d ms per thread)",
            n_tids, thread_wait_ms);

    /* Try each thread with PTRACE_SYSCALL until one exits its syscall.
     * Use a per-thread timeout so we don't hang on futex/poll forever. */
    int per_thread_timeout = thread_wait_ms;
    if (per_thread_timeout > 500)
      per_thread_timeout = 500; /* cap */

    for (size_t i = 0; i < n_tids; i++) {
      if (wait_for_syscall_exit(all_tids[i], per_thread_timeout) == 0) {
        inj_tid = all_tids[i];
        syscall_wait_done = 1;
        INJ_LOG("Thread %d reached syscall-exit — ready for injection", inj_tid);
        break;
      }
    }

    if (!syscall_wait_done) {
      INJ_LOG("No thread exited syscall within timeout — using main thread "
              "(best effort, retry loop will try next region)");
    }
  }

  if (syscall_wait_done) {
    INJ_LOG("Using thread %d (waited for syscall exit)", inj_tid);
  } else if (inj_tid != pid) {
    INJ_LOG("Selected thread %d for injection (not in syscall)", inj_tid);
  } else if (n_in_syscall > 0) {
    INJ_LOG("All %zu thread(s) still in syscall after wait — using main thread "
            "(best effort, retry loop will try next region)",
            n_tids);
  }

  /* ── Save registers of the chosen thread ── */
  SyringeArchRegs regs_orig, regs_new;
  if (syringe_arch_getregs(inj_tid, &regs_orig) < 0) {
    /* "No such process" means the thread died between attach and
     * GETREGS — common on runtimes with anti-debug (e.g., .NET CoreCLR,
     * Java JVM, anti-cheat) which kill ptraced threads.
     * Return -2 to abort the retry loop: target has likely set
     * PR_SET_DUMPABLE=0, so further attempts will EPERM anyway. */
    if (errno == ESRCH) {
      INJ_ERR("ptrace GETREGS (tid %d): thread died (anti-debug)", inj_tid);
      ptrace(PTRACE_DETACH, pid, NULL, NULL);
      free(all_tids);
      return -2; /* abort retry loop */
    }
    INJ_ERR("ptrace GETREGS (tid %d): %s", inj_tid, strerror(errno));
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    free(all_tids);
    return -1;
  }
  INJ_LOG("Original RIP: 0x%lx RSP: 0x%lx (tid %d)", syringe_arch_get_pc(&regs_orig), syringe_arch_get_sp(&regs_orig),
          inj_tid);

  /* ── Backup original memory at injection site ── */
  unsigned char orig_mem[512];
  remote_read_bytes(pid, inject_addr, orig_mem, sc_len);

  /* ── Write shellcode ── */
  remote_write_bytes(pid, inject_addr, sc, sc_len);
  INJ_LOG("Shellcode written to 0x%lx", inject_addr);

  /* ── Redirect PC -> shellcode (+ entry_skip for ptrace restart quirk) ── */
  memcpy(&regs_new, &regs_orig, sizeof(regs_orig));
  syringe_arch_set_pc(&regs_new, inject_addr + syringe_arch_entry_skip());
  if (syringe_arch_setregs(inj_tid, &regs_new) < 0) {
    INJ_ERR("ptrace SETREGS (tid %d): %s", inj_tid, strerror(errno));
    /* Restore memory before detaching */
    remote_write_bytes(pid, inject_addr, orig_mem, sc_len);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    free(all_tids);
    return -1;
  }

  /* ── Continue and wait for trap (SIGTRAP) ──
   *
   * In multi-threaded targets, other threads may send signals.
   * If we get SIGSEGV, the shellcode may have crashed — but dlopen
   * might have already succeeded (library loaded, constructor may
   * have run). Best effort: restore original state and detach,
   * let the process continue. Report success if library was loaded. */
  INJ_LOG("Running shellcode in thread %d ...", inj_tid);
  if (ptrace(PTRACE_CONT, inj_tid, NULL, NULL) < 0) {
    INJ_ERR("ptrace CONT (tid %d): %s", inj_tid, strerror(errno));
    remote_write_bytes(pid, inject_addr, orig_mem, sc_len);
    syringe_arch_setregs(inj_tid, &regs_orig);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    free(all_tids);
    return -1;
  }

  int status;
  if (waitpid(inj_tid, &status, __WALL) < 0) {
    INJ_ERR("waitpid (shellcode, tid %d): %s", inj_tid, strerror(errno));
    remote_write_bytes(pid, inject_addr, orig_mem, sc_len);
    syringe_arch_setregs(inj_tid, &regs_orig);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    free(all_tids);
    return -1;
  }

  int rc = 0;
  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
    INJ_OK("Shellcode executed (SIGTRAP received from tid %d)", inj_tid);
  } else if (WIFSTOPPED(status)) {
    /* SIGSEGV or other signal — shellcode may have crashed.
     * But dlopen might have succeeded before the crash.
     * Restore state and detach — let the process continue.
     * The library constructor will run if dlopen completed.
     * Return -1 so the retry loop can try another region. */
    INJ_ERR_PRINT("Thread %d stopped with signal %d (expected SIGTRAP) — "
                  "region 0x%lx (%s) failed\n",
                  inj_tid, WSTOPSIG(status), inject_addr, region_name ? region_name : "?");
    INJ_ERR_PRINT("Restoring state and detaching\n");
    rc = -1;
  } else if (WIFSIGNALED(status)) {
    INJ_ERR_PRINT("Thread %d killed by signal %d\n", inj_tid, WTERMSIG(status));
    free(all_tids);
    return -1;
  } else {
    INJ_ERR_PRINT("Unexpected wait status: 0x%x\n", status);
    rc = -1;
  }

  /* ── Restore original memory and registers ── */
  remote_write_bytes(pid, inject_addr, orig_mem, sc_len);
  if (syringe_arch_setregs(inj_tid, &regs_orig) < 0) {
    INJ_ERR("ptrace SETREGS (restore, tid %d): %s", inj_tid, strerror(errno));
    rc = -1;
  } else {
    INJ_OK("Original state restored (RIP=0x%lx)", syringe_arch_get_pc(&regs_orig));
  }

  /* ── Detach ──
   * For SEIZE: PTRACE_DETACH on the main thread automatically resumes
   * all other threads (they share the same ptrace stop state).
   * For ATTACH fallback: same PTRACE_DETACH works. */
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
    INJ_ERR("ptrace DETACH: %s", strerror(errno));
    rc = -1;
  }
  free(all_tids);
  if (rc == 0) {
    INJ_OK("Detached. Library injected successfully.");
  }
  return rc;
}

/*
 * Resolve dlopen address in the target process. Tries libdl first, then
 * libc (modern glibc bakes dlopen into libc).
 * Returns 0 on failure.
 */
static unsigned long resolve_remote_dlopen(pid_t pid) {
  unsigned long addr = find_remote_sym(pid, "libdl", "__dlopen");
  if (!addr)
    addr = find_remote_sym(pid, "libdl", "dlopen");
  if (!addr)
    addr = find_remote_sym(pid, "libc", "__dlopen");
  if (!addr)
    addr = find_remote_sym(pid, "libc", "dlopen");
  if (!addr) {
    INJ_ERR("Cannot find dlopen in target process. "
            "Make sure the target links against libc/libdl.");
  }
  return addr;
}

int syringe_inject_with_retry(pid_t pid, const char *so_path, int max_retries, int retry_delay_ms) {
  /* ── 1. Resolve absolute path ── */
  char abs_path[PATH_MAX];

  if (so_path[0] == '/') {
    strncpy(abs_path, so_path, sizeof(abs_path) - 1);
    abs_path[sizeof(abs_path) - 1] = '\0';
  } else if (so_path[0] == '.') {
    if (!realpath(so_path, abs_path)) {
      INJ_ERR("realpath '%s': %s", so_path, strerror(errno));
      return -1;
    }
  } else {
    char candidate[PATH_MAX];
    int found = 0;

    /* Try CWD */
    snprintf(candidate, sizeof(candidate), "./%s", so_path);
    if (realpath(candidate, abs_path))
      found = 1;

    /* Try each directory in LD_LIBRARY_PATH */
    int has_usr_local_lib = 0, has_usr_lib = 0;
    const char *ld_lib = getenv("LD_LIBRARY_PATH");
    if (!found && ld_lib && ld_lib[0]) {
      char ld_buf[PATH_MAX];
      strncpy(ld_buf, ld_lib, sizeof(ld_buf) - 1);
      ld_buf[sizeof(ld_buf) - 1] = '\0';
      char *saveptr, *dir = strtok_r(ld_buf, ":", &saveptr);
      while (dir && !found) {
        if (strcmp(dir, "/usr/local/lib") == 0)
          has_usr_local_lib = 1;
        if (strcmp(dir, "/usr/lib") == 0)
          has_usr_lib = 1;
        snprintf(candidate, sizeof(candidate), "%s/%s", dir, so_path);
        if (realpath(candidate, abs_path))
          found = 1;
        dir = strtok_r(NULL, ":", &saveptr);
      }
    }

    /* Fallback to standard paths not already covered by LD_LIBRARY_PATH */
    if (!found) {
      const char *fallback[2];
      int n = 0;
      if (!has_usr_local_lib)
        fallback[n++] = "/usr/local/lib";
      if (!has_usr_lib)
        fallback[n++] = "/usr/lib";
      for (int i = 0; i < n && !found; i++) {
        snprintf(candidate, sizeof(candidate), "%s/%s", fallback[i], so_path);
        if (access(candidate, F_OK) == 0) {
          strncpy(abs_path, candidate, sizeof(abs_path) - 1);
          abs_path[sizeof(abs_path) - 1] = '\0';
          found = 1;
        }
      }
    }

    if (!found) {
      INJ_ERR("library '%s' not found in CWD, LD_LIBRARY_PATH, /usr/local/lib, or /usr/lib", so_path);
      return -1;
    }
  }
  INJ_LOG("Injecting: %s", abs_path);

  /* ── 2. Find dlopen in target ── */
  unsigned long dlopen_addr = resolve_remote_dlopen(pid);
  if (!dlopen_addr)
    return -1;

  /* ── 3. Find ALL executable regions ── */
  size_t n_regions = 0;
  MapEntry *regions = find_all_maps(pid, "rx", &n_regions);
  if (!regions || n_regions == 0) {
    INJ_ERR("No executable mapping found in target");
    free(regions);
    return -1;
  }

  /* max_retries semantics:
   *   max_retries > 0 : try at most max_retries regions
   *   max_retries == 0: try only the first region (legacy behavior)
   *   max_retries < 0 : try ALL regions (unlimited) */
  size_t attempts;
  if (max_retries < 0) {
    attempts = n_regions;
    INJ_LOG("Will try all %zu executable region(s) (unlimited retries)", n_regions);
  } else {
    attempts = (size_t)max_retries;
    if (attempts > n_regions)
      attempts = n_regions;
    if (attempts == 0)
      attempts = 1; /* always try at least once */
    INJ_LOG("Will try up to %zu region(s) out of %zu available", attempts, n_regions);
  }

  /* thread_wait_ms: how long to wait (per attempt) for a thread to exit
   * a blocking syscall before giving up on that region. Set to 10× the
   * retry delay so each region attempt gets a fair chance to catch a
   * thread off-syscall before moving on. Default 500ms is enough for
   * most event-loop apps (they cycle through syscalls every few ms). */
  int thread_wait_ms = retry_delay_ms * 10;
  if (thread_wait_ms < 100)
    thread_wait_ms = 100; /* floor: 100ms */
  if (thread_wait_ms > 2000)
    thread_wait_ms = 2000; /* ceiling: 2s */

  /* ── 4. Try each region ── */
  for (size_t i = 0; i < attempts; i++) {
    INJ_LOG("Attempt %zu/%zu: region 0x%lx-0x%lx (%s)", i + 1, attempts, regions[i].start, regions[i].end,
            regions[i].name[0] ? regions[i].name : "anonymous");

    int rc = syringe_inject_at(pid, abs_path, dlopen_addr, regions[i].start, regions[i].name, thread_wait_ms);
    if (rc == 0) {
      free(regions);
      return 0; /* success! */
    }

    /* rc == -2 means EPERM — target has anti-debug protection.
     * No point trying more regions, abort immediately. */
    if (rc == -2) {
      INJ_ERR("Anti-debug protection detected — aborting retry loop "
              "(attempted %zu/%zu regions)",
              i + 1, attempts);
      free(regions);
      return -1;
    }

    INJ_LOG("Region 0x%lx failed, %s", regions[i].start, (i + 1 < attempts) ? "trying next" : "no more regions to try");

    /* Delay between attempts to let the target recover from any
     * partial ptrace state. Default 100ms is enough for the kernel
     * to clean up without being noticeable to the user. */
    if (i + 1 < attempts && retry_delay_ms > 0) {
      usleep(retry_delay_ms * 1000);
    }
  }

  INJ_ERR("All %zu attempt(s) failed", attempts);
  free(regions);
  return -1;
}

int syringe_inject(pid_t pid, const char *so_path) {
  /* Auto-detect: if target has a .NET diagnostic socket, use that path
   * (bypasses ptrace + anti-debug). Otherwise, use ptrace with retry.
   *
   * .NET diagnostic socket: /tmp/dotnet-diagnostic-{pid}-*-socket
   * If present, target is a .NET process with diagnostics enabled.
   * Using syringe_inject_dotnet avoids EPERM from .NET anti-debug. */
  char dotnet_socket[128];
  if (syringe_dotnet_find_socket(pid, dotnet_socket, sizeof(dotnet_socket)) == 0) {
    INJ_LOG("Detected .NET diagnostic socket — using diagnostic IPC "
            "(bypasses ptrace + anti-debug)");
    return syringe_inject_dotnet(pid, so_path);
  }

  /* Default: ptrace path — try up to 3 regions with 100ms delay.
   * This handles most cases without the 66s+ hang of unlimited retries.
   *
   * The thread-wait logic in syringe_inject_at handles the common
   * "all threads in syscall" case by waiting up to 1s for a thread to
   * exit, so we rarely need more than 1-2 region attempts.
   *
   * Callers that want different behavior should call
   * syringe_inject_with_retry directly:
   *   syringe_inject_with_retry(pid, so, -1, 100)  // all regions
   *   syringe_inject_with_retry(pid, so, 1, 0)     // single attempt, no wait
   */
  return syringe_inject_with_retry(pid, so_path, 3, 100);
}
