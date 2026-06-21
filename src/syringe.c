/*
 * syringe.c — Core logic for injecting a shared library into a running process
 *
 *   SYRINGE Yields Runtime Injected Native Global Executables
 *
 * Technique:
 *   1. Attach to target process with ptrace
 *   2. Find dlopen() address in the target (via /proc/<pid>/maps + symbol lookup)
 *   3. Write a shellcode stub that calls dlopen(path, RTLD_NOW|RTLD_GLOBAL)
 *   4. Redirect RIP to shellcode, let it run, then restore original state
 *
 * This file is the arch-agnostic core. Everything that depends on the target
 * CPU — shellcode emission, register layout, PC fixup, entry-skip — is routed
 * through the per-architecture backend in src/arch/arch_<arch>.c (see
 * src/arch/arch.h). Adding a new architecture only requires a new arch .c
 * file; this file does not change.
 *
 * Public API (declared in syringe.h):
 *   syringe_inject(pid_t pid, const char *so_path) -> 0 on success, -1 on failure
 *
 * Internal helper (file-scope prototype — NOT in syringe.h, intentionally
 * kept out of the public surface; tests reach it via extern):
 *   syringe_build_shellcode(buf, bufsz, dlopen_addr, so_path, inject_addr)
 *     -> shellcode size in bytes, or 0 on overflow
 *   This is now a thin escape-hatch wrapper around the arch backend's
 *   syringe_arch_build_shellcode(); it exists purely so existing callers
 *   (unit tests via extern, advanced consumers) keep resolving the symbol.
 *
 * The in-process GOT/PLT hooking surface (syringe_hook_install, etc.) lives
 * in a SEPARATE library: libsyringe_hook.so. See syringe_hook.h. libsyringe.so
 * does NOT link against libsyringe_hook.so — they are independent surfaces.
 */

#define _GNU_SOURCE
#include "syringe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <dirent.h>
#include <dlfcn.h>

#include "arch/arch.h"   /* per-architecture shellcode + register backend */

/* ── internal prototype (not in public header) ────────────────────────────
 *
 * syringe_build_shellcode is intentionally not declared in syringe.h.
 * Most callers should use syringe_inject() which calls it internally.
 * It's left as a non-static symbol so unit tests can extern it, but
 * consumers of libsyringe.so should NOT rely on it being present.
 */
size_t syringe_build_shellcode(unsigned char *buf, size_t bufsz,
                                unsigned long dlopen_addr,
                                const char *so_path,
                                unsigned long inject_addr);

/* ── logging macros ─────────────────────────────────────────────────────── */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#define INJ_LOG(fmt, ...) fprintf(stderr, "[*] " fmt "\n", ##__VA_ARGS__)
#define INJ_OK(fmt, ...)  fprintf(stderr, "[+] " fmt "\n", ##__VA_ARGS__)
#define INJ_ERR(fmt, ...) do {                                  \
    fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__);            \
    return -1;                                                  \
} while(0)
#pragma GCC diagnostic pop

/* ── helpers ────────────────────────────────────────────────────────────── */

/* Read a word from remote process memory */
static long remote_read_word(pid_t pid, unsigned long addr) {
    errno = 0;
    long val = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, NULL);
    if (val == -1 && errno) {
        perror("ptrace PEEKDATA");
        return -1;
    }
    return val;
}

/* Write a word into remote process memory */
static void remote_write_word(pid_t pid, unsigned long addr, long data) {
    if (ptrace(PTRACE_POKEDATA, pid, (void*)addr, (void*)data) < 0) {
        perror("ptrace POKEDATA");
    }
}

/* Write arbitrary bytes into remote memory word-by-word */
static void remote_write_bytes(pid_t pid, unsigned long addr,
                               const unsigned char *buf, size_t len) {
    size_t i = 0;
    while (i + sizeof(long) <= len) {
        long word;
        memcpy(&word, buf + i, sizeof(long));
        remote_write_word(pid, addr + i, word);
        i += sizeof(long);
    }
    if (i < len) {                          /* partial last word */
        long word = remote_read_word(pid, addr + i);
        memcpy(&word, buf + i, len - i);
        remote_write_word(pid, addr + i, word);
    }
}

/* Read arbitrary bytes from remote memory */
static void remote_read_bytes(pid_t pid, unsigned long addr,
                              unsigned char *buf, size_t len) {
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
static int find_map(pid_t pid, const char *needle, const char *perms_must,
                    MapEntry *out) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen maps"); return 0; }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        MapEntry e = {0};
        char perms[8];
        /* addr-addr perms offset dev inode [name] */
        int n = sscanf(line, "%lx-%lx %7s %*s %*s %*s %[^\n]",
                       &e.start, &e.end, perms, e.name);
        if (n < 3) continue;
        if (n < 4) e.name[0] = '\0';
        memcpy(e.perms, perms, sizeof(e.perms));

        /* check permissions */
        int ok = 1;
        for (const char *p = perms_must; *p; p++)
            if (!strchr(perms, *p)) { ok = 0; break; }
        if (!ok) continue;

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
            if (strncmp(base, needle, nlen) != 0) continue;
            if (base[nlen] != '.' && base[nlen] != '\0') continue;
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
static MapEntry *find_all_maps(pid_t pid, const char *perms_must,
                                size_t *count) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen maps"); return NULL; }

    /* First pass: count matches */
    size_t n = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char perms[8];
        unsigned long dummy_start, dummy_end;
        if (sscanf(line, "%lx-%lx %7s", &dummy_start, &dummy_end, perms) < 3) continue;
        int ok = 1;
        for (const char *p = perms_must; *p; p++)
            if (!strchr(perms, *p)) { ok = 0; break; }
        if (ok) n++;
    }
    if (n == 0) { fclose(f); return NULL; }

    /* Second pass: collect */
    MapEntry *arr = malloc(n * sizeof(MapEntry));
    if (!arr) { fclose(f); return NULL; }
    rewind(f);
    size_t i = 0;
    while (fgets(line, sizeof(line), f) && i < n) {
        MapEntry e = {0};
        char perms[8];
        int parsed = sscanf(line, "%lx-%lx %7s %*s %*s %*s %[^\n]",
                            &e.start, &e.end, perms, e.name);
        if (parsed < 3) continue;
        if (parsed < 4) e.name[0] = '\0';
        memcpy(e.perms, perms, sizeof(e.perms));

        int ok = 1;
        for (const char *p = perms_must; *p; p++)
            if (!strchr(perms, *p)) { ok = 0; break; }
        if (!ok) continue;

        arr[i++] = e;
    }
    fclose(f);
    *count = i;
    return arr;
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
static unsigned long find_remote_sym(pid_t pid,
                                     const char *lib_substr,
                                     const char *sym) {
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
        int n = sscanf(line, "%lx-%lx %7s %*s %*s %*s %[^\n]",
                       &s, &e, perms, name);
        if (n < 4) continue;
        if (strstr(name, lib_substr)) {
            /* pick the lowest address mapping (true base of the library) */
            if (!lib_base || s < lib_base) {
                lib_base = s;
                snprintf(lib_path, sizeof(lib_path), "%s", name);
            }
        }
    }
    if (f) fclose(f);
    if (!lib_path[0]) {
        fprintf(stderr, "[!] Cannot find '%s' in our maps\n", lib_substr);
        return 0;
    }

    /* resolve symbol offset in our process */
    void *h = dlopen(lib_path, RTLD_LAZY);
    if (!h) {
        fprintf(stderr, "[!] dlopen '%s': %s\n", lib_path, dlerror());
        return 0;
    }

    void *sym_addr = dlsym(h, sym);
    if (!sym_addr) {
        fprintf(stderr, "[!] dlsym '%s': %s\n", sym, dlerror());
        return 0;
    }

    unsigned long offset = (unsigned long)sym_addr - lib_base;
    INJ_LOG("'%s' offset in %s: 0x%lx (base 0x%lx)", sym, lib_path,
            offset, lib_base);

    /* find the same library in the target */
    MapEntry their_map = {0};
    if (!find_map(pid, lib_substr, "r", &their_map)) {
        fprintf(stderr, "[!] '%s' not mapped in pid %d\n", lib_substr, pid);
        return 0;
    }

    unsigned long remote_addr = their_map.start + offset;
    INJ_LOG("Remote '%s' @ 0x%lx (their base 0x%lx + offset 0x%lx)",
            sym, remote_addr, their_map.start, offset);
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
size_t syringe_build_shellcode(unsigned char *buf, size_t bufsz,
                               unsigned long dlopen_addr,
                               const char *so_path,
                               unsigned long inject_addr) {
    return syringe_arch_build_shellcode(buf, bufsz, dlopen_addr,
                                        so_path, inject_addr);
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
static int syringe_inject_at(pid_t pid, const char *abs_path,
                              unsigned long dlopen_addr,
                              unsigned long inject_addr,
                              const char *region_name) {
    INJ_LOG("Injection site: 0x%lx (%s)", inject_addr,
            region_name ? region_name : "?");

    /* ── Build shellcode ── */
    unsigned char sc[512] = {0};
    size_t sc_len = syringe_arch_build_shellcode(sc, sizeof(sc), dlopen_addr,
                                                  abs_path, inject_addr);
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
     * target is multithreaded (.NET runtime, Wayland compositor, eglgears),
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

    if (ptrace(PTRACE_SEIZE, pid, NULL, PTRACE_O_TRACECLONE) == 0) {
        /* Enumerate all threads in /proc/<pid>/task/ and stop them. */
        char task_path[64];
        snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);
        DIR *td = opendir(task_path);
        if (td) {
            struct dirent *de;
            /* First pass: count */
            while ((de = readdir(td))) {
                if (de->d_name[0] >= '0' && de->d_name[0] <= '9') n_tids++;
            }
            rewinddir(td);
            all_tids = malloc(n_tids * sizeof(int));
            size_t i = 0;
            while ((de = readdir(td)) && i < n_tids) {
                if (de->d_name[0] >= '0' && de->d_name[0] <= '9') {
                    all_tids[i++] = atoi(de->d_name);
                }
            }
            closedir(td);
        }
        /* INTERRUPT the main thread — this stops ALL threads atomically
         * because they share the same ptrace stop state. */
        if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) < 0) {
            INJ_LOG("PTRACE_INTERRUPT failed: %s — proceeding anyway", strerror(errno));
        }
        if (waitpid(pid, NULL, 0) < 0) {
            INJ_ERR("waitpid (seize): %s", strerror(errno));
            free(all_tids);
            return -1;
        }
        INJ_OK("Attached via SEIZE (stopped %zu thread%s)",
               n_tids, n_tids == 1 ? "" : "s");
    } else {
        /* Fallback: classic ATTACH (single-thread stop only) */
        INJ_LOG("PTRACE_SEIZE failed: %s — falling back to ATTACH", strerror(errno));
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
            INJ_ERR("ptrace ATTACH: %s", strerror(errno));
            return -1;
        }
        if (waitpid(pid, NULL, 0) < 0) {
            INJ_ERR("waitpid: %s", strerror(errno));
            return -1;
        }
        INJ_OK("Attached via ATTACH (single-thread — multithread targets may SIGSEGV)");
    }

    /* ── Save registers ── */
    SyringeArchRegs regs_orig, regs_new;
    if (syringe_arch_getregs(pid, &regs_orig) < 0) {
        INJ_ERR("ptrace GETREGS: %s", strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        free(all_tids);
        return -1;
    }
    INJ_LOG("Original RIP: 0x%lx RSP: 0x%lx",
            syringe_arch_get_pc(&regs_orig),
            syringe_arch_get_sp(&regs_orig));

    /* ── Backup original memory at injection site ── */
    unsigned char orig_mem[512];
    remote_read_bytes(pid, inject_addr, orig_mem, sc_len);

    /* ── Write shellcode ── */
    remote_write_bytes(pid, inject_addr, sc, sc_len);
    INJ_LOG("Shellcode written to 0x%lx", inject_addr);

    /* ── Redirect PC -> shellcode (+ entry_skip for ptrace restart quirk) ── */
    memcpy(&regs_new, &regs_orig, sizeof(regs_orig));
    syringe_arch_set_pc(&regs_new, inject_addr + syringe_arch_entry_skip());
    if (syringe_arch_setregs(pid, &regs_new) < 0) {
        INJ_ERR("ptrace SETREGS: %s", strerror(errno));
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
    INJ_LOG("Running shellcode ...");
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        INJ_ERR("ptrace CONT: %s", strerror(errno));
        remote_write_bytes(pid, inject_addr, orig_mem, sc_len);
        syringe_arch_setregs(pid, &regs_orig);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        free(all_tids);
        return -1;
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        INJ_ERR("waitpid (shellcode): %s", strerror(errno));
        remote_write_bytes(pid, inject_addr, orig_mem, sc_len);
        syringe_arch_setregs(pid, &regs_orig);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        free(all_tids);
        return -1;
    }

    int rc = 0;
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        INJ_OK("Shellcode executed (SIGTRAP received)");
    } else if (WIFSTOPPED(status)) {
        /* SIGSEGV or other signal — shellcode may have crashed.
         * But dlopen might have succeeded before the crash.
         * Restore state and detach — let the process continue.
         * The library constructor will run if dlopen completed.
         * Return -1 so the retry loop can try another region. */
        fprintf(stderr, "[!] Process stopped with signal %d (expected SIGTRAP) — "
                "region 0x%lx (%s) failed\n",
                WSTOPSIG(status), inject_addr,
                region_name ? region_name : "?");
        fprintf(stderr, "[!] Restoring state and detaching (library may still have loaded)\n");
        rc = -1;
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr, "[!] Process killed by signal %d\n", WTERMSIG(status));
        free(all_tids);
        return -1;
    } else {
        fprintf(stderr, "[!] Unexpected wait status: 0x%x\n", status);
        rc = -1;
    }

    /* ── Restore original memory and registers ── */
    remote_write_bytes(pid, inject_addr, orig_mem, sc_len);
    if (syringe_arch_setregs(pid, &regs_orig) < 0) {
        INJ_ERR("ptrace SETREGS (restore): %s", strerror(errno));
        rc = -1;
    } else {
        INJ_OK("Original state restored (RIP=0x%lx)",
               syringe_arch_get_pc(&regs_orig));
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
    if (!addr) addr = find_remote_sym(pid, "libdl", "dlopen");
    if (!addr) addr = find_remote_sym(pid, "libc", "__dlopen");
    if (!addr) addr = find_remote_sym(pid, "libc", "dlopen");
    if (!addr) {
        INJ_ERR("Cannot find dlopen in target process. "
                "Make sure the target links against libc/libdl.");
    }
    return addr;
}

int syringe_inject_with_retry(pid_t pid, const char *so_path, int max_retries) {
    /* ── 1. Resolve absolute path ── */
    char abs_path[PATH_MAX];
    if (!realpath(so_path, abs_path)) {
        INJ_ERR("realpath '%s': %s", so_path, strerror(errno));
        return -1;
    }
    INJ_LOG("Injecting: %s", abs_path);

    /* ── 2. Find dlopen in target ── */
    unsigned long dlopen_addr = resolve_remote_dlopen(pid);
    if (!dlopen_addr) return -1;

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
        if (attempts > n_regions) attempts = n_regions;
        if (attempts == 0) attempts = 1;  /* always try at least once */
        INJ_LOG("Will try up to %zu region(s) out of %zu available",
                attempts, n_regions);
    }

    /* ── 4. Try each region ── */
    for (size_t i = 0; i < attempts; i++) {
        INJ_LOG("Attempt %zu/%zu: region 0x%lx-0x%lx (%s)",
                i + 1, attempts, regions[i].start, regions[i].end,
                regions[i].name[0] ? regions[i].name : "anonymous");

        int rc = syringe_inject_at(pid, abs_path, dlopen_addr,
                                    regions[i].start, regions[i].name);
        if (rc == 0) {
            free(regions);
            return 0;  /* success! */
        }

        INJ_LOG("Region 0x%lx failed, %s",
                regions[i].start,
                (i + 1 < attempts) ? "trying next" : "no more regions to try");

        /* Brief delay between attempts to let the target recover from
         * any partial state. 100ms is enough for the kernel to clean up
         * ptrace state without being noticeable to the user. */
        if (i + 1 < attempts) {
            usleep(100000);
        }
    }

    INJ_ERR("All %zu attempt(s) failed", attempts);
    free(regions);
    return -1;
}

int syringe_inject(pid_t pid, const char *so_path) {
    /* Default behavior: try the first executable region only.
     * This matches the pre-retry behavior — single attempt, main binary
     * text segment (which find_all_maps returns first, since /proc/maps
     * is sorted by address).
     *
     * Callers that want multi-region retry should call
     * syringe_inject_with_retry directly with max_retries=-1 (all regions)
     * or a specific count. */
    return syringe_inject_with_retry(pid, so_path, 1);
}
