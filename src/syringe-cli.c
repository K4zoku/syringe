/*
 * syringe-cli — CLI for injecting a shared library into a running process
 *
 * Usage:
 *   syringe-cli <pid> <library.so>
 *
 * Links against libsyringe.so (the public API).
 *
 * Public API (syringe.h):
 *   int syringe_inject(pid_t pid, const char *so_path);
 *   size_t syringe_build_shellcode(...);
 *
 * Hooks in the target process are NOT installed by this CLI — that's the
 * job of the injected .so's __attribute__((constructor)). The CLI only
 * does ptrace + dlopen to load the .so; the .so then runs inside the
 * target and calls got_hook_install() itself.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#ifdef HAVE_LIBCAP
#include <sys/capability.h>  /* cap_get_proc, CAP_SYS_PTRACE */
#endif

#include "syringe.h"
#include "dotnet/dotnet_diagnostic.h"  /* .NET auto-detect */

/* ── pre-flight ptrace capability check ───────────────────────────────────
 *
 * Fail fast if ptrace won't work at all, instead of trying 600+ regions
 * and getting EPERM on each. Two checks:
 *
 * 1. CAP_SYS_PTRACE capability — if present, ptrace always works regardless
 *    of yama scope. Root has this by default; non-root can be granted via
 *    `setcap cap_sys_ptrace+ep syringe-cli`.
 *
 * 2. /proc/sys/kernel/yama/ptrace_scope:
 *    0 = classic (any process can ptrace any same-UID process)
 *    1 = restricted (only parent can ptrace children, OR CAP_SYS_PTRACE)
 *    2 = admin-only (requires CAP_SYS_PTRACE)
 *    3 = no ptrace at all
 *
 * If scope >= 3 and no CAP_SYS_PTRACE → fail.
 * If scope == 2 and no CAP_SYS_PTRACE → fail.
 * If scope == 1 and no CAP_SYS_PTRACE → warn (may fail unless we're parent).
 * If scope == 0 → OK (or if CAP_SYS_PTRACE present).
 *
 * Returns 0 if OK to proceed, -1 if should abort.
 */
static int check_ptrace_capability(pid_t target_pid) {
    int has_cap_sys_ptrace = 0;

    /* Check 1: CAP_SYS_PTRACE capability. */
#ifdef HAVE_LIBCAP
    cap_t caps = cap_get_proc();
    if (caps) {
        cap_flag_value_t v = CAP_CLEAR;
        if (cap_get_flag(caps, CAP_SYS_PTRACE, CAP_EFFECTIVE, &v) == 0 && v == CAP_SET) {
            has_cap_sys_ptrace = 1;
        }
        cap_free(caps);
    }
    /* If libcap not available or cap_get_proc failed, assume no cap.
     * The yama scope check below will catch the cases that matter. */
#else
    /* Without libcap, check via /proc/self/status CapEff bit (bit 19 = CAP_SYS_PTRACE).
     * This is a fallback when libcap-dev is not installed. */
    FILE *sf = fopen("/proc/self/status", "r");
    if (sf) {
        char line[256];
        while (fgets(line, sizeof(line), sf)) {
            unsigned long cap_eff = 0;
            if (sscanf(line, "CapEff: %lx", &cap_eff) == 1) {
                /* CAP_SYS_PTRACE is capability #19 (0-indexed) */
                if (cap_eff & (1UL << 19)) {
                    has_cap_sys_ptrace = 1;
                }
                break;
            }
        }
        fclose(sf);
    }
#endif

    /* Check 2: /proc/sys/kernel/yama/ptrace_scope */
    int yama_scope = 0;  /* default: assume classic if can't read */
    FILE *f = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
    if (f) {
        if (fscanf(f, "%d", &yama_scope) != 1) yama_scope = 0;
        fclose(f);
    }

    /* Decision matrix: */
    if (has_cap_sys_ptrace) {
        /* CAP_SYS_PTRACE bypasses yama restrictions entirely. */
        fprintf(stderr, "[+] CAP_SYS_PTRACE present — ptrace will work "
                "(yama ptrace_scope=%d ignored)\n", yama_scope);
        return 0;
    }

    if (yama_scope >= 3) {
        fprintf(stderr, "[!] Kernel yama ptrace_scope=%d (no ptrace at all) "
                "and no CAP_SYS_PTRACE. Cannot inject.\n", yama_scope);
        fprintf(stderr, "    Fix: run as root, or: "
                "sudo setcap cap_sys_ptrace+ep %s\n", program_invocation_name);
        return -1;
    }

    if (yama_scope == 2) {
        fprintf(stderr, "[!] Kernel yama ptrace_scope=2 (admin-only attach) "
                "and no CAP_SYS_PTRACE. Cannot inject.\n");
        fprintf(stderr, "    Fix: run as root, or: "
                "sudo setcap cap_sys_ptrace+ep %s\n", program_invocation_name);
        return -1;
    }

    if (yama_scope == 1) {
        /* Restricted: only parent of target can ptrace, OR CAP_SYS_PTRACE.
         * Check if we're the parent (PPID of target == our PID). */
        char status_path[64];
        snprintf(status_path, sizeof(status_path), "/proc/%d/status", target_pid);
        FILE *sf = fopen(status_path, "r");
        if (sf) {
            char line[256];
            pid_t target_ppid = 0;
            while (fgets(line, sizeof(line), sf)) {
                if (sscanf(line, "PPid: %d", &target_ppid) == 1) break;
            }
            fclose(sf);
            if (target_ppid == getpid()) {
                fprintf(stderr, "[+] yama ptrace_scope=1 — we are parent of "
                        "target (ppid=%d), ptrace allowed\n", target_ppid);
                return 0;
            }
        }
        fprintf(stderr, "[!] Kernel yama ptrace_scope=1 (restricted) and no "
                "CAP_SYS_PTRACE. May fail unless we're parent of target.\n");
        fprintf(stderr, "    If injection fails with EPERM, run as root or: "
                "sudo setcap cap_sys_ptrace+ep %s\n", program_invocation_name);
        /* Don't abort — let it try, may succeed if kernel allows. */
        return 0;
    }

    /* yama_scope == 0: classic ptrace permissions. */
    fprintf(stderr, "[+] yama ptrace_scope=0 (classic) — ptrace allowed\n");
    return 0;
}

/* ── entry point ────────────────────────────────────────────────────────── */

static void print_usage(const char *prog) {
    fprintf(stderr,
        "syringe-cli — inject a shared library into a running process\n\n"
        "  SYRINGE Yields Runtime Injected Native Global Executables\n\n"
        "Usage:\n"
        "  %s [OPTIONS] <pid> <library.so>\n\n"
        "Options:\n"
        "  -q, --quiet       Suppress all output except errors\n"
        "  -r, --retry N     Try up to N executable regions on failure\n"
        "                    (default: 3)\n"
        "                    Use -1 or 'all' to try every region\n"
        "  -d, --delay MS    Delay between region attempts in ms (default: 100)\n"
        "                    Also sets thread-wait timeout (10x this value)\n\n"
        "Examples:\n"
        "  syringe-cli 10024 ./liboverlay.so\n"
        "  syringe-cli --quiet 10024 /usr/local/lib/libhook.so\n"
        "  syringe-cli --retry all 10024 ./liboverlay.so   # try every region\n"
        "  syringe-cli -r 5 10024 ./liboverlay.so          # try up to 5 regions\n"
        "  syringe-cli -r 1 -d 500 10024 ./lib.so          # 1 region, 500ms wait\n\n"
        "Notes:\n"
        "  - Run as root, or with the same UID as the target process\n"
        "  - Requires ptrace_scope <= 1 "
          "(check /proc/sys/kernel/yama/ptrace_scope)\n"
        "  - For non-root + ptrace_scope >= 1: build with -Dset-ptrace-cap=true\n"
        "    and install with: sudo meson install -C build\n"
        "  - The target must link against libc/libdl (virtually all do)\n"
        "  - The injected .so's __attribute__((constructor)) runs on load\n"
        "  - To hook symbols in the target, the .so's constructor should\n"
        "    call got_hook_install() (declared in syringe.h)\n",
        prog);
}

/* ── quiet mode flag ───────────────────────────────────────────────────── */
static int quiet_mode = 0;
static int retry_count = 3;     /* default: try up to 3 regions */
static int retry_delay_ms = 100; /* default: 100ms between attempts */
FILE *original_stderr = NULL;

static void setup_quiet_mode(void) {
    if (!quiet_mode) return;
    original_stderr = stderr;
    stderr = fopen("/dev/null", "w");
}

static void restore_quiet_mode(void) {
    if (original_stderr) {
        fclose(stderr);
        stderr = original_stderr;
    }
}

int main(int argc, char *argv[]) {
    int arg_idx = 1;

    /* parse optional flags */
    while (arg_idx < argc) {
        if (strcmp(argv[arg_idx], "-q") == 0 || strcmp(argv[arg_idx], "--quiet") == 0) {
            quiet_mode = 1;
            arg_idx++;
        } else if (strcmp(argv[arg_idx], "-r") == 0 || strcmp(argv[arg_idx], "--retry") == 0) {
            if (arg_idx + 1 >= argc) {
                fprintf(stderr, "[!] --retry requires an argument (N or 'all')\n");
                return 1;
            }
            const char *val = argv[arg_idx + 1];
            if (strcmp(val, "all") == 0) {
                retry_count = -1;  /* unlimited */
            } else {
                retry_count = atoi(val);
                if (retry_count < -1) retry_count = -1;
            }
            arg_idx += 2;
        } else if (strcmp(argv[arg_idx], "-d") == 0 || strcmp(argv[arg_idx], "--delay") == 0) {
            if (arg_idx + 1 >= argc) {
                fprintf(stderr, "[!] --delay requires an argument (ms)\n");
                return 1;
            }
            retry_delay_ms = atoi(argv[arg_idx + 1]);
            if (retry_delay_ms < 0) retry_delay_ms = 0;
            arg_idx += 2;
        } else {
            break;
        }
    }

    if ((argc - arg_idx) != 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *pid_str = argv[arg_idx];
    const char *so_path = argv[arg_idx + 1];

    pid_t pid = (pid_t)atoi(pid_str);
    if (pid <= 0) {
        fprintf(stderr, "[!] Invalid PID: %s\n", pid_str);
        return 1;
    }

    /* quick sanity check: does the process exist? */
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
    if (access(proc_path, F_OK) != 0) {
        fprintf(stderr, "[!] Process %d not found (or no permission)\n", pid);
        return 1;
    }

    /* Pre-flight: check ptrace capability + yama scope.
        * Skip if target is .NET — syringe_inject will auto-detect and use
        * diagnostic IPC (no ptrace needed, bypasses anti-debug). */
    char dotnet_sock[128];
    int is_dotnet = (syringe_dotnet_find_socket(pid, dotnet_sock, sizeof(dotnet_sock)) == 0);
    if (!is_dotnet) {
        if (check_ptrace_capability(pid) < 0) {
            return 1;
        }
    }

    setup_quiet_mode();
    /* Use syringe_inject (auto-detects .NET → diagnostic IPC, else ptrace).
     * If user specified --retry or --delay, call syringe_inject_with_retry
     * directly (but only for non-.NET targets — .NET path ignores those). */
    int ret;
    if (is_dotnet) {
        fprintf(stderr, "[+] .NET process detected — using diagnostic IPC "
                "(bypasses ptrace + anti-debug)\n");
        ret = syringe_inject_dotnet(pid, so_path);
    } else {
        ret = syringe_inject_with_retry(pid, so_path, retry_count, retry_delay_ms);
    }
    restore_quiet_mode();

    return (ret == 0) ? 0 : 1;
}
