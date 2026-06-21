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
#include <sys/types.h>

#include "syringe.h"

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
        "                    (default: 1 = first region only)\n"
        "                    Use -1 or 'all' to try every region\n\n"
        "Examples:\n"
        "  syringe-cli 10024 ./liboverlay.so\n"
        "  syringe-cli --quiet 10024 /usr/local/lib/libhook.so\n"
        "  syringe-cli --retry all 10024 ./liboverlay.so   # try every region\n"
        "  syringe-cli -r 5 10024 ./liboverlay.so          # try up to 5 regions\n\n"
        "Notes:\n"
        "  - Run as root, or with the same UID as the target process\n"
        "  - Requires ptrace_scope <= 1 "
          "(check /proc/sys/kernel/yama/ptrace_scope)\n"
        "  - The target must link against libc/libdl (virtually all do)\n"
        "  - The injected .so's __attribute__((constructor)) runs on load\n"
        "  - To hook symbols in the target, the .so's constructor should\n"
        "    call got_hook_install() (declared in syringe.h)\n",
        prog);
}

/* ── quiet mode flag ───────────────────────────────────────────────────── */
static int quiet_mode = 0;
static int retry_count = 1;  /* default: try first region only */
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

    setup_quiet_mode();
    int ret = syringe_inject_with_retry(pid, so_path, retry_count);
    restore_quiet_mode();

    return (ret == 0) ? 0 : 1;
}
