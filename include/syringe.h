/*
 * syringe.h — Public API for syringe (cross-process injection)
 *
 *   SYRINGE Yields Runtime Injected Native Global Executables
 *
 * syringe is a ptrace-based shared-library injector for x86-64 Linux.
 * This header exposes the cross-process injection surface ONLY.
 *
 *   - syringe_inject(pid, so_path)
 *       ptrace-attach a target process, write a small shellcode stub
 *       into its text segment, redirect RIP, run dlopen(), trap, restore.
 *
 * The in-process GOT/PLT hooking surface lives in a SEPARATE library
 * (libsyringe_hook.so) and a SEPARATE header (syringe_hook.h). Typical
 * workflow: use libsyringe.so to inject a .so into a target process;
 * that .so then links libsyringe_hook.so (or copies syringe_hook.c
 * statically) and calls syringe_hook_install() in its constructor to
 * patch the target's GOT.
 *
 * Usage:
 *   #define _GNU_SOURCE   // before any system header
 *   #include "syringe.h"
 *   int rc = syringe_inject(1234, "/path/to/library.so");
 *
 * syringe does NOT require root, but the caller must have ptrace access
 * to the target (same UID, or ptrace_scope <= 1).
 */

#ifndef SYRINGE_H
#define SYRINGE_H

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Inject a shared library into a running process.
 *
 * Technique:
 *   1. Attach to target process with ptrace
 *   2. Find dlopen() address in the target (via /proc/<pid>/maps + symbol lookup)
 *   3. Write a shellcode stub that calls dlopen(path, RTLD_NOW|RTLD_GLOBAL)
 *   4. Redirect RIP to shellcode, let it run, then restore original state
 *
 * Hooks in the target process are NOT installed by this call. The injected
 * .so's __attribute__((constructor)) is responsible for calling
 * syringe_hook_install() (declared in syringe_hook.h) in the target's
 * address space. syringe_inject only loads the .so via dlopen — that's
 * enough for the constructor to fire.
 *
 * This is equivalent to `syringe_inject_with_retry(pid, so_path, 1)` —
 * tries only the first executable region (legacy behavior). Use
 * syringe_inject_with_retry for multi-region retry on hard targets.
 *
 * @param pid       Target process ID (must be ptrace-accessible)
 * @param so_path   Absolute or relative path to the .so file to inject.
 *                  Will be resolved to an absolute path via realpath().
 * @return          0 on success, -1 on failure (check errno or printed errors).
 */
int syringe_inject(pid_t pid, const char *so_path);

/**
 * Inject a shared library with multi-region retry and configurable delay.
 *
 * Same as syringe_inject, but if the first executable region fails
 * (SIGSEGV, EACCES, EAGAIN, etc.), tries the NEXT executable region
 * from /proc/<pid>/maps. This handles targets where the default region
 * is W^X-enforced, read-only, or otherwise unsuitable for shellcode.
 *
 * Regions are tried in /proc/<pid>/maps order (lowest address first),
 * which typically means: main binary text → libc → ld-linux → other libs.
 * The main binary is usually the safest to patch, so it's tried first.
 *
 * Thread-wait logic: when ALL threads are in blocking syscalls (common
 * for event-loop apps like eglgears_wayland and osu!), this function
 * waits up to `retry_delay_ms × 10` (capped at 2s) for a thread to exit
 * its syscall before giving up on that region. This avoids the need to
 * scan hundreds of regions — usually 1-2 region attempts with thread-wait
 * is enough.
 *
 * @param pid            Target process ID
 * @param so_path        Path to the .so file (resolved via realpath)
 * @param max_retries    Maximum number of regions to try:
 *                       - `> 0`: try at most max_retries regions
 *                       - `0`:   try only the first region (same as syringe_inject)
 *                       - `< 0`: try ALL executable regions (unlimited)
 * @param retry_delay_ms Delay between region attempts in milliseconds.
 *                       Also sets the thread-wait timeout (10× this value,
 *                       capped at 2s). 0 = no delay (fast but may fail
 *                       on multithreaded targets). 100 is a good default.
 * @return               0 on success, -1 if all attempts failed
 */
int syringe_inject_with_retry(pid_t pid, const char *so_path,
                               int max_retries, int retry_delay_ms);

/**
 * Inject a shared library into a running .NET process via diagnostic IPC.
 *
 * Uses the .NET CoreCLR Diagnostic Server (not ptrace) to attach a profiler
 * .so. This bypasses anti-debug techniques that block ptrace:
 *   - prctl(PR_SET_DUMPABLE, 0)
 *   - seccomp filters on ptrace
 *   - .NET runtime anti-debug
 *
 * Works on .NET Core 3.0+ and .NET 5+. Target must have diagnostics enabled
 * (default; disabled via DOTNET_EnableDiagnostics=0 env var).
 *
 * @param pid     Target .NET process ID
 * @param so_path Path to the library to inject
 * @return        0 on success, -1 on failure
 *
 * Note: the .so must be a valid .NET COM profiler (export DllGetClassObject
 * and implement ICorProfilerCallback). For regular .so injection, use the
 * syringe-dotnet-profiler.so wrapper (TODO: not yet implemented).
 */
int syringe_inject_dotnet(pid_t pid, const char *so_path);

/* ── Verbose logging control ──────────────────────────────────────────────
 *
 * Set to 1 to enable info logging (INJ_LOG/INJ_OK). Default: 0 (silent).
 * The CLI sets this via -v/--verbose flag. Library callers can set directly.
 */
extern int syringe_verbose;

#ifdef __cplusplus
}
#endif

#endif /* SYRINGE_H */
