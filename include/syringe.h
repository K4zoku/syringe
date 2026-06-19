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
 * @param pid       Target process ID (must be ptrace-accessible)
 * @param so_path   Absolute or relative path to the .so file to inject.
 *                  Will be resolved to an absolute path via realpath().
 * @return          0 on success, -1 on failure (check errno or printed errors).
 */
int syringe_inject(pid_t pid, const char *so_path);

#ifdef __cplusplus
}
#endif

#endif /* SYRINGE_H */
