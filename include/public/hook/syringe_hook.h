/**
 * syringe_hook.h — Header-only in-process GOT/PLT + inline hooker
 *
 * #include this from exactly one .c file per .so. All functions are
 * static inline; each TU gets its own private hook registry.
 *
 * Hook strategies (tried in order):
 *   1. GOT/PLT patch — overwrites GOT entries in every loaded module.
 *   2. Inline trampoline — overwrites function prologue with JMP to hook.
 *   3. dlsym fallback — stores dlsym address when no GOT importers found.
 *
 * Configuration (define BEFORE #include):
 *   SYRINGE_HOOK_MAX=N      Registry capacity (default: 32)
 *   SYRINGE_HOOK_NO_HELPERS Strip remove/count/is_installed to debloat
 *   SYRINGE_HOOK_QUIET      Disable log output
 *
 * Architecture support: x86-64 and aarch64 have full disasm+trampoline.
 * arm32/riscv64 fall back to GOT-only patching.
 *
 * Usage:
 *   #define _GNU_SOURCE
 *   #include <syringe/hook/syringe_hook.h>
 *   int n = syringe_hook_install("open", my_hook, &orig);
 */

#ifndef SYRINGE_HOOK_H
#define SYRINGE_HOOK_H

#ifndef _GNU_SOURCE
#warning "syringe_hook: _GNU_SOURCE not defined — define it before including this header"
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <elf.h>
#include <link.h>      /* struct dl_phdr_info for syringe_hook_phdr_cb */
#include <dlfcn.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SYRINGE_HOOK_MAX
#define SYRINGE_HOOK_MAX 32
#endif

#ifdef SYRINGE_HOOK_QUIET
#define SYRINGE_HOOK_LOG(fmt, ...) ((void)0)
#else
#include <stdarg.h>

static void syringe_hook_log_real(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fflush(stderr);
}

static void syringe_hook_log_nop(const char *fmt, ...) { (void)fmt; }

static void (*syringe_hook_log_fn)(const char *fmt, ...) = syringe_hook_log_nop;
static int syringe_hook_log_ready = 0;

static inline void syringe_hook_log_init(void) {
    syringe_hook_log_ready = 1;
    const char *e = getenv("SYRINGE_HOOK_DEBUG");
    if (e && e[0] != '\0')
        syringe_hook_log_fn = syringe_hook_log_real;
}

#define SYRINGE_HOOK_LOG(fmt, ...) \
    do { \
        if (!syringe_hook_log_ready) syringe_hook_log_init(); \
        syringe_hook_log_fn("[syringe_hook] " fmt "\n", ##__VA_ARGS__); \
    } while (0)
#endif

/* ══════════════════════════════════════════════════════════════════════════
 *  ARCH DISPATCH — include arch-specific backend first
 * ══════════════════════════════════════════════════════════════════════════
 *
 * The arch header MUST define:
 *   - TRAMP_JMP_SZ, TRAMP_STOLEN_MAX, TRAMP_BOUNCE_MAX constants
 *   - syringe_hook_arch_build_jmp()
 *   - syringe_hook_arch_disasm()
 *   - syringe_hook_arch_tramp_make()
 *   - syringe_hook_arch_atomic_patch_jmp()
 *
 * See include/hook/arch/syringe_hook_arch.h for the contract.
 */
#if defined(__x86_64__) && defined(__LP64__)
  #include "arch/syringe_hook_x86_64.h"
#elif defined(__aarch64__)
  #include "arch/syringe_hook_aarch64.h"
#elif defined(__arm__)
  #include "arch/syringe_hook_arm.h"
#elif defined(__riscv) && __riscv_xlen == 64
  #include "arch/syringe_hook_riscv64.h"
#else
  #warning "syringe_hook: unsupported architecture — only GOT/PLT patching will work"
  /* Provide stubs so the common code compiles. tramp_install will fail
   * gracefully and install() will fall back to GOT-only mode. */
  #define TRAMP_JMP_SZ     16
  #define TRAMP_STOLEN_MAX 32
  #define TRAMP_BOUNCE_MAX (TRAMP_STOLEN_MAX + TRAMP_JMP_SZ)
  #define BOUNCE_SZ        TRAMP_BOUNCE_MAX
  #include "syringe_hook_types.h"
  static inline void syringe_hook_arch_build_jmp(uint8_t *buf, void *dest) {
    (void)buf; (void)dest;
  }
  static inline size_t syringe_hook_arch_disasm(const uint8_t *code, int *reloc) {
    (void)code; (void)reloc; return 0;
  }
  static inline size_t syringe_hook_arch_tramp_make(uint8_t *b, size_t c,
                                                     const void *t, size_t *cp) {
    (void)b; (void)c; (void)t; (void)cp; return 0;
  }
  static inline int syringe_hook_arch_atomic_patch_jmp(void *t, const uint8_t *j) {
    (void)t; (void)j; return -1;
  }
#endif

/* ══════════════════════════════════════════════════════════════════════════
 *  COMMON FRAMEWORK — registry, GOT walk, public API
 * ══════════════════════════════════════════════════════════════════════════ */
#include "syringe_hook_common.h"

#ifdef __cplusplus
}
#endif

#endif /* SYRINGE_HOOK_H */
