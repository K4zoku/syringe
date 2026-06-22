/*
 * syringe_hook.h — Header-only in-process GOT/PLT + inline hooker
 *
 *   SYRINGE Yields Runtime Injected Native Global Executables
 *
 * ─────────────────────────────────────────────────────────────────────────
 *  OVERVIEW
 * ─────────────────────────────────────────────────────────────────────────
 *
 * This is a HEADER-ONLY library. There is no libsyringe_hook.so to link
 * against — just #include this header from ONE .c file in your project
 * and call the API. All functions are marked `static inline` so each
 * translation unit gets its own private copy of the hook registry.
 *
 * Three hooking strategies are tried in order:
 *
 *  1. GOT/PLT patch  — overwrite GOT entries in every loaded module.
 *                      Catches all cross-library calls.
 *                      Handles Full-RELRO via mprotect, with /proc/self/mem
 *                      as a fallback when mprotect is blocked (SELinux/seccomp).
 *                      Force-resolves lazy PLT stubs before reading orig_addr.
 *                      Handles both RELA (.rela.plt/.rela.dyn) and REL sections.
 *
 *  2. Inline trampoline — overwrites the first TRAMP_JMP_SZ bytes of the
 *                         target function with a JMP to the hook.
 *                         Catches intra-library calls (e.g. libEGL calling
 *                         itself, or SDL calling through a dlsym'd pointer).
 *                         Original prologue bytes are saved + a bounce stub
 *                         is allocated so orig() can still be called.
 *                         Uses a length-disassembler to avoid splitting
 *                         instructions, and patches PC-relative disps.
 *
 *  3. dlsym fallback   — when GOT walk finds zero entries (symbol present but
 *                         no importers), stores dlsym address as orig so the
 *                         hook can at least be wired up via trampoline.
 *
 * NOTE: syringe_hook_* operates on the CALLING process, not a remote process.
 * To hook a target process, inject a .so whose __attribute__((constructor))
 * calls syringe_hook_install() — that .so will run inside the target.
 *
 * ─────────────────────────────────────────────────────────────────────────
 *  PUBLIC API
 * ─────────────────────────────────────────────────────────────────────────
 *
 *  Installation:
 *    int syringe_hook_install(sym, hook, &orig)
 *        Hook by symbol name (GOT + inline trampoline). Returns patch count.
 *
 *    int syringe_hook_install_addr(sym, target, hook, &orig)
 *        Hook by explicit address (inline only, bypass GOT). Returns 1/0.
 *        Use when symbol is loaded via dlopen and not in your PLT.
 *
 *  Removal:
 *    int  syringe_hook_remove(sym)         Remove one hook. Returns patches removed.
 *    void syringe_hook_remove_all()        Remove all installed hooks.
 *
 *  Query:
 *    int  syringe_hook_count()             Current hook count.
 *    int  syringe_hook_is_installed(sym)   Check if symbol is hooked.
 *    int  syringe_hook_registry_size()     Max registry capacity (SYRINGE_HOOK_MAX).
 *    void* syringe_hook_read_dst(src)      Read dst of installed JMP at src.
 *
 *  Trampoline internals (also public, used by install_addr):
 *    int  syringe_hook_tramp_install(&t, target, hook, &orig)
 *    void syringe_hook_tramp_remove(&t)
 *
 *  Memory helpers (always available):
 *    void syringe_hook_memfd_open()
 *    int  syringe_hook_mem_write(dst, src, len)
 *    int  syringe_hook_mem_read(dst, src, len)
 *    int  syringe_hook_safe_write(dst, src, len)         — data pages
 *    int  syringe_hook_safe_write_code(dst, src, len)    — code pages (preserves X)
 *    int  syringe_hook_safe_write_ptr(slot, val)         — atomic pointer write
 *
 * ─────────────────────────────────────────────────────────────────────────
 *  CONFIGURATION MACROS (define BEFORE #include)
 * ─────────────────────────────────────────────────────────────────────────
 *
 *  SYRINGE_HOOK_MAX=N
 *      Set the hook registry capacity (default: 32).
 *      Example: #define SYRINGE_HOOK_MAX 64
 *
 *  SYRINGE_HOOK_NO_HELPERS
 *      Strip out remove/count/is_installed/install_addr/read_dst to debloat.
 *      Use when you only call install() in a constructor and never need
 *      cleanup. WARNING: trampoline bounce stubs (mmap-allocated) will
 *      leak on .so unload. Only use for .so's that stay loaded for the
 *      lifetime of the target process.
 *
 *  SYRINGE_HOOK_NO_LOG
 *      Disable all SYRINGE_HOOK_LOG() output (default: logs to stderr).
 *
 * ─────────────────────────────────────────────────────────────────────────
 *  IMPORTANT — single-TU usage
 * ─────────────────────────────────────────────────────────────────────────
 *
 * Because the registry is `static` (per-translation-unit), you MUST include
 * this header from EXACTLY ONE .c file per .so / executable. The standard
 * pattern for an injectable .so is:
 *
 *     // libhook.c  ← the ONLY .c file in libhook.so that includes this header
 *     #define _GNU_SOURCE
 *     #define SYRINGE_HOOK_MAX 64          // optional: more than 32 hooks
 *     // #define SYRINGE_HOOK_NO_HELPERS   // optional: debloat
 *     // #define SYRINGE_HOOK_NO_LOG       // optional: silent
 *     #include <syringe/hook/syringe_hook.h>
 *
 *     static int (*orig_open)(const char *, int, ...);
 *     static int my_open(const char *p, int f, ...) { return orig_open(p, f, 0); }
 *
 *     __attribute__((constructor))
 *     static void on_load(void) {
 *         syringe_hook_install("open", (void *)my_open, (void **)&orig_open);
 *     }
 *
 *     __attribute__((destructor))
 *     static void on_unload(void) {
 *         syringe_hook_remove_all();    // requires SYRINGE_HOOK_NO_HELPERS NOT defined
 *     }
 *
 * Build:
 *     gcc -shared -fPIC -O2 -o libhook.so libhook.c \
 *         -I/path/to/syringe/include -ldl -lpthread
 *
 * If you need hook logic split across multiple .c files, keep ALL
 * syringe_hook_install / syringe_hook_remove calls in ONE file and call
 * them from that file's constructor. Other files in the same .so should
 * NOT include this header — each would get its own private registry and
 * hooks won't be visible across files.
 *
 * ─────────────────────────────────────────────────────────────────────────
 *  ARCHITECTURE SUPPORT
 * ─────────────────────────────────────────────────────────────────────────
 *
 * Inline hooking requires a per-arch length-disassembler and JMP encoder.
 * Currently supported:
 *   - x86-64   (full: disasm + trampoline + atomic patch)
 *   - aarch64  (full: disasm + trampoline + PAC/BTI handling)
 *
 * On other archs (arm32, riscv64), the inline trampoline path fails
 * gracefully and only GOT/PLT patching is used.
 *
 * The arch dispatch happens at include time — see include/hook/arch/.
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

#ifdef SYRINGE_HOOK_NO_LOG
#define SYRINGE_HOOK_LOG(fmt, ...) ((void)0)
#else
#define SYRINGE_HOOK_LOG(fmt, ...) \
    fprintf(stderr, "[syringe_hook] " fmt "\n", ##__VA_ARGS__), fflush(stderr)
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
