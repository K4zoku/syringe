/*
 * syringe_hook.h — Header-only in-process GOT/PLT hooker
 *
 *   SYRINGE Yields Runtime Injected Native Global Executables
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
 *  2. Inline trampoline — overwrites the first 16 bytes of the target function
 *                         with an absolute JMP to the hook.
 *                         Catches intra-library calls (e.g. libEGL calling itself).
 *                         Original prologue bytes are saved + a bounce stub is
 *                         allocated so orig() can still be called.
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
 *  Configuration macros (define BEFORE #include)
 * ─────────────────────────────────────────────────────────────────────────
 *
 *  SYRINGE_HOOK_MAX=N
 *      Set the hook registry capacity (default: 32).
 *      Override if you need to install more than 32 hooks in one .so.
 *      Example: #define SYRINGE_HOOK_MAX 64
 *
 *  SYRINGE_HOOK_NO_HELPERS
 *      Strip out helper / query functions to debloat the binary when you
 *      manage hooks yourself (e.g. only call install() in constructor,
 *      never call remove/count/is_installed at runtime).
 *
 *      When defined, the following functions are NOT compiled:
 *        - syringe_hook_remove(sym)        — still need remove? don't define
 *        - syringe_hook_remove_all()       — destructor cleanup not available
 *        - syringe_hook_count()            — query not available
 *        - syringe_hook_is_installed(sym)  — query not available
 *        - syringe_hook_registry_size()    — query not available
 *
 *      Functions still available:
 *        - syringe_hook_install(sym, hook, &orig)   — install hooks
 *        - syringe_hook_memfd_open() / mem_write()  — memory helpers
 *        - syringe_hook_safe_write*()               — internal helpers
 *        - syringe_hook_tramp_*()                   — trampoline helpers
 *
 *      Use this when binary size matters (e.g. embedded .so for injection
 *      into constrained targets) and you're certain you don't need cleanup.
 *      WARNING: without remove_all(), destructor cleanup is not possible
 *      and the trampoline bounce stubs (mmap-allocated) will leak on .so
 *      unload. Only use this for .so's that stay loaded for the lifetime
 *      of the target process.
 *
 *  SYRINGE_HOOK_NO_LOG
 *      Disable all SYRINGE_HOOK_LOG() output (default: logs to stderr).
 *      Define for silent operation in production.
 *
 * ─────────────────────────────────────────────────────────────────────────
 *  IMPORTANT — single-TU usage
 * ─────────────────────────────────────────────────────────────────────────
 * Because the registry is `static` (per-translation-unit), you MUST include
 * this header from EXACTLY ONE .c file per .so / executable. The standard
 * pattern for an injectable .so is:
 *
 *     // libhook.c  ← the ONLY .c file in libhook.so
 *     #define _GNU_SOURCE
 *     #define SYRINGE_HOOK_MAX 64          // optional: more than 32 hooks
 *     // #define SYRINGE_HOOK_NO_HELPERS   // optional: debloat
 *     // #define SYRINGE_HOOK_NO_LOG       // optional: silent
 *     #include "syringe_hook.h"
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
 *     gcc -shared -fPIC -O2 -o libhook.so libhook.c -I. -ldl -lpthread
 *
 * If you need hook logic split across multiple .c files, keep ALL
 * syringe_hook_install / syringe_hook_remove calls in ONE file and call
 * them from that file's constructor. Other files in the same .so should
 * NOT include this header.
 */

#ifndef SYRINGE_HOOK_H
#define SYRINGE_HOOK_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
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

/* ── Trampoline structures ────────────────────────────────────────────────
 *
 * TRAMP_JMP_SZ = 14 bytes for `FF 25 00 00 00 00 + 8-byte absolute target`.
 * TRAMP_STOLEN_MAX is the worst-case number of bytes we may need to copy
 * from the target prologue before we've copied at least TRAMP_JMP_SZ
 * instruction-aligned bytes. Real prologues rarely exceed 20 bytes
 * (endbr64 + push rbp + mov rbp,rsp + sub rsp,imm32 + ...), but we
 * over-provision to 32 so the disassembler never runs off the end.
 *
 * Each Trampoline now records `stolen_len` (the exact number of bytes
 * overwritten on the target) and `bounce_len` (size of the mmap'd
 * bounce stub, used to munmap on removal).
 *
 * BOUNCE_SZ is kept as an alias for TRAMP_BOUNCE_MAX for backward
 * compatibility with any external caller that still references it.
 */

#define TRAMP_JMP_SZ     14
#define TRAMP_STOLEN     16           /* deprecated alias, kept for compat */
#define TRAMP_STOLEN_MAX 32
#define TRAMP_BOUNCE_MAX (TRAMP_STOLEN_MAX + TRAMP_JMP_SZ)
#define BOUNCE_SZ        TRAMP_BOUNCE_MAX

typedef struct {
    uint8_t  stolen[TRAMP_STOLEN_MAX]; /* original prologue bytes */
    size_t   stolen_len;               /* exact bytes overwritten on target */
    void    *target;                   /* hooked function address */
    uint8_t *bounce;                   /* mmap'd trampoline stub */
    size_t   bounce_len;               /* size of bounce (for munmap) */
    int      active;                   /* 1 if currently installed */
} Trampoline;

/* ── HookRecord (per-TU registry entry) ─────────────────────────────────── */

typedef struct SyringeHookRecord SyringeHookRecord;

struct SyringeHookRecord {
    char  sym[128];
    void *hook;
    void **orig_out;
    void  *orig_addr;

    struct {
        void **entry;
        void  *saved;
    } patches[64];
    int npatch;

    Trampoline tramp;
    int has_tramp;
};

/* ── WalkCtx (internal, used by dl_iterate callback) ───────────────────── */

typedef struct {
    const char        *sym_name;
    void              *hook;
    SyringeHookRecord *rec;
    int                count;
} WalkCtx;

/* ══════════════════════════════════════════════════════════════════════════
 *  IMPLEMENTATION — everything below is `static inline` so each .c file
 *  that includes this header gets its own private copy of the registry
 *  and all functions. See "single-TU usage" note above.
 * ══════════════════════════════════════════════════════════════════════════ */

/* ── per-TU registry (private to each translation unit) ─────────────────── */

static SyringeHookRecord syringe_hooks[SYRINGE_HOOK_MAX];
static int               syringe_nhooks = 0;
static int               syringe_memfd  = -1;

/* ── /proc/self/mem write (bypasses mprotect restrictions) ─────────────── */

static inline void syringe_hook_memfd_open(void) {
    if (syringe_memfd >= 0) return;
    syringe_memfd = open("/proc/self/mem", O_RDWR);
    if (syringe_memfd < 0)
        SYRINGE_HOOK_LOG("warn: /proc/self/mem open failed: %s", strerror(errno));
}

static inline int syringe_hook_mem_write(void *dst, const void *src, size_t len) {
    if (syringe_memfd < 0) {
        syringe_hook_memfd_open();
    }
    if (syringe_memfd < 0) return -1;
    if (pwrite(syringe_memfd, src, len, (off_t)(uintptr_t)dst) != (ssize_t)len) {
        SYRINGE_HOOK_LOG("pwrite /proc/self/mem @ %p failed: %s", dst, strerror(errno));
        return -1;
    }
    return 0;
}

static inline int syringe_hook_mem_read(void *dst, void *src, size_t len) {
    if (syringe_memfd < 0) {
        syringe_hook_memfd_open();
    }
    if (syringe_memfd < 0) return -1;
    if (pread(syringe_memfd, dst, len, (off_t)(uintptr_t)src) != (ssize_t)len) {
        SYRINGE_HOOK_LOG("pread /proc/self/mem @ %p failed: %s", src, strerror(errno));
        return -1;
    }
    return 0;
}

/* ── page protection helpers ────────────────────────────────────────────── */

static inline uintptr_t syringe_hook_page_floor(uintptr_t a) {
    return a & ~((uintptr_t)getpagesize() - 1);
}

static inline int syringe_hook_page_is_ro(void *addr) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    uintptr_t t = (uintptr_t)addr;
    char line[256]; int ro = 0;
    while (fgets(line, sizeof(line), f)) {
        uintptr_t s, e; char p[8];
        if (sscanf(line, "%lx-%lx %7s", &s, &e, p) != 3) continue;
        if (t >= s && t < e) { ro = (p[1] != 'w'); break; }
    }
    fclose(f);
    return ro;
}

static inline int syringe_hook_make_rw(void *addr) {
    uintptr_t page = syringe_hook_page_floor((uintptr_t)addr);
    return mprotect((void*)page, getpagesize(), PROT_READ|PROT_WRITE);
}

static inline void syringe_hook_make_ro(void *addr) {
    uintptr_t page = syringe_hook_page_floor((uintptr_t)addr);
    mprotect((void*)page, getpagesize(), PROT_READ);
}

/* v0.5: make_rx — restore Read+Execute on a code page. Used by
 * syringe_hook_safe_write_code() after patching a function prologue
 * that originally lived in an r-x mapping (libc, libEGL.so, etc).
 *
 * The original syringe_hook_make_ro() collapses the page to PROT_READ
 * only, which is correct for GOT entries (data, never executed) but
 * silently strips EXECUTE permission from code pages, causing SIGSEGV
 * the next time the function is called. This was masked before v0.5
 * because the inline trampoline was gated off for r-x targets; now
 * that the gate is removed, we need a separate code-page restore. */
static inline int syringe_hook_make_rx(void *addr) {
    uintptr_t page = syringe_hook_page_floor((uintptr_t)addr);
    return mprotect((void*)page, getpagesize(), PROT_READ|PROT_EXEC);
}

/* ── process_vm_writev (fallback for read-only code segments) ─────────────
 *
 * On modern Linux, mprotect() cannot make shared library text segments
 * writable (they are file-backed shared mappings). The /proc/self/mem
 * approach also has issues with certain kernel hardening.
 *
 * process_vm_writev() (kernel >= 3.5) writes directly to another process's
 * VM — for /proc/self, it writes directly to our own address space without
 * needing mprotect(). This is the most reliable way to patch read-only
 * code segments.
 *
 * Usage: link with -lprocinfo or call via syscall (__NR_process_vm_writev)
 */
#ifndef __NR_process_vm_writev
#ifdef __x86_64__
#define __NR_process_vm_writev 311
#elif defined(__aarch64__)
#define __NR_process_vm_writev 273
#elif defined(__i386__)
#define __NR_process_vm_writev 347
#elif defined(__riscv) && __riscv_xlen == 64
#define __NR_process_vm_writev 271
#else
#define __NR_process_vm_writev 0 /* unknown */
#endif
#endif

static inline int syringe_hook_process_vm_writev(void *dst, const void *src, size_t len) {
#ifndef SYS_getpid
    return -1;
#endif
    struct iovec loc_iov = {
        .iov_base = (void *)dst,
        .iov_len  = len,
    };
    struct iovec rem_iov = {
        .iov_base = (void *)src,
        .iov_len  = len,
    };
    ssize_t ret = syscall(__NR_process_vm_writev, getpid(),
                          &rem_iov, 1, &loc_iov, 1, 0);
    return (ret == (ssize_t)len) ? 0 : -1;
}

/* Safe write: try mprotect first, fall back to /proc/self/mem,
 * then process_vm_writev as last resort. */
static inline int syringe_hook_safe_write(void *dst, const void *src, size_t len) {
    int ro = syringe_hook_page_is_ro(dst);
    if (ro) {
        /* Try mprotect first (works for private mappings) */
        if (syringe_hook_make_rw(dst) == 0) {
            memcpy(dst, src, len);
            syringe_hook_make_ro(dst);
            SYRINGE_HOOK_LOG("safe_write: patched via mprotect @ %p", dst);
            return 0;
        }
        int merr = errno;
        SYRINGE_HOOK_LOG("safe_write: mprotect failed (err=%d), trying /proc/self/mem ...", merr);

        /* Fallback 1: /proc/self/mem via pwrite */
        if (syringe_hook_mem_write(dst, src, len) == 0) {
            SYRINGE_HOOK_LOG("safe_write: patched via /proc/self/mem @ %p", dst);
            return 0;
        }
        SYRINGE_HOOK_LOG("safe_write: /proc/self/mem failed, trying process_vm_writev ...");

        /* Fallback 2: process_vm_writev (works on most modern kernels) */
        if (syringe_hook_process_vm_writev(dst, src, len) == 0) {
            __builtin___clear_cache((char*)dst, (char*)dst + len);
            SYRINGE_HOOK_LOG("safe_write: patched via process_vm_writev @ %p", dst);
            return 0;
        }
        SYRINGE_HOOK_LOG("safe_write: ALL methods failed for %p (mprotect err=%d, memfd, pvwrite)",
                         dst, merr);
        return -1;
    }
    memcpy(dst, src, len);
    return 0;
}

/* v0.5: safe_write_code — like safe_write but preserves the EXECUTE
 * bit on the target page. Use this when patching code (function
 * prologues); use safe_write for data (GOT slots).
 *
 * Strategy: try /proc/self/mem FIRST (atomic from userspace's perspective,
 * no permission change, no window where the page is non-executable). Fall
 * back to process_vm_writev (also atomic, no mprotect). Only as last resort
 * use mprotect RW → memcpy → mprotect RX — there's a brief window where
 * the page is non-executable, but if we got here it means both /proc/self/mem
 * and process_vm_writev are unavailable (seccomp), so this is the best we
 * can do.
 *
 * This is the OPPOSITE order from safe_write (data) because for code we
 * MUST avoid the transient RW-without-X state — another thread executing
 * the function during that window would SIGSEGV. */
static inline int syringe_hook_safe_write_code(void *dst, const void *src, size_t len) {
    /* Method 1: /proc/self/mem via pwrite — atomic, no mprotect. */
    syringe_hook_memfd_open();
    if (syringe_memfd >= 0) {
        if (syringe_hook_mem_write(dst, src, len) == 0) {
            SYRINGE_HOOK_LOG("safe_write_code: patched via /proc/self/mem @ %p", dst);
            return 0;
        }
        SYRINGE_HOOK_LOG("safe_write_code: /proc/self/mem failed, trying process_vm_writev");
    }

    /* Method 2: process_vm_writev — also atomic, no mprotect. */
    if (syringe_hook_process_vm_writev(dst, src, len) == 0) {
        __builtin___clear_cache((char*)dst, (char*)dst + len);
        SYRINGE_HOOK_LOG("safe_write_code: patched via process_vm_writev @ %p", dst);
        return 0;
    }
    SYRINGE_HOOK_LOG("safe_write_code: process_vm_writev failed, falling back to mprotect");

    /* Method 3 (last resort): mprotect RW → memcpy → mprotect RX.
     * There's a brief non-executable window — caller beware. */
    if (syringe_hook_make_rw(dst) == 0) {
        memcpy(dst, src, len);
        syringe_hook_make_rx(dst);   /* restore R-X, not just R */
        SYRINGE_HOOK_LOG("safe_write_code: patched via mprotect RW→RX @ %p", dst);
        return 0;
    }

    SYRINGE_HOOK_LOG("safe_write_code: ALL methods failed for %p", dst);
    return -1;
}

static inline void syringe_hook_atomic_write_ptr(void **slot, void *val) {
    __atomic_store_n(slot, val, __ATOMIC_SEQ_CST);
}

static inline int syringe_hook_safe_write_ptr(void **slot, void *val) {
    int ro = syringe_hook_page_is_ro(slot);
    if (ro) {
        if (syringe_hook_make_rw(slot) == 0) {
            syringe_hook_atomic_write_ptr(slot, val);
            syringe_hook_make_ro(slot);
            return 0;
        }
        int merr = errno;
        if (syringe_hook_mem_write(slot, &val, sizeof(val)) == 0) return 0;
        if (syringe_hook_process_vm_writev(slot, &val, sizeof(val)) == 0) return 0;
        SYRINGE_HOOK_LOG("safe_write_ptr: ALL methods failed for %p (mprotect err=%d)",
                         (void*)slot, merr);
        return -1;
    }
    syringe_hook_atomic_write_ptr(slot, val);
    return 0;
}

/* ── inline trampoline ────────────────────────────────────────────────────
 *
 * v0.5 rewrite — fixes four real-world bugs that previously made the
 * inline path silently fail on every shared library:
 *
 *   1. The old code copied a fixed 16-byte window of the target prologue
 *      into the bounce stub. If a 16-byte cut split an instruction in
 *      the middle, the CPU hit Illegal Instruction on the first orig()
 *      call. Fix: a real x86-64 length-disassembler (syringe_hook_disasm_x86_64)
 *      walks whole instructions until >= TRAMP_JMP_SZ bytes have been
 *      copied, then appends the JMP back.
 *
 *   2. The old code never fixed up RIP-relative displacements inside the
 *      stolen prologue. libEGL.so / libGL.so / libc.so.6 are all built
 *      -fPIC, so prologues like `lea rax,[rip+0x1234]` were copied
 *      verbatim to the bounce stub at a different VA — the displacement
 *      now pointed somewhere completely wrong, and orig() SIGSEGV'd on
 *      first use. Fix: syringe_hook_disasm_x86_64 reports the offset of
 *      any rel32 / RIP-relative disp; syringe_hook_tramp_make patches
 *      each disp by the delta (bounce - target).
 *
 *   3. The old code refused to patch any target whose page was r-x (i.e.
 *      every shared library on the planet). That made the entire inline
 *      path dead code for the osu-lazer use case (libEGL.so is r-x).
 *      Fix: syringe_hook_tramp_install always tries via safe_write_code
 *      which uses /proc/self/mem or process_vm_writev first (no
 *      permission change needed at all), mprotect RW→RX as last resort.
 *
 *   4. The old code never flushed the instruction cache for the bounce
 *      stub. On x86-64 this happens to work (coherent I-cache), but on
 *      aarch64 the bounce was invisible to the CPU. Fix:
 *      __builtin___clear_cache over both the target patch site and the
 *      bounce stub.
 *
 * Additionally, the patch itself is now emitted as two 8-byte atomic
 * stores instead of a 14-byte memcpy, shrinking the race window where
 * another thread can fetch a half-patched prologue.
 *
 * The user's local improvements that are PRESERVED here:
 *   - process_vm_writev as a fallback method (now in safe_write_code)
 *   - safe pread of the target prologue via /proc/self/mem (avoids
 *     segfault when target is in vDSO / unreadable page)
 *   - fflush(stderr) in SYRINGE_HOOK_LOG
 *   - the dlsym fallback when orig_addr is NULL or == hook
 */

static inline void syringe_hook_build_jmp(uint8_t *buf, void *dest) {
    buf[0]=0xFF; buf[1]=0x25;
    buf[2]=buf[3]=buf[4]=buf[5]=0x00;
    memcpy(buf+6, &dest, 8);
}

/* ── x86-64 length-disassembler (minimal, prologue-focused) ────────────────
 *
 * Returns the length of the instruction starting at `code`, or 0 if the
 * opcode is not recognised. When the instruction contains a rel32 or
 * RIP-relative displacement, `*reloc_offset` is set to the byte offset
 * (within the instruction) where the 4-byte displacement lives; the
 * caller will patch it when copying the instruction to a new VA.
 *
 * Coverage is deliberately biased toward prologue patterns:
 *   - All legacy prefixes (F0 F2 F3 2E 36 3E 26 64 65 66 67)
 *   - REX prefixes (40-4F) — required for x86-64
 *   - endbr64 / endbr32 (F3 0F 1E FA / F3 0F 1E FB) — CET prologue,
 *     present on every Ubuntu 22.04+ binary built with -fcf-protection
 *   - Multi-byte NOPs (0F 1F /0..7, 0F 1E /7, 66 0F 1F ...) — emitted
 *     by -O2 for alignment padding
 *   - Common prologue opcodes: push r64, mov r/m,r, sub r/m,imm8/32,
 *     lea r,m, call rel32, jmp rel32, mov r,imm
 *   - SSE/AVX prologue-ish: movaps, movdqa, movdqu, xorps, movq
 *   - ADD/AND/OR/CMP r/m,imm8/32 (reg/0, /4, /1, /7)
 *
 * Unknown opcodes return 0; caller falls back to raw copy (with warning).
 *
 * On non-x86-64 targets this function is a no-op stub returning 0; the
 * trampoline layer then falls back to fixed-width instruction handling
 * (aarch64: 4-byte fixed, no disp fixup needed; see syringe_hook_tramp_make).
 */

#if defined(__x86_64__) && defined(__LP64__)

static inline size_t syringe_hook_disasm_x86_64(const uint8_t *code,
                                                 int *reloc_offset) {
    enum {
        F_MODRM      = 1 << 0,
        F_PLUS_R     = 1 << 1,   /* opcode low 3 bits encode register */
        F_REG_OPCODE = 1 << 2,   /* ModRM /n must match */
        F_IMM8       = 1 << 3,
        F_IMM16      = 1 << 4,
        F_IMM32      = 1 << 5,
        F_RELOC_REL  = 1 << 6,   /* rel32 disp — patch when relocated */
        F_RELOC_RIP  = 1 << 7    /* RIP-relative ModRM disp32 — patch */
    };

    struct opinfo {
        uint8_t  opcode;
        uint8_t  reg_opcode;   /* ModRM /n, only used if F_REG_OPCODE */
        uint8_t  flags;
    };

    /* Legacy prefixes (in order of the reference manual). */
    static const uint8_t legacy_prefixes[] = {
        0xF0, 0xF2, 0xF3,                  /* lock, repne, rep */
        0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, /* segment overrides */
        0x66, 0x67                          /* opsize, addrsize */
    };

    /* Opcode table. Keep grouped by leading byte for readability. */
    static const struct opinfo opcodes[] = {
        /* Control flow — rel32 needs fixup when relocated */
        {0xE8, 0, F_IMM32 | F_RELOC_REL},                   /* CALL rel32 */
        {0xE9, 0, F_IMM32 | F_RELOC_REL},                   /* JMP  rel32 */
        {0xEB, 0, F_IMM8},                                  /* JMP  rel8  */
        {0xE3, 0, F_IMM8},                                  /* JRCXZ rel8 */
        {0x70, 0, F_IMM8 | F_PLUS_R},                       /* Jcc rel8 (70..7F) */
        {0xC3, 0, 0},                                       /* RET */
        {0xC2, 0, F_IMM16},                                 /* RET imm16 */

        /* LEA / MOV r,m */
        {0x8D, 0, F_MODRM},                                 /* LEA r,m */
        {0x8B, 0, F_MODRM},                                 /* MOV r,r/m */
        {0x89, 0, F_MODRM},                                 /* MOV r/m,r */
        {0x88, 0, F_MODRM},                                 /* MOV r/m8,r8 */
        {0x8A, 0, F_MODRM},                                 /* MOV r8,r/m8 */
        {0x8C, 0, F_MODRM},                                 /* MOV r/m,Sreg */
        {0x8E, 0, F_MODRM},                                 /* MOV Sreg,r/m */
        {0xA0, 0, F_IMM8},                                  /* MOV AL,moffs8 */
        {0xA1, 0, F_IMM32},                                 /* MOV EAX,moffs32 */
        {0xA2, 0, F_IMM8},                                  /* MOV moffs8,AL */
        {0xA3, 0, F_IMM32},                                 /* MOV moffs32,EAX */
        {0xB0, 0, F_PLUS_R | F_IMM8},                       /* MOV r8,imm8 */
        {0xB8, 0, F_PLUS_R | F_IMM32},                      /* MOV r32,imm32 */
        {0xC6, 0, F_MODRM | F_REG_OPCODE | F_IMM8},         /* MOV r/m8,imm8 */
        {0xC7, 0, F_MODRM | F_REG_OPCODE | F_IMM32},        /* MOV r/m,imm32 */

        /* Stack frame setup */
        {0x50, 0, F_PLUS_R},                                /* PUSH r64 */
        {0x58, 0, F_PLUS_R},                                /* POP r64 */
        {0x8F, 0, F_MODRM | F_REG_OPCODE},                  /* POP r/m */
        {0xFF, 6, F_MODRM | F_REG_OPCODE},                  /* PUSH r/m */
        {0xFF, 2, F_MODRM | F_REG_OPCODE},                  /* CALL r/m */
        {0xFF, 4, F_MODRM | F_REG_OPCODE},                  /* JMP  r/m */
        {0x6A, 0, F_IMM8},                                  /* PUSH imm8 */
        {0x68, 0, F_IMM32},                                 /* PUSH imm32 */

        /* Arithmetic on stack/frame — Group 1 (0x80/0x81/0x83 /n) */
        {0x83, 0, F_MODRM | F_REG_OPCODE | F_IMM8},         /* ADD r/m,imm8 (reg/0) */
        {0x81, 0, F_MODRM | F_REG_OPCODE | F_IMM32},        /* ADD r/m,imm32 (reg/0) */
        {0x83, 1, F_MODRM | F_REG_OPCODE | F_IMM8},         /* OR  r/m,imm8 */
        {0x81, 1, F_MODRM | F_REG_OPCODE | F_IMM32},        /* OR  r/m,imm32 */
        {0x83, 4, F_MODRM | F_REG_OPCODE | F_IMM8},         /* AND r/m,imm8 */
        {0x81, 4, F_MODRM | F_REG_OPCODE | F_IMM32},        /* AND r/m,imm32 */
        {0x83, 5, F_MODRM | F_REG_OPCODE | F_IMM8},         /* SUB r/m,imm8 */
        {0x81, 5, F_MODRM | F_REG_OPCODE | F_IMM32},        /* SUB r/m,imm32 */
        {0x83, 7, F_MODRM | F_REG_OPCODE | F_IMM8},         /* CMP r/m,imm8 */
        {0x81, 7, F_MODRM | F_REG_OPCODE | F_IMM32},        /* CMP r/m,imm32 */

        /* Arithmetic r,r/m and r/m,r */
        {0x29, 0, F_MODRM},                                 /* SUB r/m,r */
        {0x2B, 0, F_MODRM},                                 /* SUB r,r/m */
        {0x01, 0, F_MODRM},                                 /* ADD r/m,r */
        {0x03, 0, F_MODRM},                                 /* ADD r,r/m */
        {0x31, 0, F_MODRM},                                 /* XOR r/m,r */
        {0x33, 0, F_MODRM},                                 /* XOR r,r/m */

        /* TEST / CMP */
        {0x85, 0, F_MODRM},                                 /* TEST r/m,r */
        {0x39, 0, F_MODRM},                                 /* CMP r/m,r */
        {0x3B, 0, F_MODRM},                                 /* CMP r,r/m */
        {0xF7, 0, F_MODRM | F_REG_OPCODE | F_IMM32},        /* TEST/CMP r/m,imm32 */
        {0xF6, 0, F_MODRM | F_REG_OPCODE | F_IMM8},         /* TEST/CMP r/m8,imm8 */
    };

    size_t len = 0;
    int has_66 = 0;
    int has_rex = 0;
    (void)has_rex;       /* reserved for future SIB extension; OK to drop */
    if (reloc_offset) *reloc_offset = 0;

    /* 1) Consume legacy prefixes. */
    for (size_t i = 0; i < sizeof(legacy_prefixes)/sizeof(*legacy_prefixes); i++) {
        if (code[len] == legacy_prefixes[i]) {
            if (legacy_prefixes[i] == 0x66) {
                has_66 = 1;
            }
            len++;
            /* keep consuming — multiple prefixes are legal */
            i = (size_t)-1; /* restart scan */
            if (len >= 15) return 0; /* x86 caps prefix count */
        }
    }

    /* 2) REX prefix (0x40..0x4F) — only valid in long mode. */
    if ((code[len] & 0xF0) == 0x40) {
        has_rex = 1;
        len++;
    }

    /* 3) endbr64 / endbr32 (F3 0F 1E FA / F3 0F 1E FB). The 0xF3 was
     *    consumed as a prefix above, so we recognise the tail here. */
    if (len >= 1 && code[len] == 0x0F && code[len+1] == 0x1E &&
        (code[len+2] == 0xFA || code[len+2] == 0xFB)) {
        len += 3;
        return len;
    }

    /* 4) Multi-byte NOP: 0F 1F /0..7, 0F 1E /7, with optional 66 prefix. */
    if (code[len] == 0x0F && (code[len+1] == 0x1F || code[len+1] == 0x1E)) {
        uint8_t modrm = code[len+2];
        int mod = modrm >> 6;
        int rm  = modrm & 7;
        size_t insn_len = 3;
        if (mod != 3 && rm == 4) insn_len++;     /* SIB */
        if (mod == 1) insn_len += 1;             /* disp8 */
        if (mod == 2 || (mod == 0 && rm == 5)) insn_len += 4; /* disp32 */
        return len + insn_len;
    }

    /* 5) Two-byte opcode escape 0F xx — small subset we recognise. */
    if (code[len] == 0x0F) {
        uint8_t op2 = code[len+1];
        /* MOVAPS / MOVUPS / MOVAPD / MOVUPD: 0F 28 / 0F 29 / 0F 10 / 0F 11 */
        if (op2 == 0x28 || op2 == 0x29 || op2 == 0x10 || op2 == 0x11 ||
            op2 == 0x57 /* XORPS */) {
            uint8_t modrm = code[len+2];
            int mod = modrm >> 6;
            int rm  = modrm & 7;
            size_t insn_len = 3;
            if (mod != 3 && rm == 4) insn_len++;
            if (mod == 1) insn_len += 1;
            if (mod == 2 || (mod == 0 && rm == 5)) {
                insn_len += 4;
                if (reloc_offset) *reloc_offset = (int)(insn_len - 4);
                return len + insn_len;
            }
            return len + insn_len;
        }
        /* Unrecognised 0F xx — bail. */
        return 0;
    }

    /* 6) One-byte opcode table lookup. */
    const struct opinfo *match = NULL;
    for (size_t i = 0; i < sizeof(opcodes)/sizeof(*opcodes); i++) {
        const struct opinfo *o = &opcodes[i];
        int found = 0;

        if (o->flags & F_PLUS_R) {
            /* opcode low 3 bits encode register */
            if ((code[len] & 0xF8) == o->opcode) found = 1;
        } else if (o->flags & F_REG_OPCODE) {
            /* exact opcode + ModRM /n must match */
            if (code[len] == o->opcode &&
                ((code[len+1] >> 3) & 7) == o->reg_opcode) found = 1;
        } else {
            if (code[len] == o->opcode) found = 1;
        }

        if (found) { match = o; break; }
    }
    if (!match) return 0;

    /* Record rel32 location for RELOC_REL instructions (CALL/JMP rel32). */
    if ((match->flags & F_RELOC_REL) && reloc_offset) {
        /* rel32 disp starts immediately after the 1-byte opcode */
        *reloc_offset = (int)(len + 1);
    }

    len++;  /* consume opcode */

    /* 7) ModRM byte. */
    if (match->flags & F_MODRM) {
        uint8_t modrm = code[len++];
        int mod = modrm >> 6;
        int rm  = modrm & 7;

        if (mod != 3 && rm == 4) len++;          /* SIB */
        if (mod == 1) len += 1;                  /* disp8 */
        if (mod == 2 || (mod == 0 && rm == 5)) {
            /* On x86-64 in long mode, mod=0 rm=5 means [RIP+disp32] —
             * a RIP-relative address that needs fixup. */
            len += 4;
            if (reloc_offset && !(match->flags & F_RELOC_REL))
                *reloc_offset = (int)(len - 4);
        }
    }

    /* 8) Immediates. */
    if (match->flags & F_IMM8)  len += 1;
    if (match->flags & F_IMM16) len += 2;
    if (match->flags & F_IMM32) len += (has_66 ? 2 : 4);

    return len;
}

#else  /* !__x86_64__ */

/* Non-x86-64 stub: callers should use arch-specific fixed-length handling.
 * For now we return 0 so tramp_make falls back to raw copy with a warning.
 * aarch64 etc. need a separate implementation. */
static inline size_t syringe_hook_disasm_x86_64(const uint8_t *code,
                                                 int *reloc_offset) {
    (void)code; (void)reloc_offset;
    return 0;
}

#endif /* __x86_64__ */

/* ── trampoline builder: copy prologue + fix up relative disps ────────────
 *
 * Fills `bounce_payload` with:
 *   [ stolen prologue bytes, with rel32 / RIP disps patched ] [ JMP abs ]
 *
 * On success returns the number of bytes to overwrite on the target
 * (i.e. the stolen prologue length, always >= TRAMP_JMP_SZ) and sets
 * *copied_bytes to the same value. Returns 0 on failure.
 *
 * The prologue bytes are read via /proc/self/mem (pread) so that
 * targets in unreadable pages (vDSO, kernel trap gates) don't segfault.
 */
static inline size_t syringe_hook_tramp_make(uint8_t *bounce_payload,
                                              size_t bounce_cap,
                                              const void *target,
                                              size_t *copied_bytes) {
    size_t stolen = 0;
    const uint8_t *src = (const uint8_t*)target;

    /* Shadow-read prologue via /proc/self/mem to avoid segfault on
     * unreadable targets. We need up to TRAMP_STOLEN_MAX bytes. */
    uint8_t prologue_buf[TRAMP_STOLEN_MAX];
    int have_prologue = 0;
    if (syringe_memfd < 0) syringe_hook_memfd_open();
    if (syringe_memfd >= 0) {
        ssize_t rd = pread(syringe_memfd, prologue_buf, TRAMP_STOLEN_MAX,
                           (off_t)(uintptr_t)target);
        if (rd == (ssize_t)TRAMP_STOLEN_MAX) {
            have_prologue = 1;
            src = prologue_buf;
        } else {
            SYRINGE_HOOK_LOG("tramp_make: pread prologue failed (rd=%zd)", rd);
        }
    }
    if (!have_prologue) {
        /* Last-resort: direct read. May segfault on protected pages. */
        memcpy(prologue_buf, target, TRAMP_STOLEN_MAX);
        src = prologue_buf;
    }

    while (stolen < TRAMP_JMP_SZ) {
        int reloc_off = 0;
        size_t insn_len = syringe_hook_disasm_x86_64(src + stolen, &reloc_off);

        if (insn_len == 0) {
            SYRINGE_HOOK_LOG("tramp_make: unknown opcode at +%zu (target=%p)",
                             stolen, target);
            return 0;
        }
        if (stolen + insn_len > TRAMP_STOLEN_MAX) {
            SYRINGE_HOOK_LOG("tramp_make: stolen prologue exceeds %d bytes",
                             TRAMP_STOLEN_MAX);
            return 0;
        }
        if (stolen + insn_len + TRAMP_JMP_SZ > bounce_cap) {
            SYRINGE_HOOK_LOG("tramp_make: bounce buffer too small");
            return 0;
        }

        /* Copy instruction verbatim, then patch its displacement if any. */
        memcpy(bounce_payload + stolen, src + stolen, insn_len);

        if (reloc_off > 0) {
            /* rel32 / RIP-disp32: add (target - bounce) so that when this
             * instruction executes from the bounce stub, the disp points
             * back to the same absolute address it referenced originally. */
            intptr_t b_addr = (intptr_t)(bounce_payload + stolen);
            intptr_t t_addr = (intptr_t)((const uint8_t*)target + stolen);
            int32_t orig_disp;
            memcpy(&orig_disp, bounce_payload + stolen + reloc_off, 4);
            int32_t new_disp = (int32_t)(orig_disp + (t_addr - b_addr));
            memcpy(bounce_payload + stolen + reloc_off, &new_disp, 4);
        }

        stolen += insn_len;
    }

    /* Append the JMP abs back to target+stolen. */
    syringe_hook_build_jmp(bounce_payload + stolen,
                           (void*)((uintptr_t)target + stolen));

    if (copied_bytes) *copied_bytes = stolen;
    return stolen;
}

/* Atomic 14-byte patch: split the 14-byte JMP-abs into two 8-byte atomic
 * stores so the target is never in an inconsistent half-patched state
 * for more than one store. On x86-64 this is enough to prevent any thread
 * from fetching a 0xFF prefix without its matching ModRM.
 *
 * The caller's `jmp[14]` is copied into a 16-byte stack buffer first so
 * the second 8-byte read (offset 8..16) is fully inside an aligned
 * object — GCC's -Warray-bounds= would otherwise flag it. */
static inline int syringe_hook_atomic_patch_jmp(void *target,
                                                 const uint8_t jmp[TRAMP_JMP_SZ]) {
    uint8_t buf[16] = {0};
    memcpy(buf, jmp, TRAMP_JMP_SZ);
    uint64_t lo, hi;
    memcpy(&lo, buf,     8);
    memcpy(&hi, buf + 8, 8);
    __atomic_store_n((uint64_t*)target,      lo, __ATOMIC_SEQ_CST);
    __atomic_store_n((uint64_t*)target + 1,  hi, __ATOMIC_SEQ_CST);
    return 0;
}

/* ── public trampoline install / remove ───────────────────────────────────
 *
 * syringe_hook_tramp_install now:
 *   - always tries to patch (no page_is_ro gate)
 *   - uses the length-disassembler to steal whole instructions
 *   - patches RIP-relative / rel32 disps in the bounce stub
 *   - emits the target patch via two atomic 8-byte stores
 *   - flushes I-cache on BOTH the target and the bounce stub
 *   - reads prologue via /proc/self/mem (safe for vDSO / unreadable pages)
 *   - patches via safe_write_code (preserves EXECUTE bit)
 */
static inline int syringe_hook_tramp_install(Trampoline *t, void *target,
                                              void *hook, void **orig_out) {
    memset(t, 0, sizeof(*t));
    t->target = target;

    if (target == NULL) {
        SYRINGE_HOOK_LOG("tramp: NULL target address");
        return -1;
    }

    /* mmap bounce stub RWX. On kernels with MDWE this may fail; fall back
     * to mmap RW then mprotect RX (two-step). */
    t->bounce_len = TRAMP_BOUNCE_MAX;
    t->bounce = (uint8_t*)mmap(NULL, t->bounce_len,
                                PROT_READ|PROT_WRITE|PROT_EXEC,
                                MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (t->bounce == MAP_FAILED) {
        t->bounce = (uint8_t*)mmap(NULL, t->bounce_len,
                                    PROT_READ|PROT_WRITE,
                                    MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (t->bounce == MAP_FAILED) {
            SYRINGE_HOOK_LOG("tramp: mmap bounce failed: %s", strerror(errno));
            return -1;
        }
        if (mprotect(t->bounce, t->bounce_len, PROT_READ|PROT_EXEC) != 0) {
            SYRINGE_HOOK_LOG("tramp: mprotect bounce RX failed: %s",
                             strerror(errno));
            munmap(t->bounce, t->bounce_len);
            t->bounce = NULL;
            return -1;
        }
    }

    /* Build the bounce stub (stolen prologue + JMP back). tramp_make
     * returns the exact byte count we must overwrite on the target.
     * It reads the prologue via /proc/self/mem (safe pread). */
    size_t stolen = syringe_hook_tramp_make(t->bounce, t->bounce_len,
                                             target, &t->stolen_len);
    if (stolen == 0) {
        SYRINGE_HOOK_LOG("tramp: disassembler refused prologue at %p", target);
        munmap(t->bounce, t->bounce_len);
        t->bounce = NULL;
        return -1;
    }

    /* Save original bytes for restore — also via /proc/self/mem so we
     * don't crash if target becomes unreadable between make and patch. */
    if (syringe_memfd >= 0) {
        ssize_t rd = pread(syringe_memfd, t->stolen, t->stolen_len,
                           (off_t)(uintptr_t)target);
        if (rd != (ssize_t)t->stolen_len) {
            memcpy(t->stolen, target, t->stolen_len);  /* fallback */
        }
    } else {
        memcpy(t->stolen, target, t->stolen_len);
    }

    /* Flush I-cache on bounce stub BEFORE patching target, so that any
     * thread that immediately jumps into the bounce sees correct code. */
    __builtin___clear_cache((char*)t->bounce,
                            (char*)t->bounce + t->bounce_len);

    /* Build the JMP-abs-to-hook and patch the target prologue.
     * Use safe_write_code (not safe_write) so we preserve the EXECUTE
     * bit on the target page — otherwise the next call to the hooked
     * function SIGSEGVs. */
    uint8_t jmp[TRAMP_JMP_SZ];
    syringe_hook_build_jmp(jmp, hook);

    if (syringe_hook_safe_write_code(target, jmp, TRAMP_JMP_SZ) != 0) {
        SYRINGE_HOOK_LOG("tramp: patch failed for %p", target);
        munmap(t->bounce, t->bounce_len);
        t->bounce = NULL;
        return -1;
    }

    /* For targets patched via direct memcpy (RW page), still try the
     * atomic path so concurrent readers see a consistent state. If the
     * page is RX and safe_write_code went through /proc/self/mem or
     * process_vm_writev, atomicity is the kernel's problem. */
    if (!syringe_hook_page_is_ro(target)) {
        syringe_hook_atomic_patch_jmp(target, jmp);
    }

    __builtin___clear_cache((char*)target,
                            (char*)target + TRAMP_JMP_SZ);

    t->active = 1;
    if (orig_out) *orig_out = t->bounce;
    SYRINGE_HOOK_LOG("tramp: patched %p → %p (stolen=%zu, bounce @ %p)",
                     target, hook, t->stolen_len, t->bounce);
    return 0;
}

static inline void syringe_hook_tramp_remove(Trampoline *t) {
    if (!t->active) return;
    /* Restore exactly the bytes we overwrote (was a fixed 16-byte window
     * before, now correctly sized to t->stolen_len). Use safe_write_code
     * so we keep EXECUTE permission on the target page after restore. */
    syringe_hook_safe_write_code(t->target, t->stolen, t->stolen_len);
    __builtin___clear_cache((char*)t->target,
                            (char*)t->target + t->stolen_len);
    if (t->bounce && t->bounce_len) {
        munmap(t->bounce, t->bounce_len);
    }
    t->active = 0;
    t->bounce = NULL;
    t->bounce_len = 0;
    t->stolen_len = 0;
    SYRINGE_HOOK_LOG("tramp: restored %p", t->target);
}

/* ── ELF / GOT walking ──────────────────────────────────────────────────── */

/* Force-resolve a lazy PLT stub by calling dlsym with RTLD_NOW semantics. */
static inline void syringe_hook_force_resolve(const char *sym) {
    (void)dlsym(RTLD_DEFAULT, sym);
}

static inline void syringe_hook_patch_rela(const Elf64_Rela *rela, size_t n,
                        const Elf64_Sym *symtab, const char *strtab,
                        uintptr_t bias, WalkCtx *ctx) {
    for (size_t i = 0; i < n; i++) {
        uint32_t sidx = ELF64_R_SYM(rela[i].r_info);
        uint32_t type = ELF64_R_TYPE(rela[i].r_info);
        if (type != R_X86_64_JUMP_SLOT && type != R_X86_64_GLOB_DAT) continue;
        if (sidx == STN_UNDEF) continue;
        if (strcmp(strtab + symtab[sidx].st_name, ctx->sym_name) != 0) continue;

        void **slot = (void**)(bias + rela[i].r_offset);

        if (ctx->rec->orig_addr == NULL) {
            syringe_hook_force_resolve(ctx->sym_name);
            void *resolved = dlsym(RTLD_DEFAULT, ctx->sym_name);
            ctx->rec->orig_addr = resolved ? resolved : *slot;
        }

        int np = ctx->rec->npatch;
        if (np >= 64) continue;
        ctx->rec->patches[np].entry = slot;
        ctx->rec->patches[np].saved = *slot;

        if (syringe_hook_safe_write_ptr(slot, ctx->hook) == 0) {
            ctx->rec->npatch++;
            ctx->count++;
            SYRINGE_HOOK_LOG("  GOT[%s] @ %p patched", ctx->sym_name, (void*)slot);
        } else {
            SYRINGE_HOOK_LOG("  GOT[%s] @ %p write failed", ctx->sym_name, (void*)slot);
        }
    }
}

/* Handle old-style Elf64_Rel (no addend) */
static inline void syringe_hook_patch_rel(const Elf64_Rel *rel, size_t n,
                       const Elf64_Sym *symtab, const char *strtab,
                       uintptr_t bias, WalkCtx *ctx) {
    for (size_t i = 0; i < n; i++) {
        uint32_t sidx = ELF64_R_SYM(rel[i].r_info);
        uint32_t type = ELF64_R_TYPE(rel[i].r_info);
        if (type != R_X86_64_JUMP_SLOT && type != R_X86_64_GLOB_DAT) continue;
        if (sidx == STN_UNDEF) continue;
        if (strcmp(strtab + symtab[sidx].st_name, ctx->sym_name) != 0) continue;

        void **slot = (void**)(bias + rel[i].r_offset);

        if (ctx->rec->orig_addr == NULL) {
            syringe_hook_force_resolve(ctx->sym_name);
            void *resolved = dlsym(RTLD_DEFAULT, ctx->sym_name);
            ctx->rec->orig_addr = resolved ? resolved : *slot;
        }

        int np = ctx->rec->npatch;
        if (np >= 64) continue;
        ctx->rec->patches[np].entry = slot;
        ctx->rec->patches[np].saved = *slot;

        if (syringe_hook_safe_write_ptr(slot, ctx->hook) == 0) {
            ctx->rec->npatch++;
            ctx->count++;
            SYRINGE_HOOK_LOG("  GOT/REL[%s] @ %p patched", ctx->sym_name, (void*)slot);
        }
    }
}

/* dl_iterate_phdr callback — must NOT be static so its address can be taken
 * by dl_iterate_phdr() (which expects a function pointer with external
 * linkage). However, because it's `inline` (not `static inline`), each TU
 * that includes this header gets its own copy, and the linker picks one
 * (C99 inline semantics). The function is also marked `static inline`
 * below — both work; we use `static inline` for consistency. */
static inline int syringe_hook_phdr_cb(struct dl_phdr_info *info, size_t sz, void *data) {
    (void)sz;
    WalkCtx *ctx = (WalkCtx*)data;
    uintptr_t bias = info->dlpi_addr;

    const Elf64_Dyn *dyn = NULL;
    for (int i = 0; i < info->dlpi_phnum; i++)
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = (const Elf64_Dyn*)(bias + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    if (!dyn) return 0;

    const Elf64_Sym  *symtab    = NULL;
    const char       *strtab    = NULL;
    const Elf64_Rela *rela_plt  = NULL; size_t rela_plt_sz = 0;
    const Elf64_Rela *rela_dyn  = NULL; size_t rela_dyn_sz = 0;
    const Elf64_Rel  *rel_plt   = NULL; size_t rel_plt_sz  = 0;
    const Elf64_Rel  *rel_dyn   = NULL; size_t rel_dyn_sz  = 0;
    int pltrel_is_rela = 1;

    for (const Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
        case DT_SYMTAB:    symtab   = (const Elf64_Sym*) d->d_un.d_ptr; break;
        case DT_STRTAB:    strtab   = (const char*)       d->d_un.d_ptr; break;
        case DT_JMPREL:    rela_plt = (const Elf64_Rela*) d->d_un.d_ptr; break;
        case DT_PLTRELSZ:  rela_plt_sz = d->d_un.d_val;                  break;
        case DT_PLTREL:    pltrel_is_rela = (d->d_un.d_val == DT_RELA);  break;
        case DT_RELA:      rela_dyn = (const Elf64_Rela*) d->d_un.d_ptr; break;
        case DT_RELASZ:    rela_dyn_sz = d->d_un.d_val;                   break;
        case DT_REL:       rel_dyn  = (const Elf64_Rel*)  d->d_un.d_ptr; break;
        case DT_RELSZ:     rel_dyn_sz  = d->d_un.d_val;                   break;
        default: break;
        }
    }
    if (!symtab || !strtab) return 0;

    int before = ctx->count;

    if (pltrel_is_rela) {
        if (rela_plt && rela_plt_sz)
            syringe_hook_patch_rela(rela_plt, rela_plt_sz/sizeof(Elf64_Rela),
                       symtab, strtab, bias, ctx);
    } else {
        rel_plt  = (const Elf64_Rel*)rela_plt;
        rel_plt_sz = rela_plt_sz;
        if (rel_plt && rel_plt_sz)
            syringe_hook_patch_rel(rel_plt, rel_plt_sz/sizeof(Elf64_Rel),
                      symtab, strtab, bias, ctx);
    }

    if (rela_dyn && rela_dyn_sz)
        syringe_hook_patch_rela(rela_dyn, rela_dyn_sz/sizeof(Elf64_Rela),
                   symtab, strtab, bias, ctx);
    if (rel_dyn && rel_dyn_sz)
        syringe_hook_patch_rel(rel_dyn, rel_dyn_sz/sizeof(Elf64_Rel),
                  symtab, strtab, bias, ctx);

    if (ctx->count > before) {
        const char *mod = (info->dlpi_name && info->dlpi_name[0])
                        ? info->dlpi_name : "(main)";
        SYRINGE_HOOK_LOG("  module %s: +%d GOT slot(s)", mod, ctx->count - before);
    }
    return 0;
}

/* ── public API ─────────────────────────────────────────────────────────── */

/**
 * Install a hook on `sym`.
 * @param sym     symbol name to hook
 * @param hook    function pointer to redirect to
 * @param orig_out pointer to store the original function pointer (or trampoline bounce)
 * @return total patches applied (GOT slots + trampoline), or 0 on failure
 */
static inline int syringe_hook_install(const char *sym, void *hook, void **orig_out) {
    if (syringe_nhooks >= SYRINGE_HOOK_MAX) { SYRINGE_HOOK_LOG("hook table full"); return 0; }
    for (int i = 0; i < syringe_nhooks; i++)
        if (strcmp(syringe_hooks[i].sym, sym) == 0) {
            SYRINGE_HOOK_LOG("'%s' already hooked", sym); return 0;
        }

    SyringeHookRecord *rec = &syringe_hooks[syringe_nhooks];
    memset(rec, 0, sizeof(*rec));
    strncpy(rec->sym, sym, sizeof(rec->sym)-1);
    rec->hook     = hook;
    rec->orig_out = orig_out;

    SYRINGE_HOOK_LOG("installing '%s' hook → %p", sym, hook);

    WalkCtx ctx = { sym, hook, rec, 0 };
    dl_iterate_phdr(syringe_hook_phdr_cb, &ctx);
    SYRINGE_HOOK_LOG("'%s': %d GOT slot(s) patched", sym, ctx.count);

    if (rec->orig_addr == NULL || rec->orig_addr == hook) {
        /* No GOT entry found (or still points to hook itself).
         * Fall back to dlsym(RTLD_DEFAULT, sym) to get the real address.
         * This handles symbols resolved via dlopen() that have no PLT/GOT. */
        SYRINGE_HOOK_LOG("'%s': orig_addr is NULL=%d or ==hook=%d, falling back to dlsym",
                         sym, rec->orig_addr == NULL, rec->orig_addr == hook);
        (void)dlsym(RTLD_DEFAULT, sym);
        void *resolved = dlsym(RTLD_DEFAULT, sym);
        if (resolved) {
            rec->orig_addr = resolved;
            SYRINGE_HOOK_LOG("'%s': dlsym resolved to %p", sym, resolved);
        } else {
            SYRINGE_HOOK_LOG("'%s': dlsym returned NULL", sym);
        }
    }

    if (rec->orig_addr && rec->orig_addr != hook) {
        void *tramp_orig = NULL;
        /* v0.5: always attempt inline trampoline. The previous npatch > 0
         * gate skipped the trampoline for symbols with GOT patches — but
         * that missed the osu-lazer use case where SDL calls eglSwapBuffers
         * through a dlsym'd pointer (intra-library call that bypasses GOT).
         *
         * The trampoline now uses safe_write_code (with /proc/self/mem +
         * process_vm_writev fallbacks) so patching shared library code is
         * safe. The length-disassembler ensures we don't split instructions. */
        if (syringe_hook_tramp_install(&rec->tramp, rec->orig_addr,
                                        hook, &tramp_orig) == 0) {
            rec->has_tramp = 1;
            if (orig_out) *orig_out = tramp_orig;
            SYRINGE_HOOK_LOG("'%s': inline trampoline installed", sym);
        } else {
            SYRINGE_HOOK_LOG("'%s': inline trampoline failed (GOT-only)", sym);
            if (orig_out) *orig_out = rec->orig_addr;
        }
    } else {
        if (orig_out) *orig_out = rec->orig_addr;
    }

    if (ctx.count == 0 && !rec->has_tramp) {
        SYRINGE_HOOK_LOG("'%s': no GOT slots and trampoline failed — hook not installed", sym);
        return 0;
    }

    syringe_nhooks++;
    return ctx.count + (rec->has_tramp ? 1 : 0);
}

/**
 * Install an inline hook on an explicit address.
 *
 * Bypasses the GOT walk and the dlsym(RTLD_DEFAULT) lookup. Use this when:
 *   - the symbol is not in the caller's PLT (e.g. libEGL.so loaded by SDL
 *     via dlopen, eglSwapBuffers never appears in the main binary's GOT)
 *   - you already have the function pointer (e.g. from eglGetProcAddress)
 *   - you want to hook a static / local function with no ELF symbol
 *
 * The `sym` parameter is only used as a registry key for later remove().
 * Pass any unique non-NULL string.
 *
 * @param sym       registry key (any unique string, e.g. "eglSwapBuffers")
 * @param target    function address to hook (in the CALLING process)
 * @param hook      function pointer to redirect to
 * @param orig_out  pointer to store trampoline bounce address (callable
 *                  as if it were the original function)
 * @return 1 on success (inline trampoline installed), 0 on failure
 *
 * Conditionally compiled — define SYRINGE_HOOK_NO_HELPERS to strip out.
 *   When stripped, the caller can still drive the trampoline layer
 *   directly via syringe_hook_tramp_install().
 */
#ifndef SYRINGE_HOOK_NO_HELPERS
static inline int syringe_hook_install_addr(const char *sym, void *target,
                                              void *hook, void **orig_out) {
    if (syringe_nhooks >= SYRINGE_HOOK_MAX) {
        SYRINGE_HOOK_LOG("hook table full");
        return 0;
    }
    if (!sym || !target || !hook) {
        SYRINGE_HOOK_LOG("install_addr: NULL arg");
        return 0;
    }
    for (int i = 0; i < syringe_nhooks; i++)
        if (strcmp(syringe_hooks[i].sym, sym) == 0) {
            SYRINGE_HOOK_LOG("'%s' already hooked", sym);
            return 0;
        }

    SyringeHookRecord *rec = &syringe_hooks[syringe_nhooks];
    memset(rec, 0, sizeof(*rec));
    strncpy(rec->sym, sym, sizeof(rec->sym)-1);
    rec->hook      = hook;
    rec->orig_out  = orig_out;
    rec->orig_addr = target;     /* caller-supplied, skip dlsym */

    void *tramp_orig = NULL;
    if (syringe_hook_tramp_install(&rec->tramp, target, hook, &tramp_orig) != 0) {
        SYRINGE_HOOK_LOG("'%s': install_addr trampoline failed", sym);
        return 0;
    }
    rec->has_tramp = 1;
    if (orig_out) *orig_out = tramp_orig;

    SYRINGE_HOOK_LOG("'%s': install_addr OK (target=%p, bounce=%p)",
                     sym, target, tramp_orig);
    syringe_nhooks++;
    return 1;
}
#endif /* !SYRINGE_HOOK_NO_HELPERS */

/**
 * Read the destination address of a JMP installed at `src`.
 *
 * Returns non-NULL if `src` starts with the 14-byte FF 25 abs-jmp sequence
 * emitted by syringe_hook_tramp_install (i.e. the function is already
 * hooked by us — or by anything else using the same encoding, e.g. subhook
 * with the abs-jmp variant). Returns NULL otherwise.
 *
 * Useful for:
 *   - detecting existing hooks before installing your own (avoid clobbering)
 *   - chaining hooks (read the previous dst, install your hook, call prev
 *     from inside your hook)
 *   - defensive self-checks in destructors
 *
 * @param src function address to inspect
 * @return destination address if hooked, NULL otherwise
 *
 * Conditionally compiled — define SYRINGE_HOOK_NO_HELPERS to strip out.
 */
#ifndef SYRINGE_HOOK_NO_HELPERS
static inline void *syringe_hook_read_dst(void *src) {
    if (!src) return NULL;
    uint8_t *p = (uint8_t*)src;
    /* FF 25 00 00 00 00 + 8-byte abs addr */
    if (p[0] != 0xFF || p[1] != 0x25) return NULL;
    if (p[2] != 0x00 || p[3] != 0x00 ||
        p[4] != 0x00 || p[5] != 0x00) return NULL;
    void *dst;
    /* Read via /proc/self/mem to avoid segfault on unreadable pages. */
    if (syringe_memfd >= 0) {
        ssize_t rd = pread(syringe_memfd, &dst, 8,
                           (off_t)(uintptr_t)(p + 6));
        if (rd != 8) return NULL;
    } else {
        memcpy(&dst, p + 6, 8);
    }
    return dst;
}
#endif /* !SYRINGE_HOOK_NO_HELPERS */

/**
 * Remove a specific hook.
 * @param sym symbol name to unhook
 * @return patches count removed, or 0 if not found
 *
 * Conditionally compiled — define SYRINGE_HOOK_NO_HELPERS to strip out.
 */
#ifndef SYRINGE_HOOK_NO_HELPERS
static inline int syringe_hook_remove(const char *sym) {
    for (int i = 0; i < syringe_nhooks; i++) {
        SyringeHookRecord *rec = &syringe_hooks[i];
        if (strcmp(rec->sym, sym) != 0) continue;

        for (int j = 0; j < rec->npatch; j++)
            syringe_hook_safe_write_ptr(rec->patches[j].entry, rec->patches[j].saved);

        if (rec->has_tramp) syringe_hook_tramp_remove(&rec->tramp);

        if (rec->orig_out) *rec->orig_out = NULL;

        syringe_hooks[i] = syringe_hooks[--syringe_nhooks];
        SYRINGE_HOOK_LOG("'%s' removed", sym);
        return rec->npatch + (rec->has_tramp ? 1 : 0);
    }
    return 0;
}

/**
 * Remove all installed hooks.
 *
 * Conditionally compiled — define SYRINGE_HOOK_NO_HELPERS to strip out.
 * WARNING: without this, destructor cleanup is impossible and trampoline
 * bounce stubs (mmap-allocated) will leak on .so unload.
 */
static inline void syringe_hook_remove_all(void) {
    for (int i = syringe_nhooks-1; i >= 0; i--)
        syringe_hook_remove(syringe_hooks[i].sym);
}

/* ── testable query functions ───────────────────────────────────────────── */

/** Get the current number of installed hooks.
 *  Conditionally compiled — define SYRINGE_HOOK_NO_HELPERS to strip out. */
static inline int syringe_hook_count(void) {
    return syringe_nhooks;
}

/** Check if a symbol is currently hooked.
 *  Conditionally compiled — define SYRINGE_HOOK_NO_HELPERS to strip out. */
static inline int syringe_hook_is_installed(const char *sym) {
    for (int i = 0; i < syringe_nhooks; i++) {
        if (strcmp(syringe_hooks[i].sym, sym) == 0) return 1;
    }
    return 0;
}

/** Get the maximum registry capacity.
 *  Conditionally compiled — define SYRINGE_HOOK_NO_HELPERS to strip out. */
static inline int syringe_hook_registry_size(void) {
    return SYRINGE_HOOK_MAX;
}
#endif /* !SYRINGE_HOOK_NO_HELPERS */

#ifdef __cplusplus
}
#endif

#endif /* SYRINGE_HOOK_H */
