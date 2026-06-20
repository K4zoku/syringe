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
    fprintf(stderr, "[syringe_hook] " fmt "\n", ##__VA_ARGS__)
#endif

/* ── Trampoline structures ──────────────────────────────────────────────── */

#define TRAMP_JMP_SZ   14
#define TRAMP_STOLEN   16
#define BOUNCE_SZ      (TRAMP_STOLEN + TRAMP_JMP_SZ)

typedef struct {
    uint8_t  stolen[TRAMP_STOLEN];
    void    *target;
    uint8_t *bounce;
    int      active;
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

/* Safe write: try mprotect first, fall back to /proc/self/mem */
static inline int syringe_hook_safe_write(void *dst, const void *src, size_t len) {
    int ro = syringe_hook_page_is_ro(dst);
    if (ro) {
        if (syringe_hook_make_rw(dst) == 0) {
            memcpy(dst, src, len);
            syringe_hook_make_ro(dst);
            return 0;
        }
        SYRINGE_HOOK_LOG("mprotect failed, trying /proc/self/mem ...");
        return syringe_hook_mem_write(dst, src, len);
    }
    memcpy(dst, src, len);
    return 0;
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
        return syringe_hook_mem_write(slot, &val, sizeof(val));
    }
    syringe_hook_atomic_write_ptr(slot, val);
    return 0;
}

/* ── inline trampoline ──────────────────────────────────────────────────── */

static inline void syringe_hook_build_jmp(uint8_t *buf, void *dest) {
    buf[0]=0xFF; buf[1]=0x25;
    buf[2]=buf[3]=buf[4]=buf[5]=0x00;
    memcpy(buf+6, &dest, 8);
}

static inline int syringe_hook_tramp_install(Trampoline *t, void *target, void *hook, void **orig_out) {
    memset(t, 0, sizeof(*t));
    t->target = target;

    if (target == NULL) {
        SYRINGE_HOOK_LOG("tramp: NULL target address");
        return -1;
    }

    t->bounce = (uint8_t*)mmap(NULL, BOUNCE_SZ,
                                PROT_READ|PROT_WRITE|PROT_EXEC,
                                MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (t->bounce == MAP_FAILED) {
        SYRINGE_HOOK_LOG("tramp: mmap bounce failed: %s", strerror(errno));
        return -1;
    }

    /* Read the prologue bytes from the target function. If the target
     * is in a protected/unreadable region (e.g., vDSO, kernel trap gate),
     * reading may segfault. Use /proc/self/mem pread as a safe shadow-read
     * so we never dereference an invalid address directly. */
    if (syringe_memfd < 0) syringe_hook_memfd_open();
    if (syringe_memfd >= 0) {
        ssize_t rd = pread(syringe_memfd, t->stolen, TRAMP_STOLEN,
                           (off_t)(uintptr_t)target);
        if (rd == (ssize_t)TRAMP_STOLEN) {
            memcpy(t->bounce, t->stolen, TRAMP_STOLEN);
        } else {
            /* Can't read target — zero-fill. write path will fail safely. */
            memset(t->stolen, 0, TRAMP_STOLEN);
            memset(t->bounce, 0, TRAMP_STOLEN);
        }
    } else {
        /* No /proc/self/mem: must read directly (may segfault on protected pages) */
        memcpy(t->stolen, target, TRAMP_STOLEN);
        memcpy(t->bounce, t->stolen, TRAMP_STOLEN);
    }

    uint8_t *ret_site = (uint8_t*)target + TRAMP_STOLEN;
    syringe_hook_build_jmp(t->bounce + TRAMP_STOLEN, ret_site);

    uint8_t jmp[TRAMP_JMP_SZ];
    syringe_hook_build_jmp(jmp, hook);
    if (syringe_hook_safe_write(target, jmp, TRAMP_JMP_SZ) != 0) {
        SYRINGE_HOOK_LOG("tramp: patch failed for %p", target);
        munmap(t->bounce, BOUNCE_SZ);
        return -1;
    }

    __builtin___clear_cache(target, (char*)target + TRAMP_JMP_SZ);

    t->active = 1;
    if (orig_out) *orig_out = t->bounce;
    SYRINGE_HOOK_LOG("tramp: patched %p → %p (bounce @ %p)", target, hook, t->bounce);
    return 0;
}

static inline void syringe_hook_tramp_remove(Trampoline *t) {
    if (!t->active) return;
    syringe_hook_safe_write(t->target, t->stolen, TRAMP_STOLEN);
    __builtin___clear_cache(t->target, (char*)t->target + TRAMP_STOLEN);
    munmap(t->bounce, BOUNCE_SZ);
    t->active = 0;
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

    if (rec->orig_addr == NULL) {
        (void)dlsym(RTLD_DEFAULT, sym);
        rec->orig_addr = dlsym(RTLD_DEFAULT, sym);
    }

    if (rec->orig_addr && rec->orig_addr != hook) {
        void *tramp_orig = NULL;
        /* Only install inline trampoline for symbols with NO GOT patches.
         * Symbols with GOT patches are already redirected via PLT/GOT,
         * so patching the target function itself is unnecessary and dangerous
         * (corrupts shared-library code that may call the symbol internally).
         *
         * For symbols WITHOUT GOT entries (intra-library calls), the trampoline
         * is essential. syringe_hook_tramp_install() uses syringe_hook_safe_write()
         * which has full fallback: mprotect → /proc/self/mem. */
        if (rec->npatch > 0) {
            /* Already hooked via GOT/PLT — no trampoline needed */
            SYRINGE_HOOK_LOG("'%s': GOT-only (skip trampoline)", sym);
            if (orig_out) *orig_out = rec->orig_addr;
        } else {
            /* No GOT entries — need trampoline for direct calls */
            if (syringe_hook_tramp_install(&rec->tramp, rec->orig_addr, hook, &tramp_orig) == 0) {
                rec->has_tramp = 1;
                if (orig_out) *orig_out = tramp_orig;
                SYRINGE_HOOK_LOG("'%s': inline trampoline installed", sym);
            } else {
                SYRINGE_HOOK_LOG("'%s': inline trampoline failed (GOT-only)", sym);
                if (orig_out) *orig_out = rec->orig_addr;
            }
        }
    } else {
        if (orig_out) *orig_out = rec->orig_addr;
    }

    if (ctx.count == 0 && !rec->has_tramp) {
        SYRINGE_HOOK_LOG("'%s': no GOT slots and trampoline skipped — hook not installed", sym);
        return 0;
    }

    syringe_nhooks++;
    return ctx.count + (rec->has_tramp ? 1 : 0);
}

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
