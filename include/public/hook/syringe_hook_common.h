/*
 * syringe_hook_common.h — arch-agnostic hook framework
 *
 * Provides the per-TU registry, GOT/PLT walker, safe_write helpers,
 * trampoline install/remove, and the public API (install, install_addr,
 * read_dst, remove, count, is_installed, etc.).
 *
 * Calls into arch-specific functions declared in
 * include/hook/arch/syringe_hook_arch.h:
 *
 *   - syringe_hook_arch_build_jmp
 *   - syringe_hook_arch_disasm
 *   - syringe_hook_arch_tramp_make
 *   - syringe_hook_arch_atomic_patch_jmp
 *
 * This file is included by syringe_hook.h AFTER the arch header, so the
 * arch_* functions above are already defined. Do NOT include this file
 * directly — include <syringe/hook/syringe_hook.h> from one .c file.
 */

#ifndef SYRINGE_HOOK_COMMON_H
#define SYRINGE_HOOK_COMMON_H

/* Pull in Trampoline, SyringeHookRecord, WalkCtx, the TRAMP_*_MAX
 * constants (defined by the arch header that ran before us), and the
 * /proc/self/mem helpers (syringe_memfd, memfd_open, mem_write, mem_read).
 * These live in types.h because the arch header's tramp_make uses them
 * and the arch header runs BEFORE this common file. */
#include "syringe_hook_types.h"

/* ── per-TU registry (private to each translation unit) ──────────────────── */

static SyringeHookRecord syringe_hooks[SYRINGE_HOOK_MAX];
static int               syringe_nhooks = 0;

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

/* ── safe_write (for data pages — GOT slots) ──────────────────────────────
 * Try mprotect first, fall back to /proc/self/mem, then process_vm_writev. */
static inline int syringe_hook_safe_write(void *dst, const void *src, size_t len) {
    int ro = syringe_hook_page_is_ro(dst);
    if (ro) {
        if (syringe_hook_make_rw(dst) == 0) {
            memcpy(dst, src, len);
            syringe_hook_make_ro(dst);
            SYRINGE_HOOK_LOG("safe_write: patched via mprotect @ %p", dst);
            return 0;
        }
        int merr = errno;
        SYRINGE_HOOK_LOG("safe_write: mprotect failed (err=%d), trying /proc/self/mem ...", merr);

        if (syringe_hook_mem_write(dst, src, len) == 0) {
            SYRINGE_HOOK_LOG("safe_write: patched via /proc/self/mem @ %p", dst);
            return 0;
        }
        SYRINGE_HOOK_LOG("safe_write: /proc/self/mem failed, trying process_vm_writev ...");

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

/* ── safe_write_code (for code pages — preserves EXECUTE bit) ──────────────
 *
 * Strategy: try /proc/self/mem FIRST (atomic, no permission change, no
 * window where the page is non-executable). Fall back to process_vm_writev
 * (also atomic, no mprotect). Only as last resort use mprotect RW→memcpy→
 * mprotect RX — there's a brief window where the page is non-executable,
 * but if we got here it means both /proc/self/mem and process_vm_writev
 * are unavailable (seccomp), so this is the best we can do.
 *
 * This is the OPPOSITE order from safe_write (data) because for code we
 * MUST avoid the transient RW-without-X state — another thread executing
 * the function during that window would SIGSEGV. */
static inline int syringe_hook_safe_write_code(void *dst, const void *src, size_t len) {
    syringe_hook_memfd_open();
    if (syringe_memfd >= 0) {
        if (syringe_hook_mem_write(dst, src, len) == 0) {
            SYRINGE_HOOK_LOG("safe_write_code: patched via /proc/self/mem @ %p", dst);
            return 0;
        }
        SYRINGE_HOOK_LOG("safe_write_code: /proc/self/mem failed, trying process_vm_writev");
    }

    if (syringe_hook_process_vm_writev(dst, src, len) == 0) {
        __builtin___clear_cache((char*)dst, (char*)dst + len);
        SYRINGE_HOOK_LOG("safe_write_code: patched via process_vm_writev @ %p", dst);
        return 0;
    }
    SYRINGE_HOOK_LOG("safe_write_code: process_vm_writev failed, falling back to mprotect");

    if (syringe_hook_make_rw(dst) == 0) {
        memcpy(dst, src, len);
        syringe_hook_make_rx(dst);
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

/* ── public trampoline install / remove ───────────────────────────────────
 *
 * syringe_hook_tramp_install:
 *   - always tries to patch (no page_is_ro gate)
 *   - uses the length-disassembler (arch-specific) to steal whole instructions
 *   - patches PC-relative / rel disps in the bounce stub (arch-specific)
 *   - emits the target patch via arch_atomic_patch_jmp
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

    /* Build the bounce stub (stolen prologue + JMP back). arch_tramp_make
     * returns the exact byte count we must overwrite on the target.
     * It reads the prologue via /proc/self/mem (safe pread). */
    size_t stolen = syringe_hook_arch_tramp_make(t->bounce, t->bounce_len,
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

    /* Build the JMP-to-hook and patch the target prologue.
     * Use safe_write_code (not safe_write) so we preserve the EXECUTE
     * bit on the target page — otherwise the next call to the hooked
     * function SIGSEGVs. */
    uint8_t jmp[TRAMP_JMP_SZ];
    syringe_hook_arch_build_jmp(jmp, hook);

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
        syringe_hook_arch_atomic_patch_jmp(target, jmp);
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
    /* Restore exactly the bytes we overwrote (correctly sized to
     * t->stolen_len). Use safe_write_code so we keep EXECUTE permission
     * on the target page after restore. */
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

static inline int syringe_hook_install(const char *sym, void *hook, void **orig_out) {
    if (syringe_nhooks >= SYRINGE_HOOK_MAX) { SYRINGE_HOOK_LOG("hook table full"); return 0; }
    for (int i = 0; i < syringe_nhooks; i++)
        if (strcmp(syringe_hooks[i].sym, sym) == 0) {
            SYRINGE_HOOK_LOG("'%s' already hooked", sym); return 0;
        }

    SyringeHookRecord *rec = &syringe_hooks[syringe_nhooks];
    memset(rec, 0, sizeof(*rec));
    if (strlen(sym) >= sizeof(rec->sym)) {
        SYRINGE_HOOK_LOG("'%s': symbol name too long (max %zu)", sym, sizeof(rec->sym) - 1);
        return 0;
    }
    strncpy(rec->sym, sym, sizeof(rec->sym)-1);
    rec->hook     = hook;
    rec->orig_out = orig_out;

    SYRINGE_HOOK_LOG("installing '%s' hook → %p", sym, hook);

    WalkCtx ctx = { sym, hook, rec, 0 };
    dl_iterate_phdr(syringe_hook_phdr_cb, &ctx);
    SYRINGE_HOOK_LOG("'%s': %d GOT slot(s) patched", sym, ctx.count);

    if (rec->orig_addr == NULL || rec->orig_addr == hook) {
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
    if (strlen(sym) >= sizeof(rec->sym)) {
        SYRINGE_HOOK_LOG("'%s': symbol name too long (max %zu)", sym, sizeof(rec->sym) - 1);
        return 0;
    }
    strncpy(rec->sym, sym, sizeof(rec->sym)-1);
    rec->hook      = hook;
    rec->orig_out  = orig_out;
    rec->orig_addr = target;

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

#ifndef SYRINGE_HOOK_NO_HELPERS
static inline void *syringe_hook_jmp_target(void *src) {
    return syringe_hook_arch_read_jmp_target(src);
}

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

static inline void syringe_hook_remove_all(void) {
    for (int i = syringe_nhooks-1; i >= 0; i--)
        syringe_hook_remove(syringe_hooks[i].sym);
}

static inline int syringe_hook_count(void) {
    return syringe_nhooks;
}

static inline int syringe_hook_is_installed(const char *sym) {
    for (int i = 0; i < syringe_nhooks; i++) {
        if (strcmp(syringe_hooks[i].sym, sym) == 0) return 1;
    }
    return 0;
}

static inline int syringe_hook_registry_size(void) {
    return SYRINGE_HOOK_MAX;
}
#endif /* !SYRINGE_HOOK_NO_HELPERS */

#endif /* SYRINGE_HOOK_COMMON_H */
