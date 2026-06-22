/*
 * syringe_hook_types.h — shared types and constants for syringe_hook
 *
 * Tiny header included by both syringe_hook_common.h and the per-arch
 * headers (syringe_hook_x86_64.h, syringe_hook_aarch64.h, ...).
 *
 * Provides:
 *   - Trampoline struct (needs TRAMP_STOLEN_MAX, defined by arch header
 *     BEFORE including this file — see syringe_hook.h dispatch order)
 *   - SyringeHookRecord struct (registry entry)
 *   - WalkCtx struct (GOT walk callback context)
 *
 * IMPORTANT: arch headers must #define TRAMP_JMP_SZ, TRAMP_STOLEN_MAX,
 * TRAMP_BOUNCE_MAX BEFORE including this file (or this file is included
 * after the arch header in syringe_hook.h).
 */

#ifndef SYRINGE_HOOK_TYPES_H
#define SYRINGE_HOOK_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

/* Trampoline struct — fields are arch-agnostic, but stolen[] size depends
 * on TRAMP_STOLEN_MAX which is defined by the arch header.
 *
 * If TRAMP_STOLEN_MAX is not defined yet (e.g. unsupported arch with the
 * stub fallback in syringe_hook.h), use a default. */
#ifndef TRAMP_STOLEN_MAX
#define TRAMP_STOLEN_MAX 32
#endif
#ifndef TRAMP_JMP_SZ
#define TRAMP_JMP_SZ 16
#endif
#ifndef TRAMP_BOUNCE_MAX
#define TRAMP_BOUNCE_MAX (TRAMP_STOLEN_MAX + TRAMP_JMP_SZ)
#endif
#ifndef BOUNCE_SZ
#define BOUNCE_SZ TRAMP_BOUNCE_MAX
#endif

typedef struct {
    uint8_t  stolen[TRAMP_STOLEN_MAX]; /* original prologue bytes */
    size_t   stolen_len;               /* exact bytes overwritten on target */
    void    *target;                   /* hooked function address */
    uint8_t *bounce;                   /* mmap'd trampoline stub */
    size_t   bounce_len;               /* size of bounce (for munmap) */
    int      active;                   /* 1 if currently installed */
} Trampoline;

/* Forward declaration for WalkCtx (defined fully below) */
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

typedef struct {
    const char        *sym_name;
    void              *hook;
    SyringeHookRecord *rec;
    int                count;
} WalkCtx;

/* ── /proc/self/mem helpers ──────────────────────────────────────────────────
 *
 * These are pulled into types.h (rather than common.h) because the arch
 * header's tramp_make function needs to call syringe_hook_memfd_open() and
 * read syringe_memfd — and the arch header runs BEFORE common.h in the
 * include order.
 *
 * The registry state (syringe_hooks, syringe_nhooks) stays in common.h
 * because arch code doesn't touch it. */
static int syringe_memfd = -1;

/* SYRINGE_HOOK_LOG is defined in syringe_hook.h (the dispatcher) before
 * the arch header is included, so it's available here. */
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

#endif /* SYRINGE_HOOK_TYPES_H */
