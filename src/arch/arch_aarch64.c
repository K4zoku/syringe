/*
 * arch_aarch64.c — ARM64 (aarch64) backend for syringe injector
 *
 * Implements the interface declared in arch.h:
 *   - syringe_arch_build_shellcode : aarch64 dlopen() trampoline
 *   - syringe_arch_getregs/setregs : PTRACE_GETREGSET / SETREGSET with NT_PRSTATUS
 *   - syringe_arch_get_pc/set_pc   : pc field of user_pt_regs
 *   - syringe_arch_get_sp          : sp field of user_pt_regs
 *   - syringe_arch_entry_skip      : 0 (no ptrace restart quirk on aarch64)
 *   - syringe_arch_*_type          : R_AARCH64_JUMP_SLOT / GLOB_DAT
 *
 * Shellcode layout (4-byte instructions throughout):
 *
 *   ┌─ entry (no NOPs — aarch64 has no ptrace restart quirk) ─┐
 *   │ stp x29, x30, [sp, #-16]!       save frame pointer + LR  │
 *   │ stp x0,  x1,  [sp, #-16]!       save args                │
 *   │ stp x2,  x3,  [sp, #-16]!                                 │
 *   │ stp x4,  x5,  [sp, #-16]!                                 │
 *   │ stp x6,  x7,  [sp, #-16]!                                 │
 *   │ stp x8,  x9,  [sp, #-16]!                                 │
 *   │ stp x10, x11, [sp, #-16]!                                 │
 *   │ stp x12, x13, [sp, #-16]!                                 │
 *   │ stp x14, x15, [sp, #-16]!                                 │
 *   │ stp x16, x17, [sp, #-16]!                                 │
 *   │ stp x18, x19, [sp, #-16]!                                 │
 *   │ stp x20, x21, [sp, #-16]!                                 │
 *   │ stp x22, x23, [sp, #-16]!                                 │
 *   │ stp x24, x25, [sp, #-16]!                                 │
 *   │ stp x26, x27, [sp, #-16]!                                 │
 *   │ stp x28, x29, [sp, #-16]!       (x29 already saved, but  │
 *   │                                  keeping symmetric)       │
 *   ├─ set up dlopen args ────────────────────────────────────┤
 *   │ adr x0, path                     x0 = &path (PC-relative)│
 *   │ mov x1, #0x102                    x1 = RTLD_NOW|RTLD_GLOBAL│
 *   │ movz x16, #(dlopen_addr & 0xFFFF)                         │
 *   │ movk x16, #(dlopen_addr >> 16 & 0xFFFF), lsl #16         │
 *   │ movk x16, #(dlopen_addr >> 32 & 0xFFFF), lsl #32         │
 *   │ movk x16, #(dlopen_addr >> 48 & 0xFFFF), lsl #48         │
 *   │ blr x16                          call dlopen              │
 *   ├─ trap for injector to catch ─────────────────────────────┤
 *   │ brk #0                           trap (0xD4200000)        │
 *   ├─ restore GPRs (reverse order) ───────────────────────────┤
 *   │ ldp x28, x29, [sp], #16                                   │
 *   │ ldp x26, x27, [sp], #16                                   │
 *   │ ... (all the way back to x0/x1)                          │
 *   │ ldp x29, x30, [sp], #16                                   │
 *   │ ret                              return to caller         │
 *   └─ embedded path string ──────────────────────────────────┘
 *   │ "/path/to/lib.so\0"                                       │
 *   └──────────────────────────────────────────────────────────┘
 *
 * Register access via PTRACE_GETREGSET (kernel >= 3.5):
 *   struct user_pt_regs {
 *       __u64 regs[31];   // x0-x30
 *       __u64 sp;
 *       __u64 pc;
 *       __u64 pstate;
 *   };
 *
 *   struct iovec iov = { &regs_buf, sizeof(regs_buf) };
 *   ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov);
 *
 * PAC handling: addresses read from the target's registers may have
 * PAC bits set. We strip them before using as a patch destination via
 * the same `xpac` trick used in the hooker.
 */

#define _GNU_SOURCE

#include "arch.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>      /* struct iovec for PTRACE_GETREGSET */
#include <sys/user.h>
#include <elf.h>           /* R_AARCH64_* — also pulls in Elf64_* types */
#include <asm/ptrace.h>    /* struct user_pt_regs */
/* NT_PRSTATUS: defined in <elf.h> (glibc) since glibc 2.18+.
 * Don't include <linux/elf.h> here — it conflicts with <elf.h>.
 * If your glibc is older, define the constant manually. */
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

/* Sanity: the native regset must fit in the opaque storage. */
_Static_assert(sizeof(struct user_pt_regs) <= SYRINGE_ARCH_REGS_MAX,
               "SYRINGE_ARCH_REGS_MAX too small for aarch64 user_pt_regs");

/* RTLD_NOW(2) | RTLD_GLOBAL(0x100) — emitted as the dlopen() flags arg. */
#define RTLD_NOW_GLOBAL  0x102

/* ── aarch64 instruction encoders ────────────────────────────────────────────
 *
 * Each function returns the 4-byte encoding of one instruction.
 */

/* stp xN, xM, [sp, #-16]!  (pre-indexed, 64-bit)
 * Encoding: 1010 1001 10 imm7 Rt2 Rn Rt
 *   opc=10 (64-bit), V=0, L=0 (store), imm7=-2 (offset -16 bytes / 8)
 *   Rn = sp (31), Rt2 = xM, Rt = xN
 */
static inline uint32_t emit_stp_pre(int rt, int rt2) {
    /* imm7 = -2 (signed 7-bit, scale 8 → offset = -16)
     * Rn = 31 (sp), Rt2, Rt
     * bits: 1010 1001 10 imm7[6:0] Rt2[4:0] Rn[4:0] Rt[4:0]
     */
    return 0xA9800000       /* base: stp ..., [sp, #0]! pre-indexed */
         | ((uint32_t)(-2 & 0x7F) << 15)  /* imm7 = -2 */
         | ((uint32_t)(rt2 & 0x1F) << 10)
         | ((uint32_t)31 << 5)            /* Rn = sp */
         | (uint32_t)(rt & 0x1F);
}

/* ldp xN, xM, [sp], #16  (post-indexed, 64-bit)
 * Encoding: 1010 1001 01 imm7 Rt2 Rn Rt
 *   opc=10, V=0, L=1 (load), imm7=2 (offset +16 bytes / 8)
 *   Rn = sp (31), Rt2 = xM, Rt = xN
 */
static inline uint32_t emit_ldp_post(int rt, int rt2) {
    return 0xA8C00000       /* base: ldp ..., [sp], #0 post-indexed */
         | ((uint32_t)2 << 15)            /* imm7 = +2 */
         | ((uint32_t)(rt2 & 0x1F) << 10)
         | ((uint32_t)31 << 5)            /* Rn = sp */
         | (uint32_t)(rt & 0x1F);
}

/* adr x0, label  — PC-relative address with 21-bit signed byte offset
 * Encoding: 0 immlo 10000 immhi Rd
 *   imm = (label - pc), split into immlo (bits 30:29) and immhi (bits 23:5)
 */
static inline uint32_t emit_adr_x0(int32_t offset) {
    int32_t immlo = offset & 0x3;
    int32_t immhi = (offset >> 2) & 0x7FFFF;
    return 0x10000000
         | ((uint32_t)immlo << 29)
         | ((uint32_t)immhi << 5)
         | 0;   /* Rd = x0 */
}

/* mov x1, #imm16  (movz, 16-bit immediate, no shift)
 * Encoding: 110100101 00 imm16 Rd
 */
static inline uint32_t emit_movz_x1(uint16_t imm16) {
    return 0xD2800000
         | ((uint32_t)imm16 << 5)
         | 1;   /* Rd = x1 */
}

/* movz x16, #imm16, lsl #0   — first chunk of 64-bit immediate */
static inline uint32_t emit_movz_x16(uint16_t imm16, int shift) {
    /* shift in {0, 16, 32, 48}, encoded as hw = shift/16 */
    uint32_t hw = (uint32_t)(shift / 16);
    return 0xD2800000
         | (hw << 21)
         | ((uint32_t)imm16 << 5)
         | 16;   /* Rd = x16 */
}

/* movk x16, #imm16, lsl #shift  — keep low bits, insert new chunk */
static inline uint32_t emit_movk_x16(uint16_t imm16, int shift) {
    uint32_t hw = (uint32_t)(shift / 16);
    return 0xF2800000
         | (hw << 21)
         | ((uint32_t)imm16 << 5)
         | 16;
}

/* blr x16  — branch with link to address in x16
 * Encoding: 1101011000 1 11111 0000 00 Rn 00000
 *   Rn = 16
 */
static inline uint32_t emit_blr_x16(void) {
    return 0xD63F0200;
}

/* brk #0  — breakpoint trap (used by injector to catch the shellcode) */
static inline uint32_t emit_brk_0(void) {
    return 0xD4200000;
}

/* ret  — return to address in x30 (link register) */
static inline uint32_t emit_ret(void) {
    return 0xD65F03C0;
}

/* ── shellcode builder ──────────────────────────────────────────────────── */

size_t syringe_arch_build_shellcode(unsigned char *buf, size_t bufsz,
                                     unsigned long dlopen_addr,
                                     const char *so_path,
                                     unsigned long inject_addr) {
    (void)inject_addr; /* aarch64 adr is PC-relative, independent of base */
    unsigned char *p = buf;

#define EMIT32(v) do {                                   \
    if ((size_t)(p - buf) + 4 > bufsz) {                 \
        fprintf(stderr, "[!] shellcode buffer overflow at %zu\n", \
                (size_t)(p - buf));                      \
        return 0;                                        \
    }                                                    \
    uint32_t _v = (uint32_t)(v);                         \
    memcpy(p, &_v, 4); p += 4;                           \
} while(0)

    /* Save frame pointer + link register + all argument registers x0-x28.
     * x29 (frame ptr) and x30 (LR) first, then x0-x28 in pairs.
     * Total: 1 (x29,x30) + 14 (x0-x28 in pairs) = 15 stp instructions.
     * Stack used: 15 × 16 = 240 bytes. */
    EMIT32(emit_stp_pre(29, 30));
    EMIT32(emit_stp_pre(0,  1));
    EMIT32(emit_stp_pre(2,  3));
    EMIT32(emit_stp_pre(4,  5));
    EMIT32(emit_stp_pre(6,  7));
    EMIT32(emit_stp_pre(8,  9));
    EMIT32(emit_stp_pre(10, 11));
    EMIT32(emit_stp_pre(12, 13));
    EMIT32(emit_stp_pre(14, 15));
    EMIT32(emit_stp_pre(16, 17));
    EMIT32(emit_stp_pre(18, 19));
    EMIT32(emit_stp_pre(20, 21));
    EMIT32(emit_stp_pre(22, 23));
    EMIT32(emit_stp_pre(24, 25));
    EMIT32(emit_stp_pre(26, 27));
    /* x28 alone — pair it with a dummy stp x28, xzr */
    /* Actually we have x28 left. stp needs a pair; use xzr (reg 31 in
     * this context means sp, but for stp Rt encoding reg 31 = xzr when
     * not used as addressing register). To keep it simple, save x28
     * with xzr: */
    /* stp x28, xzr, [sp, #-16]! — xzr = register 31 in data context */
    EMIT32(0xA9800000 | ((uint32_t)(-2 & 0x7F) << 15)
                     | ((uint32_t)31 << 10)   /* Rt2 = xzr */
                     | ((uint32_t)31 << 5)    /* Rn = sp */
                     | 28);                   /* Rt = x28 */

    /* adr x0, path — placeholder, we patch the offset after laying out code */
    size_t adr_offset = (size_t)(p - buf);
    EMIT32(emit_adr_x0(0));   /* placeholder offset 0 */

    /* mov x1, #0x102 (RTLD_NOW | RTLD_GLOBAL) */
    EMIT32(emit_movz_x1(RTLD_NOW_GLOBAL & 0xFFFF));

    /* movz/movk x16, dlopen_addr (4 chunks of 16 bits) */
    uint64_t dl = (uint64_t)dlopen_addr;
    EMIT32(emit_movz_x16((uint16_t)(dl >>  0),  0));
    EMIT32(emit_movk_x16((uint16_t)(dl >> 16), 16));
    EMIT32(emit_movk_x16((uint16_t)(dl >> 32), 32));
    EMIT32(emit_movk_x16((uint16_t)(dl >> 48), 48));

    /* blr x16 */
    EMIT32(emit_blr_x16());

    /* brk #0 — trap for injector */
    EMIT32(emit_brk_0());

    /* Restore GPRs in reverse order */
    /* ldp x28, xzr, [sp], #16 */
    EMIT32(0xA8C00000 | ((uint32_t)2 << 15)
                     | ((uint32_t)31 << 10)   /* Rt2 = xzr */
                     | ((uint32_t)31 << 5)    /* Rn = sp */
                     | 28);                   /* Rt = x28 */
    EMIT32(emit_ldp_post(26, 27));
    EMIT32(emit_ldp_post(24, 25));
    EMIT32(emit_ldp_post(22, 23));
    EMIT32(emit_ldp_post(20, 21));
    EMIT32(emit_ldp_post(18, 19));
    EMIT32(emit_ldp_post(16, 17));
    EMIT32(emit_ldp_post(14, 15));
    EMIT32(emit_ldp_post(12, 13));
    EMIT32(emit_ldp_post(10, 11));
    EMIT32(emit_ldp_post(8,  9));
    EMIT32(emit_ldp_post(6,  7));
    EMIT32(emit_ldp_post(4,  5));
    EMIT32(emit_ldp_post(2,  3));
    EMIT32(emit_ldp_post(0,  1));
    EMIT32(emit_ldp_post(29, 30));

    /* ret */
    EMIT32(emit_ret());

    /* ── path string ── */
    size_t path_start = (size_t)(p - buf);
    size_t path_len   = strlen(so_path) + 1;
    /* Align path to 4 bytes so the offset is a clean adr displacement */
    while (path_start % 4 != 0) {
        if ((size_t)(p - buf) + 1 > bufsz) return 0;
        *p++ = 0;
        path_start++;
    }
    if ((size_t)(p - buf) + path_len > bufsz) {
        fprintf(stderr, "[!] shellcode buffer overflow (path) at %zu\n",
                (size_t)(p - buf));
        return 0;
    }
    memcpy(p, so_path, path_len);
    p += path_len;

    /* Patch the adr offset: adr is at buf+adr_offset, and its PC value
     * (when executing) = inject_addr + adr_offset. Target = inject_addr + path_start.
     * disp = (inject_addr + path_start) - (inject_addr + adr_offset) = path_start - adr_offset.
     */
    int32_t adr_disp = (int32_t)(path_start - adr_offset);
    uint32_t adr_insn;
    memcpy(&adr_insn, buf + adr_offset, 4);
    int32_t immlo = adr_disp & 0x3;
    int32_t immhi = (adr_disp >> 2) & 0x7FFFF;
    adr_insn = (adr_insn & 0x9F00001F)
             | ((uint32_t)immlo << 29)
             | ((uint32_t)immhi << 5);
    memcpy(buf + adr_offset, &adr_insn, 4);

    return (size_t)(p - buf);

#undef EMIT32
}

/* ── register access ────────────────────────────────────────────────────── */

int syringe_arch_getregs(pid_t pid, SyringeArchRegs *regs) {
    struct user_pt_regs u;
    struct iovec iov = { &u, sizeof(u) };
    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) < 0) {
        fprintf(stderr, "[!] PTRACE_GETREGSET failed: %s\n", strerror(errno));
        return -1;
    }
    memcpy(regs->_u._buf, &u, sizeof u);
    return 0;
}

int syringe_arch_setregs(pid_t pid, const SyringeArchRegs *regs) {
    struct user_pt_regs u;
    memcpy(&u, regs->_u._buf, sizeof u);
    struct iovec iov = { &u, sizeof(u) };
    if (ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov) < 0) {
        fprintf(stderr, "[!] PTRACE_SETREGSET failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

unsigned long syringe_arch_get_pc(const SyringeArchRegs *regs) {
    struct user_pt_regs u;
    memcpy(&u, regs->_u._buf, sizeof u);
    return (unsigned long)u.pc;
}

void syringe_arch_set_pc(SyringeArchRegs *regs, unsigned long pc) {
    struct user_pt_regs u;
    memcpy(&u, regs->_u._buf, sizeof u);
    u.pc = (__u64)pc;
    memcpy(regs->_u._buf, &u, sizeof u);
}

unsigned long syringe_arch_get_sp(const SyringeArchRegs *regs) {
    struct user_pt_regs u;
    memcpy(&u, regs->_u._buf, sizeof u);
    return (unsigned long)u.sp;
}

/* ── misc arch constants ────────────────────────────────────────────────── */

unsigned long syringe_arch_entry_skip(void) {
    return 0;   /* aarch64 has no ptrace restart quirk */
}

unsigned int syringe_arch_jump_slot_type(void) {
    return R_AARCH64_JUMP_SLOT;
}

unsigned int syringe_arch_glob_dat_type(void) {
    return R_AARCH64_GLOB_DAT;
}
