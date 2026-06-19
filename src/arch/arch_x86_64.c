/*
 * arch_x86_64.c — x86-64 backend for syringe
 *
 * Implements the interface declared in arch.h:
 *   - syringe_arch_build_shellcode : x86-64 dlopen() trampoline
 *   - syringe_arch_getregs/setregs : PTRACE_GETREGS / SETREGS
 *   - syringe_arch_get_pc/set_pc   : rip
 *   - syringe_arch_get_sp          : rsp
 *   - syringe_arch_entry_skip      : 2 (NOPs for ptrace restart quirk)
 *   - syringe_arch_*_type          : R_X86_64_JUMP_SLOT / GLOB_DAT
 *
 * The shellcode was lifted verbatim from the previous monolithic
 * src/syringe.c; only the symbol name changed (syringe_build_shellcode ->
 * syringe_arch_build_shellcode). Existing unit tests keep exercising it
 * through the syringe_build_shellcode() escape-hatch wrapper in syringe.c.
 *
 * Register access shuttles the native struct user_regs_struct in and out of
 * the opaque SyringeArchRegs buffer via memcpy — no aliasing, and the
 * layout is never visible outside this translation unit.
 */
#define _GNU_SOURCE

#include "arch.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>      /* struct user_regs_struct */
#include <elf.h>           /* R_X86_64_* */

/* Sanity: the native regset must fit in the opaque storage. */
_Static_assert(sizeof(struct user_regs_struct) <= SYRINGE_ARCH_REGS_MAX,
               "SYRINGE_ARCH_REGS_MAX too small for x86-64 user_regs_struct");

/* RTLD_NOW(2) | RTLD_GLOBAL(0x100) — emitted as the dlopen() flags arg. */
#define RTLD_NOW_GLOBAL  0x102

/* ── shellcode builder ──────────────────────────────────────────────────── */

size_t syringe_arch_build_shellcode(unsigned char *buf, size_t bufsz,
                                     unsigned long dlopen_addr,
                                     const char *so_path,
                                     unsigned long inject_addr) {
    (void)inject_addr; /* RIP-relative displacement is independent of base */
    unsigned char *p = buf;

#define EMIT(...)  do {                                           \
    unsigned char _b[] = {__VA_ARGS__};                          \
    if (p - buf + sizeof(_b) >= bufsz) {                         \
        fprintf(stderr, "[!] shellcode buffer overflow at %zu\n", \
                p - buf);                                         \
        return 0;                                                 \
    }                                                            \
    memcpy(p, _b, sizeof(_b)); p += sizeof(_b);                  \
} while(0)

#define EMIT64(v) do { uint64_t _v = (uint64_t)(v); \
    memcpy(p, &_v, 8); p += 8; } while(0)

#define EMIT32(v) do { uint32_t _v = (uint32_t)(v); \
    memcpy(p, &_v, 4); p += 4; } while(0)

    /* Entry NOPs for ptrace RIP-2 quirk */
    EMIT(0x90, 0x90);                    /* nop nop */

    /* Save flags + all GPRs */
    EMIT(0x9C);                          /* pushfq */
    EMIT(0x50);                          /* push rax */
    EMIT(0x51);                          /* push rcx */
    EMIT(0x52);                          /* push rdx */
    EMIT(0x53);                          /* push rbx */
    EMIT(0x55);                          /* push rbp */
    EMIT(0x56);                          /* push rsi */
    EMIT(0x57);                          /* push rdi */
    EMIT(0x41,0x50);                     /* push r8  */
    EMIT(0x41,0x51);                     /* push r9  */
    EMIT(0x41,0x52);                     /* push r10 */
    EMIT(0x41,0x53);                     /* push r11 */
    EMIT(0x41,0x54);                     /* push r12 */
    EMIT(0x41,0x55);                     /* push r13 */
    EMIT(0x41,0x56);                     /* push r14 */
    EMIT(0x41,0x57);                     /* push r15 */

    /* lea rdi, [rip + offset_to_path]
     * RIP after the lea+modrm+sib+disp4 = p+7
     * path string starts after the entire preamble; we'll fill offset below */
    size_t lea_offset_pos = (size_t)(p - buf) + 3; /* position of the 32-bit disp */
    EMIT(0x48, 0x8D, 0x3D);             /* lea rdi, [rip+disp32] */
    EMIT32(0);                           /* placeholder */

    /* mov rsi, RTLD_NOW|RTLD_GLOBAL */
    EMIT(0x48, 0xBE);                    /* mov rsi, imm64 */
    EMIT64((uint64_t)RTLD_NOW_GLOBAL);

    /* mov rax, dlopen_addr */
    EMIT(0x48, 0xB8);                    /* mov rax, imm64 */
    EMIT64(dlopen_addr);

    /* call rax */
    EMIT(0xFF, 0xD0);

    /* int3 — trap so the injector can continue */
    EMIT(0xCC);

    /* Restore all GPRs + flags */
    EMIT(0x41,0x5F);                     /* pop r15 */
    EMIT(0x41,0x5E);                     /* pop r14 */
    EMIT(0x41,0x5D);                     /* pop r13 */
    EMIT(0x41,0x5C);                     /* pop r12 */
    EMIT(0x41,0x5B);                     /* pop r11 */
    EMIT(0x41,0x5A);                     /* pop r10 */
    EMIT(0x41,0x59);                     /* pop r9  */
    EMIT(0x41,0x58);                     /* pop r8  */
    EMIT(0x5F);                          /* pop rdi */
    EMIT(0x5E);                          /* pop rsi */
    EMIT(0x5D);                          /* pop rbp */
    EMIT(0x5B);                          /* pop rbx */
    EMIT(0x5A);                          /* pop rdx */
    EMIT(0x59);                          /* pop rcx */
    EMIT(0x58);                          /* pop rax */
    EMIT(0x9D);                          /* popfq  */

    /* ret — we'll fix up RIP separately after restoring registers */
    EMIT(0xC3);

    /* ── path string ── */
    size_t path_start = (size_t)(p - buf);
    size_t path_len   = strlen(so_path) + 1;
    if (p - buf + path_len >= bufsz) {
        fprintf(stderr, "[!] shellcode buffer overflow (path) at %zu\n",
                p - buf);
        return 0;
    }
    memcpy(p, so_path, path_len);
    p += path_len;

    /* patch the lea displacement:
     * displacement = path_start - (lea_offset_pos + 4)
     * because RIP after the lea instruction = inject_addr + lea_offset_pos + 4 */
    int32_t disp = (int32_t)(path_start - (lea_offset_pos + 4));
    memcpy(buf + lea_offset_pos, &disp, 4);

    return (size_t)(p - buf);

#undef EMIT
#undef EMIT64
#undef EMIT32
}

/* ── register access ────────────────────────────────────────────────────── */

int syringe_arch_getregs(pid_t pid, SyringeArchRegs *regs) {
    struct user_regs_struct u;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &u) < 0)
        return -1;
    memcpy(regs->_u._buf, &u, sizeof u);
    return 0;
}

int syringe_arch_setregs(pid_t pid, const SyringeArchRegs *regs) {
    struct user_regs_struct u;
    memcpy(&u, regs->_u._buf, sizeof u);
    if (ptrace(PTRACE_SETREGS, pid, NULL, &u) < 0)
        return -1;
    return 0;
}

unsigned long syringe_arch_get_pc(const SyringeArchRegs *regs) {
    struct user_regs_struct u;
    memcpy(&u, regs->_u._buf, sizeof u);
    return (unsigned long)u.rip;
}

void syringe_arch_set_pc(SyringeArchRegs *regs, unsigned long pc) {
    struct user_regs_struct u;
    memcpy(&u, regs->_u._buf, sizeof u);
    u.rip = (unsigned long long)pc;
    memcpy(regs->_u._buf, &u, sizeof u);
}

unsigned long syringe_arch_get_sp(const SyringeArchRegs *regs) {
    struct user_regs_struct u;
    memcpy(&u, regs->_u._buf, sizeof u);
    return (unsigned long)u.rsp;
}

/* ── misc arch constants ────────────────────────────────────────────────── */

unsigned long syringe_arch_entry_skip(void) {
    return 2;   /* skip the two leading NOPs (ptrace restart quirk) */
}

unsigned int syringe_arch_jump_slot_type(void) {
    return R_X86_64_JUMP_SLOT;
}

unsigned int syringe_arch_glob_dat_type(void) {
    return R_X86_64_GLOB_DAT;
}
