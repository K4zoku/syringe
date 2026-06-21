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

/* ── Shellcode (compiled from shellcode_x86_64.S) ──────────────────────
 *
 * The shellcode binary is generated at build time by meson:
 *   gcc -c shellcode_x86_64.S → objcopy -O binary → xxd -i → shellcode_x86_64.h
 *
 * Layout (see shellcode_x86_64.S for full documentation):
 *   [0x00] nop; nop; pushfq; push rax-r15     (save state)
 *   [0x1A] lea rdi, [rip+0x37]                (path string, PC-relative)
 *   [0x27] movabs $0x102, %rsi                (RTLD_NOW|RTLD_GLOBAL)
 *   [0x2B] movabs $0, %rax                    (dlopen addr — PATCHED)
 *   [0x3B] call *%rax                         (call dlopen)
 *   [0x3D] int3                               (SIGTRAP)
 *   [0x3E] pop r15-rax; popfq; ret            (restore + return)
 *   [0x58] path: 256 bytes                    (so_path — PATCHED)
 *
 * Two runtime patches:
 *   1. dlopen_addr at offset 0x2B+2 (the imm64 in movabs)
 *   2. so_path at offset 0x58 (256 bytes, NUL-terminated)
 */

/* Offsets into the shellcode binary (must match shellcode_x86_64.S layout).
 * These are verified at build time by the test suite. */
#define SC_DLOPEN_ADDR_OFF   0x2D   /* offset of dlopen addr imm64 value */
#define SC_PATH_OFF          0x58   /* offset of path string region */
#define SC_PATH_MAX          256    /* max path length (space reserved in .S) */

/* Generated header (in build dir) — contains syringe_shellcode_x86_64[]
 * and syringe_shellcode_x86_64_len */
#include "shellcode_x86_64.h"

/* ── shellcode builder ──────────────────────────────────────────────────── */

size_t syringe_arch_build_shellcode(unsigned char *buf, size_t bufsz,
                                     unsigned long dlopen_addr,
                                     const char *so_path,
                                     unsigned long inject_addr) {
    (void)inject_addr; /* RIP-relative displacement is independent of base */

    size_t sc_len = syringe_shellcode_x86_64_len;
    if (sc_len > bufsz) {
        fprintf(stderr, "[!] shellcode buffer too small: need %zu, have %zu\n",
                sc_len, bufsz);
        return 0;
    }

    /* Copy template into output buffer */
    memcpy(buf, syringe_shellcode_x86_64, sc_len);

    /* Patch 1: dlopen address (movabs $0, %rax → movabs $addr, %rax) */
    memcpy(buf + SC_DLOPEN_ADDR_OFF, &dlopen_addr, sizeof(dlopen_addr));

    /* Patch 2: .so path string */
    size_t path_len = strlen(so_path) + 1;  /* include NUL */
    if (path_len > SC_PATH_MAX) {
        fprintf(stderr, "[!] shellcode path too long: %zu > %d\n",
                path_len, SC_PATH_MAX);
        return 0;
    }
    memcpy(buf + SC_PATH_OFF, so_path, path_len);

    return sc_len;
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
