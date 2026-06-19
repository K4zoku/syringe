/*
 * arch_riscv64.c — RISC-V 64 backend stub for syringe
 *
 * PLACEHOLDER — not implemented yet.
 *
 * syringe_arch_build_shellcode() returns 0, so syringe_inject() fails
 * cleanly with "Failed to build shellcode" rather than emitting garbage.
 * The remaining entry points return failure / 0; they are unreachable from
 * syringe_inject() on this architecture (which bails at shellcode build).
 *
 * Implement per plan.md §3.3 when RISC-V 64 support is needed:
 *   - registers: PTRACE_GETREGSET / SETREGSET with NT_PRSTATUS,
 *                struct user_regs_struct { pc, ra, sp, gp, tp, t0-t6,
 *                s0-s11, a0-a7, ... } from <sys/ucontext.h> / mcontext_t
 *   - trap:      ebreak  (0x00100073, 4 bytes)
 *   - shellcode: addi sp,-N -> sd ra,gp,tp,s0-s11,a0-a7 -> la a0,path (auipc+addi)
 *                -> li a1,0x102 -> la ra,dlopen_addr -> jalr ra -> ebreak
 *                -> ld ... -> ret
 *   - entry_skip: 0
 *   - relocations: R_RISCV_JUMP_SLOT / R_RISCV_64
 *   - gotcha:     RVC (compressed 2-byte) instructions — trampoline stolen
 *                bytes must be >= 16 to stay on instruction boundaries.
 *
 * See src/arch/arch_x86_64.c for a complete reference implementation.
 */
#define _GNU_SOURCE

#include "arch.h"

#include <stddef.h>
#include <stdio.h>

size_t syringe_arch_build_shellcode(unsigned char *buf, size_t bufsz,
                                     unsigned long dlopen_addr,
                                     const char *so_path,
                                     unsigned long inject_addr) {
    (void)buf; (void)bufsz; (void)dlopen_addr;
    (void)so_path; (void)inject_addr;
    fprintf(stderr, "[syringe] riscv64 backend not implemented yet\n");
    return 0;
}

int syringe_arch_getregs(pid_t pid, SyringeArchRegs *regs) {
    (void)pid; (void)regs;
    return -1;
}

int syringe_arch_setregs(pid_t pid, const SyringeArchRegs *regs) {
    (void)pid; (void)regs;
    return -1;
}

unsigned long syringe_arch_get_pc(const SyringeArchRegs *regs) {
    (void)regs;
    return 0;
}

void syringe_arch_set_pc(SyringeArchRegs *regs, unsigned long pc) {
    (void)regs; (void)pc;
}

unsigned long syringe_arch_get_sp(const SyringeArchRegs *regs) {
    (void)regs;
    return 0;
}

unsigned long syringe_arch_entry_skip(void) {
    return 0;   /* riscv has no ptrace restart quirk */
}

unsigned int syringe_arch_jump_slot_type(void) {
    return 0;   /* R_RISCV_JUMP_SLOT — fill in when implementing */
}

unsigned int syringe_arch_glob_dat_type(void) {
    return 0;   /* R_RISCV_64 — fill in when implementing */
}
