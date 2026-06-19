/*
 * arch_arm.c — ARM32 (armv7) backend stub for syringe
 *
 * PLACEHOLDER — not implemented yet.
 *
 * syringe_arch_build_shellcode() returns 0, so syringe_inject() fails
 * cleanly with "Failed to build shellcode" rather than emitting garbage.
 * The remaining entry points return failure / 0; they are unreachable from
 * syringe_inject() on this architecture (which bails at shellcode build).
 *
 * Implement per plan.md §3.2 when ARM32 support is needed:
 *   - registers: PTRACE_GETREGSET / SETREGSET with NT_PRSTATUS,
 *                struct pt_regs (r0-r15, cpsr) from <sys/user.h>
 *   - trap:      bkpt #0  (ARM 0xE1200070, Thumb 0xBE00)
 *   - shellcode: push {r0-r12,lr} -> add r0,pc,#path -> mov r1,#0x102 ->
 *                movw/movt r12,dlopen_addr -> blx r12 -> bkpt -> pop -> bx lr
 *   - entry_skip: 0
 *   - relocations: R_ARM_JUMP_SLOT / R_ARM_GLOB_DAT
 *   - gotcha:     Thumb interworking — strip bit 0 of function pointers.
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
    fprintf(stderr, "[syringe] arm (armv7) backend not implemented yet\n");
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
    return 0;   /* arm has no ptrace restart quirk */
}

unsigned int syringe_arch_jump_slot_type(void) {
    return 0;   /* R_ARM_JUMP_SLOT — fill in when implementing */
}

unsigned int syringe_arch_glob_dat_type(void) {
    return 0;   /* R_ARM_GLOB_DAT — fill in when implementing */
}
