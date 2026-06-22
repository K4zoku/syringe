/*
 * arch_arm.c — ARM32 (armv7) backend stub for syringe
 *
 * Not implemented yet. Returns 0 so syringe_inject() fails cleanly.
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
