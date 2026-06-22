/*
 * arch.h — per-architecture backend interface for syringe
 *
 * The injector core (src/syringe.c) is fully architecture-agnostic: every
 * shellcode emission, register access, and PC fixup goes through the
 * `syringe_arch_*` functions declared here. Each supported architecture
 * supplies a src/arch/arch_<name>.c file implementing all of them.
 *
 * meson.build selects exactly one arch backend per build, based on
 * host_machine.cpu_family(). Architectures that are not yet implemented
 * ship a stub backend whose syringe_arch_build_shellcode() returns 0, so
 * syringe_inject() fails cleanly with "Failed to build shellcode" instead
 * of crashing or emitting garbage.
 *
 * Register storage is intentionally opaque: callers see only a fixed-size,
 * properly-aligned byte bag (SyringeArchRegs) and reach into it through
 * syringe_arch_get_pc / set_pc / get_sp. The concrete native register
 * layout (struct user_regs_struct on x86-64, struct user_pt_regs on
 * aarch64, …) is known ONLY to the arch .c file, which shuttles bytes in
 * and out via memcpy — no aliasing, no layout leaks into the core.
 */
#ifndef SYRINGE_ARCH_H
#define SYRINGE_ARCH_H

#include <stddef.h>      /* size_t, max_align_t */
#include <sys/types.h>   /* pid_t */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Worst-case register-set size across supported backends. NT_PRSTATUS
 * integer regsets are small (x86-64 ~= 216 B, aarch64 = 272 B, arm ~= 72 B,
 * riscv64 ~= 256 B). 512 leaves comfortable headroom; bump it if a backend
 * ever needs to also stash FP/state.
 */
#define SYRINGE_ARCH_REGS_MAX 512

/* Opaque register storage. Arch backends memcpy the _buf member to/from
 * their native ptrace reg struct; the core never inspects the contents. */
typedef struct SyringeArchRegs {
    union {
        unsigned char _buf[SYRINGE_ARCH_REGS_MAX];
        max_align_t   _align;   /* guarantee suitable alignment for any regs */
    } _u;
} SyringeArchRegs;

/*
 * Build a dlopen-calling shellcode stub for this architecture.
 *
 * @param buf          destination buffer
 * @param bufsz        capacity of buf
 * @param dlopen_addr  address of dlopen() inside the target process
 * @param so_path      NUL-terminated path embedded after the code
 * @param inject_addr  target injection address (for PC-relative fixups)
 * @return             shellcode size in bytes, or 0 on overflow / unsupported
 */
size_t syringe_arch_build_shellcode(unsigned char *buf, size_t bufsz,
                                     unsigned long dlopen_addr,
                                     const char *so_path,
                                     unsigned long inject_addr);

/*
 * Read / write the target's full integer register set.
 *   x86-64:        PTRACE_GETREGS / PTRACE_SETREGS
 *   arm / riscv:   PTRACE_GETREGSET / PTRACE_SETREGSET (NT_PRSTATUS)
 * @return 0 on success, -1 on failure.
 */
int syringe_arch_getregs(pid_t pid, SyringeArchRegs *regs);
int syringe_arch_setregs(pid_t pid, const SyringeArchRegs *regs);

/* Get / set the program counter. */
unsigned long syringe_arch_get_pc(const SyringeArchRegs *regs);
void          syringe_arch_set_pc(SyringeArchRegs *regs, unsigned long pc);

/* Get the stack pointer (diagnostics only). */
unsigned long syringe_arch_get_sp(const SyringeArchRegs *regs);

/*
 * Bytes to advance past the injection-site entry sequence before running
 * the shellcode. x86-64 returns 2 (skip the two leading NOPs to dodge the
 * ptrace restart quirk); ARM/RISC-V return 0.
 */
unsigned long syringe_arch_entry_skip(void);

/*
 * ELF relocation type codes for GOT walks. NOTE: these are informational —
 * the header-only hooker (syringe_hook.h) runs in the TARGET process and
 * cannot call into libsyringe.so, so it resolves these via #ifdef instead.
 * They are kept here for completeness and future in-process GOT tooling.
 */
unsigned int syringe_arch_jump_slot_type(void);
unsigned int syringe_arch_glob_dat_type(void);

#ifdef __cplusplus
}
#endif

#endif /* SYRINGE_ARCH_H */
