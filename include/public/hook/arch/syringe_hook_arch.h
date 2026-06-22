/*
 * syringe_hook_arch.h — Architecture contract for syringe_hook
 *
 * Each per-architecture backend header (syringe_hook_<arch>.h) must define:
 *   - TRAMP_JMP_SZ, TRAMP_STOLEN_MAX, TRAMP_BOUNCE_MAX
 *   - syringe_hook_arch_build_jmp()
 *   - syringe_hook_arch_read_jmp_target()
 *   - syringe_hook_arch_disasm()
 *   - syringe_hook_arch_tramp_make()
 *   - syringe_hook_arch_atomic_patch_jmp()
 *
 * See syringe_hook_x86_64.h and syringe_hook_aarch64.h for reference.
 */
#ifndef SYRINGE_HOOK_ARCH_H
#define SYRINGE_HOOK_ARCH_H

/* This header is documentation-only — no code, no macros.
 * Each per-arch header defines the actual constants and functions. */

#endif /* SYRINGE_HOOK_ARCH_H */
