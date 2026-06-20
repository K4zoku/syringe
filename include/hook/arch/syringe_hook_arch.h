/*
 * syringe_hook_arch.h — Architecture contract for syringe_hook
 *
 * This header DOCUMENTS the interface that each per-architecture backend
 * header (syringe_hook_<arch>.h) must implement. It is included by
 * syringe_hook_common.h so the common code can call into the arch layer.
 *
 * Each arch header must define ALL of the following (all `static inline`):
 *
 *   ── Constants ──────────────────────────────────────────────────────────
 *
 *   TRAMP_JMP_SZ
 *       Size in bytes of the JMP instruction emitted by build_jmp.
 *       x86-64: 14 (FF 25 00 00 00 00 + 8-byte abs addr)
 *       aarch64: 4 (B rel26, ±128 MB range) OR 16 (LDR x16,[pc,#8] + BR x16
 *                + .quad addr — full range, used when target is far)
 *
 *   TRAMP_STOLEN_MAX
 *       Worst-case number of bytes we may need to copy from the target
 *       prologue before we've copied at least TRAMP_JMP_SZ
 *       instruction-aligned bytes.
 *
 *   TRAMP_BOUNCE_MAX
 *       Total bounce stub size = TRAMP_STOLEN_MAX + TRAMP_JMP_SZ.
 *       Used to mmap the bounce region.
 *
 *   ── Functions ──────────────────────────────────────────────────────────
 *
 *   static inline void syringe_hook_arch_build_jmp(uint8_t *buf, void *dest);
 *       Encode a JMP-to-dest into buf. Must be TRAMP_JMP_SZ bytes.
 *       The arch may choose between short-range and long-range encodings
 *       based on (dest - buf) at emit time — but the size MUST be fixed
 *       so the trampoline builder can compute offsets.
 *
 *   static inline size_t syringe_hook_arch_disasm(const uint8_t *code,
 *                                                   int *reloc_offset);
 *       Length-disassembler. Returns the length of the instruction at
 *       `code`, or 0 if not recognised. When the instruction contains a
 *       PC-relative / rel-displacement (RIP-relative on x86-64, ADR/ADRP/
 *       B/BL/LDR-literal on aarch64), `*reloc_offset` is set to the byte
 *       offset (within the instruction) where the displacement lives.
 *       Caller patches this disp when copying the instruction to a new VA.
 *
 *   static inline size_t syringe_hook_arch_tramp_make(uint8_t *bounce,
 *                                                      size_t bounce_cap,
 *                                                      const void *target,
 *                                                      size_t *copied_bytes);
 *       Build the bounce stub: stolen prologue bytes (with PC-relative
 *       disps fixed up) followed by a JMP back to (target + copied_bytes).
 *       Returns the number of bytes to overwrite on the target (always
 *       >= TRAMP_JMP_SZ), or 0 on failure. Sets *copied_bytes to the same.
 *
 *   static inline int syringe_hook_arch_atomic_patch_jmp(void *target,
 *                                                          const uint8_t *jmp,
 *                                                          size_t jmp_sz);
 *       Atomically patch `target` with `jmp` bytes. Should split into
 *       word-sized atomic stores to minimise the race window where
 *       another thread can fetch a half-patched prologue.
 *
 *   ── Optional: security features ────────────────────────────────────────
 *
 *   For architectures with pointer authentication (ARM64 PAC), branch
 *   target identification (ARM64 BTI), or memory tagging (MTE), the arch
 *   header should also handle:
 *
 *     - Stripping PAC bits from `target` before patching
 *     - Detecting `bti c` / `bti j` prologue and including it in the
 *       bounce stub so the trampoline remains BTI-compliant
 *     - Avoiding MTE-tagged addresses for the bounce mmap
 *
 *   See syringe_hook_x86_64.h and syringe_hook_aarch64.h for reference
 *   implementations.
 */

#ifndef SYRINGE_HOOK_ARCH_H
#define SYRINGE_HOOK_ARCH_H

/* This header is documentation-only — no code, no macros.
 * Each per-arch header defines the actual constants and functions. */

#endif /* SYRINGE_HOOK_ARCH_H */
