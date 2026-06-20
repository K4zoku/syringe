/*
 * syringe_hook_aarch64.h — ARM64 (aarch64) backend for syringe_hook
 *
 * Implements the arch contract declared in syringe_hook_arch.h:
 *   - syringe_hook_arch_build_jmp         : B rel26 (4 bytes, ±128 MB)
 *                                             OR LDR x16,=addr + BR x16 (16 bytes)
 *   - syringe_hook_arch_disasm            : fixed 4-byte instruction, detect
 *                                           PC-relative variants (B/BL/ADR/
 *                                           ADRP/LDR-lit)
 *   - syringe_hook_arch_tramp_make        : steal 4 instructions, fix
 *                                           PC-relative disps
 *   - syringe_hook_arch_atomic_patch_jmp  : 4-byte atomic store (B rel26) or
 *                                           2 × 8-byte (LDR+BR variant)
 *
 * Constants:
 *   TRAMP_JMP_SZ       = 16   (always use the long-range LDR+BR variant
 *                              for simplicity. 4-byte B rel26 is only safe
 *                              if hook is within ±128 MB of target, which
 *                              we can't guarantee — libhook.so may map far
 *                              from libEGL.so. Using the 16-byte variant
 *                              universally avoids a runtime range check.)
 *   TRAMP_STOLEN_MAX   = 16   (4 instructions × 4 bytes — enough to cover
 *                              typical aarch64 prologue: stp + mov + mov
 *                              + stp, plus the bti c prologue if present)
 *   TRAMP_BOUNCE_MAX   = 32
 *
 * ARM64 security features handled:
 *   - PAC (Pointer Authentication): strip PAC bits from `target` via
 *     `xpac` before patching. Without this, the high bits of `target`
 *     would be authentication signature, not address — patching them
 *     into the prologue would corrupt the function.
 *   - BTI (Branch Target Identification): if the prologue starts with
 *     `bti c` or `bti j`, include it in the bounce stub so the
 *     trampoline remains a valid branch target.
 *   - MTE (Memory Tagging): the bounce stub is mmap'd with
 *     MAP_ANONYMOUS which gives untagged memory; this is fine because
 *     the bounce only executes code, never dereferences tagged pointers.
 *
 * aarch64 instruction encoding reference:
 *   - B   imm26:   0x14000000 | (imm26 & 0x03FFFFFF)
 *                  imm26 = (target - pc) >> 2, signed, ±128 MB range
 *   - BL  imm26:   0x94000000 | (imm26 & 0x03FFFFFF)
 *   - ADR Xd, imm: 0x10000000 | (immlo << 29) | (immhi << 5) | Xd
 *                  21-bit signed PC-relative byte offset, ±1 MB range
 *   - ADRP Xd, imm:0x90000000 | (immlo << 29) | (immhi << 5) | Xd
 *                  21-bit signed PC-relative PAGE offset (4 KB pages),
 *                  ±4 GB range
 *   - LDR (literal): 0x18000000 | (imm19 << 5) | Rt
 *                    19-bit signed PC-relative word offset, ±1 MB range
 *   - BR Xn:        0xD61F0000 | (Xn << 5)
 *   - BTI c:        0xD503245F
 *   - BTI j:        0xD50324DF
 *   - BRK #0:       0xD4200000
 *
 * This file is included by syringe_hook.h when compiling on aarch64.
 * It is NOT meant to be included directly by users.
 */

#ifndef SYRINGE_HOOK_AARCH64_H
#define SYRINGE_HOOK_AARCH64_H

/* Arch constants — defined here so the types header picks them up via
 * its #ifndef fallback. Must come BEFORE syringe_hook_types.h. */
#define TRAMP_JMP_SZ     16    /* LDR x16,[pc,#8] + BR x16 + .quad addr */
#define TRAMP_STOLEN_MAX 16    /* 4 instructions × 4 bytes */
#define TRAMP_BOUNCE_MAX (TRAMP_STOLEN_MAX + TRAMP_JMP_SZ)
#define BOUNCE_SZ        TRAMP_BOUNCE_MAX

#include "../syringe_hook_types.h"

/* ── ARM64 security helpers ──────────────────────────────────────────────────
 *
 * PAC (Pointer Authentication Codes):
 *   On ARM64 hardware with PAC enabled (Apple Silicon, Graviton 3+,
 *   Snapdragon 8 Gen 2+), the upper bits of a function pointer may
 *   contain a cryptographic signature. Using such a pointer directly as
 *   a patch destination would write the signature into the prologue,
 *   corrupting the function.
 *
 *   `xpac x16` strips the PAC bits, returning the raw address. We use
 *   a single inline asm to do this. On hardware without PAC, `xpac`
 *   is a NOP (the upper bits are already zero).
 *
 *   We use x16 (IP0) as the scratch register because it's caller-saved
 *   and not used for argument passing.
 */
static inline void *syringe_hook_aarch64_strip_pac(void *ptr) {
#if defined(__aarch64__)
    void *result;
    __asm__ volatile (
        "mov x16, %[p]\n"
        "xpac x16\n"           /* strip PAC bits (NOP on non-PAC hardware) */
        "mov %[r], x16\n"
        : [r] "=r"(result)
        : [p] "r"(ptr)
        : "x16"
    );
    return result;
#else
    return ptr;
#endif
}

/* Check if a 4-byte instruction is `bti c` (0xD503245F) or `bti j` (0xD50324DF).
 * Returns 1 if BTI prologue, 0 otherwise. */
static inline int syringe_hook_aarch64_is_bti(uint32_t insn) {
    return insn == 0xD503245F  /* bti c */
        || insn == 0xD50324DF; /* bti j */
}

/* ── JMP encoder: LDR x16, [pc, #8] + BR x16 + .quad addr (16 bytes) ────────
 *
 * Layout (16 bytes total):
 *   +0:  LDR x16, [pc, #8]   ; 0x58000050
 *        Loads the 8-byte address at PC+8 into x16. PC = current instr addr.
 *        LDR (literal) with imm19=2 (offset 8 bytes from this instr).
 *   +4:  BR x16               ; 0xD61F0200
 *        Unconditional branch to address in x16.
 *   +8:  <8-byte absolute address of `dest`>
 *
 * This is a position-independent 16-byte trampoline that can jump to any
 * 64-bit address. Used instead of B rel26 (which is limited to ±128 MB)
 * because we can't guarantee hook and target are within range.
 */
static inline void syringe_hook_arch_build_jmp(uint8_t *buf, void *dest) {
    /* LDR x16, [pc, #8] — load from PC+8 = address of the .quad below */
    const uint32_t ldr_x16 = 0x58000050;
    /* BR x16 */
    const uint32_t br_x16  = 0xD61F0200;

    memcpy(buf + 0, &ldr_x16, 4);
    memcpy(buf + 4, &br_x16,  4);
    memcpy(buf + 8, &dest,    8);
}

/* ── aarch64 length-disassembler ────────────────────────────────────────────
 *
 * aarch64 instructions are always 4 bytes (no variable-length like x86).
 * So the length is trivially 4 — the interesting part is detecting
 * PC-relative instructions and reporting the displacement field offset
 * so tramp_make can patch it.
 *
 * PC-relative instruction families we recognise:
 *   - B   (unconditional branch):  bits [25:0]  = imm26 (signed, ×4)
 *                                  reloc offset = 0 (disp starts at bit 0)
 *   - BL  (branch with link):      same as B but opcode bit 31 = 1
 *   - ADR (PC-relative address):   bits [30:29] = immlo, [23:5] = immhi
 *                                  combined: 21-bit signed byte offset
 *                                  reloc offset = 0 (we patch the whole
 *                                  instruction word)
 *   - ADRP (PC-relative page addr): same layout as ADR, opcode bit 31 = 1
 *                                  offset is in pages (×4096)
 *   - LDR (literal):               bits [23:5] = imm19 (signed, ×4)
 *                                  reloc offset = 0 (we patch the whole
 *                                  instruction word)
 *
 * For ADR/ADRP/LDR-lit we report reloc_offset = 0 and tramp_make will
 * re-encode the instruction with the new disp.
 *
 * Returns 4 for recognised opcodes, 0 for unknown (caller falls back
 * to raw 4-byte copy with no fixup — may be incorrect for PC-relative
 * instructions, but better than refusing to hook).
 */
static inline size_t syringe_hook_arch_disasm(const uint8_t *code,
                                                int *reloc_offset) {
    uint32_t insn;
    memcpy(&insn, code, 4);
    if (reloc_offset) *reloc_offset = 0;

    /* B (unconditional branch): 0001 01xx xxxx xxxx xxxx xxxx xxxx xxxx
     * opcode = bits [31:26] = 0b000101 → mask 0xFC000000, value 0x14000000 */
    if ((insn & 0xFC000000) == 0x14000000) {
        /* B imm26 — reloc_offset = 0 means "disp starts at bit 0" */
        return 4;
    }

    /* BL (branch with link): 1001 01xx xxxx xxxx xxxx xxxx xxxx xxxx
     * opcode = bits [31:26] = 0b100101 → mask 0xFC000000, value 0x94000000 */
    if ((insn & 0xFC000000) == 0x94000000) {
        return 4;
    }

    /* ADR: 0 immlo 10000 immhi Rd  →  mask 0x9F000000, value 0x10000000 */
    if ((insn & 0x9F000000) == 0x10000000) {
        return 4;
    }

    /* ADRP: 1 immlo 10000 immhi Rd →  mask 0x9F000000, value 0x90000000 */
    if ((insn & 0x9F000000) == 0x90000000) {
        return 4;
    }

    /* LDR (literal, 64-bit): 01 011 000 imm19 Rt → mask 0xBF000000, value 0x18000000
     * Also covers 32-bit LDR literal (0x18000000 | opc=00 → 0x18000000)
     * and LDRSW (0x98000000). */
    if ((insn & 0xBF000000) == 0x18000000  /* LDR (literal) Xd */
        || (insn & 0xBF000000) == 0x18000000  /* LDR (literal) Wd */
        || (insn & 0xFF000000) == 0x98000000) /* LDRSW (literal) */ {
        return 4;
    }

    /* CBZ / CBNZ: 0b0110100/0b0110101 + imm19 + Rt
     * mask 0x7F000000, value 0x34000000 (CBZ) or 0x35000000 (CBNZ) */
    if ((insn & 0x7F000000) == 0x34000000
        || (insn & 0x7F000000) == 0x35000000) {
        return 4;
    }

    /* TBZ / TBNZ: 0b0110110/0b0110111 + b5 + b40 + imm14 + Rt
     * Both have bit 31 = 0, opcodes 0x36000000 (TBZ) / 0x37000000 (TBNZ).
     * Mask 0x7F000000 keeps bits 30:24 (the opcode bits) and excludes
     * bit 31 (always 0 for these opcodes). */
    if ((insn & 0x7F000000) == 0x36000000
        || (insn & 0x7F000000) == 0x37000000) {
        return 4;
    }

    /* Not a PC-relative instruction — still 4 bytes, but no fixup needed. */
    return 4;
}

/* ── trampoline builder: copy prologue + fix up PC-relative disps ────────────
 *
 * Fills `bounce_payload` with:
 *   [ optional bti c ] [ stolen prologue, with PC-relative disps patched ]
 *   [ JMP abs back to target+stolen ]
 *
 * On aarch64, all instructions are 4 bytes, so we steal exactly
 * TRAMP_JMP_SZ/4 = 4 instructions (16 bytes). If the prologue has fewer
 * than 4 instructions before `ret`, we copy `ret` and the bytes after
 * it (which are usually padding or next function — harmless to copy).
 *
 * For each stolen instruction, if it's PC-relative (B/BL/ADR/ADRP/LDR-lit/
 * CBZ/CBNZ/TBZ/TBNZ), we re-encode it with the displacement adjusted by
 * (target - bounce) so it references the same absolute address from the
 * new location.
 *
 * PAC handling: `target` is stripped via xpac before use.
 * BTI handling: if the original prologue starts with `bti c` or `bti j`,
 * we keep it as the first instruction of the bounce stub.
 */
static inline size_t syringe_hook_arch_tramp_make(uint8_t *bounce_payload,
                                                    size_t bounce_cap,
                                                    const void *target_in,
                                                    size_t *copied_bytes) {
    /* Strip PAC bits from target (NOP on non-PAC hardware). */
    void *target = syringe_hook_aarch64_strip_pac((void*)target_in);
    size_t stolen = 0;

    /* Shadow-read prologue via /proc/self/mem. We need TRAMP_STOLEN_MAX bytes. */
    uint8_t prologue_buf[TRAMP_STOLEN_MAX];
    int have_prologue = 0;
    if (syringe_memfd < 0) syringe_hook_memfd_open();
    if (syringe_memfd >= 0) {
        ssize_t rd = pread(syringe_memfd, prologue_buf, TRAMP_STOLEN_MAX,
                           (off_t)(uintptr_t)target);
        if (rd == (ssize_t)TRAMP_STOLEN_MAX) {
            have_prologue = 1;
        } else {
            SYRINGE_HOOK_LOG("tramp_make: pread prologue failed (rd=%zd)", rd);
        }
    }
    if (!have_prologue) {
        memcpy(prologue_buf, target, TRAMP_STOLEN_MAX);
    }

    /* Steal exactly TRAMP_STOLEN_MAX bytes (4 instructions on aarch64).
     * Each instruction is 4 bytes — no length-disassembler loop needed. */
    while (stolen < TRAMP_STOLEN_MAX) {
        if (stolen + 4 > TRAMP_STOLEN_MAX) {
            SYRINGE_HOOK_LOG("tramp_make: stole partial instruction");
            return 0;
        }
        if (stolen + 4 + TRAMP_JMP_SZ > bounce_cap) {
            SYRINGE_HOOK_LOG("tramp_make: bounce buffer too small");
            return 0;
        }

        uint32_t insn;
        memcpy(&insn, prologue_buf + stolen, 4);

        /* Patch PC-relative instructions.
         *
         * For B/BL imm26: imm26 = (target - pc) >> 2
         *   new_imm26 = old_imm26 + ((target_addr - bounce_addr) >> 2)
         *   where target_addr = (uint8_t*)target + stolen
         *         bounce_addr = bounce_payload + stolen
         *
         * For ADR/ADRP/LDR-lit/CBZ/CBNZ/TBZ/TBNZ: similar but with
         * different bit fields and scale factors.
         *
         * Implementation: re-encode the instruction with the new disp.
         * We use the reloc_offset = 0 convention from disasm to indicate
         * "the whole instruction word is PC-relative" — but for aarch64
         * we handle each family explicitly here for clarity.
         */
        intptr_t t_addr = (intptr_t)((const uint8_t*)target + stolen);
        intptr_t b_addr = (intptr_t)(bounce_payload + stolen);
        int64_t delta = t_addr - b_addr;  /* how much to ADD to the disp */

        /* B / BL imm26 (signed, scale 4) */
        if ((insn & 0xFC000000) == 0x14000000
            || (insn & 0xFC000000) == 0x94000000) {
            int32_t imm26 = (int32_t)(insn & 0x03FFFFFF);
            /* sign-extend imm26 from 26 bits */
            if (imm26 & (1 << 25)) imm26 |= 0xFC000000;
            int64_t new_imm = (int64_t)imm26 + (delta >> 2);
            /* Check it still fits in 26 bits signed */
            if (new_imm < -(1LL << 25) || new_imm >= (1LL << 25)) {
                SYRINGE_HOOK_LOG("tramp_make: B/BL disp out of range after fixup");
                return 0;
            }
            insn = (insn & 0xFC000000) | ((uint32_t)new_imm & 0x03FFFFFF);
        }
        /* ADR (21-bit byte offset, immlo:immhi) */
        else if ((insn & 0x9F000000) == 0x10000000) {
            int32_t immlo = (insn >> 29) & 0x3;
            int32_t immhi = (insn >> 5) & 0x7FFFF;
            int32_t imm = (immhi << 2) | immlo;
            /* sign-extend from 21 bits */
            if (imm & (1 << 20)) imm |= 0xFFE00000;
            int64_t new_imm = (int64_t)imm + delta;
            if (new_imm < -(1LL << 20) || new_imm >= (1LL << 20)) {
                SYRINGE_HOOK_LOG("tramp_make: ADR disp out of range");
                return 0;
            }
            int32_t nlo = new_imm & 0x3;
            int32_t nhi = (new_imm >> 2) & 0x7FFFF;
            insn = (insn & 0x9F00001F) | ((uint32_t)nlo << 29) | ((uint32_t)nhi << 5);
        }
        /* ADRP (21-bit page offset, scale 4096) */
        else if ((insn & 0x9F000000) == 0x90000000) {
            int32_t immlo = (insn >> 29) & 0x3;
            int32_t immhi = (insn >> 5) & 0x7FFFF;
            int32_t imm = (immhi << 2) | immlo;
            if (imm & (1 << 20)) imm |= 0xFFE00000;
            /* For ADRP, PC and target are page-aligned before the disp
             * is applied. The disp is in units of 4096 bytes. */
            int64_t pc_page = (t_addr >> 12) & ~0ULL;
            int64_t b_page  = (b_addr >> 12) & ~0ULL;
            int64_t new_imm = (int64_t)imm + (pc_page - b_page);
            if (new_imm < -(1LL << 20) || new_imm >= (1LL << 20)) {
                SYRINGE_HOOK_LOG("tramp_make: ADRP disp out of range");
                return 0;
            }
            int32_t nlo = new_imm & 0x3;
            int32_t nhi = (new_imm >> 2) & 0x7FFFF;
            insn = (insn & 0x9F00001F) | ((uint32_t)nlo << 29) | ((uint32_t)nhi << 5);
        }
        /* LDR (literal) imm19 (signed, scale 4) */
        else if ((insn & 0xBF000000) == 0x18000000
                 || (insn & 0xFF000000) == 0x98000000) {
            int32_t imm19 = (insn >> 5) & 0x7FFFF;
            if (imm19 & (1 << 18)) imm19 |= 0xFFF80000;
            int64_t new_imm = (int64_t)imm19 + (delta >> 2);
            if (new_imm < -(1LL << 18) || new_imm >= (1LL << 18)) {
                SYRINGE_HOOK_LOG("tramp_make: LDR-lit disp out of range");
                return 0;
            }
            insn = (insn & 0xFF00001F) | (((uint32_t)new_imm & 0x7FFFF) << 5);
        }
        /* CBZ / CBNZ imm19 (signed, scale 4) */
        else if ((insn & 0x7F000000) == 0x34000000
                 || (insn & 0x7F000000) == 0x35000000) {
            int32_t imm19 = (insn >> 5) & 0x7FFFF;
            if (imm19 & (1 << 18)) imm19 |= 0xFFF80000;
            int64_t new_imm = (int64_t)imm19 + (delta >> 2);
            if (new_imm < -(1LL << 18) || new_imm >= (1LL << 18)) {
                SYRINGE_HOOK_LOG("tramp_make: CBZ/CBNZ disp out of range");
                return 0;
            }
            insn = (insn & 0xFF00001F) | (((uint32_t)new_imm & 0x7FFFF) << 5);
        }
        /* TBZ / TBNZ imm14 (signed, scale 4) */
        else if ((insn & 0x7F000000) == 0x36000000
                 || (insn & 0x7F000000) == 0x37000000) {
            int32_t imm14 = (insn >> 5) & 0x3FFF;
            if (imm14 & (1 << 13)) imm14 |= 0xFFFFC000;
            int64_t new_imm = (int64_t)imm14 + (delta >> 2);
            if (new_imm < -(1LL << 13) || new_imm >= (1LL << 13)) {
                SYRINGE_HOOK_LOG("tramp_make: TBZ/TBNZ disp out of range");
                return 0;
            }
            insn = (insn & 0xFFF8001F) | (((uint32_t)new_imm & 0x3FFF) << 5);
        }
        /* else: not PC-relative, copy verbatim */

        memcpy(bounce_payload + stolen, &insn, 4);
        stolen += 4;
    }

    /* Append the JMP abs back to target+stolen. */
    syringe_hook_arch_build_jmp(bounce_payload + stolen,
                                 (void*)((uintptr_t)target + stolen));

    if (copied_bytes) *copied_bytes = stolen;
    return stolen;
}

/* ── Atomic patch: 16-byte JMP via 2 × 8-byte atomic stores ──────────────────
 *
 * The 16-byte JMP encoding is:
 *   +0:  LDR x16, [pc, #8]   (4 bytes)
 *   +4:  BR x16               (4 bytes)
 *   +8:  <8-byte address>     (8 bytes)
 *
 * To patch atomically, we split into two 8-byte stores:
 *   - Store 1: bytes 0-7 (LDR + BR) — 1 atomic 8-byte write
 *   - Store 2: bytes 8-15 (address) — 1 atomic 8-byte write
 *
 * A thread executing the target during the patch window will fetch
 * either the old prologue (4 instructions) or the new JMP. If it
 * fetches a mix, the worst case is executing the LDR (which loads
 * garbage from PC+8 if the address isn't there yet) then BR — but
 * since BR x16 just branches to whatever x16 contains, this could
 * jump anywhere. To minimise this race, we write the address FIRST
 * (store 2 → store 1), so by the time LDR executes, the address
 * is already in place.
 *
 * However, we can't fully order the stores without a memory barrier
 * between them — which we add via SEQ_CST.
 *
 * The caller's `jmp[16]` is copied into a 16-byte stack buffer first
 * so the 8-byte reads are aligned. */
static inline int syringe_hook_arch_atomic_patch_jmp(void *target,
                                                       const uint8_t jmp[TRAMP_JMP_SZ]) {
    uint8_t buf[16];
    memcpy(buf, jmp, 16);
    uint64_t lo, hi;
    memcpy(&lo, buf,     8);   /* LDR + BR */
    memcpy(&hi, buf + 8, 8);   /* address */

    /* Write address FIRST (SEQ_CST ensures other cores see ordering). */
    __atomic_store_n((uint64_t*)((uint8_t*)target + 8), hi, __ATOMIC_SEQ_CST);
    /* Then write the LDR+BR pair. */
    __atomic_store_n((uint64_t*)target,                 lo, __ATOMIC_SEQ_CST);
    return 0;
}

#endif /* SYRINGE_HOOK_AARCH64_H */
