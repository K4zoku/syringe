/*
 * syringe_hook_x86_64.h — x86-64 backend for syringe_hook
 *
 * Implements the arch contract declared in syringe_hook_arch.h:
 *   - syringe_hook_arch_build_jmp         : FF 25 abs JMP (14 bytes)
 *   - syringe_hook_arch_disasm            : length-disassembler, ~50 opcodes
 *   - syringe_hook_arch_tramp_make        : steal prologue, fix RIP-relative disps
 *   - syringe_hook_arch_atomic_patch_jmp  : 2 × 8-byte atomic stores
 *
 * Constants:
 *   TRAMP_JMP_SZ       = 14  (FF 25 00 00 00 00 + 8-byte abs addr)
 *   TRAMP_STOLEN_MAX   = 32  (worst-case prologue: endbr64 + push + mov + sub + NOPs)
 *   TRAMP_BOUNCE_MAX   = 46  (stolen + jmp)
 *
 * Coverage of the disassembler (prologue-biased):
 *   - All legacy prefixes (F0 F2 F3 2E 36 3E 26 64 65 66 67)
 *   - REX prefixes (40-4F) — required for x86-64
 *   - endbr64 / endbr32 (F3 0F 1E FA / F3 0F 1E FB) — CET prologue
 *   - Multi-byte NOPs (0F 1F /0..7, 0F 1E /7, 66 0F 1F ...)
 *   - Common prologue opcodes: push r64, mov r/m,r, sub r/m,imm8/32,
 *     lea r,m, call rel32, jmp rel32, mov r,imm
 *   - SSE: movaps, movups, xorps
 *   - Group 1: ADD/AND/OR/SUB/CMP r/m,imm8/32 (0x80/0x81/0x83 /n)
 *
 * Unknown opcodes return 0; tramp_make then fails gracefully.
 *
 * This file is included by syringe_hook_common.h when compiling on x86-64.
 * It is NOT meant to be included directly by users.
 */

#ifndef SYRINGE_HOOK_X86_64_H
#define SYRINGE_HOOK_X86_64_H

/* Arch constants — defined here so the types header picks them up via
 * its #ifndef fallback. Must come BEFORE syringe_hook_types.h. */
#define TRAMP_JMP_SZ     14
#define TRAMP_STOLEN     16           /* deprecated alias, kept for compat */
#define TRAMP_STOLEN_MAX 32
#define TRAMP_BOUNCE_MAX (TRAMP_STOLEN_MAX + TRAMP_JMP_SZ)
#define BOUNCE_SZ        TRAMP_BOUNCE_MAX   /* deprecated alias */

#include "../syringe_hook_types.h"

/* ── JMP encoder: FF 25 00 00 00 00 + 8-byte absolute target ────────────────── */
static inline void syringe_hook_arch_build_jmp(uint8_t *buf, void *dest) {
    buf[0]=0xFF; buf[1]=0x25;
    buf[2]=buf[3]=buf[4]=buf[5]=0x00;
    memcpy(buf+6, &dest, 8);
}

/* Backward-compat alias */
static inline void syringe_hook_build_jmp(uint8_t *buf, void *dest) {
    syringe_hook_arch_build_jmp(buf, dest);
}

/* ── x86-64 length-disassembler ─────────────────────────────────────────────── */

static inline size_t syringe_hook_arch_disasm(const uint8_t *code,
                                                int *reloc_offset) {
    enum {
        F_MODRM      = 1 << 0,
        F_PLUS_R     = 1 << 1,   /* opcode low 3 bits encode register */
        F_REG_OPCODE = 1 << 2,   /* ModRM /n must match */
        F_IMM8       = 1 << 3,
        F_IMM16      = 1 << 4,
        F_IMM32      = 1 << 5,
        F_RELOC_REL  = 1 << 6,   /* rel32 disp — patch when relocated */
        F_RELOC_RIP  = 1 << 7    /* RIP-relative ModRM disp32 — patch */
    };

    struct opinfo {
        uint8_t  opcode;
        uint8_t  reg_opcode;   /* ModRM /n, only used if F_REG_OPCODE */
        uint8_t  flags;
    };

    /* Legacy prefixes (in order of the reference manual). */
    static const uint8_t legacy_prefixes[] = {
        0xF0, 0xF2, 0xF3,                  /* lock, repne, rep */
        0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, /* segment overrides */
        0x66, 0x67                          /* opsize, addrsize */
    };

    /* Opcode table. Keep grouped by leading byte for readability. */
    static const struct opinfo opcodes[] = {
        /* Control flow — rel32 needs fixup when relocated */
        {0xE8, 0, F_IMM32 | F_RELOC_REL},                   /* CALL rel32 */
        {0xE9, 0, F_IMM32 | F_RELOC_REL},                   /* JMP  rel32 */
        {0xEB, 0, F_IMM8},                                  /* JMP  rel8  */
        {0xE3, 0, F_IMM8},                                  /* JRCXZ rel8 */
        {0x70, 0, F_IMM8 | F_PLUS_R},                       /* Jcc rel8 (70..7F) */
        {0xC3, 0, 0},                                       /* RET */
        {0xC2, 0, F_IMM16},                                 /* RET imm16 */

        /* LEA / MOV r,m */
        {0x8D, 0, F_MODRM},                                 /* LEA r,m */
        {0x8B, 0, F_MODRM},                                 /* MOV r,r/m */
        {0x89, 0, F_MODRM},                                 /* MOV r/m,r */
        {0x88, 0, F_MODRM},                                 /* MOV r/m8,r8 */
        {0x8A, 0, F_MODRM},                                 /* MOV r8,r/m8 */
        {0x8C, 0, F_MODRM},                                 /* MOV r/m,Sreg */
        {0x8E, 0, F_MODRM},                                 /* MOV Sreg,r/m */
        {0xA0, 0, F_IMM8},                                  /* MOV AL,moffs8 */
        {0xA1, 0, F_IMM32},                                 /* MOV EAX,moffs32 */
        {0xA2, 0, F_IMM8},                                  /* MOV moffs8,AL */
        {0xA3, 0, F_IMM32},                                 /* MOV moffs32,EAX */
        {0xB0, 0, F_PLUS_R | F_IMM8},                       /* MOV r8,imm8 */
        {0xB8, 0, F_PLUS_R | F_IMM32},                      /* MOV r32,imm32 */
        {0xC6, 0, F_MODRM | F_REG_OPCODE | F_IMM8},         /* MOV r/m8,imm8 */
        {0xC7, 0, F_MODRM | F_REG_OPCODE | F_IMM32},        /* MOV r/m,imm32 */

        /* Stack frame setup */
        {0x50, 0, F_PLUS_R},                                /* PUSH r64 */
        {0x58, 0, F_PLUS_R},                                /* POP r64 */
        {0x8F, 0, F_MODRM | F_REG_OPCODE},                  /* POP r/m */
        {0xFF, 6, F_MODRM | F_REG_OPCODE},                  /* PUSH r/m */
        {0xFF, 2, F_MODRM | F_REG_OPCODE},                  /* CALL r/m */
        {0xFF, 4, F_MODRM | F_REG_OPCODE},                  /* JMP  r/m */
        {0x6A, 0, F_IMM8},                                  /* PUSH imm8 */
        {0x68, 0, F_IMM32},                                 /* PUSH imm32 */

        /* Arithmetic on stack/frame — Group 1 (0x80/0x81/0x83 /n) */
        {0x83, 0, F_MODRM | F_REG_OPCODE | F_IMM8},         /* ADD r/m,imm8 (reg/0) */
        {0x81, 0, F_MODRM | F_REG_OPCODE | F_IMM32},        /* ADD r/m,imm32 (reg/0) */
        {0x83, 1, F_MODRM | F_REG_OPCODE | F_IMM8},         /* OR  r/m,imm8 */
        {0x81, 1, F_MODRM | F_REG_OPCODE | F_IMM32},        /* OR  r/m,imm32 */
        {0x83, 4, F_MODRM | F_REG_OPCODE | F_IMM8},         /* AND r/m,imm8 */
        {0x81, 4, F_MODRM | F_REG_OPCODE | F_IMM32},        /* AND r/m,imm32 */
        {0x83, 5, F_MODRM | F_REG_OPCODE | F_IMM8},         /* SUB r/m,imm8 */
        {0x81, 5, F_MODRM | F_REG_OPCODE | F_IMM32},        /* SUB r/m,imm32 */
        {0x83, 7, F_MODRM | F_REG_OPCODE | F_IMM8},         /* CMP r/m,imm8 */
        {0x81, 7, F_MODRM | F_REG_OPCODE | F_IMM32},        /* CMP r/m,imm32 */

        /* Arithmetic r,r/m and r/m,r */
        {0x29, 0, F_MODRM},                                 /* SUB r/m,r */
        {0x2B, 0, F_MODRM},                                 /* SUB r,r/m */
        {0x01, 0, F_MODRM},                                 /* ADD r/m,r */
        {0x03, 0, F_MODRM},                                 /* ADD r,r/m */
        {0x31, 0, F_MODRM},                                 /* XOR r/m,r */
        {0x33, 0, F_MODRM},                                 /* XOR r,r/m */

        /* TEST / CMP */
        {0x85, 0, F_MODRM},                                 /* TEST r/m,r */
        {0x39, 0, F_MODRM},                                 /* CMP r/m,r */
        {0x3B, 0, F_MODRM},                                 /* CMP r,r/m */
        {0xF7, 0, F_MODRM | F_REG_OPCODE | F_IMM32},        /* TEST/CMP r/m,imm32 */
        {0xF6, 0, F_MODRM | F_REG_OPCODE | F_IMM8},         /* TEST/CMP r/m8,imm8 */
    };

    size_t len = 0;
    int has_66 = 0;
    int has_rex = 0;
    (void)has_rex;       /* reserved for future SIB extension; OK to drop */
    if (reloc_offset) *reloc_offset = 0;

    /* 1) Consume legacy prefixes. */
    for (size_t i = 0; i < sizeof(legacy_prefixes)/sizeof(*legacy_prefixes); i++) {
        if (code[len] == legacy_prefixes[i]) {
            if (legacy_prefixes[i] == 0x66) {
                has_66 = 1;
            }
            len++;
            /* keep consuming — multiple prefixes are legal */
            i = (size_t)-1; /* restart scan */
            if (len >= 15) return 0; /* x86 caps prefix count */
        }
    }

    /* 2) REX prefix (0x40..0x4F) — only valid in long mode. */
    if ((code[len] & 0xF0) == 0x40) {
        has_rex = 1;
        len++;
    }

    /* 3) endbr64 / endbr32 (F3 0F 1E FA / F3 0F 1E FB). The 0xF3 was
     *    consumed as a prefix above, so we recognise the tail here. */
    if (len >= 1 && code[len] == 0x0F && code[len+1] == 0x1E &&
        (code[len+2] == 0xFA || code[len+2] == 0xFB)) {
        len += 3;
        return len;
    }

    /* 4) Multi-byte NOP: 0F 1F /0..7, 0F 1E /7, with optional 66 prefix. */
    if (code[len] == 0x0F && (code[len+1] == 0x1F || code[len+1] == 0x1E)) {
        uint8_t modrm = code[len+2];
        int mod = modrm >> 6;
        int rm  = modrm & 7;
        size_t insn_len = 3;
        if (mod != 3 && rm == 4) insn_len++;     /* SIB */
        if (mod == 1) insn_len += 1;             /* disp8 */
        if (mod == 2 || (mod == 0 && rm == 5)) insn_len += 4; /* disp32 */
        return len + insn_len;
    }

    /* 5) Two-byte opcode escape 0F xx — small subset we recognise. */
    if (code[len] == 0x0F) {
        uint8_t op2 = code[len+1];
        /* MOVAPS / MOVUPS / MOVAPD / MOVUPD: 0F 28 / 0F 29 / 0F 10 / 0F 11 */
        if (op2 == 0x28 || op2 == 0x29 || op2 == 0x10 || op2 == 0x11 ||
            op2 == 0x57 /* XORPS */) {
            uint8_t modrm = code[len+2];
            int mod = modrm >> 6;
            int rm  = modrm & 7;
            size_t insn_len = 3;
            if (mod != 3 && rm == 4) insn_len++;
            if (mod == 1) insn_len += 1;
            if (mod == 2 || (mod == 0 && rm == 5)) {
                insn_len += 4;
                if (reloc_offset) *reloc_offset = (int)(insn_len - 4);
                return len + insn_len;
            }
            return len + insn_len;
        }
        /* Unrecognised 0F xx — bail. */
        return 0;
    }

    /* 6) One-byte opcode table lookup. */
    const struct opinfo *match = NULL;
    for (size_t i = 0; i < sizeof(opcodes)/sizeof(*opcodes); i++) {
        const struct opinfo *o = &opcodes[i];
        int found = 0;

        if (o->flags & F_PLUS_R) {
            /* opcode low 3 bits encode register */
            if ((code[len] & 0xF8) == o->opcode) found = 1;
        } else if (o->flags & F_REG_OPCODE) {
            /* exact opcode + ModRM /n must match */
            if (code[len] == o->opcode &&
                ((code[len+1] >> 3) & 7) == o->reg_opcode) found = 1;
        } else {
            if (code[len] == o->opcode) found = 1;
        }

        if (found) { match = o; break; }
    }
    if (!match) return 0;

    /* Record rel32 location for RELOC_REL instructions (CALL/JMP rel32). */
    if ((match->flags & F_RELOC_REL) && reloc_offset) {
        /* rel32 disp starts immediately after the 1-byte opcode */
        *reloc_offset = (int)(len + 1);
    }

    len++;  /* consume opcode */

    /* 7) ModRM byte. */
    if (match->flags & F_MODRM) {
        uint8_t modrm = code[len++];
        int mod = modrm >> 6;
        int rm  = modrm & 7;

        if (mod != 3 && rm == 4) len++;          /* SIB */
        if (mod == 1) len += 1;                  /* disp8 */
        if (mod == 2 || (mod == 0 && rm == 5)) {
            /* On x86-64 in long mode, mod=0 rm=5 means [RIP+disp32] —
             * a RIP-relative address that needs fixup. */
            len += 4;
            if (reloc_offset && !(match->flags & F_RELOC_REL))
                *reloc_offset = (int)(len - 4);
        }
    }

    /* 8) Immediates. */
    if (match->flags & F_IMM8)  len += 1;
    if (match->flags & F_IMM16) len += 2;
    if (match->flags & F_IMM32) len += (has_66 ? 2 : 4);

    return len;
}

/* Backward-compat alias */
static inline size_t syringe_hook_disasm_x86_64(const uint8_t *code,
                                                 int *reloc_offset) {
    return syringe_hook_arch_disasm(code, reloc_offset);
}

/* ── trampoline builder: copy prologue + fix up relative disps ────────────────
 *
 * Fills `bounce_payload` with:
 *   [ stolen prologue bytes, with rel32 / RIP disps patched ] [ JMP abs ]
 *
 * On success returns the number of bytes to overwrite on the target
 * (i.e. the stolen prologue length, always >= TRAMP_JMP_SZ) and sets
 * *copied_bytes to the same value. Returns 0 on failure.
 *
 * The prologue bytes are read via /proc/self/mem (pread) so that
 * targets in unreadable pages (vDSO, kernel trap gates) don't segfault.
 */
static inline size_t syringe_hook_arch_tramp_make(uint8_t *bounce_payload,
                                                    size_t bounce_cap,
                                                    const void *target,
                                                    size_t *copied_bytes) {
    size_t stolen = 0;
    const uint8_t *src = (const uint8_t*)target;

    /* Shadow-read prologue via /proc/self/mem to avoid segfault on
     * unreadable targets. We need up to TRAMP_STOLEN_MAX bytes. */
    uint8_t prologue_buf[TRAMP_STOLEN_MAX];
    int have_prologue = 0;
    if (syringe_memfd < 0) syringe_hook_memfd_open();
    if (syringe_memfd >= 0) {
        ssize_t rd = pread(syringe_memfd, prologue_buf, TRAMP_STOLEN_MAX,
                           (off_t)(uintptr_t)target);
        if (rd == (ssize_t)TRAMP_STOLEN_MAX) {
            have_prologue = 1;
            src = prologue_buf;
        } else {
            SYRINGE_HOOK_LOG("tramp_make: pread prologue failed (rd=%zd)", rd);
        }
    }
    if (!have_prologue) {
        /* Last-resort: direct read. May segfault on protected pages. */
        memcpy(prologue_buf, target, TRAMP_STOLEN_MAX);
        src = prologue_buf;
    }

    while (stolen < TRAMP_JMP_SZ) {
        int reloc_off = 0;
        size_t insn_len = syringe_hook_arch_disasm(src + stolen, &reloc_off);

        if (insn_len == 0) {
            SYRINGE_HOOK_LOG("tramp_make: unknown opcode at +%zu (target=%p)",
                             stolen, target);
            return 0;
        }
        if (stolen + insn_len > TRAMP_STOLEN_MAX) {
            SYRINGE_HOOK_LOG("tramp_make: stolen prologue exceeds %d bytes",
                             TRAMP_STOLEN_MAX);
            return 0;
        }
        if (stolen + insn_len + TRAMP_JMP_SZ > bounce_cap) {
            SYRINGE_HOOK_LOG("tramp_make: bounce buffer too small");
            return 0;
        }

        /* Copy instruction verbatim, then patch its displacement if any. */
        memcpy(bounce_payload + stolen, src + stolen, insn_len);

        if (reloc_off > 0) {
            /* rel32 / RIP-disp32: add (target - bounce) so that when this
             * instruction executes from the bounce stub, the disp points
             * back to the same absolute address it referenced originally. */
            intptr_t b_addr = (intptr_t)(bounce_payload + stolen);
            intptr_t t_addr = (intptr_t)((const uint8_t*)target + stolen);
            int32_t orig_disp;
            memcpy(&orig_disp, bounce_payload + stolen + reloc_off, 4);
            int32_t new_disp = (int32_t)(orig_disp + (t_addr - b_addr));
            memcpy(bounce_payload + stolen + reloc_off, &new_disp, 4);
        }

        stolen += insn_len;
    }

    /* Append the JMP abs back to target+stolen. */
    syringe_hook_arch_build_jmp(bounce_payload + stolen,
                                 (void*)((uintptr_t)target + stolen));

    if (copied_bytes) *copied_bytes = stolen;
    return stolen;
}

/* Backward-compat alias */
static inline size_t syringe_hook_tramp_make(uint8_t *bounce_payload,
                                              size_t bounce_cap,
                                              const void *target,
                                              size_t *copied_bytes) {
    return syringe_hook_arch_tramp_make(bounce_payload, bounce_cap,
                                         target, copied_bytes);
}

/* ── Atomic 14-byte patch ─────────────────────────────────────────────────────
 *
 * Split the 14-byte JMP-abs into two 8-byte atomic stores so the target
 * is never in an inconsistent half-patched state for more than one store.
 * On x86-64 this is enough to prevent any thread from fetching a 0xFF
 * prefix without its matching ModRM.
 *
 * The caller's `jmp[14]` is copied into a 16-byte stack buffer first so
 * the second 8-byte read (offset 8..16) is fully inside an aligned
 * object — GCC's -Warray-bounds= would otherwise flag it. */
static inline int syringe_hook_arch_atomic_patch_jmp(void *target,
                                                       const uint8_t jmp[TRAMP_JMP_SZ]) {
    uint8_t buf[16] = {0};
    memcpy(buf, jmp, TRAMP_JMP_SZ);
    uint64_t lo, hi;
    memcpy(&lo, buf,     8);
    memcpy(&hi, buf + 8, 8);
    __atomic_store_n((uint64_t*)target,      lo, __ATOMIC_SEQ_CST);
    __atomic_store_n((uint64_t*)target + 1,  hi, __ATOMIC_SEQ_CST);
    return 0;
}

/* Backward-compat alias */
static inline int syringe_hook_atomic_patch_jmp(void *target,
                                                 const uint8_t jmp[TRAMP_JMP_SZ]) {
    return syringe_hook_arch_atomic_patch_jmp(target, jmp);
}

#endif /* SYRINGE_HOOK_X86_64_H */
