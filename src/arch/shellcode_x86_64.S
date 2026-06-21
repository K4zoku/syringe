/*
 * shellcode_x86_64.S — dlopen-calling shellcode template (x86-64)
 *
 * Compiled to raw binary via: gcc -c → objcopy -O binary -j .text
 * Then embedded into arch_x86_64.c via xxd -i (see meson.build).
 *
 * The compiled binary has TWO placeholder regions that are patched at
 * runtime by syringe_arch_build_shellcode():
 *
 *   1. dlopen_addr placeholder: 8 bytes of 0x00 inside `movabs $0, %rax`.
 *      Patched with the target process's dlopen() address (full 64-bit).
 *
 *   2. so_path placeholder: 256 bytes of 0x00 at the end.
 *      Patched with the .so path string (NUL-terminated).
 *
 * ── Register save/restore strategy ───────────────────────────────────
 *
 * Only CALLER-SAVED registers are saved (rax, rcx, rdx, rsi, rdi, r8-r11)
 * plus RFLAGS. Callee-saved registers (rbx, rbp, r12-r15) are NOT saved
 * because dlopen() — a normal C function — is required by the System V
 * AMD64 ABI to preserve them across the call. rsp is implicitly preserved
 * by the matched push/pop sequence.
 *
 * This trades a (tiny) assumption about dlopen's ABI compliance for a
 * ~10% size reduction vs the previous "save all 15 GPRs" approach. All
 * production libc implementations (glibc, musl, bionic) honor this.
 *
 * Stack alignment: 1 pushfq + 9 push = 10 stack ops × 8 bytes = 80 bytes
 * (multiple of 16), so the 16-byte ABI alignment is preserved through
 * the `call *%rax` boundary. (Target's pre-injection alignment is
 * preserved verbatim — we don't fix up a misaligned entry rsp.)
 *
 * ── DF caveat ─────────────────────────────────────────────────────────
 *
 * The System V ABI requires DF=0 on function entry/exit. We restore the
 * target's original RFLAGS via popfq, so if the target had DF=1 at the
 * injection site, DF=1 is restored. This matches the pre-optimization
 * behavior — not a regression — and is the target's responsibility.
 *
 * Layout (after compilation — verified against objcopy -O binary output):
 *   [0x00] nop; nop                          (2 bytes, entry skip for ptrace quirk)
 *   [0x02] pushfq                            (1 byte, save RFLAGS)
 *   [0x03] push rax,rcx,rdx,rsi,rdi          (5 × 1 byte, caller-saved + arg regs)
 *   [0x08] push r8..r11                      (4 × 2 bytes, REX-prefixed caller-saved)
 *   [0x10] lea rdi, [rip + 0x21]             (7 bytes — RIP+0x21 = path @ 0x38)
 *   [0x17] mov $0x102, %esi                  (5 bytes — RTLD_NOW|RTLD_GLOBAL, zero-extends)
 *   [0x1C] movabs $0, %rax                   (10 bytes — dlopen addr, PATCHED)
 *                                                   imm64 value at 0x1E
 *   [0x26] call *%rax                        (2 bytes)
 *   [0x28] int3                              (1 byte — SIGTRAP)
 *   [0x29] pop r11..r8                       (4 × 2 bytes)
 *   [0x31] pop rdi,rsi,rdx,rcx,rax           (5 × 1 byte)
 *   [0x36] popfq                             (1 byte)
 *   [0x37] ret                               (1 byte)
 *   [0x38] path: .space 256                  (256 bytes — so_path, PATCHED)
 *
 * Total: 0x138 = 312 bytes (was 344 before caller-saved-only optimization)
 *
 * The lea displacement (0x21) is computed by the assembler from the
 * RIP-relative reference to `path`, so no manual patching is needed for it.
 */

    .section .text
    .globl syringe_shellcode_x86_64
    .globl syringe_shellcode_x86_64_size
    .type syringe_shellcode_x86_64, @function

syringe_shellcode_x86_64:
    /* Entry NOPs for ptrace RIP-2 quirk */
    nop
    nop

    /* Save RFLAGS + caller-saved GPRs (callee-saved rbx/rbp/r12-r15 are
     * preserved by dlopen per System V ABI — no need to save here).
     * 1 pushfq + 9 push = 10 stack ops × 8 bytes = 80 bytes (16-aligned). */
    pushfq
    push %rax
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %r8
    push %r9
    push %r10
    push %r11

    /* lea path(%rip), %rdi  — path string (PC-relative) */
    lea path(%rip), %rdi

    /* mov $0x102, %esi  — RTLD_NOW(2) | RTLD_GLOBAL(0x100).
     * 5-byte mov $imm32 zero-extends to rsi, no need for 10-byte movabs. */
    mov $0x102, %esi

    /* movabs $0, %rax  — dlopen address placeholder (PATCHED at runtime).
     * Must keep movabs (10 bytes) so the runtime 8-byte patch fits in the
     * imm64 slot without overflowing into the next instruction. */
    movabs $0, %rax

    /* call *%rax */
    call *%rax

    /* int3 — trap so injector can catch */
    int3

    /* Restore caller-saved GPRs + RFLAGS (reverse order) */
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rdi
    pop %rsi
    pop %rdx
    pop %rcx
    pop %rax
    popfq

    /* ret */
    ret

    /* Path string — 256 bytes, patched at runtime.
     * Naturally 8-byte aligned at 0x38 (no .align directive needed). */
    .align 8
path:
    .space 256, 0

    /* Size marker (filled by linker) */
    .align 8
syringe_shellcode_x86_64_end:

    .section .rodata
syringe_shellcode_x86_64_size:
    .quad syringe_shellcode_x86_64_end - syringe_shellcode_x86_64
