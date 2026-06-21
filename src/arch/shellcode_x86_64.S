/*
 * shellcode_x86_64.S — dlopen-calling shellcode template (x86-64)
 *
 * Compiled to raw binary via: gcc -c → objcopy -O binary -j .text
 * Then embedded into arch_x86_64.c via xxd -i.
 *
 * The compiled binary has TWO placeholder regions that are patched at
 * runtime by syringe_arch_build_shellcode():
 *
 *   1. dlopen_addr placeholder: 8 bytes of 0x00 after "movabs $0, %rax"
 *      Patched with the target process's dlopen() address.
 *
 *   2. so_path placeholder: 256 bytes of 0x00 at the end (after .asciz)
 *      Patched with the .so path string (NUL-terminated).
 *
 * Layout (after compilation):
 *   [0x00] nop; nop                          (entry skip for ptrace quirk)
 *   [0x02] pushfq + push rax-r15             (save 16 regs + flags)
 *   [0x20] lea rdi, [rip + path_offset]      (path string address)
 *   [0x27] movabs $0, %rsi                   (RTLD_NOW|RTLD_GLOBAL = 0x102)
 *   [0x31] movabs $0, %rax                   (dlopen addr — PATCHED)
 *   [0x3B] call *%rax                        (call dlopen)
 *   [0x3D] int3                              (SIGTRAP — injector catches)
 *   [0x3E] pop r15-rax + popfq               (restore 16 regs + flags)
 *   [0x56] ret                               (return to original RIP)
 *   [0x57] path: .space 256                  (so_path — PATCHED)
 *
 * Total: ~0x157 bytes (343)
 *
 * The path_offset in lea is calculated at assembly time by the linker
 * (RIP-relative), so no manual patching needed for that.
 */

    .section .text
    .globl syringe_shellcode_x86_64
    .globl syringe_shellcode_x86_64_size
    .type syringe_shellcode_x86_64, @function

syringe_shellcode_x86_64:
    /* Entry NOPs for ptrace RIP-2 quirk */
    nop
    nop

    /* Save flags + all GPRs */
    pushfq
    push %rax
    push %rcx
    push %rdx
    push %rbx
    push %rbp
    push %rsi
    push %rdi
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15

    /* lea rdi, [rip + path - 1f]  — path string (PC-relative) */
    lea path(%rip), %rdi

    /* mov rsi, RTLD_NOW|RTLD_GLOBAL = 0x102 */
    movabs $0x102, %rsi

    /* movabs $0, %rax  — dlopen address placeholder (PATCHED at runtime) */
    movabs $0, %rax

    /* call *%rax */
    call *%rax

    /* int3 — trap so injector can catch */
    int3

    /* Restore all GPRs + flags (reverse order) */
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rdi
    pop %rsi
    pop %rbp
    pop %rbx
    pop %rdx
    pop %rcx
    pop %rax
    popfq

    /* ret */
    ret

    /* Path string — 256 bytes, patched at runtime */
    .align 8
path:
    .space 256, 0

    /* Size marker (filled by linker) */
    .align 8
syringe_shellcode_x86_64_end:

    .section .rodata
syringe_shellcode_x86_64_size:
    .quad syringe_shellcode_x86_64_end - syringe_shellcode_x86_64
