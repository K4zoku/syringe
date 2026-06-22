/*
 * test_hook.c — unit tests for syringe_hook module
 *
 * Tests:
 *   - syringe_hook_page_floor()
 *   - syringe_hook_registry_size()
 *   - syringe_hook_count() — must be 0 initially
 *   - syringe_hook_remove() on empty registry → return 0
 *   - syringe_hook_remove_all() on empty registry → no segfault
 *   - syringe_hook_is_installed() — false when not hooked
 *   - syringe_hook_install() on non-existent symbol → return 0
 *   - syringe_hook_install() + syringe_hook_remove() — count back to 0
 *   - syringe_hook_install() duplicate symbol → return 0
 *   - syringe_hook_build_jmp() — jmp struct is correct 14 bytes
 *   - syringe_hook_tramp_install() non-existent symbol → MAP_FAILED
 *
 * v0.5 additions:
 *   - syringe_hook_disasm_x86_64() — instruction length + reloc offset
 *     on common prologues (endbr64, push rbp, mov rbp,rsp, sub rsp,
 *     lea r,[rip+disp], call rel32, NOP multi-byte)
 *   - syringe_hook_jmp_target() — detect if already hooked
 *   - syringe_hook_install_addr() — inline hook from direct address
 *   - syringe_hook_tramp_make() — fix-up RIP-relative disp when copying prologue
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <dlfcn.h>
#include <sys/mman.h>

#include "hook/syringe_hook.h"   /* pulls in syringe_hook_* API */

/* ── assertion helpers ─────────────────────────────────────────────────── */

static int tests_run = 0;
static int tests_pass = 0;
static int tests_fail = 0;

static void check_int(int expected, int actual, const char *expr) {
    tests_run++;
    if (expected == actual) {
        tests_pass++;
        fprintf(stderr, "  PASS: %s == %d\n", expr, actual);
    } else {
        tests_fail++;
        fprintf(stderr, "FAIL: %s:%d: %s — expected %d, got %d\n",
                __FILE__, __LINE__, expr, expected, actual);
    }
}

static void check_ptr(void *ptr, int expect_null, const char *expr) {
    tests_run++;
    int is_null = (ptr == NULL);
    if (is_null == expect_null) {
        tests_pass++;
        if (expect_null)
            fprintf(stderr, "  PASS: %s is NULL\n", expr);
        else
            fprintf(stderr, "  PASS: %s is non-NULL\n", expr);
    } else {
        tests_fail++;
        fprintf(stderr, "FAIL: %s:%d: expected %s, got %s\n",
                __FILE__, __LINE__,
                expect_null ? "NULL" : "non-NULL",
                is_null ? "NULL" : "non-NULL");
    }
}

static void check_ptr_eq(void *expected, void *actual, const char *expr) {
    tests_run++;
    if (expected == actual) {
        tests_pass++;
        fprintf(stderr, "  PASS: %s\n", expr);
    } else {
        tests_fail++;
        fprintf(stderr, "FAIL: %s:%d: %s — expected %p, got %p\n",
                __FILE__, __LINE__, expr, expected, actual);
    }
}

#define CHECK_EQ(exp, act, desc) check_int((exp), (act), desc)

/* ── tests: page helpers ───────────────────────────────────────────────── */

static void test_page_floor(void) {
    printf("\n[page_floor]\n");
    uintptr_t r;

    r = syringe_hook_page_floor(0x0);
    CHECK_EQ(0x0, r, "page_floor(0x0)");

    r = syringe_hook_page_floor(1);
    CHECK_EQ(0x0, r, "page_floor(1)");

    r = syringe_hook_page_floor(0x1000);
    CHECK_EQ(0x1000, r, "page_floor(0x1000)");

    r = syringe_hook_page_floor(0x1001);
    CHECK_EQ(0x1000, r, "page_floor(0x1001)");

    r = syringe_hook_page_floor(0x1FFF);
    CHECK_EQ(0x1000, r, "page_floor(0x1FFF)");
}

static void test_page_is_ro(void) {
    printf("\n[page_is_ro]\n");

    int local_var = 42;
    int ro = syringe_hook_page_is_ro(&local_var);
    CHECK_EQ(0, ro, "stack variable is not RO");

    const char *ro_str = "constant string";
    ro = syringe_hook_page_is_ro((void *)ro_str);
    CHECK_EQ(1, ro, "string literal is RO");
}

/* ── tests: registry helpers ────────────────────────────────────────────── */

static void test_registry_helpers(void) {
    printf("\n[registry helpers]\n");

    syringe_hook_remove_all();

    int size = syringe_hook_registry_size();
    CHECK_EQ(SYRINGE_HOOK_MAX, size, "registry_size");

    int count = syringe_hook_count();
    CHECK_EQ(0, count, "count is 0 after init");
}

/* ── tests: remove on empty registry ────────────────────────────────────── */

static void test_remove_empty(void) {
    printf("\n[remove empty]\n");

    syringe_hook_remove_all();

    int r = syringe_hook_remove("nonexistent_symbol");
    CHECK_EQ(0, r, "remove nonexistent → 0");

    syringe_hook_remove_all();
    int count = syringe_hook_count();
    CHECK_EQ(0, count, "count still 0");
}

/* ── tests: is_installed ────────────────────────────────────────────────── */

static void test_is_installed(void) {
    printf("\n[is_installed]\n");

    syringe_hook_remove_all();

    int installed = syringe_hook_is_installed("fake_symbol");
    CHECK_EQ(0, installed, "fake_symbol not installed");
}

/* ── tests: install non-existent symbol ─────────────────────────────────── */

static void test_install_nonexistent(void) {
    printf("\n[install nonexistent]\n");

    syringe_hook_remove_all();

    void *my_hook = (void *)0x12345678;
    void *orig = NULL;

    int r = syringe_hook_install("__fake_symbol_xyz_does_not_exist", my_hook, &orig);
    CHECK_EQ(0, r, "install nonexistent → 0");

    int count = syringe_hook_count();
    CHECK_EQ(0, count, "count stays 0");
}

/* ── tests: install + remove cycle ────────────────────────────────────────
 *
 * v0.5 note: previously this test hooked `printf` with a bogus 0xDEADBEEF
 * hook address. That worked when the inline trampoline was gated off for
 * r-x pages (libc.so.6 is r-x). Now the trampoline ALWAYS runs, so the
 * hook address must be a callable function — otherwise any code path
 * between install() and remove() that invokes the hooked symbol crashes
 * the test process. We use an mmap'd RWX page with a synthetic prologue
 * and a no-op hook so the test exercises the install/remove bookkeeping
 * without depending on libc symbol behaviour.
 */

static void hook_noop_for_cycle(void) { return; }

static void test_install_remove_cycle(void) {
    printf("\n[install/remove cycle]\n");

    syringe_hook_remove_all();

    /* Build a fake "target" with a real prologue on an RWX page.
     * Padding with multi-byte NOPs so the disassembler can steal past
     * the 14-byte boundary that the actual instructions don't reach. */
    static const uint8_t prologue[] = {
        0xF3, 0x0F, 0x1E, 0xFA,                /* endbr64 (4) */
        0x55,                                  /* push rbp (1) */
        0x48, 0x89, 0xE5,                      /* mov rbp,rsp (3) */
        0xC3,                                  /* ret (1) — total 9, need 5 more */
        0x0F, 0x1F, 0x44, 0x00, 0x00,          /* 5-byte NOP (5) */
        0x0F, 0x1F, 0x44, 0x00, 0x00,          /* 5-byte NOP */
        0x0F, 0x1F, 0x44, 0x00, 0x00           /* 5-byte NOP */
    };
    void *target = mmap(NULL, getpagesize(),
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (target == MAP_FAILED) {
        printf("  SKIP: mmap failed\n");
        return;
    }
    memcpy(target, prologue, sizeof(prologue));

    void *orig = NULL;
    int r = syringe_hook_install_addr("__test_target", target,
                                       (void*)hook_noop_for_cycle, &orig);
    CHECK_EQ(1, r, "install_addr returns 1");

    int count = syringe_hook_count();
    CHECK_EQ(1, count, "1 hook after install");

    int installed = syringe_hook_is_installed("__test_target");
    CHECK_EQ(1, installed, "__test_target is installed");

    syringe_hook_remove("__test_target");
    count = syringe_hook_count();
    CHECK_EQ(0, count, "count back to 0 after remove");

    installed = syringe_hook_is_installed("__test_target");
    CHECK_EQ(0, installed, "__test_target not installed after remove");

    /* Verify the stolen region of target prologue was restored.
     * Only the first `stolen_len` bytes were overwritten; bytes after
     * that were never touched. The known stolen_len for this prologue
     * is 14: endbr64(4) + push(1) + mov(3) + ret(1) = 9, + 5-byte
     * NOP = 14. */
    CHECK_EQ(0, memcmp(target, prologue, 14),
             "target prologue (first 14 bytes) restored after remove");

    syringe_hook_remove_all();
    munmap(target, getpagesize());
}

/* ── tests: duplicate install ───────────────────────────────────────────── */

static void hook1_for_dup(void) { return; }
static void hook2_for_dup(void) { return; }

static void test_duplicate_install(void) {
    printf("\n[duplicate install]\n");

    syringe_hook_remove_all();

    static const uint8_t prologue[] = {
        0xF3, 0x0F, 0x1E, 0xFA,
        0x55,
        0x48, 0x89, 0xE5,
        0xC3,
        0x0F, 0x1F, 0x44, 0x00, 0x00,
        0x0F, 0x1F, 0x44, 0x00, 0x00,
        0x0F, 0x1F, 0x44, 0x00, 0x00
    };
    void *target = mmap(NULL, getpagesize(),
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (target == MAP_FAILED) {
        printf("  SKIP: mmap failed\n");
        return;
    }
    memcpy(target, prologue, sizeof(prologue));

    void *orig1 = NULL;
    void *orig2 = NULL;

    int r = syringe_hook_install_addr("__test_dup", target,
                                       (void*)hook1_for_dup, &orig1);
    CHECK_EQ(1, r, "first install_addr OK");

    int r2 = syringe_hook_install_addr("__test_dup", target,
                                        (void*)hook2_for_dup, &orig2);
    CHECK_EQ(0, r2, "duplicate install → 0");

    syringe_hook_remove_all();
    munmap(target, getpagesize());
}

/* ── tests: build_jmp ───────────────────────────────────────────────────── */

static void test_build_jmp(void) {
    printf("\n[build_jmp]\n");

    uint8_t buf[TRAMP_JMP_SZ];
    void *dest = (void *)0xDEADBEEF;

    syringe_hook_build_jmp(buf, dest);

    CHECK_EQ(TRAMP_JMP_SZ, (int)sizeof(buf), "jmp buffer size");
    CHECK_EQ(0xFF, (int)buf[0], "jmp opcode byte 0");
    CHECK_EQ(0x25, (int)buf[1], "jmp modrm byte");
    CHECK_EQ(0, (int)buf[2], "jmp disp byte 2");
    CHECK_EQ(0, (int)buf[3], "jmp disp byte 3");
    CHECK_EQ(0, (int)buf[4], "jmp disp byte 4");
    CHECK_EQ(0, (int)buf[5], "jmp disp byte 5");

    uint64_t addr;
    memcpy(&addr, buf + 6, 8);
    CHECK_EQ(0xDEADBEEF, (uint32_t)addr, "jmp address stored correctly");
}

/* ── tests: tramp_install on invalid address ────────────────────────────── */

static void test_tramp_install_invalid(void) {
    printf("\n[tramp_install invalid]\n");

    Trampoline t;
    memset(&t, 0, sizeof(t));

    int r = syringe_hook_tramp_install(&t, NULL, (void *)0x1234, NULL);
    CHECK_EQ(-1, r, "tramp_install on NULL address fails");
    check_ptr(t.bounce, 1, "bounce is NULL after failed install");
}

/* ── tests: tramp_install on writable page ────────────────────────────────
 *
 * v0.5: this test used to mmap a zero-filled page and expect tramp_install
 * to "succeed" — that worked when the old code did a dumb 16-byte memcpy
 * without disassembling. The new disassembler-based trampoline correctly
 * refuses zero bytes (would decode as `add [rax],al` which is unsafe to
 * relocate because rax is not a known value at prologue entry). We now
 * fill the page with a valid synthetic prologue so the test exercises the
 * real install path.
 */
static void test_tramp_install_writable(void) {
    printf("\n[tramp_install writable]\n");
#if defined(__x86_64__) && defined(__LP64__)

    Trampoline t;
    memset(&t, 0, sizeof(t));

    void *target = mmap(NULL, getpagesize(),
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (target == MAP_FAILED) {
        printf("  SKIP: mmap failed (likely no permissions)\n");
        return;
    }

    /* Fill target with a realistic prologue: endbr64 + push rbp +
     * mov rbp,rsp + sub rsp,0x20 + multi-byte NOP padding. */
    static const uint8_t prologue[] = {
        0xF3, 0x0F, 0x1E, 0xFA,                /* endbr64 */
        0x55,                                  /* push rbp */
        0x48, 0x89, 0xE5,                      /* mov rbp,rsp */
        0x48, 0x83, 0xEC, 0x20,                /* sub rsp,0x20 */
        0x0F, 0x1F, 0x44, 0x00, 0x00,          /* 5-byte NOP */
        0x0F, 0x1F, 0x44, 0x00, 0x00,          /* 5-byte NOP */
        0xC3                                   /* ret */
    };
    memcpy(target, prologue, sizeof(prologue));

    void *hook = (void *)0xCAFEBABE;
    void *orig = NULL;

    int r = syringe_hook_tramp_install(&t, target, hook, &orig);
    CHECK_EQ(0, r, "tramp_install on writable page succeeds");
    check_ptr(t.bounce, 0, "bounce allocated");
    check_ptr(orig, 0, "orig bounce pointer set");

    CHECK_EQ(0xFF, ((uint8_t *)target)[0], "target patched with jmp opcode");
    CHECK_EQ(0x25, ((uint8_t *)target)[1], "target patched with jmp modrm");
    /* stolen_len = bytes stolen to fit a whole-instruction boundary >= 14:
     *   endbr64(4) + push(1) + mov(3) + sub(4) = 12, need >= 14
     *   + 5-byte NOP = 17. So stolen_len == 17. */
    CHECK_EQ(17, (int)t.stolen_len, "stolen_len is 17 (endbr64+push+mov+sub+1 NOP)");

    syringe_hook_tramp_remove(&t);
    CHECK_EQ(0, t.active, "trampoline inactive after remove");
    /* Verify original prologue was restored byte-for-byte. */
    CHECK_EQ(0, memcmp(target, prologue, sizeof(prologue)),
             "target prologue restored after remove");
    munmap(target, getpagesize());
#else
    printf("  SKIP: not x86-64\n");
#endif
}

/* ── tests: x86-64 length-disassembler ────────────────────────────────────
 *
 * We feed the disassembler hand-assembled prologue bytes and assert the
 * reported length matches the architecture manual.
 */

static void test_disasm_x86_64(void) {
    printf("\n[disasm_x86_64]\n");
#if !defined(__x86_64__) || !defined(__LP64__)
    printf("  SKIP: not x86-64\n");
    (void)syringe_hook_disasm_x86_64;
#else
    int reloc = -1;
    size_t len;

    /* endbr64 = F3 0F 1E FA — 4 bytes, no reloc */
    {
        uint8_t code[] = { 0xF3, 0x0F, 0x1E, 0xFA };
        reloc = -1;
        len = syringe_hook_disasm_x86_64(code, &reloc);
        CHECK_EQ(4, (int)len, "endbr64 length");
        CHECK_EQ(0, reloc, "endbr64 has no reloc");
    }

    /* push rbp = 55 — 1 byte */
    {
        uint8_t code[] = { 0x55 };
        len = syringe_hook_disasm_x86_64(code, NULL);
        CHECK_EQ(1, (int)len, "push rbp length");
    }

    /* mov rbp, rsp = 48 89 E5 — 3 bytes (REX + MOV r/m,r + ModRM) */
    {
        uint8_t code[] = { 0x48, 0x89, 0xE5 };
        len = syringe_hook_disasm_x86_64(code, NULL);
        CHECK_EQ(3, (int)len, "mov rbp,rsp length");
    }

    /* sub rsp, 0x20 = 48 83 EC 20 — 4 bytes */
    {
        uint8_t code[] = { 0x48, 0x83, 0xEC, 0x20 };
        len = syringe_hook_disasm_x86_64(code, NULL);
        CHECK_EQ(4, (int)len, "sub rsp,0x20 length");
    }

    /* lea rax, [rip+0x1234] = 48 8D 05 34 12 00 00 — 7 bytes, reloc at offset 3 */
    {
        uint8_t code[] = { 0x48, 0x8D, 0x05, 0x34, 0x12, 0x00, 0x00 };
        reloc = -1;
        len = syringe_hook_disasm_x86_64(code, &reloc);
        CHECK_EQ(7, (int)len, "lea rax,[rip+0x1234] length");
        CHECK_EQ(3, reloc, "lea rip-relative reloc offset");
    }

    /* mov rax, [rip+0x100] = 48 8B 05 00 01 00 00 — 7 bytes, reloc at 3 */
    {
        uint8_t code[] = { 0x48, 0x8B, 0x05, 0x00, 0x01, 0x00, 0x00 };
        reloc = -1;
        len = syringe_hook_disasm_x86_64(code, &reloc);
        CHECK_EQ(7, (int)len, "mov rax,[rip+0x100] length");
        CHECK_EQ(3, reloc, "mov rax,[rip] reloc offset");
    }

    /* call rel32 = E8 00 00 00 00 — 5 bytes, reloc at 1 */
    {
        uint8_t code[] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
        reloc = -1;
        len = syringe_hook_disasm_x86_64(code, &reloc);
        CHECK_EQ(5, (int)len, "call rel32 length");
        CHECK_EQ(1, reloc, "call rel32 reloc offset");
    }

    /* jmp rel32 = E9 00 00 00 00 — 5 bytes, reloc at 1 */
    {
        uint8_t code[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
        reloc = -1;
        len = syringe_hook_disasm_x86_64(code, &reloc);
        CHECK_EQ(5, (int)len, "jmp rel32 length");
        CHECK_EQ(1, reloc, "jmp rel32 reloc offset");
    }

    /* multi-byte NOP 0F 1F 00 = 3 bytes */
    {
        uint8_t code[] = { 0x0F, 0x1F, 0x00 };
        len = syringe_hook_disasm_x86_64(code, NULL);
        CHECK_EQ(3, (int)len, "nop 0F 1F 00 length");
    }

    /* 5-byte NOP: 0F 1F 44 00 00 */
    {
        uint8_t code[] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };
        len = syringe_hook_disasm_x86_64(code, NULL);
        CHECK_EQ(5, (int)len, "nop 0F 1F 44 00 00 length");
    }

    /* mov r12, rsp = 49 89 E4 — 3 bytes (REX.WB + MOV r/m,r + ModRM) */
    {
        uint8_t code[] = { 0x49, 0x89, 0xE4 };
        len = syringe_hook_disasm_x86_64(code, NULL);
        CHECK_EQ(3, (int)len, "mov r12,rsp length");
    }

    /* push r12 = 41 54 — 2 bytes (REX.B + PUSH r64) */
    {
        uint8_t code[] = { 0x41, 0x54 };
        len = syringe_hook_disasm_x86_64(code, NULL);
        CHECK_EQ(2, (int)len, "push r12 length");
    }

    /* sub rsp, 0x100 = 48 81 EC 00 01 00 00 — 7 bytes (REX + SUB r/m,imm32) */
    {
        uint8_t code[] = { 0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00 };
        len = syringe_hook_disasm_x86_64(code, NULL);
        CHECK_EQ(7, (int)len, "sub rsp,0x100 length");
    }

    /* Unknown opcode (e.g. 0x62 — EVEX prefix, not in our table) → 0 */
    {
        uint8_t code[] = { 0x62, 0x00, 0x00 };
        len = syringe_hook_disasm_x86_64(code, NULL);
        CHECK_EQ(0, (int)len, "unknown opcode returns 0");
    }
#endif
}

/* ── tests: syringe_hook_jmp_target ───────────────────────────────────────── */

static void test_read_dst(void) {
    printf("\n[read_dst]\n");
#ifndef SYRINGE_HOOK_NO_HELPERS

    /* Not hooked → NULL */
    uint8_t plain[] = { 0x55, 0x48, 0x89, 0xE5 };
    void *dst = syringe_hook_jmp_target(plain);
    check_ptr(dst, 1, "plain prologue → NULL");

    /* Hooked (FF 25 + zeros + 8-byte addr) → returns the addr */
    uint8_t hooked[14];
    syringe_hook_build_jmp(hooked, (void*)0xDEADBEEFCAFEULL);
    dst = syringe_hook_jmp_target(hooked);
    check_ptr(dst, 0, "hooked prologue → non-NULL");
    #ifdef __LP64__
        check_ptr_eq((void*)0xDEADBEEFCAFEULL, dst, "read_dst returns correct addr");
    #endif

    /* NULL input */
    dst = syringe_hook_jmp_target(NULL);
    check_ptr(dst, 1, "NULL input → NULL");
#else
    printf("  SKIP: SYRINGE_HOOK_NO_HELPERS defined\n");
#endif
}

/* ── tests: syringe_hook_install_addr ─────────────────────────────────────
 *
 * Build a small function in an mmap'd RWX page, install an inline hook
 * via syringe_hook_install_addr, verify the hook is called, verify the
 * trampoline can still call the original, then remove the hook.
 *
 * The function is intentionally built WITHOUT GOT/PLT dependencies so
 * the only path that can install the hook is the inline trampoline.
 */

/* hook_mul: replacement that returns a*b instead of a+b. Defined at
 * file scope because nested function definitions are not standard C. */
typedef int (*add_fn)(int, int);
static add_fn orig_add_for_test = NULL;

static int hook_mul(int a, int b) {
    return a * b;  /* ignore orig — we just want to see the hook fire */
}

static void test_install_addr(void) {
    printf("\n[install_addr]\n");
#ifndef SYRINGE_HOOK_NO_HELPERS

    uint8_t target_code_v2[] = {
        /* 0:  endbr64             */ 0xF3, 0x0F, 0x1E, 0xFA,    /* 4 bytes */
        /* 4:  push rbp            */ 0x55,                       /* 1 byte  */
        /* 5:  mov rbp, rsp        */ 0x48, 0x89, 0xE5,           /* 3 bytes */
        /* 8:  mov eax, edi        */ 0x89, 0xF8,                 /* 2 bytes */
        /* 10: add eax, esi        */ 0x01, 0xF0,                 /* 2 bytes */
        /* 12: pop rbp             */ 0x5D,                       /* 1 byte  */
        /* 13: ret                 */ 0xC3,                       /* 1 byte  */
        /* 14: padding             */ 0x0F, 0x1F, 0x44, 0x00, 0x00,
        0x0F, 0x1F, 0x44, 0x00, 0x00
    };

    void *page = mmap(NULL, getpagesize(),
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  SKIP: mmap failed\n");
        return;
    }
    memcpy(page, target_code_v2, sizeof(target_code_v2));

    add_fn target_add = (add_fn)page;

    /* Before hooking: target_add(3, 4) == 7 */
    int before = target_add(3, 4);
    CHECK_EQ(7, before, "target_add(3,4) before hook");

    syringe_hook_remove_all();
    orig_add_for_test = NULL;
    int n = syringe_hook_install_addr("target_add", (void*)target_add,
                                       (void*)hook_mul, (void**)&orig_add_for_test);
    CHECK_EQ(1, n, "install_addr returns 1");

    int installed = syringe_hook_is_installed("target_add");
    CHECK_EQ(1, installed, "target_add is_installed");

    /* After hook: target_add(3, 4) == 12 (3*4) */
    int after = target_add(3, 4);
    CHECK_EQ(12, after, "target_add(3,4) after hook returns 3*4");

    /* Trampoline should still call the original → 7 */
    int via_orig = orig_add_for_test(3, 4);
    CHECK_EQ(7, via_orig, "orig_add(3,4) via trampoline");

    /* Remove hook */
    syringe_hook_remove("target_add");
    int after_remove = target_add(3, 4);
    CHECK_EQ(7, after_remove, "target_add(3,4) after remove");

    installed = syringe_hook_is_installed("target_add");
    CHECK_EQ(0, installed, "target_add not installed after remove");

    syringe_hook_remove_all();
    munmap(page, getpagesize());
#else
    printf("  SKIP: SYRINGE_HOOK_NO_HELPERS defined\n");
#endif
}

/* ── tests: tramp_make with RIP-relative fixup ────────────────────────────
 *
 * Build a prologue that uses RIP-relative addressing, run tramp_make, and
 * verify the displacement in the bounce stub has been patched by the
 * delta (bounce - target).
 */

static void test_tramp_make_rip_relative(void) {
    printf("\n[tramp_make RIP-relative]\n");
#if defined(__x86_64__) && defined(__LP64__)

    /* lea rax, [rip+0x100]  (7 bytes)
     * mov rbp, rsp          (3 bytes)
     * push rbx              (1 byte)
     * push r12              (2 bytes)
     * sub rsp, 0x20         (4 bytes)
     * ret                   (1 byte)   ← total 18 bytes, > TRAMP_JMP_SZ */
    uint8_t prologue[] = {
        0x48, 0x8D, 0x05, 0x00, 0x01, 0x00, 0x00,    /* lea rax,[rip+0x100] */
        0x48, 0x89, 0xE5,                              /* mov rbp,rsp */
        0x53,                                          /* push rbx */
        0x41, 0x54,                                    /* push r12 */
        0x48, 0x83, 0xEC, 0x20,                        /* sub rsp,0x20 */
        0xC3                                           /* ret */
    };

    void *page = mmap(NULL, getpagesize(),
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  SKIP: mmap failed\n");
        return;
    }
    memcpy(page, prologue, sizeof(prologue));

    uint8_t bounce[TRAMP_BOUNCE_MAX];
    size_t copied = 0;
    size_t stolen = syringe_hook_tramp_make(bounce, sizeof(bounce),
                                             page, &copied);

    CHECK_EQ(1, stolen >= TRAMP_JMP_SZ ? 1 : 0, "tramp_make returned >= JMP_SZ");
    CHECK_EQ(stolen, copied, "stolen == copied_bytes");

    /* The first instruction's RIP-relative disp should have been patched:
     * original disp was 0x100 (referencing page+7+0x100 = page+0x107).
     * In the bounce, the same instruction is at bounce+0, so to reference
     * page+0x107, the new disp must be page+0x107 - (bounce+7) =
     * 0x100 + (page - bounce). */
    int32_t orig_disp = 0x100;
    int32_t new_disp;
    memcpy(&new_disp, bounce + 3, 4);

    intptr_t expected_delta = (intptr_t)page - (intptr_t)bounce;
    int32_t expected_disp = (int32_t)(orig_disp + expected_delta);
    CHECK_EQ(expected_disp, new_disp, "RIP-relative disp fixed up");

    /* The last 14 bytes of the bounce should be the JMP abs back to
     * (uint8_t*)page + stolen. Verify opcode is FF 25. */
    CHECK_EQ(0xFF, bounce[stolen + 0], "bounce tail is JMP abs opcode 0xFF");
    CHECK_EQ(0x25, bounce[stolen + 1], "bounce tail is JMP abs ModRM 0x25");

    void *jmp_dst;
    memcpy(&jmp_dst, bounce + stolen + 6, 8);
    CHECK_EQ((uintptr_t)((uint8_t*)page + stolen), (uintptr_t)jmp_dst,
             "bounce tail JMP returns to target+stolen");

    munmap(page, getpagesize());
#else
    printf("  SKIP: not x86-64\n");
#endif
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(void) {
    printf("=== syringe_hook unit tests ===\n");

    test_page_floor();
    test_page_is_ro();
    test_registry_helpers();
    test_remove_empty();
    test_is_installed();
    test_install_nonexistent();
    test_install_remove_cycle();
    test_duplicate_install();
    test_build_jmp();
    test_tramp_install_invalid();
    test_tramp_install_writable();

    /* v0.5 additions */
    test_disasm_x86_64();
    test_read_dst();
    test_install_addr();
    test_tramp_make_rip_relative();

    printf("\n=== results ===\n");
    printf("  run:   %d\n", tests_run);
    printf("  pass:  %d\n", tests_pass);
    printf("  fail:  %d\n", tests_fail);

    return tests_fail > 0 ? 1 : 0;
}
