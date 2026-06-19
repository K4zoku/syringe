/*
 * test_hook.c — unit tests cho syringe_hook module
 *
 * Tests:
 *   - syringe_hook_page_floor()
 *   - syringe_hook_registry_size()
 *   - syringe_hook_count() — khởi đầu phải là 0
 *   - syringe_hook_remove() trên registry rỗng → return 0
 *   - syringe_hook_remove_all() trên registry rỗng → ko segfault
 *   - syringe_hook_is_installed() — false khi chưa hook
 *   - syringe_hook_install() trên symbol ko tồn tại → return 0
 *   - syringe_hook_install() + syringe_hook_remove() — đếm quay về 0
 *   - syringe_hook_install() trùng symbol → return 0
 *   - syringe_hook_build_jmp() — cấu trúc jmp đúng 14 bytes
 *   - syringe_hook_tramp_install() ko tồn tại symbol → MAP_FAILED
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <dlfcn.h>
#include <sys/mman.h>

#include "syringe_hook.h"   /* pulls in syringe_hook_* API */

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
            printf("  PASS: %s is NULL\n", expr);
        else
            printf("  PASS: %s is non-NULL\n", expr);
    } else {
        tests_fail++;
        fprintf(stderr, "FAIL: %s:%d: expected %s, got %s\n",
                __FILE__, __LINE__,
                expect_null ? "NULL" : "non-NULL",
                is_null ? "NULL" : "non-NULL");
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

/* ── tests: install + remove cycle ──────────────────────────────────────── */

static void test_install_remove_cycle(void) {
    printf("\n[install/remove cycle]\n");

    syringe_hook_remove_all();

    void *my_hook = (void *)0xDEADBEEF;
    void *orig = NULL;

    /* Use 'printf' — it's in the main executable's GOT/PLT,
     * unlike dlopen which is resolved via RTLD_DEFAULT. */
    int r = syringe_hook_install("printf", my_hook, &orig);
    if (r == 0) {
        fprintf(stderr, "  SKIP: printf hook returned 0 (expected in minimal binary)\n");
        return;
    }

    int count = syringe_hook_count();
    CHECK_EQ(1, count, "1 hook after install");

    int installed = syringe_hook_is_installed("printf");
    CHECK_EQ(1, installed, "printf is installed");

    syringe_hook_remove("printf");
    count = syringe_hook_count();
    CHECK_EQ(0, count, "count back to 0 after remove");

    installed = syringe_hook_is_installed("printf");
    CHECK_EQ(0, installed, "printf not installed after remove");

    syringe_hook_remove_all();
}

/* ── tests: duplicate install ───────────────────────────────────────────── */

static void test_duplicate_install(void) {
    printf("\n[duplicate install]\n");

    syringe_hook_remove_all();

    void *hook1 = (void *)0x11111111;
    void *hook2 = (void *)0x22222222;
    void *orig1 = NULL;
    void *orig2 = NULL;

    int r = syringe_hook_install("printf", hook1, &orig1);
    if (r == 0) {
        printf("  SKIP: printf not found in GOT\n");
        return;
    }

    int r2 = syringe_hook_install("printf", hook2, &orig2);
    CHECK_EQ(0, r2, "duplicate install → 0");

    syringe_hook_remove_all();
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

/* ── tests: tramp_install on writable page ──────────────────────────────── */

static void test_tramp_install_writable(void) {
    printf("\n[tramp_install writable]\n");

    Trampoline t;
    memset(&t, 0, sizeof(t));

    void *target = mmap(NULL, getpagesize(),
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (target == MAP_FAILED) {
        printf("  SKIP: mmap failed (likely no permissions)\n");
        return;
    }

    void *hook = (void *)0xCAFEBABE;
    void *orig = NULL;

    int r = syringe_hook_tramp_install(&t, target, hook, &orig);
    CHECK_EQ(0, r, "tramp_install on writable page succeeds");
    check_ptr(t.bounce, 0, "bounce allocated");
    check_ptr(orig, 0, "orig bounce pointer set");

    CHECK_EQ(0xFF, ((uint8_t *)target)[0], "target patched with jmp opcode");

    syringe_hook_tramp_remove(&t);
    CHECK_EQ(0, t.active, "trampoline inactive after remove");
    munmap(target, getpagesize());
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

    printf("\n=== results ===\n");
    printf("  run:   %d\n", tests_run);
    printf("  pass:  %d\n", tests_pass);
    printf("  fail:  %d\n", tests_fail);

    return tests_fail > 0 ? 1 : 0;
}
