/*
 * test_inline.c — end-to-end test cho v0.5 inline hook path
 *
 * Scenario:
 *   1. Build a real C function `target_add(a, b)` with -fcf-protection=full
 *      so its prologue has endbr64 (the CET prologue present on every
 *      Ubuntu 22.04+ binary).
 *   2. Install an inline hook via syringe_hook_install_addr() that
 *      replaces a+b with a*b.
 *   3. Verify:
 *      - target_add(3, 4) returns 12 (3*4)  — hook fired
 *      - orig_add(3, 4)  returns 7  (3+4)   — trampoline works
 *      - read_dst(target_add) returns hook_mul (already-hooked detect)
 *   4. Remove the hook, verify target_add returns to 3+4=7.
 *
 * This test exercises:
 *   - syringe_hook_disasm_x86_64 with real compiler-emitted prologue
 *     (endbr64 + push rbp + mov rbp,rsp + mov eax,edi + ...)
 *   - syringe_hook_tramp_make with possibly RIP-relative instructions
 *     in the prologue (compiler may emit them at -O2)
 *   - syringe_hook_tramp_install atomic patch
 *   - syringe_hook_install_addr public API
 *   - syringe_hook_read_dst helper
 *   - syringe_hook_remove restore
 *
 * Build:
 *   gcc -O2 -fcf-protection=full test_inline.c -o test_inline \
 *       -Iinclude -ldl -lpthread
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "syringe_hook.h"

/* ── target function ──────────────────────────────────────────────────────
 *
 * Built with -fcf-protection=full so the compiler emits endbr64 as the
 * first instruction. -O2 keeps the prologue small and predictable.
 *
 * NOINLINE ensures the function exists as a discrete symbol we can take
 * the address of, rather than being inlined into the caller.
 */

__attribute__((noinline, used))
int target_add(int a, int b) {
    /* Force a real prologue + epilogue even at -O2 by touching rbp. */
    volatile int sum = a + b;
    return sum;
}

/* ── hook function ──────────────────────────────────────────────────────── */

typedef int (*add_fn)(int, int);
static add_fn orig_add = NULL;

__attribute__((noinline, used))
static int hook_mul(int a, int b) {
    /* Return a*b instead of a+b. */
    volatile int prod = a * b;
    return prod;
}

/* ── tiny test framework ────────────────────────────────────────────────── */

static int tests_run   = 0;
static int tests_pass  = 0;
static int tests_fail  = 0;

#define ASSERT(cond, msg) do {                                  \
    tests_run++;                                                \
    if (cond) {                                                 \
        tests_pass++;                                           \
        printf("  PASS: %s\n", msg);                            \
    } else {                                                    \
        tests_fail++;                                           \
        printf("FAIL: %s:%d: %s\n", __FILE__, __LINE__, msg);   \
    }                                                           \
} while (0)

#define ASSERT_EQ(exp, act, msg) do {                           \
    tests_run++;                                                \
    int _e = (int)(exp); int _a = (int)(act);                   \
    if (_e == _a) {                                             \
        tests_pass++;                                           \
        printf("  PASS: %s == %d\n", msg, _a);                  \
    } else {                                                    \
        tests_fail++;                                           \
        printf("FAIL: %s:%d: %s — expected %d, got %d\n",       \
               __FILE__, __LINE__, msg, _e, _a);                \
    }                                                           \
} while (0)

/* ── tests ───────────────────────────────────────────────────────────────── */

static void test_basic_hook(void) {
    printf("\n[basic inline hook]\n");

    /* 1. Before hooking: target_add(3, 4) == 7 */
    int before = target_add(3, 4);
    ASSERT_EQ(7, before, "target_add(3,4) before hook");

    /* 2. Install hook via install_addr (bypasses GOT, goes straight
     *    to inline trampoline). */
    orig_add = NULL;
    int n = syringe_hook_install_addr("target_add",
                                       (void*)target_add,
                                       (void*)hook_mul,
                                       (void**)&orig_add);
    ASSERT_EQ(1, n, "install_addr returns 1");

    /* 3. After hook: target_add(3, 4) == 12 (3*4) */
    int after = target_add(3, 4);
    ASSERT_EQ(12, after, "target_add(3,4) after hook returns 3*4");

    /* 4. Trampoline should call the original → 7 */
    ASSERT(orig_add != NULL, "orig_add is non-NULL");
    int via_orig = orig_add(3, 4);
    ASSERT_EQ(7, via_orig, "orig_add(3,4) via trampoline returns 3+4");

    /* 5. read_dst should detect the hook we just installed */
    void *dst = syringe_hook_read_dst((void*)target_add);
    ASSERT(dst == (void*)hook_mul, "read_dst returns hook_mul address");

    /* 6. Verify it works with different arguments */
    ASSERT_EQ(20, target_add(4, 5), "target_add(4,5) = 4*5 = 20");
    ASSERT_EQ(9, orig_add(4, 5), "orig_add(4,5) = 4+5 = 9");

    /* 7. Remove hook */
    int removed = syringe_hook_remove("target_add");
    ASSERT(removed > 0, "remove returns >0");

    /* 8. After remove: target_add returns to original behaviour */
    int after_remove = target_add(3, 4);
    ASSERT_EQ(7, after_remove, "target_add(3,4) after remove returns 3+4");

    /* 9. read_dst should now return NULL */
    dst = syringe_hook_read_dst((void*)target_add);
    ASSERT(dst == NULL, "read_dst returns NULL after remove");
}

static void test_edge_cases(void) {
    printf("\n[edge cases]\n");

    /* Install + remove + reinstall the same hook */
    orig_add = NULL;
    int n1 = syringe_hook_install_addr("target_add", (void*)target_add,
                                        (void*)hook_mul, (void**)&orig_add);
    ASSERT_EQ(1, n1, "first install OK");

    /* Duplicate install must be rejected */
    add_fn orig2 = NULL;
    int n2 = syringe_hook_install_addr("target_add", (void*)target_add,
                                        (void*)hook_mul, (void**)&orig2);
    ASSERT_EQ(0, n2, "duplicate install returns 0");

    syringe_hook_remove("target_add");

    /* Reinstall after remove */
    orig_add = NULL;
    int n3 = syringe_hook_install_addr("target_add", (void*)target_add,
                                        (void*)hook_mul, (void**)&orig_add);
    ASSERT_EQ(1, n3, "reinstall after remove OK");
    ASSERT_EQ(12, target_add(3, 4), "reinstalled hook fires");

    syringe_hook_remove_all();
    ASSERT_EQ(7, target_add(3, 4), "after remove_all, original restored");
}

static void test_is_installed(void) {
    printf("\n[is_installed query]\n");

    ASSERT_EQ(0, syringe_hook_is_installed("target_add"),
              "not installed initially");

    orig_add = NULL;
    syringe_hook_install_addr("target_add", (void*)target_add,
                               (void*)hook_mul, (void**)&orig_add);
    ASSERT_EQ(1, syringe_hook_is_installed("target_add"),
              "installed after install_addr");

    syringe_hook_remove_all();
    ASSERT_EQ(0, syringe_hook_is_installed("target_add"),
              "not installed after remove_all");
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(void) {
    printf("=== syringe_hook inline hook end-to-end tests ===\n");
    printf("target_add @ %p\n", (void*)target_add);
    printf("hook_mul   @ %p\n", (void*)hook_mul);

    test_basic_hook();
    test_edge_cases();
    test_is_installed();

    printf("\n=== results ===\n");
    printf("  run:   %d\n", tests_run);
    printf("  pass:  %d\n", tests_pass);
    printf("  fail:  %d\n", tests_fail);

    return tests_fail > 0 ? 1 : 0;
}
