/*
 * test_syringe.c — unit tests for syringe (cross-process injector)
 *
 * Tests:
 *   - validate_pid() — valid / invalid PID
 *   - syringe_build_shellcode() — size, NOP entry, path string placement
 *   - syringe_build_shellcode() — int3 (SIGTRAP) present in shellcode
 *   - syringe_build_shellcode() — path string embedded correctly
 *   - syringe_build_shellcode() — mov rsi, RTLD_NOW_GLOBAL
 *   - syringe_build_shellcode() — call rax
 *   - syringe_build_shellcode() — ret at end
 *   - syringe_build_shellcode() — buffer overflow protection
 *   - syringe_build_shellcode() — various dlopen addresses
 *
 * NOTE: syringe_build_shellcode is intentionally NOT declared in syringe.h
 * (it's an internal helper). Tests reach it via extern declaration below.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <stdarg.h>
#include <sys/ptrace.h>

#include "syringe.h"

/* Internal helper — not in public header, declared here for testing only */
extern size_t syringe_build_shellcode(unsigned char *buf, size_t bufsz,
                                       unsigned long dlopen_addr,
                                       const char *so_path,
                                       unsigned long inject_addr);

/* ── assertion helpers ─────────────────────────────────────────────────── */

static int tests_run = 0;
static int tests_pass = 0;
static int tests_fail = 0;

static void check(int cond, const char *msg) {
    tests_run++;
    if (cond) {
        tests_pass++;
        printf("  PASS: %s\n", msg);
    } else {
        tests_fail++;
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, msg);
    }
}

/* ── Shellcode building (link against libinjector.so) ──────────────────── */

#define RTLD_NOW_GLOBAL  0x102

static void check_fmt(int cond, const char *fmt, ...) {
    char msg[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    check(cond, msg);
}

/* ── tests: argument validation ────────────────────────────────────────── */

static int validate_pid(const char *pid_str) {
    long pid = strtol(pid_str, NULL, 10);
    return pid > 0 && pid < 4194304;
}

static void test_validate_pid(void) {
    printf("\n[validate_pid]\n");

    check(validate_pid("1"), "PID 1 (init) is valid");
    check(validate_pid("12345"), "PID 12345 is valid");
    check(!validate_pid("0"), "PID 0 is invalid");
    check(!validate_pid("-1"), "PID -1 is invalid");
    check(!validate_pid("abc"), "PID 'abc' is invalid");
}

/* ── tests: build_shellcode size ───────────────────────────────────────── */

static void test_shellcode_size(void) {
    printf("\n[shellcode size]\n");

    unsigned char buf[512];
    memset(buf, 0, sizeof(buf));

    size_t sz = syringe_build_shellcode(buf, sizeof(buf), 0x7F0000001000UL,
                                       "/tmp/test.so", 0);
    check(sz > 0, "syringe_build_shellcode returns valid size");
    check(sz < sizeof(buf), "shellcode fits in 512 bytes");
    printf("  shellcode size: %zu bytes\n", sz);
}

/* ── tests: shellcode starts with NOPs ─────────────────────────────────── */

static void test_shellcode_entry_nops(void) {
    printf("\n[shellcode entry NOPs]\n");

    unsigned char buf[512];
    memset(buf, 0, sizeof(buf));

    size_t sz = syringe_build_shellcode(buf, sizeof(buf), 0x7F0000001000UL,
                                       "/tmp/test.so", 0);
    if (sz == 0) { printf("  SKIP: build failed\n"); return; }

    check(buf[0] == 0x90, "first byte is NOP");
    check(buf[1] == 0x90, "second byte is NOP");
}

/* ── tests: shellcode contains int3 (SIGTRAP) ──────────────────────────── */

static void test_shellcode_contains_int3(void) {
    printf("\n[shellcode contains SIGTRAP]\n");

    unsigned char buf[512];
    memset(buf, 0, sizeof(buf));

    size_t sz = syringe_build_shellcode(buf, sizeof(buf), 0x7F0000001000UL,
                                       "/tmp/test.so", 0);
    if (sz == 0) { printf("  SKIP: build failed\n"); return; }

    int found = 0;
    for (size_t i = 0; i < sz; i++) {
        if (buf[i] == 0xCC) { found = 1; break; }
    }
    check(found, "shellcode contains INT3 (SIGTRAP)");
}

/* ── tests: shellcode embeds .so path ──────────────────────────────────── */

static void test_shellcode_embeds_path(void) {
    printf("\n[shellcode embeds .so path]\n");

    unsigned char buf[512];
    memset(buf, 0, sizeof(buf));

    const char *test_path = "/usr/local/lib/mylib.so";
    size_t sz = syringe_build_shellcode(buf, sizeof(buf), 0x7F0000001000UL,
                                       test_path, 0);
    if (sz == 0) { printf("  SKIP: build failed\n"); return; }

    int found = 0;
    for (size_t i = 0; i + strlen(test_path) < sz; i++) {
        if (memcmp(buf + i, test_path, strlen(test_path) + 1) == 0) {
            found = 1; break;
        }
    }
    check(found, ".so path embedded in shellcode");
}

/* ── tests: shellcode contains mov rsi, RTLD_NOW_GLOBAL ────────────────── */

static void test_shellcode_mov_rsi(void) {
    printf("\n[shellcode mov rsi]\n");

    unsigned char buf[512];
    memset(buf, 0, sizeof(buf));

    size_t sz = syringe_build_shellcode(buf, sizeof(buf), 0x7F0000001000UL,
                                       "/tmp/test.so", 0);
    if (sz == 0) { printf("  SKIP: build failed\n"); return; }

    int found = 0;
    for (size_t i = 0; i + 9 <= sz; i++) {
        if (buf[i] == 0x48 && buf[i + 1] == 0xBE) {
            uint64_t imm;
            memcpy(&imm, buf + i + 2, 8);
            if (imm == RTLD_NOW_GLOBAL) { found = 1; break; }
        }
    }
    check(found, "shellcode contains 'mov rsi, RTLD_NOW_GLOBAL'");
}

/* ── tests: shellcode contains call rax ─────────────────────────────────── */

static void test_shellcode_call_rax(void) {
    printf("\n[shellcode call rax]\n");

    unsigned char buf[512];
    memset(buf, 0, sizeof(buf));

    size_t sz = syringe_build_shellcode(buf, sizeof(buf), 0x7F0000001000UL,
                                       "/tmp/test.so", 0);
    if (sz == 0) { printf("  SKIP: build failed\n"); return; }

    int found = 0;
    for (size_t i = 0; i + 1 < sz; i++) {
        if (buf[i] == 0xFF && buf[i + 1] == 0xD0) { found = 1; break; }
    }
    check(found, "shellcode contains 'call rax'");
}

/* ── tests: shellcode ends with ret ────────────────────────────────────── */

static void test_shellcode_ends_with_ret(void) {
    printf("\n[shellcode ends with ret]\n");

    unsigned char buf[512];
    memset(buf, 0, sizeof(buf));

    const char *test_path = "/tmp/test.so";
    size_t sz = syringe_build_shellcode(buf, sizeof(buf), 0x7F0000001000UL,
                                       test_path, 0);
    if (sz == 0) { printf("  SKIP: build failed\n"); return; }

    size_t path_len = strlen(test_path) + 1;
    size_t ret_pos = sz - path_len - 1;
    check(buf[ret_pos] == 0xC3, "shellcode ends with RET");
}

/* ── tests: shellcode buffer overflow protection ───────────────────────── */

static void test_shellcode_buffer_overflow(void) {
    printf("\n[shellcode buffer overflow]\n");

    unsigned char buf[16];
    memset(buf, 0, sizeof(buf));

    size_t sz = syringe_build_shellcode(buf, sizeof(buf), 0x7F0000001000UL,
                                       "/tmp/test.so", 0);
    check(sz == 0, "overflow detected (build returns 0)");
}

/* ── tests: shellcode with different dlopen addresses ──────────────────── */

static void test_shellcode_various_dlopen_addrs(void) {
    printf("\n[shellcode various dlopen addresses]\n");

    unsigned char buf[512];

    unsigned long addrs[] = {
        0x7F0000001000UL,
        0x00007F0000001000UL,
        0xFFFFFFFFFFFFFFFFUL,
        0x0000000000000000UL,
    };

    for (int i = 0; i < 4; i++) {
        memset(buf, 0, sizeof(buf));
        size_t sz = syringe_build_shellcode(buf, sizeof(buf), addrs[i],
                                           "/tmp/test.so", 0);
        check_fmt(sz > 0, "shellcode builds for dlopen_addr 0x%lx", addrs[i]);
    }
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(void) {
    printf("=== syringe unit tests ===\n");

    test_validate_pid();
    test_shellcode_size();
    test_shellcode_entry_nops();
    test_shellcode_contains_int3();
    test_shellcode_embeds_path();
    test_shellcode_mov_rsi();
    test_shellcode_call_rax();
    test_shellcode_ends_with_ret();
    test_shellcode_buffer_overflow();
    test_shellcode_various_dlopen_addrs();

    printf("\n=== results ===\n");
    printf("  run:   %d\n", tests_run);
    printf("  pass:  %d\n", tests_pass);
    printf("  fail:  %d\n", tests_fail);

    return tests_fail > 0 ? 1 : 0;
}
