/*
 * libtest.so — minimal test library for syringe_inject verification
 *
 * Its constructor runs as soon as dlopen() loads it. Used by the test
 * suite to verify that injection actually delivers a .so into the
 * target process and triggers its constructor.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>

__attribute__((constructor))
static void libtest_init(void) {
    fprintf(stderr, "[libtest] library loaded into pid %d!\n", getpid());
}

__attribute__((destructor))
static void libtest_fini(void) {
    fprintf(stderr, "[libtest] library unloaded from pid %d\n", getpid());
}
