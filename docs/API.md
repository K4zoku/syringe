# API Reference

## `libsyringe` — injection surface (syringe.h)

| Function | Description |
|----------|-------------|
| `syringe_inject(pid, so_path)` | Inject `.so` into process via ptrace + dlopen. Returns 0 on success, -1 on failure. |

> `syringe_build_shellcode` exists as an internal helper in `libsyringe.so` but is **NOT declared in `syringe.h`**. Most callers should use `syringe_inject()`. If you genuinely need to drive ptrace yourself, you can `extern`-declare it (see `tests/src/test_syringe.c`).

## `syringe/hook/syringe_hook.h` — hooking surface (header-only)

| Function | Description | Conditional |
|----------|-------------|-------------|
| `syringe_hook_install(sym, hook, &orig)` | Hook `sym` via GOT/PLT patch + inline trampoline fallback. Returns patch count, 0 on failure. | Always available |
| `syringe_hook_install_addr(sym, target, hook, &orig)` | **v0.5** — Inline-hook an explicit address (bypass GOT/dlsym). Use when symbol is loaded via `dlopen` and not in PLT. | Always available |
| `syringe_hook_jmp_target(src)` | **v0.5** — Check if addr has a syringe-installed JMP; returns jump target or NULL if not. | Stripped by `SYRINGE_HOOK_NO_HELPERS` |
| `syringe_hook_remove(sym)` | Remove a specific hook by symbol name. | Stripped by `SYRINGE_HOOK_NO_HELPERS` |
| `syringe_hook_remove_all()` | Remove all installed hooks. | Stripped by `SYRINGE_HOOK_NO_HELPERS` |
| `syringe_hook_count()` | Get number of currently installed hooks. | Stripped by `SYRINGE_HOOK_NO_HELPERS` |
| `syringe_hook_is_installed(sym)` | Check if `sym` is currently hooked. | Stripped by `SYRINGE_HOOK_NO_HELPERS` |
| `syringe_hook_registry_size()` | Get registry capacity (default 32). | Stripped by `SYRINGE_HOOK_NO_HELPERS` |

> **Note:** `syringe_hook_*` operates on the **calling** process, not a remote process. To hook a target process, inject a `.so` whose `__attribute__((constructor))` calls `syringe_hook_install()`.

## Configuration macros for `syringe/hook/syringe_hook.h`

Define these macros BEFORE `#include <syringe/hook/syringe_hook.h>` to customize the hooker's behavior and footprint. They affect ONLY the translation unit that includes the header.

### `SYRINGE_HOOK_MAX` — registry capacity

Default: `32`. Override if you need more (or fewer) hooks installed simultaneously in one `.so`.

```c
#define SYRINGE_HOOK_MAX 64   /* support up to 64 hooks */
#include <syringe/hook/syringe_hook.h>
```

### `SYRINGE_HOOK_NO_HELPERS` — strip remove/query functions (debloat)

Removes `syringe_hook_remove`, `syringe_hook_remove_all`, `syringe_hook_count`, `syringe_hook_is_installed`, `syringe_hook_registry_size` from the binary. Use when you only call `syringe_hook_install()` in a constructor and never need cleanup or queries.

```c
#define SYRINGE_HOOK_NO_HELPERS
#include <syringe/hook/syringe_hook.h>

__attribute__((constructor))
static void on_load(void) {
    syringe_hook_install("open", (void *)my_open, (void **)&orig_open);
    /* no destructor cleanup — .so stays loaded for target's lifetime */
}
```

**Warning:** Without `syringe_hook_remove_all()`, you cannot clean up hooks in a destructor. Trampoline bounce stubs (mmap-allocated) will leak on `.so` unload. Only use this for `.so`'s that stay loaded for the lifetime of the target process, or when binary size is critical (e.g. embedded injection).

Build size comparison (real, on x86-64 with `-O2`, libhook.so with 1 hook):

| Build | `libhook.so` size | Savings |
|-------|---------------------|---------|
| Default (all helpers) | ~20 KB | — |
| `SYRINGE_HOOK_NO_HELPERS` | ~16 KB | ~21% |
| `SYRINGE_HOOK_NO_HELPERS` + `SYRINGE_HOOK_QUIET` | ~15 KB | ~25% |

### `SYRINGE_HOOK_DEBUG` — runtime log control (env var)

By default logging is silent. Set `SYRINGE_HOOK_DEBUG=1` to enable `[syringe_hook]` log output to stderr.

```bash
SYRINGE_HOOK_DEBUG=1 ./my_injectable.so
```

The first `SYRINGE_HOOK_LOG()` call reads the env var and sets a function pointer — zero overhead when not debugging.

### `SYRINGE_HOOK_QUIET` — compile-time log stripping

Defining this before `#include` strips all `SYRINGE_HOOK_LOG()` calls at compile time, eliminating the branch + function pointer call. Use when binary size is critical.

```c
#define SYRINGE_HOOK_QUIET
#include <syringe/hook/syringe_hook.h>
```

### Combined example

```c
/* libhook.c — minimal injectable .so, no helpers, no logs, 16-hook capacity */
#define _GNU_SOURCE
#define SYRINGE_HOOK_MAX 16
#define SYRINGE_HOOK_NO_HELPERS
#define SYRINGE_HOOK_QUIET
#include <syringe/hook/syringe_hook.h>

static int (*orig_open)(const char *, int, ...);
static int my_open(const char *p, int f, ...) { return orig_open(p, f, 0); }

__attribute__((constructor))
static void on_load(void) {
    syringe_hook_install("open", (void *)my_open, (void **)&orig_open);
    /* no destructor — leaks are acceptable for this use case */
}
```

```bash
gcc -shared -fPIC -O2 -o libhook.so libhook.c -I/usr/local/include -ldl -lpthread
```

## v0.5 inline hooking — what changed

The inline trampoline path (used as fallback when GOT/PLT patching is not
enough, e.g. when SDL calls `eglSwapBuffers` through a `dlsym`'d pointer)
was rewritten to fix four real-world bugs that previously made it silently
fail on every shared library:

1. **No length-disassembler** → 16-byte raw prologue copy could split an
   instruction, causing SIGILL on first `orig()` call. **Fixed** with a
   real x86-64 length-disassembler (`syringe_hook_disasm_x86_64`) that
   walks whole instructions until `>= TRAMP_JMP_SZ` bytes have been
   copied.

2. **No RIP-relative fixup** → prologue instructions like
   `lea rax,[rip+disp]` were copied verbatim to the bounce stub at a
   different VA, so the displacement pointed to a random address and
   `orig()` SIGSEGV'd. **Fixed**: every rel32 / RIP-relative displacement
   in the stolen prologue is patched by the (target - bounce) delta.

3. **`page_is_ro` gate** → the old code refused to patch any r-x page,
   which is every shared library on Linux. That made the inline path
   dead code for the osu-lazer / libEGL.so use case. **Fixed**:
   trampoline now always tries to patch, using `/proc/self/mem` first
   (atomic, no permission change) with `process_vm_writev` as second
   fallback and mprotect RW→RX as last resort.

4. **No `__builtin___clear_cache` on bounce** → silently broken on
   aarch64. **Fixed**: cache is flushed on both target patch site and
   bounce stub.

Additionally:

- The 14-byte target patch is now emitted as **two 8-byte atomic stores**
  instead of `memcpy`, shrinking the race window where another thread can
  fetch a half-patched prologue.
- `endbr64` (CET prologue on Ubuntu 22.04+), REX prefixes, multi-byte
  NOPs and a wider opcode table are now disassembled correctly.
- New public API: `syringe_hook_install_addr(sym, target, hook, &orig)`
  for hooking addresses directly (no GOT walk, no `dlsym`), and
  `syringe_hook_jmp_target(src)` for detecting existing hooks.
- `safe_write_code` is a new helper that preserves the EXECUTE bit on
  code pages (the old `safe_write` collapsed to PROT_READ, causing
  SIGSEGV on the next call to the hooked function).
- Prologue bytes are now read via `/proc/self/mem` (`pread`) instead of
  direct `memcpy`, avoiding segfault when the target lives in an
  unreadable page (vDSO, kernel trap gates).
- `process_vm_writev` syscall is used as an additional fallback for
  patching read-only code segments when both mprotect and `/proc/self/mem`
  fail (e.g. under seccomp).

These changes bring syringe's inline hook to feature parity with
[subhook](https://github.com/wyrover/subhook) while keeping syringe's
advantages: header-only, multi-layer write fallback, auto-registry, and
multi-arch ptrace injector.
