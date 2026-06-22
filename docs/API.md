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
| `syringe_hook_install_addr(sym, target, hook, &orig)` | Inline-hook an explicit address (bypass GOT/dlsym). Use when symbol is loaded via `dlopen` and not in PLT. | Always available |
| `syringe_hook_jmp_target(src)` | Check if addr has a syringe-installed JMP; returns jump target or NULL if not. | Stripped by `SYRINGE_HOOK_NO_HELPERS` |
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
