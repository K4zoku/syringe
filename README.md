# syringe

**S**YRINGE **Y**ields **R**untime **I**njected **N**ative **G**lobal **E**xecutables

A two-part toolkit for x86-64 Linux:

- **`libsyringe.so`** — ptrace-based shared-library injector (cross-process). Build with meson, link with `-lsyringe`.
- **`syringe/hook/syringe_hook.h`** — header-only GOT/PLT + inline trampoline hooker (in-process). Just `#include` it; nothing to link.

The two halves are independent. Typical workflow: use `libsyringe` to inject a `.so` into a target process; that `.so` then `#include <syringe/hook/syringe_hook.h>` and calls `syringe_hook_install()` in its constructor to patch the target's GOT.

## Build

```bash
meson setup build
meson compile -C build
```

## Tests

```bash
meson test -C build -v
```

Two test suites:
- `test_syringe` — links `libsyringe.so`, tests `syringe_inject` + internal `syringe_build_shellcode`
- `test_hook` — header-only, `#include <syringe/hook/syringe_hook.h>`, tests `syringe_hook_*`

## Install (system-wide)

```bash
sudo meson install -C build
sudo ldconfig
```

Installs:

| Path | Purpose |
|------|---------|
| `/usr/local/lib/x86_64-linux-gnu/libsyringe.so.0.4` | Cross-process injector |
| `/usr/local/include/syringe/syringe.h` | Header for `libsyringe` — only `syringe_inject` |
| `/usr/local/include/syringe/hook/syringe_hook.h` | Header-only hooker — `#include` from 1 `.c` file, nothing to link |
| `/usr/local/bin/syringe-cli` | CLI tool |
| `/usr/local/lib/x86_64-linux-gnu/pkgconfig/libsyringe.pc` | pkg-config for injection |

> **Note:** There is no `libsyringe_hook.so` to install — the hooker is header-only.

## Usage

### Pattern 1: Inject a `.so` into a running process (CLI)

```bash
syringe-cli <pid> <library.so>

# example
syringe-cli 10024 ./libhook.so
```

### Pattern 2: Inject from your own C code

```c
#define _GNU_SOURCE
#include "syringe.h"
#include <stdio.h>

int main(void) {
    int rc = syringe_inject(1234, "/path/to/lib.so");
    return rc == 0 ? 0 : 1;
}
```

```bash
gcc -D_GNU_SOURCE injector.c -o injector $(pkg-config --cflags --libs libsyringe)
```

### Pattern 3: Write a `.so` to be injected (header-only hooker)

```c
/* libhook.c — the ONLY .c file in libhook.so */
#define _GNU_SOURCE
#include <syringe/hook/syringe_hook.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>

static int (*orig_open)(const char *, int, ...);

static int my_open(const char *path, int flags, ...) {
    fprintf(stderr, "[hook] open(\"%s\", %d)\n", path, flags);
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    return orig_open(path, flags, mode);
}

__attribute__((constructor))
static void on_load(void) {
    syringe_hook_install("open", (void *)my_open, (void **)&orig_open);
}

__attribute__((destructor))
static void on_unload(void) {
    syringe_hook_remove_all();
}
```

Build — **just include the header, no link to libsyringe_hook**:

```bash
# Option A: system install (recommended)
sudo ninja -C build install    # one-time
gcc -shared -fPIC -O2 -o libhook.so libhook.c \
    -I/usr/local/include -ldl -lpthread

# Option B: vendored (copy header into your project tree)
cp /path/to/syringe/include/hook/syringe_hook.h my_project/vendor/
gcc -shared -fPIC -O2 -o libhook.so libhook.c \
    -Imy_project/vendor -ldl -lpthread

# Option C: meson subproject
gcc -shared -fPIC -O2 -o libhook.so libhook.c \
    -Isubprojects/syringe/include -ldl -lpthread
```

All three options produce identical binaries — the header is `static inline` so the compiler generates the same code regardless of where the header lives. Pick whichever fits your project's dependency style.

Then inject:

```bash
syringe-cli <pid> ./libhook.so
```

> ⚠️ **Single-TU rule:** Because `syringe/hook/syringe_hook.h` uses `static` registry, you MUST include it from **exactly one** `.c` file per `.so` / executable. The standard pattern above (1 `.c` file with constructor) is correct. Do not include `syringe/hook/syringe_hook.h` from multiple `.c` files in the same `.so` — each will get its own private registry and hooks won't be visible across files.

### Pattern 4: App hooking itself (also header-only)

```c
#define _GNU_SOURCE
#include <syringe/hook/syringe_hook.h>
#include <stdio.h>
#include <fcntl.h>

static int (*orig_open)(const char *, int, ...);
static int my_open(const char *p, int f, ...) {
    fprintf(stderr, "[app] opening %s\n", p);
    return orig_open(p, f, 0);
}

int main(void) {
    syringe_hook_install("open", (void *)my_open, (void **)&orig_open);
    /* every open() after this goes through my_open */
    int fd = orig_open("/etc/hostname", O_RDONLY);
    syringe_hook_remove_all();
    return 0;
}
```

```bash
gcc -D_GNU_SOURCE app.c -o app -I/usr/local/include -ldl -lpthread
```

(No `-lsyringe` needed — only the header.)

## Usage in another meson project

### Option 1: System install + pkg-config (for `libsyringe` only)

```meson
syringe_dep = dependency('libsyringe', required: true)
executable('my_injector', 'main.c', dependencies: [syringe_dep])
```

For `syringe/hook/syringe_hook.h`, just add the include path manually:

```meson
executable('my_hook_so', 'hook.c',
  include_directories: include_directories('/usr/local/include/syringe'),
  c_args: ['-D_GNU_SOURCE'],
  link_args: ['-ldl', '-lpthread'],
)
```

### Option 2: Subproject

Copy this project into `subprojects/syringe/`, then:

```meson
syringe_proj = subproject('syringe')
syringe_dep  = syringe_proj.get_variable('libsyringe_dep')

# Injector that calls syringe_inject:
executable('my_injector', 'main.c', dependencies: [syringe_dep])

# .so to be injected (header-only hooker, no link):
executable('my_hook_so', 'hook.c',
  include_directories: 'subprojects/syringe/include',
  c_args: ['-D_GNU_SOURCE', '-fPIC', '-shared'],
)
```

## API

### `libsyringe` — injection surface (syringe.h)

| Function | Description |
|----------|-------------|
| `syringe_inject(pid, so_path)` | Inject `.so` into process via ptrace + dlopen. Returns 0 on success, -1 on failure. |

> `syringe_build_shellcode` exists as an internal helper in `libsyringe.so` but is **NOT declared in `syringe.h`**. Most callers should use `syringe_inject()`. If you genuinely need to drive ptrace yourself, you can `extern`-declare it (see `tests/src/test_syringe.c`).

### `syringe/hook/syringe_hook.h` — hooking surface (header-only)

| Function | Description | Conditional |
|----------|-------------|-------------|
| `syringe_hook_install(sym, hook, &orig)` | Hook `sym` via GOT/PLT patch + inline trampoline fallback. Returns patch count, 0 on failure. | Always available |
| `syringe_hook_install_addr(sym, target, hook, &orig)` | **v0.5** — Inline-hook an explicit address (bypass GOT/dlsym). Use when symbol is loaded via `dlopen` and not in PLT. | Stripped by `SYRINGE_HOOK_NO_HELPERS` |
| `syringe_hook_read_dst(src)` | **v0.5** — Read the destination address of an installed `FF 25` JMP at `src`. Returns NULL if not hooked. | Stripped by `SYRINGE_HOOK_NO_HELPERS` |
| `syringe_hook_remove(sym)` | Remove a specific hook by symbol name. | Stripped by `SYRINGE_HOOK_NO_HELPERS` |
| `syringe_hook_remove_all()` | Remove all installed hooks. | Stripped by `SYRINGE_HOOK_NO_HELPERS` |
| `syringe_hook_count()` | Get number of currently installed hooks. | Stripped by `SYRINGE_HOOK_NO_HELPERS` |
| `syringe_hook_is_installed(sym)` | Check if `sym` is currently hooked. | Stripped by `SYRINGE_HOOK_NO_HELPERS` |
| `syringe_hook_registry_size()` | Get registry capacity (default 32). | Stripped by `SYRINGE_HOOK_NO_HELPERS` |
| `syringe_hook_memfd_open()` / `syringe_hook_mem_write()` / `syringe_hook_mem_read()` | Memory helpers (`/proc/self/mem` fallback). | Always available |
| `syringe_hook_safe_write*()` / `syringe_hook_safe_write_code()` / `syringe_hook_tramp_*()` | Internal helpers. | Always available |

> **Note:** `syringe_hook_*` operates on the **calling** process, not a remote process. To hook a target process, inject a `.so` whose `__attribute__((constructor))` calls `syringe_hook_install()`.

### v0.5 inline hooking — what changed

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
  `syringe_hook_read_dst(src)` for detecting existing hooks.
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

**⚠️ Warning:** Without `syringe_hook_remove_all()`, you cannot clean up hooks in a destructor. Trampoline bounce stubs (mmap-allocated) will leak on `.so` unload. Only use this for `.so`'s that stay loaded for the lifetime of the target process, or when binary size is critical (e.g. embedded injection).

Build size comparison (real, on x86-64 with `-O2`, libhook.so with 1 hook):

| Build | `libhook.so` size | Savings |
|-------|---------------------|---------|
| Default (all helpers) | ~20 KB | — |
| `SYRINGE_HOOK_NO_HELPERS` | ~16 KB | ~21% |
| `SYRINGE_HOOK_NO_HELPERS` + `SYRINGE_HOOK_NO_LOG` | ~15 KB | ~25% |

### `SYRINGE_HOOK_NO_LOG` — silence log output

Replaces all `SYRINGE_HOOK_LOG()` calls with no-ops. Use in production where stderr noise is undesirable.

```c
#define SYRINGE_HOOK_NO_LOG
#include <syringe/hook/syringe_hook.h>
```

### Combined example

```c
/* libhook.c — minimal injectable .so, no helpers, no logs, 16-hook capacity */
#define _GNU_SOURCE
#define SYRINGE_HOOK_MAX 16
#define SYRINGE_HOOK_NO_HELPERS
#define SYRINGE_HOOK_NO_LOG
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

## CLI

```bash
syringe-cli <pid> <library.so>

# example
syringe-cli 10024 ./libhook.so
```

## Platform support

| Platform | Injector (`libsyringe.so`) | Hooker (`syringe/hook/syringe_hook.h`) | Notes |
|----------|----------------------------|---------------------------|-------|
| **Linux x86_64** | ✅ Full | ✅ Full | Primary target. 76 unit tests + 19 e2e tests. |
| **Linux aarch64** | ✅ Full (v0.6) | ✅ Full (v0.6) | PAC strip via `xpac`, BTI `bti c` prologue detection. Cross-compile via `cross/aarch64-linux-gnu.ini`. |
| **Linux arm32** | ⚠️ Stub only | ❌ No inline (GOT-only) | Injector returns 0 from `build_shellcode`. Hooker falls back to GOT/PLT patching. |
| **Linux riscv64** | ⚠️ Stub only | ❌ No inline (GOT-only) | Same as arm32. |
| **Windows** | ❌ | ❌ | Out of scope (use Detours or MinHook). |
| **macOS** | ❌ | ❌ | Out of scope (Mach-O injection is very different). |

### aarch64 (ARM64) specifics

The aarch64 backend handles these ARM security features:

- **PAC (Pointer Authentication)**: function pointers may have PAC signature
  in the upper bits. We strip them via `xpac x16` before patching. On
  non-PAC hardware (older ARMv8.0), `xpac` is a no-op.
- **BTI (Branch Target Identification)**: if the prologue starts with
  `bti c` or `bti j`, the trampoline bounce stub includes the same BTI
  instruction so it remains a valid branch target.
- **MTE (Memory Tagging)**: the bounce stub is `mmap`'d with
  `MAP_ANONYMOUS`, which yields untagged memory. The bounce only
  executes code, never dereferences tagged pointers, so MTE is safe.

The aarch64 inline hook uses a 16-byte `LDR x16,[pc,#8] + BR x16 + .quad addr`
encoding (instead of x86-64's 14-byte `FF 25` abs JMP). This is fixed-size
regardless of hook-target distance — `B rel26` (4-byte branch) would only
work within ±128 MB and we can't guarantee that.

### Cross-compiling for aarch64

```bash
# Prerequisites (Ubuntu/Debian):
sudo apt install gcc-aarch64-linux-gnu qemu-user qemu-user-static

# Build:
meson setup build-aarch64 --cross-file cross/aarch64-linux-gnu.ini
ninja -C build-aarch64

# Run tests under QEMU user-mode:
qemu-aarch64 -L /usr/aarch64-linux-gnu ./build-aarch64/test_hook
qemu-aarch64 -L /usr/aarch64-linux-gnu ./build-aarch64/test_inline
```

## Architecture

```
┌──────────────────────────┐         ptrace + dlopen         ┌──────────────────────────┐
│  Injector process        │  ─────────────────────────────► │  Target process          │
│                          │                                 │                          │
│  ┌────────────────────┐  │                                 │  ┌────────────────────┐  │
│  │ libsyringe.so      │  │                                 │  │ libhook.so         │  │
│  │  syringe_inject()  │  │                                 │  │  #include          │  │
│  └────────────────────┘  │                                 │  │   "syringe_hook.h" │  │
│                          │                                 │  │  __constructor__   │  │
│  syringe-cli             │                                 │  │   ↓                │  │
│   (links libsyringe only)│                                 │  │  syringe_hook_     │  │
│                          │                                 │  │   install()        │  │
│                          │                                 │  │   ↓                │  │
│                          │                                 │  │  Patch GOT của     │  │
│                          │                                 │  │  target process    │  │
│                          │                                 │  └────────────────────┘  │
│                          │                                 │   ↑                      │
│                          │                                 │   │ header-only          │
│                          │                                 │   │ (no .so to link)     │
└──────────────────────────┘                                 └──────────────────────────┘
```

### Why is `syringe_hook` header-only?

1. **Simpler consumer experience** — 1 file to copy/include, no link flags, no pkg-config needed
2. **Self-contained injectable `.so`** — `libhook.so` has 0 runtime dependencies beyond libc/libdl/libpthread
3. **Per-`.so` registry isolation** — each `.so` that includes `syringe/hook/syringe_hook.h` gets its own private `static` registry, so hooks from different `.so`'s don't conflict
4. **No ABI risk** — every `.so` compiles the hooker source with its own compiler/version, no chance of struct layout mismatch

### Trade-off: single-TU per `.so`

Because the registry is `static` (per-translation-unit), `syringe/hook/syringe_hook.h` must be included from **exactly one** `.c` file per `.so` / executable. The standard pattern (1 `.c` file with constructor + destructor) works perfectly. If you need hook logic across multiple `.c` files, keep all `syringe_hook_install` / `syringe_hook_remove` calls in ONE file and call them from that file's constructor; other files in the same `.so` should not include `syringe/hook/syringe_hook.h`.
