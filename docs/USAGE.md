# Usage

## Pattern 1: Inject a `.so` into a running process (CLI)

```bash
syringe-cli <pid> <library.so>

# example
syringe-cli 10024 ./libhook.so
```

## Pattern 2: Inject from your own C code

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

## Pattern 3: Write a `.so` to be injected (header-only hooker)

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

All three options produce identical binaries — the header is `static inline` so the compiler generates the same code regardless of where the header lives.

Then inject:

```bash
syringe-cli <pid> ./libhook.so
```

> **Single-TU rule:** Because `syringe/hook/syringe_hook.h` uses `static` registry, you MUST include it from **exactly one** `.c` file per `.so` / executable. The standard pattern above (1 `.c` file with constructor) is correct. Do not include `syringe/hook/syringe_hook.h` from multiple `.c` files in the same `.so` — each will get its own private registry and hooks won't be visible across files.

## Pattern 4: App hooking itself (also header-only)

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

## CLI

```bash
syringe-cli <pid> <library.so>

# example
syringe-cli 10024 ./libhook.so
```
