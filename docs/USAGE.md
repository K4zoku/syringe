# Usage

## Injecting

### Via CLI

Inject a shared library into a running process:

```bash
syringe-cli <pid> <library.so>

# Example: inject libhook.so into PID 10024
syringe-cli 10024 ./libhook.so
```

### From C code

```c
#define _GNU_SOURCE
#include "syringe.h"

int main(void) {
    int rc = syringe_inject(1234, "/path/to/lib.so");
    return rc == 0 ? 0 : 1;
}
```

```bash
gcc -D_GNU_SOURCE injector.c -o injector $(pkg-config --cflags --libs libsyringe)
```

## Hooking

`syringe_hook.h` is **header-only** — no library to link. All functions are `static inline`.

### Writing an injectable `.so`

```c
/* libhook.c — include from exactly one .c file per .so */
#define _GNU_SOURCE
#include <syringe/hook/syringe_hook.h>
#include <stdio.h>
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

**Build** — only the header is needed, no link step:

```bash
# System install (run once):
sudo ninja -C build install

# Then build your .so:
gcc -shared -fPIC -O2 -o libhook.so libhook.c -I/usr/local/include -ldl -lpthread
```

After building, inject as normal:

```bash
syringe-cli <pid> ./libhook.so
```

> **Single-TU rule:** `syringe_hook.h` maintains a `static` registry. Include it from **exactly one** `.c` file per `.so`. Including it in multiple `.c` files gives each one a private registry, so hooks become invisible across files.

### Hooking from the app itself

You don't need a separate `.so` to hook your own process:

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
    int fd = orig_open("/etc/hostname", O_RDONLY);
    syringe_hook_remove_all();
    return 0;
}
```

```bash
gcc -D_GNU_SOURCE app.c -o app -I/usr/local/include -ldl -lpthread
```

No `-lsyringe` — the hooker is entirely header-only.

## Embedding in another Meson project

### System install + pkg-config

```meson
# libsyringe (for syringe_inject):
syringe_dep = dependency('libsyringe', required: true)
executable('my_injector', 'main.c', dependencies: [syringe_dep])

# Hooker (header-only):
executable('my_hook_so', 'hook.c',
  include_directories: include_directories('/usr/local/include/syringe'),
  c_args: ['-D_GNU_SOURCE'],
  link_args: ['-ldl', '-lpthread'],
)
```

### Subproject

Include syringe in another Meson project by placing the source tree under `subprojects/syringe/`. Two approaches:

#### Manual

Add the repository via Git submodules:

```bash
cd your_project
git submodule add https://github.com/kazoku/syringe.git subprojects/syringe
```

Or clone directly:

```bash
cd your_project/subprojects
git clone https://github.com/kazoku/syringe.git
```

#### Meson Wrap

Instead of copying files, let Meson fetch the repository automatically. Create `subprojects/syringe.wrap`:

```ini
[wrap-git]
url = https://github.com/kazoku/syringe.git
revision = main
```

Meson will detect and fetch the source on the first build.

#### Reference

Whichever method you choose, reference syringe in your `meson.build` the same way:

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
