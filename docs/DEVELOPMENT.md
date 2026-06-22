# Development

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

## Cross-compiling for aarch64

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

## Ptrace privileges

Running the injector or e2e tests may require `CAP_SYS_PTRACE`. On some systems you can grant it to your binary:

```bash
sudo setcap cap_sys_ptrace=eip ./build/src/syringe-cli
```

Or use the script at `scripts/setcap_ptrace.sh`.
