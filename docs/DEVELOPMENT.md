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

`ptrace(2)` is the Linux syscall that allows one process to inspect and modify another process's memory, registers, and execution state. `syringe-cli` relies on it to attach to a target process and inject shared libraries. Modern Linux distributions, however, apply two layers of restriction that commonly block this:

- **POSIX capabilities** — by default only `root` (or processes carrying `CAP_SYS_PTRACE`) may attach to an arbitrary PID.
- **Kernel Yama LSM** (`kernel.yama.ptrace_scope`) — a kernel-level policy that further limits who may call `ptrace`, independent of capabilities.

There are two orthogonal ways to work around these restrictions:

1. **`setcap`** — grants `CAP_SYS_PTRACE` to the binary itself. The change persists across reboots and is the recommended approach.
2. **`kernel.yama.ptrace_scope`** — a sysctl knob that can temporarily relax Yama's rules. This change is **ephemeral**: it is lost on reboot and weakens the system-wide ptrace safety net, so revert it when done.

### Setting CAP_SYS_PTRACE with Meson (persistent)

The cleanest way to grant ptrace capability is through the built-in Meson option. Enable it at configure time, then run `install` as root:

```bash
meson setup build -Dset-ptrace-cap=true
sudo meson install -C build
```

This invokes `scripts/setcap_ptrace.sh` post-install, which runs:

```bash
setcap cap_sys_ptrace+ep /usr/local/bin/syringe-cli   # or your --prefix path
```

You can also apply it manually to a pre-built binary:

```bash
sudo scripts/setcap_ptrace.sh /usr/local/bin syringe-cli
# or equivalently:
sudo setcap cap_sys_ptrace+ep /usr/local/bin/syringe-cli
```

### Kernel Yama LSM — temporary relaxation (lost on reboot)

Yama restricts `ptrace` even when `CAP_SYS_PTRACE` is set. Check your current setting:

```bash
sysctl kernel.yama.ptrace_scope
# or equivalently:
cat /proc/sys/kernel/yama/ptrace_scope
```

| Value | Behavior |
|-------|----------|
| `0`   | No restriction — any process can trace any other process (legacy behavior). |
| `1`   | **Default.** A process can only trace its children (via `fork`/`exec`) or processes it has explicitly attached to via `PTRACE_TRACEME`. |
| `2`   | Only `root` may use `ptrace`. |
| `3`   | Only `root` or processes sharing the same real UID may use `ptrace`. |

When `ptrace_scope ≥ 1`, `syringe-cli` will fail with `EPERM` because it targets arbitrary PIDs. To temporarily disable Yama:

```bash
sudo sysctl kernel.yama.ptrace_scope=0
# or equivalently:
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

> **Warning:** This weakens system-wide ptrace security. Revert afterward:
