# syringe

**S**YRINGE **Y**ields **R**untime **I**njected **N**ative **G**lobal **E**xecutables

A two-part toolkit for x86-64 Linux:

- **`libsyringe.so`** — ptrace-based shared-library injector (cross-process). Build with meson, link with `-lsyringe`.
- **`syringe/hook/syringe_hook.h`** — header-only GOT/PLT + inline trampoline hooker (in-process). Just `#include` it; nothing to link.

The two halves are independent. Typical workflow: use `libsyringe` to inject a `.so` into a target process; that `.so` then `#include <syringe/hook/syringe_hook.h>` and calls `syringe_hook_install()` in its constructor to patch the target's GOT.

## Quick start

```bash
meson setup build
meson compile -C build
sudo meson install -C build
sudo ldconfig
```

## Install (system-wide)

| Path | Purpose |
|------|---------|
| `${libdir}/libsyringe.so.0.7` | Cross-process injector |
| `${libdir}/syringe-dotnet-profiler.so` | .NET COM profiler for ptrace-free injection via AttachProfiler |
| `${includedir}/syringe/syringe.h` | Header for `libsyringe` — only `syringe_inject` |
| `${includedir}/syringe/hook/syringe_hook.h` | Header-only hooker — `#include` from 1 `.c` file, nothing to link |
| `${includedir}/syringe/hook/syringe_hook_common.h` | Internal helpers (included transitively by `syringe_hook.h`) |
| `${includedir}/syringe/hook/arch/syringe_hook_arch.h` | Arch dispatch header (included transitively) |
| `${includedir}/syringe/hook/arch/syringe_hook_x86_64.h` | x86-64 inline trampoline backend |
| `${includedir}/syringe/hook/arch/syringe_hook_aarch64.h` | aarch64 inline trampoline backend |
| `${includedir}/syringe/hook/syringe_hook_dotnet.h` | .NET diagnostic IPC helpers (header-only) |
| `${bindir}/syringe-cli` | CLI tool |
| `${libdir}/pkgconfig/libsyringe.pc` | pkg-config for injection |

> **Note:** There is no `libsyringe_hook.so` to install — the hooker is header-only.

`${libdir}` is typically `lib/x86_64-linux-gnu` on Debian/Ubuntu, `lib64` on Fedora/RHEL, or just `lib` on others — use `meson configure` to see the effective paths for your build.

## Documentation

| File | What's in it |
|------|-------------|
| [docs/USAGE.md](docs/USAGE.md) | All four usage patterns (CLI inject, C inject, write a `.so`, app self-hook) + meson subproject integration |
| [docs/API.md](docs/API.md) | `libsyringe` and `syringe_hook` API reference, configuration macros, v0.5 changelog |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System diagram, platform support matrix, aarch64 specifics, design rationale |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Build, test, cross-compile for aarch64, ptrace privileges |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | How to contribute, code style, commit conventions, PR workflow |
