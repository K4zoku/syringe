# syringe

A two-part toolkit for runtime hooking on Linux:

- **`libsyringe.so`** — `ptrace`-based shared-library injector (cross-process). Supports automatic `.NET CoreCLR` profiler bypass to evade `ptrace` anti-debug protections. Build with Meson, link with `-lsyringe`.
- **`syringe/hook/syringe_hook.h`** — Header-only in-process hooker. Uses **GOT/PLT patching** as the primary strategy, with **inline trampoline** fallback. Just `#include` it from a single `.c` file; no library to link.

The two halves are independent. The typical workflow: use `libsyringe` to inject a `.so` into a target process; that `.so` `#include`s `syringe_hook.h` and calls `syringe_hook_install()` in its constructor to patch the target's GOT/PLT entries.

## How hooking works

`syringe_hook` uses a multi-layered approach:

1. **GOT/PLT patching** (primary) — Walks all loaded modules via `dl_iterate_phdr()`, finds GOT/PLT slots for the target symbol, and patches them with the hook function. Uses the safest available write method: `/proc/self/mem` → `process_vm_writev` → `mprotect` fallback.

2. **Inline trampoline** (secondary) — Installs a trampoline at the resolved function address: disassembles the function prologue using a length disassembler, copies stolen instructions to an mmap'd bounce stub (fixing RIP/PC-relative displacements), and patches a jump at the original entry point.

Both strategies are architecture-aware, with full backends for **x86-64** and **aarch64** (including PAC stripping and BTI detection).

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
| `${libdir}/syringe-dotnet-profiler.so` | .NET COM profiler — ptrace-free injection via AttachProfiler |
| `${includedir}/syringe/syringe.h` | Public injector API — `syringe_inject`, `syringe_inject_with_retry`, `syringe_inject_dotnet` |
| `${includedir}/syringe/hook/syringe_hook.h` | Header-only hooker — `#include` from 1 `.c` file, nothing to link |
| `${includedir}/syringe/hook/syringe_hook_common.h` | Internal helpers (included transitively) |
| `${includedir}/syringe/hook/syringe_hook_types.h` | Type definitions — `Trampoline`, `SyringeHookRecord`, `WalkCtx` |
| `${includedir}/syringe/hook/arch/syringe_hook_x86_64.h` | x86-64 inline trampoline backend |
| `${includedir}/syringe/hook/arch/syringe_hook_aarch64.h` | aarch64 inline trampoline backend |
| `${includedir}/syringe/hook/arch/syringe_hook_arch.h` | Arch dispatch header |
| `${bindir}/syringe-cli` | CLI tool |
| `${libdir}/pkgconfig/libsyringe.pc` | pkg-config for injection |

> **Note:** There is no `libsyringe_hook.so` — the hooker is entirely header-only.

`${libdir}` is typically `lib/x86_64-linux-gnu` on Debian/Ubuntu, `lib64` on Fedora/RHEL, or `lib` on others — run `meson configure` to see the effective paths for your build.

## Used by

| Project | Usage |
|---------|-------|
| [idk-overlay](https://github.com/K4zoku/idk-overlay) | GLES/GLX/SDL/Wayland hook overlay for games — uses `libsyringe` for cross-process `.so` injection and `syringe_hook` for GOT/PLT hooking |

## Documentation

| File | What's in it |
|------|-------------|
| [docs/USAGE.md](docs/USAGE.md) | Injecting (CLI + C), hooking (injectable `.so` + self-hook), Meson integration (system install, subproject, wrap) |
| [docs/API.md](docs/API.md) | `libsyringe` and `syringe_hook` API reference, configuration macros |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System diagram, platform support matrix, aarch64 specifics, design rationale |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Build, test, cross-compile for aarch64, ptrace privileges |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | How to contribute, code style, commit conventions, PR workflow |
