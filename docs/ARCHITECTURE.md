# Architecture

## Overview

Syringe is a cross-process injection and hooking toolkit for Linux, composed of two independent surfaces:

| Surface | Component | Language | Purpose |
|---------|-----------|----------|---------|
| **Injector** | `libsyringe.so` + `syringe-cli` | C (Meson) | Inject `.so` into a target process via ptrace or .NET AttachProfiler IPC |
| **Hooker** | `syringe/hook/syringe_hook.h` | Header-only C | Install inline/GOT hooks in the target process's address space |

These two surfaces are **decoupled**: the injector has no knowledge of the hooker, and the hooker has no runtime dependency on `libsyringe`. The only bridge is `dlopen` — the injector loads the `.so`, the `.so`'s constructor includes the header-only hooker and installs hooks.

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
│                          │                                 │  │  Patch GOT of      │  │
│                          │                                 │  │  target process    │  │
│                          │                                 │  └────────────────────┘  │
│                          │                                 │   ↑                      │
│                          │                                 │   │ header-only          │
│                          │                                 │   │ (no .so to link)     │
└──────────────────────────┘                                 └──────────────────────────┘
```

## Ptrace injection flow

The standard injection path uses `ptrace(2)` to:

1. **Attach** to the target process
2. **Find** `dlopen()` in the target's address space
3. **Write** a shellcode stub that calls `dlopen(path, RTLD_NOW|RTLD_GLOBAL)`
4. **Redirect** RIP to the shellcode, let it execute, then restore original state
5. The injected `.so`'s `__attribute__((constructor))` fires, installing hooks

```
Injector (ptrace + shellcode)        Target process memory
─────────────────────────            ───────────────────────
                                    ┌────────────────────┐
   syringe_inject()                 │  Target process    │
     ├─ ptrace_attach(pid) ────────►│                    │
     ├─ read /proc/pid/maps         │  ...               │
     ├─ find dlopen() addr          │  ...               │
     ├─ write shellcode at addr     │  [shellcode]       │
     ├─ save registers              │   dlopen(path,     │
     ├─ JMP RIP → shellcode         │    RTLD_NOW)       │
     ├─ PTRACE_CONT (run)           │   ↓                │
     ├─ wait(dlopen returns)        │   .so loaded       │
     ├─ restore registers           │   __constructor    │
     └─ ptrace_detach               │   ↓                │
                                    │   syringe_hook_*   │
                                    └────────────────────┘
```

## .NET CoreCLR injection flow (AttachProfiler)

For .NET processes with anti-debug protections, syringe auto-detects the .NET diagnostic socket and uses AttachProfiler IPC instead of ptrace. This bypasses `prctl(PR_SET_DUMPABLE)`, seccomp filters, and the need for `CAP_SYS_PTRACE`.

| Aspect | Ptrace | AttachProfiler |
|--------|--------|----------------|
| Requires `CAP_SYS_PTRACE` | Yes | No |
| Bypasses `PR_SET_DUMPABLE` | No | Yes |
| Bypasses seccomp | No | Yes |
| Socket discovery | N/A | `/tmp/dotnet-diagnostic-{pid}-{key}-socket` |
| IPC format | Shellcode (x86-64) | Binary IPC v1 (UTF-16 paths, 20-byte header) |
| Profiler `.so` | Not needed | `libsyringe-dotnet-profiler.so` (COM `ICorProfilerCallback3`) |

```
Injector (AttachProfiler IPC)       .NET process (CoreCLR)
───────────────────────────         ──────────────────────
                                   ┌────────────────────┐
   syringe_inject_dotnet(pid)      │  .NET runtime      │
     ├─ find socket path           │  ┌──────────────┐  │
     ├─ connect AF_UNIX            │  │ profiler .so │  │
     ├─ send Binary IPC v1         │  │ (Attach      │  │
     ├─ runtime loads              │  │  Profiler)   │  │
     │   libsyringe-dotnet-        │  └──────┬───────┘  │
     │   profiler.so               │         │          │
     ├─ profiler dlopen(target) ──►│  __constructor     │
     │   (requested .so)           │   ↓                │
     │                             │  dlopen(...)       │
     │                             │   (target .so)     │
     │                             └─────────┬──────────┘
     │                                       ↓
     │                               Target app hooks
```

## Hooker architecture

`syringe_hook.h` is a header-only library that provides inline and GOT/PLT hooking capabilities. It is included directly in the source of an injectable `.so`, with no runtime dependency on `libsyringe`.

### Design decisions

1. **Simpler consumer experience** — 1 file to copy/include, no link flags, no pkg-config needed
2. **Self-contained injectable `.so`** — `libhook.so` has 0 runtime dependencies beyond libc/libdl/libpthread
3. **Per-`.so` registry isolation** — each `.so` that includes the header gets its own private `static` registry, so hooks from different `.so`'s don't conflict
4. **No ABI risk** — every `.so` compiles the hooker source with its own compiler/version, no chance of struct layout mismatch

### Single-TU constraint

Because the registry is `static` (per-translation-unit), `syringe/hook/syringe_hook.h` must be included from **exactly one** `.c` file per `.so` / executable. The standard pattern (1 `.c` file with constructor + destructor) works perfectly. If you need hook logic across multiple `.c` files, keep all `syringe_hook_install` / `syringe_hook_remove` calls in ONE file and call them from that file's constructor; other files in the same `.so` should not include `syringe/hook/syringe_hook.h`.

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
