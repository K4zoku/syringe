# Architecture

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

## Why is `syringe_hook` header-only?

1. **Simpler consumer experience** — 1 file to copy/include, no link flags, no pkg-config needed
2. **Self-contained injectable `.so`** — `libhook.so` has 0 runtime dependencies beyond libc/libdl/libpthread
3. **Per-`.so` registry isolation** — each `.so` that includes `syringe/hook/syringe_hook.h` gets its own private `static` registry, so hooks from different `.so`'s don't conflict
4. **No ABI risk** — every `.so` compiles the hooker source with its own compiler/version, no chance of struct layout mismatch

## Trade-off: single-TU per `.so`

Because the registry is `static` (per-translation-unit), `syringe/hook/syringe_hook.h` must be included from **exactly one** `.c` file per `.so` / executable. The standard pattern (1 `.c` file with constructor + destructor) works perfectly. If you need hook logic across multiple `.c` files, keep all `syringe_hook_install` / `syringe_hook_remove` calls in ONE file and call them from that file's constructor; other files in the same `.so` should not include `syringe/hook/syringe_hook.h`.
