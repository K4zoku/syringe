project(
    'syringe',
    'c',
    version: '0.6.0',
    default_options: [
        'warning_level=3',
        'c_std=gnu11',
    ],
    meson_version: '>= 1.0.0',
)

# ── compiler & linker setup ───────────────────────────────────────────────

add_project_arguments('-fPIC', language: 'c')

project_c_flags = [
    '-Wall',
    '-Wextra',
    '-O2',
    '-Wno-pedantic',
]

# ── Dependencies ──────────────────────────────────────────────────────────

cc = meson.get_compiler('c')
pthread_lib = cc.find_library('pthread', required: true)
dl_lib = cc.find_library('dl', required: true)

inc = include_directories('include')

# ── Architecture selection ────────────────────────────────────────────────
# Exactly one arch backend is compiled in, chosen from the host CPU family.
# Add a new arch: drop src/arch/arch_<name>.c (implementing src/arch/arch.h),
# then add it to the map below.
host_arch = host_machine.cpu_family()

arch_srcs = {
    'x86_64': 'src/arch/arch_x86_64.c',
    'aarch64': 'src/arch/arch_aarch64.c',
    'arm': 'src/arch/arch_arm.c',
    'riscv64': 'src/arch/arch_riscv64.c',
}

if not arch_srcs.has_key(host_arch)
    error(
        'Unsupported architecture: '
        + host_arch
        + '. Supported: '
        + ', '.join(arch_srcs.keys()),
    )
endif

arch_src = arch_srcs[host_arch]
message('  target arch:      ' + host_arch + ' → ' + arch_src)

# ══════════════════════════════════════════════════════════════════════════
#  SHELLCODE GENERATION (x86-64 only for now)
# ══════════════════════════════════════════════════════════════════════════
#
# Compile shellcode_x86_64.S → .o → raw binary → xxd -i → .h
# The generated header is #include'd by arch_x86_64.c.
#
# Pipeline is inlined as a single `sh -c` custom_target — no wrapper script.
# Tools are detected at configure time via find_program() so missing xxd or
# objcopy fails fast with a clear error instead of a build-time crash.
#
# For architectures without a shellcode .S file (arm, riscv64),
# arch_<arch>.c still uses the old EMIT() approach (or returns 0).

shellcode_h = ''
if host_arch == 'x86_64'
  xxd_prog     = find_program('xxd',     required: true)
  objcopy_prog = find_program('objcopy', required: true)
  cc_exe       = cc.cmd_array()[0]

  # xxd -i derives the C array name from the input filename's basename
  # (non-alphanumeric chars → '_'). Copying sc.bin to a file named exactly
  # 'syringe_shellcode_x86_64' makes xxd emit the exact symbol we need:
  #   unsigned char syringe_shellcode_x86_64[] = { ... };
  #   unsigned int  syringe_shellcode_x86_64_len = 344;
  # We use @OUTDIR@ (meson-managed per-target dir) for intermediate files
  # so there's no /tmp juggling and cleanup is a one-liner.
  # Tool paths are baked into the script string at configure time.
  sc_cmd = 'set -e; ' + \
           '@0@ -c -fPIC -nostdlib -fno-stack-protector @INPUT@ -o "@OUTDIR@/sc.o"; ' \
             .format(cc_exe) + \
           '@0@ -O binary -j .text "@OUTDIR@/sc.o" "@OUTDIR@/sc.bin"; ' \
             .format(objcopy_prog.full_path()) + \
           'cp "@OUTDIR@/sc.bin" "@OUTDIR@/syringe_shellcode_x86_64"; ' + \
           '( cd "@OUTDIR@" && @0@ -i syringe_shellcode_x86_64 ) > @OUTPUT@; ' \
             .format(xxd_prog.full_path()) + \
           'rm -f "@OUTDIR@/sc.o" "@OUTDIR@/sc.bin" "@OUTDIR@/syringe_shellcode_x86_64"'

  shellcode_h = custom_target('shellcode_x86_64.h',
    input: 'src/arch/shellcode_x86_64.S',
    output: 'shellcode_x86_64.h',
    command: ['sh', '-c', sc_cmd],
    build_by_default: true,
  )
endif

# ══════════════════════════════════════════════════════════════════════════
#  TARGETS
# ══════════════════════════════════════════════════════════════════════════

# ── libsyringe.so — cross-process injection surface ───────────────────────
#
#   SYRINGE Yields Runtime Injected Native Global Executables
#
# Public API (syringe.h):
#   - syringe_inject(pid, so_path)   — ptrace + dlopen inject
#
# Internal (NOT in header, file-scope prototype in syringe.c):
#   - syringe_build_shellcode(...)   — escape hatch for advanced users
#
# The GOT/PLT hooker (syringe_hook.h) is HEADER-ONLY — no separate .so
# to link. Consumers just #include "syringe_hook.h" from one .c file.
syringe_lib_sources = ['src/syringe.c', arch_src]
if host_arch == 'x86_64'
  syringe_lib_sources += shellcode_h
endif
syringe_lib = library(
    'syringe',
    syringe_lib_sources,
    c_args: project_c_flags,
    include_directories: [inc, include_directories('.')],
    link_args: ['-ldl', '-lpthread'],
    version: '0.6',
    install: true,
)

# Install injector header (syringe.h) under subdir 'syringe/'
install_headers(
    ['include/syringe.h'],
    subdir: 'syringe',
)

# Install hooker headers under subdir 'syringe/hook/'
# Public:     syringe_hook.h (user includes this)
# Internal:   syringe_hook_common.h, arch/* (included transitively)
install_headers(
    ['include/hook/syringe_hook.h',
     'include/hook/syringe_hook_common.h'],
    subdir: 'syringe/hook',
)
install_headers(
    ['include/hook/arch/syringe_hook_arch.h',
     'include/hook/arch/syringe_hook_x86_64.h',
     'include/hook/arch/syringe_hook_aarch64.h'],
    subdir: 'syringe/hook/arch',
)

# ── syringe-cli (CLI binary — links only libsyringe)
syringe_cli_exe = executable(
    'syringe-cli',
    'src/syringe-cli.c',
    c_args: project_c_flags,
    include_directories: inc,
    link_args: ['-ldl', '-lpthread'],
    link_with: syringe_lib,
    install: true,
)

# ── libgleshook.so (internal — inject-ready sample, hooks EGL/GLX/SDL/Wayland)
# syringe_hook.h is header-only, so libgleshook.c just #includes it.
gleshook_lib = library(
    'gleshook',
    sources: ['tests/lib/libgleshook.c'],
    c_args: project_c_flags,
    include_directories: inc,
    link_args: ['-ldl', '-lpthread'],
    install: false,
)

# ── libtest.so (internal — minimal test library for injection verification) ──
# Meson auto-prepends 'lib' to library names, and reserves 'test' as a target
# name. Using name_prefix: '' with full filename 'libtest' produces libtest.so.
test_sample_lib = library(
    'libtest',
    'tests/lib/libtest.c',
    c_args: project_c_flags,
    include_directories: inc,
    link_args: ['-ldl', '-lpthread'],
    name_prefix: '',
    install: false,
)

# ══════════════════════════════════════════════════════════════════════════
#  TESTS: unit tests
# ══════════════════════════════════════════════════════════════════════════

# ── test_hook (header-only — just #include syringe_hook.h) ───────────────
test_hook_exe = executable(
    'test_hook',
    ['tests/src/test_hook.c'],
    c_args: project_c_flags,
    include_directories: inc,
    link_args: ['-ldl', '-lpthread'],
    dependencies: [pthread_lib, dl_lib],
)

test('hook', test_hook_exe, timeout: 30)

# ── test_inline (v0.5: end-to-end inline hook with -fcf-protection) ──────
# Builds with CET (endbr64 prologues) to exercise the length-disassembler
# and RIP-relative fixup on real compiler-emitted code, not just hand-
# assembled bytes. Verifies install_addr + trampoline + read_dst + remove
# on a callable target function.
test_inline_exe = executable(
    'test_inline',
    ['tests/src/test_inline.c'],
    c_args: project_c_flags + ['-fcf-protection=full'],
    include_directories: inc,
    link_args: ['-ldl', '-lpthread'],
    dependencies: [pthread_lib, dl_lib],
)

test('inline', test_inline_exe, timeout: 30)

# ── test_syringe (links against libsyringe.so) ───────────────────────────
test_syringe_exe = executable(
    'test_syringe',
    'tests/src/test_syringe.c',
    c_args: project_c_flags,
    include_directories: inc,
    link_args: ['-ldl', '-lpthread'],
    link_with: syringe_lib,
)

test('syringe', test_syringe_exe, timeout: 30)

# ══════════════════════════════════════════════════════════════════════════
#  PKG-CONFIG + SUBPROJECT SUPPORT
# ══════════════════════════════════════════════════════════════════════════

# pkg-config file for libsyringe (injection only)
pkg = import('pkgconfig')
pkg.generate(
    syringe_lib,
    name: 'libsyringe',
    description: 'ptrace-based shared-library injector for x86-64 (hooker is header-only)',
    version: meson.project_version(),
    filebase: 'libsyringe',
    extra_cflags: '-I${includedir}/syringe',
)

# declare_dependency — for subproject usage
libsyringe_dep = declare_dependency(
    link_with: [syringe_lib],
    link_args: ['-ldl', '-lpthread'],
    include_directories: inc,
)

# Suppress unused variable warnings — these are intentionally kept for
# Meson's internal build target tracking
_ = [
    syringe_cli_exe,
    gleshook_lib,
    test_sample_lib,
    libsyringe_dep,
    test_inline_exe,
]

# ══════════════════════════════════════════════════════════════════════════
#  Summary
# ══════════════════════════════════════════════════════════════════════════

message('\n=== syringe build configuration ===')
message('  libsyringe:       ptrace inject (syringe_inject)')
message('  syringe_hook.h:   header-only GOT/PLT hooker (no .so)')
message('  syringe-cli:      CLI (links libsyringe only)')
message(
    '  libgleshook:      inject-ready sample (EGL/GLX/SDL/Wayland hooks, header-only hooker)',
)
message('  libtest:          minimal test .so for injection verification')
message('  tests:            hook, inline, syringe')
message(
    '  install:          syringe.h + syringe_hook.h + libsyringe.so + pkg-config',
)
message('=============================================\n')
