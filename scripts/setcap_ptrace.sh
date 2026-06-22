#!/bin/sh
# setcap_ptrace.sh — post-install script to set CAP_SYS_PTRACE on syringe-cli
#
# Called by meson install when -Dset-ptrace-cap=true.
# Meson sets MESON_INSTALL_PREFIX and MESON_SOURCE_ROOT env vars.
# Args: <bindir> <binary_name>

set -e

BINDIR="$1"
BINARY="$2"

# Construct full path. MESON_INSTALL_PREFIX is set by meson.
PREFIX="${MESON_INSTALL_PREFIX:-/usr/local}"
DESTDIR="${DESTDIR:-}"
FULL_PATH="${DESTDIR}${PREFIX}/${BINDIR}/${BINARY}"

if [ ! -f "$FULL_PATH" ]; then
    echo "[setcap] Binary not found: $FULL_PATH" >&2
    exit 1
fi

echo "[setcap] Setting CAP_SYS_PTRACE on $FULL_PATH"

# Try setcap directly first (works if running as root or have CAP_SETFCAP)
if setcap cap_sys_ptrace+ep "$FULL_PATH" 2>/dev/null; then
    echo "[setcap] OK — CAP_SYS_PTRACE set"
    exit 0
fi

# setcap failed — try sudo (common case: meson install run as non-root)
if command -v sudo >/dev/null 2>&1; then
    echo "[setcap] setcap failed (need root) — retrying with sudo"
    if sudo setcap cap_sys_ptrace+ep "$FULL_PATH"; then
        echo "[setcap] OK — CAP_SYS_PTRACE set (via sudo)"
        exit 0
    fi
fi

# Both failed — warn but don't fail the install
echo "[setcap] WARNING: Could not set CAP_SYS_PTRACE." >&2
echo "[setcap] Run manually: sudo setcap cap_sys_ptrace+ep $FULL_PATH" >&2
exit 0  # don't fail install — user can setcap manually
