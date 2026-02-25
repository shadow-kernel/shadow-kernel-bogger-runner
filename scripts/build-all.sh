#!/bin/bash
set -euo pipefail

echo "[BOGGER] Building all components (static, musl-libc)..."

# Prefer musl-gcc for static builds, fallback to gcc
if command -v musl-gcc >/dev/null 2>&1; then
    export CC=musl-gcc
    echo "[BOGGER] Compiler: musl-gcc (static libc)"
else
    export CC=gcc
    echo "[BOGGER] Warning: musl-gcc not found, using gcc (may not be fully static)"
fi

make clean
make all

# Build kernel module (requires kernel headers)
KDIR_PATH="${KDIR_PATH:-/lib/modules/$(uname -r)/build}"
if [ -d "$KDIR_PATH" ]; then
    echo "[BOGGER] Building kernel module (KDIR=$KDIR_PATH)..."
    make -C kmod KDIR="$KDIR_PATH"
else
    echo "[BOGGER] Warning: kernel headers not found at $KDIR_PATH — skipping kmod build"
fi

echo "[BOGGER] Build successful."
echo "[BOGGER] Run 'scripts/install-to-initramfs.sh <initramfs_dir>' to install."
