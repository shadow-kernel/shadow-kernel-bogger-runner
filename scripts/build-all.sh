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

echo "[BOGGER] Build successful."
echo "[BOGGER] Run 'scripts/install-to-initramfs.sh <initramfs_dir>' to install."
