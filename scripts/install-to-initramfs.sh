#!/bin/bash
set -euo pipefail

INITRAMFS_DIR="${1:?Usage: install-to-initramfs.sh <initramfs_dir>}"
INSTALL_BASE="$INITRAMFS_DIR/opt/bogger"

echo "[BOGGER] Installing to: $INSTALL_BASE"

mkdir -p "$INSTALL_BASE"/{supervisor,launcher,stealth,scripts}

# Binaries
[ -f supervisor/bogger_supervisor ] && \
    cp supervisor/bogger_supervisor "$INSTALL_BASE/supervisor/" && \
    chmod +x "$INSTALL_BASE/supervisor/bogger_supervisor"

[ -f launcher/bogger_efi_scan ] && \
    cp launcher/bogger_efi_scan "$INSTALL_BASE/launcher/" && \
    chmod +x "$INSTALL_BASE/launcher/bogger_efi_scan"

# Scripts
cp launcher/bogger_launcher.sh "$INSTALL_BASE/launcher/"
chmod +x "$INSTALL_BASE/launcher/bogger_launcher.sh"

for s in scripts/*.sh; do
    cp "$s" "$INSTALL_BASE/scripts/"
    chmod +x "$INSTALL_BASE/scripts/$(basename $s)"
done

# Config
cp bogger.conf "$INSTALL_BASE/"

echo "[BOGGER] Installation complete."
echo "[BOGGER] Add this line to your initramfs /init before the final exec:"
echo ""
echo "  /opt/bogger/launcher/bogger_launcher.sh"
echo ""
