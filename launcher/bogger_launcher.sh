#!/bin/sh
# BOGGER Runner - Main Launcher
# Invoked from initramfs /init after network setup
set -e

BOGGER_DIR="/opt/bogger"
CONF="$BOGGER_DIR/bogger.conf"

# Load configuration
[ -f "$CONF" ] && . "$CONF"

BOGGER_VERSION="${BOGGER_VERSION:-0.1.0}"
BOGGER_LOG_LEVEL="${BOGGER_LOG_LEVEL:-1}"

bogger_log() {
    [ "$BOGGER_LOG_LEVEL" -ge "$1" ] && echo "[BOGGER] $2" >/dev/console 2>/dev/null || true
}

bogger_log 1 "=== BOGGER Runner v${BOGGER_VERSION} ==="

# Step 1: CPU capability check
bogger_log 1 "Checking CPU virtualization support..."
"$BOGGER_DIR/scripts/check-vmx.sh" || {
    bogger_log 1 "FATAL: No VMX/SVM support. Cannot launch BOGGER."
    exit 1
}

# Step 2: Auto-detect Windows EFI partition
if [ -z "${BOGGER_EFI_PATH:-}" ]; then
    bogger_log 1 "Scanning for Windows EFI partition..."
    BOGGER_EFI_PATH=$("$BOGGER_DIR/launcher/bogger_efi_scan" 2>/dev/null || true)
    if [ -z "$BOGGER_EFI_PATH" ]; then
        bogger_log 1 "FATAL: winload.efi not found. Check disk configuration."
        exit 1
    fi
fi

bogger_log 1 "Windows EFI target: $BOGGER_EFI_PATH"

# Step 3: Launch BOGGER supervisor (takes over CPU, boots Windows)
bogger_log 1 "Initializing hypervisor and launching Windows..."
exec "$BOGGER_DIR/supervisor/bogger_supervisor" \
    --efi  "$BOGGER_EFI_PATH" \
    --conf "$CONF"
