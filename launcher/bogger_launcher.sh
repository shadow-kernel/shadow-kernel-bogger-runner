#!/bin/sh
# BOGGER Runner - Main Launcher
# Invoked from initramfs /init after network setup

BOGGER_DIR="/opt/bogger"
CONF="$BOGGER_DIR/bogger.conf"

# Load configuration
[ -f "$CONF" ] && . "$CONF"

BOGGER_VERSION="${BOGGER_VERSION:-0.2.0}"
BOGGER_LOG_LEVEL="${BOGGER_LOG_LEVEL:-0}"
BOGGER_SILENT="${BOGGER_SILENT:-1}"

bogger_log() {
    [ "$BOGGER_SILENT" = "1" ] && return 0
    echo "[BOGGER] $2"
}

bogger_log 1 "=== BOGGER Runner v${BOGGER_VERSION} ==="

# Step 1: CPU capability check (AMD SVM only)
# Check multiple patterns: ' svm ', ' svm$', leading 'svm '
if ! grep -qE '(^| )svm( |$)' /proc/cpuinfo 2>/dev/null; then
    # Fallback: check if CPUID reports SVM (bit 2 of ECX for CPUID 0x80000001)
    bogger_log 1 "WARNING: SVM not in /proc/cpuinfo flags, trying anyway..."
fi

# Step 2: Setup OVMF firmware
OVMF_CODE_PATH="/opt/bogger/firmware/OVMF_CODE.4m.fd"
OVMF_VARS_PATH="/opt/bogger/firmware/OVMF_VARS.4m.fd"

if [ ! -f "$OVMF_CODE_PATH" ]; then
    bogger_log 1 "FATAL: OVMF_CODE not found at $OVMF_CODE_PATH"
    exit 1
fi

bogger_log 1 "OVMF firmware: $OVMF_CODE_PATH"

# Also scan for Windows EFI partition (for logging purposes)
if [ -z "${BOGGER_EFI_PATH:-}" ]; then
    BOGGER_EFI_PATH=$("$BOGGER_DIR/launcher/bogger_efi_scan" 2>/dev/null || echo "")
fi
[ -n "$BOGGER_EFI_PATH" ] && bogger_log 1 "Windows EFI: $BOGGER_EFI_PATH"

# Build insmod parameter string
BOGGER_GUEST_RAM_MB="${BOGGER_GUEST_RAM_MB:-0}"
KMOD_PARAMS="bogger_ovmf_code=$OVMF_CODE_PATH bogger_ram_mb=$BOGGER_GUEST_RAM_MB"
if [ -f "$OVMF_VARS_PATH" ]; then
    KMOD_PARAMS="$KMOD_PARAMS bogger_ovmf_vars=$OVMF_VARS_PATH"
fi
bogger_log 1 "Module params: $KMOD_PARAMS"

# Step 3: Load BOGGER kernel module
bogger_log 1 "Loading hypervisor kernel module..."
insmod "$BOGGER_DIR/kmod/bogger_kmod.ko" $KMOD_PARAMS 2>&1
INSMOD_RET=$?

# Always dump kernel log after insmod to show VMRUN results
echo ""
echo "=== BOGGER Kernel Log (after insmod, exit=$INSMOD_RET) ==="
dmesg | grep -i bogger | tail -50
echo "=== End BOGGER Kernel Log ==="
echo ""

if [ $INSMOD_RET -ne 0 ]; then
    echo "[BOGGER] insmod failed (exit=$INSMOD_RET), retrying with -f..."
    insmod -f "$BOGGER_DIR/kmod/bogger_kmod.ko" $KMOD_PARAMS 2>&1
    INSMOD_RET=$?
    echo "=== BOGGER Kernel Log (retry, exit=$INSMOD_RET) ==="
    dmesg | grep -i bogger | tail -50
    echo "=== End ==="
    if [ $INSMOD_RET -ne 0 ]; then
        echo "[BOGGER] FATAL: Failed to load bogger_kmod.ko"
        exit 1
    fi
fi

# If we reach here, VMRUN loop has ended (Windows exited)
echo "[BOGGER] Hypervisor VMRUN loop has returned."
echo "[BOGGER] Full kernel log:"
dmesg | tail -80
