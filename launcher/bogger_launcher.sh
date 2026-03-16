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
    local level="$1"
    shift
    # Always log errors (level 1), skip info (level 2+) in silent mode
    if [ "$BOGGER_SILENT" = "1" ] && [ "${level:-2}" -gt 1 ]; then
        return 0
    fi
    echo "[BOGGER] $*"
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
BOGGER_PASSTHROUGH_GPU="${BOGGER_PASSTHROUGH_GPU:-0}"
BOGGER_GPU_BDF="${BOGGER_GPU_BDF:-}"

# Override settings from kernel cmdline
if [ -r /proc/cmdline ]; then
    for word in $(cat /proc/cmdline); do
        case "$word" in
            bogger_ram_mb=*) BOGGER_GUEST_RAM_MB="${word#bogger_ram_mb=}" ;;
            bogger_gpu=0)    BOGGER_PASSTHROUGH_GPU=0; BOGGER_GPU_BDF="" ;;
            bogger_gpu=1)    BOGGER_PASSTHROUGH_GPU=1 ;;
            bogger_disk=*)   BOGGER_DISK_PATH="${word#bogger_disk=}" ;;
        esac
    done
fi

# In QEMU mode (bogger_gpu=1 from cmdline but no matching bare-metal GPU),
# auto-detect the first VGA device (QXL at 00:06.0) for GPU passthrough.
if [ "$BOGGER_PASSTHROUGH_GPU" = "1" ] && [ -n "$BOGGER_GPU_BDF" ]; then
    GPU_SYS="/sys/bus/pci/devices/0000:$BOGGER_GPU_BDF"
    if [ ! -d "$GPU_SYS" ]; then
        bogger_log 2 "Configured GPU BDF $BOGGER_GPU_BDF not found, scanning..."
        BOGGER_GPU_BDF=""
    fi
fi
if [ "$BOGGER_PASSTHROUGH_GPU" = "1" ] && [ -z "$BOGGER_GPU_BDF" ]; then
    # Scan for any VGA device (class 0x030000)
    for dev in /sys/bus/pci/devices/*/class; do
        devclass=$(cat "$dev" 2>/dev/null)
        case "$devclass" in
            0x030000|0x030200)
                found_bdf=$(basename "$(dirname "$dev")")
                # Strip domain (0000:)
                BOGGER_GPU_BDF="${found_bdf#0000:}"
                bogger_log 1 "Auto-detected GPU: $BOGGER_GPU_BDF (class $devclass)"
                break
                ;;
        esac
    done
fi

KMOD_PARAMS="bogger_ovmf_code=$OVMF_CODE_PATH bogger_ram_mb=$BOGGER_GUEST_RAM_MB"
if [ -f "$OVMF_VARS_PATH" ]; then
    KMOD_PARAMS="$KMOD_PARAMS bogger_ovmf_vars=$OVMF_VARS_PATH"
fi

# Disk path for Windows backing storage
# Already set from bogger.conf, cmdline override handled above
BOGGER_DISK_PATH="${BOGGER_DISK_PATH:-}"
if [ -n "$BOGGER_DISK_PATH" ] && [ -b "$BOGGER_DISK_PATH" ]; then
    KMOD_PARAMS="$KMOD_PARAMS bogger_disk_path=$BOGGER_DISK_PATH"
    bogger_log 1 "Disk backing: $BOGGER_DISK_PATH (configured)"
elif [ -n "$BOGGER_DISK_PATH" ] && [ ! -b "$BOGGER_DISK_PATH" ]; then
    bogger_log 1 "WARNING: Configured disk $BOGGER_DISK_PATH not found, auto-detecting..."
    BOGGER_DISK_PATH=""
fi

# Auto-detect Windows NVMe if not set or not found
if [ -z "$BOGGER_DISK_PATH" ]; then
    for try_dev in /dev/nvme1n1 /dev/nvme0n1 /dev/vda /dev/sda; do
        if [ -b "$try_dev" ]; then
            BOGGER_DISK_PATH="$try_dev"
            KMOD_PARAMS="$KMOD_PARAMS bogger_disk_path=$BOGGER_DISK_PATH"
            bogger_log 1 "Disk backing: $BOGGER_DISK_PATH (auto-detected)"
            break
        fi
    done
    if [ -z "$BOGGER_DISK_PATH" ]; then
        bogger_log 1 "WARNING: No disk device found for Windows!"
        bogger_log 1 "Available block devices:"
        ls -la /dev/nvme* /dev/vd* /dev/sd* 2>/dev/null | while read line; do
            bogger_log 1 "  $line"
        done
    fi
fi

# GPU Passthrough (bare metal only)
if [ "$BOGGER_PASSTHROUGH_GPU" = "1" ] && [ -n "$BOGGER_GPU_BDF" ]; then
    KMOD_PARAMS="$KMOD_PARAMS bogger_passthrough_gpu=1 bogger_gpu_bdf=$BOGGER_GPU_BDF"
    bogger_log 1 "GPU Passthrough: BDF=$BOGGER_GPU_BDF"

    # Pre-unbind GPU drivers to ensure clean handoff to BOGGER
    # The kernel module also does this, but doing it early avoids races
    GPU_SYS="/sys/bus/pci/devices/0000:$BOGGER_GPU_BDF"
    if [ -d "$GPU_SYS" ]; then
        # Check and unbind current driver
        if [ -L "$GPU_SYS/driver" ]; then
            DRV_NAME=$(basename "$(readlink "$GPU_SYS/driver")")
            bogger_log 1 "GPU currently using driver: $DRV_NAME"
            echo "0000:$BOGGER_GPU_BDF" > "$GPU_SYS/driver/unbind" 2>/dev/null || true
            bogger_log 1 "GPU driver unbound"
        fi
        # Also unbind audio function (.1)
        AUDIO_BDF="${BOGGER_GPU_BDF%.*}.1"
        AUDIO_SYS="/sys/bus/pci/devices/0000:$AUDIO_BDF"
        if [ -d "$AUDIO_SYS" ] && [ -L "$AUDIO_SYS/driver" ]; then
            echo "0000:$AUDIO_BDF" > "$AUDIO_SYS/driver/unbind" 2>/dev/null || true
            bogger_log 2 "GPU audio driver unbound"
        fi
    fi
fi
bogger_log 2 "Module params: $KMOD_PARAMS"

# Step 3: Prepare system for hypervisor
# Ensure IOMMU is active
if [ -d /sys/class/iommu ]; then
    IOMMU_COUNT=$(ls /sys/class/iommu/ 2>/dev/null | wc -l)
    if [ "$IOMMU_COUNT" -gt 0 ]; then
        bogger_log 2 "IOMMU active ($IOMMU_COUNT groups)"
    else
        bogger_log 1 "WARNING: No IOMMU groups found — GPU passthrough may fail"
        bogger_log 1 "Ensure amd_iommu=on iommu=pt in kernel cmdline"
    fi
fi

# Step 4: Load BOGGER kernel module
bogger_log 1 "Loading hypervisor kernel module..."
insmod "$BOGGER_DIR/kmod/bogger.ko" $KMOD_PARAMS 2>&1
INSMOD_RET=$?

# Always dump kernel log after insmod to show initial VMRUN results
echo ""
echo "=== BOGGER Kernel Log (after insmod, exit=$INSMOD_RET) ==="
dmesg | grep -i bogger | tail -50
echo "=== End BOGGER Kernel Log ==="
echo ""

if [ $INSMOD_RET -ne 0 ]; then
    echo "[BOGGER] insmod failed (exit=$INSMOD_RET), retrying with -f..."
    insmod -f "$BOGGER_DIR/kmod/bogger.ko" $KMOD_PARAMS 2>&1
    INSMOD_RET=$?
    echo "=== BOGGER Kernel Log (retry, exit=$INSMOD_RET) ==="
    dmesg | grep -i bogger | tail -50
    echo "=== End ==="
    if [ $INSMOD_RET -ne 0 ]; then
        echo "[BOGGER] FATAL: Failed to load bogger.ko"
        exit 1
    fi
fi

# The VMRUN loop runs in a kthread (bogger_vmrun).
# insmod returns immediately after module_init().
# We must wait here until the VM finishes (kthread exits).
echo "[BOGGER] VM is running (VMRUN kthread active)..."
echo "[BOGGER] Monitoring VM status. Press Ctrl+C to stop."

# Wait for the bogger_vmrun kthread to finish
VMRUN_ALIVE=1
STATUS_INTERVAL=0
while [ "$VMRUN_ALIVE" = "1" ]; do
    sleep 5
    STATUS_INTERVAL=$((STATUS_INTERVAL + 1))

    # Check if the kthread is still running using multiple methods
    KTHREAD_FOUND=0
    # Method 1: check /proc/*/comm (suppress all errors)
    if cat /proc/[0-9]*/comm 2>/dev/null | grep -q "bogger_vmrun"; then
        KTHREAD_FOUND=1
    fi
    # Method 2: check if module is still loaded
    if grep -q "^bogger " /proc/modules 2>/dev/null; then
        # Module loaded means VM might still be running even if grep above failed
        if [ "$KTHREAD_FOUND" = "0" ]; then
            # Double check with ps if available
            if command -v ps >/dev/null 2>&1; then
                if ps -e 2>/dev/null | grep -q "bogger"; then
                    KTHREAD_FOUND=1
                fi
            else
                # Assume still running if module is loaded
                KTHREAD_FOUND=1
            fi
        fi
    else
        KTHREAD_FOUND=0
        echo "[BOGGER] Module unloaded."
    fi

    if [ "$KTHREAD_FOUND" = "0" ]; then
        VMRUN_ALIVE=0
        echo "[BOGGER] VMRUN kthread has exited."
    fi


    # Periodic status every 30 seconds (6 * 5s)
    if [ "$VMRUN_ALIVE" = "1" ] && [ $((STATUS_INTERVAL % 6)) -eq 0 ]; then
        # Show latest BOGGER log entries
        LATEST=$(dmesg | grep '\[BOGGER\]' | tail -3)
        echo "[BOGGER] VM still running (${STATUS_INTERVAL}x5s). Latest:"
        echo "$LATEST"
    fi
done

# VM has finished — dump final log
echo ""
echo "[BOGGER] Hypervisor VMRUN loop has returned."
echo "[BOGGER] Full kernel log:"
dmesg | tail -80

# Check if it was a clean shutdown or a crash
LAST_BOGGER=$(dmesg | grep '\[BOGGER\]' | tail -5)
echo ""
echo "[BOGGER] Last BOGGER messages:"
echo "$LAST_BOGGER"

# Exit 0 = normal, the init script should not treat this as unexpected
exit 0

