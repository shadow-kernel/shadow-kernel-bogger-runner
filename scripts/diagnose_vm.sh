#!/bin/sh
# diagnose_vm.sh – Run this over SSH to diagnose BOGGER VM issues
# Usage: ssh root@<hyperboot-ip> /opt/bogger/scripts/diagnose_vm.sh
#
# Collects all relevant diagnostic information about the hypervisor state.

echo "══════════════════════════════════════════════════════════════"
echo " BOGGER VM Diagnostic Report"
echo " $(date)"
echo "══════════════════════════════════════════════════════════════"
echo ""

# 1. Module status
echo "── Module Status ──────────────────────────────────────────"
if grep -q "^bogger " /proc/modules 2>/dev/null; then
    echo "✓ bogger.ko is loaded"
    grep "^bogger " /proc/modules
else
    echo "✗ bogger.ko is NOT loaded!"
    echo "  Check: dmesg | grep -i bogger"
fi
echo ""

# 2. VMRUN kthread
echo "── VMRUN Thread ───────────────────────────────────────────"
VMRUN_PID=""
for pid in /proc/[0-9]*; do
    if [ -f "$pid/comm" ] && grep -q "bogger_vmrun" "$pid/comm" 2>/dev/null; then
        VMRUN_PID=$(basename "$pid")
        echo "✓ bogger_vmrun kthread running (PID=$VMRUN_PID)"
        cat "$pid/status" 2>/dev/null | grep -E "^(State|Cpus_allowed|voluntary)"
        break
    fi
done
if [ -z "$VMRUN_PID" ]; then
    echo "✗ bogger_vmrun kthread NOT found!"
    echo "  The VM may have exited or failed to start."
fi
echo ""

# 3. GPU PCI device status
echo "── GPU PCI Device ─────────────────────────────────────────"
# Read GPU BDF from config or kernel log
GPU_BDF=$(dmesg | grep -o 'bogger_gpu_bdf=[0-9a-f:\.]*' | head -1 | cut -d= -f2)
if [ -z "$GPU_BDF" ]; then
    GPU_BDF=$(grep BOGGER_GPU_BDF /opt/bogger/bogger.conf 2>/dev/null | cut -d= -f2)
fi
if [ -n "$GPU_BDF" ]; then
    echo "Configured GPU BDF: $GPU_BDF"
    GPU_SYS="/sys/bus/pci/devices/0000:$GPU_BDF"
    if [ -d "$GPU_SYS" ]; then
        echo "  Vendor/Device: $(cat "$GPU_SYS/vendor" 2>/dev/null):$(cat "$GPU_SYS/device" 2>/dev/null)"
        if [ -L "$GPU_SYS/driver" ]; then
            echo "  Driver: $(basename "$(readlink "$GPU_SYS/driver")")"
            echo "  ⚠ GPU still has a driver bound! It should be unbound for passthrough."
        else
            echo "  Driver: NONE (unbound) ✓"
        fi
        echo "  IOMMU Group: $(basename "$(readlink "$GPU_SYS/iommu_group")" 2>/dev/null)"
        echo "  BARs:"
        for i in 0 1 2 3 4 5; do
            BAR=$(cat "$GPU_SYS/resource" 2>/dev/null | sed -n "$((i+1))p")
            [ -n "$BAR" ] && echo "    BAR$i: $BAR"
        done
        echo "  ROM:"
        ROM=$(cat "$GPU_SYS/resource" 2>/dev/null | sed -n '7p')
        [ -n "$ROM" ] && echo "    ROM: $ROM"
    else
        echo "  ⚠ Device not found in sysfs"
    fi
else
    echo "  Could not determine GPU BDF"
fi
echo ""

# 4. IOMMU status
echo "── IOMMU Status ───────────────────────────────────────────"
if [ -d /sys/class/iommu ]; then
    IOMMU_COUNT=$(ls /sys/class/iommu/ 2>/dev/null | wc -l)
    echo "IOMMU devices: $IOMMU_COUNT"
else
    echo "⚠ IOMMU not detected!"
fi
grep -i iommu /proc/cmdline 2>/dev/null
echo ""

# 5. BOGGER kernel log (last 100 entries)
echo "── BOGGER Kernel Log ────────────────────────────────────────"
echo "Last 100 BOGGER messages from dmesg:"
dmesg | grep -i '\[BOGGER\]\|BOGGER-\|bogger_' | tail -100
echo ""

# 6. OVMF debug output
echo "── OVMF Debug Output ──────────────────────────────────────"
echo "OVMF messages (port 0x402 / COM1 serial):"
dmesg | grep -E '\[OVMF\]|\[OVMF-DBG\]|\[OVMF-COM2\]' | tail -50
echo ""

# 7. PCI config ring buffer
echo "── PCI Config Ring Buffer ─────────────────────────────────"
echo "Last PCI config accesses (if logged):"
dmesg | grep '\[PCI-RING\]\|BOGGER-PCI' | tail -30
echo ""

# 8. GPU Passthrough specific
echo "── GPU Passthrough Status ─────────────────────────────────"
dmesg | grep '\[BOGGER-PT\]' | tail -40
echo ""

# 9. VM milestone exits
echo "── VM Exit Milestones ───────────────────────────────────────"
dmesg | grep '\[BOGGER\].*exits\|VMRUN loop\|FV FOUND\|FV scan' | tail -20
echo ""

# 10. Errors and warnings
echo "── Errors & Warnings ──────────────────────────────────────"
dmesg | grep -iE '\[BOGGER\].*FATAL|\[BOGGER\].*ERROR|\[BOGGER\].*WARNING|\[BOGGER\].*FAIL|\[BOGGER\].*STUCK' | tail -20
echo ""

# 11. Memory status
echo "── Memory Status ──────────────────────────────────────────"
echo "Free memory:"
cat /proc/meminfo | grep -E "MemTotal|MemFree|MemAvailable"
echo ""

# 12. Kernel cmdline
echo "── Kernel Command Line ────────────────────────────────────"
cat /proc/cmdline
echo ""

echo "══════════════════════════════════════════════════════════════"
echo " End of Diagnostic Report"
echo "══════════════════════════════════════════════════════════════"
