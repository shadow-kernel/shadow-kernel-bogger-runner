#!/bin/sh
# BOGGER pre-flight: Check CPU virtualization support (AMD SVM)
SILENT="${BOGGER_SILENT:-0}"

[ "$SILENT" = "0" ] && echo "[BOGGER] Checking CPU features..."

if grep -q ' svm ' /proc/cpuinfo 2>/dev/null; then
    [ "$SILENT" = "0" ] && echo "[BOGGER] AMD-V (SVM): SUPPORTED"
    exit 0
elif grep -q ' vmx ' /proc/cpuinfo 2>/dev/null; then
    [ "$SILENT" = "0" ] && echo "[BOGGER] Intel VT-x (VMX): detected but NOT SUPPORTED by BOGGER"
    [ "$SILENT" = "0" ] && echo "[BOGGER] BOGGER currently requires AMD SVM. Intel VMX support is planned."
    exit 1
else
    [ "$SILENT" = "0" ] && echo "[BOGGER] ERROR: No VMX or SVM flag in /proc/cpuinfo"
    [ "$SILENT" = "0" ] && echo "[BOGGER] Ensure AMD-V is enabled in BIOS/UEFI firmware settings."
    exit 1
fi
