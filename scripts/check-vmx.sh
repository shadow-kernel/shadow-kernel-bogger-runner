#!/bin/sh
# BOGGER pre-flight: Check CPU virtualization support
echo "[BOGGER] Checking CPU features..."

if grep -q ' vmx ' /proc/cpuinfo 2>/dev/null; then
    echo "[BOGGER] Intel VT-x (VMX): SUPPORTED"
    exit 0
elif grep -q ' svm ' /proc/cpuinfo 2>/dev/null; then
    echo "[BOGGER] AMD-V (SVM): SUPPORTED"
    exit 0
else
    echo "[BOGGER] ERROR: No VMX or SVM flag in /proc/cpuinfo"
    echo "[BOGGER] Ensure VT-x/AMD-V is enabled in BIOS/UEFI firmware settings."
    exit 1
fi
