# BOGGER Runner

Type-1 bare-metal hypervisor for the [shadow-kernel](https://github.com/shadow-kernel) project.
Places the host CPU into AMD SVM root mode and boots Windows 11 inside non-root mode —
Windows believes it is running on real hardware. No VM-detection technique (including
kernel-level anti-cheat: BattlEye, EAC) can observe the hypervisor layer.

## Architecture

```
GRUB / UEFI
  └── shadow-kernel Linux (custom kernel)
        └── initramfs /init
              ├── Network + SSH (Dropbear)
              └── /opt/bogger/launcher/bogger_launcher.sh
                    ├── CPU check (AMD SVM)
                    ├── bogger_efi_scan         ← locate Windows EFI bootloader
                    ├── insmod bogger.ko         ← VMCB setup, NPT, stealth layer
                    └── VMRUN                    ← Windows starts in SVM non-root
                          └── Windows 11 (bare-metal driver stack, no guest drivers)
                                └── BOGGER dispatches #VMEXIT silently
```

## Stealth

| Technique | Mechanism |
|-----------|-----------|
| **CPUID** | Clears hypervisor-present bit; zeroes leaves `0x40000000`–`0x400000FF` |
| **MSR** | `IA32_FEATURE_CONTROL` returns lock-bit only; all VMX capability MSRs return 0 |
| **TSC** | Native RDTSC passthrough (no exit), TSC offset cancels VM-exit latency |
| **ACPI** | Real ACPI tables passed through (DMAR/IVRS identity mapping) |
| **Hardware** | Full GPU, NVMe, NIC passthrough via AMD-Vi IOMMU |
| **SMBIOS** | Real BIOS/motherboard strings (no VM fingerprint) |

## Repository Layout

```
bogger-runner/
├── Makefile              ← Top-level build (delegates to subdirs)
├── bogger.conf           ← Runtime configuration (disk, RAM, stealth flags)
├── core/
│   ├── vmx/              ← VMX/SVM enable, VMCB init, #VMEXIT dispatch
│   └── passthrough/      ← ACPI and IOMMU passthrough helpers
├── kmod/                 ← Kernel module sources (bogger.ko)
│   ├── bogger_kmod.c     ← Module entry (insmod → VMRUN kthread)
│   ├── bogger_svm.c      ← SVM/VMCB setup
│   ├── bogger_npt.c      ← Nested Page Tables
│   ├── bogger_vmrun.S    ← VMRUN assembly loop
│   ├── bogger_stealth.c  ← CPUID/MSR intercept
│   ├── bogger_nvme.c     ← NVMe passthrough (disk backing)
│   ├── bogger_ovmf.c     ← OVMF firmware loading
│   └── ...               ← LAPIC, IOAPIC, HPET, PIC, PS/2, VGA, PCI, SMBIOS
├── supervisor/           ← bogger_supervisor (userland orchestrator)
├── launcher/
│   ├── bogger_launcher.sh  ← Runtime launcher (called from initramfs /init)
│   └── bogger_efi_scan.c   ← EFI partition scanner (finds bootmgfw.efi)
├── stealth/              ← CPUID/MSR stealth + SMBIOS fingerprint check
└── scripts/              ← Runtime helper scripts (installed to initramfs)
    ├── check-vmx.sh      ← CPU capability pre-flight check
    └── diagnose_vm.sh    ← SSH diagnostic tool (run from remote)
```

## Build

**This module is built automatically by the top-level Makefile:**

```bash
# From the shadow-kernel-hyper-boot root:
make bogger         # Build BOGGER only
make                # Build everything (kernel + BOGGER + initramfs)
```

The top-level `make` handles:
1. Kernel build → `modules_prepare` → `Module.symvers` sync
2. BOGGER userland build (`musl-gcc`, static)
3. BOGGER kmod build (against project kernel, vermagic match)
4. Installation into initramfs at `/opt/bogger/`
5. CPIO packing

**Manual build** (standalone, for development):

```bash
cd bogger-runner
make CC=musl-gcc KDIR=../linux    # Build all components
make -C kmod KDIR=../linux        # Build kernel module only
make clean KDIR=../linux          # Clean
```

## Runtime (initramfs)

After boot, the initramfs `/init` script calls:

```
/opt/bogger/launcher/bogger_launcher.sh
```

This script:
1. Reads `/opt/bogger/bogger.conf`
2. Checks AMD SVM support
3. Scans for OVMF firmware + Windows EFI partition
4. Loads `bogger.ko` with parameters (RAM, disk, GPU passthrough)
5. Monitors the VMRUN kthread until Windows exits

## Configuration (`bogger.conf`)

```ini
BOGGER_DISK_PATH=           # Auto-detect (nvme1n1 → vda → sda)
BOGGER_GUEST_RAM_MB=8192    # Guest RAM (0 = auto: 50% of host)
BOGGER_SILENT=0             # 0=verbose, 1=errors only
BOGGER_STEALTH_CPUID=1      # Hide hypervisor from CPUID
BOGGER_STEALTH_MSR=1        # Hide VMX MSRs
BOGGER_STEALTH_TSC=1        # Native RDTSC passthrough
```

Kernel cmdline overrides: `bogger_ram_mb=4096 bogger_disk=/dev/nvme1n1 bogger_gpu=1`

## Integration

This is a git submodule inside
[shadow-kernel-hyper-boot](https://github.com/shadow-kernel/shadow-kernel-hyper-boot)
at path `bogger-runner/`. It is not intended to be built standalone — use the top-level
`make` system.
