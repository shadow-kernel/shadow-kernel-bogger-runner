# shadow-kernel-bogger-runner

BOGGER Runner is a stealth Type-1 hypervisor written in C, compiled statically with
`musl-gcc`, and executed from the initramfs of the [shadow-kernel](https://github.com/shadow-kernel)
project. It places the host CPU into VMX Root mode (Ring -1) and boots Windows 11 inside
VMX Non-Root mode so that Windows believes it is running on real bare-metal hardware. No
VM-detection technique — including kernel-level anti-cheat engines such as BattlEye or
EAC — is able to observe the hypervisor layer.

---

## Architecture

```
UEFI/GRUB
  └── shadow-kernel Linux (shadow-kernel-linux)
        └── initramfs /init
              ├── Network setup (existing)
              ├── [BOGGER] check-vmx.sh       ← CPU capability check
              ├── [BOGGER] bogger_efi_scan     ← Find winload.efi
              ├── [BOGGER] bogger_supervisor   ← VMXON, VMCS setup, stealth layer
              └── [BOGGER] VMLAUNCH           ← Windows starts in VMX Non-Root
                    └── Windows 11 runs (thinks it's on bare metal)
                          └── BOGGER dispatches VM exits silently in background
```

---

## Stealth Strategy

| Technique | Mechanism |
|-----------|-----------|
| **CPUID intercept** | Clears `ECX[31]` (Hypervisor Present) on leaf `0x1`; zeroes all outputs for leaves `0x40000000`–`0x400000FF` |
| **MSR intercept** | `IA32_FEATURE_CONTROL` (0x3A) returns lock-bit only (VMX bits cleared); all `IA32_VMX_*` capability MSRs (0x480–0x48F) return 0 |
| **TSC offset** | VMCS `TSC_OFFSET` field cancels VM-exit round-trip latency; `RDTSC_EXITING=0` so RDTSC runs natively |
| **Full hardware passthrough** | VT-d / AMD-Vi identity mapping for GPU, NVMe, and NIC via ACPI DMAR/IVRS tables |
| **No guest drivers** | Zero paravirtual or VM-guest drivers installed in Windows — pure bare-metal driver stack |

---

## Repository Layout

```
shadow-kernel-bogger-runner/
├── bogger.conf               ← Runtime configuration
├── Makefile                  ← Top-level build
├── core/
│   ├── vmx/                  ← VMX enable, VMCS init, VM-exit dispatch
│   └── passthrough/          ← ACPI and IOMMU passthrough helpers
├── supervisor/               ← Main entry-point binary (bogger_supervisor)
├── launcher/                 ← Shell launcher + EFI partition scanner
├── stealth/                  ← CPUID/MSR stealth config + SMBIOS fingerprint check
└── scripts/                  ← Build, install, and pre-flight scripts
```

---

## Build Instructions

Requirements: `musl-gcc`, GNU `make`

```sh
# Build all components (static, ffreestanding)
./scripts/build-all.sh

# Install into an initramfs tree
./scripts/install-to-initramfs.sh /path/to/initramfs
```

---

## Integration

This repository is used as a git submodule inside
[shadow-kernel-hyper-boot](https://github.com/shadow-kernel/shadow-kernel-hyper-boot)
at path `bogger-runner/`.

```sh
git submodule add https://github.com/shadow-kernel/shadow-kernel-bogger-runner bogger-runner
```
