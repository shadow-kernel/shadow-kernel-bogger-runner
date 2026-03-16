/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOGGER_PCI_PASSTHROUGH_H
#define BOGGER_PCI_PASSTHROUGH_H
#include "bogger_types.h"
#include <linux/pci.h>

struct iommu_domain;

/*
 * bogger_pci_passthrough.h – PCI device passthrough for GPU etc.
 *
 * On real hardware, the GPU is unbound from its host driver and
 * its BAR regions are identity-mapped into the guest NPT.
 * The guest sees the real GPU and can drive the display directly.
 *
 * Guest PCI topology:
 *   00:0.0  i440FX Host Bridge (emulated)
 *   00:1.0  PIIX3 ISA Bridge (emulated)
 *   00:1.1  PIIX3 IDE (emulated)
 *   00:1.3  PIIX3 PM/ACPI (emulated)
 *   00:2.0  Bochs VGA (emulated, fallback display)
 *   00:3.0  GPU (passthrough, if enabled) ← GUEST_GPU_BDF
 *   00:3.1  GPU Audio (passthrough, if found)
 *   00:4.0  NVMe (emulated)
 *
 * GPU is presented at guest BDF 00:3.0 regardless of its real bus
 * position, so OVMF discovers it during bus 0 enumeration.
 */

#define BOGGER_MAX_PASSTHROUGH_BARS  6
#define BOGGER_MAX_PASSTHROUGH_DEVS  4

/* Fixed guest BDFs for passthrough devices on bus 0 */
#define GUEST_GPU_BDF      0x0018  /* 00:3.0 */
#define GUEST_GPU_AUD_BDF  0x0019  /* 00:3.1 */

struct bogger_passthrough_bar {
    u64  gpa;       /* Guest Physical Address (= Host Physical for identity map) */
    u64  hpa;       /* Host Physical Address */
    u64  size;      /* BAR size in bytes */
    int  bar_idx;   /* PCI BAR index (0–5) */
    bool is_mmio;   /* true=MMIO, false=IO port */
    bool is_64bit;  /* 64-bit BAR (consumes two BAR slots) */
    bool mapped;    /* Already mapped in NPT? */
};

struct bogger_passthrough_dev {
    struct pci_dev *pdev;
    u16  vendor_id;
    u16  device_id;
    u8   bus, devfn;        /* Real host bus/devfn */
    u32  guest_bdf;         /* Guest-visible BDF (on bus 0) */
    bool active;
    bool was_bound;         /* Had a driver before we took it */
    char orig_driver[32];   /* Original driver name for restoration */
    struct bogger_passthrough_bar bars[BOGGER_MAX_PASSTHROUGH_BARS];
    int  num_bars;

    /* Shadow BAR registers — guest-written PCI BAR values.
     * OVMF assigns its own BAR addresses.  We track them here so we can:
     *   - Return them on config reads (OVMF sees consistent values)
     *   - Lazily create NPT mappings guest_gpa → hardware_hpa on NPF */
    u32  shadow_bar[6];     /* Guest-written BAR register values (raw, incl type bits) */
    bool shadow_bar_set[6]; /* true after guest wrote a non-probe value */
    u32  shadow_rom_bar;    /* Guest-written ROM BAR register value */
    bool shadow_rom_set;    /* true after guest wrote a non-probe ROM BAR value */

    /* Expansion ROM (VBIOS / UEFI GOP driver for display output) */
    u64  rom_hpa;       /* Host physical address of ROM BAR region */
    u64  rom_size;      /* ROM region size in bytes */
    bool rom_mapped;    /* ROM region mapped in NPT? */

    /* IOMMU: DMA remapping domain for this device */
    struct iommu_domain *iommu_dom;
    struct iommu_group  *iommu_grp;  /* IOMMU group (shared with audio func) */
    bool iommu_attached;
    bool iommu_group_claimed; /* true if iommu_group_claim_dma_owner() succeeded */

    /* MSI: host IRQ for interrupt forwarding to guest */
    int  msi_irqs;          /* Number of MSI vectors allocated */
    int  msi_host_irq;      /* Linux IRQ number for MSI vector 0 */
    u8   msi_guest_vector;  /* Guest interrupt vector to inject */
    bool msi_enabled;
    u8   msi_cap_off;       /* PCI config offset of MSI capability (from pdev->msi_cap) */
    u8   msix_cap_off;      /* PCI config offset of MSI-X capability (from pdev->msix_cap) */
};

/* Module parameters (defined in bogger_kmod.c) */
extern char *bogger_gpu_bdf;
extern bool  bogger_passthrough_gpu;

/* Extern device array */
extern struct bogger_passthrough_dev passthrough_devs[BOGGER_MAX_PASSTHROUGH_DEVS];
extern int passthrough_dev_count;

/* API */
int  bogger_pci_passthrough_init(void);
void bogger_pci_passthrough_free(void);
int  bogger_pci_passthrough_map_bars(void);

/* IOMMU DMA remapping: map guest RAM pages so GPU can DMA correctly */
int  bogger_pci_passthrough_setup_iommu(void);
void bogger_pci_passthrough_teardown_iommu(void);

/* MSI interrupt forwarding: catch GPU IRQ, inject into guest */
int  bogger_pci_passthrough_setup_msi(void);
void bogger_pci_passthrough_teardown_msi(void);

/* Atomic flag: set by MSI IRQ handler, consumed by VMRUN loop */
extern atomic_t bogger_pt_irq_pending;
extern atomic_t bogger_pt_irq_vector;

/* Flag: set when lazy_map_bar_region() modifies NPT during IOIO handling.
 * VMRUN loop must flush TLB when this is set after IOIO exit. */
extern bool bogger_npt_dirty_from_ioio;

/* PCI config space passthrough for a specific guest BDF */
bool bogger_pci_passthrough_config_read(u32 bdf, u32 reg, u32 *val);
bool bogger_pci_passthrough_config_write(u32 bdf, u32 reg, u32 val, int size);

/* Check if a GPA falls in a passthrough BAR region */
bool bogger_pci_passthrough_is_bar(u64 gpa);

/* Lazy NPT mapping for passthrough BAR accesses.
 * Called from NPF handler. Returns true if gpa is in a passthrough region;
 * *hpa_out is set to the corresponding host physical address for mapping. */
bool bogger_pci_passthrough_resolve_npf(u64 gpa, u64 *hpa_out);

/* Compute the guest GPA for a BAR (using shadow or hardware values) */
u64 bogger_pci_passthrough_get_bar_gpa(struct bogger_passthrough_dev *ptdev,
                                        struct bogger_passthrough_bar *bar);

#endif

