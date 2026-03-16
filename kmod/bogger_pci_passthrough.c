// SPDX-License-Identifier: GPL-2.0
/*
 * bogger_pci_passthrough.c – PCI device passthrough for GPU
 *
 * On bare-metal AMD systems, this module:
 *   1. Finds the GPU by BDF (e.g. "01:00.0")
 *   2. Unbinds it from its host driver (e.g. amdgpu, nvidia)
 *   3. Reads all BAR addresses and sizes
 *   4. Identity-maps the BARs into the guest NPT
 *   5. Sets up IOMMU DMA remapping (so GPU can DMA to guest RAM)
 *   6. Registers MSI IRQ handler for interrupt forwarding
 *   7. Maps GPU at guest BDF 00:3.0 so OVMF discovers it
 *
 * In QEMU debug mode, passthrough is disabled — QEMU provides a
 * virtual QXL/VGA instead, and the guest sees that via BOGGER's
 * existing VGA I/O port emulation.
 */
#include "bogger_pci_passthrough.h"
#include "bogger_npt.h"
#include <linux/iommu.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/pci.h>

struct bogger_passthrough_dev passthrough_devs[BOGGER_MAX_PASSTHROUGH_DEVS];
int passthrough_dev_count;

/* BAR emulation state — prevents guest from relocating hardware BARs.
 * Hardware BARs stay at their BIOS-assigned addresses; the NPT identity
 * mapping remains correct.  We emulate BAR sizing probes locally. */
static bool pt_bar_probing[BOGGER_MAX_PASSTHROUGH_DEVS][6];
static bool pt_rom_probing[BOGGER_MAX_PASSTHROUGH_DEVS];

/* Atomic IRQ flag: set by MSI handler, consumed by VMRUN loop */
atomic_t bogger_pt_irq_pending = ATOMIC_INIT(0);
atomic_t bogger_pt_irq_vector  = ATOMIC_INIT(0);

/* Flag: set when lazy_map_bar_region() modifies NPT entries during IOIO handling.
 * The VMRUN loop checks this after IOIO exits and flushes the TLB if set.
 * Without this, stale zero-page TLB entries prevent GPU BAR access. */
bool bogger_npt_dirty_from_ioio;

/* Forward declaration — defined below after is_bar()/resolve_npf() */
static void lazy_map_bar_region(u64 guest_base, u64 hpa_base, u64 size);

/* ═══════════════════════════════════════════════════════════════════
 * Find our bar entry for a PCI BAR index (0–5).
 * A 64-bit BAR at index N consumes index N+1 for the high 32 bits.
 * ═══════════════════════════════════════════════════════════════════ */
static struct bogger_passthrough_bar *find_bar_by_pci_idx(
        struct bogger_passthrough_dev *ptdev, int pci_bar_idx, bool *is_high_half)
{
    int b;
    *is_high_half = false;
    for (b = 0; b < ptdev->num_bars; b++) {
        struct bogger_passthrough_bar *bar = &ptdev->bars[b];
        if (bar->bar_idx == pci_bar_idx)
            return bar;
        if (bar->is_64bit && bar->bar_idx + 1 == pci_bar_idx) {
            *is_high_half = true;
            return bar;
        }
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 * Parse BDF string "XX:XX.X" into bus/dev/fn
 * ═══════════════════════════════════════════════════════════════════ */
static int parse_bdf(const char *bdf_str, u8 *bus, u8 *dev, u8 *fn)
{
    unsigned int b, d, f;
    if (!bdf_str || bdf_str[0] == '\0')
        return -EINVAL;
    if (sscanf(bdf_str, "%x:%x.%x", &b, &d, &f) != 3)
        return -EINVAL;
    *bus = (u8)b;
    *dev = (u8)d;
    *fn  = (u8)f;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * Read BAR info from a PCI device
 * ═══════════════════════════════════════════════════════════════════ */
static int read_bars(struct bogger_passthrough_dev *ptdev)
{
    struct pci_dev *pdev = ptdev->pdev;
    int i;

    ptdev->num_bars = 0;

    for (i = 0; i < 6; i++) {
        struct bogger_passthrough_bar *bar;
        resource_size_t start, len;
        unsigned long flags;

        start = pci_resource_start(pdev, i);
        len   = pci_resource_len(pdev, i);
        flags = pci_resource_flags(pdev, i);

        if (len == 0)
            continue;

        bar = &ptdev->bars[ptdev->num_bars];
        bar->bar_idx = i;
        bar->hpa     = (u64)start;
        bar->gpa     = (u64)start;  /* Identity mapping! */
        bar->size    = (u64)len;
        bar->is_mmio = !!(flags & IORESOURCE_MEM);
        bar->is_64bit = !!(flags & IORESOURCE_MEM_64);
        bar->mapped  = false;

        pr_info("[BOGGER-PT] BAR%d: HPA=0x%llx size=0x%llx %s%s\n",
                i, bar->hpa, bar->size,
                bar->is_mmio ? "MMIO" : "IO",
                bar->is_64bit ? " 64-bit" : "");

        ptdev->num_bars++;

        /* 64-bit BAR occupies two slots */
        if (bar->is_64bit)
            i++;
    }

    /* Read expansion ROM BAR (VBIOS containing UEFI GOP driver) */
    {
        resource_size_t rom_start = pci_resource_start(pdev, PCI_ROM_RESOURCE);
        resource_size_t rom_len   = pci_resource_len(pdev, PCI_ROM_RESOURCE);
        if (rom_start && rom_len > 0) {
            ptdev->rom_hpa  = (u64)rom_start;
            ptdev->rom_size = (u64)rom_len;
            pr_info("[BOGGER-PT] ROM BAR: HPA=0x%llx size=0x%llx (%llu KB)\n",
                    ptdev->rom_hpa, ptdev->rom_size,
                    (unsigned long long)(ptdev->rom_size >> 10));
        } else {
            ptdev->rom_hpa  = 0;
            ptdev->rom_size = 0;
            pr_info("[BOGGER-PT] No expansion ROM detected\n");
        }
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * Unbind device from host driver
 * ═══════════════════════════════════════════════════════════════════ */
static int unbind_device(struct bogger_passthrough_dev *ptdev)
{
    struct pci_dev *pdev = ptdev->pdev;
    struct device_driver *drv;

    drv = pdev->dev.driver;
    if (drv) {
        strncpy(ptdev->orig_driver, drv->name, sizeof(ptdev->orig_driver) - 1);
        ptdev->was_bound = true;
        pr_info("[BOGGER-PT] Unbinding %04x:%02x:%02x.%x from driver '%s'\n",
                pci_domain_nr(pdev->bus), pdev->bus->number,
                PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn),
                drv->name);

        /* Release the device from its driver */
        device_release_driver(&pdev->dev);
    } else {
        ptdev->was_bound = false;
        pr_info("[BOGGER-PT] Device %04x:%02x:%02x.%x has no driver bound\n",
                pci_domain_nr(pdev->bus), pdev->bus->number,
                PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
    }

    /* Disable INTx, we handle interrupts ourselves */
    pci_intx(pdev, 0);

    /* ═══ GPU Reset Sequence ═══
     * AMD/NVIDIA GPUs need a careful reset sequence to come up in a clean
     * state that OVMF's GOP driver can reinitialize.  A simple FLR is often
     * insufficient — the GPU's display PHYs, memory controller, and power
     * management need time to stabilize.
     *
     * Sequence:
     *   1. Ensure device is in D0 before any reset
     *   2. D3hot → wait → D0 (full power cycle)
     *   3. FLR or bus reset
     *   4. Wait for GPU internal init to complete
     *   5. Re-enable device and verify accessibility
     */

    /* Step 1: Ensure device is in D0 (required before FLR) */
    pci_set_power_state(pdev, PCI_D0);
    msleep(50);

    /* Step 2: Full D3hot → D0 power cycle.
     * This resets internal GPU state more thoroughly than FLR alone.
     * AMD GPUs in particular need this to reset the display controller
     * and PHY layers so UEFI GOP can reinitialize them. */
    pr_info("[BOGGER-PT] Power cycling %s: D0 → D3hot → D0\n", pci_name(pdev));
    pci_set_power_state(pdev, PCI_D3hot);
    msleep(100);
    pci_set_power_state(pdev, PCI_D0);
    msleep(100);

    /* Step 3: FLR (Function Level Reset) — put GPU into a known initial state.
     * pci_reset_function() tries FLR first, then PM reset, then bus reset.
     * After FLR, the device's config space is reset to power-on defaults
     * except for BARs and a few sticky bits. */
    {
        int reset_ret;

        pr_info("[BOGGER-PT] Performing FLR on %s...\n", pci_name(pdev));
        reset_ret = pci_reset_function(pdev);
        if (reset_ret == 0) {
            pr_info("[BOGGER-PT] FLR reset completed for %s\n", pci_name(pdev));
        } else if (reset_ret == -ENOTTY) {
            pr_info("[BOGGER-PT] Device %s does not support FLR, trying bus reset\n",
                    pci_name(pdev));
            if (pci_reset_bus(pdev) == 0)
                pr_info("[BOGGER-PT] Bus reset completed for %s\n", pci_name(pdev));
            else
                pr_warn("[BOGGER-PT] Bus reset also failed for %s\n", pci_name(pdev));
        } else {
            pr_warn("[BOGGER-PT] FLR failed for %s: %d, trying bus reset\n",
                    pci_name(pdev), reset_ret);
            if (pci_reset_bus(pdev) == 0)
                pr_info("[BOGGER-PT] Bus reset completed as fallback for %s\n",
                        pci_name(pdev));
        }
    }

    /* Step 4: Wait for GPU to complete internal initialization.
     * After FLR, the GPU's microcontroller reboots.  AMD GPUs typically
     * need 100-500ms for the SMU/PSP to come up.  Without this delay,
     * config space reads may return 0xFFFFFFFF (device not ready). */
    msleep(200);

    /* Verify device is accessible after reset */
    {
        u16 vendor;
        pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor);
        if (vendor == 0xFFFF) {
            pr_warn("[BOGGER-PT] Device not responding after reset, waiting longer...\n");
            msleep(500);
            pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor);
            if (vendor == 0xFFFF)
                pr_err("[BOGGER-PT] Device STILL not responding! GPU passthrough may fail.\n");
            else
                pr_info("[BOGGER-PT] Device came back after extended wait (vendor=0x%04x)\n", vendor);
        } else {
            pr_info("[BOGGER-PT] Device responsive after reset (vendor=0x%04x)\n", vendor);
        }
    }

    /* Step 5: Pre-enable the GPU: set power state D0, enable MMIO/IO/BusMaster
     * so OVMF can actually access the hardware when it discovers the device. */
    pci_set_power_state(pdev, PCI_D0);
    if (pci_enable_device(pdev) == 0) {
        pci_set_master(pdev);
        pr_info("[BOGGER-PT] GPU pre-enabled: D0 + MEM/IO/BusMaster\n");
    } else {
        u16 cmd;
        pr_warn("[BOGGER-PT] pci_enable_device failed, setting CMD manually\n");
        pci_read_config_word(pdev, PCI_COMMAND, &cmd);
        cmd |= PCI_COMMAND_MEMORY | PCI_COMMAND_IO | PCI_COMMAND_MASTER;
        pci_write_config_word(pdev, PCI_COMMAND, cmd);
    }

    /* Small delay for device to stabilize after re-enable */
    msleep(50);

    /* Verify PCIe link status — if link is down, display will never work */
    {
        int exp_cap = pci_find_capability(pdev, PCI_CAP_ID_EXP);
        if (exp_cap) {
            u16 link_sta;
            pci_read_config_word(pdev, exp_cap + PCI_EXP_LNKSTA, &link_sta);
            pr_info("[BOGGER-PT] PCIe Link: speed=%d width=x%d training=%d\n",
                    link_sta & PCI_EXP_LNKSTA_CLS,
                    (link_sta & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT,
                    !!(link_sta & PCI_EXP_LNKSTA_LT));
            if ((link_sta & PCI_EXP_LNKSTA_NLW) == 0) {
                pr_err("[BOGGER-PT] PCIe link width is 0! Link is DOWN.\n");
                pr_err("[BOGGER-PT] Trying secondary bus reset to retrain link...\n");
                pci_reset_bus(pdev);
                msleep(200);
                pci_read_config_word(pdev, exp_cap + PCI_EXP_LNKSTA, &link_sta);
                pr_info("[BOGGER-PT] PCIe Link after bus reset: speed=%d width=x%d\n",
                        link_sta & PCI_EXP_LNKSTA_CLS,
                        (link_sta & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT);
            }
        }
    }

    /* Enable expansion ROM access so OVMF can read the VBIOS/GOP driver.
     * FLR may have cleared the ROM BAR address, so we restore it from
     * the kernel's PCI resource (set during boot enumeration). */
    {
        u32 rom_bar;
        resource_size_t rom_res = pci_resource_start(pdev, PCI_ROM_RESOURCE);
        resource_size_t rom_len = pci_resource_len(pdev, PCI_ROM_RESOURCE);

        pci_read_config_dword(pdev, PCI_ROM_ADDRESS, &rom_bar);
        pr_info("[BOGGER-PT] ROM BAR hw=0x%08x, kernel resource=0x%llx len=0x%llx\n",
                rom_bar, (u64)rom_res, (u64)rom_len);

        if ((rom_bar & ~0x01U) == 0 && rom_res != 0) {
            /* ROM BAR was cleared (e.g., by FLR) — restore from kernel resource */
            pci_write_config_dword(pdev, PCI_ROM_ADDRESS,
                                   (u32)rom_res | PCI_ROM_ADDRESS_ENABLE);
            pr_info("[BOGGER-PT] ROM BAR restored: 0x%08x (from kernel resource)\n",
                    (u32)rom_res);
        } else if (rom_bar & ~0x01U) {
            pci_write_config_dword(pdev, PCI_ROM_ADDRESS,
                                   rom_bar | PCI_ROM_ADDRESS_ENABLE);
            pr_info("[BOGGER-PT] ROM enabled at 0x%08x\n", rom_bar & ~0x01U);
        } else {
            pr_warn("[BOGGER-PT] No ROM BAR available! GPU GOP driver may not load.\n");
        }

        /* Verify ROM is accessible: check for PCI ROM signature 0xAA55
         * and walk the PCI Data Structure chain to look for UEFI GOP image */
        {
            u32 rom_addr;
            pci_read_config_dword(pdev, PCI_ROM_ADDRESS, &rom_addr);
            if (rom_addr & PCI_ROM_ADDRESS_ENABLE) {
                void __iomem *rom;
                size_t rom_actual_size;
                rom = pci_map_rom(pdev, &rom_actual_size);
                if (rom) {
                    u16 sig = readw(rom);
                    pr_info("[BOGGER-PT] ROM signature: 0x%04x (%s), size=%zu bytes\n",
                            sig, sig == 0xAA55 ? "VALID" : "INVALID", rom_actual_size);

                    /* Walk PCI ROM images looking for Code Type 3 (EFI) */
                    if (sig == 0xAA55) {
                        u32 image_off = 0;
                        int img_num = 0;
                        bool found_efi = false;
                        while (image_off < rom_actual_size - 4) {
                            u16 isig = readw(rom + image_off);
                            u16 pcir_off;
                            u8 code_type, indicator;
                            u16 img_len;
                            if (isig != 0xAA55) break;
                            pcir_off = readw(rom + image_off + 0x18);
                            if (pcir_off == 0 || image_off + pcir_off + 0x14 > rom_actual_size)
                                break;
                            /* PCIR signature check */
                            if (readl(rom + image_off + pcir_off) != 0x52494350) /* "PCIR" */
                                break;
                            code_type = readb(rom + image_off + pcir_off + 0x14);
                            img_len = readw(rom + image_off + pcir_off + 0x10); /* in 512B units */
                            indicator = readb(rom + image_off + pcir_off + 0x15);
                            pr_info("[BOGGER-PT] ROM image %d: CodeType=%d (%s) size=%u KB\n",
                                img_num, code_type,
                                code_type == 0 ? "x86 BIOS" :
                                code_type == 1 ? "OpenFirmware" :
                                code_type == 3 ? "EFI/UEFI" : "unknown",
                                (unsigned)(img_len / 2));
                            if (code_type == 3)
                                found_efi = true;
                            if (indicator & 0x80) break; /* last image */
                            image_off += (u32)img_len * 512;
                            img_num++;
                            if (img_num > 8) break; /* safety */
                        }
                        if (found_efi)
                            pr_info("[BOGGER-PT] UEFI GOP driver FOUND in ROM\n");
                        else
                            pr_warn("[BOGGER-PT] WARNING: No UEFI GOP driver in ROM! Display may not work.\n");
                    }
                    pci_unmap_rom(pdev, rom);
                    /* pci_unmap_rom() called pci_disable_rom() which cleared
                     * the ROM enable bit.  Re-enable it so the ROM content
                     * is accessible via identity-mapped NPT before OVMF
                     * reassigns the ROM BAR address. */
                    {
                        u32 cur_rom;
                        pci_read_config_dword(pdev, PCI_ROM_ADDRESS, &cur_rom);
                        if (!(cur_rom & PCI_ROM_ADDRESS_ENABLE)) {
                            pci_write_config_dword(pdev, PCI_ROM_ADDRESS,
                                                   cur_rom | PCI_ROM_ADDRESS_ENABLE);
                            pr_info("[BOGGER-PT] ROM re-enabled after unmap (0x%08x)\n",
                                    cur_rom | PCI_ROM_ADDRESS_ENABLE);
                        }
                    }
                } else {
                    pr_warn("[BOGGER-PT] pci_map_rom() failed — ROM may not be accessible\n");
                }
            }
        }
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * Re-bind device to original driver (on module unload)
 * ═══════════════════════════════════════════════════════════════════ */
static void rebind_device(struct bogger_passthrough_dev *ptdev)
{
    struct pci_dev *pdev = ptdev->pdev;

    if (!pdev || !ptdev->active)
        return;

    /* Re-enable the device */
    if (pci_enable_device(pdev))
        pr_warn("[BOGGER-PT] Failed to re-enable device\n");
    pci_intx(pdev, 1);

    if (ptdev->was_bound && ptdev->orig_driver[0] != '\0') {
        pr_info("[BOGGER-PT] Requesting re-probe for device (was: %s)\n",
                ptdev->orig_driver);
        /* Trigger re-probing — the driver core will rebind */
        if (device_attach(&pdev->dev) <= 0)
            pr_warn("[BOGGER-PT] Re-probe failed, device may need manual rebind\n");
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * Main init: find device, unbind, read BARs
 * ═══════════════════════════════════════════════════════════════════ */
int bogger_pci_passthrough_init(void)
{
    u8 bus, dev, fn;
    struct pci_dev *pdev;
    struct bogger_passthrough_dev *ptdev;
    int ret;

    passthrough_dev_count = 0;

    if (!bogger_passthrough_gpu || !bogger_gpu_bdf ||
        bogger_gpu_bdf[0] == '\0') {
        pr_info("[BOGGER-PT] GPU passthrough disabled\n");
        return 0;
    }

    ret = parse_bdf(bogger_gpu_bdf, &bus, &dev, &fn);
    if (ret) {
        pr_err("[BOGGER-PT] Invalid GPU BDF: '%s' (format: XX:XX.X)\n",
               bogger_gpu_bdf);
        return ret;
    }

    pr_info("[BOGGER-PT] Looking for GPU at PCI %02x:%02x.%x\n", bus, dev, fn);

    pdev = pci_get_domain_bus_and_slot(0, bus, PCI_DEVFN(dev, fn));
    if (!pdev) {
        pr_err("[BOGGER-PT] PCI device %02x:%02x.%x not found!\n", bus, dev, fn);
        return -ENODEV;
    }

    ptdev = &passthrough_devs[0];
    memset(ptdev, 0, sizeof(*ptdev));
    ptdev->pdev      = pdev;
    ptdev->vendor_id  = pdev->vendor;
    ptdev->device_id  = pdev->device;
    ptdev->bus        = bus;
    ptdev->devfn      = PCI_DEVFN(dev, fn);
    ptdev->guest_bdf  = GUEST_GPU_BDF;
    ptdev->active     = true;
    ptdev->msi_cap_off  = pdev->msi_cap;
    ptdev->msix_cap_off = pdev->msix_cap;

    pr_info("[BOGGER-PT] Found GPU: %04x:%04x (%s) msi_cap=0x%02x msix_cap=0x%02x\n",
            ptdev->vendor_id, ptdev->device_id,
            pci_name(pdev), ptdev->msi_cap_off, ptdev->msix_cap_off);

    /* Unbind from host driver */
    ret = unbind_device(ptdev);
    if (ret) {
        pci_dev_put(pdev);
        return ret;
    }

    /* Read BAR configuration */
    ret = read_bars(ptdev);
    if (ret) {
        rebind_device(ptdev);
        pci_dev_put(pdev);
        return ret;
    }

    passthrough_dev_count = 1;

    /* Also handle audio function (typically .1) on same GPU */
    {
        struct pci_dev *audio_dev;
        audio_dev = pci_get_domain_bus_and_slot(0, bus, PCI_DEVFN(dev, 1));
        if (audio_dev && passthrough_dev_count < BOGGER_MAX_PASSTHROUGH_DEVS) {
            struct bogger_passthrough_dev *apt = &passthrough_devs[passthrough_dev_count];
            memset(apt, 0, sizeof(*apt));
            apt->pdev      = audio_dev;
            apt->vendor_id = audio_dev->vendor;
            apt->device_id = audio_dev->device;
            apt->bus       = bus;
            apt->devfn     = PCI_DEVFN(dev, 1);
            apt->guest_bdf = GUEST_GPU_AUD_BDF;
            apt->active    = true;
            apt->msi_cap_off  = audio_dev->msi_cap;
            apt->msix_cap_off = audio_dev->msix_cap;

            pr_info("[BOGGER-PT] Found GPU audio: %04x:%04x\n",
                    apt->vendor_id, apt->device_id);

            unbind_device(apt);
            read_bars(apt);
            passthrough_dev_count++;
        }
    }

    pr_info("[BOGGER-PT] %d device(s) ready for passthrough\n",
            passthrough_dev_count);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * Map all passthrough BAR regions into guest NPT (identity-mapped)
 * Call AFTER bogger_npt_init()!
 * ═══════════════════════════════════════════════════════════════════ */
int bogger_pci_passthrough_map_bars(void)
{
    int d, b;

    if (passthrough_dev_count == 0)
        return 0;

    for (d = 0; d < passthrough_dev_count; d++) {
        struct bogger_passthrough_dev *ptdev = &passthrough_devs[d];
        if (!ptdev->active) continue;

        for (b = 0; b < ptdev->num_bars; b++) {
            struct bogger_passthrough_bar *bar = &ptdev->bars[b];
            u64 gpa, hpa, end;
            unsigned int pd_idx, pd_e, pt_e;
            u64 *pt;

            if (!bar->is_mmio || bar->size == 0)
                continue;

            pr_info("[BOGGER-PT] Mapping BAR%d: GPA=0x%llx → HPA=0x%llx (%llu MB)\n",
                    bar->bar_idx, bar->gpa, bar->hpa,
                    (unsigned long long)(bar->size >> 20));

            /* Map page-by-page into NPT.
             * For large BARs (GPU VRAM = 256MB–16GB), we use 2MB pages
             * where possible for efficiency. */
            gpa = bar->gpa & ~0xFFFULL;
            hpa = bar->hpa & ~0xFFFULL;
            end = bar->gpa + bar->size;

            while (gpa < end) {
                pd_idx = (unsigned int)(gpa >> 30);
                pd_e   = (unsigned int)((gpa >> 21) & 0x1FF);
                pt_e   = (unsigned int)((gpa >> 12) & 0x1FF);

                if (pd_idx >= NPT_NUM_PD_TABLES) {
                    pr_warn("[BOGGER-PT] BAR GPA 0x%llx exceeds NPT range\n", gpa);
                    break;
                }

                /* Lazily allocate PD table if needed (for high GPU BARs) */
                if (!npt_pd_tables[pd_idx]) {
                    npt_pd_tables[pd_idx] = (u64 *)get_zeroed_page(GFP_KERNEL);
                    if (!npt_pd_tables[pd_idx]) {
                        pr_err("[BOGGER-PT] Failed to alloc PD table %u\n", pd_idx);
                        return -ENOMEM;
                    }
                    /* Wire into PDPT */
                    npt_pdpt[pd_idx] = virt_to_phys(npt_pd_tables[pd_idx]) | 0x07ULL;
                    pr_info("[BOGGER-PT] Lazily allocated PD table %u for BAR mapping\n", pd_idx);
                }

                /* Try 2MB page if aligned and large enough */
                if ((gpa & ((1ULL << 21) - 1)) == 0 &&
                    (hpa & ((1ULL << 21) - 1)) == 0 &&
                    (end - gpa) >= (1ULL << 21)) {
                    /* 2MB large page: set bit 7 (PS) + RWX + UC */
                    npt_pd_tables[pd_idx][pd_e] = hpa | 0x87ULL | (1ULL << 4); /* PS + UC-ish */
                    gpa += (1ULL << 21);
                    hpa += (1ULL << 21);
                    continue;
                }

                /* 4KB page: ensure PT exists */
                if (!(npt_pd_tables[pd_idx][pd_e] & 0x01ULL)) {
                    u64 *new_pt = (u64 *)get_zeroed_page(GFP_KERNEL);
                    if (!new_pt) {
                        pr_err("[BOGGER-PT] Failed to alloc PT page\n");
                        return -ENOMEM;
                    }
                    npt_pd_tables[pd_idx][pd_e] = virt_to_phys(new_pt) | 0x07ULL;
                }

                /* Break 2MB page if PS bit is set */
                if (npt_pd_tables[pd_idx][pd_e] & (1ULL << 7)) {
                    u64 base_2mb = gpa & ~((1ULL << 21) - 1);
                    u64 *new_pt = (u64 *)get_zeroed_page(GFP_KERNEL);
                    unsigned int k;
                    if (!new_pt) return -ENOMEM;
                    for (k = 0; k < 512; k++)
                        new_pt[k] = (base_2mb + ((u64)k << 12)) | 0x07ULL;
                    npt_pd_tables[pd_idx][pd_e] = virt_to_phys(new_pt) | 0x07ULL;
                }

                pt = (u64 *)phys_to_virt(npt_pd_tables[pd_idx][pd_e] & ~0xFFFULL);
                pt[pt_e] = hpa | 0x17ULL;  /* RWX + PCD (UC- for MMIO) */

                gpa += PAGE_SIZE;
                hpa += PAGE_SIZE;
            }

            bar->mapped = true;
        }

        /* Map expansion ROM BAR into NPT (identity-mapped, 4KB pages)
         * OVMF reads the GPU VBIOS from here to find the UEFI GOP driver
         * which is required for physical display output. */
        if (ptdev->rom_hpa && ptdev->rom_size > 0 && !ptdev->rom_mapped) {
            u64 gpa = ptdev->rom_hpa & ~0xFFFULL;
            u64 hpa = gpa;
            u64 end = (ptdev->rom_hpa + ptdev->rom_size + 0xFFF) & ~0xFFFULL;
            unsigned int pd_idx, pd_e, pt_e;
            u64 *pt;

            pr_info("[BOGGER-PT] Mapping ROM: GPA=0x%llx -> HPA=0x%llx (%llu KB)\n",
                    gpa, hpa, (unsigned long long)((end - gpa) >> 10));

            while (gpa < end) {
                pd_idx = (unsigned int)(gpa >> 30);
                pd_e   = (unsigned int)((gpa >> 21) & 0x1FF);
                pt_e   = (unsigned int)((gpa >> 12) & 0x1FF);

                if (pd_idx >= NPT_NUM_PD_TABLES) {
                    pr_warn("[BOGGER-PT] ROM GPA 0x%llx exceeds NPT range\n", gpa);
                    break;
                }

                if (!npt_pd_tables[pd_idx]) {
                    npt_pd_tables[pd_idx] = (u64 *)get_zeroed_page(GFP_KERNEL);
                    if (!npt_pd_tables[pd_idx]) {
                        pr_err("[BOGGER-PT] Failed to alloc PD table for ROM\n");
                        break;
                    }
                    npt_pdpt[pd_idx] = virt_to_phys(npt_pd_tables[pd_idx]) | 0x07ULL;
                }

                /* 4KB page: ensure PT exists */
                if (!(npt_pd_tables[pd_idx][pd_e] & 0x01ULL)) {
                    u64 *new_pt = (u64 *)get_zeroed_page(GFP_KERNEL);
                    if (!new_pt) break;
                    npt_pd_tables[pd_idx][pd_e] = virt_to_phys(new_pt) | 0x07ULL;
                }

                /* Break 2MB page into 4KB if PS bit is set */
                if (npt_pd_tables[pd_idx][pd_e] & (1ULL << 7)) {
                    u64 base_2mb = gpa & ~((1ULL << 21) - 1);
                    u64 *new_pt = (u64 *)get_zeroed_page(GFP_KERNEL);
                    unsigned int k;
                    if (!new_pt) break;
                    for (k = 0; k < 512; k++)
                        new_pt[k] = (base_2mb + ((u64)k << 12)) | 0x07ULL;
                    npt_pd_tables[pd_idx][pd_e] = virt_to_phys(new_pt) | 0x07ULL;
                }

                pt = (u64 *)phys_to_virt(npt_pd_tables[pd_idx][pd_e] & ~0xFFFULL);
                pt[pt_e] = hpa | 0x17ULL;  /* RWX + PCD (UC- for MMIO) */

                gpa += PAGE_SIZE;
                hpa += PAGE_SIZE;
            }
            ptdev->rom_mapped = true;
        }
    }

    pr_info("[BOGGER-PT] All BAR regions mapped into NPT\n");
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * PCI config space passthrough (read)
 *
 * BAR registers (0x10–0x24) use shadow values so OVMF sees what it
 * wrote (not hardware values).  On first read before any write,
 * hardware values are returned.  ROM BAR (0x30) is similar.
 * ═══════════════════════════════════════════════════════════════════ */
bool bogger_pci_passthrough_config_read(u32 bdf, u32 reg, u32 *val)
{
    int d;
    for (d = 0; d < passthrough_dev_count; d++) {
        struct bogger_passthrough_dev *ptdev = &passthrough_devs[d];

        if (!ptdev->active || !ptdev->pdev) continue;
        if (ptdev->guest_bdf != bdf) continue;

        /* Log GPU config reads (first 100) for passthrough debugging */
        {
            static int pt_cfg_rd_log;
            if (pt_cfg_rd_log < 100) {
                pr_info("[BOGGER-PT] CFG RD bdf=0x%04x reg=0x%02x (dev=%02x:%02x.%x)\n",
                        bdf, reg, ptdev->bus,
                        PCI_SLOT(ptdev->devfn), PCI_FUNC(ptdev->devfn));
                pt_cfg_rd_log++;
            }
        }
        /* Always log key GPU discovery reads: vendor/device, class, ROM BAR */
        if (reg == 0x00 || reg == 0x08 || reg == 0x30) {
            u32 hw_val;
            pci_read_config_dword(ptdev->pdev, reg, &hw_val);
            pr_info("[BOGGER-PT] GPU key cfg: reg=0x%02x hw=0x%08x (vid=%04x did=%04x class=%06x)\n",
                    reg, hw_val,
                    ptdev->vendor_id, ptdev->device_id,
                    (reg == 0x08) ? (hw_val >> 8) : 0);
        }

        /* ── BAR registers (0x10–0x24) ─────────────────────── */
        if (reg >= 0x10 && reg <= 0x24) {
            int pci_bar_idx = (reg - 0x10) / 4;
            bool is_high;
            struct bogger_passthrough_bar *bar;

            bar = find_bar_by_pci_idx(ptdev, pci_bar_idx, &is_high);

            if (bar && pt_bar_probing[d][pci_bar_idx]) {
                /* Probe response: return size mask.
                 * For 64-bit BARs, present them as 32-bit to the guest
                 * so OVMF places them in the below-4GB MMIO window.
                 * Our NPT only covers 512GB, and OVMF would otherwise
                 * place large BARs at addresses like 0x380000000000
                 * which are completely unreachable. */
                u64 mask = ~(bar->size - 1);
                pt_bar_probing[d][pci_bar_idx] = false;
                if (is_high) {
                    /* High half of 64-bit BAR: return 0 to indicate
                     * no address bits needed above 32-bit.  Combined
                     * with clearing the 64-bit type bits below, this
                     * makes OVMF treat the BAR as 32-bit only. */
                    *val = 0;
                } else {
                    u32 type_bits;
                    pci_read_config_dword(ptdev->pdev, reg, &type_bits);
                    /* Force 64-bit BARs (type bits = 10b) to appear as
                     * 32-bit (type bits = 00b) so OVMF keeps them below 4G.
                     * Preserve the prefetchable bit (bit 3). */
                    if (bar->is_64bit)
                        type_bits = (type_bits & ~0x06U);  /* clear type=10 → 00 */
                    *val = ((u32)mask & ~0xFU) | (type_bits & 0xFU);
                }
                return true;
            }

            /* High half of 64-bit BAR: always return 0.
             * Since we present these as 32-bit BARs, the guest should
             * not access the high half, but if it does, return 0. */
            if (bar && bar->is_64bit && is_high) {
                *val = 0;
                return true;
            }

            /* Return shadow value if guest has written one */
            if (ptdev->shadow_bar_set[pci_bar_idx]) {
                *val = ptdev->shadow_bar[pci_bar_idx];
                return true;
            }

            /* No shadow yet: return hardware value.
             * For 64-bit BARs, mask the type bits to 32-bit. */
            pci_read_config_dword(ptdev->pdev, reg, val);
            if (bar && bar->is_64bit && !is_high)
                *val = (*val & ~0x06U);  /* clear 64-bit type bits */
            return true;
        }

        /* ── ROM BAR (0x30) ────────────────────────────────── */
        if (reg == 0x30) {
            if (pt_rom_probing[d]) {
                pt_rom_probing[d] = false;
                if (ptdev->rom_size > 0) {
                    u32 mask = ~((u32)ptdev->rom_size - 1);
                    *val = mask & 0xFFFFF800U;
                } else {
                    *val = 0;
                }
                return true;
            }
            /* Return shadow value if guest has written one */
            if (ptdev->shadow_rom_set) {
                *val = ptdev->shadow_rom_bar;
                return true;
            }
            /* No shadow: return hardware ROM BAR */
            pci_read_config_dword(ptdev->pdev, 0x30, val);
            return true;
        }

        /* ── MSI capability: return what guest expects.
         *    We shadow MSI writes, so reads must reflect guest intent,
         *    not the host's actual MSI config. ──────────────────────── */
        if (ptdev->msi_cap_off &&
            reg >= ptdev->msi_cap_off && reg < ptdev->msi_cap_off + 0x18) {
            u8 cap_base = ptdev->msi_cap_off;
            /* Read from hardware first (gives capability ID, next ptr, etc.) */
            pci_read_config_dword(ptdev->pdev, reg, val);
            /* Override the MSI Data register with guest's vector.
             * 64-bit MSI: data at cap+0x0C; 32-bit MSI: data at cap+0x08 */
            if (reg == cap_base + 0x0C || reg == cap_base + 0x08) {
                *val = (*val & 0xFFFFFF00U) | (u32)ptdev->msi_guest_vector;
            }
            /* Override MSI Message Control's enable bit with guest state */
            if (reg == cap_base) {
                if (ptdev->msi_enabled)
                    *val |= (1U << 16);      /* bit 16 = MSI Enable */
                else
                    *val &= ~(1U << 16);
            }
            return true;
        }
        /* ── MSI-X capability: also shadow reads ──────────────────── */
        if (ptdev->msix_cap_off &&
            reg >= ptdev->msix_cap_off && reg < ptdev->msix_cap_off + 0x0C) {
            pci_read_config_dword(ptdev->pdev, reg, val);
            return true;
        }

        /* ── All other registers: direct passthrough ───────── */
        pci_read_config_dword(ptdev->pdev, reg, val);
        return true;
    }
    return false;
}

/* ═══════════════════════════════════════════════════════════════════
 * PCI config space passthrough (write)
 *
 * BAR writes (0x10–0x24) are stored in shadow registers but NOT sent
 * to hardware (hardware BARs stay at BIOS-assigned addresses).
 * When OVMF probes a BAR, shadow state tracks the probe/assign cycle.
 * ROM BAR (0x30): shadow-tracked; enable bit forwarded to hardware.
 * All other writes go through to the real device.
 * ═══════════════════════════════════════════════════════════════════ */
bool bogger_pci_passthrough_config_write(u32 bdf, u32 reg, u32 val, int size)
{
    int d;
    for (d = 0; d < passthrough_dev_count; d++) {
        struct bogger_passthrough_dev *ptdev = &passthrough_devs[d];

        if (!ptdev->active || !ptdev->pdev) continue;
        if (ptdev->guest_bdf != bdf) continue;

        {
            u32 dword_reg = reg & ~3U;

            /* ── BAR registers (0x10–0x24): shadow, do NOT write to HW ── */
            if (dword_reg >= 0x10 && dword_reg <= 0x24) {
                int pci_bar_idx = (dword_reg - 0x10) / 4;
                bool is_high;
                struct bogger_passthrough_bar *bar;

                bar = find_bar_by_pci_idx(ptdev, pci_bar_idx, &is_high);

                if (val == 0xFFFFFFFF || val == 0xFFFFFFF0 ||
                    val == 0xFFFFFFFC || val == 0xFFFFFFFE) {
                    pt_bar_probing[d][pci_bar_idx] = true;
                } else {
                    pt_bar_probing[d][pci_bar_idx] = false;

                    /* For 64-bit BARs presented as 32-bit to guest:
                     * silently clamp high-half writes to 0 and skip them.
                     * The guest should not write here (we told it the BAR
                     * is 32-bit), but if it does, ensure the address
                     * stays below 4GB. */
                    if (bar && bar->is_64bit && is_high) {
                        ptdev->shadow_bar[pci_bar_idx] = 0;
                        ptdev->shadow_bar_set[pci_bar_idx] = true;
                        return true;
                    }

                    /* Save the guest-assigned BAR value */
                    ptdev->shadow_bar[pci_bar_idx] = val;
                    ptdev->shadow_bar_set[pci_bar_idx] = true;

                    if (bar && bar->is_mmio && bar->size > 0) {
                        /* For 64-bit BARs (presented as 32-bit to guest),
                         * auto-set the high half shadow to 0 so GPA
                         * computation always yields a 32-bit address. */
                        if (bar->is_64bit) {
                            int hi_idx = bar->bar_idx + 1;
                            ptdev->shadow_bar[hi_idx] = 0;
                            ptdev->shadow_bar_set[hi_idx] = true;
                        }

                        {
                            u64 guest_gpa = bogger_pci_passthrough_get_bar_gpa(ptdev, bar);
                            pr_info("[BOGGER-PT] BAR%d assigned: guest GPA=0x%llx (hw HPA=0x%llx, size=0x%llx)\n",
                                    bar->bar_idx, guest_gpa, bar->hpa, bar->size);

                            /* EAGER NPT MAPPING: create the NPT mapping NOW.
                             * The MMIO hole (0xC0000000-0xFFFFFFFF) is filled with
                             * zero-page PTEs, so no NPF would ever fire for addresses
                             * in that range.  We must map eagerly here. */
                            if (guest_gpa != 0 && guest_gpa < (512ULL << 30)) {
                                u64 old_gpa = bar->gpa;

                                /* Clean up stale NPT entries at the OLD GPA before
                                 * mapping the new location.  Without this, 2MB huge
                                 * pages from a prior BAR mapping persist and can
                                 * cause crashes when other devices (like NVMe) are
                                 * relocated into the vacated region. */
                                if (old_gpa != 0 && old_gpa != guest_gpa) {
                                    bogger_npt_restore_zero_region(old_gpa, bar->size);
                                }

                                lazy_map_bar_region(guest_gpa, bar->hpa, bar->size);
                                bar->mapped = true;
                                bar->gpa = guest_gpa;
                                pr_info("[BOGGER-PT] BAR%d eagerly mapped in NPT: GPA 0x%llx -> HPA 0x%llx\n",
                                        bar->bar_idx, guest_gpa, bar->hpa);

                                /* Update IOMMU mapping so GPU DMA using
                                 * guest-assigned BARs resolves correctly.
                                 * Without this, Windows GPU driver DMA would
                                 * fault when accessing relocated BARs. */
                                if (ptdev->iommu_dom && guest_gpa != old_gpa) {
                                    u64 a;
                                    if (old_gpa != 0 && old_gpa != bar->hpa)
                                        for (a = 0; a < bar->size; a += PAGE_SIZE)
                                            iommu_unmap(ptdev->iommu_dom, old_gpa + a, PAGE_SIZE);
                                    for (a = 0; a < bar->size; a += PAGE_SIZE)
                                        iommu_map(ptdev->iommu_dom, guest_gpa + a, bar->hpa + a,
                                                  PAGE_SIZE, IOMMU_READ | IOMMU_WRITE | IOMMU_MMIO,
                                                  GFP_KERNEL);
                                    pr_info("[BOGGER-PT] IOMMU BAR%d remapped: GPA 0x%llx -> HPA 0x%llx\n",
                                            bar->bar_idx, guest_gpa, bar->hpa);
                                }
                            }
                        }
                    } else if (bar && !bar->is_mmio && bar->size > 0) {
                        /* I/O BAR reassignment: update guest port tracking.
                         * Guest may reassign I/O BARs to different port ranges
                         * (e.g., OVMF moves GPU BAR5 from 0xd000 to 0xc000).
                         * The IOPM must be updated so the old port range is
                         * trapped and the VMEXIT handler can perform port
                         * translation (guest port → hardware port). */
                        u64 new_gpa = (u64)(val & ~0x3U);  /* mask off type bits */
                        u64 old_gpa = bar->gpa;
                        if (new_gpa != 0 && new_gpa < 0x10000) {
                            u8 *iopm = (u8 *)io_bitmap;
                            int p;

                            /* Restore old IOPM bits to TRAP if the old range
                             * differs from the new range */
                            if (iopm && old_gpa != new_gpa && old_gpa != 0) {
                                u64 old_end = old_gpa + bar->size;
                                if (old_end > 0xFFFF) old_end = 0xFFFF;
                                for (p = (int)old_gpa; p < (int)old_end; p++)
                                    iopm[p / 8] |= (1U << (p % 8));
                            }

                            bar->gpa = new_gpa;

                            /* If new GPA == HPA, enable direct passthrough */
                            if (iopm && new_gpa == bar->hpa) {
                                u64 new_end = new_gpa + bar->size;
                                if (new_end > 0xFFFF) new_end = 0xFFFF;
                                for (p = (int)new_gpa; p < (int)new_end; p++)
                                    iopm[p / 8] &= ~(1U << (p % 8));
                                pr_info("[BOGGER-PT] I/O BAR%d: GPA=HPA=0x%llx, IOPM direct passthrough\n",
                                        bar->bar_idx, new_gpa);
                            } else {
                                /* GPA != HPA: ensure new range is TRAPPED so
                                 * pt_iobar_in/out can translate ports */
                                if (iopm) {
                                    u64 new_end = new_gpa + bar->size;
                                    if (new_end > 0xFFFF) new_end = 0xFFFF;
                                    for (p = (int)new_gpa; p < (int)new_end; p++)
                                        iopm[p / 8] |= (1U << (p % 8));
                                }
                                pr_info("[BOGGER-PT] I/O BAR%d: GPA=0x%llx -> HPA=0x%llx, VMEXIT+translate\n",
                                        bar->bar_idx, new_gpa, bar->hpa);
                            }
                        }
                    }
                }
                return true;
            }

            /* ── ROM BAR (0x30): shadow + forward enable bit ────────── */
            if (dword_reg == 0x30) {
                if ((val & 0xFFFFF800U) == 0xFFFFF800U || val == 0xFFFFFFFF) {
                    pt_rom_probing[d] = true;
                } else {
                    pt_rom_probing[d] = false;
                    ptdev->shadow_rom_bar = val;
                    ptdev->shadow_rom_set = true;

                    /* Forward ROM enable bit (bit 0) to real hardware */
                    {
                        u32 rom_reg;
                        pci_read_config_dword(ptdev->pdev, 0x30, &rom_reg);
                        rom_reg = (rom_reg & ~1U) | (val & 1U);
                        pci_write_config_dword(ptdev->pdev, 0x30, rom_reg);
                    }

                    /* EAGER NPT MAPPING for ROM BAR.  Same zero-page issue
                     * as regular BARs — must map immediately. */
                    if (ptdev->rom_hpa && ptdev->rom_size > 0) {
                        u64 rom_gpa = (u64)(val & 0xFFFFF800U);
                        if (rom_gpa != 0 && rom_gpa < (512ULL << 30)) {
                            lazy_map_bar_region(rom_gpa, ptdev->rom_hpa, ptdev->rom_size);
                            ptdev->rom_mapped = true;
                            pr_info("[BOGGER-PT] ROM eagerly mapped in NPT: GPA 0x%llx -> HPA 0x%llx (%llu KB)\n",
                                    rom_gpa, ptdev->rom_hpa,
                                    (unsigned long long)(ptdev->rom_size >> 10));
                        }
                    }

                    pr_info("[BOGGER-PT] ROM BAR assigned: guest GPA=0x%08x enable=%d (hw=0x%llx)\n",
                            val & 0xFFFFF800U, !!(val & 1), ptdev->rom_hpa);

                    /* Verify ROM accessibility when enable bit is set */
                    if (val & 1) {
                        size_t rom_verify_size = 0;
                        void __iomem *rom = pci_map_rom(ptdev->pdev, &rom_verify_size);
                        if (rom) {
                            u8 sig0 = readb(rom);
                            u8 sig1 = readb(rom + 1);
                            pr_info("[BOGGER-PT] ROM verify after enable: sig=0x%02x%02x (%s), size=%zu\n",
                                    sig0, sig1,
                                    (sig0 == 0x55 && sig1 == 0xAA) ? "VALID" : "INVALID",
                                    rom_verify_size);
                            pci_unmap_rom(ptdev->pdev, rom);
                            /* Re-enable ROM after pci_unmap_rom clears enable */
                            {
                                u32 re_rom;
                                pci_read_config_dword(ptdev->pdev, 0x30, &re_rom);
                                if (!(re_rom & 1)) {
                                    pci_write_config_dword(ptdev->pdev, 0x30, re_rom | 1);
                                }
                            }
                        } else {
                            pr_warn("[BOGGER-PT] ROM verify: pci_map_rom FAILED!\n");
                        }
                    }
                }
                return true;
            }

            /* ── MSI capability: shadow writes, do NOT forward to hardware.
             *    The host-allocated MSI config must stay intact. ──────── */
            if (ptdev->msi_cap_off && reg >= ptdev->msi_cap_off && reg < ptdev->msi_cap_off + 0x18) {
                u8 cap_base = ptdev->msi_cap_off;
                /* MSI Message Data: extract guest vector.
                 * 64-bit MSI: data at cap+0x0C; 32-bit MSI: data at cap+0x08 */
                if (reg == cap_base + 0x0C || reg == cap_base + 0x0D ||
                    reg == cap_base + 0x08 || reg == cap_base + 0x09) {
                    u8 new_vec = (u8)(val & 0xFF);
                    if (new_vec >= 0x20 && new_vec != ptdev->msi_guest_vector) {
                        pr_info("[BOGGER-PT] MSI guest vector: 0x%02x -> 0x%02x (shadowed, reg=0x%02x)\n",
                                ptdev->msi_guest_vector, new_vec, reg);
                        ptdev->msi_guest_vector = new_vec;
                    }
                }
                /* MSI Message Control (cap+0x02): track enable bit */
                if (reg == cap_base + 0x02 || (reg == cap_base && size >= 4)) {
                    u16 msgctl = (reg == cap_base + 0x02) ? (u16)val
                                                          : (u16)(val >> 16);
                    bool enable = !!(msgctl & 0x0001);
                    if (enable != ptdev->msi_enabled) {
                        pr_info("[BOGGER-PT] MSI %s by guest (shadowed)\n",
                                enable ? "ENABLED" : "DISABLED");
                        ptdev->msi_enabled = enable;
                    }
                }
                /* Do NOT write MSI regs to hardware */
                return true;
            }
            /* ── MSI-X capability: also shadow writes ───────────────── */
            if (ptdev->msix_cap_off && reg >= ptdev->msix_cap_off && reg < ptdev->msix_cap_off + 0x0C) {
                /* Don't forward MSI-X config writes to hardware */
                return true;
            }

            /* ── All other registers: pass through to hardware ──────── */
            /* Log CMD register changes (important: MEM/IO/BusMaster enable) */
            if (reg == 0x04) {
                static int cmd_log_cnt;
                if (cmd_log_cnt < 20) {
                    pr_info("[BOGGER-PT] CMD write bdf=0x%04x val=0x%04x (MEM=%d IO=%d BM=%d IntDis=%d)\n",
                            bdf, val & 0xFFFF,
                            !!(val & 0x02), !!(val & 0x01),
                            !!(val & 0x04), !!(val & 0x0400));
                    cmd_log_cnt++;
                }
            }
            switch (size) {
            case 1: pci_write_config_byte(ptdev->pdev, reg, (u8)val); break;
            case 2: pci_write_config_word(ptdev->pdev, reg, (u16)val); break;
            case 4: pci_write_config_dword(ptdev->pdev, reg, val); break;
            }

            return true;
        }
    }
    return false;
}

/* ═══════════════════════════════════════════════════════════════════
 * Compute guest GPA for a BAR using shadow registers if set.
 * For 64-bit BARs, combines shadow_bar[n] and shadow_bar[n+1].
 * ═══════════════════════════════════════════════════════════════════ */
u64 bogger_pci_passthrough_get_bar_gpa(struct bogger_passthrough_dev *ptdev,
                                        struct bogger_passthrough_bar *bar)
{
    int idx = bar->bar_idx;

    if (!ptdev->shadow_bar_set[idx])
        return bar->hpa;  /* No guest write yet → identity (HPA=GPA) */

    if (bar->is_64bit) {
        u64 lo = (u64)(ptdev->shadow_bar[idx] & 0xFFFFFFF0U);
        u64 hi = ptdev->shadow_bar_set[idx + 1]
                 ? (u64)ptdev->shadow_bar[idx + 1] : 0;
        return (hi << 32) | lo;
    }

    if (bar->is_mmio)
        return (u64)(ptdev->shadow_bar[idx] & 0xFFFFFFF0U);
    else
        return (u64)(ptdev->shadow_bar[idx] & 0xFFFFFFFCU);  /* IO BAR */
}

/* ═══════════════════════════════════════════════════════════════════
 * Check if a GPA is in any passthrough BAR range
 * (checks both guest-assigned and hardware identity ranges)
 * ═══════════════════════════════════════════════════════════════════ */
bool bogger_pci_passthrough_is_bar(u64 gpa)
{
    int d, b;
    for (d = 0; d < passthrough_dev_count; d++) {
        struct bogger_passthrough_dev *ptdev = &passthrough_devs[d];
        if (!ptdev->active) continue;
        for (b = 0; b < ptdev->num_bars; b++) {
            struct bogger_passthrough_bar *bar = &ptdev->bars[b];
            u64 guest_gpa;
            if (!bar->is_mmio || bar->size == 0)
                continue;
            /* Identity-mapped range (hardware HPA) */
            if (bar->mapped &&
                gpa >= bar->gpa && gpa < bar->gpa + bar->size)
                return true;
            /* Guest-assigned range (shadow BAR, may differ from hardware) */
            guest_gpa = bogger_pci_passthrough_get_bar_gpa(ptdev, bar);
            if (guest_gpa != bar->hpa && guest_gpa != 0 &&
                gpa >= guest_gpa && gpa < guest_gpa + bar->size)
                return true;
        }
        /* Expansion ROM — identity-mapped */
        if (ptdev->rom_mapped && ptdev->rom_hpa &&
            gpa >= ptdev->rom_hpa && gpa < ptdev->rom_hpa + ptdev->rom_size)
            return true;
        /* Expansion ROM — guest-assigned */
        if (ptdev->shadow_rom_set && ptdev->rom_size > 0) {
            u64 rom_gpa = (u64)(ptdev->shadow_rom_bar & 0xFFFFF800U);
            if (rom_gpa != 0 && rom_gpa != ptdev->rom_hpa &&
                gpa >= rom_gpa && gpa < rom_gpa + ptdev->rom_size)
                return true;
        }
    }
    return false;
}

/* ═══════════════════════════════════════════════════════════════════
 * Lazily map an entire BAR region into NPT.
 * Uses 2MB large pages when both GPA and HPA are 2MB-aligned.
 * ═══════════════════════════════════════════════════════════════════ */
static void lazy_map_bar_region(u64 guest_base, u64 hpa_base, u64 size)
{
    u64 gpa = guest_base & ~0xFFFULL;
    u64 hpa = hpa_base   & ~0xFFFULL;
    u64 end = guest_base + size;

    /* Signal that NPT was modified — VMRUN loop must flush TLB */
    bogger_npt_dirty_from_ioio = true;

    while (gpa < end) {
        unsigned int pd_idx = (unsigned int)(gpa >> 30);
        unsigned int pd_e   = (unsigned int)((gpa >> 21) & 0x1FF);

        if (pd_idx >= NPT_NUM_PD_TABLES)
            break;

        /* Allocate PD table if needed (for high GPU BARs above 4G) */
        if (!npt_pd_tables[pd_idx]) {
            npt_pd_tables[pd_idx] = (u64 *)get_zeroed_page(GFP_KERNEL);
            if (!npt_pd_tables[pd_idx])
                break;
            npt_pdpt[pd_idx] = virt_to_phys(npt_pd_tables[pd_idx]) | 0x07ULL;
        }

        /* Try 2MB large page if both sides are 2MB-aligned */
        if ((gpa & ((1ULL << 21) - 1)) == 0 &&
            (hpa & ((1ULL << 21) - 1)) == 0 &&
            (end - gpa) >= (1ULL << 21)) {
            u64 existing = npt_pd_tables[pd_idx][pd_e];
            /* If there's an existing 4KB PT, free it (it's a zero-page PT
             * in the MMIO hole — safe to replace for GPU BAR mapping) */
            if ((existing & 0x01ULL) && !(existing & (1ULL << 7))) {
                u64 *old_pt = (u64 *)phys_to_virt(existing & ~0xFFFULL);
                free_page((unsigned long)old_pt);
            }
            /* 2MB large page: PS bit + RWX + uncacheable */
            npt_pd_tables[pd_idx][pd_e] = hpa | 0x87ULL | (1ULL << 4);
            gpa += (1ULL << 21);
            hpa += (1ULL << 21);
            continue;
        }

        /* 4KB page fallback */
        {
            unsigned int pt_e = (unsigned int)((gpa >> 12) & 0x1FF);
            u64 *pt;

            if (!(npt_pd_tables[pd_idx][pd_e] & 0x01ULL)) {
                u64 *new_pt = (u64 *)get_zeroed_page(GFP_KERNEL);
                if (!new_pt) break;
                npt_pd_tables[pd_idx][pd_e] = virt_to_phys(new_pt) | 0x07ULL;
            }
            /* Break 2MB page into 4KB if PS bit set */
            if (npt_pd_tables[pd_idx][pd_e] & (1ULL << 7)) {
                u64 base_2mb = gpa & ~((1ULL << 21) - 1);
                u64 *new_pt = (u64 *)get_zeroed_page(GFP_KERNEL);
                unsigned int k;
                if (!new_pt) break;
                for (k = 0; k < 512; k++)
                    new_pt[k] = (base_2mb + ((u64)k << 12)) | 0x07ULL;
                npt_pd_tables[pd_idx][pd_e] = virt_to_phys(new_pt) | 0x07ULL;
            }

            pt = (u64 *)phys_to_virt(npt_pd_tables[pd_idx][pd_e] & ~0xFFFULL);
            pt[pt_e] = hpa | 0x17ULL;  /* RWX + PCD (UC- for MMIO) */
            gpa += PAGE_SIZE;
            hpa += PAGE_SIZE;
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * Resolve an NPF in a passthrough BAR region.
 * On first touch, maps the ENTIRE BAR into NPT so subsequent
 * accesses don't cause VMEXITs.
 * Returns true if GPA is in a passthrough BAR; *hpa_out = page HPA.
 * ═══════════════════════════════════════════════════════════════════ */
bool bogger_pci_passthrough_resolve_npf(u64 gpa, u64 *hpa_out)
{
    int d, b;
    for (d = 0; d < passthrough_dev_count; d++) {
        struct bogger_passthrough_dev *ptdev = &passthrough_devs[d];
        if (!ptdev->active) continue;

        for (b = 0; b < ptdev->num_bars; b++) {
            struct bogger_passthrough_bar *bar = &ptdev->bars[b];
            u64 guest_gpa;

            if (!bar->is_mmio || bar->size == 0)
                continue;

            guest_gpa = bogger_pci_passthrough_get_bar_gpa(ptdev, bar);
            if (guest_gpa == 0)
                continue;

            if (gpa >= guest_gpa && gpa < guest_gpa + bar->size) {
                u64 offset = gpa - guest_gpa;
                *hpa_out = bar->hpa + offset;

                /* Map the entire BAR into NPT on first access */
                if (!bar->mapped || guest_gpa != bar->gpa) {
                    pr_info("[BOGGER-PT] Lazy NPT map BAR%d: GPA 0x%llx → HPA 0x%llx (%llu MB)\n",
                            bar->bar_idx, guest_gpa, bar->hpa,
                            (unsigned long long)(bar->size >> 20));
                    lazy_map_bar_region(guest_gpa, bar->hpa, bar->size);
                    bar->mapped = true;
                    bar->gpa = guest_gpa;  /* Update GPA to reflect guest-assigned addr */
                }
                return true;
            }
        }

        /* Check ROM BAR */
        if (ptdev->rom_hpa && ptdev->rom_size > 0) {
            u64 rom_gpa;
            if (ptdev->shadow_rom_set)
                rom_gpa = (u64)(ptdev->shadow_rom_bar & 0xFFFFF800U);
            else
                rom_gpa = ptdev->rom_hpa;

            if (rom_gpa != 0 && gpa >= rom_gpa && gpa < rom_gpa + ptdev->rom_size) {
                *hpa_out = ptdev->rom_hpa + (gpa - rom_gpa);
                if (!ptdev->rom_mapped || rom_gpa != ptdev->rom_hpa) {
                    pr_info("[BOGGER-PT] Lazy NPT map ROM: GPA 0x%llx → HPA 0x%llx (%llu KB)\n",
                            rom_gpa, ptdev->rom_hpa,
                            (unsigned long long)(ptdev->rom_size >> 10));
                    lazy_map_bar_region(rom_gpa, ptdev->rom_hpa, ptdev->rom_size);
                    ptdev->rom_mapped = true;
                }
                return true;
            }
        }
    }
    return false;
}

/* ═══════════════════════════════════════════════════════════════════
 * IOMMU DMA Remapping
 *
 * The GPU does DMA using host physical addresses.  Guest RAM pages
 * are scattered (alloc_page), so GPA 0x1000 != HPA 0x1000.
 * We create an IOMMU domain for each passthrough device and map
 * every guest RAM page at its GPA → HPA, mirroring the NPT.
 * This allows the GPU to DMA to guest addresses after the guest
 * driver programs them.
 * ═══════════════════════════════════════════════════════════════════ */
int bogger_pci_passthrough_setup_iommu(void)
{
    int d, ret;
    unsigned long pg;
    struct iommu_group *group = NULL;
    struct iommu_domain *shared_dom = NULL;
    bool group_claimed = false;

    if (passthrough_dev_count == 0)
        return 0;

    /* On AMD hardware, GPU + audio function share an IOMMU group.
     * We must use group-based IOMMU APIs (not per-device) to avoid
     * -EINVAL from iommu_attach_device() on kernel 6.x+.
     *
     * Strategy:
     *   1. Get the IOMMU group from the first (primary GPU) device
     *   2. Claim DMA ownership for the entire group
     *   3. Create one paging domain and attach the entire group
     *   4. Map guest RAM into that single domain
     */

    /* Find the primary GPU device to get the IOMMU group */
    for (d = 0; d < passthrough_dev_count; d++) {
        struct bogger_passthrough_dev *ptdev = &passthrough_devs[d];
        if (!ptdev->active || !ptdev->pdev)
            continue;
        group = iommu_group_get(&ptdev->pdev->dev);
        if (group) {
            pr_info("[BOGGER-PT] IOMMU group %d for %02x:%02x.%x\n",
                    iommu_group_id(group),
                    ptdev->bus, PCI_SLOT(ptdev->devfn), PCI_FUNC(ptdev->devfn));
            break;
        }
    }

    if (!group) {
        pr_warn("[BOGGER-PT] No IOMMU group found — DMA passthrough may fail\n");
        pr_warn("[BOGGER-PT] Ensure amd_iommu=on iommu=pt in kernel cmdline\n");
        return -ENODEV;
    }

    /* Claim DMA ownership for the entire group (covers GPU + audio) */
    ret = iommu_group_claim_dma_owner(group, THIS_MODULE);
    if (ret) {
        pr_warn("[BOGGER-PT] IOMMU group claim failed (group %d): %d\n",
                iommu_group_id(group), ret);
        pr_warn("[BOGGER-PT] Try adding iommu=pt to kernel cmdline\n");
        iommu_group_put(group);
        return ret;
    }
    group_claimed = true;

    /* Allocate a single paging domain for the group */
    shared_dom = iommu_paging_domain_alloc(&passthrough_devs[0].pdev->dev);
    if (IS_ERR(shared_dom)) {
        pr_warn("[BOGGER-PT] IOMMU domain alloc failed: %ld\n", PTR_ERR(shared_dom));
        iommu_group_release_dma_owner(group);
        iommu_group_put(group);
        return PTR_ERR(shared_dom);
    }

    /* Attach the entire IOMMU group to the domain */
    ret = iommu_attach_group(shared_dom, group);
    if (ret) {
        pr_warn("[BOGGER-PT] IOMMU group attach failed (group %d): %d\n",
                iommu_group_id(group), ret);
        iommu_domain_free(shared_dom);
        iommu_group_release_dma_owner(group);
        iommu_group_put(group);
        return ret;
    }

    /* Store group/domain references in all passthrough devices */
    for (d = 0; d < passthrough_dev_count; d++) {
        struct bogger_passthrough_dev *ptdev = &passthrough_devs[d];
        if (!ptdev->active || !ptdev->pdev)
            continue;
        ptdev->iommu_dom = shared_dom;
        ptdev->iommu_grp = group;
        ptdev->iommu_attached = true;
        ptdev->iommu_group_claimed = true;
    }

    pr_info("[BOGGER-PT] IOMMU group %d attached successfully\n", iommu_group_id(group));

    /* Now map guest RAM into the shared domain (only once!) */
    d = 0; /* Use first device for log messages */
    {

        /* Map guest RAM pages: below-4G region */
        unsigned long below_4g_pages = (unsigned long)(guest_ram_below_4g >> PAGE_SHIFT);
        for (pg = 0; pg < below_4g_pages && pg < guest_nr_pages; pg++) {
            u64 gpa = (u64)pg << PAGE_SHIFT;
            phys_addr_t hpa = page_to_phys(guest_pages[pg]);
            ret = iommu_map(shared_dom, gpa, hpa, PAGE_SIZE,
                            IOMMU_READ | IOMMU_WRITE, GFP_KERNEL);
            if (ret && pg < 16)
                pr_warn("[BOGGER-PT] IOMMU map GPA 0x%llx→HPA 0x%llx failed: %d\n",
                        gpa, (u64)hpa, ret);
        }

        /* Map guest RAM pages: above-4G region */
        if (guest_ram_above_4g > 0) {
            unsigned long above_4g_pages = guest_nr_pages - below_4g_pages;
            for (pg = 0; pg < above_4g_pages; pg++) {
                u64 gpa = MMIO_GAP_END + ((u64)pg << PAGE_SHIFT);
                phys_addr_t hpa = page_to_phys(guest_pages[below_4g_pages + pg]);
                ret = iommu_map(shared_dom, gpa, hpa, PAGE_SIZE,
                                IOMMU_READ | IOMMU_WRITE, GFP_KERNEL);
                if (ret && pg < 16)
                    pr_warn("[BOGGER-PT] IOMMU map above4g GPA 0x%llx failed: %d\n",
                            gpa, ret);
            }
        }

        /* Map MMIO BAR regions 1:1 (identity) in IOMMU as well,
         * for MSI-X table access and other device self-referencing. */
        {
            int dd, bb;
            for (dd = 0; dd < passthrough_dev_count; dd++) {
                struct bogger_passthrough_dev *pt = &passthrough_devs[dd];
                if (!pt->active) continue;
                for (bb = 0; bb < pt->num_bars; bb++) {
                    struct bogger_passthrough_bar *bar = &pt->bars[bb];
                    u64 addr;
                    if (!bar->is_mmio || bar->size == 0)
                        continue;
                    for (addr = 0; addr < bar->size; addr += PAGE_SIZE) {
                        iommu_map(shared_dom, bar->gpa + addr, bar->hpa + addr, PAGE_SIZE,
                                  IOMMU_READ | IOMMU_WRITE | IOMMU_MMIO, GFP_KERNEL);
                    }
                }
            }
        }

        /* Map the LAPIC MSI target address (0xFEE00000-0xFEEFFFFF) as
         * identity-mapped MMIO so hardware MSI delivery works. */
        iommu_map(shared_dom, 0xFEE00000ULL, 0xFEE00000ULL, PAGE_SIZE,
                  IOMMU_READ | IOMMU_WRITE | IOMMU_MMIO, GFP_KERNEL);

        pr_info("[BOGGER-PT] IOMMU domain mapped (%lu pages, group %d)\n",
                guest_nr_pages, iommu_group_id(group));
    }

    /* Keep a reference to the group (released in teardown) */
    /* Note: iommu_group_put() deferred to teardown_iommu() */
    return 0;
}

void bogger_pci_passthrough_teardown_iommu(void)
{
    int d;
    struct iommu_group *group = NULL;
    struct iommu_domain *dom = NULL;

    /* Find the shared group/domain (stored in all devs, just need one) */
    for (d = 0; d < passthrough_dev_count; d++) {
        struct bogger_passthrough_dev *ptdev = &passthrough_devs[d];
        if (ptdev->iommu_attached && ptdev->iommu_dom) {
            dom = ptdev->iommu_dom;
            group = ptdev->iommu_grp;
            break;
        }
    }

    /* Detach the group from the domain */
    if (dom && group) {
        iommu_detach_group(dom, group);
        iommu_domain_free(dom);
        pr_info("[BOGGER-PT] IOMMU domain released (group %d)\n",
                iommu_group_id(group));
    }

    /* Release group DMA ownership */
    if (group) {
        bool claimed = false;
        for (d = 0; d < passthrough_dev_count; d++) {
            if (passthrough_devs[d].iommu_group_claimed) {
                claimed = true;
                break;
            }
        }
        if (claimed)
            iommu_group_release_dma_owner(group);
        iommu_group_put(group);
    }

    /* Clear references in all devices */
    for (d = 0; d < passthrough_dev_count; d++) {
        struct bogger_passthrough_dev *ptdev = &passthrough_devs[d];
        ptdev->iommu_dom = NULL;
        ptdev->iommu_grp = NULL;
        ptdev->iommu_attached = false;
        ptdev->iommu_group_claimed = false;
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * MSI Interrupt Forwarding
 *
 * When the GPU fires an MSI, the host catches it and sets a flag.
 * The VMRUN loop picks up the flag and injects the interrupt into
 * the guest via VMCB event_inj.
 *
 * We allocate a single MSI vector and use the host IRQ handler.
 * The guest driver will program the GPU for a specific vector via
 * MSI/MSI-X config space — we pass those writes through to real HW.
 * ═══════════════════════════════════════════════════════════════════ */
static irqreturn_t bogger_pt_msi_handler(int irq, void *data)
{
    struct bogger_passthrough_dev *ptdev = data;

    atomic_set(&bogger_pt_irq_vector, ptdev->msi_guest_vector);
    /* Store vector before setting pending flag (write barrier) */
    smp_wmb();
    atomic_set(&bogger_pt_irq_pending, 1);

    return IRQ_HANDLED;
}

int bogger_pci_passthrough_setup_msi(void)
{
    int d, ret;

    if (passthrough_dev_count == 0)
        return 0;

    for (d = 0; d < passthrough_dev_count; d++) {
        struct bogger_passthrough_dev *ptdev = &passthrough_devs[d];

        if (!ptdev->active || !ptdev->pdev)
            continue;

        /* Only set up MSI for the primary GPU (not audio func) */
        if (ptdev->guest_bdf != GUEST_GPU_BDF)
            continue;

        /* Enable the PCI device first */
        ret = pci_enable_device(ptdev->pdev);
        if (ret) {
            pr_warn("[BOGGER-PT] pci_enable_device failed: %d\n", ret);
            continue;
        }
        pci_set_master(ptdev->pdev);

        /* Try MSI-X first (preferred for modern GPUs), fallback to MSI */
        ret = pci_alloc_irq_vectors(ptdev->pdev, 1, 1, PCI_IRQ_MSIX | PCI_IRQ_MSI);
        if (ret < 0) {
            /* Fall back to legacy INTx — not ideal but may work */
            pr_info("[BOGGER-PT] MSI/MSI-X alloc failed (%d), using legacy IRQ\n", ret);
            ptdev->msi_host_irq = ptdev->pdev->irq;
            if (ptdev->msi_host_irq <= 0)
                continue;
        } else {
            ptdev->msi_irqs = ret;
            ptdev->msi_host_irq = pci_irq_vector(ptdev->pdev, 0);
        }

        /* Default guest vector: use IRQ pin A → guest IRQ 10 (INTA) */
        ptdev->msi_guest_vector = 0x0A;  /* Will be overridden by guest MSI config */

        ret = request_irq(ptdev->msi_host_irq, bogger_pt_msi_handler,
                          IRQF_SHARED, "bogger_gpu", ptdev);
        if (ret) {
            pr_warn("[BOGGER-PT] request_irq(%d) failed: %d\n",
                    ptdev->msi_host_irq, ret);
            if (ptdev->msi_irqs > 0)
                pci_free_irq_vectors(ptdev->pdev);
            continue;
        }

        ptdev->msi_enabled = true;
        pr_info("[BOGGER-PT] MSI IRQ %d registered for GPU %02x:%02x.%x (guest vec=0x%02x)\n",
                ptdev->msi_host_irq,
                ptdev->bus, PCI_SLOT(ptdev->devfn), PCI_FUNC(ptdev->devfn),
                ptdev->msi_guest_vector);
    }
    return 0;
}

void bogger_pci_passthrough_teardown_msi(void)
{
    int d;
    for (d = 0; d < passthrough_dev_count; d++) {
        struct bogger_passthrough_dev *ptdev = &passthrough_devs[d];
        if (!ptdev->msi_enabled)
            continue;
        free_irq(ptdev->msi_host_irq, ptdev);
        if (ptdev->msi_irqs > 0)
            pci_free_irq_vectors(ptdev->pdev);
        ptdev->msi_enabled = false;
        pr_info("[BOGGER-PT] MSI IRQ released for %02x:%02x.%x\n",
                ptdev->bus, PCI_SLOT(ptdev->devfn), PCI_FUNC(ptdev->devfn));
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * Cleanup: unmap, teardown IOMMU+MSI, rebind drivers
 * ═══════════════════════════════════════════════════════════════════ */
void bogger_pci_passthrough_free(void)
{
    int d;

    bogger_pci_passthrough_teardown_msi();
    bogger_pci_passthrough_teardown_iommu();

    for (d = 0; d < passthrough_dev_count; d++) {
        struct bogger_passthrough_dev *ptdev = &passthrough_devs[d];
        if (!ptdev->active) continue;

        pr_info("[BOGGER-PT] Releasing device %02x:%02x.%x (guest BDF 0x%04x)\n",
                ptdev->bus, PCI_SLOT(ptdev->devfn), PCI_FUNC(ptdev->devfn),
                ptdev->guest_bdf);

        rebind_device(ptdev);

        if (ptdev->pdev) {
            pci_dev_put(ptdev->pdev);
            ptdev->pdev = NULL;
        }
        ptdev->active = false;
    }
    passthrough_dev_count = 0;
    pr_info("[BOGGER-PT] All passthrough devices released\n");
}


