// SPDX-License-Identifier: GPL-2.0
/*
 * bogger_ioport.c – I/O port emulation (PCI, CMOS, PIT, PIC, ACPI, Serial, …)
 *
 * Handles SVM_EXIT_IOIO for all emulated devices.
 * Returns via vmcb->save.rip advancement.
 */
#include "bogger_ioport.h"
#include "bogger_fwcfg.h"
#include "bogger_pic.h"
#include "bogger_ps2.h"
#include "bogger_pci_passthrough.h"
#include "bogger_svm.h"
#include "bogger_vga.h"
#include "bogger_npt.h"
#include "bogger_nvme.h"
#include "bogger_guest_ram.h"

u32 pci_config_addr;
u8  cmos_index;

/* ── PCI BAR sizing state ─────────────────────────────────────────
 * OVMF writes 0xFFFFFFFF to BARs to determine their size, then reads
 * back the mask.  We track writable BAR values for emulated devices
 * and return the correct mask when a BAR has been written.
 *
 * Layout: pci_bars[device_index][bar_index]
 *   device 0 = i440FX (00:0.0)
 *   device 1 = PIIX3 ISA (00:1.0)
 *   device 2 = PIIX3 PM (00:1.3)
 *   device 3 = PIIX3 IDE (00:1.1)
 *   device 4 = VGA (00:2.0)
 *   device 5 = NVMe (00:4.0)
 */
#define PCI_NUM_DEVICES 6
#define PCI_NUM_BARS    6
static u32 pci_bar_written[PCI_NUM_DEVICES][PCI_NUM_BARS];
static bool pci_bar_probing[PCI_NUM_DEVICES][PCI_NUM_BARS];
unsigned long fwcfg_port511_reads;
unsigned long pci_total_writes;

/* NVMe PCI config space — writable so pci.sys can enable MSI/MSI-X
 * and read back updated state during device enumeration.
 *
 * Capability chain: 0x34 → MSI(0x40) → MSI-X(0x70) → PCIe(0x80) → end
 *
 * NVMe is a PCIe-only standard.  Without a PCI Express Capability
 * (ID=0x10), Windows stornvme.sys may refuse to initialize the device
 * or fail to allocate MSI-X resources properly. */
static u8 nvme_pci_cfg[256] = {
    /* Vendor: 0x144D (Samsung), Device: 0xA809 (980 PRO) */
    [0x00]=0x4D,[0x01]=0x14,[0x02]=0x09,[0x03]=0xA8,
    /* Command: MemSpace=1, BusMaster=1 */
    [0x04]=0x06,[0x05]=0x00,
    /* Status: CapList=1 */
    [0x06]=0x10,[0x07]=0x00,
    /* Revision, ProgIf=NVMe, SubClass=NVM, Class=Mass Storage */
    [0x08]=0x01,[0x09]=0x02,[0x0A]=0x08,[0x0B]=0x01,
    [0x0E]=0x00,
    /* BAR0: MMIO at 0xE2000000 (32-bit, non-prefetchable) */
    [0x10]=0x00,[0x11]=0x00,[0x12]=0x00,[0x13]=0xE2,
    /* Subsystem Vendor/Device (Samsung) */
    [0x2C]=0x4D,[0x2D]=0x14,[0x2E]=0x01,[0x2F]=0xA8,
    /* Capability pointer → MSI at 0x40 */
    [0x34]=0x40,
    /* Interrupt: IRQ 11, INTA */
    [0x3C]=0x0B,[0x3D]=0x01,

    /* ── MSI Capability (ID=0x05) at 0x40, 14 bytes ─────────────── */
    [0x40]=0x05, /* Capability ID: MSI */
    [0x41]=0x70, /* Next capability: MSI-X at 0x70 */
    [0x42]=0x80, /* Message Control: 64-bit capable, MSI disabled */
    /* MSI Address/Data: offsets 0x44-0x4F, writable by guest */

    /* ── MSI-X Capability (ID=0x11) at 0x70, 12 bytes ───────────── */
    [0x70]=0x11, /* Capability ID: MSI-X */
    [0x71]=0x80, /* Next: PCIe at 0x80 */
    [0x72]=0x03, /* Table size = 4 entries (N-1) */
    [0x73]=0x00,
    /* MSI-X Table Offset/BIR: BAR0 + 0x2000 */
    [0x74]=0x00,[0x75]=0x20,[0x76]=0x00,[0x77]=0x00,
    /* MSI-X PBA Offset/BIR: BAR0 + 0x3000 */
    [0x78]=0x00,[0x79]=0x30,[0x7A]=0x00,[0x7B]=0x00,

    /* ── PCI Express Capability (ID=0x10) at 0x80 ───────────────── *
     * 36 bytes (0x80-0xA3): Cap header + Express Caps + Device +
     * Link + Slot (unused) + Root (unused) + Device Caps 2.
     * Minimum for a PCIe v2 Endpoint that Windows pci.sys needs. */
    [0x80]=0x10, /* Capability ID: PCI Express */
    [0x81]=0x00, /* Next: end of chain */
    /* PCI Express Capabilities Register (+0x02):
     *   [3:0]  = 2  (Capability version 2)
     *   [7:4]  = 0  (Device/Port Type: PCI Express Endpoint)
     *   [8]    = 0  (Slot Implemented: no) */
    [0x82]=0x02,[0x83]=0x00,
    /* Device Capabilities (+0x04):
     *   [2:0]  = 1   (Max Payload Size Supported: 256 bytes)
     *   [5]    = 1   (Extended Tag Field Supported)
     *   [15]   = 1   (Role-Based Error Reporting)
     *   [28]   = 1   (FLR Capable) */
    [0x84]=0x21,[0x85]=0x80,[0x86]=0x00,[0x87]=0x10,
    /* Device Control (+0x08): writable by guest, defaults 0 */
    [0x88]=0x00,[0x89]=0x00,
    /* Device Status (+0x0A): 0 */
    [0x8A]=0x00,[0x8B]=0x00,
    /* Link Capabilities (+0x0C):
     *   [3:0]  = 3   (Max Link Speed: 8 GT/s, Gen3)
     *   [9:4]  = 4   (Maximum Link Width: x4)
     *   [11:10]= 0   (ASPM Support: none) */
    [0x8C]=0x43,[0x8D]=0x00,[0x8E]=0x00,[0x8F]=0x00,
    /* Link Control (+0x10): 0 */
    [0x90]=0x00,[0x91]=0x00,
    /* Link Status (+0x12):
     *   [3:0]  = 3   (Current Link Speed: Gen3)
     *   [9:4]  = 4   (Negotiated Link Width: x4) */
    [0x92]=0x43,[0x93]=0x00,
};

/* Ring buffer capturing last 128 PCI config accesses for post-mortem */
#define PCI_RING_SIZE 128
struct pci_ring_entry {
    u32 bdf;
    u32 reg;
    u32 val;
    u8  is_write;
    u8  sz;
};
static struct pci_ring_entry pci_ring[PCI_RING_SIZE];
static int pci_ring_idx;

void bogger_dump_pci_ring(void)
{
    int i, idx;
    pr_info("[BOGGER] Last %d PCI config accesses:\n", PCI_RING_SIZE);
    for (i = 0; i < PCI_RING_SIZE; i++) {
        idx = (pci_ring_idx + i) % PCI_RING_SIZE;
        if (pci_ring[idx].bdf == 0 && pci_ring[idx].reg == 0 && pci_ring[idx].val == 0)
            continue;
        pr_info("[PCI-RING] %s bdf=0x%04x reg=0x%02x val=0x%08x sz=%d\n",
                pci_ring[idx].is_write ? "WR" : "RD",
                pci_ring[idx].bdf, pci_ring[idx].reg,
                pci_ring[idx].val, pci_ring[idx].sz);
    }
}

/* PCI Command register state per device (to track MemSpace/IOSpace enable) */
static u16 pci_cmd_reg[PCI_NUM_DEVICES] = {
    [0] = 0x07,  /* i440FX */
    [1] = 0x07,  /* PIIX3 ISA */
    [2] = 0x01,  /* PIIX3 PM */
    [3] = 0x05,  /* PIIX3 IDE */
    [4] = 0x07,  /* VGA */
    [5] = 0x06,  /* NVMe */
};

struct pci_bar_info {
    u32 base;   /* default base address */
    u32 size;   /* BAR size (must be power of 2) */
    u8  flags;  /* low bits: 0=32bit mem, 1=IO, 8=prefetchable mem */
};

/* Per-device BAR definitions */
static const struct pci_bar_info pci_bars_def[PCI_NUM_DEVICES][PCI_NUM_BARS] = {
    /* device 0: i440FX — no BARs */
    [0] = {},
    /* device 1: PIIX3 ISA — no BARs */
    [1] = {},
    /* device 2: PIIX3 PM — no BARs (uses fixed I/O ports) */
    [2] = {},
    /* device 3: PIIX3 IDE */
    [3] = { [4] = { .base = 0xC060, .size = 16, .flags = 1 } },
    /* device 4: VGA (Bochs stdvga) — BARs must be inside PCI MMIO aperture
     * (OVMF uses 0xC0000000-0xFBFFFFFF for i440FX with 3 GB RAM) */
    [4] = {
        [0] = { .base = 0xE0000000, .size = 0x01000000, .flags = 8 },  /* 16MB FB prefetch */
        [2] = { .base = 0xE1000000, .size = 0x01000000, .flags = 0 },  /* 16MB MMIO */
    },
    /* device 5: NVMe */
    [5] = {
        [0] = { .base = 0xE2000000, .size = 0x4000, .flags = 0 },  /* 16KB MMIO, 32-bit */
    },
};

/* Map BDF to device index, returns -1 if unknown */
static int pci_bdf_to_dev(u32 bdf)
{
    switch (bdf) {
    case 0x0000: return 0;  /* 00:0.0 i440FX */
    case 0x0008: return 1;  /* 00:1.0 PIIX3 ISA */
    case 0x000B: return 2;  /* 00:1.3 PIIX3 PM */
    case 0x0009: return 3;  /* 00:1.1 PIIX3 IDE */
    case 0x0010: return 4;  /* 00:2.0 VGA */
    case 0x0020: return 5;  /* 00:4.0 NVMe */
    default: return -1;
    }
}

static u32 pci_get_bar_value(int dev_idx, int bar_idx)
{
    const struct pci_bar_info *bi = &pci_bars_def[dev_idx][bar_idx];
    if (bi->size == 0) return 0;  /* no BAR */

    if (pci_bar_probing[dev_idx][bar_idx]) {
        /* Return size mask: ~(size-1) with type bits preserved */
        u32 mask = ~(bi->size - 1);
        if (bi->flags & 1)
            return (mask & 0xFFFFFFFC) | 1;  /* I/O BAR */
        else
            return (mask & 0xFFFFFFF0) | (bi->flags & 0x0F);  /* Memory BAR */
    }
    /* Return the current base address */
    if (bi->flags & 1)
        return (pci_bar_written[dev_idx][bar_idx] ? pci_bar_written[dev_idx][bar_idx] : bi->base) | 1;
    else
        return (pci_bar_written[dev_idx][bar_idx] ? pci_bar_written[dev_idx][bar_idx] : bi->base) | (bi->flags & 0x0F);
}

/*
 * pci_cfg_read_val() – assemble a multi-byte value from a PCI config
 * byte array.  'reg' is the starting register offset, 'sz' is the
 * I/O operand size (0=byte, 1=word, 2=dword).  Returns the correct
 * little-endian value that OVMF expects for PciRead8/16/32.
 */
static u32 pci_cfg_read_val(const u8 *cfg, u32 reg, int sz)
{
    u32 v = 0;
    if (reg >= 256) return 0xFF;
    v = cfg[reg];
    if (sz >= 1 && reg + 1 < 256)
        v |= (u32)cfg[reg + 1] << 8;
    if (sz >= 2 && reg + 2 < 256)
        v |= (u32)cfg[reg + 2] << 16;
    if (sz >= 2 && reg + 3 < 256)
        v |= (u32)cfg[reg + 3] << 24;
    return v;
}

/* Check if a port falls in a passthrough device I/O BAR.
 * Uses guest-assigned BAR address (bar->gpa) for matching, then
 * translates to the hardware port (bar->hpa) for actual I/O.
 * This handles the case where OVMF reassigns I/O BARs to different
 * port ranges (e.g. GPU BAR5 from 0xd000 to 0xc000). */
static bool pt_iobar_in(u64 port, int sz, u32 *out_val)
{
    int d, b;
    for (d = 0; d < passthrough_dev_count; d++) {
        struct bogger_passthrough_dev *ptdev = &passthrough_devs[d];
        if (!ptdev->active) continue;
        for (b = 0; b < ptdev->num_bars; b++) {
            struct bogger_passthrough_bar *bar = &ptdev->bars[b];
            u64 guest_base;
            u16 hw_port;
            if (bar->is_mmio || bar->size == 0) continue;
            guest_base = bar->gpa;  /* Guest-assigned I/O port base */
            if (port >= guest_base && port < guest_base + bar->size) {
                hw_port = (u16)(bar->hpa + (port - guest_base));
                if (sz == 0)      *out_val = inb(hw_port);
                else if (sz == 1) *out_val = inw(hw_port);
                else              *out_val = inl(hw_port);
                return true;
            }
        }
    }
    return false;
}

static bool pt_iobar_out(u64 port, int sz, u32 val)
{
    int d, b;
    for (d = 0; d < passthrough_dev_count; d++) {
        struct bogger_passthrough_dev *ptdev = &passthrough_devs[d];
        if (!ptdev->active) continue;
        for (b = 0; b < ptdev->num_bars; b++) {
            struct bogger_passthrough_bar *bar = &ptdev->bars[b];
            u64 guest_base;
            u16 hw_port;
            if (bar->is_mmio || bar->size == 0) continue;
            guest_base = bar->gpa;  /* Guest-assigned I/O port base */
            if (port >= guest_base && port < guest_base + bar->size) {
                hw_port = (u16)(bar->hpa + (port - guest_base));
                if (sz == 0)      outb((u8)val, hw_port);
                else if (sz == 1) outw((u16)val, hw_port);
                else              outl(val, hw_port);
                return true;
            }
        }
    }
    return false;
}

/* ACPI PM state */
static u16 pm1_sts;         /* PM1 Status register */
static u16 pm1_en;          /* PM1 Enable register */
static u16 pm1_cnt = 0x01;  /* PM1 Control: SCI_EN=1 */
static u32 gpe0_sts;        /* GPE0 Status */
static u32 gpe0_en;         /* GPE0 Enable */

/* Stuck-detection for IOIO loops */
static u64 last_ioio_port;
static u64 last_ioio_rip;
static int ioio_repeat_count;
static int ioio_stuck_logged;
static u8 serial_scr;  /* Serial COM1 Scratch Register (read/write) */
static u8 serial_lcr = 0x03;  /* Serial COM1 LCR (8N1 default) */

/*
 * bogger_handle_ioio() – called from VMRUN loop on SVM_EXIT_IOIO.
 *
 * We keep the "done" label as a return-flag: the caller checks
 * vmcb->save.rip to know if we consumed the exit.  For shutdown
 * requests (S5, reset), we set rip to 0 as a signal.
 */
void bogger_handle_ioio(struct vmcb *vmcb, int exits, int max_logged_exits)
{
    u64 info1 = vmcb->control.exit_info_1;
    u64 port  = (info1 >> 16) & 0xFFFFULL;
    int is_in = info1 & 1;
    /*
     * AMD SVM IOIO exit_info_1 operand size is ONE-HOT encoded:
     *   Bit 4 = SZ8  (8-bit / byte)
     *   Bit 5 = SZ16 (16-bit / word)
     *   Bit 6 = SZ32 (32-bit / dword)
     * We convert to: 0=byte, 1=word, 2=dword
     */
    int sz;
    if (info1 & (1 << 6))      sz = 2;  /* SZ32: dword */
    else if (info1 & (1 << 5)) sz = 1;  /* SZ16: word */
    else                        sz = 0;  /* SZ8: byte (or default) */
    u32 val   = 0xFFFFFFFF;

    /* Debug: fw_cfg port access tracking disabled to prevent stack overflow */

    /* ── REP string I/O (INS/OUTS) handler ────────────────────────
     * AMD SVM intercepts string I/O but the instruction has NOT executed:
     * RAX, RCX, RSI, RDI are all unchanged.  The VMM must emulate the
     * entire operation, including all REP iterations.
     *
     * OVMF's IoReadFifo8/IoWriteFifo8 use "rep insb"/"rep outsb",
     * critical for fw_cfg reads.  Without this, only 1 byte is read
     * before RIP advances past the instruction. */
    if (info1 & (1 << 2)) {  /* STR bit: this is a string I/O (INS/OUTS) */
        int is_rep = (info1 & (1 << 3)) != 0;
        u64 count = is_rep ? guest_gprs.rcx : 1;
        int byte_size = (sz == 0) ? 1 : (sz == 1) ? 2 : 4;
        int df = (vmcb->save.rflags & (1 << 10)) ? -1 : 1;
        static unsigned long str_io_total;
        str_io_total += count;

        if (count > 65536) count = 65536;  /* safety limit */

        if (count == 0)
            goto str_io_done;

        if (is_in) {
            /* REP INSB/INSW/INSD: read from port, write to [ES:RDI] */
            u64 gpa = guest_gprs.rdi;
            u64 i;
            for (i = 0; i < count; i++) {
                u32 v;
                void *dst;
                switch (port) {
                case 0x511: v = fwcfg_read_byte(); fwcfg_port511_reads++; break;
                default:    v = (byte_size == 1) ? 0xFF : (byte_size == 2) ? 0xFFFF : 0xFFFFFFFF; break;
                }
                /* Write to guest memory — handles below-4G, above-4G, and OVMF flash */
                dst = bogger_gpa_to_hva(gpa);
                if (dst) {
                    if (byte_size == 1)      *(u8 *)dst = (u8)v;
                    else if (byte_size == 2) *(u16 *)dst = (u16)v;
                    else                     *(u32 *)dst = v;
                }
                gpa += df * byte_size;
            }
            guest_gprs.rdi = gpa;
        } else {
            /* REP OUTSB/OUTSW/OUTSD: read from [DS:RSI], write to port */
            u64 gpa = guest_gprs.rsi;
            u64 i;
            for (i = 0; i < count; i++) {
                u32 v = 0;
                void *src = bogger_gpa_to_hva(gpa);
                if (src) {
                    if (byte_size == 1)      v = *(u8 *)src;
                    else if (byte_size == 2) v = *(u16 *)src;
                    else                     v = *(u32 *)src;
                }
                switch (port) {
                case 0x510:
                    fwcfg_selector = (u16)v;
                    fwcfg_offset = 0;
                    fwcfg_buf_valid = false;
                    break;
                case 0x511: break;  /* fw_cfg data write: ignore */
                default: break;
                }
                gpa += df * byte_size;
            }
            guest_gprs.rsi = gpa;
        }
        if (is_rep)
            guest_gprs.rcx = 0;



str_io_done:
        /* Advance RIP past the string I/O instruction */
        {
            u64 nrip = vmcb->control.exit_info_2;
            if (nrip > vmcb->save.rip && nrip < vmcb->save.rip + 16) {
                vmcb->save.rip = nrip;
            } else {
                nrip = vmcb->control.next_rip;
                if (nrip > vmcb->save.rip && nrip < vmcb->save.rip + 16)
                    vmcb->save.rip = nrip;
                else
                    vmcb->save.rip += 2;
            }
        }
        return;
    }

    if (is_in) {
        switch (port) {
        /* ── PCI Config ───────────────────────────────────────── */
        case 0xCF8: val = pci_config_addr; break;
        case 0xCFC: case 0xCFD: case 0xCFE: case 0xCFF: {
            u32 dev  = (pci_config_addr >> 11) & 0x1F;
            u32 func = (pci_config_addr >> 8) & 0x07;
            u32 reg  = (pci_config_addr & 0xFC);  /* always aligned to dword */
            u32 bdf  = ((pci_config_addr >> 16) & 0xFF) << 8 | (dev << 3) | func;
            u32 byte_off = port - 0xCFC;  /* 0-3: sub-dword offset */
            int dev_idx;

            /* PCI Configuration Mechanism 1: bit 31 of the config address
             * must be set for reads to generate a valid type 1 config cycle.
             * Without this check, reads when bit 31 is clear would return
             * device data instead of 0xFFFFFFFF, confusing bus scanning. */
            if (!(pci_config_addr & 0x80000000U)) {
                val = 0xFFFFFFFF;
                break;
            }

            /* Log PCI config reads (rate-limited, non-emergency) */
            {
                static u32 pci_scanned;
                static int pci_rd_log;
                if (reg == 0x00 && func == 0 && !(pci_scanned & (1U << dev))) {
                    pci_scanned |= (1U << dev);
                    pr_info("[BOGGER-PCI] Scan dev=%u func=%u bdf=0x%04x (rd_cnt=%d)\n",
                            dev, func, bdf, pci_rd_log);
                }
                if (pci_rd_log < 20) {
                    pr_info("[BOGGER-PCI] RD bdf=0x%04x reg=0x%02x val_pre=0x%08x port=0x%llx\n",
                            bdf, reg, val, port);
                    pci_rd_log++;
                }
            }
            val = 0xFFFFFFFF;

            if (bdf == 0x0000) {
                static const u8 i440fx_cfg[256] = {
                    [0x00]=0x86,[0x01]=0x80,[0x02]=0x37,[0x03]=0x12,
                    [0x04]=0x07,[0x06]=0x00,[0x07]=0x02,[0x08]=0x02,
                    [0x0A]=0x00,[0x0B]=0x06,[0x0E]=0x00,
                };
                val = pci_cfg_read_val(i440fx_cfg, reg, 2);
                if (reg >= 0x59 && reg <= 0x5F) val = 0x33333333;
                if (reg == 0x72) val = (val & 0xFFFFFF00) | 0x02;
            } else if (bdf == 0x0008) {
                /* Device 0:1.0 = PIIX3 ISA bridge */
                static const u8 piix3_cfg[256] = {
                    [0x00]=0x86,[0x01]=0x80,[0x02]=0x00,[0x03]=0x70,
                    [0x04]=0x07,[0x05]=0x00,[0x06]=0x00,[0x07]=0x02,
                    [0x08]=0x00,
                    [0x0A]=0x01,[0x0B]=0x06, /* ISA bridge */
                    [0x0E]=0x80,             /* multi-function */
                    /* PIRQ routing: PIRQA→IRQ11, PIRQB→IRQ11,
                     * PIRQC→IRQ11, PIRQD→IRQ11 */
                    [0x60]=0x0B,[0x61]=0x0B,[0x62]=0x0B,[0x63]=0x0B,
                    /* SERIRQC: serial IRQ control */
                    [0x69]=0xD0,
                    /* Top of Memory */
                    [0x82]=0x00,[0x83]=0x00,
                };
                val = pci_cfg_read_val(piix3_cfg, reg, 2);
            } else if (bdf == 0x000B) {
                /* Device 0:1.3 = PIIX3 ACPI/Power Management */
                static const u8 piix3_pm_cfg[256] = {
                    [0x00]=0x86,[0x01]=0x80,[0x02]=0x13,[0x03]=0x71,
                    [0x04]=0x01,[0x05]=0x00,[0x06]=0x80,[0x07]=0x02,
                    [0x08]=0x03,
                    [0x0A]=0x80,[0x0B]=0x06, /* Bridge / Other */
                    [0x0E]=0x00,
                    /* PM Base I/O (offset 0x40) = 0x0600 */
                    [0x40]=0x01,[0x41]=0x06,
                    /* DEVACTB (offset 0x58) */
                    [0x58]=0x00,
                    /* GPE0 Block I/O base (offset 0x44) = 0x0620 */
                    [0x44]=0x21,[0x45]=0x06,
                    /* PM register enables */
                    [0x80]=0x01, /* PM IO Space enable */
                    [0x3C]=0x09, /* IRQ 9 for SCI */
                    [0x3D]=0x01,
                };
                val = pci_cfg_read_val(piix3_pm_cfg, reg, 2);
            } else if (bdf == 0x0009) {
                /* Device 0:1.1 = PIIX3 IDE Controller */
                static const u8 piix3_ide_cfg[256] = {
                    [0x00]=0x86,[0x01]=0x80,[0x02]=0x10,[0x03]=0x70,
                    [0x04]=0x05,[0x05]=0x00,[0x06]=0x80,[0x07]=0x02,
                    [0x08]=0x00,
                    [0x09]=0x80, /* ProgIf: Master IDE */
                    [0x0A]=0x01,[0x0B]=0x01, /* IDE controller */
                    [0x0E]=0x00,
                    /* BAR4: I/O at 0xC060 */
                    [0x20]=0x61,[0x21]=0xC0,[0x22]=0x00,[0x23]=0x00,
                    /* Timing registers */
                    [0x40]=0xA3,[0x41]=0xA3,[0x42]=0x00,[0x43]=0x80,
                    [0x3C]=0x00,[0x3D]=0x00,
                };
                val = pci_cfg_read_val(piix3_ide_cfg, reg, 2);
            } else if (bdf == 0x0010) {
                /* Device 0:2.0 = VGA Compatible Controller (Bochs VGA / stdvga)
                 * When GPU passthrough is active, hide this device so OVMF
                 * discovers the real passthrough GPU (with UEFI GOP from its ROM)
                 * as primary display.  The emulated VGA has no physical output. */
                if (passthrough_dev_count > 0) {
                    val = 0xFFFFFFFF;  /* No device — forces OVMF to use real GPU */
                } else {
                    static const u8 vga_cfg[256] = {
                        /* Vendor: 1234 (QEMU/Bochs), Device: 1111 (stdvga) */
                        [0x00]=0x34,[0x01]=0x12,[0x02]=0x11,[0x03]=0x11,
                        /* Command: IO+Mem+BusMaster */
                        [0x04]=0x07,[0x05]=0x00,
                        /* Status */
                        [0x06]=0x00,[0x07]=0x00,
                        [0x08]=0x02,  /* Revision */
                        [0x09]=0x00,  /* ProgIf: VGA compatible */
                        [0x0A]=0x00,[0x0B]=0x03, /* Class: Display, VGA */
                        [0x0E]=0x00,
                        /* BAR0: Framebuffer at 0xE0000000 (32-bit, prefetchable) */
                        [0x10]=0x08,[0x11]=0x00,[0x12]=0x00,[0x13]=0xE0,
                        /* BAR2: MMIO at 0xE1000000 (32-bit, non-prefetchable) */
                        [0x18]=0x00,[0x19]=0x00,[0x1A]=0x00,[0x1B]=0xE1,
                        /* ROM BAR: none (UEFI doesn't need VGA BIOS) */
                        /* Subsystem */
                        [0x2C]=0x34,[0x2D]=0x12,[0x2E]=0x11,[0x2F]=0x11,
                        /* Interrupt: IRQ 10 */
                        [0x3C]=0x0A,[0x3D]=0x01,
                    };
                    val = pci_cfg_read_val(vga_cfg, reg, 2);
                }
            } else if (bdf == 0x0020) {
                /* Device 0:4.0 = NVMe Controller (Samsung 980 PRO)
                 * Config space is writable so that pci.sys can enable
                 * MSI/MSI-X and read back the updated state. */
                val = pci_cfg_read_val(nvme_pci_cfg, reg, 2);
            } else {
                /* Check passthrough devices (GPU etc.) */
                u32 pt_val;
                if (bogger_pci_passthrough_config_read(bdf, reg, &pt_val))
                    val = pt_val;
                /* All other BDFs: return 0xFFFFFFFF for vendor/device read
                 * to indicate non-existent device */
            }
            /* Overlay dynamic BAR values for BAR registers (0x10-0x24) */
            dev_idx = pci_bdf_to_dev(bdf);
            if (dev_idx >= 0 && reg >= 0x10 && reg <= 0x24) {
                int bar_idx = (reg - 0x10) / 4;
                if (bar_idx < PCI_NUM_BARS && pci_bars_def[dev_idx][bar_idx].size > 0)
                    val = pci_get_bar_value(dev_idx, bar_idx);
            }
            /* Overlay writable Command register */
            if (dev_idx >= 0 && reg == 0x04) {
                val = (val & 0xFFFF0000) | pci_cmd_reg[dev_idx];
            }
            /* ROM BAR: always return 0 (no expansion ROM on any device) */
            if (dev_idx >= 0 && reg == 0x30) {
                val = 0;
            }
            /* Log NVMe PCI config reads (first 5000 to capture Windows kernel phase) */
            if (bdf == 0x0020) {
                static int nvme_cfg_rd_log;
                if (nvme_cfg_rd_log < 5000) {
                    pr_info("[BOGGER-PCI] NVMe cfg READ reg=0x%02x val=0x%08x (#%d)\n",
                            reg, val, nvme_cfg_rd_log);
                    nvme_cfg_rd_log++;
                }
            }
            /* Record in ring buffer (pre-shift value) */
            {
                struct pci_ring_entry *e = &pci_ring[pci_ring_idx % PCI_RING_SIZE];
                e->bdf = bdf; e->reg = reg; e->val = val;
                e->is_write = 0; e->sz = (sz == 0) ? 1 : (sz == 1) ? 2 : 4;
                pci_ring_idx++;
            }
            /* Shift the value if accessing sub-dword offset (port 0xCFD/0xCFE/0xCFF) */
            if (byte_off)
                val >>= (byte_off * 8);
            break;
        }

        /* ── CMOS/RTC ─────────────────────────────────────────── */
        case 0x70: val = cmos_index; break;
        case 0x71: {
            u64 below_4g = guest_ram_below_4g;
            u32 ext_mb = (u32)(below_4g >> 20);
            u32 ext_64k = (ext_mb > 16) ? ((ext_mb - 16) * 16) : 0;
            /* Above-4G memory in 64KB blocks for CMOS 0x5b-0x5d */
            u32 high_64k = (u32)(guest_ram_above_4g >> 16);
            if (ext_64k > 0xFFFF) ext_64k = 0xFFFF;
            switch (cmos_index) {
            case 0x00: val=0x30; break; case 0x02: val=0x15; break;
            case 0x04: val=0x12; break; case 0x06: val=0x05; break;
            case 0x07: val=0x28; break; case 0x08: val=0x02; break;
            case 0x09: val=0x26; break;
            case 0x0A: val=0x26; break;   /* RTC Status A: divider=010, rate=0110, UIP=0 */
            case 0x0B: val=0x02; break;   /* RTC Status B: 24hr mode, BCD, no IRQs */
            case 0x0C: val=0x00; break;   /* RTC Status C: no IRQ flags */
            case 0x0D: val=0x80; break;   /* RTC Status D: valid RAM, power good */
            case 0x15: val=0x80; break; case 0x16: val=0x02; break;
            case 0x17: val=(ext_mb>0xFFFF?0xFF:ext_mb)&0xFF; break;
            case 0x18: val=(ext_mb>0xFFFF?0xFF:ext_mb)>>8; break;
            case 0x30: val=(ext_mb>0xFFFF?0xFF:ext_mb)&0xFF; break;
            case 0x31: val=(ext_mb>0xFFFF?0xFF:ext_mb)>>8; break;
            case 0x32: val=0x20; break;
            case 0x34: val=ext_64k&0xFF; break;
            case 0x35: val=(ext_64k>>8)&0xFF; break;
            /* Above-4G memory (OVMF reads 0x5b-0x5d for high RAM) */
            case 0x5b: val=high_64k & 0xFF; break;
            case 0x5c: val=(high_64k >> 8) & 0xFF; break;
            case 0x5d: val=(high_64k >> 16) & 0xFF; break;
            default:   val=0x00; break;
            }
            break;
        }

        /* ── PIT (8254) ───────────────────────────────────────── */
        case 0x40: case 0x41: case 0x42: {
            u64 ns = ktime_get_ns();
            u32 ticks = (u32)div_u64(ns * 1193ULL, 1000000ULL);
            val = (0xFFFF - (u16)(ticks & 0xFFFF)) & 0xFF;
            break;
        }
        case 0x43: val = 0x00; break;

        /* ── PIC ──────────────────────────────────────────────── */
        case 0x20: case 0x21: case 0xA0: case 0xA1:
            val = bogger_pic_read((u16)port);
            break;

        /* ── Serial COM1 ──────────────────────────────────────── */
        case 0x3F8: val = 0; break;       /* RBR: no data */
        case 0x3F9: val = 0; break;       /* IER */
        case 0x3FA: val = 0x01; break;    /* IIR: no pending interrupt */
        case 0x3FB: val = serial_lcr; break;    /* LCR: read back last write */
        case 0x3FC: val = 0x03; break;    /* MCR: DTR+RTS */
        case 0x3FD: val = 0x60; break;    /* LSR: THRE+TEMT (TX ready) */
        case 0x3FE: val = 0xB0; break;    /* MSR: DCD+DSR+CTS */
        case 0x3FF: val = serial_scr; break;  /* Scratch: echo back */
        /* ── Serial COM2 (0x2F8) ─────────────────────────────── */
        case 0x2F8 ... 0x2FF:
            if (port == 0x2FD) val = 0x60;     /* LSR */
            else if (port == 0x2FA) val = 0x01; /* IIR */
            else val = 0;
            break;

        /* ── PS/2 (i8042) Controller ─────────────────────────────── */
        case 0x60: /* Data port: read scan code or command response */
            val = ps2_read_data();
            break;
        case 0x64: /* Status register */
            val = ps2_read_status();
            break;

        /* ── DMA Controller (8237) ────────────────────────────── */
        case 0x00: case 0x02: case 0x04: case 0x06: {
            /* DMA Channel current address registers (16-bit).
             * OVMF uses IN AX,DX with DX=0 as a timing delay loop,
             * reading the DMA Channel 0 address counter and expecting
             * it to change.  Return a value derived from ktime so it
             * progresses and the delay loop terminates.
             * Use fine granularity (~256ns) so consecutive reads after
             * VMEXIT overhead (~1-4µs) always return different values. */
            u64 ns = ktime_get_ns();
            val = (u32)(ns >> 8) & 0xFFFF;  /* ~256ns granularity */
            break;
        }
        case 0x01: case 0x03: case 0x05: case 0x07: {
            /* DMA Channel current count registers (16-bit) */
            val = 0x0000;  /* transfer complete */
            break;
        }
        case 0x08: val = 0x0F; break;   /* DMA Status: TC on all channels */
        case 0x09 ... 0x0F: val = 0x00; break;
        case 0x10 ... 0x1F: val = 0x00; break;  /* DMA page registers overlap */
        case 0x80 ... 0x8F: val = 0x00; break;  /* DMA page registers */
        case 0xC0: case 0xC4: case 0xC8: case 0xCC: {
            /* DMA2 Channel current address (16-bit) */
            u64 ns = ktime_get_ns();
            val = (u32)(ns >> 8) & 0xFFFF;
            break;
        }
        case 0xC2: case 0xC6: case 0xCA: case 0xCE:
            val = 0x0000;  /* DMA2 count = 0, done */
            break;
        case 0xD0: val = 0x0F; break;   /* DMA2 Status */
        case 0xD2 ... 0xDF: val = 0x00; break;
        /* ── System Control Port A (0x92) ──────────────────── */
        case 0x92: val = 0x02; break;  /* A20 enabled, no reset pending */
        /* ── System Control Port B ───────────────────────── */
        case 0x61: val = 0x30; break;  /* Timer2 out, refresh req */

        /* ── ACPI PM ──────────────────────────────────────────── */
        case 0x600: /* PM1_STS (16-bit register, may be read as byte/word/dword) */
            val = pm1_sts | ((u32)pm1_en << 16);  /* dword: STS[15:0] | EN[15:0] */
            break;
        case 0x601: /* PM1_STS high byte */
            val = (pm1_sts >> 8) | ((u32)pm1_en << 8);
            break;
        case 0x602: /* PM1_EN low byte */
            val = pm1_en | ((u32)(pm1_cnt & 0xFF) << 16);
            break;
        case 0x603: /* PM1_EN high byte */
            val = (pm1_en >> 8);
            break;
        case 0x604: /* PM1_CNT (16-bit register) */
            val = pm1_cnt;
            break;
        case 0x605: /* PM1_CNT high byte */
            val = (pm1_cnt >> 8);
            break;
        case 0x608: case 0x609: case 0x60A: case 0x60B: {
            /*
             * ACPI PM Timer: nominally 3.579545 MHz.
             * TMR_VAL_EXT flag is set in FADT → 32-bit timer.
             *
             * Use ktime_get_ns() for a monotonic, correctly-paced source.
             * Formula: ticks = nanoseconds * 3579545 / 1_000_000_000
             *
             * Previous bug: the formula was inverted (tsc / (tsc_khz*1000/3579545))
             * which made the timer advance ~1000x too fast, causing OVMF
             * delay loops to exit instantly and re-enter in a tight spin.
             */
            u64 ns = ktime_get_ns();
            u32 ticks = (u32)div_u64(ns * 3579545ULL, 1000000000ULL);
            static int pm_tmr_log_count;
            if (pm_tmr_log_count < 5) {
                pr_info("[BOGGER] PM_TMR read: port=0x%llx ns=%llu ticks=0x%x\n",
                        port, ns, ticks);
                pm_tmr_log_count++;
            }
            val = ticks;
            if (port > 0x608) val >>= (port - 0x608) * 8;
            break;
        }
        /* ── ACPI GPE0 Block (32-bit registers) ─────────────── */
        case 0x620: val = gpe0_sts; break;
        case 0x621: val = gpe0_sts >> 8; break;
        case 0x622: val = gpe0_sts >> 16; break;
        case 0x623: val = gpe0_sts >> 24; break;
        case 0x624: val = gpe0_en; break;
        case 0x625: val = gpe0_en >> 8; break;
        case 0x626: val = gpe0_en >> 16; break;
        case 0x627: val = gpe0_en >> 24; break;
        case 0x628 ... 0x63F: val = 0; break;  /* rest of GPE0 IN block */

        /* ── VGA ──────────────────────────────────────────────── */
        case 0x3C0 ... 0x3CF: case 0x3D0 ... 0x3DF:
            if (passthrough_dev_count > 0) {
                /* GPU passthrough active: forward to real hardware */
                if (sz == 1) val = inb((u16)port);
                else if (sz == 2) val = inw((u16)port);
                else val = inl((u16)port);
            } else {
                val = bogger_vga_ioport_read((u16)port, sz);
            }
            break;

        /* ── Bochs VGA Dispi I/O (VBE interface) ─────────────── */
        case 0x1CE: case 0x1CF: case 0x1D0:
            if (passthrough_dev_count > 0) {
                /* GPU passthrough: return bus float (no Bochs VGA) */
                val = 0xFFFF;
            } else {
                val = bogger_vga_ioport_read((u16)port, sz);
            }
            break;

        /* ── ELCR (Edge/Level Control Registers) ─────────────── */
        case 0x4D0: val = 0x00; break;  /* ELCR1: all edge-triggered */
        case 0x4D1: val = 0x0E; break;  /* ELCR2: IRQ 9,10,11 level */

        /* ── Debug Console ────────────────────────────────────── */
        case 0x402: val = 0xE9; break;

        /* ── fw_cfg ───────────────────────────────────────────── */
        case 0x510: val = fwcfg_selector; break;
        case 0x511: {
            static int fw511_log;
            fwcfg_port511_reads++;
            val = fwcfg_read_byte();
            if (fw511_log < 3) {
                pr_info("[B] R511 sel=%x v=%02x off=%u\n",
                        fwcfg_selector, val, fwcfg_offset-1);
                fw511_log++;
            }
            break;
        }
        /* fw_cfg DMA: OVMF reads 0x514 to detect DMA support.
         * Return 0 to indicate no DMA — forces OVMF to use PIO mode
         * (port 0x510/0x511) which we fully support. */
        case 0x514: case 0x515: case 0x516: case 0x517: val = 0; break;

        /* ── Misc I/O ports that OVMF probes ─────────────────── */
        case 0xB2: case 0xB3: val = 0; break;  /* SMI CMD port — no pending SMI */
        case 0xB000 ... 0xB03F: val = 0; break;  /* PIIX4 ACPI region */
        case 0xB100 ... 0xB10F: val = 0; break;  /* PIIX4 SMBus region */
        case 0xAE00 ... 0xAEFF: val = 0; break;  /* PVPanic device (not present) */

        /* ── IDE/ATA Ports: no disks attached ─────────────────── *
         * Primary: 0x1F0-0x1F7, alt-status 0x3F6
         * Secondary: 0x170-0x177, alt-status 0x376
         * Status ports return 0x00 (BSY=0, DRDY=0 → no device) so
         * OVMF's WaitForBSYClear returns immediately instead of
         * polling for 31s per drive (4 drives = 124s wasted).
         * Other IDE regs return 0xFF (floating bus). */
        case 0x1F7: case 0x3F6:  /* Primary status / alt-status */
        case 0x177: case 0x376:  /* Secondary status / alt-status */
            val = 0x00;
            break;
        case 0x1F0 ... 0x1F6:    /* Primary data/error/features/etc */
        case 0x170 ... 0x176:    /* Secondary data/error/features/etc */
            val = 0xFF;
            break;

        default:
            /* Check if this port belongs to a passthrough device I/O BAR */
            if (passthrough_dev_count > 0 && pt_iobar_in(port, sz, &val))
                break;
            /* Track stuck I/O port polling and return appropriate default.
             * For most unknown ports, return 0xFF (bus float) for byte,
             * 0xFFFF for word, 0xFFFFFFFF for dword reads. */
            if (port == last_ioio_port && vmcb->save.rip == last_ioio_rip) {
                ioio_repeat_count++;
                if (ioio_repeat_count > 50000 && ioio_stuck_logged < 5) {
                    pr_warn("[BOGGER] IOIO stuck: %s port=0x%llx sz=%d RIP=0x%llx RAX=0x%llx (repeats=%d)\n",
                            is_in ? "IN" : "OUT", port, sz, vmcb->save.rip,
                            vmcb->save.rax, ioio_repeat_count);
                    ioio_stuck_logged++;
                }
            } else {
                last_ioio_port = port;
                last_ioio_rip = vmcb->save.rip;
                ioio_repeat_count = 0;
            }
            val = (sz == 0) ? 0xFF : (sz == 1) ? 0xFFFF : 0xFFFFFFFF;
            break;
        }

        /* Store IN result */
        if (sz == 0)      vmcb->save.rax = val & 0xFF;
        else if (sz == 1) vmcb->save.rax = val & 0xFFFF;
        else              vmcb->save.rax = val;

    } else {
        /* ── OUT (write) ──────────────────────────────────────── */
        u32 out_val = (u32)vmcb->save.rax;

        switch (port) {
        case 0xCF8: pci_config_addr = out_val; break;
        case 0xCFC: case 0xCFD: case 0xCFE: case 0xCFF: {
            u32 dev  = (pci_config_addr >> 11) & 0x1F;
            u32 func = (pci_config_addr >> 8) & 0x07;
            u32 reg  = (pci_config_addr & 0xFC) + (port - 0xCFC);
            u32 bdf  = ((pci_config_addr >> 16) & 0xFF) << 8 | (dev << 3) | func;
            int wsz  = (sz == 0) ? 1 : (sz == 1) ? 2 : 4;
            int dev_idx = pci_bdf_to_dev(bdf);
            u32 dword_reg = pci_config_addr & 0xFC;
            pci_total_writes++;

            /* PCI Mechanism 1: bit 31 must be set for valid config writes */
            if (!(pci_config_addr & 0x80000000U))
                break;

            /* Record in ring buffer */
            {
                struct pci_ring_entry *e = &pci_ring[pci_ring_idx % PCI_RING_SIZE];
                e->bdf = bdf; e->reg = reg; e->val = out_val;
                e->is_write = 1; e->sz = wsz;
                pci_ring_idx++;
            }

            /* ALWAYS log CMD register writes (reg 0x04) — no limit */
            if (dword_reg == 0x04) {
                pr_info("[BOGGER-PCI] CMD WR bdf=0x%04x val=0x%04x (Mem=%d IO=%d BM=%d)\n",
                        bdf, out_val & 0xFFFF,
                        !!(out_val & 2), !!(out_val & 1), !!(out_val & 4));
            }
            /* Log PCI config writes (first 200) */
            {
                static int pci_wr_log;
                if (pci_wr_log < 200) {
                    pr_info("[BOGGER-PCI] WR bdf=0x%04x reg=0x%02x val=0x%08x sz=%d\n",
                            bdf, reg, out_val, wsz);
                    pci_wr_log++;
                    if (pci_wr_log == 200)
                        pr_info("[BOGGER-PCI] WR log limit reached (200)\n");
                }
            }

            /* Handle BAR writes for emulated devices */
            if (dev_idx >= 0 && dword_reg >= 0x10 && dword_reg <= 0x24) {
                int bar_idx = (dword_reg - 0x10) / 4;
                if (bar_idx < PCI_NUM_BARS && pci_bars_def[dev_idx][bar_idx].size > 0) {
                    u32 wr = out_val;
                    const struct pci_bar_info *bi = &pci_bars_def[dev_idx][bar_idx];
                    /* Check if this is a BAR size probe (writing all 1s) */
                    if ((wr & ~0x0FU) == (~0x0FU & 0xFFFFFFF0U) ||
                        wr == 0xFFFFFFFF || wr == 0xFFFFFFFE || wr == 0xFFFFFFFC) {
                        pci_bar_probing[dev_idx][bar_idx] = true;
                    } else {
                        /* OVMF is writing the actual base address */
                        pci_bar_probing[dev_idx][bar_idx] = false;
                        if (bi->flags & 1)
                            pci_bar_written[dev_idx][bar_idx] = wr & 0xFFFFFFFC;
                        else
                            pci_bar_written[dev_idx][bar_idx] = wr & 0xFFFFFFF0;
                        if (wr != 0)
                            pr_info("[BOGGER-PCI] BAR ASSIGN dev=%d bar=%d addr=0x%08x\n",
                                    dev_idx, bar_idx, pci_bar_written[dev_idx][bar_idx]);

                        /* NVMe BAR0 relocated — dynamically remap NPT pages */
                        if (dev_idx == 5 && bar_idx == 0) {
                            u64 new_base = (u64)(wr & 0xFFFFFFF0);
                            if (new_base != 0 && new_base != nvme_bar_active_gpa)
                                bogger_nvme_remap_bar(new_base);
                        }
                    }
                    break;
                }
            }
            /* Handle ROM BAR writes (offset 0x30) — always return 0 = no ROM */
            if (dev_idx >= 0 && dword_reg == 0x30) {
                /* Silently consume ROM BAR probes; we have no expansion ROMs */
                break;
            }
            /* Handle Command register writes */
            if (dev_idx >= 0 && dword_reg == 0x04) {
                /* Preserve all standard PCI command bits (0-10):
                 * IO, Mem, BusMaster, SpecialCycles, MemWrInvalidate,
                 * VGAPaletteSnoop, ParityErrorResp, reserved, SERR,
                 * FastB2B, INTx Disable */
                pci_cmd_reg[dev_idx] = (u16)(out_val & 0x07FF);
                break;
            }
            /* Handle NVMe PCI config writes (BDF 0x0020).
             * All writes to the NVMe config space (capability region 0x40+,
             * interrupt line 0x3C, and status bits) are stored in the
             * writable nvme_pci_cfg[] array so that readback works correctly.
             * This is critical for pci.sys MSI/MSI-X resource allocation. */
            if (bdf == 0x0020 && reg >= 0x3C) {
                int i;
                /* Always log NVMe config writes (no limit) */
                pr_info("[BOGGER-NVMe] PCI WR reg=0x%02x val=0x%08x sz=%d\n",
                        reg, out_val, wsz);
                /* Store written bytes into the writable config space */
                for (i = 0; i < wsz && (reg + i) < 256; i++)
                    nvme_pci_cfg[reg + i] = (u8)((out_val >> (i * 8)) & 0xFF);

                /* Detect MSI-X enable (byte 0x73, bit 7 = enable) */
                if (nvme_pci_cfg[0x73] & 0x80) {
                    if (!nvme_msix_enabled) {
                        nvme_msix_enabled = true;
                        pr_info("[BOGGER-NVMe] MSI-X ENABLED via PCI config write\n");
                    }
                } else {
                    if (nvme_msix_enabled) {
                        nvme_msix_enabled = false;
                        pr_info("[BOGGER-NVMe] MSI-X DISABLED via PCI config write\n");
                    }
                }
                /* Detect MSI enable (byte 0x42, bit 0 = enable) */
                if (nvme_pci_cfg[0x42] & 0x01) {
                    static bool msi_logged;
                    if (!msi_logged) {
                        pr_info("[BOGGER-NVMe] MSI ENABLED: addr=0x%08x%08x data=0x%04x\n",
                                pci_cfg_read_val(nvme_pci_cfg, 0x48, 2),
                                pci_cfg_read_val(nvme_pci_cfg, 0x44, 2),
                                pci_cfg_read_val(nvme_pci_cfg, 0x4C, 1) & 0xFFFF);
                        msi_logged = true;
                    }
                }
                break;
            }
            /* Try passthrough, silently drop if not a PT device */
            bogger_pci_passthrough_config_write(bdf, reg, out_val, wsz);
            break;
        }
        /* OVMF debug port (PlatformDebugLibIoPort) */
        case 0x402: {
            static char dbg_line[256]; static int dbg_pos;
            char c = (char)(out_val & 0xFF);
            if (c == '\n' || c == '\r' || dbg_pos >= 254) {
                if (dbg_pos > 0) { dbg_line[dbg_pos] = 0; pr_info("[OVMF-DBG] %s\n", dbg_line); dbg_pos = 0; }
            } else if (c >= 0x20) {
                dbg_line[dbg_pos++] = c;
            }
            break;
        }
        case 0x70: cmos_index = (u8)(out_val & 0x7F); break;
        case 0x71: break;
        case 0x40: case 0x41: case 0x42: case 0x43: break;
        case 0x20: case 0x21: case 0xA0: case 0xA1:
            bogger_pic_write((u16)port, (u8)out_val);
            break;

        case 0x3F8: {
            static char line[256]; static int pos;
            char c = (char)(out_val & 0xFF);
            if (c == '\n' || c == '\r' || pos >= 254) {
                if (pos > 0) { line[pos] = 0; pr_info("[OVMF] %s\n", line); pos = 0; }
            } else if (c >= 0x20) line[pos++] = c;
            break;
        }
        case 0x3F9: case 0x3FA: case 0x3FC: case 0x3FE: break;
        case 0x3FB: serial_lcr = (u8)out_val; break;    /* LCR */
        case 0x3FF: serial_scr = (u8)out_val; break;    /* Scratch */

        case 0x60: /* PS/2 data port write */
            ps2_write_data((u8)out_val);
            break;
        case 0x64: /* PS/2 command port write */
            ps2_write_command((u8)out_val);
            break;
        case 0x2F8: {
            /* COM2 serial output */
            static char com2[256]; static int cp;
            char c = (char)(out_val & 0xFF);
            if (c == '\n' || c == '\r' || cp >= 254) {
                if (cp > 0) { com2[cp] = 0; pr_info("[OVMF-COM2] %s\n", com2); cp = 0; }
            } else if (c >= 0x20) com2[cp++] = c;
            break;
        }
        case 0x2F9 ... 0x2FF: break;
        case 0x3C0 ... 0x3CF: case 0x3D0 ... 0x3DF:
            if (passthrough_dev_count > 0) {
                /* GPU passthrough active: forward to real hardware */
                if (sz == 1) outb((u8)out_val, (u16)port);
                else if (sz == 2) outw((u16)out_val, (u16)port);
                else outl(out_val, (u16)port);
            } else {
                bogger_vga_ioport_write((u16)port, out_val, sz);
            }
            break;
        /* Bochs VGA Dispi ports */
        case 0x1CE: case 0x1CF: case 0x1D0:
            if (passthrough_dev_count > 0) {
                /* GPU passthrough: discard (no Bochs VGA) */
            } else {
                bogger_vga_ioport_write((u16)port, out_val, sz);
            }
            break;
        /* ELCR */
        case 0x4D0: case 0x4D1: break;

        case 0x510: {
            static int fwcfg_log_count;
            fwcfg_selector = (u16)out_val;
            fwcfg_offset = 0;
            fwcfg_buf_valid = false;
            if (fwcfg_log_count < 20) {
                pr_info("[BOGGER-FWCFG] select=0x%04x\n", fwcfg_selector);
                fwcfg_log_count++;
            }
            break;
        }
        case 0x511: break;
        /* fw_cfg DMA write — ignore, we don't support DMA mode */
        case 0x514: case 0x515: case 0x516: case 0x517: break;

        case 0x600: /* PM1_STS: write-1-to-clear */
            pm1_sts &= ~((u16)out_val);
            break;
        case 0x601:
            pm1_sts &= ~((u16)(out_val << 8));
            break;
        case 0x602: pm1_en = (pm1_en & 0xFF00) | (out_val & 0xFF); break;
        case 0x603: pm1_en = (pm1_en & 0x00FF) | ((out_val & 0xFF) << 8); break;
        case 0x604: case 0x605: {
            u16 new_cnt;
            if (port == 0x604)
                new_cnt = (pm1_cnt & 0xFF00) | (out_val & 0xFF);
            else
                new_cnt = (pm1_cnt & 0x00FF) | ((out_val & 0xFF) << 8);
            /* Check SLP_EN (bit 13) */
            if (new_cnt & (1U << 13)) {
                u16 slp_typ = (new_cnt >> 10) & 0x07;
                if (slp_typ == 5 || slp_typ == 7) {
                    pr_emerg("[BOGGER] S5 power-off via PM1_CNT (SLP_TYP=%u)\n", slp_typ);
                    vmcb->save.rip = 0; /* signal shutdown */
                    return;
                }
                /* S3 sleep: just clear SLP_EN and continue */
                new_cnt &= ~(1U << 13);
                /* Set WAK_STS in PM1_STS */
                pm1_sts |= (1U << 15);
            }
            pm1_cnt = new_cnt | 0x01; /* SCI_EN always set */
            break;
        }
        case 0x620: gpe0_sts &= ~((u32)out_val); break; /* write-1-to-clear */
        case 0x621: gpe0_sts &= ~((u32)(out_val << 8)); break;
        case 0x622: gpe0_sts &= ~((u32)(out_val << 16)); break;
        case 0x623: gpe0_sts &= ~((u32)(out_val << 24)); break;
        case 0x624: gpe0_en = (gpe0_en & 0xFFFFFF00) | (out_val & 0xFF); break;
        case 0x625: gpe0_en = (gpe0_en & 0xFFFF00FF) | ((out_val & 0xFF) << 8); break;
        case 0x626: gpe0_en = (gpe0_en & 0xFF00FFFF) | ((out_val & 0xFF) << 16); break;
        case 0x627: gpe0_en = (gpe0_en & 0x00FFFFFF) | ((out_val & 0xFF) << 24); break;
        case 0x628 ... 0x63F: break;  /* rest of GPE0 block */
        case 0x606 ... 0x607: break;

        case 0xCF9: {
            /* PCI Reset Control Register:
             * Bit 1 = System Reset (must be set before bit 2)
             * Bit 2 = Reset CPU  */
            static u8 cf9_val;
            static int cf9_reset_count;
            u8 old_cf9 = cf9_val;
            cf9_val = out_val;
            if ((out_val & 0x04) && !(old_cf9 & 0x04)) {
                cf9_reset_count++;
                if (cf9_reset_count <= 3) {
                    pr_info("[BOGGER] Platform reset via 0xCF9 (val=0x%02x, count=%d)\n",
                            out_val, cf9_reset_count);
                    memset(&guest_gprs, 0, sizeof(guest_gprs));
                    bogger_vmcb_reset(vmcb);
                    return;
                } else {
                    pr_warn("[BOGGER] Ignoring excess reset via 0xCF9 (count=%d)\n", cf9_reset_count);
                }
            }
            break;
        }
        case 0x92: {
            /* System Control Port A:
             * Bit 0 = A20 gate enable (always enabled in our emulation)
             * Bit 1 = Fast CPU reset
             *
             * IMPORTANT: OVMF writes various values (0x02, 0xFF) to port 0x92
             * during initialization for A20 gate control.  We NEVER trigger a
             * reset from port 0x92.  Only 0xCF9 is used for intentional resets.
             * This prevents spurious resets during OVMF SEC→PEI transition. */
            /* Just acknowledge A20 state, ignore reset bit */
            break;
        }

        case 0x00 ... 0x1F: case 0xC0 ... 0xDF: case 0x80 ... 0x8F: break;  /* DMA */
        /* SMI Command Port — OVMF writes here to enable/disable ACPI.
         * We're always in ACPI mode (SCI_EN=1), so just acknowledge. */
        case 0xB2: case 0xB3: break;
        /* PIIX4 ACPI/SMBus regions */
        case 0xB000 ... 0xB03F: break;
        case 0xB100 ... 0xB10F: break;
        /* PVPanic device */
        case 0xAE00 ... 0xAEFF: break;
        /* IDE controller ports (writes: silently absorb) */
        case 0x1F0 ... 0x1F7: case 0x3F6: break;
        case 0x170 ... 0x177: case 0x376: break;
        case 0xC060 ... 0xC06F: break;
        default:
            /* Check if this port belongs to a passthrough device I/O BAR */
            if (passthrough_dev_count > 0)
                pt_iobar_out(port, sz, out_val);
            break;
        }
    }

    /* Advance RIP — AMD SVM specification:
     * For IOIO intercepts, EXITINFO2 always contains the NRIP (next RIP).
     * This is the most reliable source. Also try VMCB.next_rip (NRIP Save). */
    {
        u64 nrip = vmcb->control.exit_info_2;
        if (nrip > vmcb->save.rip && nrip < vmcb->save.rip + 16) {
            vmcb->save.rip = nrip;
        } else {
            nrip = vmcb->control.next_rip;
            if (nrip > vmcb->save.rip && nrip < vmcb->save.rip + 16) {
                vmcb->save.rip = nrip;
            } else {
                /* Last resort fallback: estimate instruction length.
                 * IN AL,imm8 / OUT imm8,AL = 2 bytes
                 * IN AL,DX / OUT DX,AL = 1 byte
                 * IN AX/EAX,imm8 / OUT imm8,AX/EAX = 2 bytes
                 * IN AX/EAX,DX / OUT DX,AX/EAX = 1 byte
                 * With 0x66 prefix: +1 byte
                 * REP prefix: +1 byte (for string I/O)
                 * We can't perfectly determine this, so assume 2 bytes as
                 * a conservative default (most IN/OUT use imm8 encoding). */
                vmcb->save.rip += 2;
            }
        }
    }
}





