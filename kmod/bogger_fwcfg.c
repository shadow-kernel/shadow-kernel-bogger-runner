// SPDX-License-Identifier: GPL-2.0
/*
 * bogger_fwcfg.c – QEMU fw_cfg device emulation
 *
 * OVMF reads RAM size and E820 map via fw_cfg I/O ports 0x510/0x511.
 */
#include "bogger_fwcfg.h"
#include "bogger_smbios.h"
#include "bogger_acpi.h"

/* ── fw_cfg selectors ─────────────────────────────────────────────── */
#define FW_CFG_SIGNATURE    0x0000
#define FW_CFG_ID           0x0001
#define FW_CFG_RAM_SIZE     0x0003
#define FW_CFG_NB_CPUS      0x0005
#define FW_CFG_MAX_CPUS     0x0006
#define FW_CFG_FILE_DIR     0x0019
#define FW_CFG_E820_TABLE   0x8003
#define FW_CFG_FILE_E820    0x0020
#define FW_CFG_FILE_RSDP    0x0021
#define FW_CFG_FILE_SMBIOS  0x0022
#define FW_CFG_FILE_LOADER  0x0023
#define FW_CFG_FILE_ACPI    0x0024
#define FW_CFG_FILE_BOOTFAIL 0x0025
#define FW_CFG_FILE_RSVMEM  0x0026
#define FW_CFG_FILE_PCIHOLE64SZ  0x0027

u16  fwcfg_selector;
u32  fwcfg_offset;
bool fwcfg_buf_valid;

struct __attribute__((packed)) fw_e820_entry {
    u64 address;
    u64 length;
    u32 type;
};

struct __attribute__((packed)) fw_cfg_file {
    u32 size;
    u16 select;
    u16 reserved;
    char name[56];
};

static u8  fwcfg_buf[4096];
static u32 fwcfg_buf_len;

void fwcfg_build_data(u16 sel)
{
    fwcfg_buf_len = 0;
    fwcfg_buf_valid = true;

    switch (sel) {
    case FW_CFG_SIGNATURE:
        memcpy(fwcfg_buf, "QEMU", 4);
        fwcfg_buf_len = 4;
        break;

    case FW_CFG_ID:
        /* ID value (LE u32): bit 0 = traditional I/O, bit 1 = DMA.
         * We only support traditional I/O → value = 1 (LE). */
        fwcfg_buf[0] = 1; fwcfg_buf[1] = 0;
        fwcfg_buf[2] = 0; fwcfg_buf[3] = 0;
        fwcfg_buf_len = 4;
        break;

    case FW_CFG_NB_CPUS:
    case FW_CFG_MAX_CPUS:
        /* LE u16: 1 CPU */
        fwcfg_buf[0] = 1; fwcfg_buf[1] = 0;
        fwcfg_buf_len = 2;
        break;

    case FW_CFG_RAM_SIZE: {
        /* Report below-4G RAM size (OVMF uses this for LowerMemorySize) */
        u64 sz = guest_ram_below_4g;
        memcpy(fwcfg_buf, &sz, 8);
        fwcfg_buf_len = 8;
        break;
    }

    case FW_CFG_FILE_DIR: {
        struct fw_cfg_file *f;
        /* E820 entry count: 5 base entries + 1 if RAM above 4G */
        u32 num_e820 = (guest_ram_size > 0xC0000000ULL) ? 6 : 5;
        u32 e820_size = num_e820 * sizeof(struct fw_e820_entry);
        u32 cnt = cpu_to_be32(8);  /* 8 files */

        memset(fwcfg_buf, 0, sizeof(fwcfg_buf));
        memcpy(fwcfg_buf, &cnt, 4);

        /* File 0: etc/e820 */
        f = (struct fw_cfg_file *)(fwcfg_buf + 4);
        f->size = cpu_to_be32(e820_size);
        f->select = cpu_to_be16(FW_CFG_FILE_E820);
        f->reserved = 0;
        memset(f->name, 0, 56);
        strncpy(f->name, "etc/e820", 55);

        /* File 1: etc/acpi/rsdp */
        f = (struct fw_cfg_file *)(fwcfg_buf + 4 + 1*sizeof(struct fw_cfg_file));
        f->size = cpu_to_be32(acpi_rsdp_blob_len);
        f->select = cpu_to_be16(FW_CFG_FILE_RSDP);
        f->reserved = 0;
        memset(f->name, 0, 56);
        strncpy(f->name, "etc/acpi/rsdp", 55);

        /* File 2: etc/smbios/smbios-tables */
        f = (struct fw_cfg_file *)(fwcfg_buf + 4 + 2*sizeof(struct fw_cfg_file));
        {
            u32 smbios_sz = 0;
            bogger_smbios_get_data(&smbios_sz);
            f->size = cpu_to_be32(smbios_sz);
        }
        f->select = cpu_to_be16(FW_CFG_FILE_SMBIOS);
        f->reserved = 0;
        memset(f->name, 0, 56);
        strncpy(f->name, "etc/smbios/smbios-tables", 55);

        /* File 3: etc/table-loader */
        f = (struct fw_cfg_file *)(fwcfg_buf + 4 + 3*sizeof(struct fw_cfg_file));
        f->size = cpu_to_be32(acpi_loader_cmds_len);
        f->select = cpu_to_be16(FW_CFG_FILE_LOADER);
        f->reserved = 0;
        memset(f->name, 0, 56);
        strncpy(f->name, "etc/table-loader", 55);

        /* File 4: etc/acpi/tables */
        f = (struct fw_cfg_file *)(fwcfg_buf + 4 + 4*sizeof(struct fw_cfg_file));
        f->size = cpu_to_be32(acpi_tables_blob_len);
        f->select = cpu_to_be16(FW_CFG_FILE_ACPI);
        f->reserved = 0;
        memset(f->name, 0, 56);
        strncpy(f->name, "etc/acpi/tables", 55);

        /* File 5: etc/boot-fail-wait — tell OVMF to wait on boot failure */
        f = (struct fw_cfg_file *)(fwcfg_buf + 4 + 5*sizeof(struct fw_cfg_file));
        f->size = cpu_to_be32(4);
        f->select = cpu_to_be16(FW_CFG_FILE_BOOTFAIL);
        f->reserved = 0;
        memset(f->name, 0, 56);
        strncpy(f->name, "etc/boot-fail-wait", 55);

        /* File 6: etc/reserved-memory-end — PCI MMIO window boundary */
        f = (struct fw_cfg_file *)(fwcfg_buf + 4 + 6*sizeof(struct fw_cfg_file));
        f->size = cpu_to_be32(8);
        f->select = cpu_to_be16(FW_CFG_FILE_RSVMEM);
        f->reserved = 0;
        memset(f->name, 0, 56);
        strncpy(f->name, "etc/reserved-memory-end", 55);

        /* File 7: etc/pci-hole64-size — 64-bit PCI MMIO window size.
         * OVMF reads this to create a 64‑bit MMIO window for large GPU
         * BARs (VRAM) that don't fit in the 32-bit MMIO hole.
         * Without this, OVMF cannot assign 64-bit BARs → GPU unusable. */
        f = (struct fw_cfg_file *)(fwcfg_buf + 4 + 7*sizeof(struct fw_cfg_file));
        f->size = cpu_to_be32(8);
        f->select = cpu_to_be16(FW_CFG_FILE_PCIHOLE64SZ);
        f->reserved = 0;
        memset(f->name, 0, 56);
        strncpy(f->name, "etc/pci-hole64-size", 55);

        fwcfg_buf_len = 4 + 8 * sizeof(struct fw_cfg_file);
        break;
    }

    case FW_CFG_FILE_RSDP: {
        /* Return the RSDP blob built by bogger_acpi_build() */
        if (acpi_rsdp_blob_len > 0 && acpi_rsdp_blob_len <= sizeof(fwcfg_buf)) {
            memcpy(fwcfg_buf, acpi_rsdp_blob, acpi_rsdp_blob_len);
            fwcfg_buf_len = acpi_rsdp_blob_len;
        } else {
            fwcfg_buf_len = 0;
        }
        break;
    }

    case FW_CFG_FILE_SMBIOS: {
        u32 slen = 0;
        u8 *sdata = bogger_smbios_get_data(&slen);
        if (sdata && slen > 0 && slen <= sizeof(fwcfg_buf)) {
            memcpy(fwcfg_buf, sdata, slen);
            fwcfg_buf_len = slen;
        } else {
            fwcfg_buf_len = 0;
        }
        break;
    }

    case FW_CFG_FILE_LOADER:
        /* etc/table-loader: QEMU linker/loader commands for ACPI tables.
         * OVMF processes these to allocate, link, and checksum ACPI.
         * Without these commands, OVMF installs zero ACPI tables. */
        if (acpi_loader_cmds_len > 0 && acpi_loader_cmds_len <= sizeof(fwcfg_buf)) {
            memcpy(fwcfg_buf, acpi_loader_cmds, acpi_loader_cmds_len);
            fwcfg_buf_len = acpi_loader_cmds_len;
        } else {
            fwcfg_buf_len = 0;
        }
        break;

    case FW_CFG_FILE_ACPI:
        /* etc/acpi/tables: concatenated ACPI table blob (DSDT+FADT+MADT+HPET+XSDT) */
        if (acpi_tables_blob_len > 0 && acpi_tables_blob_len <= sizeof(fwcfg_buf)) {
            memcpy(fwcfg_buf, acpi_tables_blob, acpi_tables_blob_len);
            fwcfg_buf_len = acpi_tables_blob_len;
        } else {
            fwcfg_buf_len = 0;
        }
        break;

    case FW_CFG_FILE_BOOTFAIL: {
        /* etc/boot-fail-wait: u32 seconds to wait on boot failure */
        u32 wait_secs = cpu_to_le32(10);
        memcpy(fwcfg_buf, &wait_secs, 4);
        fwcfg_buf_len = 4;
        break;
    }

    case FW_CFG_FILE_RSVMEM: {
        /* etc/reserved-memory-end: u64 LE — end of reserved memory.
         * Tells OVMF the upper boundary for PCI MMIO allocation. */
        u64 rsvmem_end = cpu_to_le64(0xFEC00000ULL);
        memcpy(fwcfg_buf, &rsvmem_end, 8);
        fwcfg_buf_len = 8;
        break;
    }

    case FW_CFG_FILE_PCIHOLE64SZ: {
        /* etc/pci-hole64-size: u64 LE — size of the 64-bit PCI MMIO window.
         * OVMF places this window above all physical RAM.  We advertise
         * 32 GB (0x800000000) which accommodates GPUs with up to 24 GB VRAM.
         * Without this, OVMF has NO 64-bit address space for large BARs! */
        u64 hole64_size = cpu_to_le64(0x800000000ULL);  /* 32 GB */
        memcpy(fwcfg_buf, &hole64_size, 8);
        fwcfg_buf_len = 8;
        pr_info_once("[BOGGER-FW] pci-hole64-size = 32 GB (0x800000000)\n");
        break;
    }

    case FW_CFG_FILE_E820: {
        struct fw_e820_entry *e = (struct fw_e820_entry *)fwcfg_buf;
        u64 below_4g = guest_ram_size;
        u64 above_4g = 0;
        int num_entries;

        if (below_4g > 0xC0000000ULL) {
            above_4g = below_4g - 0xC0000000ULL;
            below_4g = 0xC0000000ULL;
        }

        /* Entry 0: 0x00000-0x9FFFF: Conventional memory (640 KB) */
        e[0].address = cpu_to_le64(0);
        e[0].length  = cpu_to_le64(0xA0000ULL);
        e[0].type    = cpu_to_le32(1);

        /* Entry 1: 0xA0000-0xBFFFF: VGA memory (reserved) */
        e[1].address = cpu_to_le64(0xA0000ULL);
        e[1].length  = cpu_to_le64(0x20000ULL);
        e[1].type    = cpu_to_le32(2);  /* Reserved */

        /* Entry 2: 0x100000 - below_4g: Main usable RAM */
        e[2].address = cpu_to_le64(0x100000ULL);
        e[2].length  = cpu_to_le64(below_4g - 0x100000ULL);
        e[2].type    = cpu_to_le32(1);

        /* Entry 3: 0xE0000-0xFFFFF: ACPI Reclaim (ACPI tables + RSDP)
         * Note: This overlaps with e[2] but has higher priority in OVMF;
         * OVMF's e820 parser handles overlapping regions correctly. */
        e[3].address = cpu_to_le64(0xE0000ULL);
        e[3].length  = cpu_to_le64(0x20000ULL);
        e[3].type    = cpu_to_le32(3);  /* ACPI Reclaim */

        /* Entry 4: 0xC0000000-0xFFFFFFFF: MMIO Reserved */
        e[4].address = cpu_to_le64(0xC0000000ULL);
        e[4].length  = cpu_to_le64(0x40000000ULL);
        e[4].type    = cpu_to_le32(2);

        num_entries = 5;

        /* High memory above 4GB */
        if (above_4g > 0) {
            e[5].address = cpu_to_le64(0x100000000ULL);
            e[5].length  = cpu_to_le64(above_4g);
            e[5].type    = cpu_to_le32(1);
            num_entries = 6;
        }

        fwcfg_buf_len = num_entries * sizeof(struct fw_e820_entry);
        break;
    }

    case FW_CFG_E820_TABLE: {
        struct fw_e820_entry entries[5];
        u32 cnt_be;
        u64 below_4g = guest_ram_size;
        u64 above_4g = 0;
        int num_entries = 3;

        if (below_4g > 0xC0000000ULL) {
            above_4g = below_4g - 0xC0000000ULL;
            below_4g = 0xC0000000ULL;
        }

        entries[0].address = 0;           entries[0].length = 0xA0000ULL;                entries[0].type = 1;
        entries[1].address = 0x100000ULL; entries[1].length = below_4g - 0x100000ULL;    entries[1].type = 1;
        entries[2].address = 0xC0000000ULL; entries[2].length = 0x40000000ULL;            entries[2].type = 2;

        if (above_4g > 0) {
            entries[3].address = 0x100000000ULL;
            entries[3].length = above_4g;
            entries[3].type = 1;
            num_entries = 4;
        }

        cnt_be = cpu_to_be32(num_entries);
        memcpy(fwcfg_buf, &cnt_be, 4);
        memcpy(fwcfg_buf + 4, entries, num_entries * sizeof(struct fw_e820_entry));
        fwcfg_buf_len = 4 + num_entries * sizeof(struct fw_e820_entry);
        break;
    }

    default:
        fwcfg_buf_valid = false;
        break;
    }
}

u8 fwcfg_read_byte(void)
{
    u8 val = 0;
    if (!fwcfg_buf_valid)
        fwcfg_build_data(fwcfg_selector);
    if (fwcfg_offset < fwcfg_buf_len)
        val = fwcfg_buf[fwcfg_offset];
    fwcfg_offset++;
    return val;
}

