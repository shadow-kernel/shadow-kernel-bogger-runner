// SPDX-License-Identifier: GPL-2.0
/*
 * bogger_acpi.c – ACPI table generator (RSDP, XSDT, FADT, MADT, DSDT, HPET)
 *
 * Builds ACPI tables for OVMF and exports them via fw_cfg linker/loader
 * protocol so OVMF's AcpiPlatformDxe can install them through the
 * EFI_ACPI_TABLE_PROTOCOL interface.
 *
 * Also pre-places tables in guest RAM at legacy addresses for fallback.
 */
#include "bogger_acpi.h"

#define ACPI_TABLE_GPA  0x000E0000ULL
#define ACPI_RSDP_GPA   0x000F0000ULL

static u8 acpi_checksum(void *buf, int len)
{
    u8 sum = 0;
    int i;
    for (i = 0; i < len; i++)
        sum += ((u8 *)buf)[i];
    return sum;
}

static void acpi_fix_checksum(void *buf, int len, int cksum_off)
{
    ((u8 *)buf)[cksum_off] = 0;
    ((u8 *)buf)[cksum_off] = -acpi_checksum(buf, len);
}

/* Extended DSDT (AML bytecode):
 *
 * DefinitionBlock ("DSDT.aml", "DSDT", 2, "BOGGER", "BOGGTBL0", 1)
 * {
 *   Scope(\_SB) {
 *     Device(PCI0) {
 *       Name(_HID, EisaId("PNP0A08"))
 *       Name(_CID, EisaId("PNP0A03"))
 *       Name(_ADR, 0x00000000)
 *       Method(_OSC, 4) { Return(Arg3) }
 *       Name(_CRS, ResourceTemplate() {
 *         WordBusNumber(ResourceProducer,MinFixed,MaxFixed,PosDecode,0,0,0xFF,0,0x100)
 *         IO(Decode16,0xCF8,0xCF8,1,8)
 *         WordIO(ResourceProducer,MinFixed,MaxFixed,PosDecode,EntireRange,0,0,0x0CF7,0,0x0CF8)
 *         WordIO(ResourceProducer,MinFixed,MaxFixed,PosDecode,EntireRange,0,0x0D00,0xFFFF,0,0xF300)
 *         DWordMemory(ResourceProducer,PosDecode,MinFixed,MaxFixed,Cacheable,ReadWrite,0,0xC0000000,0xFEBFFFFF,0,0x3EC00000)
 *       })
 *       Name(_PRT, Package() {
 *         Package(){0x0004FFFF,0,0,0x0B},  // Dev4 INTA -> IRQ 11
 *       })
 *     }
 *   }
 * }
 *
 * We compile this manually to AML bytecode below.
 * For simplicity, we build the AML programmatically.
 */

/* Helper: encode AML PkgLength at buf[pos].
 * Returns number of bytes used for the encoding (1-4).
 * val includes the length of the PkgLength field itself. */
static u32 aml_encode_pkglen(u8 *buf, u32 pos, u32 val)
{
    if (val < 0x3F) {
        buf[pos] = (u8)val;
        return 1;
    } else if (val < 0x0FFF) {
        buf[pos]   = (u8)(0x40 | (val & 0x0F));
        buf[pos+1] = (u8)(val >> 4);
        return 2;
    } else if (val < 0x0FFFFF) {
        buf[pos]   = (u8)(0x80 | (val & 0x0F));
        buf[pos+1] = (u8)(val >> 4);
        buf[pos+2] = (u8)(val >> 12);
        return 3;
    } else {
        buf[pos]   = (u8)(0xC0 | (val & 0x0F));
        buf[pos+1] = (u8)(val >> 4);
        buf[pos+2] = (u8)(val >> 12);
        buf[pos+3] = (u8)(val >> 20);
        return 4;
    }
}

/* Helper to build the DSDT AML in a buffer.
 * Returns total size written.
 *
 * Produces valid AML for:
 *   DefinitionBlock("DSDT","DSDT",2,"BOGGER","BOGGTBL0",1) {
 *     Name(\_S5_, Package(4){5,5,0,0})   // S5 soft-off SLP_TYP
 *     Scope(\_SB_) {
 *       Device(PCI0) {
 *         Name(_HID, EisaId("PNP0A03"))
 *         Name(_ADR, 0)
 *         Name(_CRS, ResourceTemplate() {
 *           WordBusNumber(...)
 *           IO(Decode16,0xCF8,0xCF8,1,8)
 *           WordIO(...)
 *           DWordMemory(0xC0000000,0xFEBFFFFF)
 *         })
 *         Device(GFX0) { Name(_ADR, 0x00030000) }
 *         Device(HDAU) { Name(_ADR, 0x00030001) }
 *         Device(NVME) { Name(_ADR, 0x00040000) }
 *         Name(_PRT, Package(3) { ... })
 *       }
 *     }
 *   }
 */
static u32 build_dsdt_aml(u8 *buf, u32 max_len)
{
    u32 p = 36;  /* skip ACPI header — fill later */
    u32 scope_start, dev_start, prt_start, inner_start;

    /* ═══ Name(\_S5_, Package(4) { 5, 5, 0, 0 }) ═══
     * Required for OVMF/Windows S5 (soft power off).
     * Tells the OS what SLP_TYP value to write for shutdown. */
    buf[p++] = 0x08;  /* NameOp */
    buf[p++] = 0x5C;  /* RootPrefix '\' */
    buf[p++] = '_'; buf[p++] = 'S'; buf[p++] = '5'; buf[p++] = '_';
    buf[p++] = 0x12;  /* PackageOp */
    buf[p++] = 0x08;  /* PkgLength = 8 (self + 1 count + 6 elements) */
    buf[p++] = 0x04;  /* NumElements = 4 */
    buf[p++] = 0x0A; buf[p++] = 0x05;  /* BytePrefix 5 (SLP_TYPa) */
    buf[p++] = 0x0A; buf[p++] = 0x05;  /* BytePrefix 5 (SLP_TYPb) */
    buf[p++] = 0x00;  /* ZeroOp (reserved) */
    buf[p++] = 0x00;  /* ZeroOp (reserved) */

    /* ═══ Scope(\_SB_) ═══
     * NOTE: The scope path is \._SB_ = RootPrefix + NameSeg.
     * Do NOT use DualNamePrefix (0x2E) — that expects TWO 4-char
     * NameSegs and would eat the DeviceOp as the second name! */
    buf[p++] = 0x10;  /* ScopeOp */
    scope_start = p;
    p += 2;           /* PkgLength placeholder — 2 bytes (content > 63) */
    buf[p++] = 0x5C;  /* RootPrefix '\' */
    buf[p++] = '_'; buf[p++] = 'S'; buf[p++] = 'B'; buf[p++] = '_';

    /* Device(PCI0) */
    buf[p++] = 0x5B; buf[p++] = 0x82;  /* ExtOp + DeviceOp */
    dev_start = p;
    p += 2;  /* PkgLength placeholder — 2 bytes (content > 63) */
    buf[p++] = 'P'; buf[p++] = 'C'; buf[p++] = 'I'; buf[p++] = '0';

    /* Name(_HID, EisaId("PNP0A08")) — PCI Express Root Complex.
     * NVMe is a PCIe-only protocol.  Windows pci.sys treats PNP0A08
     * buses as Express and properly allocates MSI/MSI-X resources.
     * Without this, stornvme.sys may never receive interrupt resources
     * and fail to initialize. */
    buf[p++] = 0x08;  /* NameOp */
    buf[p++] = '_'; buf[p++] = 'H'; buf[p++] = 'I'; buf[p++] = 'D';
    buf[p++] = 0x0C;  /* DWordPrefix */
    buf[p++] = 0x41; buf[p++] = 0xD0; buf[p++] = 0x0A; buf[p++] = 0x08;

    /* Name(_CID, EisaId("PNP0A03")) — compatible with conventional PCI.
     * Required for backward compatibility so OVMF PciBusDxe also
     * recognizes this as a PCI host bridge. */
    buf[p++] = 0x08;  /* NameOp */
    buf[p++] = '_'; buf[p++] = 'C'; buf[p++] = 'I'; buf[p++] = 'D';
    buf[p++] = 0x0C;  /* DWordPrefix */
    buf[p++] = 0x41; buf[p++] = 0xD0; buf[p++] = 0x0A; buf[p++] = 0x03;

    /* Name(_ADR, 0) */
    buf[p++] = 0x08;  /* NameOp */
    buf[p++] = '_'; buf[p++] = 'A'; buf[p++] = 'D'; buf[p++] = 'R';
    buf[p++] = 0x00;  /* ZeroOp (integer 0) */

    /* Method(_OSC, 4, NotSerialized) { Return(Arg3) }
     * Operating System Capabilities — grants the OS full native
     * control over PCIe features (hot-plug, PME, AER, MSI).
     * Windows calls this with UUID {33DB4D5B-1FF7-401C-9657-7441C03DD766}
     * and expects the firmware to grant requested capabilities.
     * We unconditionally return Arg3 unchanged = grant all. */
    buf[p++] = 0x14;  /* MethodOp */
    buf[p++] = 0x08;  /* PkgLength = 8 (4 name + 1 flags + 1 return + 1 arg) */
    buf[p++] = '_'; buf[p++] = 'O'; buf[p++] = 'S'; buf[p++] = 'C';
    buf[p++] = 0x04;  /* MethodFlags: 4 args (bits[2:0]=4), not serialized */
    buf[p++] = 0xA4;  /* ReturnOp */
    buf[p++] = 0x6B;  /* Arg3Op */

    /* ══════════════════════════════════════════════════════════════
     * Name(_CRS, ResourceTemplate() { ... })
     *
     * Declares the PCI host bridge resource windows.  OVMF and
     * Windows need this to know which address ranges are usable
     * for PCI BAR assignment.
     *
     * AML ResourceTemplate is: BufferOp + PkgLength + BufferSize +
     * raw resource descriptor bytes + EndTag.
     * ══════════════════════════════════════════════════════════════ */
    {
        u32 crs_buf_start, crs_body_len;
        u8 crs_data[512];
        u32 cd = 0;

        /* WordBusNumber: ResourceProducer, MinFixed, MaxFixed, PosDecode
         * Min=0, Max=0xFF, Translation=0, Length=0x100 */
        crs_data[cd++] = 0x88;  /* Word Address Space: type 0x88 */
        crs_data[cd++] = 0x0D;  /* Length low = 13 */
        crs_data[cd++] = 0x00;  /* Length high */
        crs_data[cd++] = 0x02;  /* ResourceType: BusNumber */
        crs_data[cd++] = 0x0C;  /* GeneralFlags: MinFixed|MaxFixed|PosDecode */
        crs_data[cd++] = 0x00;  /* TypeSpecificFlags */
        /* Granularity=0, Min=0, Max=0xFF, TransOff=0, Length=0x100 */
        crs_data[cd++] = 0x00; crs_data[cd++] = 0x00;  /* Granularity */
        crs_data[cd++] = 0x00; crs_data[cd++] = 0x00;  /* RangeMin */
        crs_data[cd++] = 0xFF; crs_data[cd++] = 0x00;  /* RangeMax */
        crs_data[cd++] = 0x00; crs_data[cd++] = 0x00;  /* TranslationOff */
        crs_data[cd++] = 0x00; crs_data[cd++] = 0x01;  /* Length = 256 */

        /* IO(Decode16, 0x0CF8, 0x0CF8, 0x01, 0x08) — PCI config ports */
        crs_data[cd++] = 0x47;  /* IO Descriptor */
        crs_data[cd++] = 0x01;  /* Decode16 */
        crs_data[cd++] = 0xF8; crs_data[cd++] = 0x0C;  /* MinBase = 0x0CF8 */
        crs_data[cd++] = 0xF8; crs_data[cd++] = 0x0C;  /* MaxBase = 0x0CF8 */
        crs_data[cd++] = 0x01;  /* Alignment */
        crs_data[cd++] = 0x08;  /* Length */

        /* WordIO: ResourceProducer, MinFixed, MaxFixed, PosDecode, EntireRange
         * Min=0x0000, Max=0x0CF7, Translation=0, Length=0x0CF8
         * (I/O range below PCI config ports) */
        crs_data[cd++] = 0x88;  /* Word Address Space */
        crs_data[cd++] = 0x0D;  /* Length low */
        crs_data[cd++] = 0x00;  /* Length high */
        crs_data[cd++] = 0x01;  /* ResourceType: IO */
        crs_data[cd++] = 0x0C;  /* GeneralFlags: Min/MaxFixed, PosDecode */
        crs_data[cd++] = 0x03;  /* TypeSpecificFlags: ISA+NonISA */
        crs_data[cd++] = 0x00; crs_data[cd++] = 0x00;  /* Granularity */
        crs_data[cd++] = 0x00; crs_data[cd++] = 0x00;  /* RangeMin = 0 */
        crs_data[cd++] = 0xF7; crs_data[cd++] = 0x0C;  /* RangeMax = 0x0CF7 */
        crs_data[cd++] = 0x00; crs_data[cd++] = 0x00;  /* TranslationOff */
        crs_data[cd++] = 0xF8; crs_data[cd++] = 0x0C;  /* Length = 0x0CF8 */

        /* WordIO: Min=0x0D00, Max=0xFFFF (I/O range above PCI config) */
        crs_data[cd++] = 0x88;
        crs_data[cd++] = 0x0D; crs_data[cd++] = 0x00;
        crs_data[cd++] = 0x01;  /* IO */
        crs_data[cd++] = 0x0C;  /* MinFixed|MaxFixed */
        crs_data[cd++] = 0x03;  /* ISA+NonISA */
        crs_data[cd++] = 0x00; crs_data[cd++] = 0x00;  /* Gran */
        crs_data[cd++] = 0x00; crs_data[cd++] = 0x0D;  /* Min = 0x0D00 */
        crs_data[cd++] = 0xFF; crs_data[cd++] = 0xFF;  /* Max = 0xFFFF */
        crs_data[cd++] = 0x00; crs_data[cd++] = 0x00;  /* Trans */
        crs_data[cd++] = 0x00; crs_data[cd++] = 0xF3;  /* Length = 0xF300 */

        /* DWordMemory: 32-bit MMIO Window 0xC0000000 - 0xFEBFFFFF
         * ResourceProducer, PosDecode, MinFixed, MaxFixed, NonCacheable, ReadWrite */
        crs_data[cd++] = 0x87;  /* DWord Address Space: type 0x87 */
        crs_data[cd++] = 0x17;  /* Length low = 23 */
        crs_data[cd++] = 0x00;  /* Length high */
        crs_data[cd++] = 0x00;  /* ResourceType: Memory */
        crs_data[cd++] = 0x0C;  /* GeneralFlags: MinFixed|MaxFixed|PosDecode */
        crs_data[cd++] = 0x01;  /* Cacheable: NonCacheable (WriteCombining OK) */
        /* Granularity=0 */
        crs_data[cd++] = 0x00; crs_data[cd++] = 0x00;
        crs_data[cd++] = 0x00; crs_data[cd++] = 0x00;
        /* RangeMin = 0xC0000000 */
        crs_data[cd++] = 0x00; crs_data[cd++] = 0x00;
        crs_data[cd++] = 0x00; crs_data[cd++] = 0xC0;
        /* RangeMax = 0xFEBFFFFF */
        crs_data[cd++] = 0xFF; crs_data[cd++] = 0xFF;
        crs_data[cd++] = 0xBF; crs_data[cd++] = 0xFE;
        /* TranslationOffset = 0 */
        crs_data[cd++] = 0x00; crs_data[cd++] = 0x00;
        crs_data[cd++] = 0x00; crs_data[cd++] = 0x00;
        /* Length = 0x3EC00000 */
        crs_data[cd++] = 0x00; crs_data[cd++] = 0x00;
        crs_data[cd++] = 0xC0; crs_data[cd++] = 0x3E;

        /* QWordMemory: 64-bit PCI MMIO Window for large GPU BARs
         * ResourceProducer, PosDecode, MinFixed, MaxFixed, NonCacheable, ReadWrite
         *
         * GPUs with 4–16 GB VRAM need 64-bit BARs that don't fit in the
         * 32-bit MMIO window (0xC0000000-0xFEBFFFFF, ~1 GB).
         * Without this, OVMF and Windows cannot assign large GPU BARs.
         *
         * Window placement: above all guest RAM
         *   Start = ROUND_UP(4G + guest_ram_above_4g, hole64_size)
         *   Size  = 32 GB (matches etc/pci-hole64-size)
         */
        {
            u64 pci64_start, pci64_end, pci64_size, pci64_len;
            u64 above_4g_end = 0x100000000ULL + guest_ram_above_4g;
            pci64_size = 0x800000000ULL;  /* 32 GB */
            /* Round up to hole64 size alignment */
            pci64_start = (above_4g_end + pci64_size - 1) & ~(pci64_size - 1);
            pci64_end = pci64_start + pci64_size - 1;
            pci64_len = pci64_size;

            pr_info("[BOGGER-ACPI] 64-bit PCI window: 0x%llx - 0x%llx (%llu GB)\n",
                    pci64_start, pci64_end,
                    (unsigned long long)(pci64_size >> 30));

            crs_data[cd++] = 0x8A;  /* QWord Address Space: type 0x8A */
            crs_data[cd++] = 0x2B;  /* Length low = 43 */
            crs_data[cd++] = 0x00;  /* Length high */
            crs_data[cd++] = 0x00;  /* ResourceType: Memory */
            crs_data[cd++] = 0x0C;  /* GeneralFlags: MinFixed|MaxFixed|PosDecode */
            crs_data[cd++] = 0x01;  /* TypeSpecificFlags: NonCacheable */
            /* Granularity = 0 (8 bytes LE) */
            crs_data[cd++] = 0; crs_data[cd++] = 0;
            crs_data[cd++] = 0; crs_data[cd++] = 0;
            crs_data[cd++] = 0; crs_data[cd++] = 0;
            crs_data[cd++] = 0; crs_data[cd++] = 0;
            /* RangeMin (8 bytes LE) */
            crs_data[cd++] = (u8)(pci64_start);
            crs_data[cd++] = (u8)(pci64_start >> 8);
            crs_data[cd++] = (u8)(pci64_start >> 16);
            crs_data[cd++] = (u8)(pci64_start >> 24);
            crs_data[cd++] = (u8)(pci64_start >> 32);
            crs_data[cd++] = (u8)(pci64_start >> 40);
            crs_data[cd++] = (u8)(pci64_start >> 48);
            crs_data[cd++] = (u8)(pci64_start >> 56);
            /* RangeMax (8 bytes LE) */
            crs_data[cd++] = (u8)(pci64_end);
            crs_data[cd++] = (u8)(pci64_end >> 8);
            crs_data[cd++] = (u8)(pci64_end >> 16);
            crs_data[cd++] = (u8)(pci64_end >> 24);
            crs_data[cd++] = (u8)(pci64_end >> 32);
            crs_data[cd++] = (u8)(pci64_end >> 40);
            crs_data[cd++] = (u8)(pci64_end >> 48);
            crs_data[cd++] = (u8)(pci64_end >> 56);
            /* TranslationOffset = 0 (8 bytes LE) */
            crs_data[cd++] = 0; crs_data[cd++] = 0;
            crs_data[cd++] = 0; crs_data[cd++] = 0;
            crs_data[cd++] = 0; crs_data[cd++] = 0;
            crs_data[cd++] = 0; crs_data[cd++] = 0;
            /* Length (8 bytes LE) */
            crs_data[cd++] = (u8)(pci64_len);
            crs_data[cd++] = (u8)(pci64_len >> 8);
            crs_data[cd++] = (u8)(pci64_len >> 16);
            crs_data[cd++] = (u8)(pci64_len >> 24);
            crs_data[cd++] = (u8)(pci64_len >> 32);
            crs_data[cd++] = (u8)(pci64_len >> 40);
            crs_data[cd++] = (u8)(pci64_len >> 48);
            crs_data[cd++] = (u8)(pci64_len >> 56);
        }

        /* EndTag */
        crs_data[cd++] = 0x79;  /* EndTag */
        crs_data[cd++] = 0x00;  /* Checksum */

        /* Now emit: Name(_CRS, Buffer(cd) { crs_data }) */
        buf[p++] = 0x08;  /* NameOp */
        buf[p++] = '_'; buf[p++] = 'C'; buf[p++] = 'R'; buf[p++] = 'S';
        /* BufferOp */
        buf[p++] = 0x11;  /* BufferOp */
        crs_buf_start = p;
        /* Reserve 2 bytes for PkgLength (will be 2-byte encoding) */
        p += 2;
        /* BufferSize: use WordPrefix (0x0B) if cd > 255, otherwise BytePrefix */
        if (cd > 255) {
            buf[p++] = 0x0B;  /* WordPrefix */
            buf[p++] = (u8)(cd & 0xFF);
            buf[p++] = (u8)(cd >> 8);
        } else {
            buf[p++] = 0x0A;  /* BytePrefix */
            buf[p++] = (u8)cd;
        }
        memcpy(buf + p, crs_data, cd);
        p += cd;
        /* Patch Buffer PkgLength */
        crs_body_len = p - crs_buf_start;
        aml_encode_pkglen(buf, crs_buf_start, crs_body_len);
    }

    /* ══════════════════════════════════════════════════════════════
     * Device nodes inside PCI0 — required for OVMF GOP discovery
     * and Windows ACPI device association.  Without explicit Device
     * nodes with _ADR, OVMF may not identify the GPU for GOP init
     * and Windows cannot associate ACPI power management.
     * ══════════════════════════════════════════════════════════════ */

    /* Device(GFX0) { Name(_ADR, 0x00030000) } — GPU at 00:3.0 */
    buf[p++] = 0x5B; buf[p++] = 0x82;  /* ExtOp + DeviceOp */
    buf[p++] = 0x0F;                    /* PkgLength = 15 */
    buf[p++] = 'G'; buf[p++] = 'F'; buf[p++] = 'X'; buf[p++] = '0';
    buf[p++] = 0x08;  /* NameOp */
    buf[p++] = '_'; buf[p++] = 'A'; buf[p++] = 'D'; buf[p++] = 'R';
    buf[p++] = 0x0C;  /* DWordPrefix */
    buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x03; buf[p++] = 0x00;

    /* Device(HDAU) { Name(_ADR, 0x00030001) } — GPU Audio at 00:3.1 */
    buf[p++] = 0x5B; buf[p++] = 0x82;  /* ExtOp + DeviceOp */
    buf[p++] = 0x0F;                    /* PkgLength = 15 */
    buf[p++] = 'H'; buf[p++] = 'D'; buf[p++] = 'A'; buf[p++] = 'U';
    buf[p++] = 0x08;  /* NameOp */
    buf[p++] = '_'; buf[p++] = 'A'; buf[p++] = 'D'; buf[p++] = 'R';
    buf[p++] = 0x0C;  /* DWordPrefix */
    buf[p++] = 0x01; buf[p++] = 0x00; buf[p++] = 0x03; buf[p++] = 0x00;

    /* Device(NVME) { Name(_ADR, 0x00040000) } — NVMe at 00:4.0 */
    buf[p++] = 0x5B; buf[p++] = 0x82;  /* ExtOp + DeviceOp */
    buf[p++] = 0x0F;                    /* PkgLength = 15 */
    buf[p++] = 'N'; buf[p++] = 'V'; buf[p++] = 'M'; buf[p++] = 'E';
    buf[p++] = 0x08;  /* NameOp */
    buf[p++] = '_'; buf[p++] = 'A'; buf[p++] = 'D'; buf[p++] = 'R';
    buf[p++] = 0x0C;  /* DWordPrefix */
    buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x04; buf[p++] = 0x00;

    /* Name(_PRT, Package(3) { ... }) — PCI interrupt routing table */
    buf[p++] = 0x08;  /* NameOp */
    buf[p++] = '_'; buf[p++] = 'P'; buf[p++] = 'R'; buf[p++] = 'T';
    buf[p++] = 0x12;  /* PackageOp */
    prt_start = p;
    buf[p++] = 0;     /* PkgLength placeholder */
    buf[p++] = 0x03;  /* NumElements = 3 */

    /* _PRT Entry 0: Device 2 (VGA) INTA → GSI 10 */
    buf[p++] = 0x12;  /* PackageOp */
    inner_start = p;
    buf[p++] = 0;     /* PkgLength placeholder */
    buf[p++] = 0x04;  /* NumElements = 4 */
    buf[p++] = 0x0C;  /* DWordPrefix: Address */
    buf[p++] = 0xFF; buf[p++] = 0xFF; buf[p++] = 0x02; buf[p++] = 0x00;
    buf[p++] = 0x00;  /* ZeroOp: Pin = INTA */
    buf[p++] = 0x00;  /* ZeroOp: Source = hardwired */
    buf[p++] = 0x0A; buf[p++] = 0x0A;  /* BytePrefix: SourceIndex = GSI 10 */
    buf[inner_start] = (u8)(p - inner_start);

    /* _PRT Entry 1: Device 3 (GPU passthrough) INTA → GSI 10 */
    buf[p++] = 0x12;  /* PackageOp */
    inner_start = p;
    buf[p++] = 0;     /* PkgLength placeholder */
    buf[p++] = 0x04;  /* NumElements = 4 */
    buf[p++] = 0x0C;  /* DWordPrefix: Address */
    buf[p++] = 0xFF; buf[p++] = 0xFF; buf[p++] = 0x03; buf[p++] = 0x00;
    buf[p++] = 0x00;  /* ZeroOp: Pin = INTA */
    buf[p++] = 0x00;  /* ZeroOp: Source = hardwired */
    buf[p++] = 0x0A; buf[p++] = 0x0A;  /* BytePrefix: SourceIndex = GSI 10 */
    buf[inner_start] = (u8)(p - inner_start);

    /* _PRT Entry 2: Device 4 (NVMe) INTA → GSI 11 */
    buf[p++] = 0x12;  /* PackageOp */
    inner_start = p;
    buf[p++] = 0;     /* PkgLength placeholder */
    buf[p++] = 0x04;  /* NumElements = 4 */
    buf[p++] = 0x0C;  /* DWordPrefix: Address */
    buf[p++] = 0xFF; buf[p++] = 0xFF; buf[p++] = 0x04; buf[p++] = 0x00;
    buf[p++] = 0x00;  /* ZeroOp: Pin = INTA */
    buf[p++] = 0x00;  /* ZeroOp: Source = hardwired */
    buf[p++] = 0x0A; buf[p++] = 0x0B;  /* BytePrefix: SourceIndex = GSI 11 */
    buf[inner_start] = (u8)(p - inner_start);

    /* Patch PkgLengths — _PRT package uses 1-byte, Device/Scope use 2-byte */
    buf[prt_start] = (u8)(p - prt_start);
    aml_encode_pkglen(buf, dev_start, p - dev_start);
    aml_encode_pkglen(buf, scope_start, p - scope_start);

    /* Now fill in DSDT header at offset 0 */
    {
        u32 total = p;
        memset(buf, 0, 36);
        memcpy(buf, "DSDT", 4);
        *(u32 *)(buf + 4) = total;
        buf[8] = 2;  /* Revision */
        memcpy(buf + 10, "BOGGER", 6);
        memcpy(buf + 16, "BOGGTBL0", 8);
        *(u32 *)(buf + 24) = 1;
        memcpy(buf + 28, "BOGR", 4);
        *(u32 *)(buf + 32) = 1;
    }
    return p;
}

/* ══════════════════════════════════════════════════════════════════
 * QEMU fw_cfg linker/loader protocol — ACPI blob export
 *
 * OVMF's AcpiPlatformDxe processes "etc/table-loader" commands to:
 *   1. ALLOCATE memory and copy table data from "etc/acpi/tables"
 *   2. ALLOCATE memory and copy RSDP from "etc/acpi/rsdp"
 *   3. ADD_POINTER to patch inter-table pointers
 *   4. ADD_CHECKSUM to recompute table checksums
 *
 * Without this, OVMF considers ACPI setup "done" with no tables,
 * and Windows never finds FADT/MADT/HPET/DSDT.
 * ══════════════════════════════════════════════════════════════════ */

u8   acpi_tables_blob[ACPI_BLOB_MAX];
u32  acpi_tables_blob_len;
u8   acpi_rsdp_blob[36];
u32  acpi_rsdp_blob_len;
u8   acpi_loader_cmds[ACPI_LOADER_MAX];
u32  acpi_loader_cmds_len;

/* Loader command types (QEMU bios-linker-loader.h) */
#define LOADER_CMD_ALLOCATE      1
#define LOADER_CMD_ADD_POINTER   2
#define LOADER_CMD_ADD_CHECKSUM  3
#define LOADER_FILESZ            56
#define LOADER_ENTRY_SIZE        128

/* Zone values */
#define LOADER_ZONE_HIGH         1   /* above 4GB if possible */
#define LOADER_ZONE_FSEG         2   /* legacy F-segment */

static u32 loader_off;  /* current write offset into acpi_loader_cmds */

static void loader_emit_allocate(const char *file, u32 alignment, u8 zone)
{
    u8 *e = &acpi_loader_cmds[loader_off];
    if (loader_off + LOADER_ENTRY_SIZE > ACPI_LOADER_MAX) return;
    memset(e, 0, LOADER_ENTRY_SIZE);
    *(u32 *)(e + 0) = LOADER_CMD_ALLOCATE;
    strncpy((char *)(e + 4), file, LOADER_FILESZ - 1);
    *(u32 *)(e + 4 + LOADER_FILESZ) = alignment;
    e[4 + LOADER_FILESZ + 4] = zone;
    loader_off += LOADER_ENTRY_SIZE;
}

static void loader_emit_add_pointer(const char *dest, const char *src,
                                    u32 offset, u8 size)
{
    u8 *e = &acpi_loader_cmds[loader_off];
    if (loader_off + LOADER_ENTRY_SIZE > ACPI_LOADER_MAX) return;
    memset(e, 0, LOADER_ENTRY_SIZE);
    *(u32 *)(e + 0) = LOADER_CMD_ADD_POINTER;
    strncpy((char *)(e + 4), dest, LOADER_FILESZ - 1);
    strncpy((char *)(e + 4 + LOADER_FILESZ), src, LOADER_FILESZ - 1);
    *(u32 *)(e + 4 + 2 * LOADER_FILESZ) = offset;
    e[4 + 2 * LOADER_FILESZ + 4] = size;
    loader_off += LOADER_ENTRY_SIZE;
}

static void loader_emit_add_checksum(const char *file, u32 cksum_off,
                                     u32 start, u32 length)
{
    u8 *e = &acpi_loader_cmds[loader_off];
    if (loader_off + LOADER_ENTRY_SIZE > ACPI_LOADER_MAX) return;
    memset(e, 0, LOADER_ENTRY_SIZE);
    *(u32 *)(e + 0) = LOADER_CMD_ADD_CHECKSUM;
    strncpy((char *)(e + 4), file, LOADER_FILESZ - 1);
    *(u32 *)(e + 4 + LOADER_FILESZ) = cksum_off;
    *(u32 *)(e + 4 + LOADER_FILESZ + 4) = start;
    *(u32 *)(e + 4 + LOADER_FILESZ + 8) = length;
    loader_off += LOADER_ENTRY_SIZE;
}

/*
 * build_fwcfg_acpi_blobs() – Copy already-built tables (from guest RAM
 * region at ACPI_TABLE_GPA) into a flat blob, replacing GPA-based
 * pointers with blob-relative offsets.  Then generate loader commands.
 *
 * @tbl:       pointer to tables in guest RAM (offset from ACPI_TABLE_GPA)
 * @total_len: total used bytes in tbl
 * @dsdt_size: size of DSDT (starts at offset 0 in tbl)
 * @fadt_off, fadt_len: FADT offset/size in tbl
 * @madt_off, madt_len: MADT offset/size in tbl
 * @hpet_off, hpet_len: HPET offset/size in tbl
 * @facs_off, facs_len: FACS offset/size in tbl
 * @waet_off, waet_len: WAET offset/size in tbl
 * @xsdt_off, xsdt_len: XSDT offset/size in tbl
 */
static void build_fwcfg_acpi_blobs(u8 *tbl, u32 total_len, u32 dsdt_size,
                                   u32 fadt_off, u32 fadt_len,
                                   u32 madt_off, u32 madt_len,
                                   u32 hpet_off, u32 hpet_len,
                                   u32 facs_off, u32 facs_len,
                                   u32 waet_off, u32 waet_len,
                                   u32 xsdt_off, u32 xsdt_len)
{
    #define TBL_FILE "etc/acpi/tables"
    #define RSDP_FILE "etc/acpi/rsdp"
    #define LOADER_FILE "etc/table-loader"

    /* 1. Copy table blob — replace absolute GPA pointers with offsets */
    if (total_len > ACPI_BLOB_MAX) {
        pr_warn("[BOGGER] ACPI blob too large (%u > %u)\n", total_len, ACPI_BLOB_MAX);
        return;
    }
    memcpy(acpi_tables_blob, tbl, total_len);
    acpi_tables_blob_len = total_len;

    /* Patch FADT pointers: replace absolute GPAs with blob offsets.
     * FADT[40] = DSDT (32-bit legacy pointer)
     * FADT[140] = X_DSDT (64-bit pointer)
     * FADT[36] = FIRMWARE_CTRL (32-bit, points to FACS)
     * FADT[132] = X_FIRMWARE_CTRL (64-bit, points to FACS) */
    *(u32 *)(acpi_tables_blob + fadt_off + 40) = 0;     /* DSDT 32-bit → offset 0 (will be patched) */
    *(u64 *)(acpi_tables_blob + fadt_off + 140) = 0;    /* X_DSDT → offset 0 */
    *(u32 *)(acpi_tables_blob + fadt_off + 36) = facs_off;  /* FIRMWARE_CTRL → FACS offset */
    *(u64 *)(acpi_tables_blob + fadt_off + 132) = (u64)facs_off; /* X_FIRMWARE_CTRL → FACS offset */

    /* Patch XSDT entries: replace absolute GPAs with blob offsets.
     * XSDT[36] = FADT, XSDT[44] = MADT, XSDT[52] = HPET, XSDT[60] = WAET */
    *(u64 *)(acpi_tables_blob + xsdt_off + 36) = (u64)fadt_off;
    *(u64 *)(acpi_tables_blob + xsdt_off + 44) = (u64)madt_off;
    *(u64 *)(acpi_tables_blob + xsdt_off + 52) = (u64)hpet_off;
    *(u64 *)(acpi_tables_blob + xsdt_off + 60) = (u64)waet_off;

    /* Zero all checksum bytes — ADD_CHECKSUM will recompute them */
    acpi_tables_blob[9] = 0;                     /* DSDT checksum */
    acpi_tables_blob[fadt_off + 9] = 0;          /* FADT checksum */
    acpi_tables_blob[madt_off + 9] = 0;          /* MADT checksum */
    acpi_tables_blob[hpet_off + 9] = 0;          /* HPET checksum */
    acpi_tables_blob[waet_off + 9] = 0;           /* WAET checksum */
    acpi_tables_blob[xsdt_off + 9] = 0;          /* XSDT checksum */

    /* 2. Build RSDP blob — XsdtAddress = 0 (patched to point into tables) */
    memset(acpi_rsdp_blob, 0, 36);
    memcpy(acpi_rsdp_blob, "RSD PTR ", 8);
    /* byte [8] = checksum v1 — zeroed, will be recomputed */
    memcpy(acpi_rsdp_blob + 9, "BOGGER", 6);
    acpi_rsdp_blob[15] = 2;          /* ACPI revision 2.0 */
    /* [16..19] = RSDT address (32-bit, unused with XSDT) */
    *(u32 *)(acpi_rsdp_blob + 20) = 36;  /* Length */
    *(u64 *)(acpi_rsdp_blob + 24) = (u64)xsdt_off;  /* XsdtAddress = offset → patched */
    /* [32] = extended checksum — zeroed, will be recomputed */
    acpi_rsdp_blob_len = 36;

    /* 3. Build loader commands */
    loader_off = 0;

    /* ALLOCATE: load table data into high memory */
    loader_emit_allocate(TBL_FILE, 64, LOADER_ZONE_HIGH);

    /* ALLOCATE: load RSDP into F-segment (or high, OVMF doesn't care) */
    loader_emit_allocate(RSDP_FILE, 16, LOADER_ZONE_FSEG);

    /* ADD_POINTER: RSDP.XsdtAddress → XSDT in tables blob
     * RSDP[24..31] (8 bytes) += base of "etc/acpi/tables" allocation */
    loader_emit_add_pointer(RSDP_FILE, TBL_FILE, 24, 8);

    /* ADD_POINTER: FADT.DSDT (32-bit) → DSDT at offset 0 in tables
     * tables[fadt_off+40..43] (4 bytes) += base of tables allocation */
    loader_emit_add_pointer(TBL_FILE, TBL_FILE, fadt_off + 40, 4);

    /* ADD_POINTER: FADT.X_DSDT (64-bit) → DSDT at offset 0 in tables
     * tables[fadt_off+140..147] (8 bytes) += base of tables allocation */
    loader_emit_add_pointer(TBL_FILE, TBL_FILE, fadt_off + 140, 8);

    /* ADD_POINTER: XSDT entry[0] (FADT) — already set to fadt_off */
    loader_emit_add_pointer(TBL_FILE, TBL_FILE, xsdt_off + 36, 8);
    /* ADD_POINTER: XSDT entry[1] (MADT) — already set to madt_off */
    loader_emit_add_pointer(TBL_FILE, TBL_FILE, xsdt_off + 44, 8);
    /* ADD_POINTER: XSDT entry[2] (HPET) — already set to hpet_off */
    loader_emit_add_pointer(TBL_FILE, TBL_FILE, xsdt_off + 52, 8);
    /* ADD_POINTER: XSDT entry[3] (WAET) — already set to waet_off */
    loader_emit_add_pointer(TBL_FILE, TBL_FILE, xsdt_off + 60, 8);

    /* ADD_POINTER: FADT.FIRMWARE_CTRL (32-bit) → FACS in tables blob */
    loader_emit_add_pointer(TBL_FILE, TBL_FILE, fadt_off + 36, 4);
    /* ADD_POINTER: FADT.X_FIRMWARE_CTRL (64-bit) → FACS in tables blob */
    loader_emit_add_pointer(TBL_FILE, TBL_FILE, fadt_off + 132, 8);

    /* ADD_CHECKSUM: recompute all table checksums after pointer patching */
    loader_emit_add_checksum(TBL_FILE, 9, 0, dsdt_size);               /* DSDT */
    loader_emit_add_checksum(TBL_FILE, fadt_off + 9, fadt_off, fadt_len); /* FADT */
    loader_emit_add_checksum(TBL_FILE, madt_off + 9, madt_off, madt_len); /* MADT */
    loader_emit_add_checksum(TBL_FILE, hpet_off + 9, hpet_off, hpet_len); /* HPET */
    loader_emit_add_checksum(TBL_FILE, waet_off + 9, waet_off, waet_len); /* WAET */
    loader_emit_add_checksum(TBL_FILE, xsdt_off + 9, xsdt_off, xsdt_len); /* XSDT */

    /* RSDP v1 checksum (bytes 0..19, checksum at byte 8) */
    loader_emit_add_checksum(RSDP_FILE, 8, 0, 20);
    /* RSDP extended checksum (bytes 0..35, checksum at byte 32) */
    loader_emit_add_checksum(RSDP_FILE, 32, 0, 36);

    acpi_loader_cmds_len = loader_off;

    pr_info("[BOGGER] ACPI fw_cfg: tables_blob=%u bytes, rsdp=%u bytes, loader=%u bytes (%u cmds)\n",
            acpi_tables_blob_len, acpi_rsdp_blob_len,
            acpi_loader_cmds_len, acpi_loader_cmds_len / LOADER_ENTRY_SIZE);

    #undef TBL_FILE
    #undef RSDP_FILE
    #undef LOADER_FILE
}


int bogger_acpi_build(void)
{
    u8 *tbl, *rsdp_ptr;
    u64 dsdt_gpa, fadt_gpa, madt_gpa, hpet_gpa, facs_gpa, waet_gpa, xsdt_gpa;
    u32 off = 0, fadt_len, madt_len, hpet_len, facs_len, waet_len, xsdt_len, dsdt_size;

    if (!guest_ram_virt) return -EINVAL;
    if (ACPI_TABLE_GPA + 0x2000 > guest_ram_size) return -ENOMEM;

    tbl = (u8 *)guest_ram_virt + ACPI_TABLE_GPA;
    memset(tbl, 0, 0x2000);

    /* ── DSDT ─────────────────────────────────────────────────────── */
    dsdt_gpa = ACPI_TABLE_GPA + off;
    dsdt_size = build_dsdt_aml(tbl + off, 0x1000);
    acpi_fix_checksum(tbl + off, dsdt_size, 9);
    off += ALIGN(dsdt_size, 16);

    /* ── FADT ─────────────────────────────────────────────────────── */
    fadt_gpa = ACPI_TABLE_GPA + off;
    fadt_len = 276;
    {
        u8 *f = tbl + off;
        memset(f, 0, fadt_len);
        memcpy(f, "FACP", 4);
        *(u32 *)(f + 4)  = fadt_len;
        f[8] = 6;   /* FADT revision 6 */
        memcpy(f + 10, "BOGGER", 6);
        memcpy(f + 16, "BOGGTBL0", 8);
        *(u32 *)(f + 24) = 1;
        memcpy(f + 28, "BOGR", 4);
        *(u32 *)(f + 32) = 1;
        *(u32 *)(f + 36) = 0;             /* FIRMWARE_CTRL (32-bit, 0=use X_FIRMWARE_CTRL) */
        *(u32 *)(f + 40) = (u32)dsdt_gpa;  /* DSDT (32-bit legacy) */
        f[45] = 1;                         /* Preferred PM Profile: Desktop */
        *(u16 *)(f + 46) = 0x0009;         /* SCI_INT: IRQ 9 */
        *(u32 *)(f + 48) = 0x000000B2;     /* SMI_CMD: standard SMI port */
        f[52] = 0xF0;                      /* ACPI_ENABLE: write 0xF0 to SMI_CMD */
        f[53] = 0xF1;                      /* ACPI_DISABLE: write 0xF1 to SMI_CMD */
        /* PM1a_EVT_BLK = 0x600, length=4 (PM1_STS + PM1_EN) */
        *(u32 *)(f + 56) = 0x600;          /* PM1a_EVT_BLK */
        f[88] = 4;                         /* PM1_EVT_LEN = 4 bytes */
        /* PM1a_CNT_BLK = 0x604, length=2 */
        *(u32 *)(f + 64) = 0x604;          /* PM1a_CNT_BLK */
        f[89] = 2;                         /* PM1_CNT_LEN = 2 bytes */
        /* PM_TMR_BLK = 0x608, length=4 */
        *(u32 *)(f + 76) = 0x608;          /* PM_TMR_BLK */
        f[91] = 4;                         /* PM_TMR_LEN = 4 bytes */
        /* GPE0_BLK = 0x620, length=8 (4 bytes STS + 4 bytes EN) */
        *(u32 *)(f + 80) = 0x620;          /* GPE0_BLK */
        f[92] = 8;                         /* GPE0_BLK_LEN = 8 bytes */
        /* Flags */
        *(u32 *)(f + 112) = (1U<<0) |  /* WBINVD */
                             (1U<<4) |  /* PROC_C1 */
                             (1U<<5) |  /* P_LVL2_UP */
                             (1U<<8) |  /* TMR_VAL_EXT (32-bit timer) */
                             (1U<<10);  /* RESET_REG_SUP */
        /* Note: bit 20 (HW_REDUCED_ACPI) must NOT be set — OVMF needs
         * full hardware ACPI with PM timer, SCI, etc. */
        /* X_DSDT (64-bit) */
        *(u64 *)(f + 140) = dsdt_gpa;
        /* X_PM1a_EVT_BLK GAS: SystemIO, 32-bit, 0x600 */
        f[148]=1; f[149]=32; f[150]=0; f[151]=3; *(u64 *)(f+152)=0x600;
        /* X_PM1a_CNT_BLK GAS: SystemIO, 16-bit, 0x604 */
        f[172]=1; f[173]=16; f[174]=0; f[175]=2; *(u64 *)(f+176)=0x604;
        /* X_PM_TMR_BLK GAS: SystemIO, 32-bit, 0x608 */
        f[208]=1; f[209]=32; f[210]=0; f[211]=3; *(u64 *)(f+212)=0x608;
        /* X_GPE0_BLK GAS: SystemIO, 32-bit (8 bytes total, 4+4), 0x620 */
        f[220]=1; f[221]=32; f[222]=0; f[223]=3; *(u64 *)(f+224)=0x620;
        /* RESET_REG GAS: SystemIO, 8-bit, 0xCF9 */
        f[116]=1; f[117]=8; f[118]=0; f[119]=1; *(u64 *)(f+120)=0xCF9;
        /* RESET_VALUE */
        f[128] = 0x06;
        /* C-state latencies */
        f[108] = 0x32; /* P_LVL2_LAT = 50µs */
        acpi_fix_checksum(f, fadt_len, 9);
    }
    off += ALIGN(fadt_len, 16);

    /* ── MADT ─────────────────────────────────────────────────────── */
    madt_gpa = ACPI_TABLE_GPA + off;
    /* MADT = 44 (header) + 8 (LAPIC) + 12 (IOAPIC) + 10 (ISO IRQ0→GSI2)
     *        + 10 (ISO IRQ9 SCI) + 6 (LAPIC NMI) = 90 bytes */
    madt_len = 44 + 8 + 12 + 10 + 10 + 6;
    {
        u8 *m = tbl + off;
        u32 p = 44;
        memset(m, 0, madt_len);
        memcpy(m, "APIC", 4);
        *(u32 *)(m + 4) = madt_len;
        m[8] = 4;
        memcpy(m + 10, "BOGGER", 6);
        memcpy(m + 16, "BOGGTBL0", 8);
        *(u32 *)(m + 24) = 1;
        memcpy(m + 28, "BOGR", 4);
        *(u32 *)(m + 32) = 1;
        *(u32 *)(m + 36) = 0xFEE00000;  /* Local APIC Address */
        *(u32 *)(m + 40) = 1;           /* Flags: PCAT_COMPAT */

        /* Type 0: Processor Local APIC (8 bytes) */
        m[p+0] = 0;    /* Type */
        m[p+1] = 8;    /* Length */
        m[p+2] = 0;    /* ACPI Processor UID */
        m[p+3] = 0;    /* APIC ID */
        *(u32 *)(m+p+4) = 1;  /* Flags: Enabled */
        p += 8;

        /* Type 1: I/O APIC (12 bytes) */
        m[p+0] = 1;    /* Type */
        m[p+1] = 12;   /* Length */
        m[p+2] = 0;    /* I/O APIC ID */
        m[p+3] = 0;    /* Reserved */
        *(u32 *)(m+p+4) = 0xFEC00000;  /* I/O APIC Address */
        *(u32 *)(m+p+8) = 0;           /* Global System Interrupt Base */
        p += 12;

        /* Type 2: Interrupt Source Override — IRQ 0 → GSI 2
         * Standard PC-AT: PIT timer (IRQ 0) is connected to IOAPIC pin 2.
         * OVMF needs this to properly route the timer interrupt. */
        m[p+0] = 2;    /* Type: Interrupt Source Override */
        m[p+1] = 10;   /* Length */
        m[p+2] = 0;    /* Bus: ISA */
        m[p+3] = 0;    /* Source: IRQ 0 */
        *(u32 *)(m+p+4) = 2;  /* Global System Interrupt: GSI 2 */
        *(u16 *)(m+p+8) = 0;  /* Flags: Conforms to bus specifications */
        p += 10;

        /* Type 2: Interrupt Source Override — IRQ 9 (SCI)
         * ACPI SCI interrupt: Level-triggered, Active-High.
         * Must match FADT SCI_INT=9 */
        m[p+0] = 2;    /* Type: Interrupt Source Override */
        m[p+1] = 10;   /* Length */
        m[p+2] = 0;    /* Bus: ISA */
        m[p+3] = 9;    /* Source: IRQ 9 */
        *(u32 *)(m+p+4) = 9;  /* Global System Interrupt: GSI 9 */
        *(u16 *)(m+p+8) = 0x000D;  /* Flags: Active High, Level-Triggered */
        p += 10;

        /* Type 5: Local APIC NMI — NMI on LINT1 for all processors.
         * Windows HAL expects this to configure NMI delivery. */
        m[p+0] = 5;    /* Type: Local APIC NMI */
        m[p+1] = 6;    /* Length */
        m[p+2] = 0xFF; /* ACPI Processor UID: all processors */
        *(u16 *)(m+p+3) = 0x0005; /* Flags: Active High, Edge-Triggered */
        m[p+5] = 1;    /* Local APIC LINT#: LINT1 */
        p += 6;

        acpi_fix_checksum(m, madt_len, 9);
    }
    off += ALIGN(madt_len, 16);

    /* ── HPET ─────────────────────────────────────────────────────── */
    hpet_gpa = ACPI_TABLE_GPA + off;
    hpet_len = 56;
    {
        u8 *h = tbl + off;
        memset(h, 0, hpet_len);
        memcpy(h, "HPET", 4);
        *(u32 *)(h + 4) = hpet_len;
        h[8] = 1;  /* Revision */
        memcpy(h + 10, "BOGGER", 6);
        memcpy(h + 16, "BOGGTBL0", 8);
        *(u32 *)(h + 24) = 1;
        memcpy(h + 28, "BOGR", 4);
        *(u32 *)(h + 32) = 1;
        /* Hardware Rev ID (offset 36) */
        *(u32 *)(h + 36) = 0x80868201;  /* matches HPET MMIO GCR */
        /* Base Address (GAS - offset 40): Memory, 64-bit, byte access, 0xFED00000 */
        h[40] = 0;     /* Address Space: Memory */
        h[41] = 64;    /* Bit Width */
        h[42] = 0;     /* Bit Offset */
        h[43] = 0;     /* Access Size */
        *(u64 *)(h + 44) = 0xFED00000ULL;  /* HPET base address */
        /* Sequence number (offset 52) */
        h[52] = 0;
        /* Minimum clock tick (offset 54) */
        *(u16 *)(h + 54) = 0;
        acpi_fix_checksum(h, hpet_len, 9);
    }
    off += ALIGN(hpet_len, 16);

    /* ── FACS (Firmware ACPI Control Structure) ───────────────────── */
    facs_gpa = ACPI_TABLE_GPA + off;
    facs_len = 64;
    {
        u8 *fc = tbl + off;
        memset(fc, 0, facs_len);
        memcpy(fc, "FACS", 4);        /* Signature */
        *(u32 *)(fc + 4) = facs_len;   /* Length */
        fc[32] = 2;                     /* Version (ACPI 2.0+) */
        /* FACS does NOT have a standard ACPI checksum */
    }
    off += ALIGN(facs_len, 16);

    /* Patch FADT → FACS pointer (FACS created after FADT) */
    {
        u8 *f = tbl + (fadt_gpa - ACPI_TABLE_GPA);
        *(u32 *)(f + 36) = (u32)facs_gpa;    /* FIRMWARE_CTRL (32-bit) */
        *(u64 *)(f + 132) = facs_gpa;         /* X_FIRMWARE_CTRL (64-bit) */
        acpi_fix_checksum(f, 276, 9);         /* Recompute FADT checksum */
    }

    /* ── WAET (Windows ACPI Emulated devices Table) ───────────────── */
    waet_gpa = ACPI_TABLE_GPA + off;
    waet_len = 40;
    {
        u8 *w = tbl + off;
        memset(w, 0, waet_len);
        memcpy(w, "WAET", 4);
        *(u32 *)(w + 4) = waet_len;
        w[8] = 1;  /* Revision */
        memcpy(w + 10, "BOGGER", 6);
        memcpy(w + 16, "BOGGTBL0", 8);
        *(u32 *)(w + 24) = 1;
        memcpy(w + 28, "BOGR", 4);
        *(u32 *)(w + 32) = 1;
        /* Emulated Device Flags (offset 36):
         * Bit 0: RTC is emulated → skip RTC period calibration
         * Bit 1: PM Timer is emulated → trust PM timer value */
        *(u32 *)(w + 36) = 0x03;
        acpi_fix_checksum(w, waet_len, 9);
    }
    off += ALIGN(waet_len, 16);

    /* ── XSDT ─────────────────────────────────────────────────────── */
    xsdt_gpa = ACPI_TABLE_GPA + off;
    xsdt_len = 36 + 4 * 8;  /* FADT + MADT + HPET + WAET */
    {
        u8 *x = tbl + off;
        memset(x, 0, xsdt_len);
        memcpy(x, "XSDT", 4);
        *(u32 *)(x + 4) = xsdt_len;
        x[8] = 1;
        memcpy(x + 10, "BOGGER", 6);
        memcpy(x + 16, "BOGGTBL0", 8);
        *(u32 *)(x + 24) = 1;
        memcpy(x + 28, "BOGR", 4);
        *(u32 *)(x + 32) = 1;
        *(u64 *)(x + 36) = fadt_gpa;
        *(u64 *)(x + 44) = madt_gpa;
        *(u64 *)(x + 52) = hpet_gpa;
        *(u64 *)(x + 60) = waet_gpa;
        acpi_fix_checksum(x, xsdt_len, 9);
    }
    off += ALIGN(xsdt_len, 16);

    /* ── RSDP ─────────────────────────────────────────────────────── */
    if (ACPI_RSDP_GPA + 36 > guest_ram_size) return -ENOMEM;
    rsdp_ptr = (u8 *)guest_ram_virt + ACPI_RSDP_GPA;
    {
        u8 *r = rsdp_ptr;
        int i; u8 sum;
        memset(r, 0, 36);
        memcpy(r, "RSD PTR ", 8);
        memcpy(r + 9, "BOGGER", 6);
        r[15] = 2;
        *(u32 *)(r + 20) = 36;
        *(u64 *)(r + 24) = xsdt_gpa;
        r[8] = 0; sum = 0;
        for (i = 0; i < 20; i++) sum += r[i];
        r[8] = -sum;
        r[32] = 0; sum = 0;
        for (i = 0; i < 36; i++) sum += r[i];
        r[32] = -sum;
    }

    pr_info("[BOGGER] ACPI: RSDP@0x%llx XSDT@0x%llx FADT@0x%llx MADT@0x%llx HPET@0x%llx DSDT@0x%llx\n",
            ACPI_RSDP_GPA, xsdt_gpa, fadt_gpa, madt_gpa, hpet_gpa, dsdt_gpa);

    /* ── Build fw_cfg linker/loader blobs for OVMF ─────────────── */
    build_fwcfg_acpi_blobs(tbl, off, dsdt_size,
                           (u32)(fadt_gpa - ACPI_TABLE_GPA), 276,
                           (u32)(madt_gpa - ACPI_TABLE_GPA), madt_len,
                           (u32)(hpet_gpa - ACPI_TABLE_GPA), hpet_len,
                           (u32)(facs_gpa - ACPI_TABLE_GPA), facs_len,
                           (u32)(waet_gpa - ACPI_TABLE_GPA), waet_len,
                           (u32)(xsdt_gpa - ACPI_TABLE_GPA), xsdt_len);

    return 0;
}





