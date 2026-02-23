#include "bogger_acpi.h"

/* RSDP signature: "RSD PTR " (8 bytes) */
#define RSDP_SIG_LO 0x20445352UL   /* "RSD " */
#define RSDP_SIG_HI 0x20525450UL   /* "PTR " */

typedef struct {
    uint8_t  signature[8];
    uint8_t  checksum;
    uint8_t  oem_id[6];
    uint8_t  revision;
    uint32_t rsdt_address;
    /* ACPI 2.0+ */
    uint32_t length;
    uint64_t xsdt_address;
    uint8_t  extended_checksum;
    uint8_t  reserved[3];
} __attribute__((packed)) rsdp_t;

static int rsdp_checksum_valid(const rsdp_t *rsdp)
{
    const uint8_t *p   = (const uint8_t *)rsdp;
    uint8_t        sum = 0;
    uint32_t       i;
    uint32_t       len = (rsdp->revision >= 2) ? rsdp->length : 20U;

    for (i = 0; i < len; i++)
        sum += p[i];

    return sum == 0;
}

static uint64_t scan_legacy_range(void)
{
    /* Scan the 0xE0000–0xFFFFF region for the RSDP signature */
    const uint8_t *p = (const uint8_t *)0xE0000UL;
    const uint8_t *end = (const uint8_t *)0x100000UL;

    while (p < end) {
        /* Check for "RSD PTR " */
        if (p[0] == 'R' && p[1] == 'S' && p[2] == 'D' && p[3] == ' ' &&
            p[4] == 'P' && p[5] == 'T' && p[6] == 'R' && p[7] == ' ') {
            if (rsdp_checksum_valid((const rsdp_t *)p))
                return (uint64_t)(uintptr_t)p;
        }
        p += 16; /* RSDP is always 16-byte aligned */
    }
    return 0;
}

uint64_t bogger_acpi_find_rsdp(void)
{
    uint64_t addr = 0;

    /* Prefer the UEFI-provided address stored in the EFI System Table.
     * In our initramfs environment the kernel exports the RSDP address
     * via /sys/firmware/acpi/rsdp or the EFI memory map exposed by the
     * kernel.  If that path is not available, fall back to legacy scan. */

    /* Try reading from the Linux EFI sysfs interface */
    /* (In a real implementation this would open /sys/firmware/acpi/rsdp and
     *  read the physical address — omitted for ffreestanding portability.) */

    /* Fallback: legacy BIOS area scan */
    addr = scan_legacy_range();

    return addr;
}

void bogger_acpi_passthrough_init(void)
{
    /* bogger_acpi_find_rsdp() returns the real physical address of the RSDP.
     * No ACPI table modification is performed — the guest receives the same
     * tables as bare-metal hardware exposes. */
    (void)bogger_acpi_find_rsdp();
}
