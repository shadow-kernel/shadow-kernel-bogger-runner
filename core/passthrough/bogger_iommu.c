#include "bogger_iommu.h"

/* ACPI table signatures */
#define SIG_DMAR 0x52414D44UL  /* "DMAR" */
#define SIG_IVRS 0x53525649UL  /* "IVRS" */

typedef struct {
    uint8_t  signature[4];
    uint32_t length;
    uint8_t  revision;
    uint8_t  checksum;
    uint8_t  oem_id[6];
    uint8_t  oem_table_id[8];
    uint32_t oem_revision;
    uint8_t  creator_id[4];
    uint32_t creator_revision;
} __attribute__((packed)) acpi_table_hdr_t;

/* IOMMU type detected */
typedef enum {
    IOMMU_NONE  = 0,
    IOMMU_VTD   = 1,   /* Intel VT-d */
    IOMMU_AMDVI = 2,   /* AMD-Vi    */
} iommu_type_t;

static iommu_type_t g_iommu_type = IOMMU_NONE;

/*
 * scan_acpi_for_table – Walk the RSDT/XSDT looking for an ACPI table with
 * the given 4-byte signature.  Returns the physical address of the table
 * header, or 0 if not found.
 *
 * In a full implementation this would parse the RSDT located via
 * bogger_acpi_find_rsdp().  Here we provide the structural skeleton that a
 * real IOMMU driver would build upon.
 */
static uint64_t scan_acpi_for_table(uint32_t sig)
{
    (void)sig;
    /* TODO: traverse real RSDT/XSDT entries */
    return 0;
}

int bogger_iommu_detect(void)
{
    if (scan_acpi_for_table(SIG_DMAR)) {
        g_iommu_type = IOMMU_VTD;
        return 0;
    }
    if (scan_acpi_for_table(SIG_IVRS)) {
        g_iommu_type = IOMMU_AMDVI;
        return 0;
    }
    g_iommu_type = IOMMU_NONE;
    return -1;
}

int bogger_iommu_init_passthrough(void)
{
    if (bogger_iommu_detect() != 0)
        return -1;

    /* Configure the IOMMU for identity mapping: guest PA == host PA.
     * This gives passthrough devices (GPU, NVMe, NIC) DMA access that is
     * transparent to Windows — no address translation is visible. */

    /* TODO: program DMA Remapping Hardware Unit (DRHD) registers for VT-d,
     *       or IOMMU MMIO base for AMD-Vi, with an identity page-table. */

    return 0;
}

void bogger_iommu_map_device(uint16_t segment, uint8_t bus,
                              uint8_t dev, uint8_t fn)
{
    /* Log the device being mapped for passthrough.
     * In a full implementation:
     *   - Locate or create a per-device context/domain entry
     *   - Programme an identity mapping covering the full 64-bit PA space
     *     (or the required range) into the IOMMU page table
     *
     * BDF = segment:bus:device.function */
    (void)segment;
    (void)bus;
    (void)dev;
    (void)fn;
    /* Identity mapping: guest PA == host PA — no translation required */
}
