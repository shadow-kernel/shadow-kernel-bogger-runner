#ifndef BOGGER_IOMMU_H
#define BOGGER_IOMMU_H

#include <stdint.h>

/*
 * bogger_iommu_detect – Detect IOMMU presence.
 *
 * Scans ACPI tables:
 *   - DMAR (DMA Remapping Reporting) for Intel VT-d
 *   - IVRS (I/O Virtualization Reporting Structure) for AMD-Vi
 *
 * Returns 0 if an IOMMU is found, -1 otherwise.
 */
int bogger_iommu_detect(void);

/*
 * bogger_iommu_init_passthrough – Configure identity (guest PA == host PA)
 * mappings for all passthrough devices so that Windows receives DMA access
 * identical to bare-metal without going through address translation.
 *
 * Returns 0 on success, -1 if no IOMMU is available.
 */
int bogger_iommu_init_passthrough(void);

/*
 * bogger_iommu_map_device – Add an identity mapping for a single PCI device
 * identified by its PCI segment/bus/device/function tuple (BDF).
 */
void bogger_iommu_map_device(uint16_t segment, uint8_t bus,
                              uint8_t dev, uint8_t fn);

#endif /* BOGGER_IOMMU_H */
