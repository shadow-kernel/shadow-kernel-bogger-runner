#ifndef BOGGER_ACPI_H
#define BOGGER_ACPI_H

#include <stdint.h>

/*
 * bogger_acpi_find_rsdp – Locate the ACPI Root System Description Pointer.
 *
 * Search order:
 *   1. UEFI memory map (EFI_SYSTEM_TABLE ConfigurationTable for ACPI 2.0 GUID)
 *   2. Legacy scan of 0x000E0000–0x000FFFFF (16-byte aligned, "RSD PTR " sig)
 *
 * Validates the RSDP checksum before returning.
 *
 * Returns the physical address of the valid RSDP, or 0 on failure.
 */
uint64_t bogger_acpi_find_rsdp(void);

/*
 * bogger_acpi_passthrough_init – Pass the real RSDP address to the guest
 * without modification so that Windows sees identical ACPI tables to
 * bare-metal.
 */
void bogger_acpi_passthrough_init(void);

#endif /* BOGGER_ACPI_H */
