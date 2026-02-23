#ifndef BOGGER_EFI_SCAN_H
#define BOGGER_EFI_SCAN_H

#include <stdint.h>

/*
 * bogger_efi_get_entry – Locate the Windows EFI boot loader and return the
 * address of its PE/COFF entry point.
 *
 * efi_path : path to the winload.efi binary on an accessible file system,
 *            e.g. "/mnt/esp/EFI/Microsoft/Boot/winload.efi"
 *
 * Returns the virtual entry-point address parsed from the PE header, or
 * 0 on failure.
 */
uint64_t bogger_efi_get_entry(const char *efi_path);

#endif /* BOGGER_EFI_SCAN_H */
