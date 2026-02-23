#ifndef BOGGER_FINGERPRINT_H
#define BOGGER_FINGERPRINT_H

/*
 * bogger_fingerprint_read – Read SMBIOS DMI data from
 * /sys/firmware/dmi/tables/DMI and extract vendor and product strings.
 *
 * Scans all Type-1 (System Information) and Type-2 (Baseboard Information)
 * structures for strings that would indicate a virtual machine environment.
 */
void bogger_fingerprint_read(void);

/*
 * bogger_fingerprint_verify – Confirm that no virtualisation strings are
 * present in the SMBIOS tables read from real hardware.
 *
 * Known virtualisation signatures checked:
 *   "VBOX", "QEMU", "VMware", "Xen", "KVM", "Hyper-V", "VirtualBox",
 *   "innotek", "BOCHS", "SeaBIOS"
 *
 * Logs a warning for each match found (unexpected on real hardware).
 * Logs success if no such strings are detected.
 */
void bogger_fingerprint_verify(void);

/*
 * bogger_fingerprint_get_vendor  – Return the hardware vendor string
 *                                  (SMBIOS Type-1, offset 0x04), or ""
 *                                  if not yet read.
 * bogger_fingerprint_get_product – Return the product name string
 *                                  (SMBIOS Type-1, offset 0x05), or "".
 */
const char *bogger_fingerprint_get_vendor(void);
const char *bogger_fingerprint_get_product(void);

#endif /* BOGGER_FINGERPRINT_H */
