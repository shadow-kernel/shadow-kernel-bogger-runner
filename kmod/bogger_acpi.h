/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOGGER_ACPI_H
#define BOGGER_ACPI_H
#include "bogger_types.h"

int bogger_acpi_build(void);

/* ── fw_cfg linker/loader blobs (built by bogger_acpi_build) ────── */
#define ACPI_BLOB_MAX  4096
#define ACPI_LOADER_MAX 2048

extern u8   acpi_tables_blob[];
extern u32  acpi_tables_blob_len;
extern u8   acpi_rsdp_blob[];
extern u32  acpi_rsdp_blob_len;
extern u8   acpi_loader_cmds[];
extern u32  acpi_loader_cmds_len;

#endif

