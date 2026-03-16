/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOGGER_GUEST_RAM_H
#define BOGGER_GUEST_RAM_H
#include "bogger_types.h"

int  bogger_guest_ram_alloc(void);
void bogger_guest_ram_free(void);
int  guest_ram_write(u64 gpa, const void *src, size_t len);
void *guest_ram_ptr(u64 gpa);
void *bogger_gpa_to_hva(u64 gpa);

#endif

