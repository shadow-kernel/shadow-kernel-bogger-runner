/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOGGER_SMBIOS_H
#define BOGGER_SMBIOS_H
#include "bogger_types.h"

int  bogger_smbios_build(void);
u8  *bogger_smbios_get_data(u32 *out_len);

#endif

