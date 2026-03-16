/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOGGER_OVMF_H
#define BOGGER_OVMF_H
#include "bogger_types.h"

int  bogger_load_ovmf(void);
void bogger_ovmf_free(void);

extern size_t ovmf_code_size;  /* size of OVMF_CODE binary (for R/O mapping) */

#endif

