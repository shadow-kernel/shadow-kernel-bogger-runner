/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOGGER_NPT_H
#define BOGGER_NPT_H
#include "bogger_types.h"

int  bogger_npt_init(void);
void bogger_npt_free(void);
void bogger_nvme_remap_bar(u64 new_gpa);
void bogger_npt_restore_zero_region(u64 gpa_base, u64 size);
void bogger_npt_remap_vga_legacy(void);

extern u64 nvme_bar_active_gpa;

#endif

