/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOGGER_HPET_H
#define BOGGER_HPET_H
#include "bogger_types.h"

#define HPET_GPA  0xFED00000ULL

void hpet_init_regs(void);
void hpet_update_counter(void);
int  hpet_updater_fn(void *data);

#endif

