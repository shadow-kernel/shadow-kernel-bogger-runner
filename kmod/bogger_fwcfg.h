/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOGGER_FWCFG_H
#define BOGGER_FWCFG_H
#include "bogger_types.h"

void fwcfg_build_data(u16 sel);
u8   fwcfg_read_byte(void);

extern u16  fwcfg_selector;
extern u32  fwcfg_offset;
extern bool fwcfg_buf_valid;

#endif

