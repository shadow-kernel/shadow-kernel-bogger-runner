/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOGGER_IOPORT_H
#define BOGGER_IOPORT_H
#include "bogger_types.h"

void bogger_handle_ioio(struct vmcb *vmcb, int exits, int max_logged_exits);
void bogger_dump_pci_ring(void);
extern unsigned long fwcfg_port511_reads;

#endif

