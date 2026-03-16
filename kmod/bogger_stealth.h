/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOGGER_STEALTH_H
#define BOGGER_STEALTH_H
#include "bogger_types.h"

void bogger_handle_cpuid_stealth(struct vmcb *vmcb, struct bogger_guest_gprs *gprs);
void bogger_handle_rdmsr_stealth(struct vmcb *vmcb, struct bogger_guest_gprs *gprs);
void bogger_handle_wrmsr_stealth(struct vmcb *vmcb, struct bogger_guest_gprs *gprs);

#endif

