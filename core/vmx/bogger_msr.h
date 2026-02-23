#ifndef BOGGER_MSR_H
#define BOGGER_MSR_H

#include "bogger_vmx.h"

/*
 * bogger_handle_rdmsr – Handle a RDMSR VM exit.
 *
 * Intercept policy:
 *   - 0x3A  (IA32_FEATURE_CONTROL) : return 0x1 — lock bit set, VMX bits clear
 *   - 0x480–0x48F (IA32_VMX_*)     : return 0 — VMX not advertised
 *   - 0x40000000–0x40000005        : return 0 — hypervisor MSRs hidden
 *   - All others                   : pass real RDMSR result to guest
 */
void bogger_handle_rdmsr(bogger_guest_state_t *guest);

/*
 * bogger_handle_wrmsr – Handle a WRMSR VM exit.
 *
 * Intercept policy:
 *   - VMX-related MSRs (0x3A, 0x480–0x48F) : silently ignored
 *   - All others                            : pass real WRMSR to hardware
 */
void bogger_handle_wrmsr(bogger_guest_state_t *guest);

#endif /* BOGGER_MSR_H */
