#ifndef BOGGER_CPUID_H
#define BOGGER_CPUID_H

#include "bogger_vmx.h"

/*
 * bogger_handle_cpuid – Handle a CPUID VM exit.
 *
 * Executes the real CPUID instruction then filters the result so that the
 * guest cannot detect the hypervisor layer:
 *   - Leaf 0x1         : ECX[31] (Hypervisor Present) cleared
 *   - Leaf 0x40000000+ : all outputs zeroed (no hypervisor vendor string)
 *   - All other leaves : passed through unmodified
 */
void bogger_handle_cpuid(bogger_guest_state_t *guest);

#endif /* BOGGER_CPUID_H */
