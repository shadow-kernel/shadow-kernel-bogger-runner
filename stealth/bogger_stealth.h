#ifndef BOGGER_STEALTH_H
#define BOGGER_STEALTH_H

#include <stdint.h>

/*
 * bogger_stealth_init – Initialise all stealth subsystems.
 *
 * Calls bogger_cpuid_stealth_configure() and bogger_msr_stealth_configure()
 * to set up the CPUID and MSR intercept bitmaps before VMLAUNCH.
 */
void bogger_stealth_init(void);

/*
 * bogger_cpuid_stealth_configure – Configure which CPUID leaves are
 * intercepted by the hypervisor.
 *
 * Always intercepted (regardless of bogger.conf):
 *   - Leaf 0x1             : ECX[31] Hypervisor Present bit cleared
 *   - Leaves 0x40000000+   : all outputs zeroed (no vendor string)
 *
 * Controlled by BOGGER_STEALTH_CPUID in bogger.conf (default: 1=enabled).
 */
void bogger_cpuid_stealth_configure(void);

/*
 * bogger_msr_stealth_configure – Populate the MSR intercept bitmap.
 *
 * Intercepted MSRs:
 *   - 0x3A  (IA32_FEATURE_CONTROL) : read + write intercept
 *   - 0x480–0x48F (IA32_VMX_*)     : read intercept
 *
 * Controlled by BOGGER_STEALTH_MSR in bogger.conf (default: 1=enabled).
 *
 * msr_bitmap : pointer to the 4-KB MSR bitmap used in the VMCS.
 */
void bogger_msr_stealth_configure(uint8_t *msr_bitmap);

/*
 * bogger_stealth_verify – Log the active status of each stealth measure to
 * /dev/console for operator verification.
 */
void bogger_stealth_verify(void);

#endif /* BOGGER_STEALTH_H */
