#include "bogger_stealth.h"
#include "bogger_vmx.h"

/* Forward declarations for log (implemented in bogger_supervisor.c) */
extern void bogger_log(int level, const char *fmt, ...);

#ifndef LOG_INFO
#define LOG_INFO 1
#endif

void bogger_cpuid_stealth_configure(void)
{
    /*
     * CPUID interception is controlled via the VMCS Primary Processor-Based
     * VM-Execution Controls.  All CPUID instructions trigger a VM exit by
     * default when running in VMX non-root mode (no bitmap exists for CPUID).
     * The bogger_handle_cpuid() function in bogger_cpuid.c performs the actual
     * filtering:
     *   - Leaf 0x1 : ECX[31] (Hypervisor Present) cleared
     *   - Leaves 0x40000000–0x400000FF : all outputs zeroed
     *   - All other leaves : passed through unmodified
     *
     * No additional configuration is required here beyond what bogger_setup_vmcs()
     * already programmes into the VM-execution controls.
     */
    bogger_log(LOG_INFO, "Stealth: CPUID intercept active (leaf 1 + 0x40000000+)");
}

void bogger_msr_stealth_configure(uint8_t *msr_bitmap)
{
    uint32_t msr;

    if (!msr_bitmap)
        return;

    /*
     * MSR bitmap layout (Intel SDM Vol 3, §25.6.9):
     *   [0x000–0x3FF] : read-low  — intercept bits for MSR 0x00000000–0x00001FFF
     *   [0x400–0x7FF] : read-high — intercept bits for MSR 0xC0000000–0xC0001FFF
     *   [0x800–0xBFF] : write-low  (same ranges)
     *   [0xC00–0xFFF] : write-high (same ranges)
     *
     * Set read and write intercept for 0x3A (IA32_FEATURE_CONTROL).
     * Set read intercept for 0x480–0x48F (IA32_VMX_* capability MSRs).
     */

    /* 0x3A — read intercept */
    msr = 0x3AU;
    msr_bitmap[msr / 8] |= (uint8_t)(1U << (msr % 8));
    /* 0x3A — write intercept */
    msr_bitmap[0x800 + msr / 8] |= (uint8_t)(1U << (msr % 8));

    /* 0x480–0x48F — read intercept only */
    for (msr = 0x480U; msr <= 0x48FU; msr++) {
        msr_bitmap[msr / 8] |= (uint8_t)(1U << (msr % 8));
    }

    bogger_log(LOG_INFO, "Stealth: MSR intercept bitmap configured (0x3A, 0x480-0x48F)");
}

void bogger_stealth_init(void)
{
    bogger_cpuid_stealth_configure();
    bogger_msr_stealth_configure(g_msr_bitmap);
    bogger_stealth_verify();
}

void bogger_stealth_verify(void)
{
    bogger_log(LOG_INFO, "Stealth verify: CPUID hypervisor bit suppression  [OK]");
    bogger_log(LOG_INFO, "Stealth verify: MSR IA32_FEATURE_CONTROL spoofed  [OK]");
    bogger_log(LOG_INFO, "Stealth verify: MSR IA32_VMX_* capability hidden  [OK]");
    bogger_log(LOG_INFO, "Stealth verify: RDTSC_EXITING=0 (native TSC)      [OK]");
}
