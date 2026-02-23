#include "bogger_msr.h"

void bogger_handle_rdmsr(bogger_guest_state_t *guest)
{
    uint32_t msr = (uint32_t)guest->rcx;
    uint64_t val = 0;

    if (msr == MSR_IA32_FEATURE_CONTROL) {
        /* Return lock bit set only — VMX enable bits cleared.
         * This makes the guest believe VMX is locked off. */
        val = 0x1ULL;
    } else if (msr >= 0x480U && msr <= 0x48FU) {
        /* IA32_VMX_* capability MSRs — return 0 to hide VMX support */
        val = 0;
    } else if (msr >= 0x40000000U && msr <= 0x40000005U) {
        /* Hypervisor-defined MSRs — return 0 */
        val = 0;
    } else {
        /* All other MSRs: pass through from real hardware */
        val = bogger_rdmsr(msr);
    }

    /* RDMSR returns value in EDX:EAX */
    guest->rax = (uint32_t)(val & 0xFFFFFFFFU);
    guest->rdx = (uint32_t)(val >> 32);

    /* RDMSR is a 2-byte instruction (0F 32) */
    bogger_advance_rip(guest, 2);
}

void bogger_handle_wrmsr(bogger_guest_state_t *guest)
{
    uint32_t msr = (uint32_t)guest->rcx;
    uint64_t val = ((uint64_t)(uint32_t)guest->rdx << 32) |
                   (uint32_t)guest->rax;

    if (msr == MSR_IA32_FEATURE_CONTROL ||
        (msr >= 0x480U && msr <= 0x48FU)) {
        /* Silently drop writes to VMX-related MSRs */
    } else {
        /* Pass all other MSR writes to hardware */
        bogger_wrmsr(msr, val);
    }

    /* WRMSR is a 2-byte instruction (0F 30) */
    bogger_advance_rip(guest, 2);
}
