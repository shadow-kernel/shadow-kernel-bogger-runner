#include "bogger_tsc.h"
#include "bogger_vmx.h"

/*
 * bogger_calibrate_vmexit_overhead – Measure VMCALL round-trip in TSC cycles.
 *
 * Executes VMCALL 16 times and averages the RDTSC delta to reduce noise.
 */
uint64_t bogger_calibrate_vmexit_overhead(void)
{
    uint64_t total = 0;
    int      i;

    for (i = 0; i < 16; i++) {
        uint32_t lo_before, hi_before, lo_after, hi_after;

        __asm__ volatile(
            "mfence\n\t"
            "rdtsc\n\t"
            "mov %%eax, %[lb]\n\t"
            "mov %%edx, %[hb]\n\t"
            "vmcall\n\t"        /* triggers a VM exit and immediate resume */
            "rdtsc\n\t"
            "mov %%eax, %[la]\n\t"
            "mov %%edx, %[ha]\n\t"
            "mfence"
            : [lb] "=m"(lo_before), [hb] "=m"(hi_before),
              [la] "=m"(lo_after),  [ha] "=m"(hi_after)
            :
            : "eax", "edx", "memory"
        );

        uint64_t before = ((uint64_t)hi_before << 32) | lo_before;
        uint64_t after  = ((uint64_t)hi_after  << 32) | lo_after;

        if (after > before)
            total += (after - before);
    }

    return total / 16;
}

/*
 * bogger_tsc_offset_init – Write a negative TSC offset into the VMCS so that
 * timing artifacts caused by VM exits are invisible to the guest.
 *
 * The offset is stored as a two's-complement signed 64-bit value.
 * A negative offset compensates for the hypervisor's own overhead so the
 * guest observes a monotonically-increasing TSC with no gaps.
 *
 * RDTSC_EXITING remains 0: the guest's RDTSC instructions run natively and
 * are affected by the offset transparently.
 */
void bogger_tsc_offset_init(void)
{
    uint64_t overhead = bogger_calibrate_vmexit_overhead();

    /* Two's-complement negation: guest TSC = host TSC + offset removes overhead */
    uint64_t offset = ~overhead + 1ULL;

    bogger_vmwrite(VMCS_TSC_OFFSET, offset);
}
