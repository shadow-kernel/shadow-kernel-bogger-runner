#ifndef BOGGER_TSC_H
#define BOGGER_TSC_H

#include <stdint.h>

/*
 * bogger_calibrate_vmexit_overhead – Measure the round-trip VM-exit overhead
 * in TSC cycles by executing a VMCALL and timing the round-trip with RDTSC.
 *
 * Returns the measured overhead in cycles.
 */
uint64_t bogger_calibrate_vmexit_overhead(void);

/*
 * bogger_tsc_offset_init – Compute a negative TSC offset that cancels VM-exit
 * round-trip latency and write it to the VMCS TSC_OFFSET field (0x2010).
 *
 * Note: RDTSC_EXITING is kept at 0 so RDTSC instructions execute natively
 * without triggering any VM exit.  The TSC offset applies to RDTSCP and any
 * future explicit TSC reads that go through the VMCS offset mechanism.
 */
void bogger_tsc_offset_init(void);

#endif /* BOGGER_TSC_H */
