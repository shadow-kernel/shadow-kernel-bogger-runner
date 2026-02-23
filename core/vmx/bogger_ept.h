#ifndef BOGGER_EPT_H
#define BOGGER_EPT_H

#include <stdint.h>

/* VMCS field for the EPT pointer */
#define VMCS_EPTP   0x201A

/* EPT memory type constants (bits 2:0 of EPTP and PTE) */
#define EPT_MT_UC   0   /* Uncacheable  */
#define EPT_MT_WB   6   /* Write-back   */

/* EPT page-table entry permission bits */
#define EPT_READ    (1ULL << 0)
#define EPT_WRITE   (1ULL << 1)
#define EPT_EXEC    (1ULL << 2)
#define EPT_RWX     (EPT_READ | EPT_WRITE | EPT_EXEC)

/* EPT page present (any of R/W/X) */
#define EPT_PRESENT EPT_RWX

/* Bit 7 in EPT PDE/PDPTE: large page */
#define EPT_LARGE   (1ULL << 7)

/* Bit 6 in leaf EPT PTE: memory type (bits 5:3 = IPAT; 2:0 = mem type) */
/* For WB leaves: set bits 2:0 = 6 */
#define EPT_MT_SHIFT    3

/* Number of entries per EPT table (512 = 2^9) */
#define EPT_ENTRIES     512

/* Physical-address width used for EPT tables (48-bit PA) */
#define EPT_PA_MASK     0x000FFFFFFFFFF000ULL

/*
 * bogger_ept_init – Build a 4-level identity-mapped EPT covering all RAM.
 *
 * Uses 1 GB large pages at the PDPT level for efficiency.  Marks the
 * hypervisor's own memory (bogger_ept_hide_range) as not-present so
 * Windows cannot see or DMA-access it.
 *
 * Writes the resulting EPTP into VMCS field VMCS_EPTP (0x201A).
 */
void bogger_ept_init(void);

/*
 * bogger_ept_hide_range – Mark a guest-physical range as not-present in
 * the EPT so that Windows cannot read, write, or execute it.
 *
 * phys_start / phys_end must be 4 KB aligned.
 */
void bogger_ept_hide_range(uint64_t phys_start, uint64_t phys_end);

#endif /* BOGGER_EPT_H */
