#include "bogger_ept.h"
#include "bogger_vmx.h"

/*
 * 4-level EPT (PML4 → PDPT → PD → PT).
 *
 * For simplicity the identity map is built at the 1 GB page granularity
 * using large pages at the PDPT level (bit 7 set), covering the first
 * 512 GB of physical address space — sufficient for any current system.
 *
 * Hypervisor-private ranges are broken out into 4 KB pages at the PD/PT
 * level so individual pages can be marked not-present.
 *
 * All tables are 4 KB aligned (required by the hardware).
 */

/* ------------------------------------------------------------------ */
/* Static EPT tables                                                    */
/* ------------------------------------------------------------------ */

/* PML4: one table, 512 entries covering 512 × 512 GB = 256 TB        */
static uint64_t g_ept_pml4[EPT_ENTRIES] __attribute__((aligned(4096)));

/* PDPT: one table, 512 entries × 1 GB large pages = 512 GB identity  */
static uint64_t g_ept_pdpt[EPT_ENTRIES] __attribute__((aligned(4096)));

/*
 * Lazy-allocated fine-grain tables used only when bogger_ept_hide_range()
 * needs to split a 1 GB region into 2 MB pages (PD) then 4 KB pages (PT).
 *
 * We pre-allocate a small pool sufficient for one contiguous hidden region
 * (the hypervisor image is typically < 64 MB).
 */
#define EPT_PD_POOL_SIZE  4     /* up to 4 PD tables (covers 4 × 1 GB) */
#define EPT_PT_POOL_SIZE  64    /* up to 64 PT tables (covers 64 × 2 MB) */

static uint64_t g_ept_pd_pool[EPT_PD_POOL_SIZE][EPT_ENTRIES]
    __attribute__((aligned(4096)));
static uint64_t g_ept_pt_pool[EPT_PT_POOL_SIZE][EPT_ENTRIES]
    __attribute__((aligned(4096)));

static int g_pd_used = 0;
static int g_pt_used = 0;

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static uint64_t *alloc_pd(void)
{
    if (g_pd_used >= EPT_PD_POOL_SIZE)
        return (uint64_t *)0; /* pool exhausted */
    return g_ept_pd_pool[g_pd_used++];
}

static uint64_t *alloc_pt(void)
{
    if (g_pt_used >= EPT_PT_POOL_SIZE)
        return (uint64_t *)0; /* pool exhausted */
    return g_ept_pt_pool[g_pt_used++];
}

/*
 * ept_build_identity_pdpt – Fill g_ept_pdpt with 512 × 1 GB WB large-page
 * entries that provide an identity map of the first 512 GB.
 */
static void ept_build_identity_pdpt(void)
{
    int i;
    for (i = 0; i < EPT_ENTRIES; i++) {
        uint64_t phys = (uint64_t)i << 30; /* 1 GB per entry */
        /* RWX | large | memory-type WB (bits 5:3 = 0; bits 2:0 = 6) */
        g_ept_pdpt[i] = phys | EPT_LARGE | EPT_RWX |
                        ((uint64_t)EPT_MT_WB << 3);
    }
}

/*
 * ept_split_1g – Split the PDPT entry for 'gb_index' from a 1 GB large
 * page into a PD of 512 × 2 MB entries.
 *
 * Returns a pointer to the newly-populated PD, or NULL on pool exhaustion.
 */
static uint64_t *ept_split_1g(int gb_index)
{
    uint64_t *pd = alloc_pd();
    if (!pd)
        return (uint64_t *)0;

    int i;
    uint64_t base = (uint64_t)gb_index << 30;
    for (i = 0; i < EPT_ENTRIES; i++) {
        uint64_t phys = base + ((uint64_t)i << 21); /* 2 MB per entry */
        pd[i] = phys | EPT_LARGE | EPT_RWX |
                ((uint64_t)EPT_MT_WB << 3);
    }

    /* Replace the 1 GB entry with a pointer to the new PD */
    uint64_t pd_phys = (uint64_t)(uintptr_t)pd;
    g_ept_pdpt[gb_index] = (pd_phys & EPT_PA_MASK) | EPT_RWX;

    return pd;
}

/*
 * ept_split_2m – Split a 2 MB entry in a PD into a PT of 512 × 4 KB pages.
 *
 * 'pd'       : pointer to the PD containing the 2 MB entry
 * 'mb2_index': index within pd of the 2 MB entry to split
 *
 * Returns a pointer to the new PT, or NULL on pool exhaustion.
 */
static uint64_t *ept_split_2m(uint64_t *pd, int mb2_index)
{
    uint64_t *pt = alloc_pt();
    if (!pt)
        return (uint64_t *)0;

    int i;
    /* Recover the 2 MB base address from the existing PD entry */
    uint64_t base = pd[mb2_index] & ~((1ULL << 21) - 1);
    base &= EPT_PA_MASK;

    for (i = 0; i < EPT_ENTRIES; i++) {
        uint64_t phys = base + ((uint64_t)i << 12); /* 4 KB per entry */
        pt[i] = (phys & EPT_PA_MASK) | EPT_RWX |
                ((uint64_t)EPT_MT_WB << 3);
    }

    /* Replace the 2 MB entry with a pointer to the new PT */
    uint64_t pt_phys = (uint64_t)(uintptr_t)pt;
    pd[mb2_index] = (pt_phys & EPT_PA_MASK) | EPT_RWX;

    return pt;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

void bogger_ept_init(void)
{
    /* Build the identity-mapped PDPT (512 × 1 GB large pages) */
    ept_build_identity_pdpt();

    /* PML4[0] → PDPT (covers 0 – 512 GB) */
    uint64_t pdpt_phys = (uint64_t)(uintptr_t)g_ept_pdpt;
    g_ept_pml4[0] = (pdpt_phys & EPT_PA_MASK) | EPT_RWX;

    /*
     * Build the EPTP:
     *   bits 2:0  = memory type for EPT paging structures (WB = 6)
     *   bits 5:3  = EPT page-walk length minus 1 (4-level = 3)
     *   bits 11:6 = 0 (AD bits not enabled)
     *   bits 63:12 = PML4 physical address
     */
    uint64_t pml4_phys = (uint64_t)(uintptr_t)g_ept_pml4;
    uint64_t eptp = (pml4_phys & EPT_PA_MASK) |
                    ((uint64_t)3 << 3) |        /* walk length − 1 */
                    (uint64_t)EPT_MT_WB;        /* memory type     */

    bogger_vmwrite(VMCS_EPTP, eptp);
}

void bogger_ept_hide_range(uint64_t phys_start, uint64_t phys_end)
{
    uint64_t addr;

    if (phys_start >= phys_end)
        return;

    /* Align to 4 KB */
    phys_start &= ~(uint64_t)0xFFF;
    phys_end    = (phys_end + 0xFFF) & ~(uint64_t)0xFFF;

    for (addr = phys_start; addr < phys_end; addr += 0x1000) {
        int gb_idx  = (int)(addr >> 30) & (EPT_ENTRIES - 1);
        int mb2_idx = (int)(addr >> 21) & (EPT_ENTRIES - 1);
        int kb4_idx = (int)(addr >> 12) & (EPT_ENTRIES - 1);
        uint64_t *pd = (uint64_t *)0;
        uint64_t *pt = (uint64_t *)0;

        /* If PDPT entry is still a large 1 GB page, split it */
        if (g_ept_pdpt[gb_idx] & EPT_LARGE) {
            pd = ept_split_1g(gb_idx);
            if (!pd)
                return; /* pool exhausted — best effort */
        } else {
            /* PDPT entry points to a PD */
            uint64_t pd_phys = g_ept_pdpt[gb_idx] & EPT_PA_MASK;
            pd = (uint64_t *)(uintptr_t)pd_phys;
        }

        /* If PD entry is still a large 2 MB page, split it */
        if (pd[mb2_idx] & EPT_LARGE) {
            pt = ept_split_2m(pd, mb2_idx);
            if (!pt)
                return; /* pool exhausted */
        } else {
            uint64_t pt_phys = pd[mb2_idx] & EPT_PA_MASK;
            pt = (uint64_t *)(uintptr_t)pt_phys;
        }

        /* Mark the 4 KB page as not-present (clear all permission bits) */
        pt[kb4_idx] = 0;
    }
}
