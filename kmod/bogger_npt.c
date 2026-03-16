// SPDX-License-Identifier: GPL-2.0
/*
 * bogger_npt.c – Nested Page Tables (NPT) for AMD SVM
 *
 * 4-level: PML4 → PDPT → PD → PT (4 KB pages for guest RAM)
 * Maps guest RAM, MMIO devices (HPET, LAPIC, IOAPIC, NVMe), OVMF flash.
 */
#include "bogger_npt.h"
#include "bogger_hpet.h"
#include "bogger_lapic.h"
#include "bogger_ioapic.h"
#include "bogger_nvme.h"
#include "bogger_ovmf.h"
#include "bogger_vga.h"

u64 *npt_pml4;
u64 *npt_pdpt;
u64 *npt_pd_tables[NPT_NUM_PD_TABLES];
u64 *npt_pt_pages[NPT_MAX_PT_PAGES];
unsigned long npt_num_pt_used;
struct page *npt_zero_page;

/* Split RAM sizes – computed here, declared extern in types.h */
u64 guest_ram_below_4g;
u64 guest_ram_above_4g;

/* Current GPA where NVMe BAR is mapped in NPT (may be relocated by guest) */
u64 nvme_bar_active_gpa = NVME_BAR_GPA;

/*
 * bogger_npt_restore_zero_region() – Restore a GPA range to zero-page
 * mappings.  Used when a BAR is relocated away from a GPA to clean up
 * stale 2MB huge pages that would otherwise persist in NPT.
 *
 * For 2MB-aligned, 2MB-sized chunks: replaces the PD entry with a
 * freshly allocated 4KB PT filled with zero pages.
 * For 4KB PT entries: overwrites individual PTEs with zero page.
 */
void bogger_npt_restore_zero_region(u64 gpa_base, u64 size)
{
    u64 gpa, end, zero_hpa;
    if (!npt_zero_page) return;
    zero_hpa = page_to_phys(npt_zero_page);
    gpa = gpa_base & ~0xFFFULL;
    end = gpa_base + size;

    while (gpa < end) {
        unsigned int pd_idx = (unsigned int)(gpa >> 30);
        unsigned int pd_e   = (unsigned int)((gpa >> 21) & 0x1FF);
        u64 pd_entry;

        if (pd_idx >= NPT_NUM_PD_TABLES || !npt_pd_tables[pd_idx])
            break;
        pd_entry = npt_pd_tables[pd_idx][pd_e];

        /* If PD entry is a 2MB huge page and we cover an entire 2MB,
         * replace it with a zero-page PT */
        if ((gpa & ((1ULL << 21) - 1)) == 0 &&
            (end - gpa) >= (1ULL << 21) &&
            (pd_entry & (1ULL << 7))) {
            u64 *zpt = (u64 *)get_zeroed_page(GFP_KERNEL);
            if (zpt) {
                unsigned int k;
                for (k = 0; k < 512; k++)
                    zpt[k] = zero_hpa | 0x07ULL;
                npt_pd_tables[pd_idx][pd_e] = virt_to_phys(zpt) | 0x07ULL;
            }
            gpa += (1ULL << 21);
            continue;
        }

        /* 4KB granularity */
        if ((pd_entry & 0x01ULL) && !(pd_entry & (1ULL << 7))) {
            unsigned int pt_e = (unsigned int)((gpa >> 12) & 0x1FF);
            u64 pt_phys = pd_entry & ~0xFFFULL;
            if (pt_phys)
                ((u64 *)phys_to_virt(pt_phys))[pt_e] = zero_hpa | 0x07ULL;
        }
        gpa += PAGE_SIZE;
    }
}

/*
 * bogger_nvme_remap_bar() – Dynamically move the NVMe BAR MMIO pages
 * in NPT when the guest PCI bus driver relocates the BAR.
 *
 * Unmaps the old GPA (sets PTEs to zero page) and maps the new GPA
 * to the nvme_bar_pages with read-only access for write trapping.
 */
/*
 * Split a 2MB huge page PD entry into 512 individual 4KB page entries.
 * The huge page HPA is preserved across all 512 sub-pages.
 * Returns the new PT's virtual address, or NULL on allocation failure.
 */
static u64 *npt_split_2mb_page(u64 *pd_entry_ptr)
{
    u64 pd_entry = *pd_entry_ptr;
    u64 huge_hpa = pd_entry & ~((1ULL << 21) - 1);
    u64 flags    = pd_entry & 0x1FULL;  /* preserve RWX + PCD bits */
    u64 *new_pt;
    unsigned int k;

    new_pt = (u64 *)get_zeroed_page(GFP_KERNEL);
    if (!new_pt) return NULL;

    for (k = 0; k < 512; k++)
        new_pt[k] = (huge_hpa + ((u64)k << 12)) | flags;

    *pd_entry_ptr = virt_to_phys(new_pt) | 0x07ULL;
    return new_pt;
}

void bogger_nvme_remap_bar(u64 new_gpa)
{
    extern bool bogger_npt_dirty_from_ioio;
    unsigned int j;
    u64 zero_hpa;

    if (!npt_zero_page || !nvme_bar_pages[0]) return;
    zero_hpa = page_to_phys(npt_zero_page);

    /* Signal NPT modification for TLB flush */
    bogger_npt_dirty_from_ioio = true;

    /* Unmap old location */
    for (j = 0; j < 4; j++) {
        u64 old_gpa = nvme_bar_active_gpa + (u64)j * PAGE_SIZE;
        unsigned int pd_idx = (unsigned int)(old_gpa >> 30);
        unsigned int pd_e = (unsigned int)((old_gpa >> 21) & 0x1FF);
        unsigned int pt_e = (unsigned int)((old_gpa >> 12) & 0x1FF);
        u64 pd_entry, pt_phys;
        if (pd_idx >= NPT_NUM_PD_TABLES || !npt_pd_tables[pd_idx]) continue;
        pd_entry = npt_pd_tables[pd_idx][pd_e];
        if (!pd_entry) continue;
        /* If this is a 2MB huge page (PS bit set), split it first */
        if (pd_entry & (1ULL << 7)) {
            if (!npt_split_2mb_page(&npt_pd_tables[pd_idx][pd_e]))
                continue;
            pd_entry = npt_pd_tables[pd_idx][pd_e];
        }
        pt_phys = pd_entry & ~0xFFFULL;
        if (pt_phys)
            ((u64 *)phys_to_virt(pt_phys))[pt_e] = zero_hpa | 0x07ULL;
    }

    /* Map at new location (read-only for write trapping via NPF) */
    for (j = 0; j < 4; j++) {
        u64 gpa = new_gpa + (u64)j * PAGE_SIZE;
        unsigned int pd_idx = (unsigned int)(gpa >> 30);
        unsigned int pd_e = (unsigned int)((gpa >> 21) & 0x1FF);
        unsigned int pt_e = (unsigned int)((gpa >> 12) & 0x1FF);
        u64 pd_entry, pt_phys;
        if (pd_idx >= NPT_NUM_PD_TABLES || !npt_pd_tables[pd_idx]) continue;
        pd_entry = npt_pd_tables[pd_idx][pd_e];
        if (!pd_entry) continue;
        /* If this is a 2MB huge page (PS bit set), split it first */
        if (pd_entry & (1ULL << 7)) {
            if (!npt_split_2mb_page(&npt_pd_tables[pd_idx][pd_e]))
                continue;
            pd_entry = npt_pd_tables[pd_idx][pd_e];
        }
        pt_phys = pd_entry & ~0xFFFULL;
        if (pt_phys)
            ((u64 *)phys_to_virt(pt_phys))[pt_e] = page_to_phys(nvme_bar_pages[j]) | 0x05ULL;
    }

    pr_info("[BOGGER] NVMe BAR remapped: 0x%llx -> 0x%llx\n",
            nvme_bar_active_gpa, new_gpa);
    nvme_bar_active_gpa = new_gpa;
}

int bogger_npt_init(void)
{
    unsigned long i, page_idx;
    unsigned long below_4g_pages, above_4g_pages;
    unsigned long below_4g_pts, above_4g_pts;

    /* Compute the below-4G / above-4G split.
     * PC architecture requires an MMIO hole from 0xC0000000 to 0xFFFFFFFF
     * for PCI BARs, LAPIC, IOAPIC, firmware flash, etc. */
    if (guest_ram_size > MMIO_GAP_START) {
        guest_ram_below_4g = MMIO_GAP_START;
        guest_ram_above_4g = guest_ram_size - MMIO_GAP_START;
    } else {
        guest_ram_below_4g = guest_ram_size;
        guest_ram_above_4g = 0;
    }
    below_4g_pages = (unsigned long)(guest_ram_below_4g >> PAGE_SHIFT);
    above_4g_pages = guest_nr_pages - below_4g_pages;

    npt_num_pt_used = (guest_nr_pages + 511) / 512;
    if (npt_num_pt_used > NPT_MAX_PT_PAGES)
        npt_num_pt_used = NPT_MAX_PT_PAGES;

    below_4g_pts = (below_4g_pages + 511) / 512;
    above_4g_pts = npt_num_pt_used - below_4g_pts;

    pr_info("[BOGGER] NPT: %lu PT pages for %lu guest pages (%llu MB)\n",
            npt_num_pt_used, guest_nr_pages, (unsigned long long)(guest_ram_size >> 20));
    pr_info("[BOGGER] NPT: below4g=%llu MB (%lu PTs), above4g=%llu MB (%lu PTs)\n",
            (unsigned long long)(guest_ram_below_4g >> 20), below_4g_pts,
            (unsigned long long)(guest_ram_above_4g >> 20), above_4g_pts);

    npt_pml4 = (u64 *)get_zeroed_page(GFP_KERNEL);
    if (!npt_pml4) return -ENOMEM;
    npt_pdpt = (u64 *)get_zeroed_page(GFP_KERNEL);
    if (!npt_pdpt) goto fail_pml4;

    /* Only allocate PD tables that are actually needed (on-demand).
     * For guest RAM below 4G, we need PD tables 0–3 (0–4 GB).
     * For above 4G, we need PD table 4+ (starting at 4 GB).
     * For MMIO gap (3–4 GB), PD table 3 is populated with zero pages.
     * GPU BAR PD tables are allocated lazily in passthrough_map_bars(). */
    {
        unsigned int needed_pd = 4; /* Always at least 0–4 GB */
        if (guest_ram_above_4g > 0) {
            u64 top = MMIO_GAP_END + guest_ram_above_4g;
            unsigned int top_pd = (unsigned int)((top - 1) >> 30) + 1;
            if (top_pd > needed_pd) needed_pd = top_pd;
        }
        if (needed_pd > NPT_NUM_PD_TABLES) needed_pd = NPT_NUM_PD_TABLES;
        for (i = 0; i < needed_pd; i++) {
            npt_pd_tables[i] = (u64 *)get_zeroed_page(GFP_KERNEL);
            if (!npt_pd_tables[i]) goto fail_pd;
        }
        /* Remaining PD tables start as NULL — allocated lazily
         * by passthrough BAR mapping or NPF zero-page fill */
    }
    for (i = 0; i < npt_num_pt_used; i++) {
        npt_pt_pages[i] = (u64 *)get_zeroed_page(GFP_KERNEL);
        if (!npt_pt_pages[i]) goto fail_pt;
    }

    /* Map guest RAM pages into PT pages (physical backing) */
    page_idx = 0;
    for (i = 0; i < npt_num_pt_used; i++) {
        unsigned int pt_idx;
        for (pt_idx = 0; pt_idx < 512 && page_idx < guest_nr_pages; pt_idx++, page_idx++)
            npt_pt_pages[i][pt_idx] = page_to_phys(guest_pages[page_idx]) | 0x07ULL;
    }

    /* Wire PT pages into PD tables – SPLIT across MMIO gap.
     *   Region 1 (below 4G):  PTs 0..below_4g_pts-1 → GPA 0 to MMIO_GAP_START-1
     *   Region 2 (above 4G):  PTs below_4g_pts..end → GPA 0x100000000 upward
     * PD table 3 (3G–4G) is left EMPTY for MMIO zero-page fill below. */
    {
        /* Region 1: below 4G starting at GPA 0 */
        u64 gpa_base = GUEST_RAM_GPA_BASE;
        unsigned int pd_table_idx = (unsigned int)(gpa_base >> 30);
        unsigned int pd_entry_start = (unsigned int)((gpa_base >> 21) & 0x1FF);
        for (i = 0; i < below_4g_pts; i++) {
            unsigned int cur_pd = pd_table_idx + ((pd_entry_start + i) / 512);
            unsigned int cur_entry = (pd_entry_start + i) % 512;
            if (cur_pd >= NPT_NUM_PD_TABLES) break;
            npt_pd_tables[cur_pd][cur_entry] = virt_to_phys(npt_pt_pages[i]) | 0x07ULL;
        }
    }
    if (above_4g_pts > 0) {
        /* Region 2: above 4G starting at GPA 0x100000000 */
        u64 gpa_base = MMIO_GAP_END;
        unsigned int pd_table_idx = (unsigned int)(gpa_base >> 30);
        unsigned int pd_entry_start = (unsigned int)((gpa_base >> 21) & 0x1FF);
        for (i = 0; i < above_4g_pts; i++) {
            unsigned int cur_pd = pd_table_idx + ((pd_entry_start + i) / 512);
            unsigned int cur_entry = (pd_entry_start + i) % 512;
            if (cur_pd >= NPT_NUM_PD_TABLES) break;
            npt_pd_tables[cur_pd][cur_entry] = virt_to_phys(npt_pt_pages[below_4g_pts + i]) | 0x07ULL;
        }
    }

    /* Zero page for unmapped regions */
    npt_zero_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (!npt_zero_page) goto fail_pt;

    /* MMIO region 0xC0000000–0xFFFFFFFF → zero pages */
    {
        unsigned int entry;
        u64 zero_hpa = page_to_phys(npt_zero_page);
        for (entry = 0; entry < 512; entry++) {
            if (npt_pd_tables[3][entry] == 0) {
                u64 *zpt = (u64 *)get_zeroed_page(GFP_KERNEL);
                if (zpt) {
                    unsigned int k;
                    for (k = 0; k < 512; k++) zpt[k] = zero_hpa | 0x07ULL;
                    npt_pd_tables[3][entry] = virt_to_phys(zpt) | 0x07ULL;
                }
            }
        }
    }

    /* ── HPET page at 0xFED00000 (read-only for write trapping) ──── */
    hpet_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (hpet_page) {
        unsigned int pd_e = (unsigned int)((HPET_GPA >> 21) & 0x1FF);
        unsigned int pt_e = (unsigned int)((HPET_GPA >> 12) & 0x1FF);
        u64 pt_phys;
        hpet_regs = (volatile u32 *)page_address(hpet_page);
        hpet_init_regs();
        pt_phys = npt_pd_tables[3][pd_e] & ~0xFFFULL;
        if (pt_phys)
            ((u64 *)phys_to_virt(pt_phys))[pt_e] = page_to_phys(hpet_page) | 0x05ULL;
    }

    /* ── LAPIC page at 0xFEE00000 (read-only for write trapping) ── */
    lapic_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (lapic_page) {
        unsigned int pd_e = (unsigned int)((LAPIC_GPA >> 21) & 0x1FF);
        unsigned int pt_e = (unsigned int)((LAPIC_GPA >> 12) & 0x1FF);
        u64 pt_phys;
        lapic_regs = (volatile u32 *)page_address(lapic_page);
        lapic_init_regs();
        pt_phys = npt_pd_tables[3][pd_e] & ~0xFFFULL;
        if (pt_phys)
            ((u64 *)phys_to_virt(pt_phys))[pt_e] = page_to_phys(lapic_page) | 0x05ULL;
    }

    /* ── IOAPIC page at 0xFEC00000 (read-only for write trapping) ─ */
    ioapic_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (ioapic_page) {
        unsigned int pd_e = (unsigned int)((IOAPIC_GPA >> 21) & 0x1FF);
        unsigned int pt_e = (unsigned int)((IOAPIC_GPA >> 12) & 0x1FF);
        u64 pt_phys;
        ioapic_regs = (volatile u32 *)page_address(ioapic_page);
        ioapic_init_regs();
        pt_phys = npt_pd_tables[3][pd_e] & ~0xFFFULL;
        if (pt_phys)
            ((u64 *)phys_to_virt(pt_phys))[pt_e] = page_to_phys(ioapic_page) | 0x05ULL;
    }

    /* ── NVMe BAR pages at NVME_BAR_GPA (0xE2000000) ───────────── */
    {
        int ok = 1;
        unsigned int j;
        for (j = 0; j < 4; j++) {
            nvme_bar_pages[j] = alloc_page(GFP_KERNEL | __GFP_ZERO);
            if (!nvme_bar_pages[j]) { ok = 0; break; }
        }
        if (ok) {
            struct page *arr[4];
            for (j = 0; j < 4; j++) arr[j] = nvme_bar_pages[j];
            nvme_regs = (volatile u32 *)vmap(arr, 4, VM_MAP, PAGE_KERNEL);
            if (nvme_regs) {
                nvme_init_regs();
                for (j = 0; j < 4; j++) {
                    u64 gpa = NVME_BAR_GPA + (u64)j * PAGE_SIZE;
                    unsigned int pd_idx = (unsigned int)(gpa >> 30);
                    unsigned int pd_e = (unsigned int)((gpa >> 21) & 0x1FF);
                    unsigned int pt_e = (unsigned int)((gpa >> 12) & 0x1FF);
                    u64 pt_phys;
                    if (pd_idx < NPT_NUM_PD_TABLES && npt_pd_tables[pd_idx][pd_e]) {
                        pt_phys = npt_pd_tables[pd_idx][pd_e] & ~0xFFFULL;
                        /* NVMe BAR: read-only mapping — writes must trigger NPF
                         * so the hypervisor can process CC, AQA, ASQ, ACQ and
                         * doorbell register updates. Reads go directly to the
                         * backing page (nvme_regs are stored there). */
                        ((u64 *)phys_to_virt(pt_phys))[pt_e] = page_to_phys(nvme_bar_pages[j]) | 0x05ULL;
                    }
                }
            }
        }
    }

    /* ── OVMF flash at 0xFFC00000 ────────────────────────────────── */
    if (ovmf_pages && ovmf_nr_pages > 0) {
        u64 flash_gpa = OVMF_FLASH_GPA;
        unsigned long fp;
        for (fp = 0; fp < ovmf_nr_pages; fp++) {
            u64 gpa = flash_gpa + ((u64)fp << PAGE_SHIFT);
            unsigned int pd_idx = (unsigned int)(gpa >> 30);
            unsigned int pd_e = (unsigned int)((gpa >> 21) & 0x1FF);
            unsigned int pt_e = (unsigned int)((gpa >> 12) & 0x1FF);
            if (pd_idx >= NPT_NUM_PD_TABLES) continue;
            if (npt_pd_tables[pd_idx][pd_e] & (1ULL << 7)) {
                u64 *new_pt = (u64 *)get_zeroed_page(GFP_KERNEL);
                unsigned int k;
                u64 base_2mb = gpa & ~((1ULL << 21) - 1);
                if (!new_pt) continue;
                for (k = 0; k < 512; k++)
                    new_pt[k] = (base_2mb + ((u64)k << 12)) | 0x17ULL;
                npt_pd_tables[pd_idx][pd_e] = virt_to_phys(new_pt) | 0x07ULL;
            }
            {
                u64 pt_phys = npt_pd_tables[pd_idx][pd_e] & ~0xFFFULL;
                /* Map all OVMF flash pages as RWX (0x07).
                 * SEC needs writable flash early in boot. */
                ((u64 *)phys_to_virt(pt_phys))[pt_e] = page_to_phys(ovmf_pages[fp]) | 0x07ULL;
            }
        }
    }

    /* ── VGA Framebuffer pages (16 MB) ───────────────────────────── */
    /* OVMF's GOP driver writes directly to the VGA framebuffer.
     * Without allocated pages here, NPFs occur during display init.
     * Allocate 16 MB of pages for the framebuffer area. */
    {
        u64 vga_fb_gpa = VGA_FB_GPA;
        unsigned long vga_pages_count = 16 * 256; /* 16 MB = 4096 pages */
        unsigned long vp;
        for (vp = 0; vp < vga_pages_count; vp++) {
            u64 gpa = vga_fb_gpa + (vp << PAGE_SHIFT);
            unsigned int pd_idx = (unsigned int)(gpa >> 30);
            unsigned int pd_e = (unsigned int)((gpa >> 21) & 0x1FF);
            unsigned int pt_e = (unsigned int)((gpa >> 12) & 0x1FF);
            u64 pt_phys;
            struct page *fb_page;
            if (pd_idx >= NPT_NUM_PD_TABLES) continue;
            if (!npt_pd_tables[pd_idx][pd_e]) continue;
            pt_phys = npt_pd_tables[pd_idx][pd_e] & ~0xFFFULL;
            if (!pt_phys) continue;
            /* Only allocate if currently pointing to zero page */
            if (((u64 *)phys_to_virt(pt_phys))[pt_e] ==
                (page_to_phys(npt_zero_page) | 0x07ULL)) {
                fb_page = alloc_page(GFP_KERNEL | __GFP_ZERO | __GFP_NOWARN);
                if (fb_page)
                    ((u64 *)phys_to_virt(pt_phys))[pt_e] = page_to_phys(fb_page) | 0x07ULL;
            }
        }
    }

    /* ── VGA MMIO pages (16 MB) ──────────────────────────────────── */
    /* Bochs VGA extended MMIO region — OVMF's BochsVga driver may
     * also access MMIO at BAR2 for VBE register access via MMIO. */
    {
        u64 vga_mmio_gpa = VGA_MMIO_GPA;
        unsigned long mmio_pages_count = 16 * 256; /* 16 MB = 4096 pages */
        unsigned long mp;
        for (mp = 0; mp < mmio_pages_count; mp++) {
            u64 gpa = vga_mmio_gpa + (mp << PAGE_SHIFT);
            unsigned int pd_idx = (unsigned int)(gpa >> 30);
            unsigned int pd_e = (unsigned int)((gpa >> 21) & 0x1FF);
            unsigned int pt_e = (unsigned int)((gpa >> 12) & 0x1FF);
            u64 pt_phys;
            struct page *mmio_page;
            if (pd_idx >= NPT_NUM_PD_TABLES) continue;
            if (!npt_pd_tables[pd_idx][pd_e]) continue;
            pt_phys = npt_pd_tables[pd_idx][pd_e] & ~0xFFFULL;
            if (!pt_phys) continue;
            if (((u64 *)phys_to_virt(pt_phys))[pt_e] ==
                (page_to_phys(npt_zero_page) | 0x07ULL)) {
                mmio_page = alloc_page(GFP_KERNEL | __GFP_ZERO | __GFP_NOWARN);
                if (mmio_page)
                    ((u64 *)phys_to_virt(pt_phys))[pt_e] = page_to_phys(mmio_page) | 0x07ULL;
            }
        }
    }

    /* ── Fill holes within guest RAM (below 4G region) ─────────────── */
    {
        u64 zero_hpa = page_to_phys(npt_zero_page);
        /* Only fill holes in the below-4G region (PD tables 0-2).
         * PD table 3 is entirely MMIO (filled above). */
        unsigned int below_4g_pd_end = (unsigned int)(guest_ram_below_4g >> 30);
        unsigned int below_4g_entry_end = (unsigned int)((guest_ram_below_4g >> 21) & 0x1FF);

        for (i = 0; i <= below_4g_pd_end && i < 3; i++) {
            unsigned int j, max_e = (i < below_4g_pd_end) ? 512 : below_4g_entry_end;
            for (j = 0; j < max_e; j++) {
                if (npt_pd_tables[i][j] == 0) {
                    u64 *zpt = (u64 *)get_zeroed_page(GFP_KERNEL);
                    unsigned int k;
                    if (!zpt) continue;
                    for (k = 0; k < 512; k++) zpt[k] = zero_hpa | 0x07ULL;
                    npt_pd_tables[i][j] = virt_to_phys(zpt) | 0x07ULL;
                }
            }
        }
        /* Fill holes in above-4G region if present */
        if (guest_ram_above_4g > 0) {
            unsigned int a4g_pd_start = (unsigned int)(MMIO_GAP_END >> 30);
            u64 a4g_end = MMIO_GAP_END + guest_ram_above_4g;
            unsigned int a4g_pd_end = (unsigned int)(a4g_end >> 30);
            unsigned int a4g_entry_end = (unsigned int)((a4g_end >> 21) & 0x1FF);
            for (i = a4g_pd_start; i <= a4g_pd_end && i < NPT_NUM_PD_TABLES; i++) {
                unsigned int j, max_e = (i < a4g_pd_end) ? 512 : a4g_entry_end;
                unsigned int start_j = (i == a4g_pd_start) ? 0 : 0;
                for (j = start_j; j < max_e; j++) {
                    if (npt_pd_tables[i][j] == 0) {
                        u64 *zpt = (u64 *)get_zeroed_page(GFP_KERNEL);
                        unsigned int k;
                        if (!zpt) continue;
                        for (k = 0; k < 512; k++) zpt[k] = zero_hpa | 0x07ULL;
                        npt_pd_tables[i][j] = virt_to_phys(zpt) | 0x07ULL;
                    }
                }
            }
        }
    }

    /* Wire up PDPT → PD and PML4 → PDPT (only for allocated PD tables) */
    for (i = 0; i < NPT_NUM_PD_TABLES; i++) {
        if (npt_pd_tables[i])
            npt_pdpt[i] = virt_to_phys(npt_pd_tables[i]) | 0x07ULL;
    }
    npt_pml4[0] = virt_to_phys(npt_pdpt) | 0x07ULL;

    pr_info("[BOGGER] NPT ready: %lu pages, below4g=0x%llx–0x%llx, above4g=0x%llx–0x%llx\n",
            guest_nr_pages,
            GUEST_RAM_GPA_BASE, guest_ram_below_4g - 1,
            guest_ram_above_4g > 0 ? MMIO_GAP_END : 0ULL,
            guest_ram_above_4g > 0 ? MMIO_GAP_END + guest_ram_above_4g - 1 : 0ULL);
    return 0;

fail_pt:
    { unsigned long j; for (j = 0; j < i; j++) free_page((unsigned long)npt_pt_pages[j]); }
    i = NPT_NUM_PD_TABLES;
fail_pd:
    { unsigned long j; for (j = 0; j < NPT_NUM_PD_TABLES; j++)
        if (npt_pd_tables[j]) { free_page((unsigned long)npt_pd_tables[j]); npt_pd_tables[j] = NULL; }
    }
    free_page((unsigned long)npt_pdpt); npt_pdpt = NULL;
fail_pml4:
    free_page((unsigned long)npt_pml4); npt_pml4 = NULL;
    return -ENOMEM;
}

/*
 * _npt_free_range_pages() – Walk a GPA range and free individually
 * alloc_page()'d content pages stored in PT entries.
 * Skips entries that still point to the zero page.
 */
static void _npt_free_range_pages(u64 base_gpa, unsigned long count, u64 zero_hpa)
{
    unsigned long n;
    for (n = 0; n < count; n++) {
        u64 gpa = base_gpa + (n << PAGE_SHIFT);
        unsigned int pd_idx = (unsigned int)(gpa >> 30);
        unsigned int pd_e   = (unsigned int)((gpa >> 21) & 0x1FF);
        unsigned int pt_e   = (unsigned int)((gpa >> 12) & 0x1FF);
        u64 pt_phys, pte, page_phys;
        if (pd_idx >= NPT_NUM_PD_TABLES || !npt_pd_tables[pd_idx]) continue;
        if (!(npt_pd_tables[pd_idx][pd_e] & 1)) continue;
        pt_phys = npt_pd_tables[pd_idx][pd_e] & ~0xFFFULL;
        pte = ((u64 *)phys_to_virt(pt_phys))[pt_e];
        if (!(pte & 1)) continue;
        page_phys = pte & ~0xFFFULL;
        if (page_phys != zero_hpa)
            __free_page(pfn_to_page(page_phys >> PAGE_SHIFT));
    }
}

void bogger_npt_free(void)
{
    unsigned long i;

    /* 1. Free NVMe vmap + backing pages */
    if (nvme_regs) { vunmap((void *)nvme_regs); nvme_regs = NULL; }
    for (i = 0; i < 4; i++) {
        if (nvme_bar_pages[i]) { __free_page(nvme_bar_pages[i]); nvme_bar_pages[i] = NULL; }
    }

    /* 2. Free special device pages */
    if (hpet_page)   { __free_page(hpet_page);   hpet_page = NULL;   hpet_regs = NULL; }
    if (lapic_page)  { __free_page(lapic_page);  lapic_page = NULL;  lapic_regs = NULL; }
    if (ioapic_page) { __free_page(ioapic_page); ioapic_page = NULL; ioapic_regs = NULL; }

    /* 3. Free VGA framebuffer + MMIO pages (alloc_page'd into PT entries,
     *    replacing zero-page mappings during init). Must happen BEFORE
     *    we tear down PT pages in step 4. */
    if (npt_zero_page) {
        u64 zero_hpa = page_to_phys(npt_zero_page);
        _npt_free_range_pages(VGA_FB_GPA,   16UL * 256, zero_hpa);  /* 16 MB */
        _npt_free_range_pages(VGA_MMIO_GPA, 16UL * 256, zero_hpa);  /* 16 MB */
    }

    /* 4. Free ALL PT pages by walking PD entries.
     *    This catches both tracked (npt_pt_pages[]) and inline-allocated PTs
     *    (MMIO zero-fill, RAM hole-fill, OVMF flash split).
     *    Guest RAM backing pages are NOT freed here — they are freed by
     *    bogger_guest_ram_free(). We only free the page-table pages. */
    for (i = 0; i < NPT_NUM_PD_TABLES; i++) {
        unsigned int j;
        if (!npt_pd_tables[i]) continue;
        for (j = 0; j < 512; j++) {
            u64 pde = npt_pd_tables[i][j];
            if (!(pde & 1) || (pde & (1ULL << 7))) continue;
            free_page((unsigned long)phys_to_virt(pde & ~0xFFFULL));
        }
    }
    memset(npt_pt_pages, 0, sizeof(npt_pt_pages));
    npt_num_pt_used = 0;

    /* 5. Free PD tables, PDPT, PML4 */
    for (i = 0; i < NPT_NUM_PD_TABLES; i++) {
        if (npt_pd_tables[i]) { free_page((unsigned long)npt_pd_tables[i]); npt_pd_tables[i] = NULL; }
    }
    if (npt_pdpt) { free_page((unsigned long)npt_pdpt); npt_pdpt = NULL; }
    if (npt_pml4) { free_page((unsigned long)npt_pml4); npt_pml4 = NULL; }

    /* 6. Free zero page (must be last — used for comparisons above) */
    if (npt_zero_page) { __free_page(npt_zero_page); npt_zero_page = NULL; }
}

/*
 * bogger_npt_remap_vga_legacy() – Remap GPA 0xA0000–0xBFFFF to HPA 0xA0000
 *
 * When GPU passthrough is active, the GPU owns VGA decode.
 * Legacy VGA memory at physical 0xA0000–0xBFFFF maps to the GPU's framebuffer.
 * We remap these 32 pages from guest RAM to the physical VGA aperture
 * with UC (uncacheable) attributes so UEFI GOP / ATOMBIOS can access them.
 */
void bogger_npt_remap_vga_legacy(void)
{
    unsigned int i;
    /* VGA memory: GPA 0xA0000–0xBFFFF (32 pages, 128 KB)
     * PD table 0, PD entry 0 → PT for GPA 0x00000–0x1FFFFF
     * PT entries 0xA0..0xBF (160..191) */
    u64 pt_phys;

    if (!npt_pd_tables[0] || !npt_pd_tables[0][0])
        return;

    pt_phys = npt_pd_tables[0][0] & ~0xFFFULL;
    if (!pt_phys)
        return;

    for (i = 0xA0; i <= 0xBF; i++) {
        u64 hpa = (u64)i << PAGE_SHIFT;  /* HPA 0xA0000..0xBF000 */
        /* 0x17 = Present | RW | User | PCD (uncacheable) */
        ((u64 *)phys_to_virt(pt_phys))[i] = hpa | 0x17ULL;
    }
    pr_info("[BOGGER] NPT: VGA legacy 0xA0000-0xBFFFF → HPA (UC, 32 pages)\n");
}

