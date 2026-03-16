// SPDX-License-Identifier: GPL-2.0
/*
 * bogger_guest_ram.c – Guest RAM allocation via individual pages + vmap
 */
#include <linux/sysinfo.h>
#include "bogger_guest_ram.h"

u64            guest_ram_size;
struct page  **guest_pages;
void          *guest_ram_virt;
unsigned long  guest_nr_pages;
unsigned long  guest_ram_pages_target;

#define BOGGER_RAM_WATERMARK_BYTES  (384ULL * 1024 * 1024)
#define BOGGER_RAM_CHECK_INTERVAL   1024
#define BOGGER_RAM_LOG_INTERVAL     (512UL * 1024 * 1024 / PAGE_SIZE)

static void bogger_compute_ram_size(void)
{
    struct sysinfo si;
    u64 free_bytes, target_bytes;
    unsigned long target_mb;

    if (bogger_ram_mb > 0) {
        target_mb = bogger_ram_mb;
        if (target_mb > 8192) target_mb = 8192;
        if (target_mb < 64)   target_mb = 64;
        pr_info("[BOGGER] Guest RAM: user-requested %lu MB\n", target_mb);
    } else {
        si_meminfo(&si);
        free_bytes = (u64)si.freeram * si.mem_unit;
        target_bytes = free_bytes / 2;
        target_mb = (unsigned long)(target_bytes >> 20);
        if (target_mb > 8192) target_mb = 8192;
        if (target_mb < 256)  target_mb = 256;
        pr_info("[BOGGER] Auto-detect: total=%lluMB free=%lluMB → guest=%luMB (50%%)\n",
                (u64)(si.totalram * si.mem_unit) >> 20, free_bytes >> 20, target_mb);
    }

    guest_ram_size = (u64)target_mb * 1024 * 1024;
    guest_ram_pages_target = (unsigned long)(guest_ram_size >> PAGE_SHIFT);
}

int bogger_guest_ram_alloc(void)
{
    unsigned long i, allocated = 0;

    bogger_compute_ram_size();

    guest_pages = vzalloc(guest_ram_pages_target * sizeof(struct page *));
    if (!guest_pages)
        return -ENOMEM;

    for (i = 0; i < guest_ram_pages_target; i++) {
        if ((i % BOGGER_RAM_CHECK_INTERVAL) == 0 && i > 0) {
            struct sysinfo si;
            u64 free_now;
            cond_resched();
            si_meminfo(&si);
            free_now = (u64)si.freeram * si.mem_unit;
            if (free_now < BOGGER_RAM_WATERMARK_BYTES) {
                pr_warn("[BOGGER] Watermark hit: free=%lluMB, stopping at %lu pages (%lu MB)\n",
                        (unsigned long long)(free_now >> 20), i, (i * PAGE_SIZE) >> 20);
                break;
            }
        }
        if ((i % BOGGER_RAM_LOG_INTERVAL) == 0 && i > 0)
            pr_info("[BOGGER] Allocating guest RAM: %lu MB / %lu MB\n",
                    (i * PAGE_SIZE) >> 20,
                    (unsigned long)(guest_ram_pages_target * PAGE_SIZE) >> 20);

        guest_pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO | __GFP_HIGHMEM |
                                     __GFP_NOWARN | __GFP_NORETRY);
        if (!guest_pages[i]) {
            pr_warn("[BOGGER] Page alloc stopped at page %lu/%lu (%lu MB)\n",
                    i, guest_ram_pages_target, (i * PAGE_SIZE) >> 20);
            break;
        }
        allocated++;
    }

    if (allocated < (128UL * 1024 * 1024 / PAGE_SIZE)) {
        pr_err("[BOGGER] Only got %lu MB — need at least 128 MB\n",
               (allocated * PAGE_SIZE) >> 20);
        goto fail;
    }

    guest_nr_pages = allocated;
    guest_ram_size = (u64)allocated << PAGE_SHIFT;

    guest_ram_virt = vmap(guest_pages, guest_nr_pages, VM_MAP, PAGE_KERNEL);
    if (!guest_ram_virt) {
        pr_err("[BOGGER] vmap failed for %lu pages\n", guest_nr_pages);
        goto fail;
    }

    pr_info("[BOGGER] Guest RAM: %llu MB (%lu pages, vmap'd)\n",
            (unsigned long long)(guest_ram_size >> 20), guest_nr_pages);
    return 0;

fail:
    for (i = 0; i < allocated; i++)
        __free_page(guest_pages[i]);
    vfree(guest_pages);
    guest_pages = NULL;
    return -ENOMEM;
}

void bogger_guest_ram_free(void)
{
    unsigned long i;
    if (guest_ram_virt) { vunmap(guest_ram_virt); guest_ram_virt = NULL; }
    if (guest_pages) {
        for (i = 0; i < guest_nr_pages; i++)
            if (guest_pages[i]) __free_page(guest_pages[i]);
        vfree(guest_pages);
        guest_pages = NULL;
    }
}

int guest_ram_write(u64 gpa, const void *src, size_t len)
{
    void *dst = bogger_gpa_to_hva(gpa);
    if (!dst) return -EINVAL;
    /* Verify the entire write fits in the same region */
    if (gpa < guest_ram_below_4g) {
        if (gpa + len > guest_ram_below_4g) return -EINVAL;
    } else if (gpa >= MMIO_GAP_END) {
        u64 off = gpa - MMIO_GAP_END;
        if (off + len > guest_ram_above_4g) return -EINVAL;
    } else {
        return -EINVAL;  /* MMIO gap */
    }
    memcpy(dst, src, len);
    return 0;
}

void *guest_ram_ptr(u64 gpa)
{
    /* Below MMIO gap: GPA 0 → linear in guest_ram_virt */
    if (gpa < guest_ram_below_4g && guest_ram_virt)
        return (u8 *)guest_ram_virt + gpa;
    /* Above MMIO gap: GPA 0x100000000+ → offset past below-4G pages */
    if (gpa >= MMIO_GAP_END && guest_ram_above_4g > 0 && guest_ram_virt) {
        u64 off = gpa - MMIO_GAP_END;
        if (off < guest_ram_above_4g)
            return (u8 *)guest_ram_virt + guest_ram_below_4g + off;
    }
    return NULL;
}

/*
 * bogger_gpa_to_hva() – translate guest physical address → host virtual address.
 *
 * Handles the full guest physical address space:
 *   - OVMF flash region (0xFFC00000–0xFFFFFFFF)
 *   - Guest RAM below MMIO gap (GPA 0 to guest_ram_below_4g)
 *   - Guest RAM above MMIO gap (GPA 0x100000000+)
 *
 * Used by string I/O, MMIO emulation, and other subsystems that need
 * to access guest memory by GPA.
 */
void *bogger_gpa_to_hva(u64 gpa)
{
    /* OVMF flash takes priority (NPT maps ovmf_pages over guest_pages) */
    if (gpa >= OVMF_FLASH_GPA && gpa < OVMF_FLASH_GPA + OVMF_FLASH_SIZE && ovmf_virt)
        return (u8 *)ovmf_virt + (gpa - OVMF_FLASH_GPA);
    /* Guest RAM below MMIO gap: GPA 0 → linear in guest_pages */
    if (gpa < guest_ram_below_4g && guest_ram_virt)
        return (u8 *)guest_ram_virt + gpa;
    /* Guest RAM above MMIO gap: GPA 0x100000000+ → offset past below-4G pages */
    if (gpa >= MMIO_GAP_END && guest_ram_above_4g > 0 && guest_ram_virt) {
        u64 off = gpa - MMIO_GAP_END;
        if (off < guest_ram_above_4g)
            return (u8 *)guest_ram_virt + guest_ram_below_4g + off;
    }
    return NULL;
}

