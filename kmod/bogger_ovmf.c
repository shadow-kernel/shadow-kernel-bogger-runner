// SPDX-License-Identifier: GPL-2.0
/*
 * bogger_ovmf.c – OVMF firmware loader
 */
#include "bogger_ovmf.h"

struct page  **ovmf_pages;
unsigned long  ovmf_nr_pages;
void          *ovmf_virt;
size_t         ovmf_code_size;  /* exported for NPT R/O mapping */

int bogger_load_ovmf(void)
{
    void *code_buf = NULL, *vars_buf = NULL;
    size_t code_size = 0, vars_size = 0;
    ssize_t ret;
    unsigned long i, nr_pages;
    u64 flash_total;

    if (!bogger_ovmf_code || bogger_ovmf_code[0] == '\0') {
        pr_err("[BOGGER] No OVMF_CODE path specified\n");
        return -EINVAL;
    }

    pr_info("[BOGGER] Loading OVMF_CODE: %s\n", bogger_ovmf_code);
    ret = kernel_read_file_from_path(bogger_ovmf_code, 0, &code_buf, INT_MAX, &code_size, READING_FIRMWARE);
    if (ret < 0) { pr_err("[BOGGER] Failed to read OVMF_CODE: %zd\n", ret); return (int)ret; }

    if (bogger_ovmf_vars && bogger_ovmf_vars[0] != '\0') {
        ret = kernel_read_file_from_path(bogger_ovmf_vars, 0, &vars_buf, INT_MAX, &vars_size, READING_FIRMWARE);
        if (ret < 0) { vars_buf = NULL; vars_size = 0; }
    }

    flash_total = OVMF_FLASH_SIZE;
    nr_pages = flash_total >> PAGE_SHIFT;

    ovmf_pages = vzalloc(nr_pages * sizeof(struct page *));
    if (!ovmf_pages) { vfree(code_buf); if (vars_buf) vfree(vars_buf); return -ENOMEM; }

    for (i = 0; i < nr_pages; i++) {
        ovmf_pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
        if (!ovmf_pages[i]) goto fail;
    }
    ovmf_nr_pages = nr_pages;

    ovmf_virt = vmap(ovmf_pages, nr_pages, VM_MAP, PAGE_KERNEL);
    if (!ovmf_virt) goto fail;

    memset(ovmf_virt, 0xFF, flash_total);
    if (vars_buf && vars_size > 0) {
        if (vars_size > flash_total - code_size) vars_size = flash_total - code_size;
        memcpy(ovmf_virt, vars_buf, vars_size);
    }
    { size_t off = flash_total - code_size; memcpy((u8 *)ovmf_virt + off, code_buf, code_size); }
    ovmf_code_size = code_size;  /* save for NPT to set CODE pages read-only */

    vfree(code_buf);
    if (vars_buf) vfree(vars_buf);
    pr_info("[BOGGER] OVMF flash: %llu MB at GPA 0x%llx (%lu pages, code=%zuKB RO)\n",
            (unsigned long long)(flash_total >> 20), OVMF_FLASH_GPA, nr_pages,
            code_size >> 10);
    return 0;

fail:
    for (i = 0; i < nr_pages; i++) if (ovmf_pages[i]) __free_page(ovmf_pages[i]);
    vfree(ovmf_pages); ovmf_pages = NULL;
    vfree(code_buf); if (vars_buf) vfree(vars_buf);
    return -ENOMEM;
}

void bogger_ovmf_free(void)
{
    unsigned long i;
    if (ovmf_virt) { vunmap(ovmf_virt); ovmf_virt = NULL; }
    if (ovmf_pages) {
        for (i = 0; i < ovmf_nr_pages; i++) if (ovmf_pages[i]) __free_page(ovmf_pages[i]);
        vfree(ovmf_pages); ovmf_pages = NULL;
    }
}

