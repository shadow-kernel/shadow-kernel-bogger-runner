/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOGGER_TYPES_H
#define BOGGER_TYPES_H

/*
 * bogger_types.h – Shared types, defines and extern declarations
 *                  for the BOGGER Hypervisor kernel module.
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/fs.h>
#include <linux/delay.h>
#include <linux/kernel_read_file.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/cpufeature.h>
#include <asm/io.h>
#include <asm/svm.h>
#include <asm/page.h>

/* ── Guest GPR state ──────────────────────────────────────────────── */
/* AMD SVM only saves rax/rsp/rip/rflags in the VMCB save area.
 * All other GPRs must be manually saved/restored around VMRUN.       */
struct bogger_guest_gprs {
    u64 rbx;    /* 0x00 */
    u64 rcx;    /* 0x08 */
    u64 rdx;    /* 0x10 */
    u64 rsi;    /* 0x18 */
    u64 rdi;    /* 0x20 */
    u64 rbp;    /* 0x28 */
    u64 r8;     /* 0x30 */
    u64 r9;     /* 0x38 */
    u64 r10;    /* 0x40 */
    u64 r11;    /* 0x48 */
    u64 r12;    /* 0x50 */
    u64 r13;    /* 0x58 */
    u64 r14;    /* 0x60 */
    u64 r15;    /* 0x68 */
    u64 _tmp;   /* 0x70 — scratch space for ASM WRMSR sequence */
};

/* ── SVM exit code for invalid VM entry ───────────────────────────── */
#define BOGGER_SVM_EXIT_INVALID  0xffffffffU

/* ── Bitmap sizes ─────────────────────────────────────────────────── */
#define MSRPM_SIZE  (2 * PAGE_SIZE)   /* 8 KB = 2 pages  */
#define IOPM_SIZE   (3 * PAGE_SIZE)   /* 12 KB = 3 pages */

/* ── Guest RAM layout ─────────────────────────────────────────────── */
#define GUEST_RAM_MAX_SIZE  (16ULL * 1024 * 1024 * 1024)
#define GUEST_RAM_MAX_PAGES (GUEST_RAM_MAX_SIZE >> PAGE_SHIFT)
#define GUEST_RAM_GPA_BASE  0x00000000ULL

/* PCI MMIO hole: 0xC0000000 – 0xFFFFFFFF (3 GB – 4 GB).
 * Guest RAM below this gap is mapped starting at GPA 0.
 * Guest RAM above this gap is mapped starting at GPA 0x100000000. */
#define MMIO_GAP_START      0xC0000000ULL
#define MMIO_GAP_END        0x100000000ULL

/* ── OVMF firmware layout ─────────────────────────────────────────── */
#define OVMF_FLASH_SIZE     (4ULL * 1024 * 1024)
#define OVMF_FLASH_GPA      (0x100000000ULL - OVMF_FLASH_SIZE) /* 0xFFC00000 */

/* ── NPT ──────────────────────────────────────────────────────────── */
/* 512 PD tables → 512 GB guest physical address space.
 * Real GPU BARs can be placed above 32 GB by the PCI bus driver,
 * so we need enough range for identity-mapped passthrough. */
#define NPT_NUM_PD_TABLES 512
#define NPT_MAX_PT_PAGES  (GUEST_RAM_MAX_SIZE / (512ULL * PAGE_SIZE))

/* ══════════════════════════════════════════════════════════════════
 * Extern declarations for shared global state
 * ══════════════════════════════════════════════════════════════════ */

/* Module parameters (defined in bogger_kmod.c) */
extern char *bogger_ovmf_code;
extern char *bogger_ovmf_vars;
extern unsigned int bogger_ram_mb;

/* SVM structures (defined in bogger_svm.c) */
extern bool svm_enabled;
extern void *hsave_area;
extern struct vmcb *g_vmcb;
extern void *msr_bitmap;
extern void *io_bitmap;
extern void *host_save_area;
extern u64   host_save_pa;

/* Guest RAM (defined in bogger_guest_ram.c) */
extern u64 guest_ram_size;
extern struct page **guest_pages;
extern void *guest_ram_virt;
extern unsigned long guest_nr_pages;
extern unsigned long guest_ram_pages_target;

/* Split RAM sizes (computed at NPT init) */
extern u64 guest_ram_below_4g;   /* RAM mapped at GPA 0..MMIO_GAP_START-1 */
extern u64 guest_ram_above_4g;   /* RAM mapped at GPA MMIO_GAP_END.. */

/* NPT (defined in bogger_npt.c) */
extern u64 *npt_pml4;
extern u64 *npt_pdpt;
extern u64 *npt_pd_tables[NPT_NUM_PD_TABLES];
extern u64 *npt_pt_pages[NPT_MAX_PT_PAGES];
extern unsigned long npt_num_pt_used;
extern struct page *npt_zero_page;

/* OVMF (defined in bogger_ovmf.c) */
extern struct page **ovmf_pages;
extern unsigned long ovmf_nr_pages;
extern void *ovmf_virt;

/* NVMe (defined in bogger_nvme.c) */
extern struct file *nvme_host_dev;
extern volatile u32 *nvme_regs;
extern struct page *nvme_bar_pages[4];
extern u32 nvme_cc, nvme_csts, nvme_aqa;
extern u64 nvme_asq_base, nvme_acq_base;

/* HPET (defined in bogger_hpet.c) */
extern struct page *hpet_page;
extern volatile u32 *hpet_regs;
extern struct task_struct *hpet_kthread;
extern volatile bool hpet_kthread_stop;

/* LAPIC (defined in bogger_lapic.c) */
extern struct page *lapic_page;
extern volatile u32 *lapic_regs;
extern u32 lapic_lvt_timer;
extern u64 lapic_timer_start_ns;
extern bool lapic_timer_armed;

/* IOAPIC (defined in bogger_ioapic.c) */
extern struct page *ioapic_page;
extern volatile u32 *ioapic_regs;
extern u32 ioapic_regsel;

/* IO port state (defined in bogger_ioport.c) */
extern u32 pci_config_addr;
extern u8  cmos_index;

/* VGA state (defined in bogger_vga.c) */
struct bogger_vga_state;
extern struct bogger_vga_state vga_state;

/* Guest GPR state (defined in bogger_kmod.c) */
extern struct bogger_guest_gprs guest_gprs;

#endif /* BOGGER_TYPES_H */

