// SPDX-License-Identifier: GPL-2.0
/*
 * bogger_svm.c – AMD SVM helpers: CPU check, enable, HSAVE, VMCB, MSR bitmap
 */
#include "bogger_svm.h"

bool svm_enabled;
void *hsave_area;
struct vmcb *g_vmcb;
void *msr_bitmap;
void *io_bitmap;
void *host_save_area;   /* Page for VMSAVE/VMLOAD of host FS/GS/LDTR/TR */
u64   host_save_pa;     /* Physical address of host_save_area */

/* ═══════════════════════════════════════════════════════════════════ */

int bogger_svm_check_support(void)
{
    u64 vm_cr;
    u32 svm_features;

    if (!boot_cpu_has(X86_FEATURE_SVM)) {
        pr_err("[BOGGER] CPU does not support SVM\n");
        return -ENODEV;
    }

    /* Check MSR_VM_CR.SVMDIS — if set, BIOS has locked out SVM */
    rdmsrq(MSR_VM_CR, vm_cr);
    if (vm_cr & (1ULL << 4)) { /* SVM_DISABLE bit */
        pr_err("[BOGGER] SVM disabled by BIOS (MSR_VM_CR.SVMDIS=1)\n");
        pr_err("[BOGGER] Enable SVM/AMD-V in BIOS settings!\n");
        return -EPERM;
    }

    /* Check NPT (Nested Page Tables) support — required */
    svm_features = cpuid_edx(0x8000000A);
    if (!(svm_features & (1U << 0))) {
        pr_err("[BOGGER] CPU does not support NPT (Nested Page Tables)\n");
        pr_err("[BOGGER] BOGGER requires RVI/NPT — check CPU capabilities\n");
        return -ENODEV;
    }

    pr_info("[BOGGER] SVM check: OK (NPT=1, NRIP=%d, VMCB_CLEAN=%d, FLUSH_ASID=%d)\n",
            !!(svm_features & (1U << 3)),
            !!(svm_features & (1U << 5)),
            !!(svm_features & (1U << 6)));
    return 0;
}

int bogger_svm_enable(void)
{
    u64 efer = native_read_msr(MSR_EFER);
    efer |= EFER_SVME;
    native_write_msr(MSR_EFER, efer);
    pr_info("[BOGGER] EFER.SVME set — SVM enabled\n");
    return 0;
}

int bogger_svm_hsave_setup(void)
{
    u64 phys;
    hsave_area = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
    if (!hsave_area) return -ENOMEM;
    phys = virt_to_phys(hsave_area);
    native_write_msr(MSR_VM_HSAVE_PA, phys);
    pr_info("[BOGGER] VM_HSAVE_PA set to 0x%llx\n", phys);

    /* Allocate page for VMSAVE/VMLOAD (host FS/GS/LDTR/TR/KernelGSBase) */
    host_save_area = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
    if (!host_save_area) {
        free_page((unsigned long)hsave_area);
        hsave_area = NULL;
        return -ENOMEM;
    }
    host_save_pa = virt_to_phys(host_save_area);
    pr_info("[BOGGER] Host save area for VMSAVE/VMLOAD at 0x%llx\n", host_save_pa);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * VMCB setup – Real Mode reset state for OVMF boot
 * ═══════════════════════════════════════════════════════════════════ */
int bogger_vmcb_init(void)
{
    g_vmcb = (struct vmcb *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
    if (!g_vmcb) return -ENOMEM;

    /* IOPM */
    io_bitmap = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(IOPM_SIZE));
    if (!io_bitmap) { free_page((unsigned long)g_vmcb); g_vmcb = NULL; return -ENOMEM; }
    memset(io_bitmap, 0xFF, IOPM_SIZE);

    /* Intercepts */
    g_vmcb->control.intercepts[INTERCEPT_VMRUN / 32]     |= (1U << (INTERCEPT_VMRUN % 32));
    g_vmcb->control.intercepts[INTERCEPT_HLT / 32]       |= (1U << (INTERCEPT_HLT % 32));
    g_vmcb->control.intercepts[INTERCEPT_IOIO_PROT / 32] |= (1U << (INTERCEPT_IOIO_PROT % 32));
    g_vmcb->control.intercepts[INTERCEPT_CPUID / 32]     |= (1U << (INTERCEPT_CPUID % 32));
    g_vmcb->control.intercepts[INTERCEPT_SHUTDOWN / 32]   |= (1U << (INTERCEPT_SHUTDOWN % 32));
    g_vmcb->control.intercepts[INTERCEPT_MSR_PROT / 32]  |= (1U << (INTERCEPT_MSR_PROT % 32));
    g_vmcb->control.intercepts[INTERCEPT_INTR / 32]      |= (1U << (INTERCEPT_INTR % 32));
    g_vmcb->control.intercepts[INTERCEPT_INIT / 32]      |= (1U << (INTERCEPT_INIT % 32));
    g_vmcb->control.intercepts[INTERCEPT_VINTR / 32]     |= (1U << (INTERCEPT_VINTR % 32));

    /* Intercept #MC(18) only for machine check detection.
     * Do NOT intercept #DF(8) — the guest (Windows) handles its own #DFs
     * through IST-based #DF handler (KiDoubleFaultAbort).  This is normal
     * during Windows MM init where nested page faults occur.
     * Do NOT intercept #GP(13) — OVMF needs to handle its own #GPs. */
    g_vmcb->control.intercepts[INTERCEPT_EXCEPTION] =
        (1U << 18);

    if (msr_bitmap)
        g_vmcb->control.msrpm_base_pa = virt_to_phys(msr_bitmap);
    g_vmcb->control.iopm_base_pa = virt_to_phys(io_bitmap);

    g_vmcb->control.asid    = 1;
    g_vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
    g_vmcb->control.int_ctl = (1ULL << 24);
    g_vmcb->control.clean   = 0;
    g_vmcb->control.event_inj = 0;

    /* Enable NRIP Save (virt_ext bit 0) — essential for correct RIP
     * advance on IOIO, MSR, and CPUID exits.  Without this, the
     * processor does NOT populate next_rip or exit_info_2 for IOIO. */
    {
        u32 svm_features; /* CPUID Fn 8000000A_EDX */
        svm_features = cpuid_edx(0x8000000A);
        if (svm_features & (1U << 3)) {
            g_vmcb->control.virt_ext |= (1ULL << 0); /* NRIP Save */
            pr_info("[BOGGER] NRIP Save enabled\n");
        } else {
            pr_warn("[BOGGER] WARNING: CPU does not support NRIP Save!\n");
        }
        /* LBR Virtualization (bit 1) if available */
        if (svm_features & (1U << 1)) {
            g_vmcb->control.virt_ext |= (1ULL << 1);
        }
    }

    /* CS: Big Real Mode */
    g_vmcb->save.cs.selector = 0xF000;
    g_vmcb->save.cs.base     = 0xFFFF0000ULL;
    g_vmcb->save.cs.limit    = 0xFFFFFFFF;
    g_vmcb->save.cs.attrib   = 0x009B;

    /* DS/ES/SS/FS/GS */
    g_vmcb->save.ds.selector = 0;
    g_vmcb->save.ds.base     = 0;
    g_vmcb->save.ds.limit    = 0xFFFFFFFF;
    g_vmcb->save.ds.attrib   = 0x00C3;
    g_vmcb->save.es = g_vmcb->save.ds;
    g_vmcb->save.ss = g_vmcb->save.ds;
    g_vmcb->save.fs = g_vmcb->save.ds;
    g_vmcb->save.gs = g_vmcb->save.ds;

    /* GDT/IDT */
    g_vmcb->save.gdtr.limit = 0xFFFF;
    g_vmcb->save.idtr.limit = 0xFFFF;

    /* LDTR */
    g_vmcb->save.ldtr.attrib = 0x0082;
    g_vmcb->save.ldtr.limit  = 0xFFFF;

    /* TR */
    g_vmcb->save.tr.attrib = 0x008B;
    g_vmcb->save.tr.limit  = 0xFFFF;

    /* Control registers */
    g_vmcb->save.cr0 = 0x00000010ULL;
    g_vmcb->save.efer = EFER_SVME;

    /* RIP at reset vector */
    g_vmcb->save.rip    = 0xFFF0;
    g_vmcb->save.rflags = 0x2;

    /* Debug regs */
    g_vmcb->save.dr7 = 0x400;
    g_vmcb->save.dr6 = 0xFFFF0FF0;
    g_vmcb->save.g_pat = 0x0007040600070406ULL;

    /* NPT */
    g_vmcb->control.nested_ctl = 1ULL;
    g_vmcb->control.nested_cr3 = virt_to_phys(npt_pml4);

    pr_info("[BOGGER] VMCB: Real Mode RIP=0x%llx CS.base=0x%llx nCR3=0x%llx\n",
            g_vmcb->save.rip, g_vmcb->save.cs.base, g_vmcb->control.nested_cr3);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * MSR Permission Map (MSRPM)
 * ═══════════════════════════════════════════════════════════════════ */
static void bogger_msr_bitmap_set(u32 msr, bool rd, bool wr)
{
    u8 *bm = (u8 *)msr_bitmap;
    u32 base_off, msr_off, byte_pos, bit_pos;

    if (msr <= 0x1FFF) {
        base_off = 0x0000; msr_off = msr;
    } else if (msr >= 0xC0000000 && msr <= 0xC0001FFF) {
        base_off = 0x0800; msr_off = msr - 0xC0000000;
    } else if (msr >= 0xC0010000 && msr <= 0xC0011FFF) {
        base_off = 0x1000; msr_off = msr - 0xC0010000;
    } else return;

    byte_pos = base_off + (msr_off * 2) / 8;
    bit_pos  = (msr_off * 2) % 8;
    if (byte_pos >= MSRPM_SIZE) return;

    if (rd) bm[byte_pos] |= (1U << bit_pos);
    if (wr) bm[byte_pos] |= (1U << (bit_pos + 1));
}

int bogger_msr_bitmap_init(void)
{
    u32 m;
    msr_bitmap = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(MSRPM_SIZE));
    if (!msr_bitmap) return -ENOMEM;

    /* Intercept reads and writes for emulated MSRs */
    bogger_msr_bitmap_set(0x1B, true, true);   /* IA32_APIC_BASE */
    bogger_msr_bitmap_set(0x3A, true, true);   /* IA32_FEATURE_CONTROL */
    bogger_msr_bitmap_set(0xCE, true, false);  /* MSR_PLATFORM_INFO (read only) */
    bogger_msr_bitmap_set(0x1A0, true, true);  /* IA32_MISC_ENABLE */
    bogger_msr_bitmap_set(0x1D9, true, true);  /* IA32_DEBUGCTL */
    bogger_msr_bitmap_set(0x277, true, true);  /* IA32_PAT */

    /* MTRR MSRs */
    bogger_msr_bitmap_set(0x2FF, true, true);  /* MTRRdefType */
    for (m = 0x200; m <= 0x20F; m++)
        bogger_msr_bitmap_set(m, true, true);  /* MTRRphysBase/Mask */
    bogger_msr_bitmap_set(0x250, true, true);  /* MTRR_FIX64K */
    bogger_msr_bitmap_set(0x258, true, true);  /* MTRR_FIX16K_0 */
    bogger_msr_bitmap_set(0x259, true, true);  /* MTRR_FIX16K_1 */
    for (m = 0x268; m <= 0x26F; m++)
        bogger_msr_bitmap_set(m, true, true);  /* MTRR_FIX4K */

    /* SYSCALL MSRs */
    bogger_msr_bitmap_set(0xC0000081, true, true); /* STAR */
    bogger_msr_bitmap_set(0xC0000082, true, true); /* LSTAR */
    bogger_msr_bitmap_set(0xC0000083, true, true); /* CSTAR */
    bogger_msr_bitmap_set(0xC0000084, true, true); /* SFMASK */
    bogger_msr_bitmap_set(0xC0000103, true, true); /* TSC_AUX */

    /* Speculation control */
    bogger_msr_bitmap_set(0x48, true, true);   /* IA32_SPEC_CTRL */
    bogger_msr_bitmap_set(0x49, true, true);   /* IA32_PRED_CMD */

    /* VMX capability MSRs (return 0) */
    for (m = 0x480; m <= 0x48F; m++)
        bogger_msr_bitmap_set(m, true, false);

    /* SVM MSRs */
    bogger_msr_bitmap_set(0xC0010114, true, true);
    bogger_msr_bitmap_set(0xC0010117, true, true);

    /* x2APIC MSRs (0x800-0x83F) — must intercept to prevent #GP on hardware.
     * Even with x2APIC hidden from CPUID, some firmware probes these. */
    for (m = 0x800; m <= 0x83F; m++)
        bogger_msr_bitmap_set(m, true, true);

    pr_info("[BOGGER] MSR bitmap configured (stealth)\n");
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * VMCB warm reset — re-enter Real Mode at the reset vector.
 *
 * OVMF typically issues a platform reset (port 0x92 or 0xCF9) early
 * in boot to transition from SEC→PEI phase.  We must reset the
 * guest CPU state back to the initial power-on state while keeping
 * the control area (NPT, IOPM, MSRPM, intercepts) intact.
 * ═══════════════════════════════════════════════════════════════════ */
void bogger_vmcb_reset(struct vmcb *vmcb)
{
    /* CS: Big Real Mode at reset vector */
    vmcb->save.cs.selector = 0xF000;
    vmcb->save.cs.base     = 0xFFFF0000ULL;
    vmcb->save.cs.limit    = 0xFFFFFFFF;
    vmcb->save.cs.attrib   = 0x009B;

    /* DS/ES/SS/FS/GS: flat 4GB segments */
    vmcb->save.ds.selector = 0;
    vmcb->save.ds.base     = 0;
    vmcb->save.ds.limit    = 0xFFFFFFFF;
    vmcb->save.ds.attrib   = 0x00C3;
    vmcb->save.es = vmcb->save.ds;
    vmcb->save.ss = vmcb->save.ds;
    vmcb->save.fs = vmcb->save.ds;
    vmcb->save.gs = vmcb->save.ds;

    /* GDT/IDT */
    vmcb->save.gdtr.base  = 0;
    vmcb->save.gdtr.limit = 0xFFFF;
    vmcb->save.idtr.base  = 0;
    vmcb->save.idtr.limit = 0xFFFF;

    /* LDTR/TR */
    vmcb->save.ldtr.selector = 0;
    vmcb->save.ldtr.base     = 0;
    vmcb->save.ldtr.attrib   = 0x0082;
    vmcb->save.ldtr.limit    = 0xFFFF;
    vmcb->save.tr.selector   = 0;
    vmcb->save.tr.base       = 0;
    vmcb->save.tr.attrib     = 0x008B;
    vmcb->save.tr.limit      = 0xFFFF;

    /* Control registers: PE=0, ET=1 */
    vmcb->save.cr0    = 0x00000010ULL;
    vmcb->save.cr2    = 0;
    vmcb->save.cr3    = 0;
    vmcb->save.cr4    = 0;
    vmcb->save.efer   = EFER_SVME;

    /* RIP at reset vector, clear GPRs */
    vmcb->save.rip    = 0xFFF0;
    vmcb->save.rsp    = 0;
    vmcb->save.rax    = 0;
    vmcb->save.rflags = 0x2;

    /* Clear external GPRs (not stored in VMCB save area) */
    memset(&guest_gprs, 0, sizeof(guest_gprs));

    /* Debug registers */
    vmcb->save.dr7 = 0x400;
    vmcb->save.dr6 = 0xFFFF0FF0;
    vmcb->save.g_pat = 0x0007040600070406ULL;

    /* Flush TLB on next VMRUN */
    vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
    vmcb->control.clean   = 0;
    vmcb->control.event_inj = 0;

    pr_info("[BOGGER] VMCB reset to Real Mode (RIP=0xFFF0)\n");
}
