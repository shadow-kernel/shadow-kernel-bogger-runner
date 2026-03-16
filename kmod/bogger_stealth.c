// SPDX-License-Identifier: GPL-2.0
/*
 * bogger_stealth.c – Stealth CPUID & MSR handlers
 *
 * Hides virtualisation from the guest OS (Windows).
 */
#include "bogger_stealth.h"
#include "bogger_lapic.h"

/* LAPIC register offsets used by x2APIC MSR mapping */
#define LAPIC_REG_ID        0x020
#define LAPIC_REG_VERSION   0x030
#define LAPIC_REG_TPR       0x080
#define LAPIC_REG_EOI       0x0B0
#define LAPIC_REG_LDR       0x0D0
#define LAPIC_REG_SVR       0x0F0
#define LAPIC_REG_ESR       0x280
#define LAPIC_REG_ICR_LO    0x300
#define LAPIC_REG_ICR_HI    0x310
#define LAPIC_REG_LVT_TIMER 0x320
#define LAPIC_REG_LVT_LINT0 0x350
#define LAPIC_REG_LVT_LINT1 0x360
#define LAPIC_REG_TIMER_ICR 0x380
#define LAPIC_REG_TIMER_DCR 0x3E0

void bogger_handle_cpuid_stealth(struct vmcb *vmcb, struct bogger_guest_gprs *gprs)
{
    u32 fn  = (u32)vmcb->save.rax;
    u32 sub = (u32)gprs->rcx;
    u32 out_eax, out_ebx, out_ecx, out_edx;

    __asm__ volatile("cpuid"
        : "=a"(out_eax), "=b"(out_ebx), "=c"(out_ecx), "=d"(out_edx)
        : "a"(fn), "c"(sub));

    switch (fn) {
    case 0x00000000:
        /* Ensure max standard leaf >= 0x16 for TSC info */
        if (out_eax < 0x16)
            out_eax = 0x16;
        break;
    case 0x00000001:
        out_ecx &= ~(1U << 31);  /* clear Hypervisor Present */
        out_ecx &= ~(1U << 5);   /* clear VMX */
        out_ecx &= ~(1U << 21);  /* NO x2APIC — we emulate xAPIC MMIO only */
        out_ecx &= ~(1U << 24);  /* NO TSC-Deadline — not emulated */
        out_edx |=  (1U << 9);   /* APIC on-chip */
        out_ecx |=  (1U << 0);   /* SSE3 */
        out_ecx |=  (1U << 9);   /* SSSE3 */
        out_ecx &= ~(1U << 26);  /* NO XSAVE — not fully emulated */
        out_ecx &= ~(1U << 27);  /* NO OSXSAVE — follows XSAVE */
        out_ecx &= ~(1U << 28);  /* NO AVX — requires XSAVE */
        out_edx |=  (1U << 0);   /* FPU */
        out_edx |=  (1U << 4);   /* TSC */
        out_edx |=  (1U << 5);   /* MSR */
        out_edx |=  (1U << 6);   /* PAE */
        out_edx |=  (1U << 13);  /* PGE */
        out_edx |=  (1U << 25);  /* SSE */
        out_edx |=  (1U << 26);  /* SSE2 */
        /* Fix EBX: APIC ID = 0, max logical proc = 1, keep CLFLUSH size */
        out_ebx = (0U << 24) | (1U << 16) | (out_ebx & 0xFF00) | (out_ebx & 0xFF);
        break;
    case 0x00000006:
        /* Thermal and Power Management: report ARAT (Always Running APIC Timer) */
        out_eax |= (1U << 2);  /* ARAT */
        break;
    case 0x00000007:
        if (sub == 0) {
            out_ebx &= ~(1U << 2);   /* SGX */
            out_ecx &= ~(1U << 13);  /* TME */
            out_ebx &= ~(1U << 5);   /* NO AVX2 — requires AVX/XSAVE */
            out_ebx &= ~(1U << 16);  /* NO AVX512F */
        }
        break;
    case 0x0000000D:
        /* XSAVE state enumeration: report only legacy X87+SSE (512 bytes).
         * Sub-leaf 0: XCR0 supported bits = 0x3 (X87+SSE)
         * Sub-leaf 1: no XSAVEOPT/XSAVEC/etc. */
        if (sub == 0) {
            out_eax = 0x3;  /* X87 + SSE */
            out_ebx = 512;  /* FXSAVE area size */
            out_ecx = 512;  /* max save area size */
            out_edx = 0;
        } else {
            out_eax = out_ebx = out_ecx = out_edx = 0;
        }
        break;
    case 0x0000000B:
        /* Extended Topology: report 1 logical processor */
        if (sub == 0) {
            out_eax = 0; out_ebx = 1; out_ecx = 0x100; out_edx = 0;
        } else if (sub == 1) {
            out_eax = 0; out_ebx = 1; out_ecx = 0x201; out_edx = 0;
        } else {
            out_eax = out_ebx = 0; out_ecx = sub; out_edx = 0;
        }
        break;
    case 0x00000015:
        /* TSC/Core Crystal Clock: 25 MHz crystal, 100:1 ratio = 2.5 GHz TSC
         * This helps OVMF calibrate timers without needing PIT */
        out_eax = 1;            /* denominator */
        out_ebx = 100;          /* numerator */
        out_ecx = 25000000;     /* crystal freq: 25 MHz */
        break;
    case 0x00000016:
        /* Processor Frequency Information:
         * EAX = Base frequency (MHz)
         * EBX = Max frequency (MHz)
         * ECX = Bus/Reference frequency (MHz) */
        out_eax = 3700;         /* 3.7 GHz base */
        out_ebx = 4600;         /* 4.6 GHz boost */
        out_ecx = 100;          /* 100 MHz bus */
        break;
    case 0x0000001F:
        /* V2 Extended Topology Enumeration — terminate immediately */
        out_eax = 0; out_ebx = 0; out_ecx = sub; out_edx = 0;
        break;
    case 0x40000000 ... 0x400000FF:
        out_eax = out_ebx = out_ecx = out_edx = 0;
        break;
    case 0x8000001E:
        /* AMD Extended APIC ID / Topology — single core, node 0 */
        out_eax = 0;             /* Extended APIC ID = 0 */
        out_ebx = 0x00000100;    /* ComputeUnitId=0, CoresPerCU=1 */
        out_ecx = 0;             /* NodeId=0 */
        out_edx = 0;
        break;
    case 0x8000001F:
        /* AMD Memory Encryption — report NONE.
         * If we pass through the host value, OVMF detects SEV/SME
         * and activates C-bit encryption in page tables, causing
         * NPT faults and broken fw_cfg PIO reads. */
        out_eax = 0;  /* No SME/SEV/SEV-ES/SEV-SNP */
        out_ebx = 0;  /* No C-bit position */
        out_ecx = 0;  /* No encrypted guests */
        out_edx = 0;  /* Min ASID = 0 */
        break;
    case 0x80000001:
        out_ecx &= ~(1U << 2);  /* hide SVM */
        out_ecx &= ~(1U << 3);  /* hide SVM lock */
        break;
    case 0x80000002:
    case 0x80000003:
    case 0x80000004:
        /* Processor Brand String — pass through from host CPU.
         * These 3 leaves return the 48-byte ASCII brand string.
         * By passing through, Windows sees the real CPU name. */
        break;
    case 0x80000008:
        /* Physical/Virtual address sizes: pass through address bits from host,
         * but fix core count = 1 and APIC ID size = 0 (single core guest) */
        out_ecx = 0;  /* NC=0 (1 core), ApicIdSize=0 */
        break;
    default:
        break;
    }

    vmcb->save.rax = out_eax;
    gprs->rbx      = out_ebx;
    gprs->rcx      = out_ecx;
    gprs->rdx      = out_edx;
    /* CPUID is always 2 bytes (0F A2).  Use next_rip if available. */
    if (vmcb->control.next_rip > vmcb->save.rip)
        vmcb->save.rip = vmcb->control.next_rip;
    else
        vmcb->save.rip += 2;
}

/* ── Static storage for guest MTRR state ─────────────────────────── */
static u64 guest_mtrr_def_type;
static u64 guest_mtrr_phys_base[16];
static u64 guest_mtrr_phys_mask[16];
static u64 guest_mtrr_fix64k;
static u64 guest_mtrr_fix16k[2];
static u64 guest_mtrr_fix4k[8];
static u64 guest_misc_enable = (1ULL << 0) | (1ULL << 11); /* FPU + BTS */
static u64 guest_pat = 0x0007040600070406ULL;
static u64 guest_tsc_aux;
static u64 guest_apic_base = 0xFEE00000ULL | (1ULL << 11) | (1ULL << 8);

void bogger_handle_rdmsr_stealth(struct vmcb *vmcb, struct bogger_guest_gprs *gprs)
{
    u32 msr = (u32)gprs->rcx;
    u64 value = 0;

    switch (msr) {
    case 0x1B:  /* IA32_APIC_BASE */
        value = guest_apic_base;
        break;
    case 0x10:  /* IA32_TIME_STAMP_COUNTER */
        rdmsrq(msr, value);
        break;
    case 0x1A0: /* IA32_MISC_ENABLE */
        value = guest_misc_enable;
        break;
    case 0x277: /* IA32_PAT */
        value = guest_pat;
        break;
    case 0x2FF: /* MTRRdefType */
        value = guest_mtrr_def_type;
        break;
    case 0x200 ... 0x20F: { /* MTRRphysBase/Mask */
        int idx = (msr - 0x200);
        if (idx < 16) value = (idx & 1) ? guest_mtrr_phys_mask[idx/2] : guest_mtrr_phys_base[idx/2];
        break;
    }
    case 0x250: value = guest_mtrr_fix64k; break;
    case 0x258: value = guest_mtrr_fix16k[0]; break;
    case 0x259: value = guest_mtrr_fix16k[1]; break;
    case 0x268 ... 0x26F: value = guest_mtrr_fix4k[msr - 0x268]; break;

    case 0xC0000080: /* EFER — return guest EFER from VMCB but hide SVME */
        value = vmcb->save.efer & ~(1ULL << 12); /* strip SVME */
        break;
    case 0xC0000081: value = vmcb->save.star; break;
    case 0xC0000082: value = vmcb->save.lstar; break;
    case 0xC0000083: value = vmcb->save.cstar; break;
    case 0xC0000084: value = vmcb->save.sfmask; break;
    case 0xC0000102: value = vmcb->save.kernel_gs_base; break;
    case 0xC0000103: value = guest_tsc_aux; break;
    case 0x174: value = vmcb->save.sysenter_cs; break;
    case 0x175: value = vmcb->save.sysenter_esp; break;
    case 0x176: value = vmcb->save.sysenter_eip; break;

    case 0x3A:           value = 0x1; break;  /* IA32_FEATURE_CONTROL */
    case 0x480 ... 0x48F: value = 0; break;   /* VMX capability MSRs */
    case 0xC0010114:     value = 0; break;     /* VM_CR */
    case 0xC0010117:     value = 0; break;     /* SVM_KEY */

    /* x2APIC MSRs (0x800-0x83F) — route to xAPIC MMIO emulation */
    case 0x802:  /* x2APIC ID */
        value = (lapic_regs) ? ((u64)lapic_regs[LAPIC_REG_ID / 4] >> 24) : 0;
        break;
    case 0x803:  /* x2APIC Version */
        value = (lapic_regs) ? lapic_regs[LAPIC_REG_VERSION / 4] : 0x00050014;
        break;
    case 0x808:  /* x2APIC TPR */
        value = (lapic_regs) ? (lapic_regs[LAPIC_REG_TPR / 4] & 0xFF) : 0;
        break;
    case 0x80A:  /* x2APIC PPR */
        value = 0; break;
    case 0x80D:  /* x2APIC LDR */
        value = (lapic_regs) ? lapic_regs[LAPIC_REG_LDR / 4] : 0;
        break;
    case 0x80F:  /* x2APIC SVR */
        value = (lapic_regs) ? lapic_regs[LAPIC_REG_SVR / 4] : 0x1FF;
        break;
    case 0x828:  /* x2APIC ESR */
        value = 0; break;
    case 0x830:  /* x2APIC ICR (64-bit in x2APIC mode) */
        value = (lapic_regs) ?
            ((u64)lapic_regs[LAPIC_REG_ICR_HI / 4] << 32 | lapic_regs[LAPIC_REG_ICR_LO / 4]) : 0;
        break;
    case 0x832:  /* x2APIC LVT Timer */
        value = lapic_lvt_timer;
        break;
    case 0x838:  /* x2APIC ICR */
        value = (lapic_regs) ? lapic_regs[LAPIC_REG_TIMER_ICR / 4] : 0;
        break;
    case 0x839:  /* x2APIC CCR */
        value = lapic_read_ccr();
        break;
    case 0x83E:  /* x2APIC DCR */
        value = (lapic_regs) ? lapic_regs[LAPIC_REG_TIMER_DCR / 4] : 0;
        break;
    case 0x800: case 0x801: case 0x804 ... 0x807:
    case 0x809: case 0x80B: case 0x80C: case 0x80E:
    case 0x810 ... 0x827: case 0x829 ... 0x82F:
    case 0x831: case 0x833 ... 0x837: case 0x83A ... 0x83D:
    case 0x83F:
        value = 0; /* other x2APIC MSRs: return 0 */
        break;
    case 0x1D9:          value = 0; break;     /* IA32_DEBUGCTL */
    case 0xCE:           /* MSR_PLATFORM_INFO: report 100 MHz bus */
        value = (25ULL << 8); /* max non-turbo ratio */
        break;
    case 0x48:  /* IA32_SPEC_CTRL */
    case 0x49:  /* IA32_PRED_CMD */
        value = 0;
        break;
    default:
        /* Safe pass-through for other MSRs */
        if (rdmsrq_safe(msr, &value)) {
            value = 0; /* return 0 on #GP */
        }
        break;
    }

    vmcb->save.rax  = (u32)(value & 0xFFFFFFFF);
    gprs->rdx       = (u32)(value >> 32);
    if (vmcb->control.next_rip > vmcb->save.rip)
        vmcb->save.rip = vmcb->control.next_rip;
    else
        vmcb->save.rip += 2;
}

void bogger_handle_wrmsr_stealth(struct vmcb *vmcb, struct bogger_guest_gprs *gprs)
{
    u32 msr = (u32)gprs->rcx;
    u64 value = ((u64)(u32)gprs->rdx << 32) | (u32)vmcb->save.rax;

    switch (msr) {
    case 0x1B:   /* IA32_APIC_BASE */
        guest_apic_base = value;
        break;
    case 0x1A0: /* IA32_MISC_ENABLE */
        guest_misc_enable = value;
        break;
    case 0x277: /* IA32_PAT */
        guest_pat = value;
        vmcb->save.g_pat = value;
        break;
    case 0x2FF: /* MTRRdefType */
        guest_mtrr_def_type = value;
        break;
    case 0x200 ... 0x20F: {
        int idx = (msr - 0x200);
        if (idx < 16) {
            if (idx & 1) guest_mtrr_phys_mask[idx/2] = value;
            else guest_mtrr_phys_base[idx/2] = value;
        }
        break;
    }
    case 0x250: guest_mtrr_fix64k = value; break;
    case 0x258: guest_mtrr_fix16k[0] = value; break;
    case 0x259: guest_mtrr_fix16k[1] = value; break;
    case 0x268 ... 0x26F: guest_mtrr_fix4k[msr - 0x268] = value; break;

    case 0xC0000080: /* EFER — update VMCB save area, always keep SVME set */
        vmcb->save.efer = (value & ~(1ULL << 12)) | (1ULL << 12); /* force SVME on */
        break;
    case 0xC0000081: vmcb->save.star = value; break;
    case 0xC0000082: vmcb->save.lstar = value; break;
    case 0xC0000083: vmcb->save.cstar = value; break;
    case 0xC0000084: vmcb->save.sfmask = value; break;
    case 0xC0000102: vmcb->save.kernel_gs_base = value; break;
    case 0xC0000103: guest_tsc_aux = value; break;
    case 0x174: vmcb->save.sysenter_cs = value; break;
    case 0x175: vmcb->save.sysenter_esp = value; break;
    case 0x176: vmcb->save.sysenter_eip = value; break;

    case 0x10:  /* IA32_TIME_STAMP_COUNTER */
        wrmsr_safe(msr, (u32)value, (u32)(value >> 32));
        break;
    case 0x3A:       /* IA32_FEATURE_CONTROL */
    case 0xC0010114: /* VM_CR */
    case 0xC0010117: /* SVM_KEY */
    case 0x1D9:      /* IA32_DEBUGCTL */
    case 0x48:       /* IA32_SPEC_CTRL */
    case 0x49:       /* IA32_PRED_CMD */
        break;  /* silently drop */

    /* x2APIC MSR writes — route to xAPIC emulation */
    case 0x808:  /* x2APIC TPR */
        if (lapic_regs) lapic_mmio_write(LAPIC_REG_TPR, (u32)value & 0xFF);
        break;
    case 0x80B:  /* x2APIC EOI */
        if (lapic_regs) lapic_mmio_write(LAPIC_REG_EOI, 0);
        break;
    case 0x80F:  /* x2APIC SVR */
        if (lapic_regs) lapic_mmio_write(LAPIC_REG_SVR, (u32)value);
        break;
    case 0x828:  /* x2APIC ESR */
        if (lapic_regs) lapic_mmio_write(LAPIC_REG_ESR, 0);
        break;
    case 0x830:  /* x2APIC ICR (64-bit write) */
        if (lapic_regs) {
            lapic_mmio_write(LAPIC_REG_ICR_HI, (u32)(value >> 32));
            lapic_mmio_write(LAPIC_REG_ICR_LO, (u32)value);
        }
        break;
    case 0x832:  /* x2APIC LVT Timer */
        if (lapic_regs) lapic_mmio_write(LAPIC_REG_LVT_TIMER, (u32)value);
        break;
    case 0x835:  /* x2APIC LVT LINT0 */
        if (lapic_regs) lapic_mmio_write(LAPIC_REG_LVT_LINT0, (u32)value);
        break;
    case 0x836:  /* x2APIC LVT LINT1 */
        if (lapic_regs) lapic_mmio_write(LAPIC_REG_LVT_LINT1, (u32)value);
        break;
    case 0x838:  /* x2APIC Timer ICR */
        if (lapic_regs) lapic_mmio_write(LAPIC_REG_TIMER_ICR, (u32)value);
        break;
    case 0x83E:  /* x2APIC Timer DCR */
        if (lapic_regs) lapic_mmio_write(LAPIC_REG_TIMER_DCR, (u32)value);
        break;
    case 0x800 ... 0x807: case 0x809: case 0x80A:
    case 0x80C ... 0x80E: case 0x810 ... 0x827:
    case 0x829 ... 0x82F: case 0x831: case 0x833: case 0x834:
    case 0x837: case 0x839 ... 0x83D: case 0x83F:
        break;  /* other x2APIC MSRs: silently drop */

    default:
        /* Try safe write, ignore errors */
        wrmsr_safe(msr, (u32)value, (u32)(value >> 32));
        break;
    }
    if (vmcb->control.next_rip > vmcb->save.rip)
        vmcb->save.rip = vmcb->control.next_rip;
    else
        vmcb->save.rip += 2;
}




