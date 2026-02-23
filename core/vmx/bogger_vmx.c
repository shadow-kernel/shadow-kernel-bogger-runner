#include "bogger_vmx.h"
#include "bogger_ept.h"

/* MSR intercept bitmap — 4 KB. Hardware requires 4-KB alignment. */
uint8_t g_msr_bitmap[4096] __attribute__((aligned(4096)));

/* Dedicated host stack used after every VM exit */
uint8_t g_host_stack[BOGGER_HOST_STACK_SIZE] __attribute__((aligned(16)));

/*
 * bogger_vmx_check_support – Return 0 if VMX (Intel) or SVM (AMD) is available,
 * non-zero otherwise.
 */
int bogger_vmx_check_support(void)
{
    uint32_t eax, ebx, ecx, edx;

    /* Intel VMX: CPUID leaf 1, ECX bit 5 */
    __asm__ volatile(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(1), "c"(0)
    );
    if (ecx & (1U << 5))
        return 0;   /* VMX supported */

    /* AMD SVM: CPUID leaf 0x80000001, ECX bit 2 */
    __asm__ volatile(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0x80000001), "c"(0)
    );
    if (ecx & (1U << 2))
        return 0;   /* SVM supported */

    return -1;
}

/*
 * bogger_vmx_enable – Set CR4.VMXE so the CPU accepts the VMXON instruction.
 */
int bogger_vmx_enable(void)
{
    uint64_t cr4 = bogger_read_cr4();
    cr4 |= CR4_VMXE;
    bogger_write_cr4(cr4);
    return 0;
}

/*
 * bogger_vmxon – Enter VMX root operation.
 * Writes the VMCS revision identifier into the VMXON region and executes VMXON.
 */
int bogger_vmxon(bogger_vmcs_region_t *vmxon_region)
{
    uint64_t vmx_basic = bogger_rdmsr(MSR_IA32_VMX_BASIC);
    uint32_t revision  = (uint32_t)(vmx_basic & VMX_BASIC_REVISION_MASK);

    vmxon_region->revision_id = revision;

    /* VMXON expects the physical address of the VMXON region.
     * In this bare-metal context the virtual == physical mapping is assumed
     * (identity-mapped initramfs environment). */
    uint64_t phys = (uint64_t)(uintptr_t)vmxon_region;
    uint8_t  cf   = 0;

    __asm__ volatile(
        "vmxon %[pa]\n\t"
        "setc  %[cf]"
        : [cf] "=rm"(cf)
        : [pa] "m"(phys)
        : "cc", "memory"
    );

    return cf ? -1 : 0;
}

/*
 * bogger_setup_vmcs – Allocate and fully initialise a VMCS for a 64-bit guest.
 *
 * guest_rip : entry point inside the guest (e.g. winload.efi entry)
 * guest_rsp : initial guest stack pointer
 */
int bogger_setup_vmcs(bogger_vmcs_region_t *vmcs, uint64_t guest_rip,
                      uint64_t guest_rsp)
{
    uint64_t vmx_basic = bogger_rdmsr(MSR_IA32_VMX_BASIC);
    uint32_t revision  = (uint32_t)(vmx_basic & VMX_BASIC_REVISION_MASK);

    vmcs->revision_id = revision;

    /* Load the VMCS as the current one */
    uint64_t phys = (uint64_t)(uintptr_t)vmcs;
    uint8_t  cf   = 0;

    __asm__ volatile(
        "vmptrld %[pa]\n\t"
        "setc    %[cf]"
        : [cf] "=rm"(cf)
        : [pa] "m"(phys)
        : "cc", "memory"
    );
    if (cf)
        return -1;

    /* ------------------------------------------------------------------ */
    /* Host state                                                          */
    /* ------------------------------------------------------------------ */
    bogger_vmwrite(VMCS_HOST_CR0,    bogger_read_cr0());
    bogger_vmwrite(VMCS_HOST_CR3,    bogger_read_cr3());
    bogger_vmwrite(VMCS_HOST_CR4,    bogger_read_cr4());

    bogger_vmwrite(VMCS_HOST_CS_SEL, bogger_read_cs() & 0xF8);
    bogger_vmwrite(VMCS_HOST_SS_SEL, bogger_read_ss() & 0xF8);
    bogger_vmwrite(VMCS_HOST_DS_SEL, bogger_read_ds() & 0xF8);
    bogger_vmwrite(VMCS_HOST_ES_SEL, bogger_read_es() & 0xF8);
    bogger_vmwrite(VMCS_HOST_FS_SEL, bogger_read_fs() & 0xF8);
    bogger_vmwrite(VMCS_HOST_GS_SEL, bogger_read_gs() & 0xF8);
    bogger_vmwrite(VMCS_HOST_TR_SEL, bogger_read_tr() & 0xF8);

    bogger_vmwrite(VMCS_HOST_GDTR_BASE, bogger_read_gdtr_base());
    bogger_vmwrite(VMCS_HOST_IDTR_BASE, bogger_read_idtr_base());

    /* Host IA32_EFER */
    bogger_vmwrite(VMCS_HOST_IA32_EFER, bogger_rdmsr(MSR_IA32_EFER));

    /* Host RSP points to the top of the dedicated host stack */
    bogger_vmwrite(VMCS_HOST_RSP,
        (uint64_t)(uintptr_t)(g_host_stack + BOGGER_HOST_STACK_SIZE));

    /* Host RIP is the VM-exit dispatch stub (implemented in bogger_supervisor) */
    extern void bogger_vmexit_stub(void);
    bogger_vmwrite(VMCS_HOST_RIP, (uint64_t)(uintptr_t)bogger_vmexit_stub);

    /* ------------------------------------------------------------------ */
    /* Guest state — 64-bit EFI long mode                                 */
    /* ------------------------------------------------------------------ */
    bogger_vmwrite(VMCS_GUEST_CR0,    0x80000031ULL); /* PG, PE, NE, ET */
    bogger_vmwrite(VMCS_GUEST_CR3,    bogger_read_cr3()); /* share host paging */
    bogger_vmwrite(VMCS_GUEST_CR4,    bogger_read_cr4());
    bogger_vmwrite(VMCS_GUEST_DR7,    0x400ULL);

    bogger_vmwrite(VMCS_GUEST_RIP,    guest_rip);
    bogger_vmwrite(VMCS_GUEST_RSP,    guest_rsp);
    bogger_vmwrite(VMCS_GUEST_RFLAGS, 0x2ULL);         /* reserved bit 1 always set */

    /* Guest segment selectors (flat 64-bit) */
    bogger_vmwrite(VMCS_GUEST_CS_SEL,   0x0010);
    bogger_vmwrite(VMCS_GUEST_CS_BASE,  0x0000);
    bogger_vmwrite(VMCS_GUEST_CS_LIMIT, 0xFFFFFFFF);
    bogger_vmwrite(VMCS_GUEST_CS_AR,    0xA09B);       /* 64-bit code, present, DPL=0 */

    bogger_vmwrite(VMCS_GUEST_SS_SEL,   0x0018);
    bogger_vmwrite(VMCS_GUEST_DS_SEL,   0x0020);
    bogger_vmwrite(VMCS_GUEST_ES_SEL,   0x0020);
    bogger_vmwrite(VMCS_GUEST_FS_SEL,   0x0020);
    bogger_vmwrite(VMCS_GUEST_GS_SEL,   0x0020);
    bogger_vmwrite(VMCS_GUEST_LDTR_SEL, 0x0000);
    bogger_vmwrite(VMCS_GUEST_TR_SEL,   bogger_read_tr());

    bogger_vmwrite(VMCS_GUEST_GDTR_BASE,  bogger_read_gdtr_base());
    bogger_vmwrite(VMCS_GUEST_IDTR_BASE,  bogger_read_idtr_base());
    bogger_vmwrite(VMCS_GUEST_GDTR_LIMIT, 0xFFFF);
    bogger_vmwrite(VMCS_GUEST_IDTR_LIMIT, 0xFFFF);

    /* Guest IA32_EFER with LME and LMA set */
    bogger_vmwrite(VMCS_GUEST_IA32_EFER, EFER_LME | EFER_LMA);

    bogger_vmwrite(VMCS_GUEST_ACTIVITY_STATE,   0); /* Active */
    bogger_vmwrite(VMCS_GUEST_INTERRUPTIBILITY, 0);
    bogger_vmwrite(VMCS_GUEST_VMCS_LINK_PTR,    0xFFFFFFFFFFFFFFFFULL);

    /* ------------------------------------------------------------------ */
    /* VM-execution controls                                               */
    /* ------------------------------------------------------------------ */

    /*
     * Primary controls:
     *   - HLT_EXITING  = 0  (no exit on HLT)
     *   - RDTSC_EXITING = 0  (RDTSC runs natively — no timing overhead)
     *   - RDPMC_EXITING = 0
     *   - MSR_BITMAPS  = 1  (use MSR bitmap to selectively intercept)
     *   - SECONDARY_CTLS = 1
     */
    uint32_t pri_ctls = 0;
    pri_ctls |= PRI_PROC_MSR_BITMAPS;
    pri_ctls |= PRI_PROC_SECONDARY_CTLS;
    bogger_vmwrite(VMCS_PRI_PROC_BASED_CTLS, pri_ctls);

    /*
     * Secondary controls:
     *   - ENABLE_EPT        = 1
     *   - RDTSCP            = 1
     *   - INVPCID           = 1
     *   - UNRESTRICTED_GUEST = 0
     */
    uint32_t sec_ctls = 0;
    sec_ctls |= SEC_PROC_ENABLE_EPT;
    sec_ctls |= SEC_PROC_RDTSCP;
    sec_ctls |= SEC_PROC_INVPCID;
    bogger_vmwrite(VMCS_SEC_PROC_BASED_CTLS, sec_ctls);

    /* Initialise EPT and write EPTP into the VMCS */
    bogger_ept_init();

    /* Pin-based controls: minimal */
    bogger_vmwrite(VMCS_PIN_BASED_CTLS, 0);

    /* VM-exit controls: 64-bit host, acknowledge interrupt on exit */
    uint32_t exit_ctls = EXIT_CTL_HOST_ADDR_SPACE | EXIT_CTL_ACK_INTR_ON_EXIT;
    bogger_vmwrite(VMCS_EXIT_CTLS, exit_ctls);

    /* VM-entry controls: IA-32e (64-bit) guest */
    bogger_vmwrite(VMCS_ENTRY_CTLS, ENTRY_CTL_IA32E_GUEST);

    /* Exception bitmap: intercept nothing by default */
    bogger_vmwrite(VMCS_EXCEPTION_BITMAP, 0);

    /* ------------------------------------------------------------------ */
    /* MSR bitmap                                                          */
    /* ------------------------------------------------------------------ */
    /*
     * The 4-KB bitmap layout (Intel SDM Vol 3, §25.6.9):
     *   Bytes 0x000–0x3FF : read-intercept for MSRs 0x00000000–0x00001FFF
     *   Bytes 0x400–0x7FF : read-intercept for MSRs 0xC0000000–0xC0001FFF
     *   Bytes 0x800–0xBFF : write-intercept for MSRs 0x00000000–0x00001FFF
     *   Bytes 0xC00–0xFFF : write-intercept for MSRs 0xC0000000–0xC0001FFF
     *
     * Set intercept bits for:
     *   - 0x3A  (IA32_FEATURE_CONTROL) – read + write
     *   - 0x480–0x48F (IA32_VMX_*) – read
     */
    uint32_t msr;

    /* Read intercept for 0x3A */
    msr = 0x3A;
    g_msr_bitmap[msr / 8] |= (uint8_t)(1U << (msr % 8));
    /* Write intercept for 0x3A */
    g_msr_bitmap[0x800 + msr / 8] |= (uint8_t)(1U << (msr % 8));

    /* Read intercept for 0x480–0x48F */
    for (msr = 0x480; msr <= 0x48F; msr++) {
        g_msr_bitmap[msr / 8] |= (uint8_t)(1U << (msr % 8));
    }

    bogger_vmwrite(VMCS_MSR_BITMAP_ADDR,
        (uint64_t)(uintptr_t)g_msr_bitmap);

    return 0;
}

/*
 * bogger_vmlaunch – Execute VMLAUNCH.  Returns -1 on failure (CF or ZF set).
 */
int bogger_vmlaunch(void)
{
    uint8_t cf = 0, zf = 0;

    __asm__ volatile(
        "vmlaunch\n\t"
        "setc %[cf]\n\t"
        "setz %[zf]"
        : [cf] "=rm"(cf), [zf] "=rm"(zf)
        :
        : "cc", "memory"
    );

    /* If we reach here VMLAUNCH failed */
    if (cf || zf)
        return -1;

    return 0; /* unreachable on success — CPU is in guest */
}

/*
 * bogger_advance_rip – Advance the guest RIP by 'bytes' bytes after emulating
 * an instruction.
 */
void bogger_advance_rip(bogger_guest_state_t *guest, uint32_t bytes)
{
    guest->rip += bytes;
    bogger_vmwrite(VMCS_GUEST_RIP, guest->rip);
}

/*
 * bogger_vmexit_handler – High-level VM-exit dispatcher.
 * Called from bogger_vmexit_stub (assembly trampoline in bogger_supervisor.c).
 */
void bogger_vmexit_handler(bogger_guest_state_t *guest)
{
    extern void bogger_handle_cpuid(bogger_guest_state_t *g);
    extern void bogger_handle_rdmsr(bogger_guest_state_t *g);
    extern void bogger_handle_wrmsr(bogger_guest_state_t *g);
    extern void bogger_handle_ipc_vmcall(bogger_guest_state_t *g);

    uint32_t reason = (uint32_t)bogger_vmread(VMCS_EXIT_REASON) & 0xFFFF;

    /* Refresh guest RIP from VMCS */
    guest->rip = bogger_vmread(VMCS_GUEST_RIP);

    switch (reason) {
    case VMX_EXIT_CPUID:
        bogger_handle_cpuid(guest);
        break;
    case VMX_EXIT_RDMSR:
        bogger_handle_rdmsr(guest);
        break;
    case VMX_EXIT_WRMSR:
        bogger_handle_wrmsr(guest);
        break;
    case VMX_EXIT_VMCALL:
        bogger_handle_ipc_vmcall(guest);
        break;
    default:
        /* Unhandled exits: simply advance past the instruction (best-effort) */
        break;
    }
}
