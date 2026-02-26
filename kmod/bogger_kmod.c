#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/cpufeature.h>
#include <asm/io.h>
#include <asm/svm.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BOGGER");
MODULE_DESCRIPTION("BOGGER Hypervisor Kernel Module");

static char *bogger_efi = "";
module_param(bogger_efi, charp, 0444);
MODULE_PARM_DESC(bogger_efi, "Path to Windows EFI binary (e.g. /EFI/Microsoft/Boot/bootmgfw.efi)");

/* Tracks whether EFER.SVME was set so exit() can clear it */
static bool svm_enabled;

/* 4 KB Host Save Area — must be page-aligned */
static void *hsave_area;

/* 4 KB VMCB — must be page-aligned */
static struct vmcb *g_vmcb;

/* SVM_EXIT_INVALID is not exported in uapi headers; define it here */
#define BOGGER_SVM_EXIT_INVALID  0xffffffffU

/* Nested Page Table (NPT) top-level PML4 and PDPT pages */
static u64 *npt_pml4;
static u64 *npt_pdpt;

/* Allocate a minimal 4-level NPT identity map covering the first 4 GB
 * using four 1 GB huge-page PDPT entries.
 */
static int bogger_npt_init(void)
{
    npt_pml4 = (u64 *)get_zeroed_page(GFP_KERNEL);
    if (!npt_pml4)
        return -ENOMEM;

    npt_pdpt = (u64 *)get_zeroed_page(GFP_KERNEL);
    if (!npt_pdpt) {
        free_page((unsigned long)npt_pml4);
        npt_pml4 = NULL;
        return -ENOMEM;
    }

    /* Four 1 GB identity-map entries: P+RW+US+PS */
    npt_pdpt[0] = 0x000000000ULL | 0x87ULL;
    npt_pdpt[1] = 0x040000000ULL | 0x87ULL;
    npt_pdpt[2] = 0x080000000ULL | 0x87ULL;
    npt_pdpt[3] = 0x0C0000000ULL | 0x87ULL;

    /* PML4[0] -> PDPT: P+RW+US */
    npt_pml4[0] = virt_to_phys(npt_pdpt) | 0x07ULL;

    return 0;
}

static void bogger_npt_free(void)
{
    if (npt_pdpt) {
        free_page((unsigned long)npt_pdpt);
        npt_pdpt = NULL;
    }
    if (npt_pml4) {
        free_page((unsigned long)npt_pml4);
        npt_pml4 = NULL;
    }
}

static int bogger_svm_check_support(void)
{
    /* CPUID Fn8000_000A: SVM feature bits */
    if (!boot_cpu_has(X86_FEATURE_SVM)) {
        pr_err("[BOGGER] CPU does not support SVM\n");
        return -ENODEV;
    }
    return 0;
}

static int bogger_svm_enable(void)
{
    u64 efer = native_read_msr(MSR_EFER);
    efer |= EFER_SVME;
    native_write_msr(MSR_EFER, efer);
    pr_info("[BOGGER] EFER.SVME set — SVM enabled\n");
    return 0;
}

static int bogger_svm_hsave_setup(void)
{
    u64 phys;

    hsave_area = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (!hsave_area)
        return -ENOMEM;

    phys = virt_to_phys(hsave_area);
    native_write_msr(MSR_VM_HSAVE_PA, phys);
    pr_info("[BOGGER] VM_HSAVE_PA set to 0x%llx\n", phys);
    return 0;
}

static int bogger_vmcb_init(void)
{
    u64 efer;

    g_vmcb = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (!g_vmcb)
        return -ENOMEM;

    /* Intercept HLT, IOIO, VMRUN and CPUID instructions */
    g_vmcb->control.intercepts[INTERCEPT_HLT / 32]       |=
        (1U << (INTERCEPT_HLT % 32));
    g_vmcb->control.intercepts[INTERCEPT_IOIO_PROT / 32] |=
        (1U << (INTERCEPT_IOIO_PROT % 32));
    g_vmcb->control.intercepts[INTERCEPT_VMRUN / 32]     |=
        (1U << (INTERCEPT_VMRUN % 32));
    g_vmcb->control.intercepts[INTERCEPT_CPUID / 32]     |=
        (1U << (INTERCEPT_CPUID % 32));

    /* Guest ASID must be non-zero; 1 is the first valid ASID */
    g_vmcb->control.asid = 1;

    /* Flush all ASID TLB entries on VMRUN */
    g_vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;

    /* CS: x86 reset-vector segment (selector=0xF000, base=0xFFFF0000) */
    g_vmcb->save.cs.selector = 0xF000;
    g_vmcb->save.cs.base     = 0xFFFF0000ULL;
    g_vmcb->save.cs.limit    = 0xFFFF;
    g_vmcb->save.cs.attrib   = 0x9B;   /* P=1, S=1, Type=0xB (exec/read/accessed) */

    /* Data segments: base=0, limit=0xFFFF, present+data+accessed */
    g_vmcb->save.ds.limit = 0xFFFF;    g_vmcb->save.ds.attrib = 0x93;
    g_vmcb->save.es.limit = 0xFFFF;    g_vmcb->save.es.attrib = 0x93;
    g_vmcb->save.ss.limit = 0xFFFF;    g_vmcb->save.ss.attrib = 0x93;
    g_vmcb->save.fs.limit = 0xFFFF;    g_vmcb->save.fs.attrib = 0x93;
    g_vmcb->save.gs.limit = 0xFFFF;    g_vmcb->save.gs.attrib = 0x93;

    /* GDTR/IDTR: base=0, limit=0xFFFF */
    g_vmcb->save.gdtr.base  = 0;
    g_vmcb->save.gdtr.limit = 0xFFFF;
    g_vmcb->save.idtr.base  = 0;
    g_vmcb->save.idtr.limit = 0xFFFF;

    /* LDTR: present LDT descriptor */
    g_vmcb->save.ldtr.attrib = 0x82;
    g_vmcb->save.ldtr.limit  = 0xFFFF;

    /* TR: present busy TSS descriptor */
    g_vmcb->save.tr.attrib = 0x83;
    g_vmcb->save.tr.limit  = 0xFFFF;

    /* RIP=0xFFF0, RFLAGS=0x2 (reserved bit always set), CR0=0x10 (ET, real mode) */
    g_vmcb->save.rip    = 0xFFF0;
    g_vmcb->save.rflags = 0x2;
    g_vmcb->save.cr0    = 0x10;
    g_vmcb->save.cr4    = 0;
    g_vmcb->save.dr7    = 0x400;
    g_vmcb->save.dr6    = 0xFFFF0FF0;

    /* EFER in the VMCB save area must have SVME set */
    efer = native_read_msr(MSR_EFER);
    g_vmcb->save.efer = efer | EFER_SVME;

    pr_info("[BOGGER] VMCB ready CR0=0x%llx EFER=0x%llx RIP=0x%llx\n",
            g_vmcb->save.cr0, g_vmcb->save.efer, g_vmcb->save.rip);

    /* Activate Nested Paging (NPT/RVI) */
    g_vmcb->control.nested_ctl = 1ULL;
    g_vmcb->control.nested_cr3 = virt_to_phys(npt_pml4);
    pr_info("[BOGGER] NPT enabled nCR3=0x%llx\n", g_vmcb->control.nested_cr3);

    return 0;
}

static void bogger_vmrun_loop(void)
{
    u64 phys = virt_to_phys(g_vmcb);
    u32 exit_code;
    int exits = 0;

    pr_info("[BOGGER] Attempting VMRUN\n");
    pr_info("[BOGGER] Entering VMRUN loop\n");

    while (true) {
        __asm__ volatile(
            "vmload %[pa]\n\t"
            "vmrun  %[pa]\n\t"
            "vmsave %[pa]\n\t"
            :
            : [pa] "a"(phys)
            : "memory"
        );

        exit_code = g_vmcb->control.exit_code;
        exits++;

        switch (exit_code) {
        case BOGGER_SVM_EXIT_INVALID:
            pr_err("[BOGGER] VMRUN exit=0x%x (INVALID) RIP=0x%llx\n",
                   exit_code, g_vmcb->save.rip);
            goto done;

        case SVM_EXIT_HLT:
            pr_info("[BOGGER] VMRUN exit=0x%x (HLT) RIP=0x%llx\n",
                    exit_code, g_vmcb->save.rip);
            goto done;

        case SVM_EXIT_IOIO:
            pr_debug("[BOGGER] IOIO port=0x%llx RIP=0x%llx -> 0x%llx\n",
                     (g_vmcb->control.exit_info_1 >> 16) & 0xFFFFULL,
                     g_vmcb->save.rip,
                     g_vmcb->control.exit_info_2);
            /* Advance RIP using exit_info_2 (next sequential instruction) */
            g_vmcb->save.rip = g_vmcb->control.exit_info_2;
            break;

        case SVM_EXIT_INIT:
            pr_info("[BOGGER] VMRUN exit=0x%x (INIT) RIP=0x%llx\n",
                    exit_code, g_vmcb->save.rip);
            goto done;

        case SVM_EXIT_SHUTDOWN:
            pr_info("[BOGGER] VMRUN exit=0x%x (SHUTDOWN) RIP=0x%llx\n",
                    exit_code, g_vmcb->save.rip);
            goto done;

        case SVM_EXIT_NPF:
            pr_info("[BOGGER] VMRUN exit=0x%x (NPF) RIP=0x%llx\n",
                    exit_code, g_vmcb->save.rip);
            goto done;

        case SVM_EXIT_CPUID: {
            u32 eax = (u32)g_vmcb->save.rax;
            u32 ebx = 0, ecx = (u32)g_vmcb->save.rcx, edx = 0;

            native_cpuid(&eax, &ebx, &ecx, &edx);
            g_vmcb->save.rax = eax;
            g_vmcb->save.rbx = ebx;
            g_vmcb->save.rcx = ecx;
            g_vmcb->save.rdx = edx;
            g_vmcb->save.rip += 2;  /* CPUID is 2 bytes: 0F A2 */
            break;
        }

        default:
            pr_warn("[BOGGER] Unhandled exit=0x%x RIP=0x%llx\n",
                    exit_code, g_vmcb->save.rip);
            /* Advance RIP via exit_info_2 if it holds a valid next RIP,
             * otherwise stop to avoid jumping to an invalid address. */
            if (g_vmcb->control.exit_info_2 != 0 &&
                g_vmcb->control.exit_info_2 > g_vmcb->save.rip)
                g_vmcb->save.rip = g_vmcb->control.exit_info_2;
            else
                goto done;
            break;
        }
    }

done:
    pr_info("[BOGGER] Loop done exits=%d\n", exits);
}

static int __init bogger_kmod_init(void)
{
    int ret;

    pr_info("[BOGGER] Kernel module loaded\n");
    pr_info("[BOGGER] EFI target: %s\n", bogger_efi);

    /* 1. Verify CPU SVM support */
    ret = bogger_svm_check_support();
    if (ret)
        return ret;

    /* 2. Set EFER.SVME */
    ret = bogger_svm_enable();
    if (ret)
        return ret;
    svm_enabled = true;

    /* 3. Allocate and register Host Save Area */
    ret = bogger_svm_hsave_setup();
    if (ret) {
        pr_err("[BOGGER] Host Save Area setup failed (%d)\n", ret);
        goto err_disable_svm;
    }

    /* 4. Allocate Nested Page Tables */
    ret = bogger_npt_init();
    if (ret) {
        pr_err("[BOGGER] NPT init failed (%d)\n", ret);
        goto err_free_hsave;
    }

    /* 5. Allocate and initialise VMCB */
    ret = bogger_vmcb_init();
    if (ret) {
        pr_err("[BOGGER] VMCB init failed (%d)\n", ret);
        goto err_free_npt;
    }

    /* 6. VMRUN loop */
    bogger_vmrun_loop();

    return 0;

err_free_npt:
    bogger_npt_free();
err_free_hsave:
    kfree(hsave_area);
    hsave_area = NULL;
err_disable_svm:
    {
        u64 efer = native_read_msr(MSR_EFER);
        efer &= ~EFER_SVME;
        native_write_msr(MSR_EFER, efer);
        svm_enabled = false;
    }
    return ret;
}

static void __exit bogger_kmod_exit(void)
{
    pr_info("[BOGGER] Kernel module unloaded\n");

    kfree(g_vmcb);
    g_vmcb = NULL;

    bogger_npt_free();

    kfree(hsave_area);
    hsave_area = NULL;

    if (svm_enabled) {
        /* Clear EFER.SVME to restore pre-module state */
        u64 efer = native_read_msr(MSR_EFER);
        efer &= ~EFER_SVME;
        native_write_msr(MSR_EFER, efer);
        svm_enabled = false;
    }
}

module_init(bogger_kmod_init);
module_exit(bogger_kmod_exit);
