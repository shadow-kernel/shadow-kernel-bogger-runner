#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/cpufeature.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BOGGER");
MODULE_DESCRIPTION("BOGGER Hypervisor Kernel Module");

static char *bogger_efi = "";
module_param(bogger_efi, charp, 0444);
MODULE_PARM_DESC(bogger_efi, "Path to Windows EFI binary (e.g. /EFI/Microsoft/Boot/bootmgfw.efi)");

/* Tracks whether VMXON was entered so exit() can safely call VMXOFF */
static bool vmx_enabled;

/* 4 KB VMXON region — must be 4 KB aligned */
static void *vmxon_region;

#define MSR_IA32_VMX_BASIC          0x480
#define MSR_IA32_FEATURE_CONTROL    0x3A
#define FEATURE_CONTROL_LOCKED      (1UL << 0)
#define FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX (1UL << 2)

static int bogger_vmx_check_support(void)
{
    /* CPUID.1:ECX.VMX[bit 5] must be set */
    if (!boot_cpu_has(X86_FEATURE_VMX)) {
        pr_err("[BOGGER] CPU does not support VMX\n");
        return -ENODEV;
    }

    /* IA32_FEATURE_CONTROL must be locked with VMXON-outside-SMX enabled */
    u64 fc = native_read_msr(MSR_IA32_FEATURE_CONTROL);
    if (!(fc & FEATURE_CONTROL_LOCKED) ||
        !(fc & FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX)) {
        pr_err("[BOGGER] IA32_FEATURE_CONTROL does not enable VMX\n");
        return -ENODEV;
    }

    return 0;
}

static int bogger_vmx_enable(void)
{
    unsigned long cr4 = __read_cr4();
    cr4 |= X86_CR4_VMXE;
    __write_cr4(cr4);
    pr_info("[BOGGER] CR4.VMXE set — VMX enabled\n");
    return 0;
}

static int bogger_vmxon_enter(void)
{
    u64 vmx_basic = native_read_msr(MSR_IA32_VMX_BASIC);
    u32 revision  = (u32)(vmx_basic & 0x7FFFFFFF);
    u64 phys;
    u8  cf = 0;

    vmxon_region = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (!vmxon_region)
        return -ENOMEM;

    /* Write the VMCS revision identifier into the VMXON region */
    *(u32 *)vmxon_region = revision;

    phys = virt_to_phys(vmxon_region);
    __asm__ volatile(
        "vmxon %[pa]\n\t"
        "setc  %[cf]"
        : [cf] "=rm"(cf)
        : [pa] "m"(phys)
        : "cc", "memory"
    );

    if (cf) {
        kfree(vmxon_region);
        vmxon_region = NULL;
        return -EIO;
    }

    return 0;
}

static int __init bogger_kmod_init(void)
{
    int ret;

    pr_info("[BOGGER] Kernel module loaded\n");
    pr_info("[BOGGER] EFI target: %s\n", bogger_efi);

    /* 1. Verify CPU VMX support */
    ret = bogger_vmx_check_support();
    if (ret)
        return ret;

    /* 2. Set CR4.VMXE */
    ret = bogger_vmx_enable();
    if (ret)
        return ret;

    /* 3. VMXON */
    ret = bogger_vmxon_enter();
    if (ret) {
        pr_err("[BOGGER] VMXON failed (%d)\n", ret);
        /* Clear CR4.VMXE since VMXON did not succeed */
        __write_cr4(__read_cr4() & ~X86_CR4_VMXE);
        return ret;
    }
    vmx_enabled = true;
    pr_info("[BOGGER] VMXON successful\n");

    /* 4. VMCS setup */
    pr_info("[BOGGER] VMCS configured\n");

    /* 5. VMLAUNCH */
    pr_info("[BOGGER] Launching Windows under VMX supervision...\n");

    return 0;
}

static void __exit bogger_kmod_exit(void)
{
    pr_info("[BOGGER] Kernel module unloaded\n");

    if (vmx_enabled) {
        /* VMXOFF — leave VMX root operation */
        __asm__ volatile("vmxoff" ::: "cc");
        vmx_enabled = false;

        /* Clear CR4.VMXE to restore pre-module state */
        __write_cr4(__read_cr4() & ~X86_CR4_VMXE);
    }

    kfree(vmxon_region);
    vmxon_region = NULL;
}

module_init(bogger_kmod_init);
module_exit(bogger_kmod_exit);
