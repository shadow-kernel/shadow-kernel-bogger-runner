#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/processor.h>
#include <asm/svm.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BOGGER");
MODULE_DESCRIPTION("BOGGER Hypervisor - SVM Real Mode Guest v2");

static char *bogger_efi = "";
module_param(bogger_efi, charp, 0444);

#define MSR_VM_CR_SVMDIS    (1ULL << 4)
#define SVM_EXIT_ERR_VAL    0xFFFFFFFFFFFFFFFFULL
#define INTERCEPT_CPUID     (1ULL << 18)
#define INTERCEPT_MSR       (1ULL << 28)
#define INTERCEPT_VMMCALL   (1ULL << 20)
#define INTERCEPT_HLT       (1ULL << 24)

static void          *hsave_area;
static struct vmcb   *g_vmcb;
static void          *msrpm;
static void          *iopm;
static bool           g_running;
static u64            g_exit_count;
static char           bogger_efi_buf[512];

struct bogger_regs {
    u64 rbx, rcx, rdx, rsi, rdi;
    u64 r8,  r9,  r10, r11;
    u64 r12, r13, r14, r15;
    u64 rbp;
};
static struct bogger_regs g_regs;

static noinline void bogger_vmrun(u64 vmcb_pa, struct bogger_regs *regs)
{
    asm volatile (
        "push %%rbp\n\t"
        "mov  %[rbx], %%rbx\n\t"
        "mov  %[rcx], %%rcx\n\t"
        "mov  %[rdx], %%rdx\n\t"
        "mov  %[rsi], %%rsi\n\t"
        "mov  %[rdi], %%rdi\n\t"
        "mov  %[rbp], %%rbp\n\t"
        "mov  %[r8],  %%r8\n\t"
        "mov  %[r9],  %%r9\n\t"
        "mov  %[r10], %%r10\n\t"
        "mov  %[r11], %%r11\n\t"
        "mov  %[r12], %%r12\n\t"
        "mov  %[r13], %%r13\n\t"
        "mov  %[r14], %%r14\n\t"
        "mov  %[r15], %%r15\n\t"
        "vmrun %%rax\n\t"
        "mov %%rbx, %[rbx]\n\t"
        "mov %%rcx, %[rcx]\n\t"
        "mov %%rdx, %[rdx]\n\t"
        "mov %%rsi, %[rsi]\n\t"
        "mov %%rdi, %[rdi]\n\t"
        "mov %%rbp, %[rbp]\n\t"
        "mov %%r8,  %[r8]\n\t"
        "mov %%r9,  %[r9]\n\t"
        "mov %%r10, %[r10]\n\t"
        "mov %%r11, %[r11]\n\t"
        "mov %%r12, %[r12]\n\t"
        "mov %%r13, %[r13]\n\t"
        "mov %%r14, %[r14]\n\t"
        "mov %%r15, %[r15]\n\t"
        "pop %%rbp\n\t"
        :
        [rbx]"+m"(regs->rbx), [rcx]"+m"(regs->rcx),
        [rdx]"+m"(regs->rdx), [rsi]"+m"(regs->rsi),
        [rdi]"+m"(regs->rdi), [rbp]"+m"(regs->rbp),
        [r8] "+m"(regs->r8),  [r9] "+m"(regs->r9),
        [r10]"+m"(regs->r10), [r11]"+m"(regs->r11),
        [r12]"+m"(regs->r12), [r13]"+m"(regs->r13),
        [r14]"+m"(regs->r14), [r15]"+m"(regs->r15)
        : "a"(vmcb_pa)
        : "memory", "cc"
    );
}

static void handle_cpuid(struct vmcb *vmcb, struct bogger_regs *regs)
{
    u32 leaf = (u32)vmcb->save.rax;
    u32 eax = 0, ebx = 0, ecx = 0, edx = 0;
    asm volatile("cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(leaf), "c"((u32)regs->rcx));
    switch (leaf) {
    case 0x1:
        ecx &= ~(1u << 5);   /* no VMX */
        ecx &= ~(1u << 31);  /* no hypervisor */
        break;
    case 0x40000000:
        eax = ebx = ecx = edx = 0;
        break;
    case 0x80000001:
        ecx &= ~(1u << 2);   /* no SVM */
        break;
    default: break;
    }
    vmcb->save.rax = eax;
    regs->rbx      = ebx;
    regs->rcx      = ecx;
    regs->rdx      = edx;
    vmcb->control.next_rip = vmcb->save.rip + 2;
    vmcb->save.rip = vmcb->control.next_rip;
}

static void handle_msr(struct vmcb *vmcb, struct bogger_regs *regs)
{
    u32 msr   = (u32)regs->rcx;
    int write = (int)vmcb->control.exit_info_1;
    if (!write) {
        u64 val = 0;
        if (msr == 0x3A) val = 0x1;
        else rdmsrq_safe(msr, &val);
        vmcb->save.rax = val & 0xFFFFFFFF;
        regs->rdx      = val >> 32;
    } else {
        u64 val = (regs->rdx << 32) | (vmcb->save.rax & 0xFFFFFFFF);
        if (msr != 0x3A) wrmsr_safe(msr, (u32)val, (u32)(val >> 32));
    }
    vmcb->save.rip = vmcb->control.next_rip;
}

static int bogger_vmexit_loop(void)
{
    u64 vmcb_pa = virt_to_phys(g_vmcb);
    int max_exits = 1000;
    pr_info("[BOGGER] Entering VMRUN loop\n");
    while (g_running && max_exits-- > 0) {
        bogger_vmrun(vmcb_pa, &g_regs);
        g_exit_count++;
        u64 exitcode = g_vmcb->control.exit_code;
        if (exitcode == SVM_EXIT_ERR_VAL) {
            pr_err("[BOGGER] VMEXIT_ERR ei1=0x%llx ei2=0x%llx\n",
                   g_vmcb->control.exit_info_1, g_vmcb->control.exit_info_2);
            pr_err("[BOGGER]   RIP=0x%llx CR0=0x%llx EFER=0x%llx RFLAGS=0x%llx\n",
                   g_vmcb->save.rip, g_vmcb->save.cr0,
                   g_vmcb->save.efer, g_vmcb->save.rflags);
            return -EIO;
        }
        switch (exitcode) {
        case SVM_EXIT_CPUID:   handle_cpuid(g_vmcb, &g_regs); break;
        case SVM_EXIT_MSR:     handle_msr(g_vmcb, &g_regs);   break;
        case SVM_EXIT_HLT:
            pr_info("[BOGGER] Guest HLT exits=%llu\n", g_exit_count);
            g_vmcb->save.rip = g_vmcb->control.next_rip;
            g_running = false; break;
        case SVM_EXIT_VMMCALL:
            pr_info("[BOGGER] VMMCALL exits=%llu\n", g_exit_count);
            g_vmcb->save.rip = g_vmcb->control.next_rip;
            g_running = false; break;
        case SVM_EXIT_SHUTDOWN:
            pr_info("[BOGGER] Guest SHUTDOWN (Triple Fault) - normal for empty guest\\n");
            pr_info("[BOGGER] Guest SHUTDOWN\n");
            g_running = false; break;
        default:
            pr_warn("[BOGGER] Unhandled exit=0x%llx RIP=0x%llx\n",
                    exitcode, g_vmcb->save.rip);
            if (g_vmcb->control.next_rip)
                g_vmcb->save.rip = g_vmcb->control.next_rip;
            else g_running = false;
            break;
        }
    }
    pr_info("[BOGGER] Loop done exits=%llu\n", g_exit_count);
    return 0;
}

static void bogger_vmcb_setup(struct vmcb *vmcb)
{
    struct vmcb_control_area *c = &vmcb->control;
    struct vmcb_save_area    *s = &vmcb->save;
    c->intercepts[INTERCEPT_WORD3] = 0;
    c->intercepts[INTERCEPT_WORD4] = 0;
    c->intercepts[INTERCEPT_WORD5] = 0;
    /* Word3: bit18=CPUID bit20=VMMCALL bit24=HLT */
    c->intercepts[INTERCEPT_WORD3] = (1u << 18) | (1u << 20) | (1u << 24);
    /* Word4: bit28-WORD4 = MSR */
    c->intercepts[INTERCEPT_WORD4] = (1u << (SVM_EXIT_MSR - 0x60));
    msrpm = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 1);
    if (msrpm) {
        u8 *bm = (u8 *)msrpm;
        bm[14] |= (1 << 4) | (1 << 5);
        c->msrpm_base_pa = virt_to_phys(msrpm);
    }
    iopm = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 2);
    if (iopm) c->iopm_base_pa = virt_to_phys(iopm);
    c->asid        = 1;
    c->tlb_ctl     = TLB_CONTROL_FLUSH_ALL_ASID;
    c->tsc_offset  = 0;
    /* Real Mode guest */
    s->efer   = 0;
    s->cr0    = 0x00000010ULL;
    s->cr4    = 0;
    s->cr3    = 0;
    s->rflags = 0x0202ULL;
    s->rip    = 0xFFF0ULL;
    s->cs.selector = 0xF000;
    s->cs.base     = 0xFFFF0000ULL;
    s->cs.limit    = 0xFFFF;
    s->cs.attrib   = 0x009B;
    s->ds.selector = 0; s->ds.base = 0; s->ds.limit = 0xFFFF; s->ds.attrib = 0x0093;
    s->es = s->ds; s->ss = s->ds; s->fs = s->ds; s->gs = s->ds;
    s->gdtr.selector = 0; s->gdtr.base = 0; s->gdtr.limit = 0xFFFF;
    s->idtr.selector = 0; s->idtr.base = 0; s->idtr.limit = 0xFFFF;
    s->ldtr.selector = 0; s->ldtr.base = 0; s->ldtr.limit = 0xFFFF; s->ldtr.attrib = 0x0082;
    s->tr.selector   = 0; s->tr.base   = 0; s->tr.limit   = 0xFFFF; s->tr.attrib   = 0x008B;
    s->cpl   = 0;
    s->dr6   = 0xFFFF0FF0ULL;
    s->dr7   = 0x00000400ULL;
    s->g_pat = 0x0007040600070406ULL;
    pr_info("[BOGGER] VMCB ready CR0=0x%llx EFER=0x%llx RIP=0x%llx\n",
            s->cr0, s->efer, s->rip);
    pr_info("[BOGGER]   phys=0x%llx ASID=%u\n",
            (u64)virt_to_phys(vmcb), c->asid);
}

static int bogger_svm_init(void)
{
    unsigned int ecx = 0;
    asm volatile("cpuid" : "=c"(ecx) : "a"(0x80000001) : "ebx", "edx");
    if (!(ecx & (1 << 2))) { pr_err("[BOGGER] No SVM\n"); return -ENODEV; }
    if (native_read_msr(MSR_VM_CR) & MSR_VM_CR_SVMDIS) {
        pr_err("[BOGGER] SVM disabled\n"); return -ENODEV;
    }
    u64 efer = native_read_msr(MSR_EFER);
    efer |= EFER_SVME;
    native_write_msr(MSR_EFER, efer);
    hsave_area = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (!hsave_area) return -ENOMEM;
    native_write_msr(MSR_VM_HSAVE_PA, virt_to_phys(hsave_area));
    pr_info("[BOGGER] SVM enabled\n");
    return 0;
}

static int __init bogger_kmod_init(void)
{
    int ret;
    pr_info("[BOGGER] Kernel module loaded\n");
    pr_info("[BOGGER] EFI: %s\n", bogger_efi);
    strncpy(bogger_efi_buf, bogger_efi, sizeof(bogger_efi_buf) - 1);
    ret = bogger_svm_init();
    if (ret) return ret;
    g_vmcb = (struct vmcb *)get_zeroed_page(GFP_KERNEL);
    if (!g_vmcb) return -ENOMEM;
    bogger_vmcb_setup(g_vmcb);
    g_running    = true;
    g_exit_count = 0;
    memset(&g_regs, 0, sizeof(g_regs));
    pr_info("[BOGGER] Attempting VMRUN\n");
    ret = bogger_vmexit_loop();
    if (ret) pr_err("[BOGGER] VMRUN failed: %d\n", ret);
    return 0;
}

static void __exit bogger_kmod_exit(void)
{
    g_running = false;
    if (g_vmcb)     { free_page((unsigned long)g_vmcb); g_vmcb = NULL; }
    if (msrpm)      { free_pages((unsigned long)msrpm, 1); msrpm = NULL; }
    if (iopm)       { free_pages((unsigned long)iopm,  2); iopm  = NULL; }
    if (hsave_area) {
        u64 efer = native_read_msr(MSR_EFER);
        efer &= ~EFER_SVME;
        native_write_msr(MSR_EFER, efer);
        kfree(hsave_area);
        hsave_area = NULL;
    }
    pr_info("[BOGGER] Unloaded exits=%llu\n", g_exit_count);
}

module_init(bogger_kmod_init);
module_exit(bogger_kmod_exit);
