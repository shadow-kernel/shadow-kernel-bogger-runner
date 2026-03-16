/* SPDX-License-Identifier: GPL-2.0 */
/*
 * bogger_vmrun.S – AMD SVM VMRUN with full host state save/restore
 *
 * void bogger_do_vmrun(u64 vmcb_phys,                  // %rdi
 *                      struct bogger_guest_gprs *gprs,  // %rsi
 *                      u64 *saved_segs,                 // %rdx → [fs, gs, kgs]
 *                      u64 host_save_phys);             // %rcx
 *
 * VMRUN/VMEXIT only save/restore a subset of host state:
 *     CS, DS, ES, SS, GDTR, IDTR, EFER, CR0-CR4, RIP, RSP, RFLAGS, RAX.
 *
 * They do NOT save/restore: FS, GS, TR, LDTR, STAR, LSTAR, CSTAR,
 * SFMASK, KERNEL_GS_BASE, SYSENTER_CS/ESP/EIP.
 *
 * On bare metal, these MUST be explicitly saved/restored via VMSAVE/VMLOAD
 * using a separate host save page.  Without this, the host TR is invalid
 * after #VMEXIT, and the first interrupt after STGI causes a triple fault.
 *
 * The sequence is:
 *   CLGI
 *   VMSAVE host_save_pa  — save host FS/GS/TR/LDTR/STAR/LSTAR/...
 *   VMLOAD vmcb_phys     — load guest FS/GS/TR/LDTR/STAR/LSTAR/...
 *   VMRUN  vmcb_phys     — enter guest
 *   [#VMEXIT]
 *   VMSAVE vmcb_phys     — save guest FS/GS/TR/LDTR/...
 *   VMLOAD host_save_pa  — restore host FS/GS/TR/LDTR/STAR/LSTAR/...
 *   [save guest GPRs, restore host GPRs]
 *   STGI
 *
 * This matches the pattern used by KVM's svm_vcpu_run and works
 * correctly on both bare metal and nested SVM (under KVM).
 */

#include <linux/linkage.h>

.text
SYM_FUNC_START(bogger_do_vmrun)
    /* Save callee-saved registers */
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15
    pushq   %rbp

    /* Save args for after VMEXIT.
     * Stack will be (from top after all pushes before CLGI):
     *   rsp+0:  gprs_ptr       (2nd push of %rsi, for post-VMEXIT GPR save)
     *   rsp+8:  vmcb_phys      (pushq %rdi)
     *   rsp+16: gprs_ptr       (pushq %rsi, original)
     *   rsp+24: saved_segs     (pushq %rdx)
     *   rsp+32: host_save_phys (pushq %rcx)
     *   rsp+40: rbp ... rbx    (callee-saved)
     */
    pushq   %rcx            /* host_save_phys */
    pushq   %rdx            /* saved_segs pointer */
    pushq   %rsi            /* gprs pointer */
    pushq   %rdi            /* vmcb_phys */

    /* Load guest GPRs from struct (rsi = gprs pointer, still valid) */
    movq    0x00(%rsi), %rbx
    movq    0x08(%rsi), %rcx
    movq    0x10(%rsi), %rdx
    movq    0x28(%rsi), %rbp
    movq    0x30(%rsi), %r8
    movq    0x38(%rsi), %r9
    movq    0x40(%rsi), %r10
    movq    0x48(%rsi), %r11
    movq    0x50(%rsi), %r12
    movq    0x58(%rsi), %r13
    movq    0x60(%rsi), %r14
    movq    0x68(%rsi), %r15

    /* Load guest RDI and RSI last (clobbers our pointers) */
    pushq   %rsi            /* save gprs ptr for after vmexit */
    movq    0x20(%rsi), %rdi  /* guest rdi */
    movq    0x18(%rsi), %rsi  /* guest rsi (must be last!) */

    /* ─── CLGI: disable interrupts (clear GIF) ───
     * Must be before VMSAVE/VMLOAD because VMLOAD overwrites host's
     * GS_BASE/TR/etc. with guest values.  If an interrupt arrived
     * between VMLOAD and VMRUN, the handler would use guest state
     * (especially guest TR → invalid TSS) causing a crash. */
    clgi

    /* ── Save host FS/GS/TR/LDTR/STAR/LSTAR/CSTAR/SFMASK/KernelGSBase ──
     * This is CRITICAL on bare metal: without it, host TR is lost after
     * the guest VMLOAD below, and the first interrupt after STGI would
     * triple-fault the host CPU. */
    movq    32(%rsp), %rax      /* host_save_phys */
    vmsave  %rax

    /* ── Load guest FS/GS/TR/LDTR/STAR/LSTAR/etc. from VMCB ── */
    movq    8(%rsp), %rax       /* vmcb_phys */
    vmload  %rax
    vmrun   %rax

    /* ═══ #VMEXIT — we're back ═══
     * RAX = vmcb_phys (host RAX restored from VM_HSAVE_PA by hardware).
     * All other GPRs hold guest values.
     * GIF is CLEAR — no interrupts possible until STGI.
     */

    /* ═══ Save guest FS/GS/TR/LDTR/STAR/LSTAR/etc. to VMCB ═══ */
    vmsave  %rax

    /* ═══ Restore host FS/GS/TR/LDTR/STAR/LSTAR/CSTAR/SFMASK/KernelGSBase ═══
     * This restores the host Task Register (TR) — critical for IST-based
     * interrupt handlers — and all SYSCALL/SYSENTER MSRs.  Without this,
     * any interrupt delivery after STGI would use the guest's (invalid)
     * TSS and cause a triple fault → reboot on bare metal. */
    movq    32(%rsp), %rax      /* host_save_phys */
    vmload  %rax

    /* ═══ Host state fully restored — save guest GPRs ═══ */

    /* Save guest RSI temporarily, get gprs pointer back */
    xchgq   %rsi, (%rsp)   /* stack top was gprs_ptr; now has guest_rsi */

    /* Save guest GPRs to struct */
    movq    %rbx, 0x00(%rsi)
    movq    %rcx, 0x08(%rsi)
    movq    %rdx, 0x10(%rsi)
    movq    %rbp, 0x28(%rsi)
    movq    %r8,  0x30(%rsi)
    movq    %r9,  0x38(%rsi)
    movq    %r10, 0x40(%rsi)
    movq    %r11, 0x48(%rsi)
    movq    %r12, 0x50(%rsi)
    movq    %r13, 0x58(%rsi)
    movq    %r14, 0x60(%rsi)
    movq    %r15, 0x68(%rsi)

    /* Save guest RSI and RDI */
    popq    %rax            /* guest_rsi from stack */
    movq    %rax, 0x18(%rsi)
    movq    %rdi, 0x20(%rsi)  /* guest rdi (still in rdi) */

    /* Clean up remaining stack args */
    popq    %rax            /* vmcb_phys — discard */
    popq    %rax            /* gprs_ptr — discard */
    popq    %rbx            /* saved_segs pointer → rbx */

    /* ═══ WRMSR safety net for FS/GS/KERNEL_GS_BASE ═══
     * The VMLOAD above already restored these, but we keep the
     * explicit WRMSR as a belt-and-suspenders measure for nested
     * SVM compatibility where VMLOAD interception semantics may
     * differ across KVM versions. */

    /* Restore GS_BASE (MSR 0xC0000101) */
    movl    $0xC0000101, %ecx
    movq    8(%rbx), %rax       /* saved_gs_base */
    movq    %rax, %rdx
    shrq    $32, %rdx
    wrmsr

    /* Restore FS_BASE (MSR 0xC0000100) */
    movl    $0xC0000100, %ecx
    movq    0(%rbx), %rax       /* saved_fs_base */
    movq    %rax, %rdx
    shrq    $32, %rdx
    wrmsr

    /* Restore KERNEL_GS_BASE (MSR 0xC0000102) */
    movl    $0xC0000102, %ecx
    movq    16(%rbx), %rax      /* saved_kernel_gs_base */
    movq    %rax, %rdx
    shrq    $32, %rdx
    wrmsr

    /* Discard host_save_phys from stack */
    addq    $8, %rsp

    /* ═══ Host fully restored — NOW safe to re-enable interrupts ═══ */
    stgi

    /* Restore callee-saved registers */
    popq    %rbp
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    RET
SYM_FUNC_END(bogger_do_vmrun)

