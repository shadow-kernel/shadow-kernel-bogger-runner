// SPDX-License-Identifier: GPL-2.0
/*
 * bogger_kmod.c – BOGGER Hypervisor Kernel Module (AMD SVM)
 *
 * Main entry point: module init/exit and the VMRUN loop.
 * All device emulation is split into separate files for clarity.
 *
 * Boot flow:
 *   1. Verify CPU SVM support
 *   2. Allocate guest RAM
 *   3. Load OVMF firmware
 *   4. Build ACPI tables
 *   5. Build NPT (maps RAM + MMIO + OVMF flash)
 *   6. Configure MSR bitmap + VMCB
 *   7. VMRUN → OVMF boots → Windows starts
 */

#include <linux/module.h>
#include <linux/init.h>
#include <asm/special_insns.h>
#include "bogger_types.h"
#include "bogger_guest_ram.h"
#include "bogger_ovmf.h"
#include "bogger_acpi.h"
#include "bogger_npt.h"
#include "bogger_svm.h"
#include "bogger_hpet.h"
#include "bogger_lapic.h"
#include "bogger_ioapic.h"
#include "bogger_nvme.h"
#include "bogger_stealth.h"
#include "bogger_ioport.h"
#include "bogger_fwcfg.h"
#include "bogger_pic.h"
#include "bogger_ps2.h"
#include "bogger_pci_passthrough.h"
#include "bogger_smbios.h"
#include "bogger_vga.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BOGGER");
MODULE_DESCRIPTION("BOGGER Hypervisor — boots Windows via OVMF/AMD SVM");

/* ── Module parameters ────────────────────────────────────────────── */
static char *bogger_efi = "";
module_param(bogger_efi, charp, 0444);

char *bogger_ovmf_code = "/usr/share/edk2/x64/OVMF_CODE.4m.fd";
module_param(bogger_ovmf_code, charp, 0444);

char *bogger_ovmf_vars = "";
module_param(bogger_ovmf_vars, charp, 0444);

unsigned int bogger_ram_mb = 0;
module_param(bogger_ram_mb, uint, 0444);

char *bogger_gpu_bdf = "";
module_param(bogger_gpu_bdf, charp, 0444);
MODULE_PARM_DESC(bogger_gpu_bdf, "GPU PCI BDF for passthrough (e.g. 01:00.0)");

bool bogger_passthrough_gpu = false;
module_param(bogger_passthrough_gpu, bool, 0444);
MODULE_PARM_DESC(bogger_passthrough_gpu, "Enable GPU PCI passthrough (bare metal only)");

char *bogger_disk_path = "";
module_param(bogger_disk_path, charp, 0444);
MODULE_PARM_DESC(bogger_disk_path, "Path to Windows disk/image backing device (e.g. /dev/nvme1n1, /dev/vda)");

/* ── Guest GPR state ──────────────────────────────────────────────── */
struct bogger_guest_gprs guest_gprs;

/* ── Host FS/GS save/restore around VMRUN ─────────────────────────
 *
 * AMD SVM VMRUN does NOT automatically save/restore host FS/GS base
 * and KernelGSBase.  bogger_do_vmrun() (in bogger_vmrun.S) restores
 * these MSRs in pure asm BEFORE any C code runs.
 */
u64 saved_segs[3];  /* [0]=FS_BASE, [1]=GS_BASE, [2]=KERNEL_GS_BASE */

static noinline void bogger_save_host_segs(void)
{
    rdmsrq(MSR_FS_BASE, saved_segs[0]);
    rdmsrq(MSR_GS_BASE, saved_segs[1]);
    rdmsrq(MSR_KERNEL_GS_BASE, saved_segs[2]);
}

/* External asm function: bogger_vmrun.S */
extern void bogger_do_vmrun(u64 vmcb_phys,
                            struct bogger_guest_gprs *gprs,
                            u64 *saved_segs,
                            u64 host_save_phys);

/* ── Helper: translate guest physical address → host virtual address ── */
/* Uses the shared bogger_gpa_to_hva() from bogger_guest_ram.c */
#define guest_gpa_to_hva(gpa)  bogger_gpa_to_hva(gpa)

/* ── Helper: walk guest 4-level page tables (VA → GPA) ────────────── */
static u64 guest_va_to_gpa(u64 cr3, u64 va)
{
    u64 pml4e, pdpte, pde, pte;
    void *p;

    /* PML4 */
    p = guest_gpa_to_hva((cr3 & ~0xFFFULL) + ((va >> 39) & 0x1FF) * 8);
    if (!p) return (u64)-1;
    pml4e = *(u64 *)p;
    if (!(pml4e & 1)) return (u64)-1;

    /* PDPT */
    p = guest_gpa_to_hva((pml4e & 0x000FFFFFFFFFF000ULL) + ((va >> 30) & 0x1FF) * 8);
    if (!p) return (u64)-1;
    pdpte = *(u64 *)p;
    if (!(pdpte & 1)) return (u64)-1;
    if (pdpte & (1ULL << 7)) /* 1GB page */
        return (pdpte & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);

    /* PD */
    p = guest_gpa_to_hva((pdpte & 0x000FFFFFFFFFF000ULL) + ((va >> 21) & 0x1FF) * 8);
    if (!p) return (u64)-1;
    pde = *(u64 *)p;
    if (!(pde & 1)) return (u64)-1;
    if (pde & (1ULL << 7)) /* 2MB page */
        return (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL);

    /* PT */
    p = guest_gpa_to_hva((pde & 0x000FFFFFFFFFF000ULL) + ((va >> 12) & 0x1FF) * 8);
    if (!p) return (u64)-1;
    pte = *(u64 *)p;
    if (!(pte & 1)) return (u64)-1;
    return (pte & 0x000FFFFFFFFFF000ULL) | (va & 0xFFFULL);
}

/* ── Helper: translate guest virtual address → host virtual address ── */
static void *guest_va_to_hva(u64 cr3, u64 va)
{
    u64 gpa = guest_va_to_gpa(cr3, va);
    if (gpa == (u64)-1) return NULL;
    return guest_gpa_to_hva(gpa);
}

/* ── Helper: read guest GPR by index (0=RAX..15=R15) ──────────────── */
static u64 reg_val(u8 idx)
{
    switch (idx & 0xF) {
    case 0:  return g_vmcb->save.rax;
    case 1:  return guest_gprs.rcx;
    case 2:  return guest_gprs.rdx;
    case 3:  return guest_gprs.rbx;
    case 4:  return g_vmcb->save.rsp;
    case 5:  return guest_gprs.rbp;
    case 6:  return guest_gprs.rsi;
    case 7:  return guest_gprs.rdi;
    case 8:  return guest_gprs.r8;
    case 9:  return guest_gprs.r9;
    case 10: return guest_gprs.r10;
    case 11: return guest_gprs.r11;
    case 12: return guest_gprs.r12;
    case 13: return guest_gprs.r13;
    case 14: return guest_gprs.r14;
    case 15: return guest_gprs.r15;
    default: return 0;
    }
}

/* ── Helper: write guest GPR by index (0=RAX..15=R15) ─────────────── */
static void set_reg_val(u8 idx, u64 val)
{
    switch (idx & 0xF) {
    case 0:  g_vmcb->save.rax = val; break;
    case 1:  guest_gprs.rcx = val;   break;
    case 2:  guest_gprs.rdx = val;   break;
    case 3:  guest_gprs.rbx = val;   break;
    case 4:  g_vmcb->save.rsp = val; break;
    case 5:  guest_gprs.rbp = val;   break;
    case 6:  guest_gprs.rsi = val;   break;
    case 7:  guest_gprs.rdi = val;   break;
    case 8:  guest_gprs.r8  = val;   break;
    case 9:  guest_gprs.r9  = val;   break;
    case 10: guest_gprs.r10 = val;   break;
    case 11: guest_gprs.r11 = val;   break;
    case 12: guest_gprs.r12 = val;   break;
    case 13: guest_gprs.r13 = val;   break;
    case 14: guest_gprs.r14 = val;   break;
    case 15: guest_gprs.r15 = val;   break;
    }
}

/* ── Helper: decode ModRM effective address (64-bit mode, SIB aware) ── */
static u64 decode_modrm_ea(u8 modrm, u8 rex, const u8 *rest, u32 *extra_bytes)
{
    u8 mod = modrm >> 6;
    u8 rm  = (modrm & 7) | ((rex & 0x01) ? 8 : 0); /* REX.B extends rm */
    u64 base;

    *extra_bytes = 0;
    if (mod == 3) return (u64)-1; /* register operand */

    /* SIB byte present when low 3 bits of rm == 4 */
    if ((rm & 7) == 4) {
        u8 sib   = rest[0];
        u8 scale = sib >> 6;
        u8 idx   = ((sib >> 3) & 7) | ((rex & 0x02) ? 8 : 0); /* REX.X */
        u8 sb    = (sib & 7) | ((rex & 0x01) ? 8 : 0);        /* REX.B */
        u32 disp_bytes = 0;

        /* Base */
        if (mod == 0 && (sb & 7) == 5) {
            /* disp32 only, no base register */
            s32 d = (s32)((u32)rest[1] | ((u32)rest[2]<<8) |
                          ((u32)rest[3]<<16) | ((u32)rest[4]<<24));
            base = (u64)(s64)d;
            disp_bytes = 4;
        } else {
            base = reg_val(sb);
            if (mod == 1) {
                base += (s8)rest[1];
                disp_bytes = 1;
            } else if (mod == 2) {
                s32 d = (s32)((u32)rest[1] | ((u32)rest[2]<<8) |
                              ((u32)rest[3]<<16) | ((u32)rest[4]<<24));
                base += (s64)d;
                disp_bytes = 4;
            }
        }
        /* Index (index==4 means no index) */
        if ((idx & 7) != 4)
            base += reg_val(idx) << scale;

        *extra_bytes = 1 + disp_bytes; /* 1 for SIB + displacement */
        return base;
    }

    if (mod == 0 && (rm & 7) == 5) { /* RIP-relative */
        *extra_bytes = 4;
        return (u64)-1;
    }

    base = reg_val(rm);

    if (mod == 1) {
        *extra_bytes = 1;
        base += (s8)rest[0];
    } else if (mod == 2) {
        s32 disp;
        *extra_bytes = 4;
        disp = (s32)((u32)rest[0] | ((u32)rest[1] << 8) |
                      ((u32)rest[2] << 16) | ((u32)rest[3] << 24));
        base += disp;
    }
    return base;
}

/* ── Emulate a store (MOV / ALU) to MMIO address.                 ──
 * Decodes the instruction at guest RIP, extracts the write value,
 * advances RIP, and returns true on success.
 * @write_val: output — value to be written to the MMIO register
 * @cur_val:   current value of the MMIO register (for ALU r-m-w ops) ── */
static bool emulate_mmio_store(u32 *write_val, u32 cur_val)
{
    u8 *code;
    int pos = 0;
    u8 rex = 0;
    bool has_rep = false;
    bool has_66 = false;  /* operand-size override: 32-bit → 16-bit */
    u8 opcode, modrm, regf;
    u32 extra;

    /* Guest RIP is a virtual address — use page table walk when paging is on */
    if (g_vmcb->save.cr0 & (1ULL << 31))
        code = guest_va_to_hva(g_vmcb->save.cr3, g_vmcb->save.rip);
    else
        code = guest_gpa_to_hva(g_vmcb->save.rip);

    if (!code) return false;

    /* Skip legacy prefixes (including LOCK 0xF0, REP 0xF3) */
    while (pos < 8) {
        u8 b = code[pos];
        if (b >= 0x40 && b <= 0x4F) { rex = b; pos++; break; }
        if (b == 0xF3 || b == 0xF2) { has_rep = (b == 0xF3); pos++; continue; }
        if (b == 0x66) { has_66 = true; pos++; continue; }
        if (b == 0x67 || b == 0xF0 ||
            b == 0x2E || b == 0x3E || b == 0x26 || b == 0x36 ||
            b == 0x64 || b == 0x65) { pos++; continue; }
        break;
    }

    opcode = code[pos]; pos++;

    /* MOV r/m, r32/r64 (opcode 0x89) — with 0x66 prefix: r16 */
    if (opcode == 0x89) {
        modrm = code[pos]; pos++;
        regf = ((modrm >> 3) & 7) | ((rex & 0x04) ? 8 : 0); /* REX.R */
        extra = 0;
        decode_modrm_ea(modrm, rex, &code[pos], &extra);
        pos += extra;
        if (has_66)
            *write_val = (u32)(reg_val(regf) & 0xFFFF);
        else
            *write_val = (u32)reg_val(regf);
        g_vmcb->save.rip += pos;
        return true;
    }
    /* MOV r/m, imm32 (opcode 0xC7 /0) — with 0x66 prefix: imm16 */
    if (opcode == 0xC7) {
        modrm = code[pos]; pos++;
        if (((modrm >> 3) & 7) != 0) return false;
        extra = 0;
        decode_modrm_ea(modrm, rex, &code[pos], &extra);
        pos += extra;
        if (has_66) {
            *write_val = (u32)code[pos] | ((u32)code[pos+1]<<8);
            pos += 2;
        } else {
            *write_val = (u32)code[pos] | ((u32)code[pos+1]<<8) |
                         ((u32)code[pos+2]<<16) | ((u32)code[pos+3]<<24);
            pos += 4;
        }
        g_vmcb->save.rip += pos;
        return true;
    }
    /* MOV r/m8, r8 (opcode 0x88) */
    if (opcode == 0x88) {
        modrm = code[pos]; pos++;
        regf = ((modrm >> 3) & 7) | ((rex & 0x04) ? 8 : 0);
        extra = 0;
        decode_modrm_ea(modrm, rex, &code[pos], &extra);
        pos += extra;
        *write_val = (u32)(reg_val(regf) & 0xFF);
        g_vmcb->save.rip += pos;
        return true;
    }
    /* MOV r/m8, imm8 (opcode 0xC6 /0) */
    if (opcode == 0xC6) {
        modrm = code[pos]; pos++;
        if (((modrm >> 3) & 7) != 0) return false;
        extra = 0;
        decode_modrm_ea(modrm, rex, &code[pos], &extra);
        pos += extra;
        *write_val = code[pos]; pos += 1;
        g_vmcb->save.rip += pos;
        return true;
    }
    /* MOVNTI r/m32, r32 (0F C3) */
    if (opcode == 0x0F && code[pos] == 0xC3) {
        pos++; /* skip 0xC3 */
        modrm = code[pos]; pos++;
        regf = ((modrm >> 3) & 7) | ((rex & 0x04) ? 8 : 0);
        extra = 0;
        decode_modrm_ea(modrm, rex, &code[pos], &extra);
        pos += extra;
        *write_val = (u32)reg_val(regf);
        g_vmcb->save.rip += pos;
        return true;
    }
    /* ── ALU reg → r/m8 (byte): ADD/OR/AND/SUB/XOR ─────────────── */
    if (opcode == 0x00 || opcode == 0x08 || opcode == 0x20 ||
        opcode == 0x28 || opcode == 0x30) {
        u8 operand;
        modrm = code[pos]; pos++;
        regf = ((modrm >> 3) & 7) | ((rex & 0x04) ? 8 : 0);
        extra = 0;
        decode_modrm_ea(modrm, rex, &code[pos], &extra);
        pos += extra;
        operand = (u8)(reg_val(regf) & 0xFF);
        switch (opcode) {
        case 0x00: *write_val = ((cur_val & 0xFF) + operand) & 0xFF; break;
        case 0x08: *write_val = ((cur_val & 0xFF) | operand); break;
        case 0x20: *write_val = ((cur_val & 0xFF) & operand); break;
        case 0x28: *write_val = ((cur_val & 0xFF) - operand) & 0xFF; break;
        case 0x30: *write_val = ((cur_val & 0xFF) ^ operand); break;
        }
        g_vmcb->save.rip += pos;
        return true;
    }
    /* ── ALU reg → r/m32/64: ADD/OR/AND/SUB/XOR — 0x66: 16-bit ── */
    if (opcode == 0x01 || opcode == 0x09 || opcode == 0x21 ||
        opcode == 0x29 || opcode == 0x31) {
        u32 operand, mask, cv;
        modrm = code[pos]; pos++;
        regf = ((modrm >> 3) & 7) | ((rex & 0x04) ? 8 : 0);
        extra = 0;
        decode_modrm_ea(modrm, rex, &code[pos], &extra);
        pos += extra;
        mask = has_66 ? 0xFFFF : 0xFFFFFFFF;
        operand = (u32)reg_val(regf) & mask;
        cv = cur_val & mask;
        switch (opcode) {
        case 0x01: *write_val = (cv + operand) & mask; break;
        case 0x09: *write_val = (cv | operand); break;
        case 0x21: *write_val = (cv & operand); break;
        case 0x29: *write_val = (cv - operand) & mask; break;
        case 0x31: *write_val = (cv ^ operand); break;
        }
        g_vmcb->save.rip += pos;
        return true;
    }
    /* ── ALU imm32 → r/m32 (opcode 0x81 /0-/6) — 0x66: imm16 ─── */
    if (opcode == 0x81) {
        u8 op;
        u32 imm, mask, cv;
        modrm = code[pos]; pos++;
        op = (modrm >> 3) & 7;
        extra = 0;
        decode_modrm_ea(modrm, rex, &code[pos], &extra);
        pos += extra;
        if (has_66) {
            imm = (u32)code[pos] | ((u32)code[pos+1]<<8);
            pos += 2;
        } else {
            imm = (u32)code[pos] | ((u32)code[pos+1]<<8) |
                  ((u32)code[pos+2]<<16) | ((u32)code[pos+3]<<24);
            pos += 4;
        }
        mask = has_66 ? 0xFFFF : 0xFFFFFFFF;
        cv = cur_val & mask;
        switch (op) {
        case 0: *write_val = (cv + imm) & mask; break;
        case 1: *write_val = (cv | imm); break;
        case 4: *write_val = (cv & imm); break;
        case 5: *write_val = (cv - imm) & mask; break;
        case 6: *write_val = (cv ^ imm); break;
        default: return false; /* ADC/SBB/CMP not handled */
        }
        g_vmcb->save.rip += pos;
        return true;
    }
    /* ── ALU imm8(sign-ext) → r/m32 (opcode 0x83 /0-/6) — 0x66: 16-bit */
    if (opcode == 0x83) {
        u8 op;
        u32 imm, mask, cv;
        modrm = code[pos]; pos++;
        op = (modrm >> 3) & 7;
        extra = 0;
        decode_modrm_ea(modrm, rex, &code[pos], &extra);
        pos += extra;
        imm = has_66 ? (u32)(s16)(s8)code[pos] : (u32)(s32)(s8)code[pos];
        pos++;
        mask = has_66 ? 0xFFFF : 0xFFFFFFFF;
        cv = cur_val & mask;
        switch (op) {
        case 0: *write_val = (cv + imm) & mask; break;
        case 1: *write_val = (cv | imm); break;
        case 4: *write_val = (cv & imm); break;
        case 5: *write_val = (cv - imm) & mask; break;
        case 6: *write_val = (cv ^ imm); break;
        default: return false;
        }
        g_vmcb->save.rip += pos;
        return true;
    }
    /* ── XCHG r/m32, r32 (opcode 0x87) — 0x66: 16-bit ────────── */
    if (opcode == 0x87) {
        u32 mem_val, reg_v;
        modrm = code[pos]; pos++;
        regf = ((modrm >> 3) & 7) | ((rex & 0x04) ? 8 : 0);
        extra = 0;
        decode_modrm_ea(modrm, rex, &code[pos], &extra);
        pos += extra;
        if (has_66) {
            mem_val = cur_val & 0xFFFF;
            reg_v = (u32)(reg_val(regf) & 0xFFFF);
            /* Write old memory value into register (low 16 bits) */
            set_reg_val(regf, (reg_val(regf) & ~0xFFFFULL) | (u64)mem_val);
            *write_val = reg_v;
        } else {
            mem_val = cur_val;
            reg_v = (u32)reg_val(regf);
            set_reg_val(regf, (u64)mem_val);
            *write_val = reg_v;
        }
        g_vmcb->save.rip += pos;
        return true;
    }
    /* ── ALU imm8 → r/m8 (opcode 0x80 /0-/6) ──────────────────── */
    if (opcode == 0x80) {
        u8 op, imm;
        modrm = code[pos]; pos++;
        op = (modrm >> 3) & 7;
        extra = 0;
        decode_modrm_ea(modrm, rex, &code[pos], &extra);
        pos += extra;
        imm = code[pos]; pos++;
        switch (op) {
        case 0: *write_val = ((cur_val & 0xFF) + imm) & 0xFF; break;
        case 1: *write_val = ((cur_val & 0xFF) | imm); break;
        case 4: *write_val = ((cur_val & 0xFF) & imm); break;
        case 5: *write_val = ((cur_val & 0xFF) - imm) & 0xFF; break;
        case 6: *write_val = ((cur_val & 0xFF) ^ imm); break;
        default: return false;
        }
        g_vmcb->save.rip += pos;
        return true;
    }
    /* ── REP STOSB (F3 AA) / REP STOSD (F3 AB) / REP STOSQ (REX.W F3 AB) ── */
    /* These come from OVMF memset() sweeping through MMIO pages.
     * Strategy: skip the MMIO page by advancing RDI/RCX appropriately.
     * The caller writes *write_val once; the rest is silently skipped.     */
    if (opcode == 0xAA || opcode == 0xAB) {
        bool df = !!(g_vmcb->save.rflags & (1ULL << 10));
        unsigned int elem_sz = (opcode == 0xAA) ? 1 : ((rex & 0x08) ? 8 : 4);
        u64 rdi_val = guest_gprs.rdi;
        *write_val = (u32)(g_vmcb->save.rax & ((elem_sz == 1) ? 0xFFULL : 0xFFFFFFFFULL));
        if (has_rep) {
            u64 rcx_val = guest_gprs.rcx;
            u64 page_off = rdi_val & 0xFFF;
            u64 bytes_left = df ? (page_off + elem_sz) : (0x1000 - page_off);
            u64 elems_in_page = bytes_left / elem_sz;
            if (elems_in_page == 0) elems_in_page = 1;
            if (elems_in_page > rcx_val) elems_in_page = rcx_val;
            guest_gprs.rcx = rcx_val - elems_in_page;
            if (df)
                guest_gprs.rdi = rdi_val - elems_in_page * elem_sz;
            else
                guest_gprs.rdi = rdi_val + elems_in_page * elem_sz;
            if (guest_gprs.rcx == 0)
                g_vmcb->save.rip += pos; /* REP done */
            /* else: RIP stays at REP STOSx, continues after VMRUN */
        } else {
            guest_gprs.rdi = df ? (rdi_val - elem_sz) : (rdi_val + elem_sz);
            g_vmcb->save.rip += pos;
        }
        return true;
    }
    /* ── REP MOVSB (F3 A4) / REP MOVSD (F3 A5) / REP MOVSQ (REX.W F3 A5) ── */
    /* memcpy writing into MMIO — read source, skip page for destination. */
    if (opcode == 0xA4 || opcode == 0xA5) {
        bool df = !!(g_vmcb->save.rflags & (1ULL << 10));
        unsigned int elem_sz = (opcode == 0xA4) ? 1 : ((rex & 0x08) ? 8 : 4);
        u64 rdi_val = guest_gprs.rdi;
        u64 rsi_val = guest_gprs.rsi;
        /* Source address: RSI is a virtual address when paging is on */
        u8 *src = (g_vmcb->save.cr0 & (1ULL << 31))
                  ? guest_va_to_hva(g_vmcb->save.cr3, rsi_val)
                  : guest_gpa_to_hva(rsi_val);
        *write_val = src ? (u32)(*src) : 0; /* first source byte */
        if (has_rep) {
            u64 rcx_val = guest_gprs.rcx;
            u64 page_off = rdi_val & 0xFFF;
            u64 bytes_left = df ? (page_off + elem_sz) : (0x1000 - page_off);
            u64 elems_in_page = bytes_left / elem_sz;
            if (elems_in_page == 0) elems_in_page = 1;
            if (elems_in_page > rcx_val) elems_in_page = rcx_val;
            guest_gprs.rcx = rcx_val - elems_in_page;
            if (df) {
                guest_gprs.rdi = rdi_val - elems_in_page * elem_sz;
                guest_gprs.rsi = rsi_val - elems_in_page * elem_sz;
            } else {
                guest_gprs.rdi = rdi_val + elems_in_page * elem_sz;
                guest_gprs.rsi = rsi_val + elems_in_page * elem_sz;
            }
            if (guest_gprs.rcx == 0)
                g_vmcb->save.rip += pos;
        } else {
            if (df) {
                guest_gprs.rdi = rdi_val - elem_sz;
                guest_gprs.rsi = rsi_val - elem_sz;
            } else {
                guest_gprs.rdi = rdi_val + elem_sz;
                guest_gprs.rsi = rsi_val + elem_sz;
            }
            g_vmcb->save.rip += pos;
        }
        return true;
    }
    return false;
}

/* Exception vector names (file scope to avoid stack pressure) */
static const char * const exc_names[32] = {
    "#DE","#DB","NMI","#BP","#OF","#BR","#UD","#NM",
    "#DF","??9","#TS","#NP","#SS","#GP","#PF","?15",
    "#MF","#AC","#MC","#XM","#VE","#CP","?22","?23",
    "?24","?25","?26","?27","#HV","#VC","#SX","?31"
};
/* Bitmap: vectors that push an error code */
static const u32 has_errcode_mask =
    (1U << 8)|(1U << 10)|(1U << 11)|(1U << 12)|(1U << 13)|
    (1U << 14)|(1U << 17)|(1U << 21)|(1U << 29)|(1U << 30);
static int exc_log_count;

/* ════════════════════════════════════════════════════════════════════
 * VMRUN loop – runs in a dedicated kthread for safe stack usage
 * ════════════════════════════════════════════════════════════════════ */

/* Ring buffer for last N VMEXITs — used for crash diagnostics */
#define VMEXIT_RING_SIZE 32
struct vmexit_record {
    u32 exit_code;
    u32 event_inj;
    u64 rip;
    u64 rflags;
    u64 info1;
    u64 info2;
};
static struct vmexit_record vmexit_ring[VMEXIT_RING_SIZE];
static unsigned int vmexit_ring_idx;

static void bogger_vmrun_loop(void)
{
    u64 phys = virt_to_phys(g_vmcb);
    u32 exit_code;
    int exits = 0;
    const int max_logged = 100;
    int post_reset_logged = 0;
    bool had_reset = false;
    unsigned long hlt_exits = 0;
    unsigned long intr_exits = 0;
    unsigned long npf_exits = 0;
    unsigned long ioio_exits = 0;
    unsigned long timer_injects = 0;
    unsigned long nvme_msix_injects = 0;
    /* Exception re-injection state — set by exit handlers, consumed by
     * the interrupt injection section at the top of each loop iteration.
     * NOTE: using function-scope static (not file-scope) to keep state
     * local to the VMRUN loop. Reset when loop starts. */
    static bool pending_exc_valid;
    static u32  pending_exc_inj;
    static u32  pending_exc_err;
    static u8   pending_vec;   /* IRQ vector waiting to be injected */
    static bool pending_irq;   /* true when pending_vec is valid    */
    pending_exc_valid = false;
    pending_exc_inj = 0;
    pending_exc_err = 0;
    pending_irq = false;
    pending_vec = 0;

    memset(&guest_gprs, 0, sizeof(guest_gprs));
    pr_info("[BOGGER] Entering VMRUN loop (VMCB phys=0x%llx)\n", phys);

    if (phys & 0xFFF) { pr_err("[BOGGER] VMCB not page-aligned!\n"); return; }
    { u64 efer = native_read_msr(MSR_EFER);
      if (!(efer & EFER_SVME)) { pr_err("[BOGGER] EFER.SVME not set!\n"); return; }
    }

    /* Touch all vmap'd guest RAM pages to pre-fault page tables */
    {
        unsigned long pg;
        volatile u8 *p = (volatile u8 *)guest_ram_virt;
        for (pg = 0; pg < guest_nr_pages; pg++) {
            (void)p[pg << PAGE_SHIFT];
            if ((pg & 0xFFFF) == 0)
                cond_resched();
        }
        pr_info("[BOGGER] Pre-faulted %lu guest RAM pages\n", guest_nr_pages);
    }

    while (true) {
        hpet_update_counter();

        /* NVMe I/O doorbell polling — runs EVERY VMRUN iteration to ensure
         * completions are posted before the guest re-enters.  This runs at
         * the shallowest stack depth (outside NPF handler) to avoid stack
         * overflow, since kernel_read() → VFS → block layer is deep. */
        if (nvme_regs && (nvme_csts & 1))
            nvme_poll_io_doorbell();

        /* NVMe admin/register sync — rate-limited to every 64 iterations
         * as a fallback; admin doorbell polling also fires from NPF handler. */
        if (nvme_regs && (exits & 63) == 0) {
            u32 new_cc = nvme_regs[5];
            if (new_cc != nvme_cc) {
                /* Detect NVMe controller re-init (Windows stornvme.sys takeover) */
                if ((nvme_cc & 1) && !(new_cc & 1))
                    pr_info("[BOGGER-NVMe] CC DISABLE: 0x%x→0x%x (driver takeover?) exit#%d nvme_io=%lu\n",
                            nvme_cc, new_cc, exits, nvme_io_cmd_count);
                else if (!(nvme_cc & 1) && (new_cc & 1))
                    pr_info("[BOGGER-NVMe] CC ENABLE: 0x%x→0x%x exit#%d\n",
                            nvme_cc, new_cc, exits);
                nvme_cc = new_cc;
            }
            nvme_aqa = nvme_regs[9];
            nvme_asq_base = (u64)nvme_regs[10] | ((u64)nvme_regs[11] << 32);
            nvme_acq_base = (u64)nvme_regs[12] | ((u64)nvme_regs[13] << 32);
            nvme_update_regs();
            nvme_poll_doorbell();
        }

        g_vmcb->control.clean = 0;
        g_vmcb->control.tlb_ctl = (exits == 0) ? TLB_CONTROL_FLUSH_ALL_ASID : 0;

        /* ── Interrupt injection ──────────────────────────────────── */
        {
            bool inject = false;
            u8 vec = 0;

            /* Update LAPIC CCR for guest reads */
            if (lapic_regs)
                lapic_regs[LAPIC_REG_TIMER_CCR / 4] = lapic_read_ccr();

            /* ── LAPIC timer — ALWAYS checked (idempotent).
             * Can preempt a lower-priority pending interrupt.
             * This prevents a low-priority PIT interrupt from
             * blocking the higher-priority LAPIC timer indefinitely. */
            if (lapic_timer_pending()) {
                u8 tvec = (u8)(lapic_lvt_timer & 0xFF);
                if (tvec >= 0x20) {
                    u8 tprio = tvec >> 4;
                    if (!pending_irq || tprio > (pending_vec >> 4)) {
                        /* Clear old vector's IRR bit if preempting to avoid
                         * leaking stale IRR bits for non-injectable vectors */
                        if (pending_irq && pending_vec != tvec)
                            lapic_clear_irr(pending_vec);
                        pending_irq = true;
                        pending_vec = tvec;
                        lapic_set_irr(tvec);
                    }
                    /* Re-arm periodic timer, disarm one-shot */
                    if (lapic_lvt_timer & (1U << 17))
                        lapic_timer_start_ns = ktime_get_ns();
                    else
                        lapic_timer_armed = false;
                }
            }

            /* Lower-priority / non-idempotent sources:
             * only checked when nothing is pending, to avoid losing
             * consumed items (IPIs, MSI-X) from their queues. */
            if (!pending_irq) {

            inject = false;
            vec = 0;

            /* Fallback PIT timer (IRQ0 → vec via PIC master) every 10ms.
             * Used by OVMF; disabled once LAPIC timer is active to avoid
             * priority inversion (PIT priority 2 blocks LAPIC priority 13). */
            {
                static u64 last_pit_ns;
                u64 now = ktime_get_ns();
                bool lapic_active = lapic_timer_armed &&
                                    !(lapic_lvt_timer & (1U << 16));
                if (!lapic_active && now - last_pit_ns > 10000000ULL) {
                    if (pic_master.vector_base >= 0x20 &&
                        !(pic_master.imr & 0x01)) {
                        inject = true;
                        vec = pic_master.vector_base;
                    }
                    last_pit_ns = now;
                }
            }

            /* Merge new interrupt with any pending one */
            if (inject) {
                pending_irq = true;
                pending_vec = vec;
                lapic_set_irr(vec);
            }

            /* GPU passthrough MSI interrupt forwarding.
             * Only accept if guest has programmed a valid vector (>= 0x20).
             * The default msi_guest_vector=0x0A is a placeholder that can
             * NEVER be injected (priority 0 <= V_TPR 0), which would block
             * all non-timer interrupt sources indefinitely. */
            if (atomic_read(&bogger_pt_irq_pending) && !pending_irq) {
                u8 gpu_vec;
                smp_rmb();
                gpu_vec = (u8)atomic_read(&bogger_pt_irq_vector);
                atomic_set(&bogger_pt_irq_pending, 0);
                if (gpu_vec >= 0x20) {
                    pending_irq = true;
                    pending_vec = gpu_vec;
                    lapic_set_irr(gpu_vec);
                }
            }

            /* NVMe MSI-X interrupt — fires after CQ completion posting */
            if (!pending_irq) {
                u8 msix_vec;
                if (nvme_msix_irq_pending(&msix_vec)) {
                    pending_irq = true;
                    pending_vec = msix_vec;
                    lapic_set_irr(msix_vec);
                    nvme_msix_injects++;
                }
            }

            /* IOAPIC-routed interrupts (INTx from PCI devices like NVMe) */
            if (!pending_irq) {
                if (atomic_read(&ioapic_irq_pending)) {
                    u8 ioapic_vec;
                    smp_rmb();
                    ioapic_vec = ioapic_irq_pending_vec;
                    atomic_set(&ioapic_irq_pending, 0);
                    if (ioapic_vec >= 0x20) {
                        pending_irq = true;
                        pending_vec = ioapic_vec;
                        lapic_set_irr(ioapic_vec);
                    }
                }
            }

            /* LAPIC self-IPI — queued when guest writes ICR with self dest
             * Note: IRR already set by lapic_queue_ipi() in lapic_mmio_write */
            if (!pending_irq) {
                u8 ipi_vec;
                if (lapic_ipi_pending(&ipi_vec)) {
                    pending_irq = true;
                    pending_vec = ipi_vec;
                }
            }

            } /* end of !pending_irq source checking */

            /* Set up int_ctl: V_INTR_MASKING always on, preserve guest V_TPR.
             * SVM maps CR8 to V_TPR (bits 3:0 of int_ctl).  Guest
             * writes to CR8 update V_TPR on VMEXIT.  We must preserve
             * it across iterations so the guest's IRQL stays correct. */
            g_vmcb->control.int_ctl = (1U << 24) |              /* V_INTR_MASKING */
                                      (g_vmcb->control.int_ctl & 0xF); /* preserve V_TPR */
            g_vmcb->control.event_inj = 0;

            /* Exception re-injection takes priority over IRQ injection.
             * This is set by #GP/other exception handlers below. */
            if (pending_exc_valid) {
                g_vmcb->control.event_inj = pending_exc_inj;
                g_vmcb->control.event_inj_err = pending_exc_err;
                pending_exc_valid = false;
                /* Don't inject IRQ in the same VMRUN as an exception */
            } else if (lapic_nmi_pending) {
                /* NMI injection — bypasses RFLAGS.IF but is blocked by
                 * NMI mask (int_state bit 1).  NMI is critical for
                 * KeBugCheckEx freeze IPI and IPI synchronization. */
                bool nmi_blocked = !!(g_vmcb->control.int_state & 0x02);
                if (!nmi_blocked) {
                    g_vmcb->control.event_inj = (1U << 31) |  /* Valid */
                                                 (2U << 8)  |  /* Type=NMI */
                                                 2;             /* Vector #2 */
                    lapic_nmi_pending = false;
                }
            } else if (pending_irq) {
                bool guest_if = !!(g_vmcb->save.rflags & (1ULL << 9));
                bool int_shadow = !!(g_vmcb->control.int_state & 0x01);
                u8 int_prio = pending_vec >> 4;
                u8 v_tpr = g_vmcb->control.int_ctl & 0xF;

                if (guest_if && !int_shadow && int_prio > v_tpr) {
                    /* IF=1, no shadow, priority beats CR8 → inject directly */
                    g_vmcb->control.event_inj = (1U << 31) | (u32)pending_vec;
                    /* Move from IRR to ISR in emulated LAPIC registers */
                    lapic_clear_irr(pending_vec);
                    lapic_set_isr(pending_vec);
                    pending_irq = false;
                    timer_injects++;
                    /* Log first few injections at kernel RIPs */
                    {
                        static int kern_inj_log;
                        if (g_vmcb->save.rip > 0xfffff80000000000ULL && kern_inj_log < 5) {
                            pr_warn("[BOGGER] INJ #%lu vec=0x%x prio=%u CR8=%u at RIP=0x%llx\n",
                                    timer_injects, pending_vec, int_prio, v_tpr,
                                    g_vmcb->save.rip);
                            kern_inj_log++;
                        }
                    }
                } else if (guest_if && !int_shadow) {
                    /* IF=1 but interrupt priority <= V_TPR (CR8).
                     * Use V_IRQ with the actual interrupt priority so
                     * VINTR fires when the guest lowers CR8 below this. */
                    g_vmcb->control.int_ctl |= (1U << 8) |              /* V_IRQ */
                                                ((u32)int_prio << 16);   /* V_INTR_PRIO = actual */
                } else {
                    /* IF=0 or interrupt shadow → use V_IRQ + V_IGN_TPR
                     * to get VINTR exit as soon as IF becomes 1.
                     * On VINTR exit we re-enter here and check priority. */
                    g_vmcb->control.int_ctl |= (1U << 8) |   /* V_IRQ */
                                                (1U << 20) |  /* V_IGN_TPR */
                                                (0xFU << 16); /* V_INTR_PRIO = max */
                }
            }

            /* Macro to queue exception re-injection from exit handlers below.
             * Usage: QUEUE_EXCEPTION(vector, type, has_errcode, errcode) */
            #define QUEUE_EXCEPTION(vec_, type_, ev_, err_) do { \
                pending_exc_valid = true; \
                pending_exc_inj = (1U << 31) | ((type_) << 8) | \
                                  ((ev_) ? (1U << 11) : 0) | (vec_); \
                pending_exc_err = (err_); \
            } while (0)
        }

        /* ── VMRUN ─────────────────────────────────────────────── */
        u32 saved_event_inj = g_vmcb->control.event_inj;
        bogger_save_host_segs();
        bogger_do_vmrun(phys, &guest_gprs, saved_segs, host_save_pa);

        exit_code = g_vmcb->control.exit_code;
        exits++;

        /* Record in ring buffer for crash diagnostics */
        {
            unsigned int ri = vmexit_ring_idx % VMEXIT_RING_SIZE;
            vmexit_ring[ri].exit_code = exit_code;
            vmexit_ring[ri].event_inj = saved_event_inj;
            vmexit_ring[ri].rip = g_vmcb->save.rip;
            vmexit_ring[ri].rflags = g_vmcb->save.rflags;
            vmexit_ring[ri].info1 = g_vmcb->control.exit_info_1;
            vmexit_ring[ri].info2 = g_vmcb->control.exit_info_2;
            vmexit_ring_idx++;
        }

        /* Yield every 4096 exits to avoid soft lockups */
        if ((exits & 0xFFF) == 0) {
            cond_resched();
            if (kthread_should_stop()) {
                pr_info("[BOGGER] Thread stop requested\n");
                goto done;
            }
        }

        /* Periodic status: 10K, 50K, then every 100K up to 1M, then every 1M */
        if ((exits == 10000) || (exits == 50000) ||
            (exits > 0 && exits <= 1000000 && (exits % 100000) == 0) ||
            (exits > 1000000 && (exits % 1000000) == 0)) {
            char milestone[16];
            u64 pm_ns = ktime_get_ns();
            u32 pm_ticks = (u32)div_u64(pm_ns * 3579545ULL, 1000000000ULL);
            if (exits < 1000000)
                snprintf(milestone, sizeof(milestone), "%uK", exits/1000);
            else
                snprintf(milestone, sizeof(milestone), "%uM", exits/1000000);

            pr_info("[BOGGER] %s exits, RIP=0x%llx CR0=0x%llx EFER=0x%llx CS.base=0x%llx\n",
                    milestone,
                    g_vmcb->save.rip,
                    g_vmcb->save.cr0, g_vmcb->save.efer,
                    g_vmcb->save.cs.base);
            pr_info("[BOGGER]   RFLAGS=0x%llx IF=%d PM_TMR=0x%x LAPIC_armed=%d\n",
                    g_vmcb->save.rflags,
                    !!(g_vmcb->save.rflags & (1ULL << 9)),
                    pm_ticks,
                    lapic_timer_armed ? 1 : 0);
            pr_info("[BOGGER]   LVT_TMR=0x%x ICR=0x%x DCR=0x%x pending=%d vec=0x%x\n",
                    lapic_lvt_timer, lapic_timer_icr, lapic_timer_dcr,
                    lapic_timer_pending() ? 1 : 0,
                    (u8)(lapic_lvt_timer & 0xFF));
            pr_info("[BOGGER]   CR2=0x%llx CR3=0x%llx EXC_BITMAP=0x%x (0xffffffff=KVM nested normal)\n",
                    g_vmcb->save.cr2, g_vmcb->save.cr3,
                    g_vmcb->control.intercepts[INTERCEPT_EXCEPTION]);
            pr_info("[BOGGER]   exits: hlt=%lu intr=%lu npf=%lu ioio=%lu tmr_inj=%lu nvme_msix=%lu nvme_io=%lu msix_fire=%lu\n",
                    hlt_exits, intr_exits, npf_exits, ioio_exits, timer_injects, nvme_msix_injects,
                    nvme_io_cmd_count, nvme_msix_fire_count);
            pr_info("[BOGGER]   NVMe: CC=0x%x CSTS=0x%x AQA=0x%x ASQ=0x%llx ACQ=0x%llx\n",
                    nvme_cc, nvme_regs ? nvme_regs[0x1C/4] : 0,
                    nvme_aqa, nvme_asq_base, nvme_acq_base);
            pr_info("[BOGGER]   PIC: master_imr=0x%02x slave_imr=0x%02x master_vec=0x%02x\n",
                    pic_master.imr, pic_slave.imr, pic_master.vector_base);
            /* GPU passthrough BAR state dump — critical for debugging display */
            if (passthrough_dev_count > 0) {
                struct bogger_passthrough_dev *ptgpu = &passthrough_devs[0];
                int bi;
                pr_info("[BOGGER]   GPU PT: vid=0x%04x did=0x%04x guest_bdf=0x%04x bars=%d\n",
                        ptgpu->vendor_id, ptgpu->device_id,
                        ptgpu->guest_bdf, ptgpu->num_bars);
                for (bi = 0; bi < ptgpu->num_bars; bi++) {
                    struct bogger_passthrough_bar *bar = &ptgpu->bars[bi];
                    u64 gpa = bogger_pci_passthrough_get_bar_gpa(ptgpu, bar);
                    pr_info("[BOGGER]   BAR%d: hpa=0x%llx gpa=0x%llx sz=0x%llx mmio=%d 64=%d mapped=%d shadow[%d]=0x%08x set=%d\n",
                            bar->bar_idx, bar->hpa, gpa, bar->size,
                            bar->is_mmio, bar->is_64bit, bar->mapped,
                            bar->bar_idx,
                            ptgpu->shadow_bar[bar->bar_idx],
                            ptgpu->shadow_bar_set[bar->bar_idx]);
                }
                pr_info("[BOGGER]   ROM: hpa=0x%llx sz=0x%llx mapped=%d shadow=0x%08x set=%d msi=%d irq=%d vec=0x%02x\n",
                        ptgpu->rom_hpa, ptgpu->rom_size, ptgpu->rom_mapped,
                        ptgpu->shadow_rom_bar, ptgpu->shadow_rom_set,
                        ptgpu->msi_enabled, ptgpu->msi_host_irq,
                        ptgpu->msi_guest_vector);
            }
            pr_info("[BOGGER]   V_TPR=0x%x (CR8) int_ctl=0x%x int_state=0x%x\n",
                    (g_vmcb->control.int_ctl & 0xFF),
                    g_vmcb->control.int_ctl,
                    g_vmcb->control.int_state);
            /* Dump instruction bytes at RIP (walk guest page tables) */
            if (g_vmcb->save.cr0 & (1ULL << 31)) { /* Paging enabled */
                u8 *insn = guest_va_to_hva(g_vmcb->save.cr3, g_vmcb->save.rip);
                if (insn) {
                    pr_info("[BOGGER]   INSN@RIP: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                            insn[0], insn[1], insn[2], insn[3],
                            insn[4], insn[5], insn[6], insn[7],
                            insn[8], insn[9], insn[10], insn[11],
                            insn[12], insn[13], insn[14], insn[15]);
                } else {
                    pr_info("[BOGGER]   INSN@RIP: page walk failed (CR3=0x%llx VA=0x%llx)\n",
                            g_vmcb->save.cr3, g_vmcb->save.rip);
                }
            }
            /* Dump guest GPRs at milestones for spinloop analysis */
            pr_info("[BOGGER]   GPRs: RAX=0x%llx RCX=0x%llx RDX=0x%llx RBX=0x%llx\n",
                    g_vmcb->save.rax, guest_gprs.rcx, guest_gprs.rdx, guest_gprs.rbx);
            pr_info("[BOGGER]   GPRs: RSP=0x%llx RBP=0x%llx RSI=0x%llx RDI=0x%llx\n",
                    g_vmcb->save.rsp, guest_gprs.rbp, guest_gprs.rsi, guest_gprs.rdi);
            pr_info("[BOGGER]   GPRs: R8=0x%llx R9=0x%llx R10=0x%llx R11=0x%llx\n",
                    guest_gprs.r8, guest_gprs.r9, guest_gprs.r10, guest_gprs.r11);
            /* Dump key IOAPIC redirection entries (0-3, 9=SCI, 11=NVMe) */
            {
                extern u64 ioapic_redir[];
                int ri;
                int key_irqs[] = {0, 1, 2, 3, 9, 11, 12};
                for (ri = 0; ri < 7; ri++) {
                    int idx = key_irqs[ri];
                    pr_info("[BOGGER]   IOAPIC redir[%d]=0x%016llx (vec=0x%02x mask=%d dest=0x%02x)\n",
                            idx, ioapic_redir[idx],
                            (u8)(ioapic_redir[idx] & 0xFF),
                            !!(ioapic_redir[idx] & (1ULL << 16)),
                            (u8)((ioapic_redir[idx] >> 56) & 0xFF));
                }
            }
            /* Always decode the current exit for diagnostics */
            if (exit_code == SVM_EXIT_IOIO) {
                u64 ii = g_vmcb->control.exit_info_1;
                pr_info("[BOGGER]   IOIO: %s port=0x%llx sz=%s RAX=0x%llx nRIP=0x%llx\n",
                        (ii & 1) ? "IN" : "OUT",
                        (ii >> 16) & 0xFFFF,
                        (ii & 0x40) ? "32" : (ii & 0x20) ? "16" : "8",
                        g_vmcb->save.rax,
                        g_vmcb->control.exit_info_2);
            } else if (exit_code == SVM_EXIT_NPF) {
                pr_info("[BOGGER]   NPF: GPA=0x%llx info1=0x%llx\n",
                        g_vmcb->control.exit_info_2,
                        g_vmcb->control.exit_info_1);
            } else if (exit_code != SVM_EXIT_INTR) {
                pr_info("[BOGGER]   exit_code=0x%x RFLAGS=0x%llx info1=0x%llx info2=0x%llx\n",
                        exit_code, g_vmcb->save.rflags,
                        g_vmcb->control.exit_info_1,
                        g_vmcb->control.exit_info_2);
            }

            /* At 10K milestone: scan guest RAM for EFI FV headers */
            if (exits == 10000 && guest_ram_virt) {
                u64 scan_addrs[] = { 0x800000, 0x900000, 0xA00000, 0x100000,
                                     0x200000, 0x300000, 0x400000, 0x7000000,
                                     0x7100000, 0x7F00000, 0x7E00000 };
                int si;
                printk(KERN_EMERG "[BOGGER] FV scan: checking guest RAM for decompressed DXEFV...\n");
                for (si = 0; si < (int)(sizeof(scan_addrs)/sizeof(scan_addrs[0])); si++) {
                    u64 addr = scan_addrs[si];
                    if (addr + 0x40 < guest_ram_size) {
                        u8 *p = (u8 *)guest_ram_virt + addr;
                        u32 sig = *(u32 *)(p + 0x28);
                        u32 fv_len = *(u32 *)(p + 0x20);
                        u16 hdr_len = *(u16 *)(p + 0x30);
                        pr_info("[BOGGER] FV @0x%llx: sig=0x%08x len=0x%x hdrlen=0x%x bytes[0..3]=%02x %02x %02x %02x\n",
                                addr, sig, fv_len, hdr_len, p[0], p[1], p[2], p[3]);
                    }
                }
                /* Also check if any FV signature exists by scanning every 64KB */
                {
                    int fv_found = 0;
                    u64 scan;
                    for (scan = 0; scan < guest_ram_size && scan < 0x10000000ULL; scan += 0x10000) {
                        u8 *p = (u8 *)guest_ram_virt + scan;
                        u32 sig = *(u32 *)(p + 0x28);
                        if (sig == 0x4856465F) { /* "_FVH" */
                            u32 fv_len = *(u32 *)(p + 0x20);
                            pr_info("[BOGGER] FV FOUND @GPA 0x%llx len=0x%x\n", scan, fv_len);
                            fv_found++;
                            if (fv_found >= 10) break;
                        }
                    }
                    if (!fv_found)
                        pr_warn("[BOGGER] NO FV found in first 256MB of guest RAM!\n");
                }
            }
        }

        /* ── Stuck detector: if guest is IF=0 with only INTR exits for too long ── */
        {
            static unsigned long consec_intr_only;
            static bool stuck_dumped;
            if (exit_code == SVM_EXIT_INTR &&
                !(g_vmcb->save.rflags & (1ULL << 9))) {
                consec_intr_only++;
            } else {
                consec_intr_only = 0;
                stuck_dumped = false;
            }
            if (consec_intr_only >= 50000 && !stuck_dumped && exits > 100000) {
                u8 *insn;
                stuck_dumped = true;
                pr_emerg("[BOGGER] STUCK DETECTED: %lu consecutive INTR-only exits with IF=0\n",
                         consec_intr_only);
                pr_emerg("[BOGGER]   RIP=0x%llx CR3=0x%llx RFLAGS=0x%llx GS.base=0x%llx\n",
                         g_vmcb->save.rip, g_vmcb->save.cr3, g_vmcb->save.rflags,
                         g_vmcb->save.gs.base);
                /* Dump PCI ring buffer — shows last 128 PCI accesses before crash */
                bogger_dump_pci_ring();
                /* Dump NVMe controller state at STUCK time */
                pr_emerg("[BOGGER]   NVMe: CC=0x%x CSTS=0x%x AQA=0x%x ASQ=0x%llx ACQ=0x%llx\n",
                         nvme_cc, nvme_csts, nvme_aqa, nvme_asq_base, nvme_acq_base);
                pr_emerg("[BOGGER]   NVMe: admin_cmds=%lu io_cmds=%lu msix_fire=%lu\n",
                         nvme_admin_cmd_count, nvme_io_cmd_count, nvme_msix_fire_count);
                {
                    int qi;
                    for (qi = 0; qi < NVME_MAX_IO_QUEUES; qi++) {
                        if (nvme_iocq_base[qi])
                            pr_emerg("[BOGGER]   NVMe IOQ[%d]: sq=0x%llx cq=0x%llx iv=%u ien=%d\n",
                                     qi+1, nvme_iosq_base[qi], nvme_iocq_base[qi],
                                     nvme_iocq_iv[qi], nvme_iocq_ien[qi]);
                    }
                }
                /* Decode instruction at RIP */
                insn = (g_vmcb->save.cr0 & (1ULL << 31))
                       ? guest_va_to_hva(g_vmcb->save.cr3, g_vmcb->save.rip)
                       : guest_gpa_to_hva(g_vmcb->save.rip);
                if (insn) {
                    pr_emerg("[BOGGER]   INSN[0..31]: %02x %02x %02x %02x %02x %02x %02x %02x"
                             " %02x %02x %02x %02x %02x %02x %02x %02x"
                             " %02x %02x %02x %02x %02x %02x %02x %02x"
                             " %02x %02x %02x %02x %02x %02x %02x %02x\n",
                             insn[0],insn[1],insn[2],insn[3],insn[4],insn[5],insn[6],insn[7],
                             insn[8],insn[9],insn[10],insn[11],insn[12],insn[13],insn[14],insn[15],
                             insn[16],insn[17],insn[18],insn[19],insn[20],insn[21],insn[22],insn[23],
                             insn[24],insn[25],insn[26],insn[27],insn[28],insn[29],insn[30],insn[31]);
                }
                /* Dump guest stack (top 8 qwords) */
                {
                    u64 *sp = (g_vmcb->save.cr0 & (1ULL << 31))
                              ? guest_va_to_hva(g_vmcb->save.cr3, g_vmcb->save.rsp)
                              : guest_gpa_to_hva(g_vmcb->save.rsp);
                    if (sp) {
                        pr_emerg("[BOGGER]   STACK[RSP]: %016llx %016llx %016llx %016llx\n",
                                 sp[0], sp[1], sp[2], sp[3]);
                        pr_emerg("[BOGGER]   STACK[+32]: %016llx %016llx %016llx %016llx\n",
                                 sp[4], sp[5], sp[6], sp[7]);
                    }
                }
                /* Read KUSER_SHARED_DATA at VA 0xFFFFF78000000000 — always mapped in Windows */
                {
                    u8 *kusd = guest_va_to_hva(g_vmcb->save.cr3, 0xFFFFF78000000000ULL);
                    if (kusd) {
                        u32 tick_lo = *(u32 *)(kusd + 0x320);
                        u32 tick_hi = *(u32 *)(kusd + 0x324);
                        u32 nt_major = *(u32 *)(kusd + 0x260);
                        u32 nt_minor = *(u32 *)(kusd + 0x264);
                        u32 build = *(u32 *)(kusd + 0x26C);
                        u32 active_cpus = *(u32 *)(kusd + 0x3C0);
                        u32 active_groups = *(u32 *)(kusd + 0x3C4);
                        u32 num_procs = *(u32 *)(kusd + 0x2A4);
                        pr_emerg("[BOGGER]   KUSD: TickCount=%u:%u NtMajor=%u NtMinor=%u Build=%u\n",
                                 tick_hi, tick_lo, nt_major, nt_minor, build);
                        pr_emerg("[BOGGER]   KUSD: ActiveProcs=%u ActiveGroups=%u NumberOfProcs=%u\n",
                                 active_cpus, active_groups, num_procs);
                    } else {
                        pr_emerg("[BOGGER]   KUSD: page walk failed for 0xFFFFF78000000000\n");
                    }
                }
                pr_emerg("[BOGGER]   GPRs: RAX=0x%llx RCX=0x%llx RDX=0x%llx RBX=0x%llx\n",
                         g_vmcb->save.rax, guest_gprs.rcx, guest_gprs.rdx, guest_gprs.rbx);
                pr_emerg("[BOGGER]   R8=0x%llx R9=0x%llx R10=0x%llx R11=0x%llx R12=0x%llx\n",
                         guest_gprs.r8, guest_gprs.r9, guest_gprs.r10, guest_gprs.r11, guest_gprs.r12);
                pr_emerg("[BOGGER]   R13=0x%llx R14=0x%llx R15=0x%llx\n",
                         guest_gprs.r13, guest_gprs.r14, guest_gprs.r15);
                pr_emerg("[BOGGER]   tmr_inj=%lu pending_irq=%d pending_vec=0x%02x\n",
                         timer_injects, !!pending_irq, pending_vec);
                pr_emerg("[BOGGER]   LAPIC: armed=%d LVT=0x%x ICR=0x%x DCR=0x%x pending=%d nmi=%d\n",
                         lapic_timer_armed, lapic_lvt_timer, lapic_timer_icr,
                         lapic_timer_dcr, lapic_timer_pending(), lapic_nmi_pending);
                /* KPRCB is EMBEDDED at KPCR+0x180, not a pointer.
                 * KPCR = GS.base, KPRCB = GS.base + 0x180 */
                {
                    u64 kprcb_va = g_vmcb->save.gs.base + 0x180;
                    u8 *kpcr = guest_va_to_hva(g_vmcb->save.cr3, g_vmcb->save.gs.base);
                    if (kpcr) {
                        u8 *kprcb = kpcr + 0x180; /* same page (offset < 0x1000) */
                        u32 val_210 = *(u32 *)(kprcb + 0x210);
                        u32 val_214 = *(u32 *)(kprcb + 0x214);
                        u32 val_3c  = *(u32 *)(kprcb + 0x3c);
                        u32 val_08  = *(u32 *)(kprcb + 0x08);
                        pr_emerg("[BOGGER]   KPRCB@0x%llx [+0x08]=0x%08x [+0x3c]=0x%08x [+0x210]=0x%08x [+0x214]=0x%08x\n",
                                 kprcb_va, val_08, val_3c, val_210, val_214);
                        /* Dump KPRCB[0x200..0x23F] for wider context */
                        {
                            u32 *p = (u32 *)(kprcb + 0x200);
                            pr_emerg("[BOGGER]   KPRCB[0x200..0x23F]: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
                                     p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
                                     p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15]);
                        }
                    } else {
                        pr_emerg("[BOGGER]   KPCR page walk FAILED: GS.base=0x%llx\n",
                                 g_vmcb->save.gs.base);
                    }
                }
                /* Resolve RIP-relative pointer from the stuck function.
                 * Look for `mov rax,[rip+disp32]` = 48 8B 05 XX XX XX XX
                 * in the function body to find the actual polled address. */
                {
                    u8 *fn = guest_va_to_hva(g_vmcb->save.cr3,
                                             g_vmcb->save.rip - 20);
                    if (fn) {
                        int i;
                        for (i = 0; i < 16; i++) {
                            if (fn[i] == 0x48 && fn[i+1] == 0x8B &&
                                (fn[i+2] == 0x05 || fn[i+2] == 0x15)) {
                                /* disp32 at fn[i+3..i+6] */
                                s32 disp32 = *(s32 *)(fn + i + 3);
                                u64 fn_va = g_vmcb->save.rip - 20 + i;
                                u64 next_va = fn_va + 7;
                                u64 eff = next_va + (s64)disp32;
                                u8 *ptr_hva = guest_va_to_hva(
                                    g_vmcb->save.cr3, eff);
                                if (ptr_hva) {
                                    u64 gptr = *(u64 *)ptr_hva;
                                    u64 poll_va = gptr + guest_gprs.rdx;
                                    u8 *poll_hva = guest_va_to_hva(
                                        g_vmcb->save.cr3, poll_va);
                                    pr_emerg("[BOGGER]   RESOLVED: [rip+0x%x]@0x%llx → ptr=0x%llx, [+0x%llx]=0x%llx\n",
                                             disp32, eff, gptr,
                                             guest_gprs.rdx, poll_va);
                                    if (poll_hva) {
                                        u32 *pp = (u32 *)poll_hva;
                                        pr_emerg("[BOGGER]   POLLED: [0x%llx]=%08x %08x %08x %08x\n",
                                                 poll_va, pp[0], pp[1],
                                                 pp[2], pp[3]);
                                    } else {
                                        /* Debug page walk for the polled VA */
                                        u64 cr3v = g_vmcb->save.cr3;
                                        u64 pml4e=0, pdpte=0, pde=0, pte=0;
                                        void *p;
                                        p = guest_gpa_to_hva((cr3v & ~0xFFFULL) + ((poll_va >> 39) & 0x1FF) * 8);
                                        if (p) pml4e = *(u64 *)p;
                                        pr_emerg("[BOGGER]   WALK[0x%llx]: PML4[%llu]=0x%llx %s\n",
                                                 poll_va, (poll_va >> 39) & 0x1FF, pml4e,
                                                 p ? ((pml4e & 1) ? "P" : "!P") : "NO-HVA");
                                        if (p && (pml4e & 1)) {
                                            u64 pdpt_gpa = (pml4e & 0x000FFFFFFFFFF000ULL) + ((poll_va >> 30) & 0x1FF) * 8;
                                            p = guest_gpa_to_hva(pdpt_gpa);
                                            if (p) pdpte = *(u64 *)p;
                                            pr_emerg("[BOGGER]   WALK: PDPT[%llu]@GPA0x%llx=0x%llx %s %s\n",
                                                     (poll_va >> 30) & 0x1FF, pdpt_gpa, pdpte,
                                                     p ? ((pdpte & 1) ? "P" : "!P") : "NO-HVA",
                                                     (pdpte & (1ULL << 7)) ? "1G" : "");
                                            if (p && (pdpte & 1) && !(pdpte & (1ULL << 7))) {
                                                u64 pd_gpa = (pdpte & 0x000FFFFFFFFFF000ULL) + ((poll_va >> 21) & 0x1FF) * 8;
                                                p = guest_gpa_to_hva(pd_gpa);
                                                if (p) pde = *(u64 *)p;
                                                pr_emerg("[BOGGER]   WALK: PD[%llu]@GPA0x%llx=0x%llx %s %s\n",
                                                         (poll_va >> 21) & 0x1FF, pd_gpa, pde,
                                                         p ? ((pde & 1) ? "P" : "!P") : "NO-HVA",
                                                         (pde & (1ULL << 7)) ? "2M" : "");
                                                if (p && (pde & 1) && (pde & (1ULL << 7))) {
                                                    /* 2MB page — compute GPA directly */
                                                    u64 gpa_2m = (pde & 0x000FFFFFFFE00000ULL) | (poll_va & 0x1FFFFFULL);
                                                    u8 *hva_2m = guest_gpa_to_hva(gpa_2m);
                                                    pr_emerg("[BOGGER]   WALK: 2M GPA=0x%llx HVA=%s\n",
                                                             gpa_2m, hva_2m ? "OK" : "NULL(out-of-range!)");
                                                    if (hva_2m) {
                                                        u32 *pp = (u32 *)hva_2m;
                                                        pr_emerg("[BOGGER]   POLLED (2M): [0x%llx]=%08x %08x %08x %08x\n",
                                                                 poll_va, pp[0], pp[1], pp[2], pp[3]);
                                                    }
                                                } else if (p && (pde & 1)) {
                                                    u64 pt_gpa = (pde & 0x000FFFFFFFFFF000ULL) + ((poll_va >> 12) & 0x1FF) * 8;
                                                    p = guest_gpa_to_hva(pt_gpa);
                                                    if (p) pte = *(u64 *)p;
                                                    pr_emerg("[BOGGER]   WALK: PT[%llu]@GPA0x%llx=0x%llx %s\n",
                                                             (poll_va >> 12) & 0x1FF, pt_gpa, pte,
                                                             p ? ((pte & 1) ? "P" : "!P") : "NO-HVA");
                                                    if (p && (pte & 1)) {
                                                        u64 final_gpa = (pte & 0x000FFFFFFFFFF000ULL) | (poll_va & 0xFFFULL);
                                                        u8 *final_hva = guest_gpa_to_hva(final_gpa);
                                                        pr_emerg("[BOGGER]   WALK: 4K GPA=0x%llx HVA=%s\n",
                                                                 final_gpa, final_hva ? "OK" : "NULL");
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
                /* Dump caller code at return address [RSP] for call-loop analysis */
                {
                    u64 *sp = (g_vmcb->save.cr0 & (1ULL << 31))
                              ? guest_va_to_hva(g_vmcb->save.cr3, g_vmcb->save.rsp)
                              : guest_gpa_to_hva(g_vmcb->save.rsp);
                    if (sp) {
                        u64 ret_addr = sp[0];
                        /* Dump 64 bytes from ret_addr-32 to see the CALL and surrounding code */
                        u8 *caller = guest_va_to_hva(g_vmcb->save.cr3, ret_addr - 32);
                        if (caller) {
                            pr_emerg("[BOGGER]   CALLER[ret-32..ret+31] at 0x%llx:\n", ret_addr - 32);
                            pr_emerg("[BOGGER]     %02x %02x %02x %02x %02x %02x %02x %02x"
                                     " %02x %02x %02x %02x %02x %02x %02x %02x"
                                     " %02x %02x %02x %02x %02x %02x %02x %02x"
                                     " %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                     caller[0],caller[1],caller[2],caller[3],
                                     caller[4],caller[5],caller[6],caller[7],
                                     caller[8],caller[9],caller[10],caller[11],
                                     caller[12],caller[13],caller[14],caller[15],
                                     caller[16],caller[17],caller[18],caller[19],
                                     caller[20],caller[21],caller[22],caller[23],
                                     caller[24],caller[25],caller[26],caller[27],
                                     caller[28],caller[29],caller[30],caller[31]);
                            pr_emerg("[BOGGER]     %02x %02x %02x %02x %02x %02x %02x %02x"
                                     " %02x %02x %02x %02x %02x %02x %02x %02x"
                                     " %02x %02x %02x %02x %02x %02x %02x %02x"
                                     " %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                     caller[32],caller[33],caller[34],caller[35],
                                     caller[36],caller[37],caller[38],caller[39],
                                     caller[40],caller[41],caller[42],caller[43],
                                     caller[44],caller[45],caller[46],caller[47],
                                     caller[48],caller[49],caller[50],caller[51],
                                     caller[52],caller[53],caller[54],caller[55],
                                     caller[56],caller[57],caller[58],caller[59],
                                     caller[60],caller[61],caller[62],caller[63]);
                        }
                    }
                }
                /* Also dump the called function (RIP-16..RIP+48) for spinloop analysis */
                {
                    u8 *fn = guest_va_to_hva(g_vmcb->save.cr3, g_vmcb->save.rip - 16);
                    if (fn) {
                        pr_emerg("[BOGGER]   FN[rip-16..rip+47]:\n");
                        pr_emerg("[BOGGER]     %02x %02x %02x %02x %02x %02x %02x %02x"
                                 " %02x %02x %02x %02x %02x %02x %02x %02x"
                                 " | %02x %02x %02x %02x %02x %02x %02x %02x"
                                 " %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                 fn[0],fn[1],fn[2],fn[3],fn[4],fn[5],fn[6],fn[7],
                                 fn[8],fn[9],fn[10],fn[11],fn[12],fn[13],fn[14],fn[15],
                                 fn[16],fn[17],fn[18],fn[19],fn[20],fn[21],fn[22],fn[23],
                                 fn[24],fn[25],fn[26],fn[27],fn[28],fn[29],fn[30],fn[31]);
                        pr_emerg("[BOGGER]     %02x %02x %02x %02x %02x %02x %02x %02x"
                                 " %02x %02x %02x %02x %02x %02x %02x %02x"
                                 " %02x %02x %02x %02x %02x %02x %02x %02x"
                                 " %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                 fn[32],fn[33],fn[34],fn[35],fn[36],fn[37],fn[38],fn[39],
                                 fn[40],fn[41],fn[42],fn[43],fn[44],fn[45],fn[46],fn[47],
                                 fn[48],fn[49],fn[50],fn[51],fn[52],fn[53],fn[54],fn[55],
                                 fn[56],fn[57],fn[58],fn[59],fn[60],fn[61],fn[62],fn[63]);
                    }
                }
                /* Dump VMEXIT ring (last 16 non-INTR entries) */
                {
                    unsigned int ri = vmexit_ring_idx;
                    int j, shown = 0;
                    pr_emerg("[BOGGER]   VMEXIT ring (recent non-INTR):\n");
                    for (j = 0; j < VMEXIT_RING_SIZE && shown < 16; j++) {
                        unsigned int idx = (ri - 1 - j) % VMEXIT_RING_SIZE;
                        if (vmexit_ring[idx].exit_code == 0 && vmexit_ring[idx].rip == 0)
                            continue;
                        if (vmexit_ring[idx].exit_code == SVM_EXIT_INTR)
                            continue;
                        pr_emerg("[BOGGER]     [-%d] code=0x%x rip=0x%llx IF=%d inj=0x%x\n",
                                 j,
                                 vmexit_ring[idx].exit_code,
                                 vmexit_ring[idx].rip,
                                 !!(vmexit_ring[idx].rflags & (1ULL << 9)),
                                 vmexit_ring[idx].event_inj);
                        shown++;
                    }
                }
            }

            /* Force-break the stuck state by enabling IF.
             * After the diagnostic dump, if the guest is STILL stuck
             * with IF=0, force IF=1 to allow interrupt delivery.
             * This breaks deadlocks where the guest is CLI-spinning
             * waiting for a self-IPI or timer that can't fire without
             * IF=1.  Also re-arm the LAPIC timer to guarantee there's
             * a pending interrupt to deliver.
             * We retry every 10K additional INTR exits. */
            if (consec_intr_only >= 60000 &&
                (consec_intr_only % 10000) == 0) {
                static int force_if_count;
                if (force_if_count < 10) {
                    g_vmcb->save.rflags |= (1ULL << 9);  /* Force IF=1 */
                    /* Ensure there's a pending timer interrupt to inject */
                    if (!pending_irq && lapic_timer_icr != 0) {
                        u8 tvec = (u8)(lapic_lvt_timer & 0xFF);
                        if (tvec >= 0x20 && !(lapic_lvt_timer & (1U << 16))) {
                            pending_irq = true;
                            pending_vec = tvec;
                            lapic_set_irr(tvec);
                            lapic_timer_armed = true;
                            lapic_timer_start_ns = ktime_get_ns();
                        }
                    }
                    pr_warn("[BOGGER] FORCE IF=1 #%d: pending=%d vec=0x%02x at RIP=0x%llx\n",
                            ++force_if_count, !!pending_irq, pending_vec,
                            g_vmcb->save.rip);
                }
            }
        }

        /* Count exit types for milestone logging */
        if (exit_code == SVM_EXIT_INTR)
            { intr_exits++; goto handle_exit; }
        else if (exit_code == SVM_EXIT_HLT) {
            static int first_hlt_logged;
            if (!first_hlt_logged) {
                extern unsigned long pci_total_writes;
                printk(KERN_EMERG "[BOGGER] FIRST HLT #%d io=%lu npf=%lu\n",
                        exits, ioio_exits, npf_exits);
                printk(KERN_EMERG "[BOGGER] fw511=%lu pciwr=%lu RIP=0x%llx\n",
                        fwcfg_port511_reads, pci_total_writes, g_vmcb->save.rip);
                printk(KERN_EMERG "[BOGGER] NVMe IO cmds=%lu MSI-X enabled=%d pending=%d\n",
                        nvme_io_cmd_count, nvme_msix_enabled ? 1 : 0,
                        atomic_read(&nvme_irq_pending_flag));
                bogger_dump_pci_ring();

                /* Inject Enter key after BDS idle — if OVMF shows
                 * a boot device menu, this selects the first entry.
                 * Also inject Escape first to dismiss any popup. */
                bogger_ps2_inject_key(0x01, 0x81);  /* Escape */
                bogger_ps2_inject_enter();
                pr_info("[BOGGER] PS/2: injected Esc+Enter after FIRST HLT\n");

                first_hlt_logged = 1;
            }
            /* Periodic re-injection: every ~2K HLTs, inject Enter
             * to keep trying in case OVMF needs multiple attempts. */
            if (hlt_exits > 0 && (hlt_exits % 2000) == 0 && hlt_exits <= 10000) {
                bogger_ps2_inject_enter();
            }
            hlt_exits++;
        }
        else if (exit_code == SVM_EXIT_NPF)
            npf_exits++;
        else if (exit_code == SVM_EXIT_IOIO)
            ioio_exits++;

        if (exits <= max_logged) {
            if (exit_code == SVM_EXIT_NPF) {
                pr_info("[BOGGER] VMEXIT #%d: NPF RIP=0x%llx GPA=0x%llx info1=0x%llx (W=%d P=%d)\n",
                        exits, g_vmcb->save.rip,
                        g_vmcb->control.exit_info_2,
                        g_vmcb->control.exit_info_1,
                        !!(g_vmcb->control.exit_info_1 & 0x02),
                        !!(g_vmcb->control.exit_info_1 & 0x01));
            } else if (exit_code == SVM_EXIT_IOIO) {
                u64 ii = g_vmcb->control.exit_info_1;
                pr_info("[BOGGER] VMEXIT #%d: IOIO %s port=0x%llx RIP=0x%llx RAX=0x%llx\n",
                        exits,
                        (ii & 1) ? "IN" : "OUT",
                        (ii >> 16) & 0xFFFF,
                        g_vmcb->save.rip,
                        g_vmcb->save.rax);
            } else {
                pr_info("[BOGGER] VMEXIT #%d: code=0x%x RIP=0x%llx\n",
                        exits, exit_code, g_vmcb->save.rip);
            }
        }

        /* Log exits after a reset to track post-reset boot progress */
        if (had_reset && post_reset_logged < 30 && exit_code != SVM_EXIT_INTR) {
            pr_info("[BOGGER] POST-RESET #%d: code=0x%x RIP=0x%llx\n",
                    post_reset_logged, exit_code, g_vmcb->save.rip);
            post_reset_logged++;
        }

handle_exit:
        switch (exit_code) {

        case BOGGER_SVM_EXIT_INVALID:
            pr_emerg("[BOGGER] VMEXIT INVALID at RIP=0x%llx\n", g_vmcb->save.rip);
            goto done;

        case SVM_EXIT_INTR:
        case SVM_EXIT_VINTR:
            break;

        case SVM_EXIT_HLT: {
            /* HLT: guest is waiting for an interrupt.
             * Wait until an actual interrupt source fires before waking
             * the guest.  This avoids spurious wakeups that cause tight
             * HLT→wake→HLT loops consuming 90%+ of exits.
             *
             * Primary source: LAPIC timer (fires every ~10ms in OVMF).
             * Fallback: PIT timer if IRQ0 is unmasked in PIC.
             * Also check: NVMe MSI-X and GPU MSI for interrupt-driven I/O.
             * Safety: max 50ms wait to avoid soft lockup. */
            int wait_us = 0;
            while (wait_us < 50000) {
                if (lapic_timer_pending())
                    break;
                /* PIT IRQ0 unmasked → timer available as interrupt source */
                if (!(pic_master.imr & 0x01) && pic_master.vector_base >= 0x20)
                    break;
                /* NVMe MSI-X completion pending → wake to deliver interrupt */
                if (atomic_read(&nvme_irq_pending_flag))
                    break;
                /* GPU passthrough MSI pending → wake for display/GPU events */
                if (atomic_read(&bogger_pt_irq_pending))
                    break;
                if (kthread_should_stop()) goto done;
                usleep_range(100, 500);
                wait_us += 300;
                hpet_update_counter();
            }
            g_vmcb->save.rip += 1;
            break;
        }

        case SVM_EXIT_IOIO: {
            u64 saved_rip = g_vmcb->save.rip;
            bogger_npt_dirty_from_ioio = false;
            bogger_handle_ioio(g_vmcb, exits, max_logged);
            if (g_vmcb->save.rip == 0) goto done;  /* shutdown signal */
            /* Detect VMCB reset (ioport reset handler sets RIP=0xFFF0) */
            if (g_vmcb->save.rip == 0xFFF0 && saved_rip != 0xFFF0) {
                had_reset = true;
                post_reset_logged = 0;
            }
            /* Flush TLB if PCI config write modified NPT entries.
             * Without this, stale zero-page TLB entries in the MMIO hole
             * prevent the guest from accessing GPU BAR regions after OVMF
             * assigns new BAR addresses via PCI config writes. */
            if (bogger_npt_dirty_from_ioio) {
                g_vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
                bogger_npt_dirty_from_ioio = false;
            }
            (void)saved_rip;
            break;
        }

        case SVM_EXIT_CPUID:
            bogger_handle_cpuid_stealth(g_vmcb, &guest_gprs);
            break;

        case SVM_EXIT_MSR:
            if (g_vmcb->control.exit_info_1 == 0)
                bogger_handle_rdmsr_stealth(g_vmcb, &guest_gprs);
            else
                bogger_handle_wrmsr_stealth(g_vmcb, &guest_gprs);
            break;

        case SVM_EXIT_INIT:
            break;

        /* ── Generic exception intercept (vectors 0-31, exit codes 0x40-0x5f) ── */
        case 0x40 ... 0x5f: {
            u32 exc_vec = exit_code - 0x40;
            u64 err_code = g_vmcb->control.exit_info_1;
            bool has_ec = !!(has_errcode_mask & (1U << exc_vec));

            /* #DF (8): dump extensive diagnostics + ring buffer, re-inject */
            if (exc_vec == 8) {
                static int df_count;
                unsigned int ri, j;

                df_count++;
                pr_emerg("[BOGGER] #DF #%d RIP=0x%llx err=0x%llx RSP=0x%llx CR2=0x%llx\n",
                         df_count, g_vmcb->save.rip, err_code, g_vmcb->save.rsp,
                         g_vmcb->save.cr2);
                pr_emerg("[BOGGER] #DF CR3=0x%llx EFER=0x%llx CR0=0x%llx CR4=0x%llx\n",
                         g_vmcb->save.cr3, g_vmcb->save.efer,
                         g_vmcb->save.cr0, g_vmcb->save.cr4);
                pr_emerg("[BOGGER] #DF IDTR base=0x%llx limit=0x%x\n",
                         g_vmcb->save.idtr.base, g_vmcb->save.idtr.limit);
                pr_emerg("[BOGGER] #DF GDTR base=0x%llx limit=0x%x\n",
                         g_vmcb->save.gdtr.base, g_vmcb->save.gdtr.limit);
                pr_emerg("[BOGGER] #DF event_inj=0x%x event_inj_err=0x%x\n",
                         g_vmcb->control.event_inj, g_vmcb->control.event_inj_err);
                pr_emerg("[BOGGER] #DF CS.sel=0x%x CS.base=0x%llx SS.sel=0x%x SS.base=0x%llx\n",
                         g_vmcb->save.cs.selector, g_vmcb->save.cs.base,
                         g_vmcb->save.ss.selector, g_vmcb->save.ss.base);
                pr_emerg("[BOGGER] #DF RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx\n",
                         g_vmcb->save.rax, guest_gprs.rbx, guest_gprs.rcx, guest_gprs.rdx);
                pr_emerg("[BOGGER] #DF R8=0x%llx R9=0x%llx RSI=0x%llx RDI=0x%llx\n",
                         guest_gprs.r8, guest_gprs.r9, guest_gprs.rsi, guest_gprs.rdi);

                /* Dump VMEXIT ring buffer — last N exits before this #DF */
                pr_emerg("[BOGGER] #DF VMEXIT ring buffer (last %d exits):\n",
                         VMEXIT_RING_SIZE);
                ri = vmexit_ring_idx;
                for (j = 0; j < VMEXIT_RING_SIZE; j++) {
                    unsigned int idx = (ri - VMEXIT_RING_SIZE + j) % VMEXIT_RING_SIZE;
                    if (vmexit_ring[idx].exit_code == 0 && vmexit_ring[idx].rip == 0)
                        continue;
                    pr_emerg("[BOGGER]   [-%u] exit=0x%x RIP=0x%llx info1=0x%llx info2=0x%llx\n",
                             VMEXIT_RING_SIZE - j,
                             vmexit_ring[idx].exit_code,
                             vmexit_ring[idx].rip,
                             vmexit_ring[idx].info1,
                             vmexit_ring[idx].info2);
                }

                /* Re-inject #DF to the guest — let Windows BSOD (IST-based #DF handler) */
                if (df_count >= 3) {
                    pr_emerg("[BOGGER] #DF count reached %d — aborting\n", df_count);
                    goto done;
                }
                QUEUE_EXCEPTION(8, 3, 1, 0);  /* #DF with error code 0 */
                break;
            }
            /* #MC (18): fatal */
            if (exc_vec == 18) {
                pr_emerg("[BOGGER] #MC RIP=0x%llx\n", g_vmcb->save.rip);
                goto done;
            }

            /* We no longer intercept #GP (bit 13) — OVMF handles its own
             * #GPs through its IDT (including FXSAVE alignment faults).
             * If we somehow still get a #GP VMEXIT (e.g., from KVM nested
             * routing or future bitmap changes), re-inject it to the guest.
             *
             * For any intercepted exception: log + re-inject to the guest
             * so its own IDT handler runs. */
            if (exc_log_count < 50) {
                pr_warn("[BOGGER] EXC %u(%s) RIP=0x%llx err=0x%llx RSP=0x%llx CR2=0x%llx\n",
                        exc_vec, exc_names[exc_vec],
                        g_vmcb->save.rip, err_code,
                        g_vmcb->save.rsp, g_vmcb->save.cr2);
                exc_log_count++;
            }
            QUEUE_EXCEPTION(exc_vec, 3, has_ec ? 1 : 0, has_ec ? (u32)err_code : 0);
            break;
        }
        case SVM_EXIT_VMRUN:
            QUEUE_EXCEPTION(13, 3, 1, 0);  /* inject #GP(0) */
            break;

        case SVM_EXIT_SHUTDOWN: {
            unsigned int ri, j;
            pr_emerg("[BOGGER] === TRIPLE FAULT ===\n");
            pr_emerg("[BOGGER] RIP=0x%llx RSP=0x%llx RFLAGS=0x%llx\n",
                     g_vmcb->save.rip, g_vmcb->save.rsp, g_vmcb->save.rflags);
            pr_emerg("[BOGGER] CR0=0x%llx CR2=0x%llx CR3=0x%llx CR4=0x%llx\n",
                     g_vmcb->save.cr0, g_vmcb->save.cr2,
                     g_vmcb->save.cr3, g_vmcb->save.cr4);
            pr_emerg("[BOGGER] EFER=0x%llx CS.sel=0x%x CS.base=0x%llx\n",
                     g_vmcb->save.efer, g_vmcb->save.cs.selector,
                     g_vmcb->save.cs.base);
            pr_emerg("[BOGGER] SS.sel=0x%x SS.base=0x%llx DS.sel=0x%x\n",
                     g_vmcb->save.ss.selector, g_vmcb->save.ss.base,
                     g_vmcb->save.ds.selector);
            pr_emerg("[BOGGER] GS.base=0x%llx FS.base=0x%llx TR.sel=0x%x\n",
                     g_vmcb->save.gs.base, g_vmcb->save.fs.base,
                     g_vmcb->save.tr.selector);
            pr_emerg("[BOGGER] TR.base=0x%llx TR.limit=0x%x\n",
                     g_vmcb->save.tr.base, g_vmcb->save.tr.limit);
            pr_emerg("[BOGGER] IDTR.base=0x%llx IDTR.limit=0x%x\n",
                     g_vmcb->save.idtr.base, g_vmcb->save.idtr.limit);
            pr_emerg("[BOGGER] GDTR.base=0x%llx GDTR.limit=0x%x\n",
                     g_vmcb->save.gdtr.base, g_vmcb->save.gdtr.limit);
            pr_emerg("[BOGGER] STAR=0x%llx LSTAR=0x%llx CSTAR=0x%llx SFMASK=0x%llx\n",
                     g_vmcb->save.star, g_vmcb->save.lstar,
                     g_vmcb->save.cstar, g_vmcb->save.sfmask);
            pr_emerg("[BOGGER] KERNEL_GS_BASE=0x%llx SYSENTER_CS=0x%llx\n",
                     g_vmcb->save.kernel_gs_base,
                     g_vmcb->save.sysenter_cs);
            pr_emerg("[BOGGER] SYSENTER_ESP=0x%llx SYSENTER_EIP=0x%llx\n",
                     g_vmcb->save.sysenter_esp,
                     g_vmcb->save.sysenter_eip);
            pr_emerg("[BOGGER] RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx\n",
                     g_vmcb->save.rax, guest_gprs.rbx,
                     guest_gprs.rcx, guest_gprs.rdx);
            pr_emerg("[BOGGER] RSI=0x%llx RDI=0x%llx RBP=0x%llx\n",
                     guest_gprs.rsi, guest_gprs.rdi, guest_gprs.rbp);
            pr_emerg("[BOGGER] R8=0x%llx R9=0x%llx R10=0x%llx R11=0x%llx\n",
                     guest_gprs.r8, guest_gprs.r9,
                     guest_gprs.r10, guest_gprs.r11);
            pr_emerg("[BOGGER] R12=0x%llx R13=0x%llx R14=0x%llx R15=0x%llx\n",
                     guest_gprs.r12, guest_gprs.r13,
                     guest_gprs.r14, guest_gprs.r15);
            pr_emerg("[BOGGER] exit_info1=0x%llx exit_info2=0x%llx int_ctl=0x%x\n",
                     g_vmcb->control.exit_info_1,
                     g_vmcb->control.exit_info_2,
                     g_vmcb->control.int_ctl);
            pr_emerg("[BOGGER] event_inj=0x%x exit_int_info=0x%x\n",
                     g_vmcb->control.event_inj,
                     g_vmcb->control.exit_int_info);

            /* Dump VMEXIT ring buffer — last N exits before triple fault */
            pr_emerg("[BOGGER] VMEXIT ring buffer (last %d exits):\n",
                     VMEXIT_RING_SIZE);
            ri = vmexit_ring_idx;
            for (j = 0; j < VMEXIT_RING_SIZE; j++) {
                unsigned int idx = (ri - VMEXIT_RING_SIZE + j) % VMEXIT_RING_SIZE;
                if (vmexit_ring[idx].exit_code == 0 && vmexit_ring[idx].rip == 0)
                    continue;
                pr_emerg("[BOGGER]   [-%u] exit=0x%x evtinj=0x%x RIP=0x%llx info1=0x%llx info2=0x%llx\n",
                         VMEXIT_RING_SIZE - j,
                         vmexit_ring[idx].exit_code,
                         vmexit_ring[idx].event_inj,
                         vmexit_ring[idx].rip,
                         vmexit_ring[idx].info1,
                         vmexit_ring[idx].info2);
            }
            goto done;
        }

        case SVM_EXIT_NPF: {
            u64 gpa  = g_vmcb->control.exit_info_2;
            u64 info = g_vmcb->control.exit_info_1;

            /* HPET — mapped read-only (0x05), writes trap via NPF.
             * Guest reads go directly to backing page, so we must keep
             * the main counter (0xF0) updated on the backing page after
             * every write NPF to avoid stale counter reads. */
            if ((gpa & ~0xFFFULL) == HPET_GPA) {
                hpet_update_counter();
                if (info & 0x02) {
                    /* Write to HPET register — emulate */
                    u32 offset = (u32)(gpa & 0xFFF) & ~3U;
                    u32 cur = hpet_regs ? hpet_regs[offset / 4] : 0;
                    u32 wval;
                    if (emulate_mmio_store(&wval, cur)) {
                        static int hpet_write_log;
                        if (hpet_write_log < 30) {
                            pr_info("[BOGGER] HPET W[0x%03x]=0x%08x (was 0x%08x) RIP=0x%llx\n",
                                    offset, wval, cur, g_vmcb->save.rip);
                            hpet_write_log++;
                        }
                        if (hpet_regs)
                            hpet_regs[offset / 4] = wval;
                    } else {
                        static int hpet_fail;
                        if (hpet_fail < 5)
                            pr_warn("[BOGGER] HPET MMIO decode failed RIP=0x%llx GPA=0x%llx\n",
                                    g_vmcb->save.rip, gpa);
                        hpet_fail++;
                    }
                }
                g_vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
                break;
            }

            /* LAPIC write trap — decode instruction instead of single-step */
            if ((gpa & ~0xFFFULL) == LAPIC_GPA && (info & 0x02)) {
                u32 offset = (u32)(gpa & 0xFFF) & ~3U;
                u32 cur = lapic_regs ? lapic_regs[offset / 4] : 0;
                u32 wval;
                if (emulate_mmio_store(&wval, cur)) {
                    /* Log writes to key LAPIC registers for debugging */
                    if (offset == 0x320 || offset == 0x380 || offset == 0x3E0) {
                        static int lapic_log_count;
                        if (lapic_log_count < 20) {
                            u8 *ic = (g_vmcb->save.cr0 & (1ULL << 31))
                                     ? guest_va_to_hva(g_vmcb->save.cr3, g_vmcb->save.rip)
                                     : guest_gpa_to_hva(g_vmcb->save.rip);
                            pr_info("[BOGGER] LAPIC W[0x%03x]=0x%08x (was 0x%08x) RIP=0x%llx insn=%02x%02x%02x%02x%02x%02x%02x%02x\n",
                                    offset, wval, cur, g_vmcb->save.rip,
                                    ic?ic[0]:0,ic?ic[1]:0,ic?ic[2]:0,ic?ic[3]:0,
                                    ic?ic[4]:0,ic?ic[5]:0,ic?ic[6]:0,ic?ic[7]:0);
                            lapic_log_count++;
                        }
                    }
                    lapic_mmio_write(offset, wval);
                } else {
                    static int mmio_fail_count;
                    if (mmio_fail_count < 10) {
                        u8 *fcode = (g_vmcb->save.cr0 & (1ULL << 31))
                                    ? guest_va_to_hva(g_vmcb->save.cr3, g_vmcb->save.rip)
                                    : guest_gpa_to_hva(g_vmcb->save.rip);
                        pr_warn("[BOGGER] LAPIC MMIO decode failed RIP=0x%llx GPA=0x%llx\n",
                                g_vmcb->save.rip, gpa);
                        if (fcode)
                            pr_warn("[BOGGER]   INSN: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                    fcode[0],fcode[1],fcode[2],fcode[3],
                                    fcode[4],fcode[5],fcode[6],fcode[7]);
                        mmio_fail_count++;
                    }
                    /* Inject #UD — safer than blindly advancing RIP */
                    QUEUE_EXCEPTION(6, 3, 0, 0);
                }
                if (lapic_regs) lapic_regs[LAPIC_REG_TIMER_CCR / 4] = lapic_read_ccr();
                g_vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
                break;
            }
            /* LAPIC read — update CCR for guest */
            if ((gpa & ~0xFFFULL) == LAPIC_GPA) {
                if (lapic_regs) lapic_regs[LAPIC_REG_TIMER_CCR / 4] = lapic_read_ccr();
                g_vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
                break;
            }

            /* IOAPIC write/read trap — decode MOV instead of single-step.
             *
             * The IOAPIC page is mapped read-only (NPT flags=0x05) so writes
             * cause NPF while reads go directly to the backing page.  The
             * IOAPIC uses a register-select/data-window model: guest writes
             * IOREGSEL (offset 0x00) to select a register, then reads/writes
             * IOWIN (offset 0x10) to access it.  Since reads don't trap, we
             * MUST update the IOWIN value on the backing page every time
             * IOREGSEL changes, otherwise the guest reads stale data. */
            if ((gpa & ~0xFFFULL) == IOAPIC_GPA) {
                u32 offset = (u32)(gpa & 0xFFF) & ~3U;
                if (info & 0x02) {
                    u32 cur = ioapic_regs ? ioapic_regs[offset / 4] : 0;
                    u32 wval;
                    if (emulate_mmio_store(&wval, cur)) {
                        ioapic_mmio_write(offset, wval);
                        /* Update backing page for subsequent guest reads.
                         * CRITICAL: When IOREGSEL changes, we must also refresh
                         * the IOWIN slot so the next guest read (which doesn't
                         * trap) returns the correct register value. */
                        if (ioapic_regs) {
                            if (offset == 0x00) {
                                ioapic_regs[0] = ioapic_regsel;
                                /* Refresh IOWIN for the newly selected register */
                                ioapic_regs[0x10/4] = ioapic_read_reg(ioapic_regsel);
                                /* Ensure cache coherency for UC guest reads */
                                clflush(&ioapic_regs[0]);
                                clflush(&ioapic_regs[0x10/4]);
                            } else if (offset == 0x10) {
                                ioapic_regs[0x10/4] = ioapic_read_reg(ioapic_regsel);
                                clflush(&ioapic_regs[0x10/4]);
                            }
                        }
                    } else {
                        static int ioapic_fail;
                        if (ioapic_fail < 10) {
                            u8 *fc = (g_vmcb->save.cr0 & (1ULL << 31))
                                     ? guest_va_to_hva(g_vmcb->save.cr3, g_vmcb->save.rip)
                                     : guest_gpa_to_hva(g_vmcb->save.rip);
                            pr_warn("[BOGGER] IOAPIC MMIO decode failed RIP=0x%llx GPA=0x%llx off=0x%x\n",
                                    g_vmcb->save.rip, gpa, offset);
                            if (fc)
                                pr_warn("[BOGGER]   INSN: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                        fc[0],fc[1],fc[2],fc[3],fc[4],fc[5],fc[6],fc[7]);
                            ioapic_fail++;
                        }
                        QUEUE_EXCEPTION(6, 3, 0, 0);
                    }
                } else {
                    /* Read trap (shouldn't normally happen with R/O mapping,
                     * but handle it just in case) */
                    if (ioapic_regs) ioapic_regs[0x10/4] = ioapic_read_reg(ioapic_regsel);
                }
                g_vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
                break;
            }

            /* NVMe BAR (address may be relocated by guest PCI driver) */
            if (gpa >= nvme_bar_active_gpa && gpa < nvme_bar_active_gpa + NVME_BAR_SIZE) {
                u32 nvme_off = (u32)(gpa - nvme_bar_active_gpa);
                u32 nvme_page_idx = nvme_off >> PAGE_SHIFT;
                if ((info & 0x02) && nvme_page_idx < 4) {
                    /* Write to NVMe BAR — decode instruction */
                    u32 cur = nvme_regs ? nvme_regs[nvme_off / 4] : 0;
                    u32 wval;
                    if (emulate_mmio_store(&wval, cur)) {
                        /* Log NVMe BAR writes (first 500) */
                        {
                            static int nvme_bar_wr_log;
                            if (nvme_bar_wr_log < 500) {
                                pr_info("[BOGGER-NVMe] BAR WRITE off=0x%04x val=0x%08x (was 0x%08x)\n",
                                        nvme_off, wval, cur);
                                nvme_bar_wr_log++;
                            }
                        }
                        /* Write decoded value to NVMe backing page */
                        if (nvme_regs)
                            nvme_regs[nvme_off / 4] = wval;

                        /* Process NVMe register writes */
                        if (nvme_regs) {
                            if (nvme_off >= 0x14 && nvme_off < 0x18)
                                nvme_cc = nvme_regs[0x14/4];
                            if (nvme_off >= 0x24 && nvme_off < 0x28)
                                nvme_aqa = nvme_regs[0x24/4];
                            if (nvme_off >= 0x28 && nvme_off < 0x30)
                                nvme_asq_base = (u64)nvme_regs[0x28/4] | ((u64)nvme_regs[0x2C/4] << 32);
                            if (nvme_off >= 0x30 && nvme_off < 0x38)
                                nvme_acq_base = (u64)nvme_regs[0x30/4] | ((u64)nvme_regs[0x34/4] << 32);
                            nvme_update_regs();

                            /* Detect MSI-X table writes (offset 0x2000-0x203F).
                             * When guest writes Message Data with valid vector,
                             * auto-enable MSI-X even if PCI config enable was missed. */
                            if (nvme_off >= 0x2000 && nvme_off < 0x2040) {
                                static int msix_tbl_log;
                                if (msix_tbl_log < 20) {
                                    pr_info("[BOGGER-NVMe] MSI-X TBL write off=0x%04x val=0x%08x\n",
                                            nvme_off, wval);
                                    msix_tbl_log++;
                                }
                                /* Check if this is a Message Data write (offset +8 within entry) */
                                if ((nvme_off & 0xF) == 0x08 && (wval & 0xFF) >= 0x20) {
                                    if (!nvme_msix_enabled) {
                                        nvme_msix_enabled = true;
                                        pr_info("[BOGGER-NVMe] MSI-X auto-enabled: guest wrote valid vec=0x%x in table\n",
                                                wval & 0xFF);
                                    }
                                }
                            }
                        }
                    } else {
                        static int nvme_mmio_fail;
                        if (nvme_mmio_fail < 20) {
                            u8 *fc = (g_vmcb->save.cr0 & (1ULL << 31))
                                     ? guest_va_to_hva(g_vmcb->save.cr3, g_vmcb->save.rip)
                                     : guest_gpa_to_hva(g_vmcb->save.rip);
                            pr_warn("[BOGGER] NVMe BAR MMIO decode failed RIP=0x%llx off=0x%04x\n",
                                    g_vmcb->save.rip, nvme_off);
                            if (fc)
                                pr_warn("[BOGGER]   INSN: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                        fc[0],fc[1],fc[2],fc[3],fc[4],fc[5],fc[6],fc[7]);
                            nvme_mmio_fail++;
                        }
                        QUEUE_EXCEPTION(6, 3, 0, 0);
                    }
                }
                /* Poll admin doorbells from NPF handler (lightweight).
                 * I/O doorbells are polled at the top of the VMRUN loop
                 * to keep kernel_read() off the NPF call stack. */
                if (nvme_csts & 1) {
                    nvme_poll_doorbell();
                }
                g_vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
                break;
            }

            /* GPU Passthrough BAR — lazy NPT mapping for guest-assigned addresses.
             * On first access, resolve_npf maps the ENTIRE BAR into NPT
             * so subsequent accesses go through without VMEXITs. */
            {
                u64 pt_hpa;
                if (bogger_pci_passthrough_resolve_npf(gpa, &pt_hpa)) {
                    g_vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
                    break;
                }
            }

            /* Generic NPF — try to map a zero page instead of crashing */
            {
                unsigned int pd_idx = (unsigned int)(gpa >> 30);
                unsigned int pd_e   = (unsigned int)((gpa >> 21) & 0x1FF);
                static int npf_unmapped_count;

                if (pd_idx >= NPT_NUM_PD_TABLES) {
                    /* GPA completely out of range — log and try to continue */
                    if (npf_unmapped_count < 10)
                        pr_warn("[BOGGER] NPF: GPA 0x%llx beyond NPT range (pd_idx=%u)\n",
                                gpa, pd_idx);
                    npf_unmapped_count++;
                    /* Skip the faulting instruction — can't map this */
                    break;
                }
                if (npt_pd_tables[pd_idx] && npt_pd_tables[pd_idx][pd_e] == 0) {
                    /* Try to dynamically allocate a zero-page PT for this PD entry */
                    if (npt_zero_page) {
                        u64 *zpt = (u64 *)get_zeroed_page(GFP_KERNEL | __GFP_NOWARN);
                        if (zpt) {
                            u64 zero_hpa = page_to_phys(npt_zero_page);
                            unsigned int k;
                            for (k = 0; k < 512; k++)
                                zpt[k] = zero_hpa | 0x07ULL;
                            npt_pd_tables[pd_idx][pd_e] = virt_to_phys(zpt) | 0x07ULL;
                            if (npf_unmapped_count < 20)
                                pr_info("[BOGGER] NPF: mapped zero-page PT for GPA 0x%llx (pd[%u][%u])\n",
                                        gpa, pd_idx, pd_e);
                            npf_unmapped_count++;
                        }
                    }
                }
                g_vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
            }
            break;
        }

        default: {
            static int unhandled_count;
            if (unhandled_count < 20)
                pr_warn("[BOGGER] Unhandled exit=0x%x RIP=0x%llx info1=0x%llx info2=0x%llx\n",
                        exit_code, g_vmcb->save.rip,
                        g_vmcb->control.exit_info_1,
                        g_vmcb->control.exit_info_2);
            unhandled_count++;
            /* Try to continue — some exits are benign (e.g. SMI, NMI) */
            if (exit_code == 0x61 || exit_code == 0x62) {
                /* SMI/NMI — just continue */
                break;
            }
            if (unhandled_count > 100) {
                pr_emerg("[BOGGER] Too many unhandled exits, stopping\n");
                goto done;
            }
            break;
        }
        }
    }

done:
    if (hpet_kthread && !IS_ERR(hpet_kthread)) {
        hpet_kthread_stop = true;
        kthread_stop(hpet_kthread);
        hpet_kthread = NULL;
    }
    nvme_io_wq_destroy();
    if (nvme_host_dev) { filp_close(nvme_host_dev, NULL); nvme_host_dev = NULL; }
    pr_emerg("[BOGGER] VMRUN loop ended after %d exits, RIP=0x%llx\n",
             exits, g_vmcb->save.rip);
}

/* ════════════════════════════════════════════════════════════════════
 * VMRUN kthread — runs the VM loop on a dedicated kernel thread
 * with its own stack, pinned to a specific CPU.
 * ════════════════════════════════════════════════════════════════════ */
static struct task_struct *vmrun_kthread;
static int vmrun_cpu = -1;

static int bogger_vmrun_thread_fn(void *data)
{
    int ret;

    /* Pin to chosen CPU */
    {
        cpumask_var_t mask;
        if (alloc_cpumask_var(&mask, GFP_KERNEL)) {
            cpumask_clear(mask);
            cpumask_set_cpu(vmrun_cpu, mask);
            set_cpus_allowed_ptr(current, mask);
            free_cpumask_var(mask);
        }
        pr_info("[BOGGER] VMRUN thread pinned to CPU %d\n", vmrun_cpu);
    }

    /* Enable SVM on this CPU */
    ret = bogger_svm_enable();
    if (ret) { pr_err("[BOGGER] SVM enable failed on CPU %d\n", vmrun_cpu); return ret; }
    svm_enabled = true;

    ret = bogger_svm_hsave_setup();
    if (ret) { pr_err("[BOGGER] HSAVE setup failed\n"); return ret; }

    ret = bogger_vmcb_init();
    if (ret) { pr_err("[BOGGER] VMCB init failed\n"); return ret; }

    /* ═══ Clear VGA I/O port interception for GPU passthrough ═══
     * When a physical GPU is passed through, the guest accesses VGA
     * hardware registers directly.  By clearing these bits in the IOPM,
     * VGA I/O (used during GPU initialization and display mode setting)
     * bypasses the VMEXIT overhead entirely.  This is critical for
     * GPU display PHY link training, which has strict timing requirements
     * that VMEXIT latency (~1-10µs per access) can violate.
     *
     * Also clear GPU I/O BAR ports if the GPU has an I/O BAR, so the
     * guest driver can access GPU I/O registers without VMEXITs. */
    if (passthrough_dev_count > 0 && io_bitmap) {
        u8 *iopm = (u8 *)io_bitmap;
        int port, d, b;

        /* Standard VGA I/O ports: 0x3B0-0x3BB (MDA), 0x3C0-0x3DF (VGA) */
        for (port = 0x3B0; port <= 0x3BB; port++)
            iopm[port / 8] &= ~(1U << (port % 8));
        for (port = 0x3C0; port <= 0x3DF; port++)
            iopm[port / 8] &= ~(1U << (port % 8));
        pr_info("[BOGGER] IOPM: VGA ports 0x3B0-0x3DF set to direct passthrough\n");

        /* GPU I/O BAR ports: set up initial passthrough.
         * Initially GPA==HPA (identity-mapped), so direct passthrough is
         * safe.  When OVMF later reassigns BARs to different port ranges,
         * the PCI config write handler will update the IOPM and bar->gpa
         * so pt_iobar_in/out can translate guest ports to hardware ports. */
        for (d = 0; d < passthrough_dev_count; d++) {
            struct bogger_passthrough_dev *ptdev = &passthrough_devs[d];
            if (!ptdev->active) continue;
            for (b = 0; b < ptdev->num_bars; b++) {
                struct bogger_passthrough_bar *bar = &ptdev->bars[b];
                u64 io_base, io_end;
                if (bar->is_mmio || bar->size == 0)
                    continue;
                /* I/O BAR: clear IOPM bits for the entire range
                 * (GPA==HPA at init, direct passthrough is correct) */
                io_base = bar->hpa;
                bar->gpa = io_base;  /* Initialize gpa to match hpa */
                io_end = io_base + bar->size;
                if (io_end > 0xFFFF) io_end = 0xFFFF;
                for (port = (int)io_base; port < (int)io_end; port++)
                    iopm[port / 8] &= ~(1U << (port % 8));
                pr_info("[BOGGER] IOPM: GPU I/O BAR%d ports 0x%llx-0x%llx set to direct passthrough\n",
                        bar->bar_idx, io_base, io_end - 1);
            }
        }
    }

    /* Open host block device for Windows guest backing storage.
     *
     * Priority:
     *   1. Explicit bogger_disk_path= module parameter (from bogger.conf)
     *   2. Auto-detect: scan likely Windows disk paths
     *      - nvme1n1   = second NVMe (typical Windows disk on dual-boot)
     *      - vda       = virtio-blk (QEMU debug with win11.qcow2)
     *      - sda       = SCSI/SATA fallback
     *      - nvme0n1p3 = Windows partition on first NVMe (legacy)
     */
    {
        static const char * const auto_disk_paths[] = {
            "/dev/nvme1n1",     /* Second NVMe = Windows (bare metal) */
            "/dev/vda",         /* virtio-blk (QEMU debug) */
            "/dev/sda",         /* SCSI/SATA */
            "/dev/nvme0n1p3",   /* Windows partition on first NVMe */
            "/dev/nvme0n1",     /* First NVMe whole disk (last resort) */
            NULL
        };
        const char * const *dp;
        nvme_host_dev = NULL;

        /* If explicit disk path provided, use it directly */
        if (bogger_disk_path && bogger_disk_path[0] != '\0') {
            nvme_host_dev = filp_open(bogger_disk_path, O_RDWR | O_LARGEFILE, 0);
            if (!IS_ERR(nvme_host_dev)) {
                pr_info("[BOGGER] NVMe backing device (configured): %s (read-write)\n", bogger_disk_path);
            } else {
                nvme_host_dev = filp_open(bogger_disk_path, O_RDONLY | O_LARGEFILE, 0);
                if (!IS_ERR(nvme_host_dev)) {
                    pr_info("[BOGGER] NVMe backing device (configured): %s (read-only)\n", bogger_disk_path);
                } else {
                    pr_err("[BOGGER] FATAL: Configured disk path %s cannot be opened!\n", bogger_disk_path);
                    nvme_host_dev = NULL;
                }
            }
        }

        /* Auto-detect if no explicit path or explicit path failed */
        if (!nvme_host_dev) {
            for (dp = auto_disk_paths; *dp; dp++) {
                nvme_host_dev = filp_open(*dp, O_RDWR | O_LARGEFILE, 0);
                if (!IS_ERR(nvme_host_dev)) {
                    pr_info("[BOGGER] NVMe backing device (auto): %s (read-write)\n", *dp);
                    break;
                }
                nvme_host_dev = filp_open(*dp, O_RDONLY | O_LARGEFILE, 0);
                if (!IS_ERR(nvme_host_dev)) {
                    pr_info("[BOGGER] NVMe backing device (auto): %s (read-only)\n", *dp);
                    break;
                }
                nvme_host_dev = ERR_PTR(-ENOENT);
            }
        }
        if (IS_ERR_OR_NULL(nvme_host_dev)) {
            pr_warn("[BOGGER] WARNING: No backing disk found for NVMe emulation!\n");
            pr_warn("[BOGGER] Set bogger_disk_path= in bogger.conf or insmod params\n");
            nvme_host_dev = NULL;
        }
    }

    /* Detect actual disk size for NVMe identify */
    nvme_detect_disk_size();

    /* Create dedicated workqueue for NVMe I/O (kernel_read runs there) */
    if (nvme_io_wq_init())
        pr_warn("[BOGGER] NVMe I/O workqueue init failed, using inline I/O\n");

    pr_info("[BOGGER] ═══ Launching OVMF via VMRUN ═══\n");
    bogger_vmrun_loop();

    /* Disable SVM on THIS cpu (the VMRUN cpu) before exiting the thread */
    if (svm_enabled) {
        u64 efer = native_read_msr(MSR_EFER);
        native_write_msr(MSR_EFER, efer & ~EFER_SVME);
        svm_enabled = false;
        pr_info("[BOGGER] EFER.SVME cleared on CPU %d\n", smp_processor_id());
    }

    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Module init / exit
 * ════════════════════════════════════════════════════════════════════ */
static int __init bogger_kmod_init(void)
{
    int ret;

    pr_info("[BOGGER] ═══════════════════════════════════════════\n");
    pr_info("[BOGGER] BOGGER Hypervisor loading\n");

    ret = bogger_svm_check_support();
    if (ret) return ret;

    ret = bogger_guest_ram_alloc();
    if (ret) return ret;

    ret = bogger_load_ovmf();
    if (ret) goto err_ram;

    bogger_pic_init();
    bogger_ps2_init();
    bogger_vga_init();

    /* Build SMBIOS tables (needed by OVMF via fw_cfg, must be before ACPI) */
    bogger_smbios_build();

    ret = bogger_acpi_build();
    if (ret) pr_warn("[BOGGER] ACPI build failed (%d), continuing\n", ret);

    ret = bogger_npt_init();
    if (ret) goto err_ovmf;

    /* GPU PCI Passthrough (before MSR bitmap, after NPT) */
    ret = bogger_pci_passthrough_init();
    if (ret && bogger_passthrough_gpu) {
        pr_err("[BOGGER] GPU passthrough failed (%d)\n", ret);
        goto err_npt;
    }
    if (passthrough_dev_count > 0) {
        ret = bogger_pci_passthrough_map_bars();
        if (ret) pr_warn("[BOGGER] Some BAR mappings failed (%d)\n", ret);

        /* Remap legacy VGA memory (0xA0000-0xBFFFF) to physical GPU aperture */
        bogger_npt_remap_vga_legacy();

        /* Set up IOMMU DMA remapping for passthrough devices.
         * This mirrors the NPT guest RAM mapping into the IOMMU page
         * tables so the GPU can DMA correctly to guest addresses. */
        ret = bogger_pci_passthrough_setup_iommu();
        if (ret) pr_warn("[BOGGER] IOMMU setup failed (%d), DMA may not work\n", ret);

        /* Set up MSI interrupt forwarding: catch GPU IRQs on host,
         * inject them into the guest VMCB. */
        ret = bogger_pci_passthrough_setup_msi();
        if (ret) pr_warn("[BOGGER] MSI setup failed (%d)\n", ret);
    }

    ret = bogger_msr_bitmap_init();
    if (ret) goto err_npt;

    /* HPET kthread — pin to CPU 0 (different from VMRUN CPU) */
    hpet_kthread_stop = false;
    hpet_kthread = kthread_create(hpet_updater_fn, NULL, "bogger_hpet");
    if (!IS_ERR(hpet_kthread)) {
        kthread_bind(hpet_kthread, 0); /* Pin to CPU 0 */
        wake_up_process(hpet_kthread);
    } else {
        hpet_kthread = NULL;
    }

    /* Select CPU for VMRUN (prefer CPU 1 if available, avoid CPU 0) */
    vmrun_cpu = (num_online_cpus() > 1) ? 1 : 0;
    pr_info("[BOGGER] Pinned to CPU %d\n", vmrun_cpu);

    /* Launch VMRUN in a dedicated kernel thread with its own stack.
     * This avoids stack overflow in the module_init context.
     * SVM must be enabled on the same CPU that runs VMRUN. */
    vmrun_kthread = kthread_run(bogger_vmrun_thread_fn, NULL, "bogger_vmrun");
    if (IS_ERR(vmrun_kthread)) {
        ret = PTR_ERR(vmrun_kthread);
        vmrun_kthread = NULL;
        pr_err("[BOGGER] Failed to create VMRUN thread (%d)\n", ret);
        goto err_npt;
    }

    return 0;

err_npt:
    bogger_npt_free();
err_ovmf:
    bogger_ovmf_free();
err_ram:
    bogger_guest_ram_free();
    return ret;
}

static void __exit bogger_kmod_exit(void)
{
    pr_info("[BOGGER] Unloading\n");

    /* Stop the VMRUN thread (it will exit on kthread_should_stop) */
    if (vmrun_kthread && !IS_ERR(vmrun_kthread)) {
        kthread_stop(vmrun_kthread);
        vmrun_kthread = NULL;
    }

    nvme_io_wq_destroy();
    if (nvme_host_dev) { filp_close(nvme_host_dev, NULL); nvme_host_dev = NULL; }
    if (g_vmcb) { free_page((unsigned long)g_vmcb); g_vmcb = NULL; }

    bogger_npt_free();
    bogger_pci_passthrough_free();
    bogger_ovmf_free();

    if (io_bitmap)  { free_pages((unsigned long)io_bitmap,  get_order(IOPM_SIZE));  io_bitmap = NULL; }
    if (msr_bitmap) { free_pages((unsigned long)msr_bitmap, get_order(MSRPM_SIZE)); msr_bitmap = NULL; }
    if (hsave_area) { free_page((unsigned long)hsave_area); hsave_area = NULL; }
    if (host_save_area) { free_page((unsigned long)host_save_area); host_save_area = NULL; }

    bogger_guest_ram_free();

    /* NOTE: EFER.SVME is cleared in the VMRUN kthread on the correct CPU.
     * Do NOT try to clear it here — module_exit may run on a different CPU. */

    pr_info("[BOGGER] Unloaded\n");
}

module_init(bogger_kmod_init);
module_exit(bogger_kmod_exit);

