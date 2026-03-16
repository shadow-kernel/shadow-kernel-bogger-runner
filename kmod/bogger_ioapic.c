// SPDX-License-Identifier: GPL-2.0
/*
 * bogger_ioapic.c – I/O APIC emulation (MMIO at GPA 0xFEC00000)
 */
#include "bogger_ioapic.h"

#define IOAPIC_ID_REG       0x00
#define IOAPIC_VER_REG      0x01
#define IOAPIC_ARB_REG      0x02
#define IOAPIC_REDIR_BASE   0x10
#define IOAPIC_MAX_REDIR    24

struct page     *ioapic_page;
volatile u32    *ioapic_regs;
u32              ioapic_regsel;

u64 ioapic_redir[IOAPIC_MAX_REDIR];

void ioapic_init_regs(void)
{
    int i;
    if (!ioapic_regs) return;
    memset((void *)ioapic_regs, 0, PAGE_SIZE);
    ioapic_regsel = 0;
    for (i = 0; i < IOAPIC_MAX_REDIR; i++)
        ioapic_redir[i] = (1ULL << 16);  /* masked */
}

u32 ioapic_read_reg(u32 reg)
{
    if (reg == IOAPIC_ID_REG)  return 0x00 << 24;
    if (reg == IOAPIC_VER_REG) return 0x00170011;
    if (reg == IOAPIC_ARB_REG) return 0;
    if (reg >= IOAPIC_REDIR_BASE &&
        reg < IOAPIC_REDIR_BASE + IOAPIC_MAX_REDIR * 2) {
        u32 idx = (reg - IOAPIC_REDIR_BASE) / 2;
        if ((reg - IOAPIC_REDIR_BASE) & 1)
            return (u32)(ioapic_redir[idx] >> 32);
        else
            return (u32)(ioapic_redir[idx] & 0xFFFFFFFF);
    }
    return 0;
}

static void ioapic_write_reg(u32 reg, u32 val)
{
    if (reg >= IOAPIC_REDIR_BASE &&
        reg < IOAPIC_REDIR_BASE + IOAPIC_MAX_REDIR * 2) {
        u32 idx = (reg - IOAPIC_REDIR_BASE) / 2;
        bool was_masked, now_masked;
        u8 vec;
        was_masked = !!(ioapic_redir[idx] & (1ULL << 16));
        if ((reg - IOAPIC_REDIR_BASE) & 1)
            ioapic_redir[idx] = (ioapic_redir[idx] & 0xFFFFFFFF) | ((u64)val << 32);
        else
            ioapic_redir[idx] = (ioapic_redir[idx] & 0xFFFFFFFF00000000ULL) | val;
        now_masked = !!(ioapic_redir[idx] & (1ULL << 16));
        vec = (u8)(ioapic_redir[idx] & 0xFF);
        /* Log IRQ routing changes (first 500 writes) */
        {
            static int ioapic_wr_log;
            if (ioapic_wr_log < 500)  {
                pr_info("[BOGGER-IOAPIC] redir[%u] = 0x%016llx (vec=0x%02x mask=%d dest=0x%02x)\n",
                        idx, ioapic_redir[idx], vec, now_masked,
                        (u8)((ioapic_redir[idx] >> 56) & 0xFF));
                ioapic_wr_log++;
            }
        }
        if (was_masked && !now_masked && vec >= 0x20)
            pr_info("[BOGGER-IOAPIC] IRQ %u UNMASKED → vec=0x%02x\n", idx, vec);
    }
}

u32 ioapic_mmio_read(u32 offset)
{
    if (offset == 0x00) return ioapic_regsel;
    if (offset == 0x10) return ioapic_read_reg(ioapic_regsel);
    return 0;
}

void ioapic_mmio_write(u32 offset, u32 val)
{
    if (offset == 0x00)
        ioapic_regsel = val;
    else if (offset == 0x10)
        ioapic_write_reg(ioapic_regsel, val);
}

/* ── Active IRQ delivery ─────────────────────────────────────────── */
atomic_t ioapic_irq_pending = ATOMIC_INIT(0);
u8 ioapic_irq_pending_vec;

bool ioapic_assert_irq(u8 irq, u8 *vec_out)
{
    u64 redir;
    u8 vec;
    bool masked;

    if (irq >= IOAPIC_MAX_REDIR)
        return false;

    redir = ioapic_redir[irq];
    masked = !!(redir & (1ULL << 16));
    vec = (u8)(redir & 0xFF);

    if (masked || vec < 0x10)
        return false;

    /* Set pending flag for the VMRUN loop.
     * If another IRQ is already pending, it will be overwritten.
     * This is acceptable for our use case (single NVMe device). */
    if (vec_out)
        *vec_out = vec;
    ioapic_irq_pending_vec = vec;
    smp_wmb();
    atomic_set(&ioapic_irq_pending, 1);
    return true;
}

