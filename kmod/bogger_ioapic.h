/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOGGER_IOAPIC_H
#define BOGGER_IOAPIC_H
#include "bogger_types.h"

#define IOAPIC_GPA  0xFEC00000ULL

void ioapic_init_regs(void);
u32  ioapic_mmio_read(u32 offset);
void ioapic_mmio_write(u32 offset, u32 val);
u32  ioapic_read_reg(u32 reg);

/*
 * Assert an IRQ line on the I/O APIC.
 * Checks the redirection entry: if unmasked, sets a pending interrupt
 * flag with the vector from the entry.  The VMRUN loop picks up the
 * pending interrupt.
 * Returns: true if IRQ was delivered (entry unmasked, valid vector).
 */
bool ioapic_assert_irq(u8 irq, u8 *vec_out);

/* Pending IOAPIC interrupt — set by ioapic_assert_irq, consumed by VMRUN loop */
extern atomic_t ioapic_irq_pending;
extern u8 ioapic_irq_pending_vec;

#endif

