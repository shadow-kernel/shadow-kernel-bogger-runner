/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOGGER_LAPIC_H
#define BOGGER_LAPIC_H
#include "bogger_types.h"

#define LAPIC_GPA           0xFEE00000ULL
#define LAPIC_REG_TIMER_CCR 0x390

void lapic_init_regs(void);
void lapic_mmio_write(u32 offset, u32 val);
u32  lapic_read_ccr(void);
bool lapic_timer_pending(void);
bool lapic_ipi_pending(u8 *vec_out);

/* IRR/ISR register management — must mirror event_inj state */
void lapic_set_irr(u8 vec);
void lapic_clear_irr(u8 vec);
void lapic_set_isr(u8 vec);
void lapic_clear_isr_highest(void);

/* NMI pending flag — set when guest sends NMI self-IPI via ICR */
extern bool lapic_nmi_pending;

/* Timer state — for diagnostic logging */
extern u32  lapic_lvt_timer;
extern u32  lapic_timer_icr;
extern u32  lapic_timer_dcr;
extern bool lapic_timer_armed;

#endif

