/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOGGER_PIC_H
#define BOGGER_PIC_H
#include "bogger_types.h"

/*
 * Dual 8259A PIC emulation (master + slave).
 *
 * OVMF initialises the PIC via ICW1-ICW4 sequence on ports 0x20/0x21
 * (master) and 0xA0/0xA1 (slave) before switching to APIC mode.
 * Windows also touches the PIC during early boot.  We need to track
 * the initialisation state so that reads of IMR/IRR return correct
 * values matching what OVMF wrote.
 */

struct bogger_pic {
    u8 irr;         /* Interrupt Request Register */
    u8 isr;         /* In-Service Register */
    u8 imr;         /* Interrupt Mask Register */
    u8 vector_base; /* ICW2: base vector */
    u8 icw3;        /* ICW3: cascade config */
    u8 icw4;        /* ICW4: mode config */
    u8 init_state;  /* 0=idle, 1=wait ICW2, 2=wait ICW3, 3=wait ICW4 */
    u8 read_isr;    /* OCW3: next read returns ISR instead of IRR */
    u8 auto_eoi;    /* ICW4 bit 1: auto-EOI mode */
    u8 special_mask; /* OCW3: special mask mode */
};

extern struct bogger_pic pic_master;
extern struct bogger_pic pic_slave;

void bogger_pic_init(void);
u32  bogger_pic_read(u16 port);
void bogger_pic_write(u16 port, u8 val);

#endif

