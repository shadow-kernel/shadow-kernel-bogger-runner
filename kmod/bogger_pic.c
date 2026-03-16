// SPDX-License-Identifier: GPL-2.0
/*
 * bogger_pic.c – Dual 8259A PIC emulation (master + slave)
 *
 * OVMF runs the ICW1-ICW4 initialisation sequence before switching to
 * APIC mode.  Windows also touches the PIC early.  We emulate enough
 * of the state machine so reads/writes behave correctly.
 */
#include "bogger_pic.h"

struct bogger_pic pic_master;
struct bogger_pic pic_slave;

void bogger_pic_init(void)
{
    memset(&pic_master, 0, sizeof(pic_master));
    memset(&pic_slave,  0, sizeof(pic_slave));

    /* Default: all IRQs unmasked for master, masked for slave */
    pic_master.imr = 0x00;  /* IRQs unmasked — OVMF will mask during init */
    pic_slave.imr  = 0xFF;  /* all masked */

    pic_master.vector_base = 0x20;  /* Safe default outside exception range (0-31) */
    pic_slave.vector_base  = 0x28;  /* Slave at 0x28 (standard reprogrammed mapping) */
}

/*
 * Handle a PIC write.  The 8259 has a complex init protocol:
 *   Port 0x20/0xA0 (command):
 *     - Bit 4 set  → ICW1 (start init sequence)
 *     - Bit 3 clear, bit 4 clear → OCW2 (EOI etc.)
 *     - Bit 3 set  → OCW3 (read IRR/ISR select)
 *   Port 0x21/0xA1 (data):
 *     - During init: ICW2, ICW3, ICW4 in sequence
 *     - Outside init: write IMR (OCW1)
 */
static void pic_cmd_write(struct bogger_pic *pic, u8 val)
{
    if (val & 0x10) {
        /* ICW1: start initialisation */
        pic->init_state = 1;  /* next data write = ICW2 */
        pic->imr = 0;
        pic->isr = 0;
        pic->irr = 0;
        pic->read_isr = 0;
        pic->auto_eoi = 0;
        pic->special_mask = 0;
        /* Bit 0: IC4 (need ICW4?) — we always expect ICW4 */
        /* Bit 1: SNGL — 0 = cascade mode */
        return;
    }

    if (!(val & 0x08)) {
        /* OCW2: EOI commands */
        u8 cmd = (val >> 5) & 0x07;
        switch (cmd) {
        case 0x01: /* Non-specific EOI */
            /* Clear highest-priority ISR bit */
            { int i; for (i = 0; i < 8; i++)
                if (pic->isr & (1U << i)) { pic->isr &= ~(1U << i); break; }
            }
            break;
        case 0x03: /* Specific EOI */
            pic->isr &= ~(1U << (val & 0x07));
            break;
        default:
            break;
        }
        return;
    }

    /* OCW3 */
    if (val & 0x02)
        pic->read_isr = (val & 0x01);  /* bit 0: 0=read IRR, 1=read ISR */
    if (val & 0x40)
        pic->special_mask = (val >> 5) & 0x01;
}

static void pic_data_write(struct bogger_pic *pic, u8 val)
{
    switch (pic->init_state) {
    case 1:  /* ICW2: vector base */
        pic->vector_base = val & 0xF8;
        pic->init_state = 2;
        break;
    case 2:  /* ICW3: cascade configuration */
        pic->icw3 = val;
        pic->init_state = 3;
        break;
    case 3:  /* ICW4: mode */
        pic->icw4 = val;
        pic->auto_eoi = (val >> 1) & 1;
        pic->init_state = 0;  /* init complete */
        break;
    default:
        /* OCW1: write IMR */
        pic->imr = val;
        break;
    }
}

void bogger_pic_write(u16 port, u8 val)
{
    switch (port) {
    case 0x20: pic_cmd_write(&pic_master, val); break;
    case 0x21: pic_data_write(&pic_master, val); break;
    case 0xA0: pic_cmd_write(&pic_slave, val); break;
    case 0xA1: pic_data_write(&pic_slave, val); break;
    }
}

u32 bogger_pic_read(u16 port)
{
    struct bogger_pic *pic;

    switch (port) {
    case 0x20: pic = &pic_master;
        return pic->read_isr ? pic->isr : pic->irr;
    case 0x21: return pic_master.imr;
    case 0xA0: pic = &pic_slave;
        return pic->read_isr ? pic->isr : pic->irr;
    case 0xA1: return pic_slave.imr;
    default: return 0xFF;
    }
}

