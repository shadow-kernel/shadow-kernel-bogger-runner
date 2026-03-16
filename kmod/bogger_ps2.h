/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOGGER_PS2_H
#define BOGGER_PS2_H
#include "bogger_types.h"

/*
 * bogger_ps2.h – i8042 PS/2 controller emulation
 *
 * Provides basic keyboard/mouse controller emulation so OVMF and
 * Windows detect an i8042 with PS/2 keyboard present.
 *
 * Port map:
 *   0x60: Data register (read: output buffer, write: data to device/controller)
 *   0x64: Status register (read), Command register (write)
 */

void bogger_ps2_init(void);
u8   ps2_read_data(void);
u8   ps2_read_status(void);
void ps2_write_data(u8 val);
void ps2_write_command(u8 cmd);

/* Inject a keypress into the PS/2 output buffer.
 * Queues make code + break code for OVMF's ConIn polling to pick up.
 * Returns true if successfully queued. */
bool bogger_ps2_inject_key(u8 make_code, u8 break_code);

/* Inject Enter key (make=0x1C, break=0x9C) */
bool bogger_ps2_inject_enter(void);

#endif /* BOGGER_PS2_H */
