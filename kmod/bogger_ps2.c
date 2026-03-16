// SPDX-License-Identifier: GPL-2.0
/*
 * bogger_ps2.c – i8042 PS/2 controller emulation
 *
 * Emulates the standard PC i8042 keyboard/mouse controller with enough
 * fidelity for OVMF UEFI firmware and Windows to detect a PS/2 keyboard.
 *
 * The controller responds to standard i8042 commands and presents a
 * PS/2 keyboard device that passes self-test and identification.
 * No actual key input is generated — this is a presence stub so
 * Windows doesn't BSOD due to missing keyboard controller.
 *
 * For real input on bare metal, the GPU passthrough path provides
 * USB keyboard/mouse input via the host USB controllers which can
 * be passed through. This PS/2 emulation is just for the boot path.
 */
#include "bogger_ps2.h"

/* ── i8042 Status Register bits ─────────────────────────────────── */
#define PS2_STS_OBF     (1 << 0)  /* Output Buffer Full (data ready to read) */
#define PS2_STS_IBF     (1 << 1)  /* Input Buffer Full (cmd/data being processed) */
#define PS2_STS_SYS     (1 << 2)  /* System flag (POST passed) */
#define PS2_STS_CMD     (1 << 3)  /* 0=data written to 0x60, 1=cmd written to 0x64 */
#define PS2_STS_KEYLOCK (1 << 4)  /* Keyboard lock (always 1 = unlocked) */
#define PS2_STS_AUXOBF  (1 << 5)  /* Aux (mouse) output buffer full */
#define PS2_STS_TIMEOUT (1 << 6)  /* General timeout */
#define PS2_STS_PARITY  (1 << 7)  /* Parity error */

/* ── i8042 Commands (written to 0x64) ───────────────────────────── */
#define PS2_CMD_READ_CCB     0x20  /* Read Controller Configuration Byte */
#define PS2_CMD_WRITE_CCB    0x60  /* Write Controller Configuration Byte */
#define PS2_CMD_DISABLE_AUX  0xA7  /* Disable auxiliary (mouse) port */
#define PS2_CMD_ENABLE_AUX   0xA8  /* Enable auxiliary port */
#define PS2_CMD_TEST_AUX     0xA9  /* Test auxiliary port */
#define PS2_CMD_SELF_TEST    0xAA  /* Controller self-test */
#define PS2_CMD_TEST_KBD     0xAB  /* Test keyboard port */
#define PS2_CMD_DISABLE_KBD  0xAD  /* Disable keyboard port */
#define PS2_CMD_ENABLE_KBD   0xAE  /* Enable keyboard port */
#define PS2_CMD_READ_INPUT   0xC0  /* Read input port */
#define PS2_CMD_READ_OUTPUT  0xD0  /* Read output port */
#define PS2_CMD_WRITE_OUTPUT 0xD1  /* Write output port */
#define PS2_CMD_WRITE_AUX    0xD4  /* Write to auxiliary device */
#define PS2_CMD_PULSE_OUTPUT 0xFE  /* Pulse output port (reset) */

/* ── Keyboard Device Commands (written to 0x60 when CCB routing) ── */
#define KBD_CMD_LED         0xED  /* Set LEDs */
#define KBD_CMD_ECHO        0xEE  /* Echo */
#define KBD_CMD_SCANCODE    0xF0  /* Get/set scancode set */
#define KBD_CMD_IDENTIFY    0xF2  /* Identify keyboard */
#define KBD_CMD_TYPEMATIC   0xF3  /* Set typematic rate/delay */
#define KBD_CMD_ENABLE      0xF4  /* Enable scanning */
#define KBD_CMD_DISABLE     0xF5  /* Disable scanning */
#define KBD_CMD_DEFAULT     0xF6  /* Set default parameters */
#define KBD_CMD_RESEND      0xFE  /* Resend last byte */
#define KBD_CMD_RESET       0xFF  /* Reset and self-test */

/* ── Response bytes ─────────────────────────────────────────────── */
#define KBD_ACK             0xFA  /* Acknowledge */
#define KBD_SELF_TEST_OK    0xAA  /* Self-test passed (also i8042 self-test) */
#define PS2_SELF_TEST_OK    0x55  /* Controller self-test passed */
#define PS2_PORT_TEST_OK    0x00  /* Port test passed */

/* ── Controller state ───────────────────────────────────────────── */
static struct {
    /* Output buffer (data to be read from port 0x60) */
    u8  out_buf[16];
    int out_head;
    int out_tail;
    int out_count;

    /* Controller Configuration Byte */
    u8  ccb;

    /* State machine */
    u8  pending_cmd;       /* i8042 command expecting data byte on port 0x60 */
    bool kbd_enabled;
    bool aux_enabled;
    bool kbd_scanning;
    u8   output_port;      /* i8042 output port register */

    /* Keyboard device state */
    bool kbd_expecting_data; /* keyboard device waiting for parameter byte */
    u8   kbd_last_cmd;       /* last keyboard command sent */
} ps2;

/* ── Output buffer management ───────────────────────────────────── */
static void ps2_queue_byte(u8 byte)
{
    if (ps2.out_count < 16) {
        ps2.out_buf[ps2.out_tail] = byte;
        ps2.out_tail = (ps2.out_tail + 1) & 15;
        ps2.out_count++;
    }
}

static u8 ps2_dequeue_byte(void)
{
    u8 val;
    if (ps2.out_count == 0)
        return 0x00;
    val = ps2.out_buf[ps2.out_head];
    ps2.out_head = (ps2.out_head + 1) & 15;
    ps2.out_count--;
    return val;
}

/* ═══════════════════════════════════════════════════════════════════
 * Initialization
 * ═══════════════════════════════════════════════════════════════════ */
void bogger_ps2_init(void)
{
    memset(&ps2, 0, sizeof(ps2));

    /* Default CCB: keyboard IRQ enabled, system flag set,
     * keyboard clock enabled, translation enabled */
    ps2.ccb = 0x47;  /* bits: KBD_IRQ | AUX_IRQ | SYS | KBD_CLK_DIS=0 | XLAT */
    ps2.kbd_enabled = true;
    ps2.aux_enabled = false;
    ps2.kbd_scanning = true;
    ps2.output_port = 0xCF; /* A20=1, reset=1, bits 4-7 default high */

    pr_info("[BOGGER] PS/2 i8042 controller initialized\n");
}

/* ═══════════════════════════════════════════════════════════════════
 * Read port 0x60 (data output buffer)
 * ═══════════════════════════════════════════════════════════════════ */
u8 ps2_read_data(void)
{
    return ps2_dequeue_byte();
}

/* ═══════════════════════════════════════════════════════════════════
 * Read port 0x64 (status register)
 * ═══════════════════════════════════════════════════════════════════ */
u8 ps2_read_status(void)
{
    u8 status = PS2_STS_SYS | PS2_STS_KEYLOCK;

    if (ps2.out_count > 0)
        status |= PS2_STS_OBF;  /* data available in output buffer */

    return status;
}

/* ═══════════════════════════════════════════════════════════════════
 * Write port 0x60 (data input)
 * Depending on state: controller data or keyboard device command
 * ═══════════════════════════════════════════════════════════════════ */
void ps2_write_data(u8 val)
{
    /* Check if a controller command is pending (expecting data byte) */
    if (ps2.pending_cmd) {
        u8 cmd = ps2.pending_cmd;
        ps2.pending_cmd = 0;

        switch (cmd) {
        case PS2_CMD_WRITE_CCB:
            ps2.ccb = val;
            break;
        case PS2_CMD_WRITE_OUTPUT:
            ps2.output_port = val;
            /* Bit 0: system reset — if cleared, reset CPU */
            /* Bit 1: A20 gate */
            break;
        case PS2_CMD_WRITE_AUX:
            /* Data to mouse device — ACK it */
            ps2_queue_byte(KBD_ACK);
            break;
        default:
            break;
        }
        return;
    }

    /* Check if keyboard device is expecting a parameter byte */
    if (ps2.kbd_expecting_data) {
        ps2.kbd_expecting_data = false;
        /* ACK the parameter */
        ps2_queue_byte(KBD_ACK);
        return;
    }

    /* Otherwise: keyboard device command */
    ps2.kbd_last_cmd = val;

    switch (val) {
    case KBD_CMD_RESET: /* 0xFF: Reset keyboard */
        ps2_queue_byte(KBD_ACK);
        ps2_queue_byte(KBD_SELF_TEST_OK); /* 0xAA = self-test passed */
        break;

    case KBD_CMD_IDENTIFY: /* 0xF2: Identify keyboard */
        ps2_queue_byte(KBD_ACK);
        ps2_queue_byte(0xAB); /* MF2 keyboard, type byte 1 */
        ps2_queue_byte(0x83); /* MF2 keyboard, type byte 2 */
        break;

    case KBD_CMD_ENABLE: /* 0xF4: Enable scanning */
        ps2.kbd_scanning = true;
        ps2_queue_byte(KBD_ACK);
        break;

    case KBD_CMD_DISABLE: /* 0xF5: Disable scanning */
        ps2.kbd_scanning = false;
        ps2_queue_byte(KBD_ACK);
        break;

    case KBD_CMD_DEFAULT: /* 0xF6: Set defaults */
        ps2.kbd_scanning = true;
        ps2_queue_byte(KBD_ACK);
        break;

    case KBD_CMD_ECHO: /* 0xEE: Echo */
        ps2_queue_byte(0xEE);
        break;

    case KBD_CMD_LED: /* 0xED: Set LEDs — expects data byte */
    case KBD_CMD_TYPEMATIC: /* 0xF3: Set typematic — expects data byte */
    case KBD_CMD_SCANCODE: /* 0xF0: Scancode set — expects data byte */
        ps2.kbd_expecting_data = true;
        ps2_queue_byte(KBD_ACK);
        break;

    case KBD_CMD_RESEND: /* 0xFE: Resend last byte */
        ps2_queue_byte(KBD_ACK);
        break;

    default:
        /* Unknown command — ACK it to prevent hangs */
        ps2_queue_byte(KBD_ACK);
        break;
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * Write port 0x64 (controller command)
 * ═══════════════════════════════════════════════════════════════════ */
void ps2_write_command(u8 cmd)
{
    switch (cmd) {
    case PS2_CMD_READ_CCB: /* 0x20: Read CCB */
        ps2_queue_byte(ps2.ccb);
        break;

    case PS2_CMD_WRITE_CCB: /* 0x60: Write CCB — next byte on 0x60 is data */
        ps2.pending_cmd = cmd;
        break;

    case PS2_CMD_SELF_TEST: /* 0xAA: Controller self-test */
        ps2_queue_byte(PS2_SELF_TEST_OK); /* 0x55 = passed */
        break;

    case PS2_CMD_TEST_KBD: /* 0xAB: Test keyboard port */
        ps2_queue_byte(PS2_PORT_TEST_OK); /* 0x00 = no error */
        break;

    case PS2_CMD_TEST_AUX: /* 0xA9: Test auxiliary (mouse) port */
        ps2_queue_byte(PS2_PORT_TEST_OK); /* 0x00 = no error */
        break;

    case PS2_CMD_DISABLE_KBD: /* 0xAD */
        ps2.kbd_enabled = false;
        ps2.ccb |= (1 << 4); /* Set KBD clock disable */
        break;

    case PS2_CMD_ENABLE_KBD: /* 0xAE */
        ps2.kbd_enabled = true;
        ps2.ccb &= ~(1 << 4); /* Clear KBD clock disable */
        break;

    case PS2_CMD_DISABLE_AUX: /* 0xA7 */
        ps2.aux_enabled = false;
        ps2.ccb |= (1 << 5); /* Set AUX clock disable */
        break;

    case PS2_CMD_ENABLE_AUX: /* 0xA8 */
        ps2.aux_enabled = true;
        ps2.ccb &= ~(1 << 5); /* Clear AUX clock disable */
        break;

    case PS2_CMD_READ_INPUT: /* 0xC0: Read input port */
        ps2_queue_byte(0xBF); /* Keyboard not locked, A20=1 */
        break;

    case PS2_CMD_READ_OUTPUT: /* 0xD0: Read output port */
        ps2_queue_byte(ps2.output_port);
        break;

    case PS2_CMD_WRITE_OUTPUT: /* 0xD1: Write output port — data on 0x60 */
        ps2.pending_cmd = cmd;
        break;

    case PS2_CMD_WRITE_AUX: /* 0xD4: Write to mouse */
        ps2.pending_cmd = cmd;
        break;

    case PS2_CMD_PULSE_OUTPUT: /* 0xFE: Pulse output port (system reset) */
        /* Not implemented — would need VMCB reset */
        break;

    default:
        /* Commands 0x20-0x3F: Read internal RAM (CCB variants) */
        if (cmd >= 0x20 && cmd <= 0x3F) {
            ps2_queue_byte(ps2.ccb); /* Return CCB for all slots */
        }
        /* Commands 0x60-0x7F: Write internal RAM — expect data on 0x60 */
        else if (cmd >= 0x60 && cmd <= 0x7F) {
            ps2.pending_cmd = PS2_CMD_WRITE_CCB; /* Treat as CCB write */
        }
        break;
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * Key injection for advancing OVMF boot menus
 * ═══════════════════════════════════════════════════════════════════ */
bool bogger_ps2_inject_key(u8 make_code, u8 break_code)
{
    /* Only inject if there's room in the buffer */
    if (ps2.out_count > 12)
        return false;

    ps2_queue_byte(make_code);
    ps2_queue_byte(break_code);
    return true;
}

bool bogger_ps2_inject_enter(void)
{
    return bogger_ps2_inject_key(0x1C, 0x9C);
}
