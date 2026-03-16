// SPDX-License-Identifier: GPL-2.0
/*
 * bogger_vga.c – Bochs VGA / VBE Dispi emulation for OVMF GOP driver
 *
 * OVMF's QemuVideoDxe / BochsVga driver uses:
 *   - PCI BAR0 at 0xFD000000 (16 MB linear framebuffer)
 *   - Bochs VBE Dispi registers at I/O ports 0x1CE/0x1CF
 *   - Standard VGA registers at 0x3C0-0x3DF
 *
 * We emulate enough of these to get OVMF's GOP protocol working,
 * which Windows Boot Manager needs for graphical output.
 */
#include "bogger_vga.h"

struct bogger_vga_state vga_state;

/*
 * Standard EDID block for a virtual 1920x1080@60Hz monitor.
 * This makes OVMF's BochsVga GOP driver detect display capabilities.
 * 128-byte base EDID (v1.3).
 */
const u8 bogger_edid_block[128] = {
    /* Header */
    0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
    /* Manufacturer: "BOG" (big-endian compressed ASCII) */
    0x09, 0xC7,
    /* Product code: 0x1234 */
    0x34, 0x12,
    /* Serial: 1 */
    0x01, 0x00, 0x00, 0x00,
    /* Week 1, Year 2024 (1990+34) */
    0x01, 0x22,
    /* EDID version 1.3 */
    0x01, 0x03,
    /* Digital input (bit 7), 8bpc (bits 6:4 = 010) */
    0xA0,
    /* H image size 53cm, V image size 30cm */
    0x35, 0x1E,
    /* Gamma 2.2 (encoded as (gamma*100)-100 = 120 = 0x78) */
    0x78,
    /* Features: RGB, preferred timing in DTD1, non-continuous */
    0x0A,
    /* Chromaticity (sRGB-ish) */
    0xEE, 0x91, 0xA3, 0x54, 0x4C, 0x99, 0x26, 0x0F, 0x50, 0x54,
    /* Established timings I/II */
    0x21, 0x08, 0x00,
    /* Standard timing block (8 entries, all unused → 0x0101) */
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    /* Detailed Timing Descriptor 1: 1920x1080@60Hz
     * Pixel clock: 148.50 MHz = 14850 (LE) = 0x3A10 */
    0x02, 0x3A,
    /* H active: 1920 (0x780), H blank: 280 (0x118) */
    0x80, 0x18, 0x71,
    /* V active: 1080 (0x438), V blank: 45 (0x2D) */
    0x38, 0x2D, 0x40,
    /* H front porch: 88 (0x58), H sync: 44 (0x2C) */
    0x58, 0x2C,
    /* V front porch: 4, V sync: 5 (packed nibbles) */
    0x45,
    /* Upper nibbles of H/V porch/sync */
    0x00,
    /* H/V image size mm: 531 × 298 */
    0x13, 0x2A, 0x21,
    /* Border: 0,0 */
    0x00, 0x00,
    /* Flags: non-interlaced, normal display, digital separate syncs, +H +V */
    0x1E,
    /* Descriptor 2: Monitor Name */
    0x00, 0x00, 0x00, 0xFC, 0x00,
    'B', 'O', 'G', 'G', 'E', 'R', ' ', 'V', 'G', 'A', 0x0A, 0x20, 0x20,
    /* Descriptor 3: Monitor Range Limits */
    0x00, 0x00, 0x00, 0xFD, 0x00,
    0x32, 0x4B,  /* V min/max: 50-75 Hz */
    0x1E, 0x51,  /* H min/max: 30-81 kHz */
    0x11,        /* Max pixel clock / 10 = 170 MHz */
    0x00, 0x0A, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    /* Descriptor 4: unused */
    0x00, 0x00, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* Extension count = 0 */
    0x00,
    /* Checksum (precomputed: -(sum bytes 0..126) & 0xFF) */
    0xE9,
};

void bogger_vga_init(void)
{
    memset(&vga_state, 0, sizeof(vga_state));

    /* VBE Dispi defaults */
    vga_state.vbe_regs[VBE_DISPI_INDEX_ID]               = VBE_DISPI_ID5;
    vga_state.vbe_regs[VBE_DISPI_INDEX_XRES]             = 1024;
    vga_state.vbe_regs[VBE_DISPI_INDEX_YRES]             = 768;
    vga_state.vbe_regs[VBE_DISPI_INDEX_BPP]              = 32;
    vga_state.vbe_regs[VBE_DISPI_INDEX_ENABLE]           = VBE_DISPI_DISABLED;
    vga_state.vbe_regs[VBE_DISPI_INDEX_BANK]             = 0;
    vga_state.vbe_regs[VBE_DISPI_INDEX_VIRT_WIDTH]       = 1024;
    vga_state.vbe_regs[VBE_DISPI_INDEX_VIRT_HEIGHT]      = 768;
    vga_state.vbe_regs[VBE_DISPI_INDEX_X_OFFSET]         = 0;
    vga_state.vbe_regs[VBE_DISPI_INDEX_Y_OFFSET]         = 0;
    vga_state.vbe_regs[VBE_DISPI_INDEX_VIDEO_MEMORY_64K] = VGA_FB_64K;
    vga_state.vbe_regs[VBE_DISPI_INDEX_DDC]              = 0;

    /* VGA standard defaults */
    vga_state.misc_output = 0x67;  /* Color mode, RAM enable, clock select */

    /* Sequencer defaults */
    vga_state.seq_regs[0] = 0x03;  /* Reset */
    vga_state.seq_regs[1] = 0x00;  /* Clocking Mode */
    vga_state.seq_regs[2] = 0x0F;  /* Map Mask */
    vga_state.seq_regs[3] = 0x00;  /* Character Map */
    vga_state.seq_regs[4] = 0x02;  /* Memory Mode */

    /* CRTC defaults (VGA mode 3 — 80x25 text) */
    vga_state.crtc_regs[0x00] = 0x5F;  /* H Total */
    vga_state.crtc_regs[0x01] = 0x4F;  /* H Display End */
    vga_state.crtc_regs[0x02] = 0x50;  /* H Blank Start */
    vga_state.crtc_regs[0x03] = 0x82;  /* H Blank End */
    vga_state.crtc_regs[0x04] = 0x55;  /* H Retrace Start */
    vga_state.crtc_regs[0x05] = 0x81;  /* H Retrace End */
    vga_state.crtc_regs[0x06] = 0xBF;  /* V Total */
    vga_state.crtc_regs[0x07] = 0x1F;  /* Overflow */
    vga_state.crtc_regs[0x09] = 0x4F;  /* Max Scan Line */
    vga_state.crtc_regs[0x0A] = 0x0D;  /* Cursor Start */
    vga_state.crtc_regs[0x0B] = 0x0E;  /* Cursor End */
    vga_state.crtc_regs[0x10] = 0x9C;  /* V Retrace Start */
    vga_state.crtc_regs[0x11] = 0x0E;  /* V Retrace End */
    vga_state.crtc_regs[0x12] = 0x8F;  /* V Display End */
    vga_state.crtc_regs[0x15] = 0x96;  /* V Blank Start */
    vga_state.crtc_regs[0x16] = 0xB9;  /* V Blank End */
    vga_state.crtc_regs[0x17] = 0xA3;  /* Mode Control */

    /* Graphics controller defaults */
    vga_state.gfx_regs[0x05] = 0x40;  /* Mode: 256-color shift */
    vga_state.gfx_regs[0x06] = 0x05;  /* Misc: A0000, chain */

    /* Default palette: 1:1 mapping for first 16 entries */
    {
        static const u8 default_pal[16][3] = {
            {0x00,0x00,0x00}, {0x00,0x00,0xAA}, {0x00,0xAA,0x00}, {0x00,0xAA,0xAA},
            {0xAA,0x00,0x00}, {0xAA,0x00,0xAA}, {0xAA,0x55,0x00}, {0xAA,0xAA,0xAA},
            {0x55,0x55,0x55}, {0x55,0x55,0xFF}, {0x55,0xFF,0x55}, {0x55,0xFF,0xFF},
            {0xFF,0x55,0x55}, {0xFF,0x55,0xFF}, {0xFF,0xFF,0x55}, {0xFF,0xFF,0xFF},
        };
        int i;
        for (i = 0; i < 16; i++) {
            vga_state.dac_palette[i][0] = default_pal[i][0] >> 2;
            vga_state.dac_palette[i][1] = default_pal[i][1] >> 2;
            vga_state.dac_palette[i][2] = default_pal[i][2] >> 2;
        }
    }
}

/* ══════════════════════════════════════════════════════════════════
 * Bochs VBE Dispi Register I/O (ports 0x1CE / 0x1CF)
 * ══════════════════════════════════════════════════════════════════ */

static u16 vbe_dispi_read(void)
{
    u16 idx = vga_state.vbe_index;

    if (idx >= VBE_DISPI_INDEX_NB)
        return 0;

    return vga_state.vbe_regs[idx];
}

static void vbe_dispi_write(u16 val)
{
    u16 idx = vga_state.vbe_index;

    if (idx >= VBE_DISPI_INDEX_NB)
        return;

    switch (idx) {
    case VBE_DISPI_INDEX_ID:
        /* Guest can write an ID to negotiate version; accept B0C0-B0C5 */
        if (val >= VBE_DISPI_ID0 && val <= VBE_DISPI_ID5)
            vga_state.vbe_regs[idx] = val;
        break;

    case VBE_DISPI_INDEX_XRES:
        if (val == 0) val = 1;
        if (val > 2560) val = 2560;
        vga_state.vbe_regs[idx] = val;
        vga_state.vbe_regs[VBE_DISPI_INDEX_VIRT_WIDTH] = val;
        break;

    case VBE_DISPI_INDEX_YRES:
        if (val == 0) val = 1;
        if (val > 1600) val = 1600;
        vga_state.vbe_regs[idx] = val;
        vga_state.vbe_regs[VBE_DISPI_INDEX_VIRT_HEIGHT] = val;
        break;

    case VBE_DISPI_INDEX_BPP:
        /* Only accept 8, 15, 16, 24, 32 */
        if (val != 8 && val != 15 && val != 16 && val != 24 && val != 32)
            val = 32;
        vga_state.vbe_regs[idx] = val;
        break;

    case VBE_DISPI_INDEX_ENABLE: {
        u16 old_enable = vga_state.vbe_regs[idx];
        vga_state.vbe_regs[idx] = val;

        if ((val & VBE_DISPI_ENABLED) && !(old_enable & VBE_DISPI_ENABLED)) {
            /* Mode switch: recalculate virtual dimensions */
            u16 xres = vga_state.vbe_regs[VBE_DISPI_INDEX_XRES];
            u16 yres = vga_state.vbe_regs[VBE_DISPI_INDEX_YRES];
            u16 bpp  = vga_state.vbe_regs[VBE_DISPI_INDEX_BPP];
            u32 stride = (u32)xres * ((bpp + 7) / 8);
            u32 max_height;

            if (stride == 0) stride = 1;
            max_height = (u32)(VGA_FB_SIZE / stride);
            if (max_height > 0xFFFF) max_height = 0xFFFF;

            vga_state.vbe_regs[VBE_DISPI_INDEX_VIRT_WIDTH]  = xres;
            if (vga_state.vbe_regs[VBE_DISPI_INDEX_VIRT_HEIGHT] < yres)
                vga_state.vbe_regs[VBE_DISPI_INDEX_VIRT_HEIGHT] = yres;
            vga_state.vbe_regs[VBE_DISPI_INDEX_X_OFFSET] = 0;
            vga_state.vbe_regs[VBE_DISPI_INDEX_Y_OFFSET] = 0;

            pr_info("[BOGGER-VGA] Mode set: %ux%u @ %ubpp (LFB=%s)\n",
                    xres, yres, bpp,
                    (val & VBE_DISPI_LFB_ENABLED) ? "yes" : "no");
        }
        break;
    }

    case VBE_DISPI_INDEX_BANK:
        vga_state.vbe_regs[idx] = val;
        break;

    case VBE_DISPI_INDEX_VIRT_WIDTH: {
        u16 bpp = vga_state.vbe_regs[VBE_DISPI_INDEX_BPP];
        u32 bytes_pp = ((u32)bpp + 7) / 8;
        if (val == 0) val = 1;
        /* Ensure stride fits in memory */
        if ((u32)val * bytes_pp > VGA_FB_SIZE)
            val = (u16)(VGA_FB_SIZE / bytes_pp);
        vga_state.vbe_regs[idx] = val;
        break;
    }

    case VBE_DISPI_INDEX_VIRT_HEIGHT:
    case VBE_DISPI_INDEX_X_OFFSET:
    case VBE_DISPI_INDEX_Y_OFFSET:
        vga_state.vbe_regs[idx] = val;
        break;

    case VBE_DISPI_INDEX_VIDEO_MEMORY_64K:
        /* Read-only — ignore writes */
        break;

    default:
        vga_state.vbe_regs[idx] = val;
        break;
    }
}

/* ══════════════════════════════════════════════════════════════════
 * Standard VGA Register I/O (ports 0x3C0-0x3DF)
 * ══════════════════════════════════════════════════════════════════ */

u32 bogger_vga_ioport_read(u16 port, int sz)
{
    u32 val = 0;

    switch (port) {
    /* ── Bochs VBE Dispi ─────────────────────────────────────── */
    case 0x1CE:
        val = vga_state.vbe_index;
        break;
    case 0x1CF:
        val = vbe_dispi_read();
        break;
    case 0x1D0:
        /* Extended Bochs ID register */
        val = VBE_DISPI_ID5;
        break;

    /* ── Attribute Controller ──────────────────────────────── */
    case 0x3C0:
        val = vga_state.attr_index;
        break;
    case 0x3C1:
        if (vga_state.attr_index < 32)
            val = vga_state.attr_regs[vga_state.attr_index & 0x1F];
        break;

    /* ── Misc Output (read) ──────────────────────────────── */
    case 0x3CC:
        val = vga_state.misc_output;
        break;

    /* ── Input Status 0 ───────────────────────────────────── */
    case 0x3C2:
        val = 0x00;  /* no switch sense */
        break;

    /* ── Sequencer ─────────────────────────────────────────── */
    case 0x3C4:
        val = vga_state.seq_index;
        break;
    case 0x3C5:
        if (vga_state.seq_index < 8)
            val = vga_state.seq_regs[vga_state.seq_index];
        break;

    /* ── DAC Palette ───────────────────────────────────────── */
    case 0x3C6:
        val = 0xFF;  /* Pixel Mask: all bits enabled */
        break;
    case 0x3C7:
        val = vga_state.dac_state;  /* 0=write mode, 3=read mode */
        break;
    case 0x3C8:
        val = vga_state.dac_write_index;
        break;
    case 0x3C9: {
        u8 idx = vga_state.dac_read_index;
        u8 sub = vga_state.dac_sub_index;
        val = vga_state.dac_palette[idx][sub];
        vga_state.dac_sub_index++;
        if (vga_state.dac_sub_index >= 3) {
            vga_state.dac_sub_index = 0;
            vga_state.dac_read_index++;
        }
        break;
    }

    /* ── Feature Control (read) ───────────────────────────── */
    case 0x3CA:
        val = vga_state.feature_ctrl;
        break;

    /* ── Graphics Controller ────────────────────────────────── */
    case 0x3CE:
        val = vga_state.gfx_index;
        break;
    case 0x3CF:
        if (vga_state.gfx_index < 16)
            val = vga_state.gfx_regs[vga_state.gfx_index];
        break;

    /* ── CRT Controller ────────────────────────────────────── */
    case 0x3D4:
        val = vga_state.crtc_index;
        break;
    case 0x3D5:
        if (vga_state.crtc_index < 32)
            val = vga_state.crtc_regs[vga_state.crtc_index];
        break;

    /* ── Input Status 1 (0x3DA/0x3BA) ─────────────────────── */
    case 0x3DA:
    case 0x3BA: {
        /* Reading IST1 resets the attribute controller flip-flop
         * and toggles the VRetrace/Display bits.
         * Bit 0: Display Enable (inverted — 1 during blanking)
         * Bit 3: Vertical Retrace */
        vga_state.attr_flip_flop = false;
        vga_state.ist1_toggle ^= 0x01;
        val = (vga_state.ist1_toggle & 0x01) ? 0x09 : 0x00;
        break;
    }

    /* Other VGA ports */
    case 0x3C3:  /* VGA Enable */
        val = 0x01;  /* VGA enabled */
        break;
    case 0x3CB:
    case 0x3CD:
        val = 0;
        break;

    default:
        val = 0;
        break;
    }

    return val;
}

void bogger_vga_ioport_write(u16 port, u32 val, int sz)
{
    switch (port) {
    /* ── Bochs VBE Dispi ─────────────────────────────────────── */
    case 0x1CE:
        vga_state.vbe_index = (u16)(val & 0xFF);
        break;
    case 0x1CF:
        vbe_dispi_write((u16)val);
        break;
    case 0x1D0:
        /* Extended — sometimes used as alias for data write */
        vbe_dispi_write((u16)val);
        break;

    /* ── Attribute Controller ──────────────────────────────── */
    case 0x3C0:
        if (!vga_state.attr_flip_flop) {
            /* Index byte */
            vga_state.attr_index = val & 0x3F;
        } else {
            /* Data byte */
            if ((vga_state.attr_index & 0x1F) < 32)
                vga_state.attr_regs[vga_state.attr_index & 0x1F] = (u8)val;
        }
        vga_state.attr_flip_flop = !vga_state.attr_flip_flop;
        break;

    /* ── Misc Output Register (write: 0x3C2) ──────────────── */
    case 0x3C2:
        vga_state.misc_output = (u8)val;
        break;

    /* ── Sequencer ─────────────────────────────────────────── */
    case 0x3C4:
        vga_state.seq_index = (u8)(val & 0x07);
        break;
    case 0x3C5:
        if (vga_state.seq_index < 8)
            vga_state.seq_regs[vga_state.seq_index] = (u8)val;
        break;

    /* ── DAC ───────────────────────────────────────────────── */
    case 0x3C6:
        /* Pixel Mask — accept but ignore */
        break;
    case 0x3C7:
        /* DAC Read Mode: set read index */
        vga_state.dac_read_index = (u8)val;
        vga_state.dac_sub_index = 0;
        vga_state.dac_state = 3;  /* read mode */
        break;
    case 0x3C8:
        vga_state.dac_write_index = (u8)val;
        vga_state.dac_sub_index = 0;
        vga_state.dac_state = 0;  /* write mode */
        break;
    case 0x3C9: {
        u8 idx = vga_state.dac_write_index;
        u8 sub = vga_state.dac_sub_index;
        vga_state.dac_palette[idx][sub] = (u8)(val & 0x3F);
        vga_state.dac_sub_index++;
        if (vga_state.dac_sub_index >= 3) {
            vga_state.dac_sub_index = 0;
            vga_state.dac_write_index++;
        }
        break;
    }

    /* ── Graphics Controller ────────────────────────────────── */
    case 0x3CE:
        vga_state.gfx_index = (u8)(val & 0x0F);
        break;
    case 0x3CF:
        if (vga_state.gfx_index < 16)
            vga_state.gfx_regs[vga_state.gfx_index] = (u8)val;
        break;

    /* ── CRT Controller ────────────────────────────────────── */
    case 0x3D4:
        vga_state.crtc_index = (u8)(val & 0x1F);
        break;
    case 0x3D5:
        if (vga_state.crtc_index < 32)
            vga_state.crtc_regs[vga_state.crtc_index] = (u8)val;
        break;

    /* ── Feature Control (write: 0x3DA/0x3BA) ─────────────── */
    case 0x3DA:
    case 0x3BA:
        vga_state.feature_ctrl = (u8)val;
        break;

    /* ── VGA Enable (0x3C3) ──────────────────────────────── */
    case 0x3C3:
        /* Accept but ignore */
        break;

    default:
        break;
    }
}
