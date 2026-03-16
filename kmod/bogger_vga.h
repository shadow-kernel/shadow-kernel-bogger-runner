/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOGGER_VGA_H
#define BOGGER_VGA_H
#include "bogger_types.h"

/* ── Bochs VBE Dispi Interface ────────────────────────────────────── */
#define VBE_DISPI_INDEX_ID               0x00
#define VBE_DISPI_INDEX_XRES             0x01
#define VBE_DISPI_INDEX_YRES             0x02
#define VBE_DISPI_INDEX_BPP              0x03
#define VBE_DISPI_INDEX_ENABLE           0x04
#define VBE_DISPI_INDEX_BANK             0x05
#define VBE_DISPI_INDEX_VIRT_WIDTH       0x06
#define VBE_DISPI_INDEX_VIRT_HEIGHT      0x07
#define VBE_DISPI_INDEX_X_OFFSET         0x08
#define VBE_DISPI_INDEX_Y_OFFSET         0x09
#define VBE_DISPI_INDEX_VIDEO_MEMORY_64K 0x0A
#define VBE_DISPI_INDEX_DDC              0x0B
#define VBE_DISPI_INDEX_NB               0x0C

#define VBE_DISPI_ID0                    0xB0C0
#define VBE_DISPI_ID5                    0xB0C5
#define VBE_DISPI_DISABLED               0x00
#define VBE_DISPI_ENABLED                0x01
#define VBE_DISPI_LFB_ENABLED           0x40

/* VGA framebuffer: 16 MB at GPA 0xE0000000 (inside PCI MMIO aperture) */
#define VGA_FB_GPA      0xE0000000ULL
#define VGA_FB_SIZE     (16ULL * 1024 * 1024)
#define VGA_FB_64K      (VGA_FB_SIZE / (64 * 1024))  /* 256 */
/* VGA extended MMIO (BAR2): 16 MB at GPA 0xE1000000 */
#define VGA_MMIO_GPA    0xE1000000ULL

/* ── VGA State ────────────────────────────────────────────────────── */
struct bogger_vga_state {
    /* Bochs VBE Dispi registers */
    u16 vbe_index;
    u16 vbe_regs[VBE_DISPI_INDEX_NB];

    /* VGA standard registers */
    u8  misc_output;     /* 3C2 write / 3CC read */
    u8  seq_index;       /* 3C4 */
    u8  seq_regs[8];     /* 3C5 data */
    u8  gfx_index;       /* 3CE */
    u8  gfx_regs[16];   /* 3CF data */
    u8  crtc_index;      /* 3D4 */
    u8  crtc_regs[32];  /* 3D5 data */
    u8  attr_index;      /* 3C0 */
    u8  attr_regs[32];  /* 3C0/3C1 data */
    bool attr_flip_flop; /* toggles on 3C0 writes (reset by reading 3DA) */
    u8  dac_read_index;  /* 3C7 */
    u8  dac_write_index; /* 3C8 */
    u8  dac_state;       /* 3C7 read */
    u8  dac_sub_index;   /* 0-2 for R/G/B within a palette entry */
    u8  dac_palette[256][3]; /* 256 entries, each R/G/B */
    u8  feature_ctrl;    /* 3DA write / 3CA read */

    /* Input Status 1 — VRetrace toggle */
    u8  ist1_toggle;

    /* EDID/DDC state for Bochs VBE DDC register (index 0x0B) */
    u8  edid_idx;        /* current byte index into EDID block */
};

extern struct bogger_vga_state vga_state;
extern const u8 bogger_edid_block[128];

void bogger_vga_init(void);
u32  bogger_vga_ioport_read(u16 port, int sz);
void bogger_vga_ioport_write(u16 port, u32 val, int sz);

#endif /* BOGGER_VGA_H */
