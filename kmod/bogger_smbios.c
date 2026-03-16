// SPDX-License-Identifier: GPL-2.0
/*
 * bogger_smbios.c – SMBIOS table generator for stealth hardware identity
 *
 * Generates realistic SMBIOS tables that make Windows think it's running
 * on real hardware (not a VM).  Uses common OEM strings to avoid detection.
 */
#include "bogger_smbios.h"

static u8 smbios_buf[4096];
static u32 smbios_len;

/* Helper: append a raw SMBIOS structure + string table */
static u32 smbios_add_struct(u8 *buf, u32 pos, u8 type, u8 hdr_len,
                             const u8 *data, u8 data_len,
                             const char **strings, int nstrings)
{
    int i;
    /* Header */
    buf[pos] = type;
    buf[pos + 1] = hdr_len;
    *(u16 *)(buf + pos + 2) = 0; /* handle: auto-assign later */
    /* Copy data (starts at offset 4 within structure) */
    if (data_len > 0 && data)
        memcpy(buf + pos + 4, data, data_len);
    /* String table follows the formatted area */
    {
        u32 sp = pos + hdr_len;
        for (i = 0; i < nstrings; i++) {
            int slen = strlen(strings[i]);
            memcpy(buf + sp, strings[i], slen);
            sp += slen;
            buf[sp++] = 0; /* NUL terminator for each string */
        }
        if (nstrings == 0)
            buf[sp++] = 0; /* empty string section needs one NUL */
        buf[sp++] = 0; /* double NUL = end of string table */
        return sp;
    }
}

int bogger_smbios_build(void)
{
    u32 pos = 0;
    u16 handle = 0;

    memset(smbios_buf, 0, sizeof(smbios_buf));

    /* ── Type 0: BIOS Information ──────────────────────────────────── */
    {
        u8 data[16];
        const char *str[] = {
            "American Megatrends Inc.",   /* 1: Vendor */
            "5.17",                       /* 2: BIOS Version */
            "03/01/2024",                 /* 3: Release Date */
        };
        memset(data, 0, sizeof(data));
        data[0] = 1;     /* Vendor (string 1) */
        data[1] = 2;     /* BIOS Version (string 2) */
        *(u16 *)(data + 2) = 0xE800; /* BIOS starting address segment */
        data[4] = 3;     /* BIOS Release Date (string 3) */
        data[5] = 0xFF;  /* BIOS ROM Size (16 MB) */
        /* BIOS Characteristics */
        *(u64 *)(data + 6) = 0x000000007CBBDE98ULL;
        data[14] = 0x01; /* BIOS Char Extension Byte 1 */
        data[15] = 0x0C; /* BIOS Char Extension Byte 2 */
        pos = smbios_add_struct(smbios_buf, pos, 0, 0x1A, data, 16, str, 3);
        *(u16 *)(smbios_buf + 2) = handle++;
    }

    /* ── Type 1: System Information ────────────────────────────────── */
    {
        u8 data[21];
        const char *str[] = {
            "ASUS",                       /* 1: Manufacturer */
            "ROG STRIX B550-F GAMING",    /* 2: Product Name */
            "1.0",                        /* 3: Version */
            "System Serial Number",       /* 4: Serial Number */
            "Desktop",                    /* 5: SKU */
            "ROG STRIX B550-F GAMING",    /* 6: Family */
        };
        memset(data, 0, sizeof(data));
        data[0] = 1;  /* Manufacturer (string 1) */
        data[1] = 2;  /* Product Name (string 2) */
        data[2] = 3;  /* Version (string 3) */
        data[3] = 4;  /* Serial Number (string 4) */
        /* UUID: random-looking but consistent */
        *(u32 *)(data + 4) = 0x4D41534B;
        *(u16 *)(data + 8) = 0x1234;
        *(u16 *)(data + 10) = 0x5678;
        data[12] = 0x90; data[13] = 0xAB;
        data[14] = 0xCD; data[15] = 0xEF;
        data[16] = 0x01; data[17] = 0x23;
        data[18] = 0x06; /* Wake-up type: Power Switch */
        data[19] = 5;    /* SKU (string 5) */
        data[20] = 6;    /* Family (string 6) */
        pos = smbios_add_struct(smbios_buf, pos, 1, 0x1B, data, 21, str, 6);
        *(u16 *)(smbios_buf + pos - smbios_len + 2) = handle; /* fixup later */
        handle++;
    }

    /* ── Type 2: Baseboard Information ─────────────────────────────── */
    {
        u8 data[11];
        const char *str[] = {
            "ASUSTeK COMPUTER INC.",      /* 1: Manufacturer */
            "ROG STRIX B550-F GAMING",    /* 2: Product */
            "Rev 1.xx",                   /* 3: Version */
            "MB-1234567890",              /* 4: Serial */
            "Base Board",                 /* 5: Asset Tag */
        };
        memset(data, 0, sizeof(data));
        data[0] = 1; data[1] = 2; data[2] = 3; data[3] = 4;
        data[4] = 5;  /* Asset Tag */
        data[5] = 0x09; /* Feature flags: hosting board, replaceable */
        data[6] = 0;    /* Location in chassis (string 0 = none) */
        *(u16 *)(data + 7) = 0x0002; /* Chassis handle */
        data[9] = 0x0A;  /* Board type: Motherboard */
        data[10] = 0;    /* Num contained object handles */
        pos = smbios_add_struct(smbios_buf, pos, 2, 0x0F, data, 11, str, 5);
        handle++;
    }

    /* ── Type 3: Chassis Information ───────────────────────────────── */
    {
        u8 data[17];
        const char *str[] = {
            "ASUSTeK COMPUTER INC.",      /* 1: Manufacturer */
            "Default string",             /* 2: Version */
            "Chassis Serial",             /* 3: Serial */
            "ATX",                        /* 4: Asset Tag */
        };
        memset(data, 0, sizeof(data));
        data[0] = 1;     /* Manufacturer */
        data[1] = 0x03;  /* Type: Desktop */
        data[2] = 2;     /* Version */
        data[3] = 3;     /* Serial */
        data[4] = 4;     /* Asset Tag */
        data[5] = 0x03;  /* Boot-up state: Safe */
        data[6] = 0x03;  /* Power Supply: Safe */
        data[7] = 0x03;  /* Thermal: Safe */
        data[8] = 0x02;  /* Security: Unknown */
        pos = smbios_add_struct(smbios_buf, pos, 3, 0x15, data, 17, str, 4);
        handle++;
    }

    /* ── Type 4: Processor Information ─────────────────────────────── */
    {
        u8 data[40];
        const char *str[] = {
            "CPU0",                                    /* 1: Socket */
            "Advanced Micro Devices, Inc.",             /* 2: Manufacturer */
            "AMD Ryzen 9 5950X 16-Core Processor",     /* 3: Version */
        };
        memset(data, 0, sizeof(data));
        data[0] = 1;     /* Socket (string 1) */
        data[1] = 0x03;  /* Processor type: Central */
        data[2] = 0x02;  /* Processor family (from SMBIOS spec) */
        data[3] = 2;     /* Manufacturer (string 2) */
        /* Processor ID (first 8 bytes of CPUID EAX=1) */
        *(u64 *)(data + 4) = 0x0800F12ULL;
        data[12] = 3;     /* Version (string 3) */
        data[13] = 0x00;  /* Voltage: legacy mode */
        *(u16 *)(data + 14) = 4000; /* External clock: 100 MHz (in MHz units actually, but SMBIOS uses variable encoding) */
        *(u16 *)(data + 16) = 4900; /* Max speed MHz */
        *(u16 *)(data + 18) = 3400; /* Current speed MHz */
        data[20] = 0x41;  /* Status: enabled, populated */
        data[21] = 0x08;  /* Upgrade: AM4 */
        /* L1/L2/L3 cache handles — 0xFFFF = not provided */
        *(u16 *)(data + 22) = 0xFFFF;
        *(u16 *)(data + 24) = 0xFFFF;
        *(u16 *)(data + 26) = 0xFFFF;
        data[28] = 0;  /* Serial (none) */
        data[29] = 0;  /* Asset Tag (none) */
        data[30] = 0;  /* Part Number (none) */
        data[31] = 1;  /* Core count */
        data[32] = 1;  /* Core enabled */
        data[33] = 1;  /* Thread count */
        *(u16 *)(data + 34) = 0x00EC; /* Processor characteristics */
        *(u16 *)(data + 36) = 0x02;   /* Processor family 2 */
        pos = smbios_add_struct(smbios_buf, pos, 4, 0x30, data, 38, str, 3);
        handle++;
    }

    /* ── Type 16: Physical Memory Array ────────────────────────────── */
    {
        u8 data[11];
        const char *str[] = { NULL };
        memset(data, 0, sizeof(data));
        data[0] = 0x03;  /* Location: System board */
        data[1] = 0x03;  /* Use: System memory */
        data[2] = 0x06;  /* Error correction: None */
        /* Max capacity in KB */
        *(u32 *)(data + 3) = (u32)((guest_ram_size >> 10) & 0xFFFFFFFF);
        *(u16 *)(data + 7) = 0xFFFE; /* Error info handle: Not provided */
        *(u16 *)(data + 9) = 1; /* Num memory devices */
        pos = smbios_add_struct(smbios_buf, pos, 16, 0x17, data, 11, str, 0);
        handle++;
    }

    /* ── Type 17: Memory Device ────────────────────────────────────── */
    {
        u8 data[32];
        u16 size_mb = (u16)((guest_ram_size >> 20) & 0x7FFF);
        const char *str[] = {
            "DIMM_A1",                    /* 1: Device Locator */
            "ChannelA-DIMM0",             /* 2: Bank Locator */
            "Samsung",                    /* 3: Manufacturer */
            "M378A1K43DB2-CVF",           /* 4: Part Number */
        };
        memset(data, 0, sizeof(data));
        *(u16 *)(data + 0) = handle - 1; /* Physical memory array handle */
        *(u16 *)(data + 2) = 0xFFFE;     /* Error info handle */
        *(u16 *)(data + 4) = 0;          /* Total width: Unknown */
        *(u16 *)(data + 6) = 64;         /* Data width: 64 bits */
        *(u16 *)(data + 8) = size_mb;    /* Size in MB */
        data[10] = 0x09; /* Form factor: DIMM */
        data[11] = 0;    /* Device Set: None */
        data[12] = 1;    /* Device Locator (string 1) */
        data[13] = 2;    /* Bank Locator (string 2) */
        data[14] = 0x1A; /* Memory type: DDR4 */
        *(u16 *)(data + 15) = 0x2000; /* Type detail: Synchronous */
        *(u16 *)(data + 17) = 3200;   /* Speed: 3200 MT/s */
        data[19] = 3;    /* Manufacturer (string 3) */
        data[20] = 0;    /* Serial (none) */
        data[21] = 0;    /* Asset Tag (none) */
        data[22] = 4;    /* Part Number (string 4) */
        pos = smbios_add_struct(smbios_buf, pos, 17, 0x28, data, 23, str, 4);
        handle++;
    }

    /* ── Type 127: End-of-Table ────────────────────────────────────── */
    {
        const char *str[] = { NULL };
        pos = smbios_add_struct(smbios_buf, pos, 127, 4, NULL, 0, str, 0);
    }

    /* Fix up all handles in order */
    {
        u32 scan = 0;
        u16 h = 0;
        while (scan < pos) {
            u8 hlen = smbios_buf[scan + 1];
            *(u16 *)(smbios_buf + scan + 2) = h++;
            /* Skip to end of string section (double NUL) */
            scan += hlen;
            while (scan + 1 < pos && !(smbios_buf[scan] == 0 && smbios_buf[scan + 1] == 0))
                scan++;
            scan += 2;
        }
    }

    smbios_len = pos;
    pr_info("[BOGGER] SMBIOS tables built: %u bytes, realistic hardware identity\n", smbios_len);
    return 0;
}

u8 *bogger_smbios_get_data(u32 *out_len)
{
    if (out_len) *out_len = smbios_len;
    return smbios_buf;
}

