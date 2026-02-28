/*
 * bogger_kmod.c – BOGGER Hypervisor Kernel Module (AMD SVM)
 *
 * Loads OVMF UEFI firmware into guest-physical memory, starts the guest
 * in x86 Real Mode at the reset vector (0xFFFFFFF0), and enters a VMRUN
 * loop.  OVMF discovers the NVMe disk, finds bootmgfw.efi on the EFI
 * System Partition, and boots Windows as a nested guest.
 *
 * Boot flow:
 *   1. Verify CPU SVM support
 *   2. Allocate guest RAM, build NPT
 *   3. Load OVMF_CODE.fd at top of 4GB (GPA 0xFFC00000)
 *   4. Load OVMF_VARS.fd at GPA 0xFF800000
 *   5. Configure VMCB for 16-bit Real Mode (reset vector)
 *   6. VMRUN → OVMF boots → Windows starts
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/fs.h>
#include <linux/kernel_read_file.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/cpufeature.h>
#include <asm/io.h>
#include <asm/svm.h>
#include <asm/page.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BOGGER");
MODULE_DESCRIPTION("BOGGER Hypervisor — boots Windows via OVMF/AMD SVM");

static char *bogger_efi = "";
module_param(bogger_efi, charp, 0444);
MODULE_PARM_DESC(bogger_efi, "Path to Windows EFI binary (legacy, used for ESP scanning)");

static char *bogger_ovmf_code = "/usr/share/edk2/x64/OVMF_CODE.4m.fd";
module_param(bogger_ovmf_code, charp, 0444);
MODULE_PARM_DESC(bogger_ovmf_code, "Path to OVMF_CODE firmware file");

static char *bogger_ovmf_vars = "";
module_param(bogger_ovmf_vars, charp, 0444);
MODULE_PARM_DESC(bogger_ovmf_vars, "Path to OVMF_VARS file (optional)");

static unsigned int bogger_ram_mb = 0;  /* 0 = auto-detect */
module_param(bogger_ram_mb, uint, 0444);
MODULE_PARM_DESC(bogger_ram_mb, "Guest RAM in MB (0=auto: 50%% of free, min 128, max 4096)");

/* ── Tracks whether EFER.SVME was set so exit() can clear it ─────── */
static bool svm_enabled;

/* ── SVM structures ───────────────────────────────────────────────── */
static void *hsave_area;        /* 4 KB Host Save Area  (page-aligned) */
static struct vmcb *g_vmcb;     /* 4 KB VMCB            (page-aligned) */

/* Forward declaration — defined with MSR bitmap code below */
#define MSRPM_SIZE  (2 * PAGE_SIZE)   /* 8 KB = 2 pages */
static void *msr_bitmap;

/* I/O Permission Map — required when INTERCEPT_IOIO_PROT is set.
 * 12 KB (3 pages), one bit per port (65536 ports / 8 = 8192 bytes + extra).
 * AMD spec: IOPM must be exactly 12 KB (3 contiguous 4 KB pages).
 * Bit = 1 → intercept I/O on that port.                               */
#define IOPM_SIZE   (3 * PAGE_SIZE)   /* 12 KB = 3 pages */
static void *io_bitmap;

#define BOGGER_SVM_EXIT_INVALID  0xffffffffU

/* ── fw_cfg emulation (QEMU Firmware Configuration) ──────────────── */
/* OVMF reads RAM size and E820 map from fw_cfg.
 * Port 0x510 = selector (write), Port 0x511 = data (read, byte stream) */
/* Forward-declare guest_ram_size (defined below with Guest RAM section) */
static u64 guest_ram_size;
#define FW_CFG_SIGNATURE    0x0000
#define FW_CFG_ID           0x0001
#define FW_CFG_RAM_SIZE     0x0003
#define FW_CFG_NB_CPUS      0x0005
#define FW_CFG_MAX_CPUS     0x0006
#define FW_CFG_FILE_DIR     0x0019
#define FW_CFG_E820_TABLE   0x8003  /* OVMF uses this for e820 */

/* fw_cfg file selectors — must match directory entries */
#define FW_CFG_FILE_E820    0x0020  /* etc/e820 → selector 0x20 */

static u16 fwcfg_selector;
static u32 fwcfg_offset;

/* E820 table entry (packed, QEMU format) */
struct __attribute__((packed)) fw_e820_entry {
    u64 address;
    u64 length;
    u32 type;
};

/* QEMU fw_cfg file directory entry */
struct __attribute__((packed)) fw_cfg_file {
    u32 size;       /* big-endian */
    u16 select;     /* big-endian */
    u16 reserved;
    char name[56];
};

/* Static buffers for fw_cfg data */
static u8 fwcfg_buf[512];
static u32 fwcfg_buf_len;
static bool fwcfg_buf_valid;

static void fwcfg_build_data(u16 sel)
{
    fwcfg_buf_len = 0;
    fwcfg_buf_valid = true;

    switch (sel) {
    case FW_CFG_SIGNATURE:
        memcpy(fwcfg_buf, "QEMU", 4);
        fwcfg_buf_len = 4;
        break;

    case FW_CFG_ID:
        /* Features: bit0=traditional — big-endian u32 */
        fwcfg_buf[0] = 0; fwcfg_buf[1] = 0;
        fwcfg_buf[2] = 0; fwcfg_buf[3] = 1;
        fwcfg_buf_len = 4;
        break;

    case FW_CFG_NB_CPUS:
    case FW_CFG_MAX_CPUS:
        /* big-endian u16 = 1 */
        fwcfg_buf[0] = 0; fwcfg_buf[1] = 1;
        fwcfg_buf_len = 2;
        break;

    case FW_CFG_RAM_SIZE: {
        /* little-endian u64 */
        u64 sz = guest_ram_size;
        memcpy(fwcfg_buf, &sz, 8);
        fwcfg_buf_len = 8;
        break;
    }

    case FW_CFG_FILE_DIR: {
        /* File directory: 1 file (etc/e820) */
        struct fw_cfg_file *f;
        u64 below_4g = guest_ram_size;
        u32 e820_size;
        u32 cnt;

        if (below_4g > 0xC0000000ULL)
            below_4g = 0xC0000000ULL;
        /* etc/e820: 3 entries × 20 bytes each = 60 bytes */
        e820_size = 3 * sizeof(struct fw_e820_entry);

        /* count (big-endian u32) */
        cnt = cpu_to_be32(1);
        memcpy(fwcfg_buf, &cnt, 4);

        /* File entry */
        f = (struct fw_cfg_file *)(fwcfg_buf + 4);
        f->size = cpu_to_be32(e820_size);
        f->select = cpu_to_be16(FW_CFG_FILE_E820);
        f->reserved = 0;
        memset(f->name, 0, 56);
        strncpy(f->name, "etc/e820", 55);

        fwcfg_buf_len = 4 + sizeof(struct fw_cfg_file);
        break;
    }

    case FW_CFG_FILE_E820: {
        /* etc/e820 — raw e820 entries (no count prefix) */
        struct fw_e820_entry *e = (struct fw_e820_entry *)fwcfg_buf;
        u64 below_4g = guest_ram_size;
        if (below_4g > 0xC0000000ULL)
            below_4g = 0xC0000000ULL;

        /* Entry 0: 0-640KB usable */
        e[0].address = cpu_to_le64(0);
        e[0].length  = cpu_to_le64(0xA0000ULL);
        e[0].type    = cpu_to_le32(1);

        /* Entry 1: 1MB - below_4g: usable */
        e[1].address = cpu_to_le64(0x100000ULL);
        e[1].length  = cpu_to_le64(below_4g - 0x100000ULL);
        e[1].type    = cpu_to_le32(1);

        /* Entry 2: reserved MMIO hole */
        e[2].address = cpu_to_le64(0xC0000000ULL);
        e[2].length  = cpu_to_le64(0x40000000ULL);
        e[2].type    = cpu_to_le32(2);

        fwcfg_buf_len = 3 * sizeof(struct fw_e820_entry);
        break;
    }

    case FW_CFG_E820_TABLE: {
        /* Legacy e820: u32 count (big-endian) + entries */
        struct fw_e820_entry entries[4];
        u32 cnt_be;
        u64 below_4g = guest_ram_size;
        if (below_4g > 0xC0000000ULL)
            below_4g = 0xC0000000ULL;

        entries[0].address = 0;
        entries[0].length  = 0xA0000ULL;
        entries[0].type    = 1;
        entries[1].address = 0x100000ULL;
        entries[1].length  = below_4g - 0x100000ULL;
        entries[1].type    = 1;
        entries[2].address = 0xC0000000ULL;
        entries[2].length  = 0x40000000ULL;
        entries[2].type    = 2;

        cnt_be = cpu_to_be32(3);
        memcpy(fwcfg_buf, &cnt_be, 4);
        memcpy(fwcfg_buf + 4, entries, 3 * sizeof(struct fw_e820_entry));
        fwcfg_buf_len = 4 + 3 * sizeof(struct fw_e820_entry);
        break;
    }

    default:
        fwcfg_buf_valid = false;
        break;
    }
}

static u8 fwcfg_read_byte(void)
{
    u8 val = 0;
    if (!fwcfg_buf_valid)
        fwcfg_build_data(fwcfg_selector);
    if (fwcfg_offset < fwcfg_buf_len)
        val = fwcfg_buf[fwcfg_offset];
    fwcfg_offset++;
    return val;
}

/* ── Guest RAM ────────────────────────────────────────────────────── */
/* Guest RAM size is determined at runtime:
 *   - If bogger_ram_mb > 0: use that exact value
 *   - If bogger_ram_mb == 0 (auto): use 50% of free RAM, clamped to [128 MB, 4096 MB]
 * The compile-time GUEST_RAM_MAX defines upper limits for static arrays. */
#define GUEST_RAM_MAX_SIZE  (4ULL * 1024 * 1024 * 1024)  /* 4 GB absolute max */
#define GUEST_RAM_MAX_PAGES (GUEST_RAM_MAX_SIZE >> PAGE_SHIFT)
#define GUEST_RAM_GPA_BASE  0x00000000ULL  /* Guest sees RAM at GPA 0 */

static unsigned long  guest_ram_pages_target; /* actual page count target */

static struct page **guest_pages;
static void *guest_ram_virt;           /* vmalloc'd virtual mapping    */
static unsigned long guest_nr_pages;

/* Zero page used for NPF: unmapped guest areas map here (read returns 0) */
static struct page *npt_zero_page;

/* ── Guest-physical layout ────────────────────────────────────────── */
/* These are *guest-physical* addresses inside the guest RAM.         */
#define GUEST_GDT_GPA       0x1000ULL
#define GUEST_PT_PML4_GPA   0x2000ULL
#define GUEST_PT_PDPT_GPA   0x3000ULL
#define GUEST_PT_PD_GPA     0x4000ULL
#define GUEST_PT_PD1_GPA    0x5000ULL
#define GUEST_PT_PD2_GPA    0x6000ULL
#define GUEST_PT_PD3_GPA    0x7000ULL
#define GUEST_STACK_TOP_GPA 0x00800000ULL

/* ── OVMF firmware layout (4 MB flash) ──────────────────────────── */
/* OVMF 4M layout occupies the top 4MB of the 32-bit address space:
 *   OVMF_VARS:  GPA 0xFFC00000 – 0xFFC83FFF  (528 KB = 540672 bytes)
 *   OVMF_CODE:  GPA 0xFFC84000 – 0xFFFFFFFF  (3.5 MB = 3653632 bytes)
 * Total flash:  4 MB = 4194304 bytes
 * Reset vector at GPA 0xFFFFFFF0 falls inside OVMF_CODE.
 *
 * We map the entire 4 MB region into guest RAM pages, overriding the
 * MMIO identity map for that range.                                  */
#define OVMF_FLASH_SIZE     (4ULL * 1024 * 1024)      /* 4 MB total */
#define OVMF_FLASH_GPA      (0x100000000ULL - OVMF_FLASH_SIZE) /* 0xFFC00000 */
#define OVMF_VARS_OFFSET    0                           /* start of flash */
#define OVMF_CODE_MAX_SIZE  (4ULL * 1024 * 1024)        /* worst case */

/* Firmware pages (allocated separately from guest RAM) */
static struct page **ovmf_pages;
static unsigned long  ovmf_nr_pages;
static void          *ovmf_virt;  /* vmap of OVMF flash region */

/* ── IO port emulation state ─────────────────────────────────────── */
static u32 pci_config_addr;  /* PCI config space address register (0xCF8) */
static u8  cmos_index;       /* CMOS/RTC index register */

/* ── QEMU fw_cfg DMA state ───────────────────────────────────────── */
/* fw_cfg emulation is defined above with fwcfg_selector/fwcfg_offset */

/* ── HPET emulation (Memory-Mapped at GPA 0xFED00000) ────────────── */
/* HPET runs at ~14.318 MHz (14318180 Hz).
 * OVMF reads the main counter at offset 0x0F0 to measure elapsed time. */
#define HPET_GPA        0xFED00000ULL
#define HPET_FREQ_HZ    14318180ULL  /* HPET standard frequency */
static struct page *hpet_page;
static volatile u32 *hpet_regs;  /* kernel-virtual pointer to HPET page */

static void hpet_init_regs(void)
{
    if (!hpet_regs) return;
    memset((void *)hpet_regs, 0, PAGE_SIZE);
    /* General Capabilities and ID Register (offset 0x000):
     * Bits 31:16 = vendor ID (8086=Intel), Bit 15 = COUNT_SIZE_CAP (64-bit),
     * Bits 12:8 = NUM_TIM_CAP (3 timers), Bits 7:0 = REV_ID (1) */
    hpet_regs[0] = 0x80868201;  /* 64-bit counter, 3 timers, rev 1, vendor 8086 */
    hpet_regs[1] = 69841279;    /* CLK_PERIOD in femtoseconds = 10^15/14318180 ≈ 69841279 fs */
    /* General Configuration (offset 0x010): Enable */
    hpet_regs[4] = 0x01;  /* ENABLE_CNF = 1 */
}

static void hpet_update_counter(void)
{
    u64 ns, ticks;
    if (!hpet_regs) return;
    ns = ktime_get_ns();
    /* Convert nanoseconds to HPET ticks: ticks = ns * 14318180 / 10^9 */
    ticks = div_u64(ns * 14318ULL, 1000000ULL);
    /* Main Counter at offset 0x0F0 (byte offset / 4 = index 0x3C) */
    hpet_regs[0x3C] = (u32)(ticks & 0xFFFFFFFF);       /* low 32 bits */
    hpet_regs[0x3D] = (u32)((ticks >> 32) & 0xFFFFFFFF); /* high 32 bits */
}

/* ── NPT-based HPET trapping ──────────────────────────────────────── */
/* ── HPET counter updater kthread ─────────────────────────────────── */
/* A kernel thread on a different CPU continuously updates the HPET
 * counter in the NPT-mapped page. Since the page is always present,
 * the guest reads fresh values without causing any VMEXITs. */
static struct task_struct *hpet_kthread;
static volatile bool hpet_kthread_stop;

static int hpet_updater_fn(void *data)
{
    pr_info("[BOGGER] HPET updater kthread started on CPU %d\n",
            smp_processor_id());
    while (!hpet_kthread_stop) {
        hpet_update_counter();
        /* Sleep ~100µs — gives ~10KHz counter update rate.
         * OVMF/Windows polling loops need ~1ms resolution. */
        usleep_range(50, 150);
    }
    pr_info("[BOGGER] HPET updater kthread stopped\n");
    return 0;
}

/* Similarly for NVMe BAR pages — trap doorbell writes */
static u64 *nvme_pte_ptrs[4];  /* PTE pointers for NVMe BAR pages */
static u64  nvme_pte_vals[4];  /* full PTE values */

/* ── NVMe Controller MMIO emulation (GPA 0xFE000000) ─────────────── */
#define NVME_BAR_GPA      0xFE000000ULL
#define NVME_BAR_SIZE     0x4000      /* 16 KB register space */
static struct page *nvme_bar_pages[4]; /* 4 pages = 16KB */
static volatile u32 *nvme_regs;       /* kernel-virtual ptr */

/* NVMe Admin Queue state */
static u64 nvme_asq_base;   /* Admin Submission Queue base GPA */
static u64 nvme_acq_base;   /* Admin Completion Queue base GPA */
static u32 nvme_aqa;        /* Admin Queue Attributes */
static u32 nvme_cc;         /* Controller Configuration */
static u32 nvme_csts;       /* Controller Status */

/* NVMe I/O queue state — support up to 4 I/O queue pairs (QID 1..4) */
#define NVME_MAX_IO_QUEUES  4
static u64 nvme_iosq_base[NVME_MAX_IO_QUEUES];  /* I/O SQ GPA per QID */
static u16 nvme_iosq_size[NVME_MAX_IO_QUEUES];  /* I/O SQ entries per QID */
static u64 nvme_iocq_base[NVME_MAX_IO_QUEUES];  /* I/O CQ GPA per QID */
static u16 nvme_iocq_size[NVME_MAX_IO_QUEUES];  /* I/O CQ entries per QID */
static u16 nvme_iosq_head[NVME_MAX_IO_QUEUES];  /* I/O SQ head (controller-side) */
static u16 nvme_iocq_tail[NVME_MAX_IO_QUEUES];  /* I/O CQ tail (controller-side) */
static u8  nvme_iocq_phase[NVME_MAX_IO_QUEUES]; /* I/O CQ phase tag */

/* Host block device opened for NVMe I/O pass-through */
static struct file *nvme_host_dev;

/* Disk backing: pointer to guest RAM where the NVMe disk image lives */
/* The actual disk data comes from the win11.qcow2 which QEMU provides
 * as a host-level NVMe device. We read it from the host and DMA it
 * into guest memory when the guest issues NVMe I/O commands. */

static void nvme_init_regs(void)
{
    if (!nvme_regs) return;
    memset((void *)nvme_regs, 0, NVME_BAR_SIZE);

    /* CAP (offset 0x00): Controller Capabilities — 64 bits
     * Bits 15:0  = MQES: Max Queue Entries Supported (0-based) = 255 → 256 entries
     * Bit 16     = CQR: Contiguous Queues Required = 1
     * Bits 20:17 = AMS: Arbitration Mechanism = 0 (round robin)
     * Bits 31:24 = TO: Timeout (500ms units) = 10 (5 seconds)
     * Bits 39:37 = CSS: Command Set Support = 001 (NVM command set)
     * Bits 51:48 = MPSMIN: Min Memory Page Size (2^(12+n)) = 0 (4KB)
     * Bits 55:52 = MPSMAX: Max Memory Page Size = 0 (4KB) */
    nvme_regs[0] = 0x0A0100FF;  /* low: MQES=255, CQR=1, TO=10 */
    nvme_regs[1] = 0x00000020;  /* high: CSS=NVM, MPSMIN=0, MPSMAX=0 */

    /* VS (offset 0x08): Version = 1.4.0 */
    nvme_regs[2] = 0x00010400;

    /* CC (offset 0x14): Controller Configuration — initially 0 (disabled) */
    nvme_regs[5] = 0x00000000;
    nvme_cc = 0;

    /* CSTS (offset 0x1C): Controller Status — 0 (not ready) */
    nvme_regs[7] = 0x00000000;
    nvme_csts = 0;
}

/* NVMe Admin Queue state variables (must be before nvme_update_regs) */
static u16 nvme_sq_head;
static u16 nvme_cq_tail;
static u8  nvme_cq_phase = 1;

static void nvme_update_regs(void)
{
    if (!nvme_regs) return;

    /* If CC.EN is set and CSTS.RDY is not, transition to ready */
    if ((nvme_cc & 1) && !(nvme_csts & 1)) {
        nvme_csts = 1; /* RDY = 1 */
        nvme_sq_head = 0;
        nvme_cq_tail = 0;
        nvme_cq_phase = 1;
        pr_info("[BOGGER-NVMe] Controller enabled, CSTS.RDY=1\n");
    }
    /* If CC.EN is cleared, go back to not ready */
    if (!(nvme_cc & 1) && (nvme_csts & 1)) {
        nvme_csts = 0;
    }

    /* Write back CSTS to MMIO page */
    nvme_regs[7] = nvme_csts;
    /* Write back CC */
    nvme_regs[5] = nvme_cc;
    /* AQA */
    nvme_regs[9] = nvme_aqa;  /* offset 0x24 / 4 */
    /* ASQ low/high */
    nvme_regs[10] = (u32)(nvme_asq_base & 0xFFFFFFFF);   /* 0x28 */
    nvme_regs[11] = (u32)((nvme_asq_base >> 32) & 0xFFFFFFFF); /* 0x2C */
    /* ACQ low/high */
    nvme_regs[12] = (u32)(nvme_acq_base & 0xFFFFFFFF);   /* 0x30 */
    nvme_regs[13] = (u32)((nvme_acq_base >> 32) & 0xFFFFFFFF); /* 0x34 */
}

/* ── NVMe Admin Queue processing ─────────────────────────────────── */
/* NVMe Submission Queue Entry = 64 bytes.
 * NVMe Completion Queue Entry = 16 bytes. */

/* Disk geometry: the win11.qcow2 NVMe is exposed to the guest.
 * We report a 64GB disk with 512-byte sectors. */
#define NVME_DISK_SECTORS   134217728ULL  /* 64 GB / 512 = 134M sectors */
#define NVME_SECTOR_SIZE    512
#define NVME_NS_ID          1

/* Post a completion entry to the Admin CQ in guest memory */
static void nvme_post_completion(u16 sq_id, u16 cmd_id, u32 dw0, u16 status)
{
    u32 cq_size = ((nvme_aqa >> 16) & 0xFFF) + 1;
    u64 cq_entry_gpa = nvme_acq_base + (u64)nvme_cq_tail * 16;
    u32 cqe[4];  /* 16-byte CQ entry */

    if (!guest_ram_virt || cq_entry_gpa >= guest_ram_size)
        return;

    cqe[0] = dw0;                                           /* DW0: command specific */
    cqe[1] = 0;                                              /* DW1: reserved */
    cqe[2] = (sq_id) | ((u32)nvme_sq_head << 16);           /* DW2: SQHD | SQID */
    cqe[3] = ((u32)cmd_id) | ((u32)(status | (nvme_cq_phase ? 1 : 0)) << 16);
    /* DW3: CID | Status+Phase */

    memcpy((u8 *)guest_ram_virt + cq_entry_gpa, cqe, 16);

    nvme_cq_tail++;
    if (nvme_cq_tail >= cq_size) {
        nvme_cq_tail = 0;
        nvme_cq_phase ^= 1;  /* flip phase tag */
    }
}

/* Process one NVMe admin command from the SQ */
static void nvme_process_admin_cmd(u32 *cmd)
{
    u8  opcode = cmd[0] & 0xFF;
    u16 cmd_id = (cmd[0] >> 16) & 0xFFFF;
    u32 nsid   = cmd[1];
    /* PRP1 is DW4/DW5; PRP2 is DW6/DW7 — note: old code had cmd[6] here (off-by-two bug) */
    u64 prp1   = (u64)cmd[4] | ((u64)cmd[5] << 32);
    u32 cdw10  = cmd[10];

    switch (opcode) {
    case 0x06: { /* Identify */
        u8 cns = cdw10 & 0xFF;
        if (cns == 1 && prp1 < guest_ram_size - 4096) {
            /* Identify Controller — fill 4KB struct */
            u8 *ident = (u8 *)guest_ram_virt + prp1;
            memset(ident, 0, 4096);
            /* VID/SSVID */
            ident[0] = 0x36; ident[1] = 0x1B;  /* PCI VID */
            ident[2] = 0x36; ident[3] = 0x1B;  /* PCI SSVID */
            /* Serial Number (offset 4, 20 bytes) */
            memcpy(ident + 4, "BOGGER-NVME00001    ", 20);
            /* Model Number (offset 24, 40 bytes) */
            memcpy(ident + 24, "BOGGER Virtual NVMe Controller          ", 40);
            /* Firmware Revision (offset 64, 8 bytes) */
            memcpy(ident + 64, "1.0.0   ", 8);
            /* MDTS (offset 77): Max Data Transfer Size = 5 (2^5 = 32 pages = 128KB) */
            ident[77] = 5;
            /* CNTLID (offset 78-79): Controller ID */
            ident[78] = 0x01; ident[79] = 0x00;
            /* NN (offset 516-519): Number of Namespaces = 1 */
            ident[516] = 1;
            /* SQES (offset 512): min=6 (64B), max=6 */
            ident[512] = 0x66;
            /* CQES (offset 513): min=4 (16B), max=4 */
            ident[513] = 0x44;
            nvme_post_completion(0, cmd_id, 0, 0); /* success */
            pr_info("[BOGGER-NVMe] Identify Controller → PRP1=0x%llx\n", prp1);
        } else if (cns == 0 && nsid == NVME_NS_ID && prp1 < guest_ram_size - 4096) {
            /* Identify Namespace */
            u8 *ns = (u8 *)guest_ram_virt + prp1;
            u64 nsze = NVME_DISK_SECTORS;
            memset(ns, 0, 4096);
            /* NSZE (offset 0, 8 bytes): Namespace Size in LBAs */
            memcpy(ns, &nsze, 8);
            /* NCAP (offset 8, 8 bytes): same */
            memcpy(ns + 8, &nsze, 8);
            /* NUSE (offset 16, 8 bytes): same */
            memcpy(ns + 16, &nsze, 8);
            /* FLBAS (offset 26): LBA format index = 0 */
            ns[26] = 0;
            /* LBAF0 (offset 128): Data Size = 9 (2^9 = 512 bytes) */
            ns[128] = 0; ns[129] = 0; ns[130] = 9; ns[131] = 0;
            nvme_post_completion(0, cmd_id, 0, 0);
            pr_info("[BOGGER-NVMe] Identify Namespace %u → %llu sectors\n",
                    nsid, nsze);
        } else if (cns == 2 && prp1 < guest_ram_size - 4096) {
            /* Active Namespace ID List */
            u32 *list = (u32 *)((u8 *)guest_ram_virt + prp1);
            memset(list, 0, 4096);
            list[0] = NVME_NS_ID;  /* one active namespace */
            nvme_post_completion(0, cmd_id, 0, 0);
        } else {
            /* Unknown CNS — return error */
            nvme_post_completion(0, cmd_id, 0, (0x0002 << 1)); /* Invalid Field */
        }
        break;
    }
    case 0x01: { /* Create I/O Submission Queue */
        u16 qid = cdw10 & 0xFFFF;
        u16 qsz = (u16)((cdw10 >> 16) + 1);
        if (qid >= 1 && qid <= NVME_MAX_IO_QUEUES) {
            nvme_iosq_base[qid - 1] = prp1;  /* PRP1 = queue GPA (PC=1 mode) */
            nvme_iosq_size[qid - 1] = qsz;
            nvme_iosq_head[qid - 1] = 0;
        }
        pr_info("[BOGGER-NVMe] Create IO SQ: QID=%u size=%u base=0x%llx\n",
                qid, qsz, prp1);
        nvme_post_completion(0, cmd_id, 0, 0);
        break;
    }
    case 0x05: { /* Create I/O Completion Queue */
        u16 qid = cdw10 & 0xFFFF;
        u16 qsz = (u16)((cdw10 >> 16) + 1);
        if (qid >= 1 && qid <= NVME_MAX_IO_QUEUES) {
            nvme_iocq_base[qid - 1]  = prp1;  /* PRP1 = queue GPA (PC=1 mode) */
            nvme_iocq_size[qid - 1]  = qsz;
            nvme_iocq_tail[qid - 1]  = 0;
            nvme_iocq_phase[qid - 1] = 1;
        }
        pr_info("[BOGGER-NVMe] Create IO CQ: QID=%u size=%u base=0x%llx\n",
                qid, qsz, prp1);
        nvme_post_completion(0, cmd_id, 0, 0);
        break;
    }
    case 0x09: /* Set Features */
        pr_info("[BOGGER-NVMe] Set Features: FID=%u\n", cdw10 & 0xFF);
        nvme_post_completion(0, cmd_id, 0, 0);
        break;
    case 0x0A: /* Get Features */
        nvme_post_completion(0, cmd_id, 0, 0);
        break;
    default:
        pr_info("[BOGGER-NVMe] Unknown admin opcode=0x%02x cid=%u\n",
                opcode, cmd_id);
        nvme_post_completion(0, cmd_id, 0, (0x0001 << 1)); /* Invalid Opcode */
        break;
    }
}

/* Check doorbell writes and process pending admin commands */
static void nvme_poll_doorbell(void)
{
    u32 sq_size, new_tail;
    u64 sq_entry_gpa;

    if (!nvme_regs || !guest_ram_virt || !(nvme_csts & 1))
        return;

    /* Admin SQ Tail Doorbell is at BAR + 0x1000 (offset 0x1000 / 4 = index 0x400) */
    new_tail = nvme_regs[0x400] & 0xFFFF;
    sq_size = (nvme_aqa & 0xFFF) + 1;

    /* Process all pending submissions */
    while (nvme_sq_head != new_tail) {
        sq_entry_gpa = nvme_asq_base + (u64)nvme_sq_head * 64;
        if (sq_entry_gpa + 64 <= guest_ram_size) {
            u32 *cmd = (u32 *)((u8 *)guest_ram_virt + sq_entry_gpa);
            nvme_process_admin_cmd(cmd);
        }
        nvme_sq_head = (nvme_sq_head + 1) % sq_size;
    }

    /* Update SQHD in MMIO regs so guest can read it */
    /* (The CQ entry already contains SQHD) */
}

/* ── NVMe I/O queue helpers ──────────────────────────────────────── */

/* Post a completion entry to an I/O CQ in guest memory */
static void nvme_post_io_completion(u16 qid, u16 sq_head, u16 cmd_id, u16 status)
{
    u16 qi = qid - 1;
    u64 cq_entry_gpa;
    u32 cqe[4];
    u8  phase;

    if (qid == 0 || qid > NVME_MAX_IO_QUEUES || !nvme_iocq_base[qi])
        return;
    if (!guest_ram_virt)
        return;

    phase = nvme_iocq_phase[qi];
    cq_entry_gpa = nvme_iocq_base[qi] + (u64)nvme_iocq_tail[qi] * 16;
    if (cq_entry_gpa + 16 > guest_ram_size)
        return;

    cqe[0] = 0;
    cqe[1] = 0;
    cqe[2] = (u32)qid | ((u32)sq_head << 16);
    cqe[3] = (u32)cmd_id | ((u32)((status & 0x7FFE) | (phase ? 1 : 0)) << 16);
    memcpy((u8 *)guest_ram_virt + cq_entry_gpa, cqe, 16);

    nvme_iocq_tail[qi]++;
    if (nvme_iocq_size[qi] && nvme_iocq_tail[qi] >= nvme_iocq_size[qi]) {
        nvme_iocq_tail[qi] = 0;
        nvme_iocq_phase[qi] ^= 1;
    }
}

/* Copy data between host device and guest RAM using PRP list */
static int nvme_prp_rw(u64 prp1, u64 prp2, u64 total_bytes,
                       loff_t *pos, bool write)
{
    u64 bytes_done = 0;
    u8 *tmp;
    int rc = 0;

    tmp = kmalloc(PAGE_SIZE, GFP_KERNEL | __GFP_NOWARN);
    if (!tmp)
        return -ENOMEM;

    while (bytes_done < total_bytes) {
        u64 cur_gpa;
        u64 pg_off;
        u64 chunk;
        ssize_t r;

        /* Determine the GPA for this chunk via the PRP chain */
        if (bytes_done == 0) {
            cur_gpa = prp1;
        } else {
            u64 first_page_bytes = PAGE_SIZE - (prp1 & 0xFFFULL);
            u64 after_first = bytes_done - first_page_bytes;

            if (bytes_done < first_page_bytes) {
                /* Still in the first page */
                cur_gpa = prp1 + bytes_done;
            } else if (total_bytes - first_page_bytes <= PAGE_SIZE) {
                /* Entire remainder fits in PRP2 directly */
                cur_gpa = (prp2 & ~0xFFFULL) + after_first;
            } else {
                /* PRP2 is a PRP list: index 0 = second page, 1 = third, … */
                u64 page_idx  = after_first / PAGE_SIZE;
                u64 page_off2 = after_first % PAGE_SIZE;
                u64 list_gpa  = (prp2 & ~0xFFFULL) + page_idx * 8;
                u64 page_gpa;

                if (list_gpa + 8 > guest_ram_size) { rc = -EIO; break; }
                page_gpa = *(u64 *)((u8 *)guest_ram_virt + list_gpa);
                cur_gpa  = (page_gpa & ~0xFFFULL) + page_off2;
            }
        }

        pg_off = cur_gpa & 0xFFFULL;
        chunk  = min_t(u64, total_bytes - bytes_done, PAGE_SIZE - pg_off);
        if (cur_gpa + chunk > guest_ram_size) { rc = -EIO; break; }

        if (write) {
            memcpy(tmp, (u8 *)guest_ram_virt + cur_gpa, chunk);
            r = kernel_write(nvme_host_dev, tmp, chunk, pos);
        } else {
            r = kernel_read(nvme_host_dev, tmp, chunk, pos);
            if (r > 0)
                memcpy((u8 *)guest_ram_virt + cur_gpa, tmp, r);
        }

        if (r <= 0) { rc = -EIO; break; }
        bytes_done += (u64)r;
    }

    kfree(tmp);
    return rc;
}

/* Process one NVMe I/O command (Read or Write) */
static void nvme_process_io_cmd(u16 qid, u16 sq_head, u32 *cmd)
{
    u8  opcode     = cmd[0] & 0xFF;
    u16 cmd_id     = (cmd[0] >> 16) & 0xFFFF;
    u64 prp1       = (u64)cmd[4] | ((u64)cmd[5] << 32);
    u64 prp2       = (u64)cmd[6] | ((u64)cmd[7] << 32);
    u64 slba       = (u64)cmd[10] | ((u64)cmd[11] << 32);
    u32 nlb        = (cmd[12] & 0xFFFF) + 1;  /* 0-based field → add 1 */
    u64 total      = (u64)nlb * NVME_SECTOR_SIZE;
    loff_t pos     = (loff_t)slba * NVME_SECTOR_SIZE;
    u16 status     = 0;

    switch (opcode) {
    case 0x02: /* NVMe Read */
        if (!nvme_host_dev || !guest_ram_virt) {
            status = (0x0002 << 1);  /* Invalid Field */
            break;
        }
        if (nvme_prp_rw(prp1, prp2, total, &pos, false) < 0)
            status = (0x0004 << 1);  /* Data Transfer Error */
        break;
    case 0x01: /* NVMe Write */
        if (!nvme_host_dev || !guest_ram_virt) {
            status = (0x0002 << 1);
            break;
        }
        if (nvme_prp_rw(prp1, prp2, total, &pos, true) < 0)
            status = (0x0004 << 1);
        break;
    default:
        status = (0x0001 << 1);  /* Invalid Opcode */
        break;
    }

    nvme_post_io_completion(qid, sq_head, cmd_id, status);
}

/* Poll I/O queue doorbells and dispatch pending I/O commands */
static void nvme_poll_io_doorbell(void)
{
    unsigned int qi;

    if (!nvme_regs || !guest_ram_virt || !(nvme_csts & 1))
        return;

    for (qi = 0; qi < NVME_MAX_IO_QUEUES; qi++) {
        u16 qid      = (u16)(qi + 1);
        u16 new_tail;
        u16 sq_size;
        u64 sq_entry_gpa;

        if (!nvme_iosq_base[qi] || !nvme_iosq_size[qi])
            continue;

        /* I/O SQ Tail doorbell: BAR + 0x1000 + (2 * qid) * 4 */
        new_tail = (u16)(nvme_regs[0x400 + 2 * qid] & 0xFFFF);
        sq_size  = nvme_iosq_size[qi];

        while (nvme_iosq_head[qi] != new_tail) {
            sq_entry_gpa = nvme_iosq_base[qi] + (u64)nvme_iosq_head[qi] * 64;
            if (sq_entry_gpa + 64 <= guest_ram_size) {
                u32 *cmd = (u32 *)((u8 *)guest_ram_virt + sq_entry_gpa);
                nvme_process_io_cmd(qid, nvme_iosq_head[qi], cmd);
            }
            nvme_iosq_head[qi] = (nvme_iosq_head[qi] + 1) % sq_size;
        }
    }
}

/* ── NPT (Nested Page Tables) ────────────────────────────────────── */
/* 4-level table: PML4 → PDPT → PD → PT (4 KB pages for guest RAM)   */
static u64 *npt_pml4;
static u64 *npt_pdpt;
#define NPT_NUM_PD_TABLES 16   /* cover up to 16 GB GPA (RAM + MMIO) */
static u64 *npt_pd_tables[NPT_NUM_PD_TABLES];

/* ────────────────────────────────────────────────────────────────── */
/* guest_ram_write – copy data to a guest-physical address           */
/* ────────────────────────────────────────────────────────────────── */
static int guest_ram_write(u64 gpa, const void *src, size_t len)
{
    u64 offset;

    if (gpa < GUEST_RAM_GPA_BASE)
        return -EINVAL;
    offset = gpa - GUEST_RAM_GPA_BASE;
    if (offset + len > guest_ram_size)
        return -EINVAL;

    memcpy((u8 *)guest_ram_virt + offset, src, len);
    return 0;
}

/* ────────────────────────────────────────────────────────────────── */
/* guest_ram_ptr – return a kernel-virtual pointer for a GPA         */
/* ────────────────────────────────────────────────────────────────── */
static void *guest_ram_ptr(u64 gpa)
{
    u64 offset;

    if (gpa < GUEST_RAM_GPA_BASE)
        return NULL;
    offset = gpa - GUEST_RAM_GPA_BASE;
    if (offset >= guest_ram_size)
        return NULL;
    return (u8 *)guest_ram_virt + offset;
}

/* ════════════════════════════════════════════════════════════════════
 * Guest RAM allocation – uses individual pages + vmap
 *
 * Instead of requiring a huge contiguous physical block (which fails
 * on real hardware), we allocate individual pages and map them into
 * a contiguous kernel-virtual region with vmap().
 * The NPT then maps each page's HPA to the corresponding GPA.
 *
 * RAM sizing:
 *   bogger_ram_mb=0 (default): auto = 50% of free RAM, clamped [128..4096]
 *   bogger_ram_mb=N:           use exactly N MB
 * ════════════════════════════════════════════════════════════════════ */
static void bogger_compute_ram_size(void)
{
    struct sysinfo si;
    u64 free_bytes, target_bytes;
    unsigned long target_mb;

    if (bogger_ram_mb > 0) {
        /* User-specified size */
        target_mb = bogger_ram_mb;
        if (target_mb > 3072) target_mb = 3072;  /* max 3GB (below MMIO hole at 3GB) */
        if (target_mb < 64)   target_mb = 64;
        pr_info("[BOGGER] Guest RAM: user-requested %lu MB\n", target_mb);
    } else {
        /* Auto-detect: use 50% of currently free RAM (leaves headroom for kernel) */
        si_meminfo(&si);
        free_bytes = (u64)si.freeram * si.mem_unit;
        target_bytes = free_bytes / 2;  /* 50% */
        target_mb = (unsigned long)(target_bytes >> 20);

        /* Clamp: max 3 GB (3072MB) to stay below MMIO hole (0xC0000000=3GB).
         * OVMF places PEI Foundation near top of detected RAM.
         * Min 256MB for a useful guest. */
        if (target_mb > 3072) target_mb = 3072;
        if (target_mb < 256)  target_mb = 256;

        pr_info("[BOGGER] Auto-detect: total=%lluMB free=%lluMB → guest=%luMB (50%%)\n",
                (u64)(si.totalram * si.mem_unit) >> 20,
                free_bytes >> 20,
                target_mb);
    }

    guest_ram_size = (u64)target_mb * 1024 * 1024;
    guest_ram_pages_target = (unsigned long)(guest_ram_size >> PAGE_SHIFT);
}

static int bogger_guest_ram_alloc(void)
{
    unsigned long i;
    unsigned long allocated = 0;

    /* Watermark: stop allocating when free RAM drops below this threshold.
     * Keeps enough memory for kernel, NPT tables, module metadata, etc. */
#define BOGGER_RAM_WATERMARK_BYTES  (384ULL * 1024 * 1024)  /* 384 MB reserved for kernel */
#define BOGGER_RAM_CHECK_INTERVAL   1024                     /* check every ~4 MB */
#define BOGGER_RAM_LOG_INTERVAL     (512UL * 1024 * 1024 / PAGE_SIZE)  /* log every 512 MB */

    /* Determine how much RAM to allocate */
    bogger_compute_ram_size();

    guest_pages = vzalloc(guest_ram_pages_target * sizeof(struct page *));
    if (!guest_pages)
        return -ENOMEM;

    /* Allocate individual pages — use __GFP_NORETRY to NEVER trigger
     * the OOM killer.  If a page can't be allocated, we get NULL
     * immediately and use whatever we got (partial allocation). */
    for (i = 0; i < guest_ram_pages_target; i++) {
        /* Periodically check free memory watermark */
        if ((i % BOGGER_RAM_CHECK_INTERVAL) == 0 && i > 0) {
            struct sysinfo si;
            u64 free_now;

            cond_resched();  /* yield CPU to prevent soft lockup */

            si_meminfo(&si);
            free_now = (u64)si.freeram * si.mem_unit;
            if (free_now < BOGGER_RAM_WATERMARK_BYTES) {
                pr_warn("[BOGGER] Watermark hit: free=%lluMB < %lluMB, stopping at %lu pages (%lu MB)\n",
                        (unsigned long long)(free_now >> 20),
                        (unsigned long long)(BOGGER_RAM_WATERMARK_BYTES >> 20),
                        i, (i * PAGE_SIZE) >> 20);
                break;
            }
        }

        /* Progress logging every 512 MB */
        if ((i % BOGGER_RAM_LOG_INTERVAL) == 0 && i > 0)
            pr_info("[BOGGER] Allocating guest RAM: %lu MB / %lu MB\n",
                    (i * PAGE_SIZE) >> 20,
                    (unsigned long)(guest_ram_pages_target * PAGE_SIZE) >> 20);

        guest_pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO | __GFP_HIGHMEM |
                                     __GFP_NOWARN | __GFP_NORETRY);
        if (!guest_pages[i]) {
            pr_warn("[BOGGER] Page alloc stopped at page %lu/%lu (%lu MB)\n",
                    i, guest_ram_pages_target, (i * PAGE_SIZE) >> 20);
            break;  /* use what we got instead of failing */
        }
        allocated++;
    }

    /* Accept partial allocation if we got at least 128 MB */
    if (allocated < (128UL * 1024 * 1024 / PAGE_SIZE)) {
        pr_err("[BOGGER] Only got %lu MB — need at least 128 MB\n",
               (allocated * PAGE_SIZE) >> 20);
        goto fail_pages;
    }

    /* Adjust actual sizes to what we allocated */
    guest_nr_pages = allocated;
    guest_ram_size = (u64)allocated << PAGE_SHIFT;

    /* Map all pages into a contiguous kernel-virtual region */
    guest_ram_virt = vmap(guest_pages, guest_nr_pages, VM_MAP, PAGE_KERNEL);
    if (!guest_ram_virt) {
        pr_err("[BOGGER] vmap failed for %lu pages\n", guest_nr_pages);
        goto fail_pages;
    }

    pr_info("[BOGGER] Guest RAM: %llu MB (%lu pages, vmap'd, GPA base=0x%llx)\n",
            (unsigned long long)(guest_ram_size >> 20), guest_nr_pages, GUEST_RAM_GPA_BASE);
    return 0;

fail_pages:
    for (i = 0; i < allocated; i++)
        __free_page(guest_pages[i]);
    vfree(guest_pages);
    guest_pages = NULL;
    return -ENOMEM;
}

static void bogger_guest_ram_free(void)
{
    unsigned long i;

    if (guest_ram_virt) {
        vunmap(guest_ram_virt);
        guest_ram_virt = NULL;
    }
    if (guest_pages) {
        for (i = 0; i < guest_nr_pages; i++) {
            if (guest_pages[i])
                __free_page(guest_pages[i]);
        }
        vfree(guest_pages);
        guest_pages = NULL;
    }
}

/* ════════════════════════════════════════════════════════════════════
 * NPT (Nested Page Tables) – maps scattered host pages into a
 * contiguous guest-physical address space.
 *
 * 4-level: PML4 → PDPT → PD → PT (4 KB pages for guest RAM region)
 * Guest RAM is at GPA [GUEST_RAM_GPA_BASE, GUEST_RAM_GPA_BASE+4GB).
 * Each 4 KB GPA is mapped to the actual HPA of the corresponding
 * individually-allocated page.
 * ════════════════════════════════════════════════════════════════════ */

/* We need PT (page table) pages for 4 KB mappings within guest RAM.
 * Static array sized for max 4 GB; actual usage depends on guest_nr_pages.
 * 4 GB / 2 MB = 2048 entries max.  Each PT page maps 512 × 4 KB = 2 MB. */
#define NPT_MAX_PT_PAGES  (GUEST_RAM_MAX_SIZE / (512ULL * PAGE_SIZE))

static u64 *npt_pt_pages[NPT_MAX_PT_PAGES];
static unsigned long npt_num_pt_used;  /* actual PT pages allocated */

static int bogger_npt_init(void)
{
    unsigned long i;
    unsigned long page_idx;

    /* Compute how many PT pages we actually need for the allocated guest RAM */
    npt_num_pt_used = (guest_nr_pages + 511) / 512;  /* round up */
    if (npt_num_pt_used > NPT_MAX_PT_PAGES)
        npt_num_pt_used = NPT_MAX_PT_PAGES;

    pr_info("[BOGGER] NPT: %lu PT pages needed for %lu guest pages (%llu MB)\n",
            npt_num_pt_used, guest_nr_pages,
            (unsigned long long)(guest_ram_size >> 20));

    npt_pml4 = (u64 *)get_zeroed_page(GFP_KERNEL);
    if (!npt_pml4) return -ENOMEM;

    npt_pdpt = (u64 *)get_zeroed_page(GFP_KERNEL);
    if (!npt_pdpt) goto fail_pml4;

    /* PD tables covering up to 16 GB of GPA space */
    for (i = 0; i < NPT_NUM_PD_TABLES; i++) {
        npt_pd_tables[i] = (u64 *)get_zeroed_page(GFP_KERNEL);
        if (!npt_pd_tables[i])
            goto fail_pd;
    }

    /* Allocate PT pages for 4 KB mapping within guest RAM region */
    for (i = 0; i < npt_num_pt_used; i++) {
        npt_pt_pages[i] = (u64 *)get_zeroed_page(GFP_KERNEL);
        if (!npt_pt_pages[i])
            goto fail_pt;
    }

    /* Fill PT entries: map each 4 KB GPA to the HPA of the
     * corresponding individually-allocated guest page.              */
    page_idx = 0;
    for (i = 0; i < npt_num_pt_used; i++) {
        unsigned int pt_idx;
        for (pt_idx = 0; pt_idx < 512 && page_idx < guest_nr_pages;
             pt_idx++, page_idx++) {
            u64 hpa = page_to_phys(guest_pages[page_idx]);
            /* P + RW + US */
            npt_pt_pages[i][pt_idx] = hpa | 0x07ULL;
        }
    }

    /* PD entries for guest RAM region: point to PT pages (not 2MB large pages) */
    {
        u64 gpa_base = GUEST_RAM_GPA_BASE;
        unsigned int pd_table_idx = (unsigned int)(gpa_base >> 30);
        unsigned int pd_entry_start = (unsigned int)((gpa_base >> 21) & 0x1FF);

        for (i = 0; i < npt_num_pt_used; i++) {
            unsigned int cur_pd_table = pd_table_idx + ((pd_entry_start + i) / 512);
            unsigned int cur_pd_entry = (pd_entry_start + i) % 512;

            if (cur_pd_table >= NPT_NUM_PD_TABLES) break;
            /* P + RW + US (no PS bit — points to PT, not 2MB page) */
            npt_pd_tables[cur_pd_table][cur_pd_entry] =
                virt_to_phys(npt_pt_pages[i]) | 0x07ULL;
        }
    }

    /* ── Allocate the shared zero page first (needed by MMIO + fill code) ── */
    npt_zero_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (!npt_zero_page) {
        pr_err("[BOGGER] NPT: failed to alloc zero page\n");
        goto fail_pt;
    }

    /* ── MMIO region: map to zero pages (NOT identity) ──────────── */
    /* GPA 0xC0000000-0xFFFFFFFF (PD[3]) — this is the MMIO hole.
     * Identity-mapping would expose real host HPET/LAPIC/IOAPIC hardware.
     * Instead, map to zero pages. OVMF reads 0 from all MMIO registers.
     * The OVMF flash at 0xFFC00000-0xFFFFFFFF is overridden below.       */
    {
        unsigned int entry;
        u64 zero_hpa = page_to_phys(npt_zero_page);
        for (entry = 0; entry < 512; entry++) {
            if (npt_pd_tables[3][entry] == 0) {
                u64 *zpt = (u64 *)get_zeroed_page(GFP_KERNEL);
                if (zpt) {
                    unsigned int k;
                    for (k = 0; k < 512; k++)
                        zpt[k] = zero_hpa | 0x07ULL;
                    npt_pd_tables[3][entry] = virt_to_phys(zpt) | 0x07ULL;
                }
            }
        }
        pr_info("[BOGGER] NPT: MMIO region 0xC0000000–0xFFFFFFFF mapped to zero pages (PD[3])\n");
    }

    /* ── HPET emulation page at GPA 0xFED00000 ────────────────────── */
    /* OVMF reads HPET registers (capabilities, counter) via MMIO.
     * We allocate a real page, fill it with HPET register data, and
     * map it into NPT. The counter is updated before each VMRUN. */
    hpet_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (hpet_page) {
        u64 hpet_hpa = page_to_phys(hpet_page);
        unsigned int hpet_pd_entry = (unsigned int)((HPET_GPA >> 21) & 0x1FF);
        unsigned int hpet_pt_entry = (unsigned int)((HPET_GPA >> 12) & 0x1FF);
        u64 pt_phys;
        u64 *pt;

        hpet_regs = (volatile u32 *)page_address(hpet_page);
        hpet_init_regs();

        /* PD[3] entry for the 2MB region containing 0xFED00000 should
         * already have a PT from the MMIO fill above. Replace just
         * the one 4KB PT entry for HPET. */
        pt_phys = npt_pd_tables[3][hpet_pd_entry] & ~0xFFFULL;
        if (pt_phys) {
            pt = phys_to_virt(pt_phys);
            pt[hpet_pt_entry] = hpet_hpa | 0x07ULL;  /* P+RW+US, always present */
            pr_info("[BOGGER] NPT: HPET page at GPA 0x%llx mapped (kthread updates counter)\n",
                    HPET_GPA);
        }
    }

    /* ── NVMe BAR MMIO pages at GPA 0xFE000000 (16KB = 4 pages) ───── */
    {
        int ok = 1;
        unsigned int i;
        for (i = 0; i < 4; i++) {
            nvme_bar_pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
            if (!nvme_bar_pages[i]) { ok = 0; break; }
        }
        if (ok) {
            struct page *pages_arr[4];
            unsigned int i;
            for (i = 0; i < 4; i++)
                pages_arr[i] = nvme_bar_pages[i];
            nvme_regs = (volatile u32 *)vmap(pages_arr, 4, VM_MAP, PAGE_KERNEL);
            if (nvme_regs) {
                nvme_init_regs();
                /* Map each page into NPT at GPA 0xFE000000 + i*4096 */
                for (i = 0; i < 4; i++) {
                    u64 gpa = NVME_BAR_GPA + (u64)i * PAGE_SIZE;
                    unsigned int pd_idx = (unsigned int)(gpa >> 30);
                    unsigned int pd_entry = (unsigned int)((gpa >> 21) & 0x1FF);
                    unsigned int pt_entry = (unsigned int)((gpa >> 12) & 0x1FF);
                    u64 pt_phys;
                    u64 *pt;

                    if (pd_idx < NPT_NUM_PD_TABLES &&
                        npt_pd_tables[pd_idx][pd_entry] != 0) {
                        pt_phys = npt_pd_tables[pd_idx][pd_entry] & ~0xFFFULL;
                        pt = phys_to_virt(pt_phys);
                        pt[pt_entry] = page_to_phys(nvme_bar_pages[i]) | 0x07ULL;
                    }
                }
                pr_info("[BOGGER] NPT: NVMe BAR at GPA 0x%llx mapped (4 pages)\n",
                        NVME_BAR_GPA);
            }
        }
    }

    /* ── Override OVMF flash region with firmware pages ──────────── */
    /* GPA 0xFFC00000–0xFFFFFFFF (4 MB) must map to OVMF firmware pages
     * instead of identity-mapped MMIO.  We need to split the 2 MB large
     * pages at GPA 0xFFC00000, 0xFFE00000 into 4 KB page tables. */
    if (ovmf_pages && ovmf_nr_pages > 0) {
        u64 flash_gpa = OVMF_FLASH_GPA;
        unsigned long flash_pg;

        for (flash_pg = 0; flash_pg < ovmf_nr_pages; flash_pg++) {
            u64 gpa = flash_gpa + ((u64)flash_pg << PAGE_SHIFT);
            unsigned int pd_idx = (unsigned int)(gpa >> 30);     /* which 1GB */
            unsigned int pd_entry = (unsigned int)((gpa >> 21) & 0x1FF); /* which 2MB */
            unsigned int pt_entry_idx = (unsigned int)((gpa >> 12) & 0x1FF); /* which 4KB */
            u64 hpa;

            if (pd_idx >= NPT_NUM_PD_TABLES)
                continue;

            /* Check if this PD entry is still a 2MB large page (PS bit set) */
            if (npt_pd_tables[pd_idx][pd_entry] & (1ULL << 7)) {
                /* Need to split: allocate a PT page for 4KB granularity */
                u64 *new_pt = (u64 *)get_zeroed_page(GFP_KERNEL);
                unsigned int k;
                u64 base_2mb = gpa & ~((1ULL << 21) - 1);

                if (!new_pt) {
                    pr_err("[BOGGER] NPT: failed to alloc PT for OVMF split\n");
                    continue;
                }

                /* Fill with identity-mapped 4KB entries for the 2MB region */
                for (k = 0; k < 512; k++) {
                    new_pt[k] = (base_2mb + ((u64)k << 12)) | 0x17ULL; /* P+RW+US+PCD */
                }

                /* Replace the 2MB PD entry with pointer to 4KB PT */
                npt_pd_tables[pd_idx][pd_entry] = virt_to_phys(new_pt) | 0x07ULL;
            }

            /* Now get the PT and replace the specific 4KB entry with OVMF page */
            {
                u64 pt_phys = npt_pd_tables[pd_idx][pd_entry] & ~0xFFFULL;
                u64 *pt = phys_to_virt(pt_phys);

                hpa = page_to_phys(ovmf_pages[flash_pg]);
                pt[pt_entry_idx] = hpa | 0x07ULL;  /* P+RW+US, no PCD (cacheable) */
            }
        }
        pr_info("[BOGGER] NPT: OVMF flash mapped at GPA 0x%llx–0x%llx (%lu pages)\n",
                OVMF_FLASH_GPA, OVMF_FLASH_GPA + OVMF_FLASH_SIZE - 1,
                ovmf_nr_pages);
    }

    /* ── Fill unmapped regions WITHIN guest RAM range ──────────── */
    /* Only fill empty PD entries that fall WITHIN the guest RAM range.
     * Regions ABOVE guest RAM must stay unmapped (PD entry = 0) so
     * OVMF detects the actual RAM boundary and doesn't place PEI
     * code beyond allocated memory.                                  */
    {
        u64 zero_hpa = page_to_phys(npt_zero_page);
        u64 ram_end_gpa = (u64)guest_nr_pages << PAGE_SHIFT;
        unsigned int ram_end_pd = (unsigned int)(ram_end_gpa >> 30);
        unsigned int ram_end_entry = (unsigned int)((ram_end_gpa >> 21) & 0x1FF);

        /* Fill holes within guest RAM PD tables only */
        for (i = 0; i <= ram_end_pd && i < 3; i++) {
            unsigned int j;
            unsigned int max_entry = (i < ram_end_pd) ? 512 : ram_end_entry;
            for (j = 0; j < max_entry; j++) {
                if (npt_pd_tables[i][j] == 0) {
                    u64 *zpt = (u64 *)get_zeroed_page(GFP_KERNEL);
                    unsigned int k;
                    if (!zpt) continue;
                    for (k = 0; k < 512; k++)
                        zpt[k] = zero_hpa | 0x07ULL;
                    npt_pd_tables[i][j] = virt_to_phys(zpt) | 0x07ULL;
                }
            }
        }
        /* DO NOT fill entries above guest RAM — leave them unmapped!
         * OVMF detects RAM size by probing; unmapped = no RAM.      */
        pr_info("[BOGGER] NPT: zero-page fill within guest RAM (0–0x%llx)\n",
                ram_end_gpa);

        /* However, pre-fill ALL empty PD entries between guest RAM end and
         * MMIO start (0xC0000000) with zero-page PT entries.
         * This is CRITICAL: the VMRUN NPF handler must NEVER allocate memory
         * because the kernel stack in insmod context is only ~8KB, and
         * get_zeroed_page → alloc_pages call chain causes stack overflow. */
        {
            u64 ext_end = 0xC0000000ULL;  /* fill everything up to MMIO */
            unsigned int ext_pd_end, ext_entry_end;
            ext_pd_end = (unsigned int)(ext_end >> 30);
            ext_entry_end = (unsigned int)((ext_end >> 21) & 0x1FF);

            for (i = ram_end_pd; i < ext_pd_end && i < NPT_NUM_PD_TABLES; i++) {
                unsigned int j;
                unsigned int start_j = (i == ram_end_pd) ? ram_end_entry : 0;
                for (j = start_j; j < 512; j++) {
                    if (npt_pd_tables[i][j] == 0) {
                        u64 *zpt = (u64 *)get_zeroed_page(GFP_KERNEL);
                        unsigned int k;
                        if (!zpt) continue;
                        for (k = 0; k < 512; k++)
                            zpt[k] = zero_hpa | 0x07ULL; /* P+RW+US */
                        npt_pd_tables[i][j] = virt_to_phys(zpt) | 0x07ULL;
                    }
                }
            }
            pr_info("[BOGGER] NPT: pre-filled gap (0x%llx–0x%llx) with zero pages\n",
                    ram_end_gpa, ext_end - 1);
        }
    }

    /* ── Map key MMIO regions to dummy RAM pages ──────────────── */
    /* OVMF accesses IOAPIC (0xFEC00000), HPET (0xFED00000), LAPIC (0xFEE00000)
     * via MMIO. We map these to dummy zeroed 2MB pages so reads return 0
     * and writes are silently absorbed. This avoids complex NPF emulation. */
    pr_info("[BOGGER] NPT: MMIO regions mapped to dummy zeroed pages (IOAPIC/HPET/LAPIC)\n");

    /* Wire up PDPT → PD and PML4 → PDPT */
    for (i = 0; i < NPT_NUM_PD_TABLES; i++)
        npt_pdpt[i] = virt_to_phys(npt_pd_tables[i]) | 0x07ULL;

    npt_pml4[0] = virt_to_phys(npt_pdpt) | 0x07ULL;

    pr_info("[BOGGER] NPT ready: %lu pages mapped at GPA 0x%llx–0x%llx (4KB granularity)\n",
            guest_nr_pages,
            GUEST_RAM_GPA_BASE,
            GUEST_RAM_GPA_BASE + guest_ram_size - 1);
    return 0;

fail_pt:
    {
        unsigned long j;
        for (j = 0; j < i; j++)
            free_page((unsigned long)npt_pt_pages[j]);
    }
    i = NPT_NUM_PD_TABLES;  /* fall through to fail_pd cleanup */
fail_pd:
    {
        unsigned long j;
        for (j = 0; j < i; j++)
            free_page((unsigned long)npt_pd_tables[j]);
    }
    free_page((unsigned long)npt_pdpt);
    npt_pdpt = NULL;
fail_pml4:
    free_page((unsigned long)npt_pml4);
    npt_pml4 = NULL;
    return -ENOMEM;
}

static void bogger_npt_free(void)
{
    unsigned long i;

    if (nvme_regs) {
        vunmap((void *)nvme_regs);
        nvme_regs = NULL;
    }
    for (i = 0; i < 4; i++) {
        if (nvme_bar_pages[i]) {
            __free_page(nvme_bar_pages[i]);
            nvme_bar_pages[i] = NULL;
        }
    }

    if (hpet_page) {
        __free_page(hpet_page);
        hpet_page = NULL;
        hpet_regs = NULL;
    }

    for (i = 0; i < npt_num_pt_used; i++) {
        if (npt_pt_pages[i]) {
            free_page((unsigned long)npt_pt_pages[i]);
            npt_pt_pages[i] = NULL;
        }
    }
    for (i = 0; i < NPT_NUM_PD_TABLES; i++) {
        if (npt_pd_tables[i]) {
            free_page((unsigned long)npt_pd_tables[i]);
            npt_pd_tables[i] = NULL;
        }
    }
    if (npt_pdpt) { free_page((unsigned long)npt_pdpt); npt_pdpt = NULL; }
    if (npt_pml4) { free_page((unsigned long)npt_pml4); npt_pml4 = NULL; }
}

/* ════════════════════════════════════════════════════════════════════
 * OVMF firmware loader – load OVMF_CODE.fd (+ optionally OVMF_VARS.fd)
 * into dedicated pages mapped at the top of the 4 GB address space.
 *
 * OVMF is a raw firmware volume (NOT a PE binary).  It gets mapped
 * so that the x86 reset vector at GPA 0xFFFFFFF0 falls inside it.
 * For a 4 MB layout:  GPA 0xFFC00000 – 0xFFFFFFFF.
 * ════════════════════════════════════════════════════════════════════ */
static int bogger_load_ovmf(void)
{
    void  *code_buf = NULL, *vars_buf = NULL;
    size_t code_size = 0, vars_size = 0;
    ssize_t ret;
    unsigned long i, nr_pages;
    u64 flash_total;

    /* Load OVMF_CODE */
    if (!bogger_ovmf_code || bogger_ovmf_code[0] == '\0') {
        pr_err("[BOGGER] No OVMF_CODE path specified\n");
        return -EINVAL;
    }

    pr_info("[BOGGER] Loading OVMF_CODE: %s\n", bogger_ovmf_code);
    ret = kernel_read_file_from_path(bogger_ovmf_code, 0, &code_buf,
                                     INT_MAX, &code_size, READING_FIRMWARE);
    if (ret < 0) {
        pr_err("[BOGGER] Failed to read OVMF_CODE: %zd\n", ret);
        return (int)ret;
    }
    pr_info("[BOGGER] OVMF_CODE: %zu bytes\n", code_size);

    /* Optionally load OVMF_VARS */
    if (bogger_ovmf_vars && bogger_ovmf_vars[0] != '\0') {
        pr_info("[BOGGER] Loading OVMF_VARS: %s\n", bogger_ovmf_vars);
        ret = kernel_read_file_from_path(bogger_ovmf_vars, 0, &vars_buf,
                                         INT_MAX, &vars_size, READING_FIRMWARE);
        if (ret < 0) {
            pr_warn("[BOGGER] Failed to read OVMF_VARS: %zd (continuing without)\n", ret);
            vars_buf = NULL;
            vars_size = 0;
        } else {
            pr_info("[BOGGER] OVMF_VARS: %zu bytes\n", vars_size);
        }
    }

    /* Total flash = 4 MB (VARS + CODE padded to fill 4 MB) */
    flash_total = OVMF_FLASH_SIZE;
    nr_pages = flash_total >> PAGE_SHIFT;

    /* Allocate pages for the flash region */
    ovmf_pages = vzalloc(nr_pages * sizeof(struct page *));
    if (!ovmf_pages) {
        vfree(code_buf);
        if (vars_buf) vfree(vars_buf);
        return -ENOMEM;
    }

    for (i = 0; i < nr_pages; i++) {
        ovmf_pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
        if (!ovmf_pages[i]) {
            pr_err("[BOGGER] Failed to allocate OVMF page %lu/%lu\n", i, nr_pages);
            goto fail_pages;
        }
    }
    ovmf_nr_pages = nr_pages;

    /* Map into contiguous kernel virtual space */
    ovmf_virt = vmap(ovmf_pages, nr_pages, VM_MAP, PAGE_KERNEL);
    if (!ovmf_virt) {
        pr_err("[BOGGER] vmap failed for OVMF flash\n");
        goto fail_pages;
    }

    /* Zero the entire flash region first */
    memset(ovmf_virt, 0xFF, flash_total);  /* 0xFF = erased flash */

    /* Copy VARS at offset 0 (start of flash region) */
    if (vars_buf && vars_size > 0) {
        if (vars_size > flash_total - code_size) {
            pr_warn("[BOGGER] OVMF_VARS too large, truncating\n");
            vars_size = flash_total - code_size;
        }
        memcpy(ovmf_virt, vars_buf, vars_size);
        pr_info("[BOGGER] OVMF_VARS placed at flash offset 0 (%zu bytes)\n", vars_size);
    }

    /* Copy CODE at end of flash (so reset vector at 0xFFFFFFF0 is inside) */
    {
        size_t code_offset = flash_total - code_size;
        memcpy((u8 *)ovmf_virt + code_offset, code_buf, code_size);
        pr_info("[BOGGER] OVMF_CODE placed at flash offset 0x%zx (%zu bytes)\n",
                code_offset, code_size);
    }

    /* Verify reset vector area is not all zeros */
    {
        u8 *reset_area = (u8 *)ovmf_virt + flash_total - 16;
        pr_info("[BOGGER] Reset vector bytes: %02x %02x %02x %02x %02x %02x\n",
                reset_area[0], reset_area[1], reset_area[2],
                reset_area[3], reset_area[4], reset_area[5]);
    }

    vfree(code_buf);
    if (vars_buf) vfree(vars_buf);

    pr_info("[BOGGER] OVMF flash: %llu MB at GPA 0x%llx–0x%llx (%lu pages)\n",
            (unsigned long long)(flash_total >> 20),
            OVMF_FLASH_GPA, OVMF_FLASH_GPA + flash_total - 1, nr_pages);
    return 0;

fail_pages:
    for (i = 0; i < nr_pages; i++) {
        if (ovmf_pages[i])
            __free_page(ovmf_pages[i]);
    }
    vfree(ovmf_pages);
    ovmf_pages = NULL;
    vfree(code_buf);
    if (vars_buf) vfree(vars_buf);
    return -ENOMEM;
}

static void bogger_ovmf_free(void)
{
    unsigned long i;
    if (ovmf_virt) {
        vunmap(ovmf_virt);
        ovmf_virt = NULL;
    }
    if (ovmf_pages) {
        for (i = 0; i < ovmf_nr_pages; i++) {
            if (ovmf_pages[i])
                __free_page(ovmf_pages[i]);
        }
        vfree(ovmf_pages);
        ovmf_pages = NULL;
    }
}

/* (Guest env setup removed — OVMF creates its own GDT, page tables, IDT) */

/* ════════════════════════════════════════════════════════════════════
 * SVM helpers
 * ════════════════════════════════════════════════════════════════════ */
static int bogger_svm_check_support(void)
{
    if (!boot_cpu_has(X86_FEATURE_SVM)) {
        pr_err("[BOGGER] CPU does not support SVM\n");
        return -ENODEV;
    }
    return 0;
}

static int bogger_svm_enable(void)
{
    u64 efer = native_read_msr(MSR_EFER);
    efer |= EFER_SVME;
    native_write_msr(MSR_EFER, efer);
    pr_info("[BOGGER] EFER.SVME set — SVM enabled\n");
    return 0;
}

static int bogger_svm_hsave_setup(void)
{
    u64 phys;

    hsave_area = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
    if (!hsave_area)
        return -ENOMEM;

    phys = virt_to_phys(hsave_area);
    native_write_msr(MSR_VM_HSAVE_PA, phys);
    pr_info("[BOGGER] VM_HSAVE_PA set to 0x%llx\n", phys);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * VMCB setup – Real Mode reset state for OVMF boot
 *
 * The guest starts in 16-bit Real Mode at the x86 reset vector:
 *   CS.selector = 0xF000, CS.base = 0xFFFF0000, IP = 0xFFF0
 *   → effective address = CS.base + IP = 0xFFFFFFF0
 * This lands inside OVMF_CODE.fd at the top of the 4 GB address space.
 * OVMF will switch to Protected Mode → Long Mode on its own.
 * ════════════════════════════════════════════════════════════════════ */
static int bogger_vmcb_init(void)
{
    g_vmcb = (struct vmcb *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
    if (!g_vmcb)
        return -ENOMEM;

    /* ── Allocate IOPM (required when INTERCEPT_IOIO_PROT is set) ── */
    io_bitmap = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
                                          get_order(IOPM_SIZE));
    if (!io_bitmap) {
        free_page((unsigned long)g_vmcb);
        g_vmcb = NULL;
        return -ENOMEM;
    }
    /* Intercept ALL I/O ports — the guest (OVMF/Windows) runs entirely
     * virtualized. We emulate the minimum devices OVMF needs to boot. */
    memset(io_bitmap, 0xFF, IOPM_SIZE);

    /* ── Intercepts ──────────────────────────────────────────────── */

    /* MANDATORY: AMD APM Vol.2 §15.5 — VMRUN intercept MUST be set */
    g_vmcb->control.intercepts[INTERCEPT_VMRUN / 32] |=
        (1U << (INTERCEPT_VMRUN % 32));

    /* NOTE: INTERCEPT_INTR is intentionally NOT set here.
     * Under nested KVM/SVM it causes kernel panic (stack guard page hit)
     * because the host interrupt handler fires in wrong stack context
     * after VMEXIT.  Use "nosoftlockup watchdog_thresh=0" kernel params
     * instead to prevent the watchdog from killing the VMRUN thread. */

    g_vmcb->control.intercepts[INTERCEPT_HLT / 32]       |=
        (1U << (INTERCEPT_HLT % 32));
    g_vmcb->control.intercepts[INTERCEPT_IOIO_PROT / 32] |=
        (1U << (INTERCEPT_IOIO_PROT % 32));
    g_vmcb->control.intercepts[INTERCEPT_CPUID / 32]     |=
        (1U << (INTERCEPT_CPUID % 32));
    g_vmcb->control.intercepts[INTERCEPT_SHUTDOWN / 32]   |=
        (1U << (INTERCEPT_SHUTDOWN % 32));

    /* Intercept MSR access */
    g_vmcb->control.intercepts[INTERCEPT_MSR_PROT / 32] |=
        (1U << (INTERCEPT_MSR_PROT % 32));

    if (msr_bitmap)
        g_vmcb->control.msrpm_base_pa = virt_to_phys(msr_bitmap);
    g_vmcb->control.iopm_base_pa = virt_to_phys(io_bitmap);

    /* ASID & TLB */
    g_vmcb->control.asid    = 1;
    g_vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;

    /* V_INTR_MASKING */
    g_vmcb->control.int_ctl = (1ULL << 24);

    /* Clean bits = 0 for first VMRUN */
    g_vmcb->control.clean = 0;
    g_vmcb->control.event_inj = 0;

    /* ── 16-bit Real Mode segment state (x86 reset) ─────────────── */

    /* CS: selector=0xF000, base=0xFFFF0000, limit=0xFFFF
     * Attrib: 16-bit, present, read/execute, accessed
     * This is the standard x86 power-on CS state. */
    g_vmcb->save.cs.selector = 0xF000;
    g_vmcb->save.cs.base     = 0xFFFF0000ULL;
    g_vmcb->save.cs.limit    = 0xFFFFFFFF;  /* 4GB — OVMF needs Big Real Mode */
    g_vmcb->save.cs.attrib   = 0x009B;  /* P=1, S=1, Type=0xB (exec/read/accessed) */

    /* DS/ES/FS/GS/SS: selector=0, base=0, limit=4GB
     * OVMF SEC Phase uses "Big Real Mode" (Unreal Mode) where it accesses
     * the full 4GB address space via 32-bit address overrides.
     * The firmware flash at GPA 0xFFC00000+ must be reachable from seg base 0. */
    g_vmcb->save.ds.selector = 0;
    g_vmcb->save.ds.base     = 0;
    g_vmcb->save.ds.limit    = 0xFFFFFFFF;  /* 4GB limit for unreal mode */
    g_vmcb->save.ds.attrib   = 0x00C3;  /* P=1, S=1, Type=3 (data r/w/accessed), G=1, D/B=1 */

    g_vmcb->save.es = g_vmcb->save.ds;
    g_vmcb->save.ss = g_vmcb->save.ds;
    g_vmcb->save.fs = g_vmcb->save.ds;
    g_vmcb->save.gs = g_vmcb->save.ds;

    /* GDTR/IDTR: standard reset values */
    g_vmcb->save.gdtr.base  = 0;
    g_vmcb->save.gdtr.limit = 0xFFFF;
    g_vmcb->save.idtr.base  = 0;
    g_vmcb->save.idtr.limit = 0xFFFF;

    /* LDTR: present LDT */
    g_vmcb->save.ldtr.selector = 0;
    g_vmcb->save.ldtr.attrib   = 0x0082;
    g_vmcb->save.ldtr.limit    = 0xFFFF;
    g_vmcb->save.ldtr.base     = 0;

    /* TR: present busy 16-bit TSS */
    g_vmcb->save.tr.selector = 0;
    g_vmcb->save.tr.attrib   = 0x008B;
    g_vmcb->save.tr.limit    = 0xFFFF;
    g_vmcb->save.tr.base     = 0;

    /* ── Control registers: Real Mode (no paging) ─────────────── */
    /* CR0: ET + NE only (no PE, no PG — Real Mode) */
    g_vmcb->save.cr0 = 0x00000010ULL;  /* ET=1 */
    /* CR3: unused in real mode */
    g_vmcb->save.cr3 = 0;
    /* CR4: 0 */
    g_vmcb->save.cr4 = 0;

    /* EFER: SVME only (required by KVM nested SVM).
     * No LME, no LMA — guest is NOT in Long Mode initially. */
    g_vmcb->save.efer = EFER_SVME;

    /* RIP: 0xFFF0 — with CS.base=0xFFFF0000, effective addr = 0xFFFFFFF0 */
    g_vmcb->save.rip    = 0xFFF0;
    g_vmcb->save.rsp    = 0;
    g_vmcb->save.rflags = 0x2;  /* reserved bit 1 always set */
    g_vmcb->save.rax    = 0;

    /* Debug registers */
    g_vmcb->save.dr7 = 0x400;
    g_vmcb->save.dr6 = 0xFFFF0FF0;

    /* G_PAT — standard default */
    g_vmcb->save.g_pat = 0x0007040600070406ULL;

    /* ── NPT (Nested Paging) ─────────────────────────────────────── */
    g_vmcb->control.nested_ctl = 1ULL;
    g_vmcb->control.nested_cr3 = virt_to_phys(npt_pml4);

    pr_info("[BOGGER] VMCB: Real Mode  CR0=0x%llx CR3=0x%llx CR4=0x%llx\n",
            g_vmcb->save.cr0, g_vmcb->save.cr3, g_vmcb->save.cr4);
    pr_info("[BOGGER] VMCB: EFER=0x%llx RIP=0x%llx (effective=0x%llx)\n",
            g_vmcb->save.efer, g_vmcb->save.rip,
            g_vmcb->save.cs.base + g_vmcb->save.rip);
    pr_info("[BOGGER] VMCB: CS=%04x base=%llx IOPM=0x%llx MSRPM=0x%llx\n",
            g_vmcb->save.cs.selector, g_vmcb->save.cs.base,
            g_vmcb->control.iopm_base_pa,
            g_vmcb->control.msrpm_base_pa);
    pr_info("[BOGGER] VMCB: nCR3=0x%llx int_ctl=0x%x\n",
            g_vmcb->control.nested_cr3,
            g_vmcb->control.int_ctl);

    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Guest GPR state — AMD SVM only saves rax/rsp/rip/rflags in the VMCB
 * save area.  All other GPRs must be manually saved/restored around VMRUN.
 * ════════════════════════════════════════════════════════════════════ */
struct bogger_guest_gprs {
    u64 rbx;
    u64 rcx;
    u64 rdx;
    u64 rsi;
    u64 rdi;
    u64 rbp;
    u64 r8;
    u64 r9;
    u64 r10;
    u64 r11;
    u64 r12;
    u64 r13;
    u64 r14;
    u64 r15;
};

static struct bogger_guest_gprs guest_gprs;

/* ════════════════════════════════════════════════════════════════════
 * MSR Permission Map (MSRPM) — AMD SVM, APM Vol 2 §15.11
 *
 * The MSRPM is 8 KB (2 pages), divided into three 2 KB sections:
 *   [0x0000–0x07FF] : MSRs 0x00000000–0x00001FFF
 *   [0x0800–0x0FFF] : MSRs 0xC0000000–0xC0001FFF
 *   [0x1000–0x17FF] : MSRs 0xC0010000–0xC0011FFF
 *
 * Within each section, each MSR has 2 consecutive bits:
 *   bit 0 = intercept RDMSR, bit 1 = intercept WRMSR.
 * So MSR N within its range uses bit (N*2) for read and (N*2+1) for write.
 * ════════════════════════════════════════════════════════════════════ */

static void bogger_msr_bitmap_set(u32 msr, bool intercept_read, bool intercept_write)
{
    u8 *bm = (u8 *)msr_bitmap;
    u32 base_offset;  /* byte offset into MSRPM for this MSR range */
    u32 msr_off;      /* MSR offset within its range */
    u32 byte_pos, bit_pos;

    if (msr <= 0x1FFF) {
        base_offset = 0x0000;
        msr_off = msr;
    } else if (msr >= 0xC0000000 && msr <= 0xC0001FFF) {
        base_offset = 0x0800;
        msr_off = msr - 0xC0000000;
    } else if (msr >= 0xC0010000 && msr <= 0xC0011FFF) {
        base_offset = 0x1000;
        msr_off = msr - 0xC0010000;
    } else {
        return;  /* MSR not coverable by MSRPM */
    }

    /* Each MSR uses 2 bits: bit(msr_off*2) = read, bit(msr_off*2+1) = write */
    byte_pos = base_offset + (msr_off * 2) / 8;
    bit_pos  = (msr_off * 2) % 8;

    if (byte_pos >= MSRPM_SIZE)
        return;

    if (intercept_read)
        bm[byte_pos] |= (1U << bit_pos);
    if (intercept_write)
        bm[byte_pos] |= (1U << (bit_pos + 1));
}

static int bogger_msr_bitmap_init(void)
{
    msr_bitmap = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
                                           get_order(MSRPM_SIZE));
    if (!msr_bitmap)
        return -ENOMEM;

    /* ── Stealth MSR intercepts ─────────────────────────────────── */

    /* IA32_FEATURE_CONTROL (0x3A) — hide VMX capability from guest */
    bogger_msr_bitmap_set(0x3A, true, true);

    /* IA32_VMX_* capability MSRs (0x480–0x48F) — deny existence */
    {
        u32 m;
        for (m = 0x480; m <= 0x48F; m++)
            bogger_msr_bitmap_set(m, true, false);
    }

    /* IA32_DEBUGCTL (0x1D9) — intercept to prevent timing attacks */
    bogger_msr_bitmap_set(0x1D9, true, true);

    /* MSR_VM_HSAVE_PA — hide SVM internal state */
    bogger_msr_bitmap_set(0xC0010117, true, true);

    /* MSR_VM_CR — hide SVM lock state */
    bogger_msr_bitmap_set(0xC0010114, true, true);

    pr_info("[BOGGER] MSR bitmap configured (stealth: 0x3A, 0x480-0x48F, VM_CR, VM_HSAVE_PA)\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Stealth CPUID handler — intercepts all CPUID and filters output
 * to hide virtualisation from the guest OS (Windows)
 * ════════════════════════════════════════════════════════════════════ */
static void bogger_handle_cpuid_stealth(struct vmcb *vmcb,
                                         struct bogger_guest_gprs *gprs)
{
    u32 fn  = (u32)vmcb->save.rax;
    u32 sub = (u32)gprs->rcx;
    u32 out_eax, out_ebx, out_ecx, out_edx;

    /* Execute real CPUID on host CPU */
    __asm__ volatile("cpuid"
        : "=a"(out_eax), "=b"(out_ebx),
          "=c"(out_ecx), "=d"(out_edx)
        : "a"(fn), "c"(sub));

    switch (fn) {
    case 0x00000001:
        /* ── STEALTH: Clear Hypervisor Present bit (ECX[31]) ──── */
        out_ecx &= ~(1U << 31);
        break;

    case 0x40000000 ... 0x400000FF:
        /* ── STEALTH: Zero all hypervisor info leaves ─────────── */
        /* These leaves would reveal "BOGGER", "KVMKVMKVM", etc.
         * Return all zeros = "no hypervisor".                      */
        out_eax = 0;
        out_ebx = 0;
        out_ecx = 0;
        out_edx = 0;
        break;

    case 0x80000002 ... 0x80000004:
        /* Processor brand string — pass through unmodified so
         * Windows sees the real CPU name (stealth).                */
        break;

    default:
        /* All other leaves: pass through native values */
        break;
    }

    vmcb->save.rax = out_eax;
    gprs->rbx      = out_ebx;
    gprs->rcx      = out_ecx;
    gprs->rdx      = out_edx;

    vmcb->save.rip += 2;  /* CPUID = 0F A2 (2 bytes) */
}

/* ════════════════════════════════════════════════════════════════════
 * Stealth MSR handler — intercepts RDMSR/WRMSR for sensitive MSRs
 * ════════════════════════════════════════════════════════════════════ */
static void bogger_handle_rdmsr_stealth(struct vmcb *vmcb,
                                         struct bogger_guest_gprs *gprs)
{
    u32 msr = (u32)gprs->rcx;
    u64 value = 0;

    switch (msr) {
    case 0x3A:  /* IA32_FEATURE_CONTROL — report VMX disabled */
        value = 0x1;  /* Lock bit set, VMX disabled */
        break;
    case 0x480 ... 0x48F:  /* IA32_VMX_* — report as zero (no VMX) */
        value = 0;
        break;
    case 0xC0010114:  /* MSR_VM_CR — hide SVM state */
        value = 0x0;  /* SVMDIS=0, LOCK=0, appears as no SVM */
        break;
    case 0xC0010117:  /* MSR_VM_HSAVE_PA — hide host save area */
        value = 0;
        break;
    case 0x1D9:  /* IA32_DEBUGCTL */
        value = 0;  /* No debug features active */
        break;
    default:
        /* Pass through: read real MSR value */
        value = native_read_msr(msr);
        break;
    }

    vmcb->save.rax    = (u32)(value & 0xFFFFFFFF);
    gprs->rdx         = (u32)(value >> 32);
    vmcb->save.rip   += 2;  /* RDMSR = 0F 32 */
}

static void bogger_handle_wrmsr_stealth(struct vmcb *vmcb,
                                         struct bogger_guest_gprs *gprs)
{
    u32 msr = (u32)gprs->rcx;
    u64 value = ((u64)(u32)gprs->rdx << 32) | (u32)vmcb->save.rax;

    switch (msr) {
    case 0x3A:       /* IA32_FEATURE_CONTROL — silently drop */
    case 0xC0010114: /* MSR_VM_CR — silently drop */
    case 0xC0010117: /* MSR_VM_HSAVE_PA — silently drop */
        break;
    case 0x1D9:      /* IA32_DEBUGCTL — silently drop */
        break;
    default:
        /* Pass through: write to real MSR */
        native_write_msr(msr, value);
        break;
    }

    vmcb->save.rip += 2;  /* WRMSR = 0F 30 */
}

/* ════════════════════════════════════════════════════════════════════
 * VMRUN loop — saves/restores all GPRs around VMRUN
 * ════════════════════════════════════════════════════════════════════ */
static void bogger_vmrun_loop(void)
{
    u64 phys = virt_to_phys(g_vmcb);
    u32 exit_code;
    int exits = 0;
    const int max_logged_exits = 200;
    const int max_total_exits = 50000000;  /* 50M exits — enough for full OVMF boot */

    /* Zero guest GPRs initially */
    memset(&guest_gprs, 0, sizeof(guest_gprs));

    pr_info("[BOGGER] Entering VMRUN loop (VMCB phys=0x%llx)\n", phys);

    /* Verify VMCB physical address is page-aligned */
    if (phys & 0xFFF) {
        pr_err("[BOGGER] FATAL: VMCB phys 0x%llx not page-aligned!\n", phys);
        return;
    }

    /* Verify EFER.SVME is actually set */
    {
        u64 efer = native_read_msr(MSR_EFER);
        pr_info("[BOGGER] Host EFER=0x%llx (SVME=%s)\n",
                efer, (efer & EFER_SVME) ? "yes" : "NO");
        if (!(efer & EFER_SVME)) {
            pr_err("[BOGGER] FATAL: EFER.SVME not set!\n");
            return;
        }
    }

    /* Probe: test clgi/stgi before doing vmrun */
    pr_info("[BOGGER] Probe: testing clgi...\n");
    __asm__ volatile("clgi" ::: "memory");
    __asm__ volatile("stgi" ::: "memory");
    pr_info("[BOGGER] Probe: clgi/stgi OK\n");

    pr_info("[BOGGER] Pre-VMRUN: RIP=0x%llx RSP=0x%llx CR3=0x%llx\n",
            g_vmcb->save.rip, g_vmcb->save.rsp, g_vmcb->save.cr3);
    pr_info("[BOGGER] Pre-VMRUN: CR0=0x%llx CR4=0x%llx EFER=0x%llx\n",
            g_vmcb->save.cr0, g_vmcb->save.cr4, g_vmcb->save.efer);
    pr_info("[BOGGER] Pre-VMRUN: nCR3=0x%llx nested_ctl=0x%llx ASID=%u\n",
            g_vmcb->control.nested_cr3, g_vmcb->control.nested_ctl,
            g_vmcb->control.asid);
    pr_info("[BOGGER] Pre-VMRUN: IOPM=0x%llx MSRPM=0x%llx int_ctl=0x%x\n",
            g_vmcb->control.iopm_base_pa,
            g_vmcb->control.msrpm_base_pa,
            g_vmcb->control.int_ctl);

    while (true) {
        /* Update HPET counter at every VMEXIT iteration */
        hpet_update_counter();

        /* Track NVMe controller state — OVMF writes CC/AQA/ASQ/ACQ
         * directly to the mapped pages. We read them back and update CSTS. */
        if (nvme_regs) {
            u32 new_cc = nvme_regs[5];  /* offset 0x14 */
            if (new_cc != nvme_cc) {
                nvme_cc = new_cc;
                if (exits <= max_logged_exits)
                    pr_info("[BOGGER-NVMe] CC written: 0x%x (EN=%d)\n",
                            nvme_cc, nvme_cc & 1);
            }
            nvme_aqa = nvme_regs[9];           /* offset 0x24 */
            nvme_asq_base = (u64)nvme_regs[10] | ((u64)nvme_regs[11] << 32); /* 0x28 */
            nvme_acq_base = (u64)nvme_regs[12] | ((u64)nvme_regs[13] << 32); /* 0x30 */
            nvme_update_regs();
        }

        /* Process any pending NVMe admin commands (doorbell writes) */
        nvme_poll_doorbell();

        /* Process any pending NVMe I/O commands (Read/Write) */
        nvme_poll_io_doorbell();

        /* Reset clean bits before each VMRUN — tells CPU all fields
         * are potentially modified.  Required for KVM nested SVM. */
        g_vmcb->control.clean = 0;

        /* Flush TLB on first entry */
        if (exits == 0)
            g_vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
        else
            g_vmcb->control.tlb_ctl = 0;  /* no flush on subsequent entries */

        /* ── Inject timer interrupt to prevent HLT stalls ──
         * OVMF uses HLT+PIT for delays. Without interrupt injection,
         * we just skip HLT but OVMF's delay loops don't make progress.
         * Inject INT 8 (IRQ0 = timer) periodically so PIT-based delays
         * and HLT-waits resolve naturally.
         * event_inj format: [31]=valid [10:8]=type(0=ext) [7:0]=vector */
        {
            static u64 last_inject_ns;
            u64 now = ktime_get_ns();
            /* Inject every ~55ms (matching 18.2 Hz PIT rate) */
            if (now - last_inject_ns > 55000000ULL) {
                /* Only inject if guest has IF=1 (interrupts enabled) */
                if (g_vmcb->save.rflags & (1ULL << 9)) {
                    g_vmcb->control.event_inj = (1U << 31) | /* valid */
                                                 (0U << 8)  | /* type = external interrupt */
                                                 0x08;         /* vector = INT 8 (timer) */
                }
                last_inject_ns = now;
            } else {
                g_vmcb->control.event_inj = 0;
            }
        }

        /*
         * VMRUN sequence with GPR save/restore.
         *
         * AMD SVM: VMRUN automatically saves host state to VM_HSAVE_PA
         * and restores it on #VMEXIT.  vmload/vmsave are NOT needed
         * around VMRUN — they're for loading extra guest state (FS/GS/
         * TR/LDTR etc.) which is already in the VMCB save area.
         *
         * In nested SVM (running under KVM), vmload before vmrun can
         * corrupt the L1 host state, so we ONLY use vmrun.
         *
         * clgi/stgi are used to disable/enable interrupts during the
         * critical VMRUN window.
         */
        {
            struct bogger_guest_gprs *gp = &guest_gprs;

            __asm__ volatile(
                /* Save host callee-saved regs we'll clobber */
                "pushq %%rbx\n\t"
                "pushq %%r12\n\t"
                "pushq %%r13\n\t"
                "pushq %%r14\n\t"
                "pushq %%r15\n\t"

                /* Load guest GPRs from struct (rdi = gp pointer) */
                "movq 0x00(%%rdi), %%rbx\n\t"
                "movq 0x08(%%rdi), %%rcx\n\t"
                "movq 0x10(%%rdi), %%rdx\n\t"
                "movq 0x18(%%rdi), %%rsi\n\t"
                /* skip rdi — loaded last */
                "movq 0x38(%%rdi), %%r8\n\t"
                "movq 0x40(%%rdi), %%r9\n\t"
                "movq 0x48(%%rdi), %%r10\n\t"
                "movq 0x50(%%rdi), %%r11\n\t"
                "movq 0x58(%%rdi), %%r12\n\t"
                "movq 0x60(%%rdi), %%r13\n\t"
                "movq 0x68(%%rdi), %%r14\n\t"
                "movq 0x70(%%rdi), %%r15\n\t"
                /* Push gp pointer so we can recover it after VMRUN */
                "pushq %%rdi\n\t"
                "movq 0x28(%%rdi), %%rdi\n\t"  /* load guest rdi last */

                /* VMRUN — just vmrun, no vmload/vmsave.
                 * vmrun saves host state to HSAVE and loads guest from VMCB.
                 * On #VMEXIT, host state is restored from HSAVE automatically. */
                "clgi\n\t"
                "vmrun  %%rax\n\t"
                "stgi\n\t"

                /* Save guest GPRs back to struct */
                "xchgq %%rdi, (%%rsp)\n\t"     /* swap: guest rdi → stack, gp → rdi */
                "movq %%rbx, 0x00(%%rdi)\n\t"
                "movq %%rcx, 0x08(%%rdi)\n\t"
                "movq %%rdx, 0x10(%%rdi)\n\t"
                "movq %%rsi, 0x18(%%rdi)\n\t"
                "popq %%rsi\n\t"               /* pop saved guest rdi */
                "movq %%rsi, 0x28(%%rdi)\n\t"  /* store guest rdi */
                "movq %%r8,  0x38(%%rdi)\n\t"
                "movq %%r9,  0x40(%%rdi)\n\t"
                "movq %%r10, 0x48(%%rdi)\n\t"
                "movq %%r11, 0x50(%%rdi)\n\t"
                "movq %%r12, 0x58(%%rdi)\n\t"
                "movq %%r13, 0x60(%%rdi)\n\t"
                "movq %%r14, 0x68(%%rdi)\n\t"
                "movq %%r15, 0x70(%%rdi)\n\t"

                /* Restore host callee-saved regs */
                "popq %%r15\n\t"
                "popq %%r14\n\t"
                "popq %%r13\n\t"
                "popq %%r12\n\t"
                "popq %%rbx\n\t"
                :
                : "a"(phys), "D"(gp)
                : "rcx", "rdx", "rsi",
                  "r8", "r9", "r10", "r11",
                  "memory", "cc"
            );
        }

        exit_code = g_vmcb->control.exit_code;
        exits++;

        /* Yield to scheduler at every VMEXIT to prevent soft lockup.
         * With INTERCEPT_INTR, we get ~250 VMEXITs/sec from host timer. */
        cond_resched();

        /* INTR exits (host timer) are frequent and uninteresting —
         * skip logging/counting but still yield via cond_resched above */
        if (exit_code == SVM_EXIT_INTR)
            goto handle_exit;

        /* Prevent infinite loops / soft lockups */
        if (exits > max_total_exits) {
            pr_err("[BOGGER] Max exits (%d) reached, stopping.\n", max_total_exits);
            goto done;
        }
        if ((exits % 1000) == 0) {
            pr_info("[BOGGER] %d exits processed, RIP=0x%llx CR0=0x%llx EFER=0x%llx\n",
                    exits, g_vmcb->save.rip, g_vmcb->save.cr0,
                    g_vmcb->save.efer);
        }

        /* Log EVERY exit for the first N exits to help debug */
        if (exits <= max_logged_exits) {
            pr_info("[BOGGER] VMEXIT #%d: code=0x%x RIP=0x%llx info1=0x%llx info2=0x%llx\n",
                    exits, exit_code, g_vmcb->save.rip,
                    g_vmcb->control.exit_info_1,
                    g_vmcb->control.exit_info_2);
            if (exits <= 20) {
                pr_info("[BOGGER]   CS: sel=0x%x base=0x%llx attr=0x%x  SS: sel=0x%x\n",
                        g_vmcb->save.cs.selector,
                        g_vmcb->save.cs.base,
                        g_vmcb->save.cs.attrib,
                        g_vmcb->save.ss.selector);
                pr_info("[BOGGER]   RAX=0x%llx RSP=0x%llx RFLAGS=0x%llx CR0=0x%llx\n",
                        g_vmcb->save.rax,
                        g_vmcb->save.rsp,
                        g_vmcb->save.rflags,
                        g_vmcb->save.cr0);
            }
        }

handle_exit:
        switch (exit_code) {
        case BOGGER_SVM_EXIT_INVALID:
            pr_emerg("[BOGGER] #VMEXIT INVALID (-1) RIP=0x%llx info1=0x%llx info2=0x%llx\n",
                   g_vmcb->save.rip, g_vmcb->control.exit_info_1,
                   g_vmcb->control.exit_info_2);
            pr_emerg("[BOGGER]   CR0=0x%llx CR3=0x%llx CR4=0x%llx EFER=0x%llx\n",
                   g_vmcb->save.cr0, g_vmcb->save.cr3,
                   g_vmcb->save.cr4, g_vmcb->save.efer);
            pr_emerg("[BOGGER]   CS.sel=0x%x CS.attr=0x%x CS.base=0x%llx\n",
                   g_vmcb->save.cs.selector, g_vmcb->save.cs.attrib,
                   g_vmcb->save.cs.base);
            goto done;

        case SVM_EXIT_INTR:
            /* Host received a physical interrupt (e.g. timer).
             * Nothing to do — just re-enter VMRUN.  The important effect
             * is that cond_resched() at the top of the loop runs, which
             * prevents soft lockup detection. Don't count these as
             * "interesting" exits. */
            break;

        case SVM_EXIT_HLT:
            /* Guest executed HLT — skip past it.
             * We do NOT inject timer interrupts because:
             * 1. OVMF's IVT entries may contain arbitrary values
             * 2. OVMF uses ACPI PM Timer (port 0x608) for delays, not interrupts
             * 3. Injecting INT into wrong IVT entry causes wild jumps
             * Just advance past HLT; OVMF's polling loops will see time
             * progression via the ACPI PM timer reads. */
            g_vmcb->save.rip += 1;
            break;

        case SVM_EXIT_IOIO: {
            u64 info1 = g_vmcb->control.exit_info_1;
            u64 port = (info1 >> 16) & 0xFFFFULL;
            int is_in = info1 & 1;
            int sz = (info1 >> 4) & 7;
            u32 val = 0xFFFFFFFF;

            if (is_in) {
                switch (port) {
                /* PCI Config Address */
                case 0xCF8: val = pci_config_addr; break;
                /* PCI Config Data — emulate i440FX host bridge + PIIX3 ISA */
                case 0xCFC: case 0xCFD: case 0xCFE: case 0xCFF: {
                    u32 bus   = (pci_config_addr >> 16) & 0xFF;
                    u32 dev   = (pci_config_addr >> 11) & 0x1F;
                    u32 func  = (pci_config_addr >> 8) & 0x07;
                    u32 reg   = (pci_config_addr & 0xFC) + (port - 0xCFC);
                    u32 bdf   = (bus << 8) | (dev << 3) | func;
                    val = 0xFFFFFFFF;

                    if (bdf == 0x0000) {
                        /* Device 0:0.0 = i440FX Host Bridge */
                        static const u8 i440fx_cfg[256] = {
                            /* 00-03: vendor=0x8086 device=0x1237 */
                            [0x00]=0x86, [0x01]=0x80, [0x02]=0x37, [0x03]=0x12,
                            /* 04-05: command: IO + MEM + BusMaster */
                            [0x04]=0x07, [0x05]=0x00,
                            /* 06-07: status */
                            [0x06]=0x00, [0x07]=0x02,
                            /* 08: revision */
                            [0x08]=0x02,
                            /* 0A-0B: class=0x0600 (host bridge) */
                            [0x0A]=0x00, [0x0B]=0x06,
                            /* 0E: header type 0 */
                            [0x0E]=0x00,
                        };
                        if (reg < 256)
                            val = i440fx_cfg[reg];
                        /* PAM registers (0x59-0x5F): open for read+write */
                        if (reg >= 0x59 && reg <= 0x5F)
                            val = 0x33;
                        /* SMRAM (0x72): open */
                        if (reg == 0x72)
                            val = 0x02;
                    } else if (bdf == 0x0001) {
                        /* Device 0:0.1 = PIIX3 ISA bridge */
                        static const u8 piix3_cfg[16] = {
                            [0x00]=0x86, [0x01]=0x80, [0x02]=0x00, [0x03]=0x70,
                            [0x04]=0x07, [0x05]=0x00, [0x06]=0x00, [0x07]=0x02,
                            [0x08]=0x00, [0x0A]=0x01, [0x0B]=0x06, [0x0E]=0x80,
                        };
                        if (reg < 16) val = piix3_cfg[reg];
                        else val = 0x00;
                    } else if (bdf == 0x0020) {
                        /* Device 0:4.0 = NVMe Controller */
                        static const u8 nvme_cfg[256] = {
                            /* 00-01: vendor=0x1B36 (QEMU/Red Hat) */
                            [0x00]=0x36, [0x01]=0x1B,
                            /* 02-03: device=0x0010 (NVMe) */
                            [0x02]=0x10, [0x03]=0x00,
                            /* 04-05: command: MEM + BusMaster */
                            [0x04]=0x06, [0x05]=0x00,
                            /* 06-07: status: capability list */
                            [0x06]=0x10, [0x07]=0x00,
                            /* 08: revision */
                            [0x08]=0x01,
                            /* 09: prog-if = 0x02 (NVMe) */
                            [0x09]=0x02,
                            /* 0A-0B: class=0x0108 (Mass Storage / NVMe) */
                            [0x0A]=0x08, [0x0B]=0x01,
                            /* 0E: header type 0 */
                            [0x0E]=0x00,
                            /* 10-17: BAR0 = 0xFE000000 (64-bit MMIO, prefetchable) */
                            [0x10]=0x04, [0x11]=0x00, [0x12]=0x00, [0x13]=0xFE,
                            [0x14]=0x00, [0x15]=0x00, [0x16]=0x00, [0x17]=0x00,
                            /* 2C-2F: subsystem vendor/device */
                            [0x2C]=0x36, [0x2D]=0x1B, [0x2E]=0x10, [0x2F]=0x00,
                            /* 34: capabilities pointer */
                            [0x34]=0x40,
                            /* 3C: interrupt line=11, pin=A */
                            [0x3C]=0x0B, [0x3D]=0x01,
                            /* 40-4B: MSI-X capability (ID=0x11, next=0x00) */
                            [0x40]=0x11, [0x41]=0x00,
                            [0x42]=0x00, [0x43]=0x00,  /* msg ctrl */
                            [0x44]=0x00, [0x45]=0x20, [0x46]=0x00, [0x47]=0x00,  /* table offset/BIR */
                            [0x48]=0x00, [0x49]=0x30, [0x4A]=0x00, [0x4B]=0x00,  /* PBA offset/BIR */
                        };
                        if (reg < 256) val = nvme_cfg[reg];
                        else val = 0x00;
                    } else {
                        val = 0xFFFFFFFF;
                    }
                    break;
                }

                /* CMOS/RTC */
                case 0x70: val = cmos_index; break;
                case 0x71: {
                    /* Minimal RTC emulation — return plausible time */
                    /* Memory size registers report guest_ram_size */
                    u32 ext_mb = (u32)((guest_ram_size >> 20) - 1);  /* MB above 1MB */
                    u32 ext_64k = (ext_mb > 16) ? ((ext_mb - 16) * 16) : 0; /* 64KB units above 16MB */
                    if (ext_64k > 0xFFFF) ext_64k = 0xFFFF;
                    switch (cmos_index) {
                    case 0x00: val = 0x30; break; /* seconds BCD */
                    case 0x02: val = 0x15; break; /* minutes BCD */
                    case 0x04: val = 0x12; break; /* hours BCD */
                    case 0x06: val = 0x05; break; /* day of week */
                    case 0x07: val = 0x28; break; /* day of month BCD */
                    case 0x08: val = 0x02; break; /* month BCD */
                    case 0x09: val = 0x26; break; /* year BCD */
                    case 0x0A: val = 0x26; break; /* Status A: UIP=0 */
                    case 0x0B: val = 0x02; break; /* Status B: 24hr */
                    case 0x0C: val = 0x00; break; /* Status C */
                    case 0x0D: val = 0x80; break; /* Status D: valid */
                    case 0x0E: val = 0x00; break; /* diag status */
                    case 0x0F: val = 0x00; break; /* shutdown */
                    case 0x10: val = 0x00; break; /* floppy type */
                    case 0x15: val = 0x80; break; /* base mem low (640K) */
                    case 0x16: val = 0x02; break; /* base mem high */
                    case 0x17: val = (ext_mb > 0xFFFF ? 0xFF : ext_mb) & 0xFF; break;
                    case 0x18: val = (ext_mb > 0xFFFF ? 0xFF : ext_mb) >> 8; break;
                    case 0x30: val = (ext_mb > 0xFFFF ? 0xFF : ext_mb) & 0xFF; break;
                    case 0x31: val = (ext_mb > 0xFFFF ? 0xFF : ext_mb) >> 8; break;
                    case 0x32: val = 0x20; break; /* century BCD */
                    case 0x34: val = ext_64k & 0xFF; break; /* ext mem above 16MB low */
                    case 0x35: val = (ext_64k >> 8) & 0xFF; break; /* ext mem above 16MB high */
                    default:   val = 0x00; break;
                    }
                    break;
                }

                /* PIT (8254) — return time-based decrementing counter.
                 * PIT Channel 0 runs at 1.193182 MHz, mode 2 (rate generator).
                 * Counter wraps at 65535 (~18.2 Hz). */
                case 0x40: case 0x41: case 0x42: {
                    u64 ns = ktime_get_ns();
                    /* 1193182 ticks/sec ≈ 1193 ticks/us */
                    u32 ticks = (u32)div_u64(ns * 1193ULL, 1000000ULL);
                    u16 count = 0xFFFF - (u16)(ticks & 0xFFFF);
                    val = count & 0xFF;
                    break;
                }
                case 0x43: val = 0x00; break;

                /* PIC (8259A) — master */
                case 0x20: val = 0x00; break;  /* IRR: no pending */
                case 0x21: val = 0xFB; break;  /* IMR: all masked except IRQ2 */
                /* PIC slave */
                case 0xA0: val = 0x00; break;
                case 0xA1: val = 0xFF; break;  /* all masked */

                /* Serial port (COM1) */
                case 0x3F8: val = 0x00; break;
                case 0x3F9: val = 0x00; break;
                case 0x3FA: val = 0x01; break;
                case 0x3FB: val = 0x03; break;
                case 0x3FC: val = 0x03; break;
                case 0x3FD: val = 0x60; break;  /* LSR: TX ready */
                case 0x3FE: val = 0xB0; break;
                case 0x3FF: val = 0x00; break;

                /* PS/2 controller */
                case 0x60: val = 0x00; break;
                case 0x64: val = 0x1C; break;  /* self-test passed */

                /* DMA */
                case 0x80: val = 0x00; break;

                /* ACPI PM ports */
                case 0x600: val = 0x00; break;  /* PM1a_STS */
                case 0x601: val = 0x00; break;
                case 0x602: val = 0x00; break;  /* PM1a_EN */
                case 0x603: val = 0x00; break;
                case 0x604: val = 0x00; break;  /* PM1a_CNT */
                case 0x605: val = 0x00; break;
                case 0x608 ... 0x60B: {
                    /* ACPI PM timer (24-bit, 3.579545 MHz)
                     * Use real host time for accurate timing. */
                    u64 ns = ktime_get_ns();
                    /* 3579545 ticks/sec = ~3.58 ticks/us = ~0.00358 ticks/ns */
                    u32 ticks = (u32)div_u64(ns * 3580ULL, 1000000ULL);
                    val = ticks & 0x00FFFFFF;
                    if (port > 0x608)
                        val >>= (port - 0x608) * 8;
                    break;
                }

                /* VGA I/O ports */
                case 0x3C0 ... 0x3CF: val = 0; break;
                case 0x3D0 ... 0x3DF: val = 0; break;

                /* QEMU Debug Console port */
                case 0x402: val = 0xE9; break; /* magic value indicating debug port present */

                /* fw_cfg (QEMU) — read byte from selected item */
                case 0x510: val = fwcfg_selector; break;
                case 0x511: val = fwcfg_read_byte(); break;

                default: val = 0xFF; break;
                }
                g_vmcb->save.rax = (g_vmcb->save.rax & ~((1ULL << (sz * 8)) - 1)) | (val & ((1ULL << (sz * 8)) - 1));
                if (sz == 0) g_vmcb->save.rax = val & 0xFF;
                else if (sz == 1) g_vmcb->save.rax = val & 0xFFFF;
                else g_vmcb->save.rax = val;
            } else {
                u32 out_val = (u32)g_vmcb->save.rax;

                switch (port) {
                case 0xCF8: pci_config_addr = out_val; break;
                case 0xCFC: case 0xCFD: case 0xCFE: case 0xCFF: break;
                case 0x70: cmos_index = (u8)(out_val & 0x7F); break;
                case 0x71: break; /* CMOS write — ignore */

                /* PIT */
                case 0x40: case 0x41: case 0x42: case 0x43: break;
                /* PIC */
                case 0x20: case 0x21: case 0xA0: case 0xA1: break;

                /* Serial — capture OVMF debug output */
                case 0x3F8: {
                    static char ovmf_line[256];
                    static int ovmf_line_pos;
                    char c = (char)(out_val & 0xFF);
                    if (c == '\n' || c == '\r' || ovmf_line_pos >= 254) {
                        if (ovmf_line_pos > 0) {
                            ovmf_line[ovmf_line_pos] = '\0';
                            pr_info("[OVMF] %s\n", ovmf_line);
                            ovmf_line_pos = 0;
                        }
                    } else if (c >= 0x20) {
                        ovmf_line[ovmf_line_pos++] = c;
                    }
                    break;
                }
                case 0x3F9: case 0x3FA: case 0x3FB:
                case 0x3FC: case 0x3FE: case 0x3FF: break;

                /* QEMU Debug Console (port 0x402) — OVMF debug output */
                case 0x402: {
                    static char dbg_line[256];
                    static int dbg_pos;
                    char c = (char)(out_val & 0xFF);
                    if (c == '\n' || c == '\r' || dbg_pos >= 254) {
                        if (dbg_pos > 0) {
                            dbg_line[dbg_pos] = '\0';
                            pr_info("[OVMF-DBG] %s\n", dbg_line);
                            dbg_pos = 0;
                        }
                    } else if (c >= 0x20) {
                        dbg_line[dbg_pos++] = c;
                    }
                    break;
                }

                /* PS/2 */
                case 0x60: case 0x64: break;
                /* VGA */
                case 0x3C0 ... 0x3CF: case 0x3D0 ... 0x3DF: break;
                /* fw_cfg */
                case 0x510: fwcfg_selector = (u16)out_val; fwcfg_offset = 0; fwcfg_buf_valid = false; break;
                case 0x511: break;
                /* ACPI PM */
                case 0x600 ... 0x603: break;  /* PM1_STS, PM1_EN — ignore */
                case 0x604: case 0x605: {
                    /* PM1a_CNT — check for S5 (shutdown) or reset */
                    u16 slp = (u16)(out_val >> 10) & 0x07;
                    u8  slp_en = (out_val >> 13) & 1;
                    if (slp_en) {
                        pr_emerg("[BOGGER] ACPI Shutdown: SLP_TYP=%d SLP_EN=1 (port=0x%llx val=0x%x)\n",
                                 slp, port, out_val);
                        if (slp == 5 || slp == 7) {
                            pr_emerg("[BOGGER] Guest requested S5 power-off — stopping VM.\n");
                            goto done;
                        }
                    }
                    break;
                }
                case 0x606 ... 0x63F: break;
                /* System Reset via port 0xCF9 */
                case 0xCF9: {
                    pr_emerg("[BOGGER] System Reset via port 0xCF9: val=0x%x\n", out_val);
                    if (out_val & 0x04) {
                        pr_emerg("[BOGGER] Hard reset requested — stopping VM.\n");
                        goto done;
                    }
                    break;
                }
                /* System Control Port A (port 0x92) — fast reset */
                case 0x92:
                    if (out_val & 1) {
                        pr_emerg("[BOGGER] Fast reset via port 0x92: val=0x%x\n", out_val);
                        goto done;
                    }
                    break;
                /* DMA + POST code (0x80) */
                case 0x00 ... 0x1F: break;
                case 0xC0 ... 0xDF: break;
                case 0x80 ... 0x8F: break;

                default: break;
                }
            }
            /* Advance RIP past the IO instruction.
             * exit_info_2 = NRIP (if CPU supports NRIP_SAVE and it's valid).
             * Fall back to manual instruction length if NRIP looks wrong. */
            {
                u64 nrip = g_vmcb->control.exit_info_2;
                if (nrip > g_vmcb->save.rip && nrip < g_vmcb->save.rip + 16) {
                    g_vmcb->save.rip = nrip;
                } else {
                    /* Manual: IN/OUT DX = 1 byte, IN/OUT imm8 = 2 bytes.
                     * SVM exit_info_1 bit 8 (IMM) tells us if immediate port. */
                    int is_imm = (info1 >> 8) & 1;  /* 1 = port in imm8, 0 = port in DX */
                    g_vmcb->save.rip += is_imm ? 2 : 1;
                }
            }
            break;
        }

        case SVM_EXIT_CPUID: {
            bogger_handle_cpuid_stealth(g_vmcb, &guest_gprs);
            break;
        }

        case SVM_EXIT_MSR: {
            if (g_vmcb->control.exit_info_1 == 0)
                bogger_handle_rdmsr_stealth(g_vmcb, &guest_gprs);
            else
                bogger_handle_wrmsr_stealth(g_vmcb, &guest_gprs);
            break;
        }

        case SVM_EXIT_INIT:
            if (exits <= max_logged_exits)
                pr_info("[BOGGER] INIT at RIP=0x%llx — ignored\n",
                        g_vmcb->save.rip);
            break;

        case SVM_EXIT_VMRUN:
            /* Guest tried to execute VMRUN — not allowed, inject #GP(0) */
            if (exits <= max_logged_exits)
                pr_info("[BOGGER] VMRUN intercepted at RIP=0x%llx — inject #GP\n",
                        g_vmcb->save.rip);
            /* Inject #GP(0): vector 13, type 3 (exception), error code valid, code=0 */
            g_vmcb->control.event_inj = (13) | (3 << 8) | (1 << 11) | (1ULL << 31);
            g_vmcb->control.event_inj_err = 0;
            break;

        case SVM_EXIT_SHUTDOWN:
            pr_emerg("[BOGGER] Triple Fault (SHUTDOWN) at RIP=0x%llx\n",
                   g_vmcb->save.rip);
            pr_emerg("[BOGGER]   CR0=0x%llx CR3=0x%llx CR4=0x%llx EFER=0x%llx\n",
                   g_vmcb->save.cr0, g_vmcb->save.cr3,
                   g_vmcb->save.cr4, g_vmcb->save.efer);
            pr_emerg("[BOGGER]   CS.sel=0x%x CS.attr=0x%x SS.sel=0x%x\n",
                   g_vmcb->save.cs.selector, g_vmcb->save.cs.attrib,
                   g_vmcb->save.ss.selector);
            pr_emerg("[BOGGER]   RSP=0x%llx RFLAGS=0x%llx\n",
                   g_vmcb->save.rsp, g_vmcb->save.rflags);
            goto done;

        case SVM_EXIT_NPF: {
            u64 fault_gpa = g_vmcb->control.exit_info_2;
            u64 npf_info = g_vmcb->control.exit_info_1;

            /* HPET page: always present now (kthread updates counter).
             * If we get an NPF here, just flush TLB and retry. */
            if ((fault_gpa & ~0xFFFULL) == HPET_GPA) {
                hpet_update_counter();
                g_vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
                break;
            }

            /* NVMe BAR page: GPA 0xFE000000–0xFE003FFF */
            if (fault_gpa >= NVME_BAR_GPA &&
                fault_gpa < NVME_BAR_GPA + NVME_BAR_SIZE) {
                /* NVMe pages are always present, this shouldn't happen
                 * unless there's a write to a doorbell page. Just flush. */
                nvme_poll_doorbell();
                g_vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
                break;
            }

            if (exits <= max_logged_exits)
                pr_info("[BOGGER] NPF: GPA=0x%llx info1=0x%llx RIP=0x%llx\n",
                        fault_gpa, npf_info, g_vmcb->save.rip);

            {
                unsigned int pd_idx = (unsigned int)(fault_gpa >> 30);
                unsigned int pd_entry = (unsigned int)((fault_gpa >> 21) & 0x1FF);

                if (pd_idx >= NPT_NUM_PD_TABLES) {
                    pr_err("[BOGGER] NPF: GPA 0x%llx out of range\n", fault_gpa);
                    goto done;
                }

                /* All NPT entries are pre-allocated during init.
                 * If we still get an NPF, it's either:
                 *  - A write to a read-only page (extension zone)
                 *  - A truly unmapped page above 4GB
                 * In both cases, just flush TLB and retry.
                 * If the PD entry is truly zero (shouldn't happen), stop. */
                if (npt_pd_tables[pd_idx][pd_entry] == 0) {
                    pr_err("[BOGGER] NPF: unmapped PD[%u][%u] at GPA 0x%llx — stopping\n",
                           pd_idx, pd_entry, fault_gpa);
                    goto done;
                }
                /* Page is mapped but faulted — could be write to read-only
                 * extension zone or MMIO. Just flush TLB and retry. */
                g_vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
            }
            break;
        }

        default:
            pr_emerg("[BOGGER] Unhandled exit=0x%x RIP=0x%llx info1=0x%llx info2=0x%llx\n",
                    exit_code, g_vmcb->save.rip,
                    g_vmcb->control.exit_info_1,
                    g_vmcb->control.exit_info_2);
            pr_emerg("[BOGGER]   CR0=0x%llx CR3=0x%llx EFER=0x%llx CS.sel=0x%x\n",
                    g_vmcb->save.cr0, g_vmcb->save.cr3,
                    g_vmcb->save.efer, g_vmcb->save.cs.selector);
            /* Try to skip the instruction if NRIP is available */
            if (g_vmcb->control.exit_info_2 != 0 &&
                g_vmcb->control.exit_info_2 > g_vmcb->save.rip) {
                g_vmcb->save.rip = g_vmcb->control.exit_info_2;
            } else {
                pr_emerg("[BOGGER] Cannot advance RIP, stopping.\n");
                goto done;
            }
            break;
        } /* end switch */

    }

done:
    /* Stop HPET updater kthread */
    if (hpet_kthread && !IS_ERR(hpet_kthread)) {
        hpet_kthread_stop = true;
        kthread_stop(hpet_kthread);
        hpet_kthread = NULL;
    }
    /* Close host NVMe device — no longer needed once VMRUN loop ends */
    if (nvme_host_dev) {
        filp_close(nvme_host_dev, NULL);
        nvme_host_dev = NULL;
    }
    pr_emerg("[BOGGER] VMRUN loop ended after %d exits\n", exits);
    pr_emerg("[BOGGER] Final state: exit_code=0x%x RIP=0x%llx RSP=0x%llx\n",
            g_vmcb->control.exit_code, g_vmcb->save.rip, g_vmcb->save.rsp);
    pr_emerg("[BOGGER] Final: CR0=0x%llx CR3=0x%llx EFER=0x%llx RFLAGS=0x%llx\n",
            g_vmcb->save.cr0, g_vmcb->save.cr3,
            g_vmcb->save.efer, g_vmcb->save.rflags);
}

/* ════════════════════════════════════════════════════════════════════
 * Module init / exit
 * ════════════════════════════════════════════════════════════════════ */
static int __init bogger_kmod_init(void)
{
    int ret;

    pr_info("[BOGGER] ═══════════════════════════════════════════\n");
    pr_info("[BOGGER] BOGGER Hypervisor Kernel Module loading\n");
    pr_info("[BOGGER] OVMF: %s\n", bogger_ovmf_code);
    pr_info("[BOGGER] ═══════════════════════════════════════════\n");

    /* 1. Verify CPU SVM support */
    ret = bogger_svm_check_support();
    if (ret) return ret;

    /* 2. Allocate guest RAM */
    ret = bogger_guest_ram_alloc();
    if (ret) return ret;

    /* 3. Load OVMF firmware into dedicated pages */
    ret = bogger_load_ovmf();
    if (ret) goto err_free_ram;

    /* 4. Build Nested Page Tables (maps guest RAM + MMIO + OVMF flash) */
    ret = bogger_npt_init();
    if (ret) goto err_free_ovmf;

    /* 5. Initialize MSR bitmap for stealth operation */
    ret = bogger_msr_bitmap_init();
    if (ret) goto err_free_npt;

    /* 6. Enable SVM (EFER.SVME) — CPU-specific, pin to this core.
     * Start HPET kthread BEFORE preempt_disable since kthread_run
     * may invoke the scheduler. */
    hpet_kthread_stop = false;
    hpet_kthread = kthread_run(hpet_updater_fn, NULL, "bogger_hpet");
    if (IS_ERR(hpet_kthread)) {
        pr_warn("[BOGGER] Failed to create HPET kthread\n");
        hpet_kthread = NULL;
    }

    /* Pin this thread to the current CPU — SVM state (EFER.SVME,
     * VM_HSAVE_PA) is per-CPU, so we must not migrate. Using CPU
     * affinity instead of preempt_disable allows cond_resched() to
     * work inside the VMRUN loop, preventing soft lockups. */
    {
        int cpu = get_cpu();  /* disables preemption temporarily */
        cpumask_var_t mask;
        put_cpu();
        if (alloc_cpumask_var(&mask, GFP_KERNEL)) {
            cpumask_clear(mask);
            cpumask_set_cpu(cpu, mask);
            set_cpus_allowed_ptr(current, mask);
            free_cpumask_var(mask);
        }
        pr_info("[BOGGER] Pinned to CPU %d for SVM operations\n", cpu);
    }

    ret = bogger_svm_enable();
    if (ret) goto err_free_npt;
    svm_enabled = true;

    /* 7. Allocate and register Host Save Area */
    ret = bogger_svm_hsave_setup();
    if (ret) goto err_disable_svm;

    /* 8. Configure VMCB for Real Mode (OVMF boot) */
    ret = bogger_vmcb_init();
    if (ret) goto err_free_hsave;

    /* 9. Open host NVMe block device for I/O pass-through to guest.
     * The host exposes the Windows disk as /dev/nvme0n1 (QEMU NVMe). */
    nvme_host_dev = filp_open("/dev/nvme0n1", O_RDWR | O_LARGEFILE, 0);
    if (IS_ERR(nvme_host_dev)) {
        pr_warn("[BOGGER] Failed to open host NVMe /dev/nvme0n1: %ld — read-only retry\n",
                PTR_ERR(nvme_host_dev));
        nvme_host_dev = filp_open("/dev/nvme0n1", O_RDONLY | O_LARGEFILE, 0);
        if (IS_ERR(nvme_host_dev)) {
            pr_warn("[BOGGER] /dev/nvme0n1 not available: %ld — NVMe I/O disabled\n",
                    PTR_ERR(nvme_host_dev));
            nvme_host_dev = NULL;
        }
    }
    if (nvme_host_dev)
        pr_info("[BOGGER] Host NVMe device opened for guest I/O pass-through\n");

    /* 10. Enter VMRUN loop — OVMF starts at reset vector → boots Windows */
    pr_info("[BOGGER] ═══ Launching OVMF via VMRUN ═══\n");
    bogger_vmrun_loop();

    return 0;

err_free_hsave:
    free_page((unsigned long)hsave_area);
    hsave_area = NULL;
err_disable_svm:
    if (svm_enabled) {
        u64 efer = native_read_msr(MSR_EFER);
        efer &= ~EFER_SVME;
        native_write_msr(MSR_EFER, efer);
        svm_enabled = false;
    }
err_free_npt:
    bogger_npt_free();
err_free_ovmf:
    bogger_ovmf_free();
err_free_ram:
    bogger_guest_ram_free();
    return ret;
}

static void __exit bogger_kmod_exit(void)
{
    pr_info("[BOGGER] Kernel module unloading\n");

    if (nvme_host_dev) {
        filp_close(nvme_host_dev, NULL);
        nvme_host_dev = NULL;
    }

    if (g_vmcb) {
        free_page((unsigned long)g_vmcb);
        g_vmcb = NULL;
    }

    bogger_npt_free();
    bogger_ovmf_free();

    if (io_bitmap) {
        free_pages((unsigned long)io_bitmap, get_order(IOPM_SIZE));
        io_bitmap = NULL;
    }

    if (msr_bitmap) {
        free_pages((unsigned long)msr_bitmap, get_order(MSRPM_SIZE));
        msr_bitmap = NULL;
    }

    if (hsave_area) {
        free_page((unsigned long)hsave_area);
        hsave_area = NULL;
    }

    bogger_guest_ram_free();

    if (svm_enabled) {
        u64 efer = native_read_msr(MSR_EFER);
        efer &= ~EFER_SVME;
        native_write_msr(MSR_EFER, efer);
        svm_enabled = false;
    }

    pr_info("[BOGGER] Kernel module unloaded\n");
}

module_init(bogger_kmod_init);
module_exit(bogger_kmod_exit);
