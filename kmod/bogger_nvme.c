// SPDX-License-Identifier: GPL-2.0
/*
 * bogger_nvme.c – NVMe Controller MMIO emulation (GPA 0xFE000000)
 *
 * NVMe I/O commands (Read/Write/Flush) are dispatched to a dedicated
 * workqueue so that kernel_read()/kernel_write() → VFS → block-layer
 * call chains run on their own kernel stack, not on the shallow
 * VMRUN-loop stack.
 */
#include "bogger_nvme.h"
#include "bogger_guest_ram.h"
#include "bogger_ioapic.h"
#include <linux/workqueue.h>
#include <linux/completion.h>

#define NVME_SECTOR_SIZE    512
#define NVME_NS_ID          1
/* NVME_MAX_IO_QUEUES defined in bogger_nvme.h */

/* Auto-detect disk size from backing device, default 64GB */
static u64 nvme_disk_sectors = 134217728ULL;  /* 64GB / 512 */

struct page     *nvme_bar_pages[4];
volatile u32    *nvme_regs;
struct file     *nvme_host_dev;

u32 nvme_cc, nvme_csts, nvme_aqa;
u64 nvme_asq_base, nvme_acq_base;

static u16 nvme_sq_head;
static u16 nvme_cq_tail;
static u8  nvme_cq_phase = 1;

u64 nvme_iosq_base[NVME_MAX_IO_QUEUES];
u16 nvme_iosq_size[NVME_MAX_IO_QUEUES];
u64 nvme_iocq_base[NVME_MAX_IO_QUEUES];
u16 nvme_iocq_size[NVME_MAX_IO_QUEUES];
u16 nvme_iosq_head[NVME_MAX_IO_QUEUES];
u16 nvme_iocq_tail[NVME_MAX_IO_QUEUES];
u8  nvme_iocq_phase[NVME_MAX_IO_QUEUES];
u16 nvme_iocq_iv[NVME_MAX_IO_QUEUES];  /* MSI-X interrupt vector per I/O CQ */
bool nvme_iocq_ien[NVME_MAX_IO_QUEUES]; /* interrupts enabled per I/O CQ */

/* ── MSI-X interrupt support ─────────────────────────────────────── */
bool  nvme_msix_enabled;          /* set when guest enables MSI-X via PCI cfg */
atomic_t nvme_irq_pending_flag = ATOMIC_INIT(0);
static u8 nvme_irq_pending_vec;

/* ── Workqueue for NVMe I/O (avoids stack overflow on VMRUN thread) ── */
static struct workqueue_struct *nvme_io_wq;

struct nvme_io_req {
    struct work_struct work;
    struct completion  done;
    u64  prp1, prp2;
    u64  slba;
    u32  nlb;
    u8   opcode;
    u16  qid;
    u16  sq_head;
    u16  cmd_id;
    u16  status;
};

static struct nvme_io_req nvme_io_pending;
/* Pre-allocated I/O scratch buffer so nvme_prp_rw avoids kmalloc per call */
static u8 *nvme_io_buf;

/*
 * Translate guest physical address → host virtual address.
 * Uses shared bogger_gpa_to_hva() from bogger_guest_ram.c.
 */
#define nvme_gpa_to_hva(gpa)  bogger_gpa_to_hva(gpa)

int nvme_io_wq_init(void)
{
    nvme_io_wq = alloc_workqueue("bogger_nvme_io", WQ_UNBOUND | WQ_HIGHPRI, 1);
    if (!nvme_io_wq)
        return -ENOMEM;
    nvme_io_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!nvme_io_buf) {
        destroy_workqueue(nvme_io_wq);
        nvme_io_wq = NULL;
        return -ENOMEM;
    }
    return 0;
}

void nvme_io_wq_destroy(void)
{
    if (nvme_io_wq) {
        flush_workqueue(nvme_io_wq);
        destroy_workqueue(nvme_io_wq);
        nvme_io_wq = NULL;
    }
    kfree(nvme_io_buf);
    nvme_io_buf = NULL;
}

void nvme_init_regs(void)
{
    if (!nvme_regs) return;
    memset((void *)nvme_regs, 0, NVME_BAR_SIZE);
    nvme_regs[0] = 0x0A0100FF;
    nvme_regs[1] = 0x00000020;
    nvme_regs[2] = 0x00010400;
    nvme_regs[5] = 0;
    nvme_regs[7] = 0;
    nvme_cc = 0;
    nvme_csts = 0;
}

/* Detect the actual size of the backing block device */
void nvme_detect_disk_size(void)
{
    loff_t size;
    if (!nvme_host_dev || IS_ERR(nvme_host_dev))
        return;
    size = i_size_read(file_inode(nvme_host_dev));
    if (size <= 0) {
        /* For block devices, try vfs_llseek to end */
        size = vfs_llseek(nvme_host_dev, 0, SEEK_END);
        if (size > 0)
            vfs_llseek(nvme_host_dev, 0, SEEK_SET);
    }
    if (size > 0) {
        nvme_disk_sectors = (u64)size / NVME_SECTOR_SIZE;
        pr_info("[BOGGER-NVMe] Backing device size: %llu bytes (%llu sectors)\n",
                (unsigned long long)size, (unsigned long long)nvme_disk_sectors);
    } else {
        pr_info("[BOGGER-NVMe] Could not detect disk size, using default %llu sectors\n",
                (unsigned long long)nvme_disk_sectors);
    }
}

void nvme_update_regs(void)
{
    if (!nvme_regs) return;
    if ((nvme_cc & 1) && !(nvme_csts & 1)) {
        nvme_csts = 1;
        nvme_sq_head = 0;
        nvme_cq_tail = 0;
        nvme_cq_phase = 1;
        pr_info("[BOGGER-NVMe] Controller enabled, CSTS.RDY=1\n");
    }
    if (!(nvme_cc & 1) && (nvme_csts & 1)) {
        unsigned int i;
        nvme_csts = 0;
        /* NVMe spec: controller reset clears all doorbell registers */
        for (i = 0x400; i < NVME_BAR_SIZE / 4; i++)
            nvme_regs[i] = 0;
        /* Clear I/O queue registrations (guest must re-create after reset) */
        memset(nvme_iosq_base, 0, sizeof(nvme_iosq_base));
        memset(nvme_iosq_size, 0, sizeof(nvme_iosq_size));
        memset(nvme_iocq_base, 0, sizeof(nvme_iocq_base));
        memset(nvme_iocq_size, 0, sizeof(nvme_iocq_size));
        memset((void *)nvme_iosq_head, 0, sizeof(nvme_iosq_head));
        memset((void *)nvme_iocq_tail, 0, sizeof(nvme_iocq_tail));
        memset((void *)nvme_iocq_phase, 0, sizeof(nvme_iocq_phase));
        memset((void *)nvme_iocq_iv, 0, sizeof(nvme_iocq_iv));
        memset(nvme_iocq_ien, 0, sizeof(nvme_iocq_ien));
        pr_info("[BOGGER-NVMe] Controller disabled, doorbells+queues reset\n");
    }

    nvme_regs[7] = nvme_csts;
    nvme_regs[5] = nvme_cc;
    nvme_regs[9] = nvme_aqa;
    nvme_regs[10] = (u32)(nvme_asq_base & 0xFFFFFFFF);
    nvme_regs[11] = (u32)(nvme_asq_base >> 32);
    nvme_regs[12] = (u32)(nvme_acq_base & 0xFFFFFFFF);
    nvme_regs[13] = (u32)(nvme_acq_base >> 32);
}

/*
 * Fire MSI-X interrupt: read MSI-X table entry from NVMe BAR and
 * set pending interrupt for the VMRUN loop to inject.
 * MSI-X table is at BAR0 + 0x2000, each entry = 16 bytes:
 *   +0x00: Message Address (low 32)
 *   +0x04: Message Address (high 32)
 *   +0x08: Message Data (vector in low 8 bits)
 *   +0x0C: Vector Control (bit 0 = mask)
 *
 * If MSI-X is not enabled via PCI config space but the MSI-X table
 * contains a valid entry (written by the guest), fire the interrupt
 * anyway.  This handles the case where the PCI config MSI-X enable
 * write was missed or the guest driver uses a non-standard flow.
 */
unsigned long nvme_msix_fire_count;

static void nvme_fire_msix(u16 iv)
{
    u32 *entry;
    u32 msg_data, vec_ctrl;
    u8 vec;

    if (!nvme_regs)
        return;

    /* MSI-X table at BAR offset 0x2000, entry = iv * 4 dwords */
    entry = (u32 *)nvme_regs + (0x2000 / 4) + iv * 4;
    vec_ctrl = entry[3];

    /* Check per-vector mask (bit 0) */
    if (vec_ctrl & 1)
        return;

    msg_data = entry[2];
    vec = (u8)(msg_data & 0xFF);

    if (vec >= 0x20) {
        /* Valid MSI-X table entry — deliver regardless of PCI enable state.
         * Guest wrote MSI-X table entries (via BAR MMIO NPF), so it expects
         * these interrupts even if we missed the PCI config MSI-X enable. */
        if (!nvme_msix_enabled && nvme_msix_fire_count == 0)
            pr_info("[BOGGER-NVMe] MSI-X table has valid vec=0x%x (pci_enable=%d), firing anyway\n",
                    vec, nvme_msix_enabled);
        nvme_irq_pending_vec = vec;
        smp_wmb();
        atomic_set(&nvme_irq_pending_flag, 1);
        nvme_msix_fire_count++;
        return;
    }

    /* No valid MSI-X table entry — use INTx via IOAPIC.
     * NVMe device is at IRQ 11 (INTA#, PIIX3 PIRQA routing).
     * Route through IOAPIC redirection entry 11 to get the vector
     * that Windows assigned during PnP enumeration. */
    {
        static unsigned long intx_count;
        u8 ioapic_vec;
        if (ioapic_assert_irq(11, &ioapic_vec)) {
            if (intx_count == 0)
                pr_info("[BOGGER-NVMe] INTx via IOAPIC: IRQ 11 → vec=0x%x\n",
                        ioapic_vec);
            intx_count++;
        } else {
            /* IOAPIC entry 11 is masked or not configured.
             * Fall back to direct injection with fixed vector.
             * This won't be useful until the guest configures IOAPIC,
             * but it ensures completions are at least attempted. */
            u8 intx_vec = 0xB1;
            if (intx_count == 0)
                pr_info("[BOGGER-NVMe] INTx fallback: IOAPIC[11] masked, using vec=0x%x\n",
                        intx_vec);
            nvme_irq_pending_vec = intx_vec;
            smp_wmb();
            atomic_set(&nvme_irq_pending_flag, 1);
            intx_count++;
        }
    }
}

/* Return true + vector if an NVMe MSI-X interrupt is pending */
bool nvme_msix_irq_pending(u8 *vec_out)
{
    if (atomic_read(&nvme_irq_pending_flag)) {
        smp_rmb();
        *vec_out = nvme_irq_pending_vec;
        atomic_set(&nvme_irq_pending_flag, 0);
        return true;
    }
    return false;
}

/* ── Completion posting ───────────────────────────────────────────── */
static void nvme_post_completion(u16 sq_id, u16 cmd_id, u32 dw0, u16 status)
{
    u32 cq_size = ((nvme_aqa >> 16) & 0xFFF) + 1;
    u64 cq_entry_gpa = nvme_acq_base + (u64)nvme_cq_tail * 16;
    u32 cqe[4];
    void *hva;

    hva = nvme_gpa_to_hva(cq_entry_gpa);
    if (!hva) return;

    cqe[0] = dw0;
    cqe[1] = 0;
    cqe[2] = sq_id | ((u32)nvme_sq_head << 16);
    cqe[3] = (u32)cmd_id | ((u32)(status | (nvme_cq_phase ? 1 : 0)) << 16);
    memcpy(hva, cqe, 16);

    nvme_cq_tail++;
    if (nvme_cq_tail >= cq_size) { nvme_cq_tail = 0; nvme_cq_phase ^= 1; }

    /* Fire MSI-X vector 0 for admin CQ */
    nvme_fire_msix(0);
}

static void nvme_post_io_completion(u16 qid, u16 sq_head, u16 cmd_id, u16 status)
{
    u16 qi = qid - 1;
    u64 cq_entry_gpa;
    u32 cqe[4];
    u8  phase;
    void *hva;

    if (qid == 0 || qid > NVME_MAX_IO_QUEUES || !nvme_iocq_base[qi]) return;
    if (!guest_ram_virt) return;

    phase = nvme_iocq_phase[qi];
    cq_entry_gpa = nvme_iocq_base[qi] + (u64)nvme_iocq_tail[qi] * 16;
    hva = nvme_gpa_to_hva(cq_entry_gpa);
    if (!hva) return;

    cqe[0] = 0; cqe[1] = 0;
    cqe[2] = (u32)qid | ((u32)sq_head << 16);
    cqe[3] = (u32)cmd_id | ((u32)((status & 0x7FFE) | (phase ? 1 : 0)) << 16);
    memcpy(hva, cqe, 16);

    nvme_iocq_tail[qi]++;
    if (nvme_iocq_size[qi] && nvme_iocq_tail[qi] >= nvme_iocq_size[qi]) {
        nvme_iocq_tail[qi] = 0;
        nvme_iocq_phase[qi] ^= 1;
    }

    /* Fire MSI-X for this I/O CQ's interrupt vector */
    if (nvme_iocq_ien[qi])
        nvme_fire_msix(nvme_iocq_iv[qi]);
}

/* ── PRP-based DMA ────────────────────────────────────────────────── */
static noinline int nvme_prp_rw(u64 prp1, u64 prp2, u64 total_bytes, loff_t *pos, bool write)
{
    u64 bytes_done = 0;
    u8 *tmp = nvme_io_buf;  /* use pre-allocated buffer */
    int rc = 0;

    if (!tmp) return -ENOMEM;

    while (bytes_done < total_bytes) {
        u64 cur_gpa, pg_off, chunk;
        void *hva;
        ssize_t r;

        if (bytes_done == 0) {
            cur_gpa = prp1;
        } else {
            u64 first_page_bytes = PAGE_SIZE - (prp1 & 0xFFFULL);
            u64 after_first = bytes_done - first_page_bytes;
            if (bytes_done < first_page_bytes) {
                cur_gpa = prp1 + bytes_done;
            } else if (total_bytes - first_page_bytes <= PAGE_SIZE) {
                cur_gpa = (prp2 & ~0xFFFULL) + after_first;
            } else {
                u64 page_idx = after_first / PAGE_SIZE;
                u64 page_off2 = after_first % PAGE_SIZE;
                u64 list_gpa = (prp2 & ~0xFFFULL) + page_idx * 8;
                u64 page_gpa;
                void *list_hva = nvme_gpa_to_hva(list_gpa);
                if (!list_hva) { rc = -EIO; break; }
                page_gpa = *(u64 *)list_hva;
                cur_gpa = (page_gpa & ~0xFFFULL) + page_off2;
            }
        }

        pg_off = cur_gpa & 0xFFFULL;
        chunk = min_t(u64, total_bytes - bytes_done, PAGE_SIZE - pg_off);
        hva = nvme_gpa_to_hva(cur_gpa);
        if (!hva) { rc = -EIO; break; }

        if (write) {
            memcpy(tmp, hva, chunk);
            r = kernel_write(nvme_host_dev, tmp, chunk, pos);
        } else {
            r = kernel_read(nvme_host_dev, tmp, chunk, pos);
            if (r > 0) memcpy(hva, tmp, r);
        }
        if (r <= 0) { rc = -EIO; break; }
        bytes_done += (u64)r;
    }
    return rc;
}

/* ── Admin commands ───────────────────────────────────────────────── */
unsigned long nvme_admin_cmd_count;
unsigned long nvme_io_cmd_count;

static void nvme_process_admin_cmd(u32 *cmd)
{
    u8  opcode = cmd[0] & 0xFF;
    u16 cmd_id = (cmd[0] >> 16) & 0xFFFF;
    u32 nsid   = cmd[1];
    u64 prp1   = (u64)cmd[6] | ((u64)cmd[7] << 32);  /* DW6-7: Data Pointer (PRP1) */
    u32 cdw10  = cmd[10];

    nvme_admin_cmd_count++;
    pr_info("[BOGGER-NVMe] ADMIN CMD #%lu: opcode=0x%02x cid=%u nsid=%u cdw10=0x%x prp1=0x%llx\n",
            nvme_admin_cmd_count, opcode, cmd_id, nsid, cdw10, prp1);

    switch (opcode) {
    case 0x06: { /* Identify */
        u8 cns = cdw10 & 0xFF;
        void *ident_hva = nvme_gpa_to_hva(prp1);
        if (cns == 1 && ident_hva) {
            u8 *ident = (u8 *)ident_hva;
            memset(ident, 0, 4096);
            /* PCI Vendor/Subsystem IDs (Samsung) */
            *(u16 *)(ident + 0) = 0x144D;
            *(u16 *)(ident + 2) = 0x144D;
            /* Serial Number (offset 4, 20 bytes) */
            memcpy(ident + 4, "S5P2NG0NB01234F     ", 20);
            /* Model Number (offset 24, 40 bytes) */
            memcpy(ident + 24, "Samsung SSD 980 PRO 1TB                 ", 40);
            /* Firmware Revision (offset 64, 8 bytes) */
            memcpy(ident + 64, "5B2QGXA7", 8);
            /* IEEE OUI (offset 73, 3 bytes) */
            ident[73] = 0x00; ident[74] = 0x2C; ident[75] = 0xE0;
            /* MDTS: Maximum Data Transfer Size (offset 77) */
            ident[77] = 5;  /* 2^5 * min page size */
            /* Controller ID (offset 78) */
            *(u16 *)(ident + 78) = 0x0001;
            /* Version (offset 80): NVMe 1.4 */
            *(u32 *)(ident + 80) = 0x00010400;
            /* OACS: Optional Admin Command Support (offset 256) */
            *(u16 *)(ident + 256) = 0x0006; /* firmware, namespace mgmt */
            /* ACWU: Atomic Compare & Write Unit (offset 258) */
            /* Error Log Page Entries (offset 262) */
            ident[262] = 63;
            /* Log Page Attributes (offset 261) */
            ident[261] = 0x04;
            /* Firmware Updates (offset 260) */
            ident[260] = 0x14;
            /* SQES: SQ Entry Size (offset 512) min=6 max=6 (64 bytes) */
            ident[512] = 0x66;
            /* CQES: CQ Entry Size (offset 513) min=4 max=4 (16 bytes) */
            ident[513] = 0x44;
            /* NN: Number of Namespaces (offset 516) */
            *(u32 *)(ident + 516) = 1;
            /* ONCS: Optional NVM Command Support (offset 520) */
            *(u16 *)(ident + 520) = 0x001F; /* compare, write uncorrectable, dsm, write zeroes, features */
            /* VWC: Volatile Write Cache (offset 525) */
            ident[525] = 0x01; /* volatile write cache present */
            nvme_post_completion(0, cmd_id, 0, 0);
        } else if (cns == 0 && nsid == NVME_NS_ID && ident_hva) {
            u8 *ns = (u8 *)ident_hva;
            u64 nsze = nvme_disk_sectors;
            memset(ns, 0, 4096);
            /* NSZE: Namespace Size in logical blocks */
            memcpy(ns, &nsze, 8);
            /* NCAP: Namespace Capacity */
            memcpy(ns + 8, &nsze, 8);
            /* NUSE: Namespace Utilization */
            memcpy(ns + 16, &nsze, 8);
            /* NSFEAT: Namespace Features */
            ns[24] = 0;
            /* NLBAF: Number of LBA Formats (0-based, 0 = 1 format) */
            ns[25] = 0;
            /* FLBAS: Formatted LBA Size (index into LBAF table) */
            ns[26] = 0; /* LBA format 0 */
            /* MC: Metadata Capabilities */
            ns[27] = 0;
            /* DPC: Data Protection Capabilities */
            ns[28] = 0;
            /* LBAF0 at offset 128: MS=0, LBADS=9 (512 bytes), RP=0 */
            *(u32 *)(ns + 128) = (9 << 16); /* LBADS=9 → 2^9 = 512 byte sectors */
            nvme_post_completion(0, cmd_id, 0, 0);
        } else if (cns == 2 && ident_hva) {
            u32 *list = (u32 *)ident_hva;
            memset(list, 0, 4096);
            list[0] = NVME_NS_ID;
            nvme_post_completion(0, cmd_id, 0, 0);
        } else {
            nvme_post_completion(0, cmd_id, 0, (0x0002 << 1));
        }
        break;
    }
    case 0x01: { /* Create I/O SQ */
        u16 qid = cdw10 & 0xFFFF;
        u16 qsz = (u16)((cdw10 >> 16) + 1);
        pr_info("[BOGGER-NVMe] Create IO SQ: qid=%u size=%u base=0x%llx\n",
                qid, qsz, prp1);
        if (qid >= 1 && qid <= NVME_MAX_IO_QUEUES) {
            nvme_iosq_base[qid - 1] = prp1;
            nvme_iosq_size[qid - 1] = qsz;
            nvme_iosq_head[qid - 1] = 0;
        }
        nvme_post_completion(0, cmd_id, 0, 0);
        break;
    }
    case 0x05: { /* Create I/O CQ */
        u16 qid = cdw10 & 0xFFFF;
        u16 qsz = (u16)((cdw10 >> 16) + 1);
        u16 iv  = (u16)((cmd[11] >> 16) & 0xFFFF); /* MSI-X interrupt vector */
        bool ien = !!(cmd[11] & 0x02);               /* Interrupts Enabled */
        pr_info("[BOGGER-NVMe] Create IO CQ: qid=%u size=%u base=0x%llx iv=%u ien=%d\n",
                qid, qsz, prp1, iv, ien);
        if (qid >= 1 && qid <= NVME_MAX_IO_QUEUES) {
            nvme_iocq_base[qid - 1]  = prp1;
            nvme_iocq_size[qid - 1]  = qsz;
            nvme_iocq_tail[qid - 1]  = 0;
            nvme_iocq_phase[qid - 1] = 1;
            nvme_iocq_iv[qid - 1]    = iv;
            nvme_iocq_ien[qid - 1]   = ien;
        }
        nvme_post_completion(0, cmd_id, 0, 0);
        break;
    }
    case 0x09: { /* Set Features */
        u8 fid = cdw10 & 0xFF;
        u32 result = 0;
        if (fid == 0x07) {
            /* Number of Queues: return what was requested, capped at max */
            u16 nsq = cmd[11] & 0xFFFF;        /* requested SQs (0-based) */
            u16 ncq = (cmd[11] >> 16) & 0xFFFF; /* requested CQs (0-based) */
            if (nsq >= NVME_MAX_IO_QUEUES) nsq = NVME_MAX_IO_QUEUES - 1;
            if (ncq >= NVME_MAX_IO_QUEUES) ncq = NVME_MAX_IO_QUEUES - 1;
            result = ((u32)ncq << 16) | nsq;
        }
        nvme_post_completion(0, cmd_id, result, 0);
        break;
    }
    case 0x0A: /* Get Features */ {
        u8 fid = cdw10 & 0xFF;
        u32 result = 0;
        switch (fid) {
        case 0x01: result = 0; break;        /* Arbitration */
        case 0x02: result = 0; break;        /* Power Management */
        case 0x04: result = 0x00060006; break; /* Temperature Threshold */
        case 0x05: result = 0; break;        /* Error Recovery */
        case 0x06: result = 0; break;        /* Volatile Write Cache: disabled */
        case 0x07: result = ((NVME_MAX_IO_QUEUES - 1) << 16) | (NVME_MAX_IO_QUEUES - 1); break; /* Number of Queues (0-based) */
        case 0x08: result = 0; break;        /* Interrupt Coalescing */
        case 0x09: result = 0; break;        /* Interrupt Vector Config */
        case 0x0A: result = 0; break;        /* Write Atomicity */
        case 0x0B: result = 0; break;        /* Async Event Config */
        default: break;
        }
        nvme_post_completion(0, cmd_id, result, 0);
        break;
    }
    case 0x02: { /* Get Log Page */
        /* Windows queries various log pages; return zeroed data */
        void *log_hva = nvme_gpa_to_hva(prp1);
        if (log_hva) {
            u32 numd = (cdw10 >> 16) & 0xFFFF;
            u32 log_bytes = ((u32)numd + 1) * 4;
            if (log_bytes > 4096) log_bytes = 4096;
            memset(log_hva, 0, log_bytes);
        }
        nvme_post_completion(0, cmd_id, 0, 0);
        break;
    }
    case 0x00: { /* Delete I/O Submission Queue */
        u16 qid_del = cdw10 & 0xFFFF;
        if (qid_del >= 1 && qid_del <= NVME_MAX_IO_QUEUES) {
            nvme_iosq_base[qid_del - 1] = 0;
            nvme_iosq_size[qid_del - 1] = 0;
            nvme_iosq_head[qid_del - 1] = 0;
        }
        nvme_post_completion(0, cmd_id, 0, 0);
        break;
    }
    case 0x04: { /* Delete I/O Completion Queue */
        u16 qid_del = cdw10 & 0xFFFF;
        if (qid_del >= 1 && qid_del <= NVME_MAX_IO_QUEUES) {
            nvme_iocq_base[qid_del - 1] = 0;
            nvme_iocq_size[qid_del - 1] = 0;
            nvme_iocq_tail[qid_del - 1] = 0;
            nvme_iocq_phase[qid_del - 1] = 0;
        }
        nvme_post_completion(0, cmd_id, 0, 0);
        break;
    }
    case 0x08: /* Abort */
        nvme_post_completion(0, cmd_id, 0, 0);
        break;
    default:   nvme_post_completion(0, cmd_id, 0, (0x0001 << 1)); break;
    }
}

void nvme_poll_doorbell(void)
{
    u32 sq_size, new_tail;
    u64 sq_entry_gpa;

    if (!nvme_regs || !guest_ram_virt || !(nvme_csts & 1)) return;

    new_tail = nvme_regs[0x400] & 0xFFFF;
    sq_size = (nvme_aqa & 0xFFF) + 1;

    while (nvme_sq_head != new_tail) {
        sq_entry_gpa = nvme_asq_base + (u64)nvme_sq_head * 64;
        nvme_sq_head = (nvme_sq_head + 1) % sq_size;  /* advance BEFORE completion */
        {
            void *hva = nvme_gpa_to_hva(sq_entry_gpa);
            if (hva) {
                u32 *cmd = (u32 *)hva;
                nvme_process_admin_cmd(cmd);
            }
        }
    }
}

/* ── I/O commands — workqueue worker ──────────────────────────────── */
static void nvme_io_work_fn(struct work_struct *work)
{
    struct nvme_io_req *req = container_of(work, struct nvme_io_req, work);
    u64 total  = (u64)req->nlb * NVME_SECTOR_SIZE;
    loff_t pos = (loff_t)req->slba * NVME_SECTOR_SIZE;
    u16 status = 0;

    switch (req->opcode) {
    case 0x00: /* Flush */
        if (nvme_host_dev)
            vfs_fsync(nvme_host_dev, 0);
        break;
    case 0x02: /* Read */
        if (!nvme_host_dev || !guest_ram_virt) { status = (0x0002 << 1); break; }
        if (nvme_prp_rw(req->prp1, req->prp2, total, &pos, false) < 0)
            status = (0x0004 << 1);
        else if (nvme_io_cmd_count <= 25 && status == 0) {
            /* Diagnostic: dump first bytes of key disk reads.
             * GPT header (LBA 1), partition entries (LBA 2), VBRs. */
            void *hva = nvme_gpa_to_hva(req->prp1);
            if (hva) {
                u8 *d8 = (u8 *)hva;
                if (req->slba == 0) {
                    pr_info("[BOGGER-NVMe] DIAG LBA0 (MBR): %02x%02x %02x%02x sig=%02x%02x type[0]=%02x\n",
                            d8[0], d8[1], d8[2], d8[3],
                            d8[510], d8[511], d8[0x1C2]);
                } else if (req->slba == 1) {
                    pr_info("[BOGGER-NVMe] DIAG LBA1 (GPT): sig=%c%c%c%c%c%c%c%c rev=%02x%02x%02x%02x\n",
                            d8[0], d8[1], d8[2], d8[3], d8[4], d8[5], d8[6], d8[7],
                            d8[8], d8[9], d8[10], d8[11]);
                    pr_info("[BOGGER-NVMe] DIAG GPT: myLBA=%llu altLBA=%llu firstLBA=%llu lastLBA=%llu parts=%u entSz=%u\n",
                            *(u64 *)(d8 + 24), *(u64 *)(d8 + 32),
                            *(u64 *)(d8 + 40), *(u64 *)(d8 + 48),
                            *(u32 *)(d8 + 80), *(u32 *)(d8 + 84));
                } else if (req->slba == 2 && req->nlb >= 2) {
                    /* First two GPT partition entries (128 bytes each) */
                    int e;
                    for (e = 0; e < 4 && e * 128 + 48 <= (int)total; e++) {
                        u8 *ent = d8 + e * 128;
                        u64 start_lba = *(u64 *)(ent + 32);
                        u64 end_lba   = *(u64 *)(ent + 40);
                        if (start_lba == 0 && end_lba == 0) break;
                        pr_info("[BOGGER-NVMe] DIAG GPT[%d]: type=%02x%02x%02x%02x-%02x%02x-%02x%02x start=%llu end=%llu (%llu MB)\n",
                                e, ent[3], ent[2], ent[1], ent[0],
                                ent[5], ent[4], ent[7], ent[6],
                                start_lba, end_lba,
                                (unsigned long long)((end_lba - start_lba + 1) * 512 / 1048576));
                    }
                } else if (req->slba > 2 && nvme_io_cmd_count <= 12) {
                    /* Partition VBR: dump filesystem signature */
                    pr_info("[BOGGER-NVMe] DIAG LBA%llu (VBR): %02x %02x%02x%02x OEM=%.8s sig=%02x%02x\n",
                            req->slba, d8[0], d8[1], d8[2], d8[3], d8 + 3,
                            d8[510], d8[511]);
                }
            }
        }
        break;
    case 0x01: /* Write */
        if (!nvme_host_dev || !guest_ram_virt) { status = (0x0002 << 1); break; }
        if (nvme_prp_rw(req->prp1, req->prp2, total, &pos, true) < 0)
            status = (0x0004 << 1);
        break;
    default:
        status = (0x0001 << 1);
        break;
    }
    req->status = status;
    complete(&req->done);
}

static noinline void nvme_process_io_cmd(u16 qid, u16 sq_head, u32 *cmd)
{
    u8  opcode = cmd[0] & 0xFF;
    u16 cmd_id = (cmd[0] >> 16) & 0xFFFF;
    u16 status;

    nvme_io_cmd_count++;
    if (nvme_io_cmd_count <= 200) {
        u64 slba = (u64)cmd[10] | ((u64)cmd[11] << 32);
        u32 nlb  = (cmd[12] & 0xFFFF) + 1;
        u64 io_prp1 = (u64)cmd[6] | ((u64)cmd[7] << 32);
        u64 io_prp2 = (u64)cmd[8] | ((u64)cmd[9] << 32);
        pr_info("[BOGGER-NVMe] IO CMD #%lu: op=0x%02x cid=%u LBA=%llu NLB=%u prp1=0x%llx prp2=0x%llx qid=%u\n",
                nvme_io_cmd_count, opcode, cmd_id,
                (unsigned long long)slba, nlb,
                (unsigned long long)io_prp1, (unsigned long long)io_prp2, qid);
    }

    /* Dispatch to workqueue to keep kernel_read() off the VMRUN stack */
    init_completion(&nvme_io_pending.done);
    nvme_io_pending.opcode  = opcode;
    nvme_io_pending.cmd_id  = cmd_id;
    nvme_io_pending.qid     = qid;
    nvme_io_pending.sq_head = sq_head;
    nvme_io_pending.prp1    = (u64)cmd[6] | ((u64)cmd[7] << 32);
    nvme_io_pending.prp2    = (u64)cmd[8] | ((u64)cmd[9] << 32);
    nvme_io_pending.slba    = (u64)cmd[10] | ((u64)cmd[11] << 32);
    nvme_io_pending.nlb     = (cmd[12] & 0xFFFF) + 1;
    nvme_io_pending.status  = 0;

    INIT_WORK(&nvme_io_pending.work, nvme_io_work_fn);

    if (nvme_io_wq) {
        queue_work(nvme_io_wq, &nvme_io_pending.work);
        wait_for_completion(&nvme_io_pending.done);
        status = nvme_io_pending.status;
    } else {
        /* Fallback: run inline (risky for stack) */
        nvme_io_work_fn(&nvme_io_pending.work);
        status = nvme_io_pending.status;
    }

    if (nvme_io_cmd_count <= 200 && status != 0)
        pr_warn("[BOGGER-NVMe] IO CMD #%lu: FAILED status=0x%04x prp1=0x%llx\n",
                nvme_io_cmd_count, status,
                (unsigned long long)nvme_io_pending.prp1);
    nvme_post_io_completion(qid, sq_head, cmd_id, status);
}

void nvme_poll_io_doorbell(void)
{
    unsigned int qi;
    if (!nvme_regs || !guest_ram_virt || !(nvme_csts & 1)) return;

    for (qi = 0; qi < NVME_MAX_IO_QUEUES; qi++) {
        u16 qid = (u16)(qi + 1);
        u16 new_tail, sq_size;
        u64 sq_entry_gpa;

        if (!nvme_iosq_base[qi] || !nvme_iosq_size[qi]) continue;

        new_tail = (u16)(nvme_regs[0x400 + 2 * qid] & 0xFFFF);
        sq_size = nvme_iosq_size[qi];

        while (nvme_iosq_head[qi] != new_tail) {
            u16 next_head;
            sq_entry_gpa = nvme_iosq_base[qi] + (u64)nvme_iosq_head[qi] * 64;
            next_head = (nvme_iosq_head[qi] + 1) % sq_size;
            nvme_iosq_head[qi] = next_head;  /* advance BEFORE completion */
            {
                void *hva = nvme_gpa_to_hva(sq_entry_gpa);
                if (hva) {
                    u32 *cmd = (u32 *)hva;
                    nvme_process_io_cmd(qid, next_head, cmd);
                }
            }
        }
    }
}

