/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOGGER_NVME_H
#define BOGGER_NVME_H
#include "bogger_types.h"

#define NVME_BAR_GPA   0xE2000000ULL
#define NVME_BAR_SIZE  0x4000
#define NVME_MAX_IO_QUEUES  4

void nvme_init_regs(void);
void nvme_detect_disk_size(void);
void nvme_update_regs(void);
void nvme_poll_doorbell(void);
void nvme_poll_io_doorbell(void);
int  nvme_io_wq_init(void);
void nvme_io_wq_destroy(void);

/* MSI-X interrupt support */
extern bool nvme_msix_enabled;
extern atomic_t nvme_irq_pending_flag;
extern unsigned long nvme_io_cmd_count;
extern unsigned long nvme_msix_fire_count;
extern unsigned long nvme_admin_cmd_count;
extern u32 nvme_cc, nvme_csts, nvme_aqa;
extern u64 nvme_asq_base, nvme_acq_base;
extern u64 nvme_iosq_base[NVME_MAX_IO_QUEUES];
extern u64 nvme_iocq_base[NVME_MAX_IO_QUEUES];
extern u16 nvme_iocq_iv[NVME_MAX_IO_QUEUES];
extern bool nvme_iocq_ien[NVME_MAX_IO_QUEUES];
bool nvme_msix_irq_pending(u8 *vec_out);

#endif

