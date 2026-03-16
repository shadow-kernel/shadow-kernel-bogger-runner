// SPDX-License-Identifier: GPL-2.0
/*
 * bogger_hpet.c – HPET emulation (MMIO at GPA 0xFED00000)
 */
#include "bogger_hpet.h"

struct page          *hpet_page;
volatile u32         *hpet_regs;
struct task_struct   *hpet_kthread;
volatile bool         hpet_kthread_stop;

void hpet_init_regs(void)
{
    if (!hpet_regs) return;
    memset((void *)hpet_regs, 0, PAGE_SIZE);
    /* HPET General Capabilities (offset 0x00): 64-bit counter, 3 timers, rev 1, vendor 8086 */
    hpet_regs[0x00/4] = 0x80868201;
    hpet_regs[0x04/4] = 69841279;    /* CLK_PERIOD in femtoseconds (~14.318 MHz) */
    /* General Configuration (offset 0x10): ENABLE_CNF = 1 */
    hpet_regs[0x10/4] = 0x01;
}

void hpet_update_counter(void)
{
    u64 ns, ticks;
    if (!hpet_regs) return;
    ns = ktime_get_ns();
    ticks = div_u64(ns * 14318ULL, 1000000ULL);
    /* Main Counter Value (offset 0xF0-0xF7) */
    hpet_regs[0xF0/4] = (u32)(ticks & 0xFFFFFFFF);
    hpet_regs[0xF4/4] = (u32)((ticks >> 32) & 0xFFFFFFFF);
}

int hpet_updater_fn(void *data)
{
    pr_info("[BOGGER] HPET updater kthread started on CPU %d\n", smp_processor_id());
    while (!hpet_kthread_stop) {
        hpet_update_counter();
        usleep_range(50, 150);
    }
    pr_info("[BOGGER] HPET updater kthread stopped\n");
    return 0;
}

