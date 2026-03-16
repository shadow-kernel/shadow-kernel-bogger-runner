// SPDX-License-Identifier: GPL-2.0
/*
 * bogger_lapic.c – Local APIC emulation (MMIO at GPA 0xFEE00000)
 */
#include "bogger_lapic.h"

/* Forward declarations for IRR/ISR functions (defined at end of file) */
void lapic_set_irr(u8 vec);
void lapic_clear_irr(u8 vec);

#define LAPIC_REG_ID        0x020
#define LAPIC_REG_VERSION   0x030
#define LAPIC_REG_TPR       0x080
#define LAPIC_REG_EOI       0x0B0
#define LAPIC_REG_LDR       0x0D0
#define LAPIC_REG_DFR       0x0E0
#define LAPIC_REG_SVR       0x0F0
#define LAPIC_REG_ESR       0x280
#define LAPIC_REG_ICR_LO    0x300
#define LAPIC_REG_ICR_HI    0x310
#define LAPIC_REG_SELF_IPI  0x3F0

/* ── Self-IPI / fixed-delivery IPI pending queue ──────────────── */
#define LAPIC_IPI_QUEUE_SIZE 16
static u8  lapic_ipi_queue[LAPIC_IPI_QUEUE_SIZE];
static int lapic_ipi_head, lapic_ipi_tail;
static unsigned long lapic_ipi_total;

/* NMI pending flag — set when guest sends NMI self-IPI via ICR */
bool lapic_nmi_pending;

static void lapic_queue_ipi(u8 vec)
{
    int next = (lapic_ipi_tail + 1) % LAPIC_IPI_QUEUE_SIZE;
    if (next == lapic_ipi_head)
        return; /* queue full, drop (shouldn't happen) */
    lapic_ipi_queue[lapic_ipi_tail] = vec;
    lapic_ipi_tail = next;
    lapic_ipi_total++;
    /* Set IRR bit so guest can see the pending interrupt */
    lapic_set_irr(vec);
    if (lapic_ipi_total <= 5)
        pr_info("[BOGGER-LAPIC] Self-IPI #%lu vec=0x%02x queued (IRR set)\n",
                lapic_ipi_total, vec);
}

bool lapic_ipi_pending(u8 *vec_out)
{
    if (lapic_ipi_head == lapic_ipi_tail)
        return false;
    *vec_out = lapic_ipi_queue[lapic_ipi_head];
    lapic_ipi_head = (lapic_ipi_head + 1) % LAPIC_IPI_QUEUE_SIZE;
    return true;
}
#define LAPIC_REG_LVT_TIMER 0x320
#define LAPIC_REG_LVT_LINT0 0x350
#define LAPIC_REG_LVT_LINT1 0x360
#define LAPIC_REG_TIMER_ICR 0x380
#define LAPIC_REG_TIMER_DCR 0x3E0

#define LAPIC_BUS_FREQ_HZ  1000000000ULL  /* pretend 1 GHz bus */

struct page     *lapic_page;
volatile u32    *lapic_regs;

u32  lapic_lvt_timer;
u64  lapic_timer_start_ns;
bool lapic_timer_armed;

u32 lapic_timer_icr;
u32 lapic_timer_dcr;

static u32 lapic_get_divisor(void)
{
    u32 dcr = lapic_timer_dcr;
    /* DCR register bits: [3]=DV[2], [1:0]=DV[1:0], bit 2 is reserved.
     * Extract DV[2:0] properly: DV = (bit3 << 2) | bits[1:0] */
    u32 dv = ((dcr >> 1) & 4) | (dcr & 3);
    static const u32 tbl[] = {2, 4, 8, 16, 32, 64, 128, 1};
    return tbl[dv & 7];
}

u32 lapic_read_ccr(void)
{
    u64 elapsed_ns, ticks_elapsed, freq;
    u32 divisor;

    if (!lapic_timer_armed || lapic_timer_icr == 0)
        return 0;

    divisor = lapic_get_divisor();
    freq = LAPIC_BUS_FREQ_HZ / divisor;
    elapsed_ns = ktime_get_ns() - lapic_timer_start_ns;
    ticks_elapsed = div_u64(elapsed_ns * freq, 1000000000ULL);

    if (ticks_elapsed >= lapic_timer_icr) {
        if (lapic_lvt_timer & (1U << 17)) {
            u32 remain = lapic_timer_icr - (u32)(ticks_elapsed % lapic_timer_icr);
            return remain;
        }
        return 0;
    }
    return lapic_timer_icr - (u32)ticks_elapsed;
}

bool lapic_timer_pending(void)
{
    u64 elapsed_ns, ticks_elapsed, freq;
    u32 divisor;

    if (!lapic_timer_armed || lapic_timer_icr == 0) return false;
    if (lapic_lvt_timer & (1U << 16)) return false;  /* masked */

    divisor = lapic_get_divisor();
    freq = LAPIC_BUS_FREQ_HZ / divisor;
    elapsed_ns = ktime_get_ns() - lapic_timer_start_ns;
    ticks_elapsed = div_u64(elapsed_ns * freq, 1000000000ULL);

    return (ticks_elapsed >= lapic_timer_icr);
}

void lapic_init_regs(void)
{
    if (!lapic_regs) return;
    memset((void *)lapic_regs, 0, PAGE_SIZE);
    lapic_regs[LAPIC_REG_ID / 4]        = 0x00000000; /* APIC ID = 0 (BSP) */
    lapic_regs[LAPIC_REG_VERSION / 4]   = 0x00050014;
    lapic_regs[LAPIC_REG_DFR / 4]       = 0xFFFFFFFF;
    lapic_regs[LAPIC_REG_LDR / 4]       = 0x01000000;
    lapic_regs[LAPIC_REG_SVR / 4]       = 0x000001FF;
    lapic_regs[LAPIC_REG_LVT_TIMER / 4] = 0x00010000;
    lapic_regs[LAPIC_REG_LVT_LINT0 / 4] = 0x00010000;
    lapic_regs[LAPIC_REG_LVT_LINT1 / 4] = 0x00010000;
    lapic_regs[LAPIC_REG_TIMER_DCR / 4] = 0x0000000B;
    lapic_timer_dcr = 0x0B;
    lapic_lvt_timer = 0x00010000;
    pr_info("[BOGGER] LAPIC init: ID=0x%x VER=0x%x page_phys=0x%llx\n",
            lapic_regs[LAPIC_REG_ID / 4], lapic_regs[LAPIC_REG_VERSION / 4],
            (u64)page_to_phys(virt_to_page((void *)lapic_regs)));
}

void lapic_mmio_write(u32 offset, u32 val)
{
    switch (offset) {
    case LAPIC_REG_TPR:
        lapic_regs[offset / 4] = val & 0xFF;
        break;
    case LAPIC_REG_EOI:
        lapic_regs[LAPIC_REG_EOI / 4] = 0;
        /* Clear highest-priority in-service interrupt */
        lapic_clear_isr_highest();
        break;
    case LAPIC_REG_SVR:
        lapic_regs[offset / 4] = val;
        break;
    case LAPIC_REG_LDR:
        lapic_regs[offset / 4] = val & 0xFF000000;
        break;
    case LAPIC_REG_DFR:
        lapic_regs[offset / 4] = val | 0x0FFFFFFF;
        break;
    case LAPIC_REG_ICR_LO: {
        u8  icr_vec = val & 0xFF;
        u8  dlv_mode = (val >> 8) & 0x07;  /* delivery mode */
        u8  shorthand = (val >> 18) & 0x03;
        u8  dest_id = lapic_regs[LAPIC_REG_ICR_HI / 4] >> 24;
        bool is_self = (shorthand == 1 || shorthand == 2 ||
                        (shorthand == 0 && dest_id == 0));
        lapic_regs[offset / 4] = val;
        lapic_regs[offset / 4] &= ~(1U << 12); /* clear delivery status */

        /* Self-IPI: shorthand=Self(1), or All-incl-self(2), or
         * Physical dest matching our APIC ID (0) with shorthand=None(0) */
        if (dlv_mode == 0 /* Fixed */ && icr_vec >= 0x20) {
            if (is_self) {
                lapic_queue_ipi(icr_vec);
            }
        } else if (dlv_mode == 4 /* NMI */ && is_self) {
            /* NMI delivery to self — used by KeBugCheckEx to freeze
             * all processors, and by certain synchronization paths.
             * Queue NMI for injection; NMI bypasses RFLAGS.IF. */
            lapic_nmi_pending = true;
            pr_info("[BOGGER-LAPIC] NMI self-IPI queued (shorthand=%u)\n",
                    shorthand);
        } else if (dlv_mode == 1 /* Lowest Priority */ && icr_vec >= 0x20) {
            /* Lowest priority: on single-CPU, this is equivalent to Fixed
             * delivery to self */
            if (is_self)
                lapic_queue_ipi(icr_vec);
        }
        /* dlv_mode 5 (INIT) and 6 (Startup) for non-self targets are
         * no-ops since we have no APs.  Self-INIT is ignored (would
         * reset the BSP, which is not useful). */
        break;
    }
    case LAPIC_REG_ICR_HI:
        lapic_regs[offset / 4] = val;
        break;
    case LAPIC_REG_LVT_TIMER:
        lapic_lvt_timer = val;
        lapic_regs[offset / 4] = val;
        break;
    case LAPIC_REG_LVT_LINT0:
    case LAPIC_REG_LVT_LINT1:
        lapic_regs[offset / 4] = val;
        break;
    case LAPIC_REG_TIMER_ICR:
        lapic_timer_icr = val;
        lapic_timer_start_ns = ktime_get_ns();
        lapic_timer_armed = (val != 0);
        lapic_regs[offset / 4] = val;
        break;
    case LAPIC_REG_TIMER_DCR:
        lapic_timer_dcr = val & 0xB;
        lapic_regs[offset / 4] = val;
        break;
    case LAPIC_REG_ESR:
        lapic_regs[offset / 4] = 0;
        break;
    case LAPIC_REG_SELF_IPI:
        /* x2APIC self-IPI register (some OSes use MMIO variant) */
        if ((val & 0xFF) >= 0x20)
            lapic_queue_ipi(val & 0xFF);
        break;
    default:
        if (offset < PAGE_SIZE)
            lapic_regs[offset / 4] = val;
        break;
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * IRR / ISR register management
 *
 * Windows (and other OSes) read the LAPIC IRR/ISR registers directly
 * to check for pending/in-service interrupts.  Since we inject
 * interrupts via VMCB event_inj (not through AVIC), we must maintain
 * these registers manually in the emulated LAPIC page.
 *
 * IRR: 0x200-0x270 (8 x 32-bit = 256 vectors)
 * ISR: 0x100-0x170 (8 x 32-bit = 256 vectors)
 * TMR: 0x180-0x1F0 (8 x 32-bit = 256 vectors, not tracked here)
 * ═══════════════════════════════════════════════════════════════════ */

#define LAPIC_IRR_BASE  0x200
#define LAPIC_ISR_BASE  0x100

void lapic_set_irr(u8 vec)
{
    u32 reg_idx = vec / 32;
    u32 bit     = 1U << (vec % 32);
    u32 offset  = LAPIC_IRR_BASE + reg_idx * 0x10;
    if (lapic_regs)
        lapic_regs[offset / 4] |= bit;
}

void lapic_clear_irr(u8 vec)
{
    u32 reg_idx = vec / 32;
    u32 bit     = 1U << (vec % 32);
    u32 offset  = LAPIC_IRR_BASE + reg_idx * 0x10;
    if (lapic_regs)
        lapic_regs[offset / 4] &= ~bit;
}

void lapic_set_isr(u8 vec)
{
    u32 reg_idx = vec / 32;
    u32 bit     = 1U << (vec % 32);
    u32 offset  = LAPIC_ISR_BASE + reg_idx * 0x10;
    if (lapic_regs)
        lapic_regs[offset / 4] |= bit;
}

void lapic_clear_isr_highest(void)
{
    int i, bit;
    if (!lapic_regs)
        return;
    /* Scan ISR from highest vector (255) down to find highest set bit */
    for (i = 7; i >= 0; i--) {
        u32 offset = LAPIC_ISR_BASE + i * 0x10;
        u32 val = lapic_regs[offset / 4];
        if (val) {
            /* Clear highest set bit in this word */
            bit = 31 - __builtin_clz(val);
            lapic_regs[offset / 4] &= ~(1U << bit);
            return;
        }
    }
}

