#include "bogger_cpuid.h"

void bogger_handle_cpuid(bogger_guest_state_t *guest)
{
    uint32_t eax_in = (uint32_t)guest->rax;
    uint32_t ecx_in = (uint32_t)guest->rcx;
    uint32_t eax, ebx, ecx, edx;

    /* Execute the real CPUID instruction */
    __asm__ volatile(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(eax_in), "c"(ecx_in)
    );

    /* Filter results to hide hypervisor presence */
    if (eax_in == 0x1) {
        /* Clear ECX[31] — Hypervisor Present bit */
        ecx &= ~(1U << 31);
    } else if (eax_in >= 0x40000000U && eax_in <= 0x400000FFU) {
        /* Hypervisor leaf range — zero all outputs */
        eax = 0;
        ebx = 0;
        ecx = 0;
        edx = 0;
    }
    /* All other leaves pass through unmodified */

    guest->rax = eax;
    guest->rbx = ebx;
    guest->rcx = ecx;
    guest->rdx = edx;

    /* CPUID is a 2-byte instruction (0F A2) */
    bogger_advance_rip(guest, 2);
}
