#include "bogger_ipc.h"

#ifndef BOGGER_IPC_PAGES
#define BOGGER_IPC_PAGES 4
#endif

/* Shared memory region — not mapped in guest page tables */
static uint8_t g_ipc_region[BOGGER_IPC_PAGES * 4096]
    __attribute__((aligned(4096)));

/* BOGGER version string returned to IPC clients */
#define BOGGER_VERSION_MAGIC 0x00010000UL  /* 0.1.0 */

void bogger_ipc_init(void)
{
    /* Zero-initialise the IPC region */
    uint8_t *p   = g_ipc_region;
    uint32_t len = BOGGER_IPC_PAGES * 4096;
    while (len--)
        *p++ = 0;
}

void bogger_handle_ipc_vmcall(bogger_guest_state_t *guest)
{
    uint64_t cmd  = guest->rax;
    uint64_t arg1 = guest->rbx;
    uint64_t arg2 = guest->rcx;
    uint64_t arg3 = guest->rdx;

    uint64_t result = 0;

    switch (cmd) {
    case IPC_CMD_PING:
        /* Echo arg1 back to caller */
        result = arg1;
        break;

    case IPC_CMD_GET_VERSION:
        result = BOGGER_VERSION_MAGIC;
        break;

    case IPC_CMD_READ_MEM: {
        /*
         * arg1 = host physical address to read
         * arg2 = size in bytes (capped at IPC region size)
         * arg3 = destination offset inside IPC region
         *
         * Copies bytes from host memory into the shared IPC region.
         * The guest can then read the IPC region via a separate mapping.
         */
        uint64_t max_size = (uint64_t)(BOGGER_IPC_PAGES * 4096);
        uint64_t size = (arg2 < max_size) ? arg2 : max_size;
        uint64_t off  = (arg3 < max_size) ? arg3 : 0;

        if (off + size <= max_size && arg1 != 0) {
            const uint8_t *src = (const uint8_t *)(uintptr_t)arg1;
            uint8_t       *dst = g_ipc_region + off;
            uint64_t       n   = size;
            while (n--)
                *dst++ = *src++;
            result = size;
        }
        break;
    }

    case IPC_CMD_WRITE_MEM: {
        /*
         * arg1 = host physical address to write
         * arg2 = size in bytes (capped at IPC region size)
         * arg3 = source offset inside IPC region
         */
        uint64_t max_size = (uint64_t)(BOGGER_IPC_PAGES * 4096);
        uint64_t size = (arg2 < max_size) ? arg2 : max_size;
        uint64_t off  = (arg3 < max_size) ? arg3 : 0;

        if (off + size <= max_size && arg1 != 0) {
            const uint8_t *src = g_ipc_region + off;
            uint8_t       *dst = (uint8_t *)(uintptr_t)arg1;
            uint64_t       n   = size;
            while (n--)
                *dst++ = *src++;
            result = size;
        }
        break;
    }

    default:
        result = (uint64_t)-1; /* Unknown command */
        break;
    }

    guest->rax = result;

    /* VMCALL is a 3-byte instruction (0F 01 C1) */
    bogger_advance_rip(guest, 3);
}
