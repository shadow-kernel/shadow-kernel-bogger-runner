#ifndef BOGGER_IPC_H
#define BOGGER_IPC_H

#include "bogger_vmx.h"
#include <stdint.h>

/* VMCALL command codes (passed in RAX) */
#define IPC_CMD_READ_MEM    0x1
#define IPC_CMD_WRITE_MEM   0x2
#define IPC_CMD_GET_VERSION 0x3
#define IPC_CMD_PING        0x4

/*
 * bogger_ipc_init – Allocate the shared memory region used for host↔guest
 * communication.  The region is BOGGER_IPC_PAGES × 4096 bytes and is NOT
 * mapped in the guest page tables by default — it is only accessible from
 * VMX root mode.
 */
void bogger_ipc_init(void);

/*
 * bogger_handle_ipc_vmcall – Dispatch a VMCALL from the Windows-side
 * userspace agent.
 *
 * VMCALL ABI:
 *   RAX = command (IPC_CMD_*)
 *   RBX = arg1
 *   RCX = arg2
 *   RDX = arg3
 *
 * Return value is placed in RAX of the guest.
 */
void bogger_handle_ipc_vmcall(bogger_guest_state_t *guest);

#endif /* BOGGER_IPC_H */
