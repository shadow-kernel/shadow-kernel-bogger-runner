#ifndef BOGGER_SUPERVISOR_H
#define BOGGER_SUPERVISOR_H

/* Log levels */
#define LOG_SILENT  0
#define LOG_ERROR   1
#define LOG_WARN    2
#define LOG_INFO    3
#define LOG_VERBOSE 4

/*
 * bogger_supervisor_main – Main entry point for the BOGGER hypervisor.
 *
 * Sequence:
 *   1. Parse --efi <path> and --conf <path> from argv
 *   2. Verify VMX support
 *   3. Initialise stealth layer (CPUID / MSR intercept configuration)
 *   4. Initialise IOMMU passthrough
 *   5. Enable VMX (CR4.VMXE)
 *   6. VMXON
 *   7. Scan for Windows EFI entry point
 *   8. Setup VMCS
 *   9. Calibrate TSC offset
 *  10. VMLAUNCH — Windows starts here
 *  11. VM-exit dispatch loop
 */
void bogger_supervisor_main(int argc, char **argv);

/*
 * bogger_log – Write a log message to /dev/console.
 * level : LOG_ERROR / LOG_INFO / LOG_WARN / LOG_VERBOSE
 */
void bogger_log(int level, const char *fmt, ...);

/*
 * bogger_vmexit_stub – Low-level assembly trampoline that saves host registers,
 * calls bogger_vmexit_handler(), restores registers, and executes VMRESUME.
 */
void bogger_vmexit_stub(void);

#endif /* BOGGER_SUPERVISOR_H */
