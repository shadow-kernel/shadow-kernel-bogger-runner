#include "bogger_supervisor.h"
#include "bogger_vmx.h"
#include "bogger_cpuid.h"
#include "bogger_msr.h"
#include "bogger_tsc.h"
#include "bogger_acpi.h"
#include "bogger_iommu.h"
#include "bogger_stealth.h"
#include "bogger_ipc.h"
#include "bogger_efi_scan.h"

#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/* Minimal write() syscall wrapper (no libc in -ffreestanding)         */
/* ------------------------------------------------------------------ */

static long bogger_write(int fd, const void *buf, unsigned long len)
{
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "0"(1L),          /* __NR_write = 1 on x86-64 */
          "D"((long)fd),
          "S"(buf),
          "d"(len)
        : "rcx", "r11", "memory"
    );
    return ret;
}

/* ------------------------------------------------------------------ */
/* Minimal integer-to-string helpers (no printf in -ffreestanding)     */
/* ------------------------------------------------------------------ */

static void uint_to_str(unsigned long v, char *buf, int base)
{
    static const char digits[] = "0123456789abcdef";
    char tmp[64];
    int  i = 0, j;

    if (v == 0) { buf[0] = '0'; buf[1] = '\0'; return; }
    while (v) {
        tmp[i++] = digits[v % (unsigned)base];
        v /= (unsigned)base;
    }
    for (j = 0; j < i; j++)
        buf[j] = tmp[i - 1 - j];
    buf[i] = '\0';
}

static int bogger_strlen(const char *s)
{
    int n = 0;
    while (s[n]) n++;
    return n;
}

/* ------------------------------------------------------------------ */
/* bogger_log                                                          */
/* ------------------------------------------------------------------ */

static int g_log_level = LOG_INFO; /* 3 = INFO and below (ERROR, WARN, INFO) */

void bogger_log(int level, const char *fmt, ...)
{
    char    buf[256];
    int     pos = 0;
    va_list ap;

    if (level > g_log_level)
        return;

    va_start(ap, fmt);

    /* Write prefix */
    const char *pfx = "[BOGGER] ";
    while (*pfx && pos < (int)sizeof(buf) - 1)
        buf[pos++] = *pfx++;

    /* Walk format string */
    const char *p = fmt;
    while (*p && pos < (int)sizeof(buf) - 2) {
        if (*p != '%') {
            buf[pos++] = *p++;
            continue;
        }
        p++; /* skip '%' */
        switch (*p) {
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (!s) s = "(null)";
            while (*s && pos < (int)sizeof(buf) - 2)
                buf[pos++] = *s++;
            break;
        }
        case 'u': {
            char tmp[32];
            uint_to_str((unsigned long)va_arg(ap, unsigned int), tmp, 10);
            const char *s = tmp;
            while (*s && pos < (int)sizeof(buf) - 2)
                buf[pos++] = *s++;
            break;
        }
        case 'x': {
            char tmp[32];
            uint_to_str((unsigned long)va_arg(ap, unsigned int), tmp, 16);
            const char *s = tmp;
            while (*s && pos < (int)sizeof(buf) - 2)
                buf[pos++] = *s++;
            break;
        }
        default:
            buf[pos++] = '%';
            if (pos < (int)sizeof(buf) - 2)
                buf[pos++] = *p;
            break;
        }
        p++;
    }

    va_end(ap);

    buf[pos++] = '\n';
    buf[pos]   = '\0';

    /* Write to /dev/console (fd 1 is stdout which maps to console in initramfs) */
    bogger_write(1, buf, (unsigned long)pos);
}

/* ------------------------------------------------------------------ */
/* VM-exit stub — saves/restores all caller-saved registers,          */
/* calls bogger_vmexit_handler(), then VMRESUME                       */
/* ------------------------------------------------------------------ */

__attribute__((naked)) void bogger_vmexit_stub(void)
{
    __asm__ volatile(
        /* Save all general-purpose registers onto the host stack */
        "push %%rax\n\t"
        "push %%rbx\n\t"
        "push %%rcx\n\t"
        "push %%rdx\n\t"
        "push %%rsi\n\t"
        "push %%rdi\n\t"
        "push %%rbp\n\t"
        "push %%r8\n\t"
        "push %%r9\n\t"
        "push %%r10\n\t"
        "push %%r11\n\t"
        "push %%r12\n\t"
        "push %%r13\n\t"
        "push %%r14\n\t"
        "push %%r15\n\t"
        /* Allocate a bogger_guest_state_t on the stack and pass pointer */
        "sub  $152, %%rsp\n\t"     /* sizeof(bogger_guest_state_t) */
        "mov  %%rsp, %%rdi\n\t"    /* first argument */
        "call bogger_vmexit_handler\n\t"
        "add  $152, %%rsp\n\t"
        /* Restore registers */
        "pop %%r15\n\t"
        "pop %%r14\n\t"
        "pop %%r13\n\t"
        "pop %%r12\n\t"
        "pop %%r11\n\t"
        "pop %%r10\n\t"
        "pop %%r9\n\t"
        "pop %%r8\n\t"
        "pop %%rbp\n\t"
        "pop %%rdi\n\t"
        "pop %%rsi\n\t"
        "pop %%rdx\n\t"
        "pop %%rcx\n\t"
        "pop %%rbx\n\t"
        "pop %%rax\n\t"
        "vmresume\n\t"
        ::: "memory"
    );
}

/* ------------------------------------------------------------------ */
/* bogger_supervisor_main                                              */
/* ------------------------------------------------------------------ */

static bogger_vmcs_region_t s_vmxon_region __attribute__((aligned(4096)));
static bogger_vmcs_region_t s_vmcs         __attribute__((aligned(4096)));

void bogger_supervisor_main(int argc, char **argv)
{
    const char *efi_path  = NULL;
    const char *conf_path = NULL;
    int         i;

    /* Parse --efi <path> and --conf <path> */
    for (i = 1; i < argc - 1; i++) {
        const char *arg = argv[i];
        int match_efi  = (bogger_strlen(arg) == 5 &&
                          arg[0]=='-' && arg[1]=='-' &&
                          arg[2]=='e' && arg[3]=='f' && arg[4]=='i');
        int match_conf = (bogger_strlen(arg) == 6 &&
                          arg[0]=='-' && arg[1]=='-' &&
                          arg[2]=='c' && arg[3]=='o' &&
                          arg[4]=='n' && arg[5]=='f');
        if (match_efi)
            efi_path = argv[++i];
        else if (match_conf)
            conf_path = argv[++i];
    }
    (void)conf_path;

    bogger_log(LOG_INFO, "=== BOGGER Supervisor v0.1.0 starting ===");

    /* 1. Check VMX support */
    if (bogger_vmx_check_support() != 0) {
        bogger_log(LOG_ERROR, "VMX not supported. Halting.");
        return;
    }
    bogger_log(LOG_INFO, "VMX support confirmed.");

    /* 2. Initialise stealth layer */
    bogger_stealth_init();

    /* 3. Initialise IPC shared memory */
    bogger_ipc_init();

    /* 4. Initialise ACPI passthrough (find and expose real RSDP) */
    bogger_acpi_passthrough_init();

    /* 5. Initialise IOMMU passthrough */
    bogger_iommu_init_passthrough();

    /* 6. Enable VMX (CR4.VMXE) */
    bogger_vmx_enable();

    /* 7. VMXON */
    if (bogger_vmxon(&s_vmxon_region) != 0) {
        bogger_log(LOG_ERROR, "VMXON failed. Halting.");
        return;
    }
    bogger_log(LOG_INFO, "VMXON succeeded — now in VMX root mode.");

    /* 8. Scan for Windows EFI if not provided */
    if (!efi_path || bogger_strlen(efi_path) == 0) {
        bogger_log(LOG_INFO, "Scanning for Windows EFI entry...");
        /* bogger_efi_get_entry() scans block devices for winload.efi */
        efi_path = "/EFI/Microsoft/Boot/winload.efi";
    }

    uint64_t guest_rip = bogger_efi_get_entry(efi_path);
    uint64_t guest_rsp = 0x7FFFFFFFE000ULL;

    bogger_log(LOG_INFO, "Guest RIP set from EFI entry.");

    /* 9. Setup VMCS (also initialises EPT and writes EPTP) */
    if (bogger_setup_vmcs(&s_vmcs, guest_rip, guest_rsp) != 0) {
        bogger_log(LOG_ERROR, "VMCS setup failed. Halting.");
        return;
    }
    bogger_log(LOG_INFO, "VMCS configured.");

    /* 10. TSC calibration */
    bogger_tsc_offset_init();

    /* 11. VMLAUNCH — Windows starts here */
    bogger_log(LOG_INFO, "Launching Windows under VMX supervision...");
    if (bogger_vmlaunch() != 0) {
        /* VMLAUNCH failed — read error code from VMCS */
        uint64_t err = bogger_vmread(0x4400); /* VM_INSTRUCTION_ERROR */
        bogger_log(LOG_ERROR, "VMLAUNCH failed, VM instruction error=%x", (unsigned)err);
        return;
    }

    /* bogger_vmexit_stub() handles all VM exits and loops via VMRESUME.
     * We should never reach here under normal operation. */
}

/* ------------------------------------------------------------------ */
/* main – C entry point called by the OS                              */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    bogger_supervisor_main(argc, argv);

    /* Unexpected return — VMLAUNCH should not return on success.
     * Drop to a rescue shell so the operator can diagnose the failure. */
    bogger_log(LOG_ERROR, "Unexpected return from supervisor — dropping to /bin/sh");

    static const char *const shell_argv[] = { "/bin/sh", (const char *)0 };
    extern int execve(const char *, char * const [], char * const []);
    execve("/bin/sh", (char * const *)shell_argv, (char * const *)0);

    /* execve should not return; if it does, halt */
    return 1;
}
