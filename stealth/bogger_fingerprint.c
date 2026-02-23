#include "bogger_fingerprint.h"
#include <stdint.h>
#include <stddef.h>

/* Forward declarations for log (implemented in bogger_supervisor.c) */
extern void bogger_log(int level, const char *fmt, ...);

#ifndef LOG_INFO
#define LOG_INFO 1
#endif
#ifndef LOG_WARN
#define LOG_WARN 1
#endif

/* ------------------------------------------------------------------ */
/* Minimal string helpers (no libc in -ffreestanding)                 */
/* ------------------------------------------------------------------ */

static int fp_strlen(const char *s)
{
    int n = 0;
    while (s[n]) n++;
    return n;
}

static int fp_strcasestr_found(const char *haystack, const char *needle)
{
    int hlen = fp_strlen(haystack);
    int nlen = fp_strlen(needle);
    int i, j;

    if (nlen == 0) return 1;
    for (i = 0; i <= hlen - nlen; i++) {
        int match = 1;
        for (j = 0; j < nlen; j++) {
            char h = haystack[i + j];
            char n = needle[j];
            /* Convert to lowercase */
            if (h >= 'A' && h <= 'Z') h += 32;
            if (n >= 'A' && n <= 'Z') n += 32;
            if (h != n) { match = 0; break; }
        }
        if (match) return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Minimal open/read/close syscalls                                    */
/* ------------------------------------------------------------------ */

static long fp_open(const char *path, int flags)
{
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "0"(2L), "D"(path), "S"((long)flags), "d"(0L)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static long fp_read(int fd, void *buf, unsigned long len)
{
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "0"(0L), "D"((long)fd), "S"(buf), "d"(len)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static void fp_close(int fd)
{
    __asm__ volatile(
        "syscall"
        :: "a"(3L), "D"((long)fd)
        : "rcx", "r11", "memory"
    );
}

/* ------------------------------------------------------------------ */
/* State                                                               */
/* ------------------------------------------------------------------ */

#define DMI_BUF_SIZE 4096

static char g_vendor[64]  = "";
static char g_product[64] = "";
static int  g_read_done   = 0;

/* Known virtualisation strings */
static const char * const virt_strings[] = {
    "VBOX", "QEMU", "VMware", "Xen", "KVM",
    "Hyper-V", "VirtualBox", "innotek", "BOCHS", "SeaBIOS",
    NULL
};

/* ------------------------------------------------------------------ */
/* SMBIOS structure walker                                             */
/* ------------------------------------------------------------------ */

/*
 * get_smbios_string – Return the Nth string from an SMBIOS structure's
 * string section (1-indexed, following the formatted area).
 */
static const char *get_smbios_string(const uint8_t *entry, uint8_t index)
{
    /* The formatted area length is at byte offset 1 */
    uint8_t      len = entry[1];
    const char  *str = (const char *)(entry + len);

    if (index == 0)
        return "";

    while (--index > 0) {
        if (*str == '\0' && *(str + 1) == '\0') return ""; /* end of strings */
        while (*str) str++;
        str++;
    }
    return str;
}

void bogger_fingerprint_read(void)
{
    static uint8_t buf[DMI_BUF_SIZE];
    long           fd, nr;
    const uint8_t *p, *end;

    if (g_read_done)
        return;

    /* Open the raw DMI table */
    fd = fp_open("/sys/firmware/dmi/tables/DMI", 0 /* O_RDONLY */);
    if (fd < 0) {
        bogger_log(LOG_WARN, "Fingerprint: cannot open /sys/firmware/dmi/tables/DMI");
        g_read_done = 1;
        return;
    }

    nr = fp_read((int)fd, buf, sizeof(buf));
    fp_close((int)fd);

    if (nr <= 0) {
        bogger_log(LOG_WARN, "Fingerprint: DMI read returned no data");
        g_read_done = 1;
        return;
    }

    p   = buf;
    end = buf + nr;

    /* Walk SMBIOS structures */
    while (p + 4 <= end) {
        uint8_t type = p[0];
        uint8_t len  = p[1];

        if (len < 4 || p + len > end)
            break;

        if (type == 1) {
            /* System Information (Type 1) */
            uint8_t vendor_idx  = (len > 0x04) ? p[0x04] : 0;
            uint8_t product_idx = (len > 0x05) ? p[0x05] : 0;
            const char *v = get_smbios_string(p, vendor_idx);
            const char *pr = get_smbios_string(p, product_idx);
            /* Copy to static buffers */
            int i;
            for (i = 0; i < 63 && v[i]; i++)  g_vendor[i]  = v[i];
            g_vendor[i] = '\0';
            for (i = 0; i < 63 && pr[i]; i++) g_product[i] = pr[i];
            g_product[i] = '\0';
        }

        /* Skip to next structure: skip the formatted area, then two
         * consecutive NUL bytes that terminate the string section */
        const uint8_t *str_area = p + len;
        while (str_area + 1 < end) {
            if (str_area[0] == 0 && str_area[1] == 0) {
                str_area += 2;
                break;
            }
            str_area++;
        }
        p = str_area;
    }

    g_read_done = 1;
    bogger_log(LOG_INFO, "Fingerprint: SMBIOS read complete.");
}

void bogger_fingerprint_verify(void)
{
    bogger_fingerprint_read();

    bogger_log(LOG_INFO, "Fingerprint: Vendor  = ");
    bogger_log(LOG_INFO, g_vendor[0]  ? g_vendor  : "(unknown)");
    bogger_log(LOG_INFO, "Fingerprint: Product = ");
    bogger_log(LOG_INFO, g_product[0] ? g_product : "(unknown)");

    /* Scan both strings for virtualisation signatures */
    int i;
    int found_any = 0;

    for (i = 0; virt_strings[i] != NULL; i++) {
        if (fp_strcasestr_found(g_vendor,  virt_strings[i]) ||
            fp_strcasestr_found(g_product, virt_strings[i])) {
            bogger_log(LOG_WARN, "Fingerprint: WARNING — virtualisation string detected in SMBIOS!");
            found_any = 1;
        }
    }

    if (!found_any)
        bogger_log(LOG_INFO, "Fingerprint: No virtualisation strings in SMBIOS [OK]");
}

const char *bogger_fingerprint_get_vendor(void)
{
    bogger_fingerprint_read();
    return g_vendor;
}

const char *bogger_fingerprint_get_product(void)
{
    bogger_fingerprint_read();
    return g_product;
}
