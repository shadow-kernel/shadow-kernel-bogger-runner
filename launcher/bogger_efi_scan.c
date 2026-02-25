/*
 * bogger_efi_scan.c – Scan block devices for the Windows EFI System Partition
 * and locate winload.efi.
 *
 * When built as a standalone binary (main() defined below) it prints the full
 * path to winload.efi on stdout and exits 0, or prints nothing and exits 1.
 *
 * When included as part of the supervisor build, bogger_efi_get_entry() parses
 * the PE/COFF header of the EFI binary and returns its entry-point RVA as an
 * absolute virtual address.
 */

#include "bogger_efi_scan.h"

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/* Minimal libc-replacement helpers (used in both build modes)         */
/* ------------------------------------------------------------------ */

/* These are provided by the standard C library when not -ffreestanding.
 * For the bogger_efi_scan standalone binary we compile WITHOUT
 * -ffreestanding so normal libc is available.                         */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* ------------------------------------------------------------------ */
/* PE/COFF header definitions (minimal)                               */
/* ------------------------------------------------------------------ */

#define PE_SIGNATURE        0x00004550UL  /* "PE\0\0" */
#define PE_MACHINE_AMD64    0x8664

typedef struct {
    uint16_t machine;
    uint16_t num_sections;
    uint32_t time_stamp;
    uint32_t sym_table_ptr;
    uint32_t num_symbols;
    uint16_t opt_hdr_size;
    uint16_t characteristics;
} __attribute__((packed)) pe_file_hdr_t;

typedef struct {
    uint16_t magic;           /* 0x020B for PE32+ */
    uint8_t  major_linker;
    uint8_t  minor_linker;
    uint32_t code_size;
    uint32_t init_data_size;
    uint32_t uninit_data_size;
    uint32_t entry_point_rva; /* Offset from image base to entry point */
    uint32_t code_base;
    uint64_t image_base;
} __attribute__((packed)) pe_opt_hdr64_t;

/*
 * bogger_efi_get_entry – Parse winload.efi and return its entry-point as
 * image_base + entry_point_rva.
 */
uint64_t bogger_efi_get_entry(const char *efi_path)
{
    if (!efi_path || efi_path[0] == '\0')
        return 0;

    FILE *f = fopen(efi_path, "rb");
    if (!f)
        return 0;

    /* Read MZ DOS header — e_lfanew is at offset 0x3C */
    uint8_t  mz[2];
    uint32_t e_lfanew = 0;

    if (fread(mz, 1, 2, f) != 2 || mz[0] != 'M' || mz[1] != 'Z')
        goto fail;

    if (fseek(f, 0x3C, SEEK_SET) != 0)
        goto fail;
    if (fread(&e_lfanew, 4, 1, f) != 1)
        goto fail;

    /* Seek to PE signature */
    if (fseek(f, (long)e_lfanew, SEEK_SET) != 0)
        goto fail;

    uint32_t sig = 0;
    if (fread(&sig, 4, 1, f) != 1 || sig != PE_SIGNATURE)
        goto fail;

    /* Read COFF file header */
    pe_file_hdr_t fhdr;
    if (fread(&fhdr, sizeof(fhdr), 1, f) != 1)
        goto fail;
    if (fhdr.machine != PE_MACHINE_AMD64)
        goto fail;

    /* Read optional header */
    pe_opt_hdr64_t opt;
    if (fread(&opt, sizeof(opt), 1, f) != 1)
        goto fail;
    if (opt.magic != 0x020B) /* PE32+ */
        goto fail;

    fclose(f);
    return opt.image_base + opt.entry_point_rva;

fail:
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */
/* EFI System Partition detection                                      */
/* ------------------------------------------------------------------ */

#define ESP_MOUNT_POINT "/tmp/bogger_esp"
#define BOOTMGFW_REL_PATH "EFI/Microsoft/Boot/bootmgfw.efi"

/* Maximum device path length: "/dev/" (5) + NAME_MAX (255) + "p" + "128" + NUL = 265.
 * Rounding up to 310 leaves room for future growth. */
#define MAX_DEVICE_PATH_LEN 310

#ifdef BOGGER_EFI_STANDALONE

/* GPT EFI System Partition type GUID (mixed-endian as stored on disk):
 * C12A7328-F81F-11D2-BA4B-00A0C93EC93B */
static const uint8_t gpt_esp_type_guid[16] = {
    0x28, 0x73, 0x2A, 0xC1,  /* C12A7328 LE */
    0x1F, 0xF8,              /* F81F LE */
    0xD2, 0x11,              /* 11D2 BE */
    0xBA, 0x4B,
    0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B
};

typedef struct {
    uint64_t signature;       /* "EFI PART" */
    uint32_t revision;
    uint32_t header_size;
    uint32_t header_crc32;
    uint32_t reserved;
    uint64_t my_lba;
    uint64_t alt_lba;
    uint64_t first_usable_lba;
    uint64_t last_usable_lba;
    uint8_t  disk_guid[16];
    uint64_t part_entry_lba;
    uint32_t num_part_entries;
    uint32_t part_entry_size;
    uint32_t part_crc32;
} __attribute__((packed)) gpt_header_t;

typedef struct {
    uint8_t  type_guid[16];
    uint8_t  part_guid[16];
    uint64_t start_lba;
    uint64_t end_lba;
    uint64_t attributes;
    uint16_t name[36]; /* UTF-16LE */
} __attribute__((packed)) gpt_entry_t;

static int guid_eq(const uint8_t *a, const uint8_t *b)
{
    int i;
    for (i = 0; i < 16; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

/*
 * try_mount_and_find – Try to mount a partition device as vfat and check
 * whether winload.efi exists on it.
 *
 * Returns 1 and fills out_path (up to out_len bytes) on success, 0 otherwise.
 */
static int try_mount_and_find(const char *dev, char *out_path, size_t out_len)
{
    struct stat st;
    char winload_path[512];
    int  found = 0;

    /* Create mount point */
    if (stat(ESP_MOUNT_POINT, &st) != 0)
        mkdir(ESP_MOUNT_POINT, 0700);

    if (mount(dev, ESP_MOUNT_POINT, "vfat", MS_RDONLY, "") != 0)
        return 0;

    snprintf(winload_path, sizeof(winload_path),
             "%s/%s", ESP_MOUNT_POINT, BOOTMGFW_REL_PATH);

    if (stat(winload_path, &st) == 0 && S_ISREG(st.st_mode)) {
        snprintf(out_path, out_len, "%s", winload_path);
        found = 1;
    }

    umount(ESP_MOUNT_POINT);
    return found;
}

/*
 * scan_gpt_device – Parse the GPT partition table of 'disk_dev' and try each
 * EFI System Partition entry.
 *
 * Returns 1 and fills out_path on success, 0 otherwise.
 */
static int scan_gpt_device(const char *disk_dev, char *out_path, size_t out_len)
{
    gpt_header_t hdr;
    int          fd;
    uint32_t     i;

    fd = open(disk_dev, O_RDONLY);
    if (fd < 0)
        return 0;

    /* LBA 1 = GPT header (512-byte sectors assumed) */
    if (lseek(fd, 512, SEEK_SET) < 0) { close(fd); return 0; }
    if (read(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) {
        close(fd); return 0;
    }

    /* Verify GPT signature: "EFI PART" = 0x5452415020494645 */
    if (hdr.signature != 0x5452415020494645ULL) {
        close(fd); return 0;
    }

    off_t part_off = (off_t)(hdr.part_entry_lba * 512);
    if (lseek(fd, part_off, SEEK_SET) < 0) { close(fd); return 0; }

    for (i = 0; i < hdr.num_part_entries && i < 128; i++) {
        gpt_entry_t entry;
        if (read(fd, &entry, sizeof(entry)) != (ssize_t)sizeof(entry))
            break;

        /* Skip empty entries */
        uint8_t zero[16] = {0};
        if (guid_eq(entry.type_guid, zero))
            continue;

        if (guid_eq(entry.type_guid, gpt_esp_type_guid)) {
            /* Construct partition device name: disk_dev + partition number */
            char part_dev[MAX_DEVICE_PATH_LEN];
            /* Heuristic: /dev/sdaX or /dev/nvme0n1pX */
            const char *base = strrchr(disk_dev, '/');
            base = base ? base + 1 : disk_dev;

            if (strncmp(base, "nvme", 4) == 0 || strncmp(base, "mmcblk", 6) == 0)
                snprintf(part_dev, sizeof(part_dev), "%sp%u", disk_dev, i + 1);
            else
                snprintf(part_dev, sizeof(part_dev), "%s%u", disk_dev, i + 1);

            if (try_mount_and_find(part_dev, out_path, out_len)) {
                close(fd);
                return 1;
            }
        }
    }

    close(fd);
    return 0;
}

/* ------------------------------------------------------------------ */
/* main – standalone bogger_efi_scan binary                           */
/* ------------------------------------------------------------------ */

int main(void)
{
    DIR           *dir;
    struct dirent *ent;
    char           out_path[512] = {0};

    dir = opendir("/sys/block");
    if (!dir) {
        fprintf(stderr, "[bogger_efi_scan] Cannot open /sys/block\n");
        return 1;
    }

    while ((ent = readdir(dir)) != NULL) {
        char disk_dev[MAX_DEVICE_PATH_LEN];

        /* Skip . and .. and loop/ram devices */
        if (ent->d_name[0] == '.')                    continue;
        if (strncmp(ent->d_name, "loop", 4) == 0)    continue;
        if (strncmp(ent->d_name, "ram",  3) == 0)    continue;
        if (strncmp(ent->d_name, "zram", 4) == 0)    continue;

        snprintf(disk_dev, sizeof(disk_dev), "/dev/%s", ent->d_name);

        if (scan_gpt_device(disk_dev, out_path, sizeof(out_path))) {
            closedir(dir);
            puts(out_path);
            return 0;
        }
    }

    closedir(dir);
    return 1; /* winload.efi not found */
}

#endif /* BOGGER_EFI_STANDALONE */
