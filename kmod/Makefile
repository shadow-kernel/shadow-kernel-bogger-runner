obj-m += bogger.o

# Multi-file kernel module: bogger.ko is built from all these .c files
bogger-y := bogger_kmod.o      \
            bogger_vmrun.o     \
            bogger_fwcfg.o     \
            bogger_guest_ram.o \
            bogger_npt.o       \
            bogger_ovmf.o      \
            bogger_acpi.o      \
            bogger_svm.o       \
            bogger_stealth.o   \
            bogger_lapic.o     \
            bogger_ioapic.o    \
            bogger_hpet.o      \
            bogger_nvme.o      \
            bogger_ioport.o    \
            bogger_pic.o       \
            bogger_ps2.o       \
            bogger_smbios.o    \
            bogger_pci_passthrough.o \
            bogger_vga.o

# Disable UBSAN for this module — the VMRUN loop + kernel_read() NVMe I/O
# path is too deep for 16KB kernel stacks when UBSAN inflates every frame.
CFLAGS_bogger_kmod.o      += -fno-sanitize=all
CFLAGS_bogger_nvme.o      += -fno-sanitize=all
CFLAGS_bogger_vmrun.o     += -fno-sanitize=all
CFLAGS_bogger_ioport.o    += -fno-sanitize=all
CFLAGS_bogger_npt.o       += -fno-sanitize=all
CFLAGS_bogger_lapic.o     += -fno-sanitize=all

# Use the project's custom kernel tree by default so vermagic matches at runtime.
# Override with: make KDIR=/path/to/other/kernel
KDIR ?= $(shell cd "$(CURDIR)/../../linux" 2>/dev/null && pwd || echo /lib/modules/$(shell uname -r)/build)

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
