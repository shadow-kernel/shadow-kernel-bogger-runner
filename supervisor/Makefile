CC     ?= musl-gcc
CFLAGS ?= -O2 -Wall -static -ffreestanding -I../core/vmx -I../core/passthrough -I../stealth -I../launcher

SRCS = bogger_supervisor.c bogger_ipc.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean
all: bogger_supervisor

bogger_supervisor: $(OBJS) ../core/vmx/bogger_vmx.o ../core/vmx/bogger_cpuid.o \
                   ../core/vmx/bogger_msr.o ../core/vmx/bogger_tsc.o \
                   ../core/vmx/bogger_ept.o \
                   ../core/passthrough/bogger_acpi.o ../core/passthrough/bogger_iommu.o \
                   ../stealth/bogger_stealth.o ../stealth/bogger_fingerprint.o \
                   ../launcher/bogger_efi_scan.o
	$(CC) $(CFLAGS) -static -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o bogger_supervisor
