CC     ?= musl-gcc
CFLAGS ?= -O2 -Wall -static -ffreestanding -I./vmx -I./passthrough

VMX_SRCS    = vmx/bogger_vmx.c vmx/bogger_cpuid.c vmx/bogger_msr.c vmx/bogger_tsc.c
PASS_SRCS   = passthrough/bogger_acpi.c passthrough/bogger_iommu.c
ALL_SRCS    = $(VMX_SRCS) $(PASS_SRCS)
ALL_OBJS    = $(ALL_SRCS:.c=.o)

.PHONY: all clean
all: $(ALL_OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f vmx/*.o passthrough/*.o
