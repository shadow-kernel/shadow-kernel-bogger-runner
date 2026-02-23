CC     ?= musl-gcc
CFLAGS ?= -O2 -Wall -static -I../core/vmx

SRCS = bogger_efi_scan.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean
all: bogger_efi_scan

# The standalone binary is built directly from source with BOGGER_EFI_STANDALONE
# so that its main() is compiled in.  The shared bogger_efi_scan.o (linked into
# the supervisor) is built WITHOUT the define, which guards the duplicate main().
bogger_efi_scan: bogger_efi_scan.c
	$(CC) $(CFLAGS) -DBOGGER_EFI_STANDALONE -static -o $@ $<

clean:
	rm -f *.o bogger_efi_scan
