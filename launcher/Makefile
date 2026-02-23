CC     ?= musl-gcc
CFLAGS ?= -O2 -Wall -static -I../core/vmx

SRCS = bogger_efi_scan.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean
all: bogger_efi_scan

bogger_efi_scan: bogger_efi_scan.o
	$(CC) -static -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o bogger_efi_scan
