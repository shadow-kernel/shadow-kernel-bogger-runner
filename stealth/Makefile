CC     ?= musl-gcc
CFLAGS ?= -O2 -Wall -static -ffreestanding -I../core/vmx

SRCS = bogger_stealth.c bogger_fingerprint.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean
all: $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o
