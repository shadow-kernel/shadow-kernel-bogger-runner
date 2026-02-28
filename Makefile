CC      ?= musl-gcc
ROOT    := $(CURDIR)
CFLAGS  = -O2 -Wall -Wextra -static -ffreestanding \
          -I$(ROOT)/core/vmx -I$(ROOT)/core/passthrough \
          -I$(ROOT)/supervisor -I$(ROOT)/stealth -I$(ROOT)/launcher
LDFLAGS = -static

KDIR    ?= $(ROOT)/../linux

.PHONY: all clean core supervisor stealth launcher kmod

all: core supervisor stealth launcher kmod
	@echo "[BOGGER] All components built."

core:
	$(MAKE) -C core CC=$(CC) CFLAGS="$(CFLAGS)"

supervisor:
	$(MAKE) -C supervisor CC=$(CC) CFLAGS="$(CFLAGS)"

stealth:
	$(MAKE) -C stealth CC=$(CC) CFLAGS="$(CFLAGS)"

launcher:
	@chmod +x launcher/bogger_launcher.sh
	$(MAKE) -C launcher CC=$(CC) CFLAGS="$(CFLAGS)"

kmod:
	$(MAKE) -C kmod KDIR=$(KDIR)

clean:
	$(MAKE) -C core clean
	$(MAKE) -C supervisor clean
	$(MAKE) -C stealth clean
	$(MAKE) -C launcher clean
	$(MAKE) -C kmod KDIR=$(KDIR) clean
	@echo "[BOGGER] Clean complete."
