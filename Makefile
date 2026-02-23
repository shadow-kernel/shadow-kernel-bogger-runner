CC      ?= musl-gcc
CFLAGS  = -O2 -Wall -Wextra -static -ffreestanding \
          -I./core/vmx -I./core/passthrough \
          -I./supervisor -I./stealth -I./launcher
LDFLAGS = -static

.PHONY: all clean core supervisor stealth launcher

all: core supervisor stealth launcher
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

clean:
	$(MAKE) -C core clean
	$(MAKE) -C supervisor clean
	$(MAKE) -C stealth clean
	$(MAKE) -C launcher clean
	@echo "[BOGGER] Clean complete."
