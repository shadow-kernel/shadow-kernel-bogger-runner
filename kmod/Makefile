obj-m += bogger_kmod.o

# Use the project's custom kernel tree by default so vermagic matches at runtime.
# Override with: make KDIR=/path/to/other/kernel
KDIR ?= $(shell cd "$(CURDIR)/../../linux" 2>/dev/null && pwd || echo /lib/modules/$(shell uname -r)/build)

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
