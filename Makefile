obj-m += mmap_guard.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

ccflags-y := -Wall

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load:
	sudo insmod mmap_guard.ko protected_path="/tmp/secreto.txt" block_mode=1

unload:
	sudo rmmod mmap_guard

reload: unload load

log:
	cat /proc/mmap_guard

dmesg:
	sudo dmesg | tail -n 40

.PHONY: all clean load unload reload log dmesg
