obj-m += uxfs.o
uxfs-y := ux_alloc.o ux_file.o ux_dir.o ux_inode.o

KDIR ?= /lib/modules/`uname -r`/build

all:
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean

load:
	insmod ./uxfs.ko

unload:
	rmmod uxfs
