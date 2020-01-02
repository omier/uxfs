obj-m += uxfs.o

uxfs-objs := ux_alloc.o ux_file.o ux_dir.o ux_inode.o

all:
	$(MAKE) -C /lib/modules/$$(uname -r)/build M=$$PWD $$@
