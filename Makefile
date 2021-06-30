FSFILE ?= fs
FSDIR  ?= mnt

all: cmds kern
cmds:
	$(MAKE) -C cmds
kern:
	$(MAKE) -C kern

clean:
	$(MAKE) -C cmds clean
	$(MAKE) -C kern clean
	rm -f $(FSFILE)
	if [ -d $(FSDIR) ]; then rmdir $(FSDIR); fi

load: kern
	/sbin/insmod kern/uxfs.ko

unload:
	/sbin/rmmod uxfs

wipefs: cmds
	dd if=/dev/zero of=$(FSFILE) bs=1M count=1
	cmds/mkfs $(FSFILE)

mount: $(FSFILE)
	mkdir -p $(FSDIR)
	mount -o loop $(FSFILE) $(FSDIR)

umount:
	umount $(FSDIR)

work: all load wipefs mount

delete: umount unload clean

.PHONY: all cmds kern clean load unload wipefs mount umount
