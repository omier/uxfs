.PHONY: all

all:
	$(MAKE) -C cmds
	$(MAKE) -C kern

clean:
	$(MAKE) -C cmds clean
	$(MAKE) -C kern clean

load:
	/sbin/insmod kern/uxfs.ko

unload:
	/sbin/rmmod uxfs
