ENTRY := helloworld
obj-m := $(ENTRY).o
KERNEL_VER = $(shell uname -r)
default: force_build
  
force_build: helloworld.c
	rm -f *.ko
	make -C /lib/modules/$(KERNEL_VER)/build M=$(PWD) modules
	ls -alh *.ko

notfound_build: helloworld.c
	[ -f *.ko ] || make -C /lib/modules/$(KERNEL_VER)/build M=$(PWD) modules

build: force_build

clean:
	make -C /lib/modules/$(KERNEL_VER)/build M=$(PWD) clean

insmod: info notfound_build
	dmesg --clear
	insmod helloworld.ko || true
	dmesg

rmmod:
	rmmod helloworld && dmesg

lsmod:
	lsmod |grep helloworld

status: lsmod

info: notfound_build helloworld.ko
	modinfo helloworld.ko
	md5sum helloworld.ko

modinfo: info

help:
	@echo " build    - build module(default target)"
	@echo " clean    - clean build dir"
	@echo " insmod   - insmod helloworld ko module"
	@echo " rmmod    - rmmod helloworld ko module"
	@echo " lsmod    - find helloworld ko module whether already insmod"
	@echo " status   - same as lsmod"
	@echo " info     - display helloworld ko info"
	@echo " modinfo  - same as info"
	@echo " help     - display help info"

