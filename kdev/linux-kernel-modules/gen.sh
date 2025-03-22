#!/bin/bash

if [ $# -ne 1 ]
then
	echo "gen.sh need one parameter, please specific kernel module name."
	echo " begin with {a-z、A-z、_} , may contain 0-9 , make it sense."
	exit 1
fi

[ ! -d src ] && mkdir src

if [ -f src/Makefile ]
then
	echo "src/Makefile already exists! clean or backup it at first!"
	exit 1
fi

cat > src/Makefile << EOF
ENTRY := helloworld
obj-m := \$(ENTRY).o
KERNEL_VER = \$(shell uname -r)
default: force_build
  
force_build: helloworld.c
	rm -f *.ko
	make -C /lib/modules/\$(KERNEL_VER)/build M=\$(PWD) modules
	ls -alh *.ko

notfound_build: helloworld.c
	[ -f *.ko ] || make -C /lib/modules/\$(KERNEL_VER)/build M=\$(PWD) modules

build: force_build

clean:
	make -C /lib/modules/\$(KERNEL_VER)/build M=\$(PWD) clean

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

EOF

if [ -f "src/$1" ]
then
	echo "src/$1 already exists! clean or backup it at first!"
	exit 1
fi

cat > "src/$1.c" << EOF
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

static int __init helloworld_init(void)
{
    printk(KERN_INFO "--------------------------------------------\n");
    printk(KERN_INFO "Loading helloworld Module\n");
    printk(KERN_INFO "file:%s func:%s line:%d\n",__FILE__,__func__,__LINE__);
    return 0;
}

static void __exit helloworld_exit(void)
{
    printk(KERN_INFO "--------------------------------------------\n");
    printk(KERN_INFO "Removing helloworld Module\n");
    printk(KERN_INFO "file:%s func:%s line:%d\n",__FILE__,__func__,__LINE__);
}

module_init(helloworld_init);
module_exit(helloworld_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("helloworld Module");
MODULE_AUTHOR("nicyou");
EOF


if [ -f README.md ]
then
	echo "README.md already exists! clean or backup it at first!"
	exit 1
fi

cat > README.md << EOF
# helloworld kernel module

* 功能： 待录入
* 创建时间： TIMESTAMP

---




---

EOF

TIMESTAMP=`date +"%Y-%m-%d %H:%M:%S"`

sed -i "s/helloworld/$1/g" src/Makefile
sed -i "s/helloworld/$1/g" "src/$1.c"
sed -i "s/helloworld/$1/g" README.md
sed -i "s/TIMESTAMP/${TIMESTAMP}/g" README.md

#[ -f gen.sh ] && rm -f gen.sh

echo "All done!"
