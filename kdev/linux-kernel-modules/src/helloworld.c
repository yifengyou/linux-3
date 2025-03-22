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
