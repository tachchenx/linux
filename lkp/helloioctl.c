#include "linux/fs.h"
#include "linux/init.h"
#include "linux/printk.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/ioctl.h>
#include <linux/stat.h>
#include <linux/uaccess.h>

#include "helloioctl.h"

MODULE_DESCRIPTION("A ioctl module");
MODULE_AUTHOR("Jonas Dohmen");
MODULE_LICENSE("GPL");

static int majorNumber;
static char *name = "hello";
static char msg[] = "Hello ioctl!";

static long hello_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case HELLO:
		if (copy_to_user((char __user *)arg, msg, sizeof(msg))) {
			return -EFAULT;
		}
		return 0;

	default:
		return -ENOTTY;
	}
}

static const struct file_operations fops = { .owner = THIS_MODULE,
					     .unlocked_ioctl = hello_ioctl };

static int __init helloioctl_init(void)
{
	majorNumber = register_chrdev(0, name, &fops);

	if (majorNumber < 0) {
		pr_err("Failed to register character device \n");
		return -1;
	}

	pr_info("Major number is: %d and name is %s\n", majorNumber, name);

	return 0;
}

static void __exit helloioctl_exit(void)
{
	unregister_chrdev(majorNumber, name);
	pr_info("helloioctl unloaded\n");
}

module_init(helloioctl_init);
module_exit(helloioctl_exit);