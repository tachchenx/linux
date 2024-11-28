#include "asm-generic/errno-base.h"
#include "asm/page_types.h"
#include "linux/gfp_types.h"
#include "linux/init.h"
#include "linux/kobject.h"
#include "linux/printk.h"
#include "linux/slab.h"
#include "linux/types.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysfs.h>

MODULE_DESCRIPTION("A sysfs module");
MODULE_AUTHOR("Jonas Dohmen");
MODULE_LICENSE("GPL");

static ssize_t show_hello(struct kobject *, struct kobj_attribute *, char *);
static ssize_t store_hello(struct kobject *kobj, struct kobj_attribute *attr,
			   const char *buf, size_t count);

static struct kobj_attribute myAttr =
	__ATTR(hello, 0600, show_hello, store_hello);

static char *name;

static int __init hellosysfs_init(void)
{
	name = kmalloc(strlen("sysfs") + 1, GFP_KERNEL);
	if (!name) {
		return -ENOMEM;
	}
	strcpy(name, "sysfs");

	int retval;

	retval = sysfs_create_file(kernel_kobj, &myAttr.attr);
	if (retval)
		goto error_init2;

	return 0;

error_init2:
	return -ENOMEM;
}

static void __exit hellosysfs_exit(void)
{
	sysfs_remove_file(kernel_kobj, &myAttr.attr);
}

static ssize_t show_hello(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	return snprintf(buf, PAGE_SIZE, "Hello %s!\n", name);
}

static ssize_t store_hello(struct kobject *kobj, struct kobj_attribute *attr,
			   const char *buf, size_t count)
{
	char *temp;
	temp = kmalloc(sizeof(buf) + 1, GFP_KERNEL);
	if (!temp) {
		pr_err("Could not get memeory for new name");
		return -ENOMEM;
	}

	strcpy(temp, buf);
	kfree(name);
	name = temp;
	return count;
}

module_exit(hellosysfs_exit);
module_init(hellosysfs_init);
