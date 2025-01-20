#include "asm-generic/errno-base.h"
#include "asm/syscall_wrapper.h"
#include "linux/gfp_types.h"
#include "linux/kern_levels.h"
#include "linux/printk.h"
#include "linux/slab.h"
#include "linux/uaccess.h"
#include <linux/kernel.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE4(hello, char __user *, who, int, who_size, char __user *, buffer,
		int, buffer_size)
{
	int err;
	if (who_size <= 0 || buffer_size <= 0) {
		err = -EINVAL;
		goto err_kern_who;
	}

	char *kern_who = kzalloc((who_size + 1) * sizeof(char), GFP_KERNEL);
	if (!kern_who) {
		err = -ENOMEM;
		goto err_kern_who;
	}

	char *kern_buf = kzalloc(buffer_size * sizeof(char), GFP_KERNEL);
	if (!kern_buf) {
		err = -ENOMEM;
		goto err_kern_buf;
	}

	int ans = copy_from_user(kern_who, who, who_size * sizeof(char));
	if (ans != 0) {
		printk(KERN_ERR "Failed to copy \'WHO\' from userspace\n");
		err = -EFAULT;
		goto err_cfu;
	}

	ans = snprintf(kern_buf, buffer_size, "Hello %s!\n", kern_who);
	if (ans < 0) {
		printk(KERN_ERR "Failed to write return buffer content\n");
		err = -EFAULT;
		goto err_cfu;
	}

	ans = copy_to_user(buffer, kern_buf, buffer_size);
	if (ans != 0) {
		printk(KERN_ERR "Failed to copy return string to userspace\n");
		err = -EFAULT;
		goto err_cfu;
	}

	ans = strlen(kern_buf);
	kfree(kern_buf);
	kfree(kern_who);
	return ans;

err_cfu:
	kfree(kern_buf);
err_kern_buf:
	kfree(kern_who);
err_kern_who:
	return err;
}