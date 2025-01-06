#include "asm-generic/errno-base.h"
#include "linux/err.h"
#include "linux/gfp_types.h"
#include "linux/limits.h"
#include "linux/printk.h"
#include "linux/rculist_bl.h"
#include "linux/rcupdate.h"
#include "linux/seq_file.h"
#include "linux/slab.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/dcache.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jonas Dohmen <jonas.dohmen@rwth-aachen.de>");
MODULE_DESCRIPTION("Totally legit linux kernel module weasel");
MODULE_VERSION("1.0");

// ### FORWARD AREA
static int print_dentry_stats(struct seq_file *file, void *v);
static int print_whoami(struct seq_file *file, void *v);
static int print_dcache(struct seq_file *file, void *v);
static int print_pwd(struct seq_file *file, void *v);

// ## VARIABLE AREA

static struct proc_dir_entry *weasel_dir;
static struct proc_dir_entry *weasle_whoami_file;
static struct proc_dir_entry *weasle_info_file;
static struct proc_dir_entry *weasle_dcache_file;
static struct proc_dir_entry *weasle_pwd_file;

// ### FUNCTION AREA

static int print_dentry_stats(struct seq_file *file, void *v)
{
	unsigned int n_buckets = 1 << (32 - d_hash_shift);
	unsigned int n_entries;
	unsigned int n_entries_total = 0;
	unsigned int n_entries_max = 0;

	struct dentry *myDentry;
	struct hlist_bl_node *myNode;

	rcu_read_lock();

	for (int bucket_idx = 0; bucket_idx < n_buckets; bucket_idx++) {
		n_entries = 0;
		hlist_bl_for_each_entry_rcu(myDentry, myNode,
					    &dentry_hashtable[bucket_idx],
					    d_hash) {
			n_entries++;
		}

		n_entries_total += n_entries;

		if (n_entries > n_entries_max)
			n_entries_max = n_entries;
	}

	rcu_read_unlock();

	seq_printf(file,
		   "address: 0x%px\n"
		   "size: %u\n"
		   "entries: %u\n"
		   "longest: %u\n",
		   dentry_hashtable, n_buckets, n_entries_total, n_entries_max);
	return 0;
}

static int print_whoami(struct seq_file *file, void *v)
{
	seq_printf(file, "I'm a weasel!\n");
	return 0;
}

static int print_dcache(struct seq_file *file, void *v)
{
	unsigned int n_buckets = 1 << (32 - d_hash_shift);
	struct dentry *my_dentry;
	struct hlist_bl_node *my_node;

	char *dentry_path, *buf;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	rcu_read_lock();

	for (unsigned int bucket_idx = 0; bucket_idx < n_buckets;
	     bucket_idx++) {
		hlist_bl_for_each_entry_rcu(my_dentry, my_node,
					    &dentry_hashtable[bucket_idx],
					    d_hash) {
			dentry_path = dentry_path_raw(my_dentry, buf, PATH_MAX);
			if (IS_ERR(dentry_path)) {
				continue;
			}

			seq_printf(file, "%s\n", dentry_path);
		}
	}

	rcu_read_unlock();
	kfree(buf);
	return 0;
}

static int print_pwd(struct seq_file *file, void *v)
{
	unsigned int n_buckets = 1 << (32 - d_hash_shift);
	struct dentry *my_dentry;
	struct hlist_bl_node *my_node;

	char *dentry_path, *buf;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	rcu_read_lock();

	for (unsigned int bucket_idx = 0; bucket_idx < n_buckets;
	     bucket_idx++) {
		hlist_bl_for_each_entry_rcu(my_dentry, my_node,
					    &dentry_hashtable[bucket_idx],
					    d_hash) {
			dentry_path = dentry_path_raw(my_dentry, buf, PATH_MAX);
			if (IS_ERR(dentry_path))
				continue;
			if (my_dentry->d_inode)
				continue;

			seq_printf(file, "%s\n", dentry_path);
		}
	}

	rcu_read_unlock();
	kfree(buf);
	return 0;
}

static int __init weasel_init(void)
{
	int ret = 0;

	weasel_dir = proc_mkdir("weasel", NULL);
	if (!weasel_dir) {
		pr_err("Could not create weasel directory\n");
		ret = -ENOMEM;
		goto err_mkdir;
	}

	weasle_whoami_file =
		proc_create_single("whoami", 0444, weasel_dir, print_whoami);
	if (!weasle_whoami_file) {
		pr_err("Could not create whoami file\n");
		ret = -ENOMEM;
		goto err_whoami;
	}

	weasle_info_file = proc_create_single("info", 0444, weasel_dir,
					      print_dentry_stats);
	if (!weasle_info_file) {
		pr_err("Could not create info file\n");
		ret = -ENOMEM;
		goto err_info;
	}

	weasle_dcache_file =
		proc_create_single("dcache", 0444, weasel_dir, print_dcache);
	if (!weasle_dcache_file) {
		pr_err("Could not create dcache file\n");
		ret = -ENOMEM;
		goto err_dcache;
	}

	weasle_pwd_file =
		proc_create_single("pwd", 0444, weasel_dir, print_pwd);
	if (!weasle_pwd_file) {
		pr_err("Could not create pwd file\n");
		ret = -ENOMEM;
		goto err_pwd;
	}

	return 0;
err_pwd:
	remove_proc_entry("dcache", weasel_dir);
err_dcache:
	remove_proc_entry("info", weasel_dir);
err_info:
	remove_proc_entry("whoami", weasel_dir);
err_whoami:
	remove_proc_entry("weasel", NULL);
err_mkdir:
	return ret;
}

static void __exit weasel_exit(void)
{
	remove_proc_entry("whoami", weasel_dir);
	remove_proc_entry("info", weasel_dir);
	remove_proc_entry("dcache", weasel_dir);
	remove_proc_entry("pwd", weasel_dir);
	remove_proc_entry("weasel", NULL);

	pr_info("weasel: Module unloaded successfully!\n");
}

module_init(weasel_init);
module_exit(weasel_exit);
