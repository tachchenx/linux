#include "asm-generic/errno-base.h"
#include "linux/blk-mq.h"
#include "linux/container_of.h"
#include "linux/dcache.h"
#include "linux/err.h"
#include "linux/fs.h"
#include "linux/gfp_types.h"
#include "linux/jiffies.h"
#include "linux/kobject.h"
#include "linux/kstrtox.h"
#include "linux/kthread.h"
#include "linux/list.h"
#include "linux/module.h"
#include "linux/moduleparam.h"
#include "linux/mutex.h"
#include "linux/pid.h"
#include "linux/printk.h"
#include "linux/sched.h"
#include "linux/sched/task.h"
#include "linux/slab.h"
#include "linux/stddef.h"
#include "linux/string.h"
#include "linux/types.h"
#include "linux/uaccess.h"
#include "taskmonitor.h"
#include "linux/kernel.h"
#include "linux/init.h"
#include "linux/shrinker.h"
#include "linux/mempool.h"
#include "linux/kref.h"
#include "linux/debugfs.h"
#include "linux/seq_file.h"

MODULE_DESCRIPTION("A module for monitoring a target task");
MODULE_AUTHOR("Jonas Dohmen");
MODULE_LICENSE("GPL");

struct taskmonitor_controller {
	struct dentry *root_dir;
	struct mutex mutex;
	struct list_head list;
};

struct task_monitor {
	struct pid *pid;
	struct mutex mutex;
	struct list_head samples;
	unsigned long sample_count;
	struct shrinker samples_shrinker;
	struct kmem_cache *samples_cache;
	mempool_t sample_pool;
	struct dentry *file;

	struct list_head list;
};

struct task_sample {
	pid_t pid;
	u64 utime;
	u64 stime;
	unsigned long total;
	unsigned long data;
	unsigned long stack;
	struct list_head list;
	struct kref ref;
	struct task_monitor *monitor;
};

// FORWARD DECLARATION AREA

static struct task_monitor *taskmonitor_new(const char *, struct dentry *);
static void taskmonitor_free(struct task_monitor *);

static int taskmonitor_set_pid(struct task_monitor *, pid_t);
static void taskmonitor_unset_pid(struct task_monitor *);

static void taskmonitor_add_sample(struct task_monitor *, struct task_sample *);
static void taskmonitor_clear_samples(struct task_monitor *);
static void taskmonitor_free_sample(struct task_sample *);
static struct task_sample *taskmonitor_new_sample(struct task_monitor *);

static int taskmonitor_threadfunc(void *);

// VARIABLE AREA

static struct taskmonitor_controller monitor_controller;
static struct task_struct *taskmonitor_thread;

// SHRINKER AREA

static unsigned long taskmonitor_count_objects(struct shrinker *,
					       struct shrink_control *);
static unsigned long taskmonitor_scan_objects(struct shrinker *,
					      struct shrink_control *);

// KREF AREA

static void taskmonitor_sample_release(struct kref *);
static void taskmonitor_sample_get(struct task_sample *);
static int taskmonitor_sample_put(struct task_sample *);

// SEQ_FILE AREA

static struct dentry *taskmonitor_debugfs_control;

static void *taskmonitor_seq_start(struct seq_file *, loff_t *);
static void *taskmonitor_seq_next(struct seq_file *, void *, loff_t *);
static void taskmonitor_seq_stop(struct seq_file *, void *);
static int taskmonitor_seq_show(struct seq_file *, void *);
static int taskmonitor_open(struct inode *, struct file *);

static ssize_t taskmonitor_control_write(struct file *, const char *, size_t,
					 loff_t *);

static const struct file_operations taskmonitor_debugfs_ops = {
	.owner = THIS_MODULE,
	.open = taskmonitor_open,
	.read = seq_read,
	.release = seq_release,
	.llseek = seq_lseek
};

static const struct seq_operations taskmonitor_seq_operations = {
	.start = taskmonitor_seq_start,
	.next = taskmonitor_seq_next,
	.stop = taskmonitor_seq_stop,
	.show = taskmonitor_seq_show,
};

static const struct file_operations taskmonitor_control_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = taskmonitor_control_write,
	.llseek = no_llseek,
};

// FUNCTION AREA

static struct task_monitor *taskmonitor_new(const char *p_pid_str,
					    struct dentry *p_dentry)
{
	struct task_monitor *tmp_taskmon;
	int err;
	pid_t tmp_pid;

	err = kstrtoint(p_pid_str, 0, &tmp_pid);
	if (err)
		goto err_no_allocs;

	tmp_taskmon = kzalloc(sizeof(struct task_monitor), GFP_KERNEL);
	if (!tmp_taskmon) {
		err = -ENOMEM;
		goto err_no_allocs;
	}

	mutex_init(&tmp_taskmon->mutex);
	INIT_LIST_HEAD(&tmp_taskmon->samples);

	tmp_taskmon->samples_shrinker.count_objects = taskmonitor_count_objects;
	tmp_taskmon->samples_shrinker.scan_objects = taskmonitor_scan_objects;
	tmp_taskmon->samples_shrinker.batch = 0;
	tmp_taskmon->samples_shrinker.seeks = DEFAULT_SEEKS;

	err = register_shrinker(&tmp_taskmon->samples_shrinker, "taskmonitor");
	if (err)
		goto err_shrinker;

	tmp_taskmon->samples_cache = KMEM_CACHE(task_sample, 0);
	if (!tmp_taskmon->samples_cache) {
		err = -ENOMEM;
		goto err_kmem;
	}

	err = mempool_init_slab_pool(&tmp_taskmon->sample_pool, 16,
				     tmp_taskmon->samples_cache);

	if (err)
		goto err_mempool;

	err = taskmonitor_set_pid(tmp_taskmon, tmp_pid);
	if (err)
		goto err_set_pid;

	tmp_taskmon->file = debugfs_create_file(p_pid_str, 0444, p_dentry,
						tmp_taskmon,
						&taskmonitor_debugfs_ops);
	if (IS_ERR(tmp_taskmon->file)) {
		err = PTR_ERR(tmp_taskmon->file);
		goto err_set_pid;
	}

	return tmp_taskmon;
err_set_pid:
	taskmonitor_unset_pid(tmp_taskmon);
	mempool_exit(&tmp_taskmon->sample_pool);
err_mempool:
	kmem_cache_destroy(tmp_taskmon->samples_cache);
err_kmem:
	unregister_shrinker(&tmp_taskmon->samples_shrinker);
err_shrinker:
	mutex_destroy(&tmp_taskmon->mutex);
	kfree(tmp_taskmon);
err_no_allocs:
	return ERR_PTR(err);
}

static void taskmonitor_free(struct task_monitor *p_taskmonitor)
{
	debugfs_remove(p_taskmonitor->file);
	taskmonitor_unset_pid(p_taskmonitor);
	unregister_shrinker(&p_taskmonitor->samples_shrinker);
	mempool_exit(&p_taskmonitor->sample_pool);
	kmem_cache_destroy(p_taskmonitor->samples_cache);
	mutex_destroy(&p_taskmonitor->mutex);
	kfree(p_taskmonitor);
}

static int taskmonitor_set_pid(struct task_monitor *p_taskmonitor,
			       pid_t p_pid_nr)
{
	struct pid *tmp_pid;

	tmp_pid = find_get_pid(p_pid_nr);
	if (IS_ERR(tmp_pid))
		return PTR_ERR(tmp_pid);

	if (!tmp_pid)
		return -EINVAL;

	taskmonitor_unset_pid(p_taskmonitor);

	p_taskmonitor->pid = tmp_pid;

	return 0;
}

static void taskmonitor_unset_pid(struct task_monitor *p_taskmonitor)
{
	if (p_taskmonitor->pid == NULL) {
		return;
	}

	put_pid(p_taskmonitor->pid);
	p_taskmonitor->pid = NULL;

	taskmonitor_clear_samples(p_taskmonitor);
}

static void taskmonitor_add_sample(struct task_monitor *p_taskmonitor,
				   struct task_sample *p_sample)
{
	taskmonitor_sample_get(p_sample);
	p_taskmonitor->sample_count++;
	list_add_tail(&p_sample->list, &p_taskmonitor->samples);
}

static void taskmonitor_clear_samples(struct task_monitor *p_taskmonitor)
{
	struct task_sample *sample, *tmp;
	mutex_lock(&p_taskmonitor->mutex);
	list_for_each_entry_safe(sample, tmp, &p_taskmonitor->samples, list) {
		list_del(&sample->list);
		taskmonitor_sample_put(sample);
		p_taskmonitor->sample_count--;
	}
	mutex_unlock(&p_taskmonitor->mutex);
}

static void taskmonitor_free_sample(struct task_sample *p_sample)
{
	mempool_free(p_sample, &p_sample->monitor->sample_pool);
}

static struct task_sample *
taskmonitor_new_sample(struct task_monitor *p_taskmonitor)
{
	struct task_sample *ret = NULL;
	struct task_struct *tmp_task;

	tmp_task = get_pid_task(p_taskmonitor->pid, PIDTYPE_PID);
	if (IS_ERR_OR_NULL(tmp_task)) {
		ret = ERR_CAST(tmp_task);
		goto err_pid_task;
	}

	if (!pid_alive(tmp_task))
		goto err_pid_alive;

	ret = mempool_alloc(&p_taskmonitor->sample_pool, GFP_KERNEL);
	if (!ret)
		goto err_pid_alive;

	memset(ret, 0, sizeof(struct task_sample));

	ret->pid = pid_nr(p_taskmonitor->pid);
	ret->utime = tmp_task->utime;
	ret->stime = tmp_task->stime;
	if (tmp_task->mm) {
		ret->total = tmp_task->mm->total_vm;
		ret->stack = tmp_task->mm->stack_vm;
		ret->data = tmp_task->mm->data_vm;
	}

	ret->monitor = p_taskmonitor;

	kref_init(&ret->ref);

err_pid_alive:
	put_task_struct(tmp_task);
err_pid_task:
	return ret;
}

static int taskmonitor_threadfunc(void *arg)
{
	struct taskmonitor_controller *tmp_controler = arg;
	struct task_monitor *tmp_taskmonitor, *tmp_next;
	struct task_sample *tmp_sample;

	while (!kthread_should_stop()) {
		mutex_lock(&tmp_controler->mutex);

		list_for_each_entry_safe(tmp_taskmonitor, tmp_next,
					 &tmp_controler->list, list) {
			tmp_sample = taskmonitor_new_sample(tmp_taskmonitor);
			if (IS_ERR_OR_NULL(tmp_sample)) {
				list_del(&tmp_taskmonitor->list);
				continue;
			}

			mutex_lock(&tmp_taskmonitor->mutex);
			taskmonitor_add_sample(tmp_taskmonitor, tmp_sample);
			mutex_unlock(&tmp_taskmonitor->mutex);

			taskmonitor_sample_put(tmp_sample);
		}

		mutex_unlock(&tmp_controler->mutex);

		// tmp_sample = taskmonitor_new_sample(tmp_taskmonitor);
		// if (IS_ERR_OR_NULL(tmp_sample)) {
		// 	taskmonitor_unset_pid(tmp_taskmonitor);
		// 	return PTR_ERR(tmp_sample);
		// }
		// taskmonitor_add_sample(tmp_taskmonitor, tmp_sample);
		// taskmonitor_sample_put(tmp_sample);
		schedule_timeout_uninterruptible(msecs_to_jiffies(1000));
	}

	list_for_each_entry_safe(tmp_taskmonitor, tmp_next,
				 &tmp_controler->list, list) {
		mutex_lock(&tmp_taskmonitor->mutex);
		list_del(&tmp_taskmonitor->list);
		mutex_unlock(&tmp_taskmonitor->mutex);
		taskmonitor_free(tmp_taskmonitor);
	}

	return 0;
}

static unsigned long taskmonitor_count_objects(struct shrinker *p_sh,
					       struct shrink_control *p_sc)
{
	struct task_monitor *taskmonitor =
		container_of(p_sh, struct task_monitor, samples_shrinker);
	unsigned long count;

	mutex_lock(&taskmonitor->mutex);
	count = taskmonitor->sample_count ? taskmonitor->sample_count :
					    SHRINK_EMPTY;
	mutex_unlock(&taskmonitor->mutex);

	return count;
}

static unsigned long taskmonitor_scan_objects(struct shrinker *p_sh,
					      struct shrink_control *p_sc)
{
	struct task_monitor *taskmonitor =
		container_of(p_sh, struct task_monitor, samples_shrinker);
	struct task_sample *sample, *next;
	unsigned long count = 0;

	if (!mutex_trylock(&taskmonitor->mutex))
		return SHRINK_STOP;

	list_for_each_entry_safe(sample, next, &taskmonitor->samples, list) {
		if (p_sc->nr_to_scan-- == 0)
			break;

		list_del(&sample->list);
		taskmonitor_sample_put(sample);
		taskmonitor->sample_count--;
		count++;
	}

	mutex_unlock(&taskmonitor->mutex);

	return count;
}

static void taskmonitor_sample_release(struct kref *p_kref)
{
	struct task_sample *sample =
		container_of(p_kref, struct task_sample, ref);

	taskmonitor_free_sample(sample);
}

static void taskmonitor_sample_get(struct task_sample *p_sample)
{
	kref_get(&p_sample->ref);
}

static int taskmonitor_sample_put(struct task_sample *p_sample)
{
	return kref_put(&p_sample->ref, taskmonitor_sample_release);
}

static void *taskmonitor_seq_start(struct seq_file *p_file, loff_t *p_position)
{
	struct task_monitor *tmp_taskmonitor = p_file->private;
	struct task_sample *tmp_sample;
	unsigned long position = *p_position;

	mutex_lock(&tmp_taskmonitor->mutex);
	list_for_each_entry(tmp_sample, &tmp_taskmonitor->samples, list) {
		if (!position--)
			return tmp_sample;
	}

	mutex_unlock(&tmp_taskmonitor->mutex);

	return NULL;
}
static void *taskmonitor_seq_next(struct seq_file *p_file, void *p_void,
				  loff_t *p_position)
{
	struct task_monitor *tmp_taskmonitor = p_file->private;
	struct task_sample *tmp_sample = (struct task_sample *)p_void;

	*p_position += 1;

	if (list_is_last(&tmp_sample->list, &tmp_taskmonitor->samples))
		return NULL;

	return list_next_entry(tmp_sample, list);
}

static void taskmonitor_seq_stop(struct seq_file *p_file, void *p_void)
{
	struct task_monitor *tmp_taskmonitor = p_file->private;

	mutex_unlock(&tmp_taskmonitor->mutex);
}

static int taskmonitor_seq_show(struct seq_file *p_file, void *p_void)
{
	struct task_sample *tmp_sample = (struct task_sample *)p_void;

	seq_printf(
		p_file,
		"pid %d usr %llu sys %llu vm_total %lu vm_stack %lu vm_data %lu\n",
		tmp_sample->pid, tmp_sample->utime, tmp_sample->stime,
		tmp_sample->total, tmp_sample->stack, tmp_sample->data);
	return 0;
}

static int taskmonitor_open(struct inode *p_inode, struct file *p_file)
{
	int ret;
	struct seq_file *seq;

	ret = seq_open(p_file, &taskmonitor_seq_operations);
	if (ret)
		return ret;

	seq = (struct seq_file *)p_file->private_data;
	seq->private = p_inode->i_private;

	return 0;
}

static ssize_t taskmonitor_control_write(struct file *file, const char *buf,
					 size_t len, loff_t *off)
{
	ssize_t ret;
	struct taskmonitor_controller *tmp_controller = file->private_data;
	struct task_monitor *tmp_monitor, *tmp_next;
	char *pid_string;
	pid_t pid;

	pid_string = memdup_user_nul(buf, len);
	if (IS_ERR(pid_string)) {
		ret = PTR_ERR(pid_string);
		goto err_usr_str;
	}

	ret = kstrtoint(pid_string, 0, &pid);
	if (ret)
		goto err_str_to_int;

	mutex_lock(&tmp_controller->mutex);

	if (pid > 0) {
		tmp_monitor = taskmonitor_new(strim(pid_string),
					      tmp_controller->root_dir);
		if (IS_ERR(tmp_monitor)) {
			ret = PTR_ERR(tmp_controller);
			goto err_new_taskmon;
		}

		list_add(&tmp_monitor->list, &tmp_controller->list);

		ret = len;
	} else {
		ret = -EINVAL;
		list_for_each_entry_safe(tmp_monitor, tmp_next,
					 &tmp_controller->list, list) {
			if (pid_nr(tmp_monitor->pid) == -pid) {
				list_del(&tmp_monitor->list);
				taskmonitor_free(tmp_monitor);
				ret = len;
				break;
			}
		}
	}

err_new_taskmon:
	mutex_unlock(&tmp_controller->mutex);

err_str_to_int:
	kfree(pid_string);

err_usr_str:
	return ret;
}

static int __init taskmonitor_init(void)
{
	int err;

	mutex_init(&monitor_controller.mutex);
	INIT_LIST_HEAD(&monitor_controller.list);

	monitor_controller.root_dir = debugfs_create_dir("taskmonitor", NULL);
	if (IS_ERR(monitor_controller.root_dir)) {
		err = PTR_ERR(monitor_controller.root_dir);
		goto err_debugfs;
	}

	taskmonitor_thread = kthread_run(taskmonitor_threadfunc,
					 &monitor_controller, "taskmonitor");
	if (IS_ERR(taskmonitor_thread)) {
		err = PTR_ERR(taskmonitor_thread);
		goto err_thread;
	}

	taskmonitor_debugfs_control = debugfs_create_file(
		"control", 0444, monitor_controller.root_dir,
		&monitor_controller, &taskmonitor_control_fops);
	if (IS_ERR(taskmonitor_debugfs_control)) {
		err = PTR_ERR(taskmonitor_debugfs_control);
		goto err_debugfs_file;
	}

	return 0;

err_debugfs_file:
	kthread_stop(taskmonitor_thread);

err_thread:
	debugfs_remove(monitor_controller.root_dir);

err_debugfs:
	mutex_destroy(&monitor_controller.mutex);
	return err;
}

static void __exit taskmonitor_exit(void)
{
	debugfs_remove(taskmonitor_debugfs_control);
	kthread_stop(taskmonitor_thread);
	debugfs_remove(monitor_controller.root_dir);
	mutex_destroy(&monitor_controller.mutex);
}

module_init(taskmonitor_init);
module_exit(taskmonitor_exit);