#include "asm-generic/errno-base.h"
#include "linux/blk-mq.h"
#include "linux/container_of.h"
#include "linux/err.h"
#include "linux/fs.h"
#include "linux/gfp_types.h"
#include "linux/jiffies.h"
#include "linux/kobject.h"
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
#include "linux/string.h"
#include "linux/sysfs.h"
#include "linux/types.h"
#include "linux/uaccess.h"
#include "taskmonitor.h"
#include "linux/kernel.h"
#include "linux/init.h"
#include "linux/shrinker.h"

MODULE_DESCRIPTION("A module for monitoring a target task");
MODULE_AUTHOR("Jonas Dohmen");
MODULE_LICENSE("GPL");

struct task_monitor {
	struct pid *pid;
	struct task_struct *thread;
	struct mutex mutex;
	struct list_head samples;
	unsigned long sample_count;
	struct shrinker samples_shrinker;
	struct kmem_cache *samples_cache;
};

struct task_sample {
	u64 utime;
	u64 stime;
	unsigned long total;
	unsigned long data;
	unsigned long stack;
	struct list_head list;
};

// FORWARD DECLARATION AREA

static struct task_monitor *taskmonitor_new(void);
static void taskmonitor_free(struct task_monitor *);

static int taskmonitor_set_pid(struct task_monitor *, pid_t);
static void taskmonitor_unset_pid(struct task_monitor *);

static void taskmonitor_add_sample(struct task_monitor *, struct task_sample *);
static void taskmonitor_clear_samples(struct task_monitor *);
static void taskmonitor_free_sample(struct task_sample *);
static struct task_sample *taskmonitor_new_sample(struct task_monitor *);

static int taskmonitor_start(struct task_monitor *);
static void taskmonitor_stop(struct task_monitor *);
static int taskmonitor_threadfunc(void *);

// VARIABLE AREA

static int target_param; //the parameter to set pid at startup
static struct task_monitor *glob_taskmonitor;

// SYSFS AREA

static ssize_t sysfs_show_taskmonitor(struct kobject *, struct kobj_attribute *,
				      char *);
static ssize_t sysfs_store_taskmonitor(struct kobject *,
				       struct kobj_attribute *, const char *,
				       size_t);
static struct kobj_attribute taskmonitor_attr = __ATTR(
	taskmonitor, 0600, sysfs_show_taskmonitor, sysfs_store_taskmonitor);

// IOCTL AREA

static int major_number;
static long ioctl_call(struct file *, unsigned int, unsigned long);
static const struct file_operations taskmonitor_fops = { .owner = THIS_MODULE,
							 .unlocked_ioctl =
								 ioctl_call };

// SHRINKER AREA

static unsigned long taskmonitor_count_objects(struct shrinker *,
					       struct shrink_control *);
static unsigned long taskmonitor_scan_objects(struct shrinker *,
					      struct shrink_control *);

// FUNCTION AREA

static struct task_monitor *taskmonitor_new(void)
{
	struct task_monitor *tmp_taskmon;
	int err;

	tmp_taskmon = kzalloc(sizeof(struct task_monitor), GFP_KERNEL);
	if (!tmp_taskmon)
		return tmp_taskmon;

	mutex_init(&tmp_taskmon->mutex);
	INIT_LIST_HEAD(&tmp_taskmon->samples);

	tmp_taskmon->samples_shrinker.count_objects = taskmonitor_count_objects;
	tmp_taskmon->samples_shrinker.scan_objects = taskmonitor_scan_objects;
	tmp_taskmon->samples_shrinker.batch = 0;
	tmp_taskmon->samples_shrinker.seeks = DEFAULT_SEEKS;

	err = register_shrinker(&tmp_taskmon->samples_shrinker, "taskmonitor");
	if (err) {
		mutex_destroy(&tmp_taskmon->mutex);
		kfree(tmp_taskmon);
		return ERR_PTR(err);
	}

	tmp_taskmon->samples_cache =
		kmem_cache_create("task_sample", sizeof(struct task_sample),
				  __alignof__(struct task_sample), 0, NULL);
	if (!tmp_taskmon->samples_cache) {
		err = -ENOMEM;
		return ERR_PTR(err);
	}

	return tmp_taskmon;
}

static void taskmonitor_free(struct task_monitor *p_taskmonitor)
{
	taskmonitor_stop(p_taskmonitor);
	taskmonitor_unset_pid(p_taskmonitor);
	unregister_shrinker(&p_taskmonitor->samples_shrinker);
	kmem_cache_destroy(p_taskmonitor->samples_cache);
	mutex_destroy(&p_taskmonitor->mutex);
	kfree(p_taskmonitor);
}

static int taskmonitor_set_pid(struct task_monitor *p_taskmonitor,
			       pid_t p_pid_nr)
{
	struct pid *tmp_pid;
	bool restart = false;
	int err = 0;

	if (p_taskmonitor->thread)
		restart = true;

	tmp_pid = find_get_pid(p_pid_nr);
	if (IS_ERR(tmp_pid))
		return PTR_ERR(tmp_pid);

	if (!tmp_pid)
		return -EINVAL;

	taskmonitor_stop(p_taskmonitor);
	taskmonitor_unset_pid(p_taskmonitor);

	p_taskmonitor->pid = tmp_pid;

	if (restart) {
		err = taskmonitor_start(p_taskmonitor);
		if (err)
			return err;
	}

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
	mutex_lock(&p_taskmonitor->mutex);
	p_taskmonitor->sample_count++;
	list_add_tail(&p_sample->list, &p_taskmonitor->samples);
	mutex_unlock(&p_taskmonitor->mutex);
}

static void taskmonitor_clear_samples(struct task_monitor *p_taskmonitor)
{
	struct task_sample *sample, *tmp;
	mutex_lock(&p_taskmonitor->mutex);
	list_for_each_entry_safe(sample, tmp, &p_taskmonitor->samples, list) {
		list_del(&sample->list);
		taskmonitor_free_sample(sample);
		p_taskmonitor->sample_count--;
	}
	mutex_unlock(&p_taskmonitor->mutex);
}

static void taskmonitor_free_sample(struct task_sample *p_sample)
{
	kmem_cache_free(glob_taskmonitor->samples_cache, p_sample);
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

	ret = kmem_cache_alloc(p_taskmonitor->samples_cache, GFP_KERNEL);
	if (!ret)
		goto err_pid_alive;

	ret->utime = tmp_task->utime;
	ret->stime = tmp_task->stime;
	ret->total = tmp_task->mm->total_vm;
	ret->stack = tmp_task->mm->stack_vm;
	ret->data = tmp_task->mm->data_vm;

err_pid_alive:
	put_task_struct(tmp_task);
err_pid_task:
	return ret;
}

static int taskmonitor_start(struct task_monitor *p_taskmonitor)
{
	struct task_struct *tmp_thread;

	if (p_taskmonitor->thread)
		return 0; //Thread already running

	tmp_thread = kthread_create(taskmonitor_threadfunc, p_taskmonitor,
				    "taskmonitor_pid");
	if (IS_ERR(tmp_thread))
		return PTR_ERR(tmp_thread);

	get_task_struct(tmp_thread);
	wake_up_process(tmp_thread);

	p_taskmonitor->thread = tmp_thread;

	return 0;
}

static void taskmonitor_stop(struct task_monitor *p_taskmonitor)
{
	if (!p_taskmonitor->thread)
		return;

	kthread_stop(p_taskmonitor->thread);
	put_task_struct(p_taskmonitor->thread);
	p_taskmonitor->thread = NULL;
}

static int taskmonitor_threadfunc(void *arg)
{
	struct task_monitor *tmp_taskmonitor = arg;
	struct task_sample *tmp_sample;

	while (!kthread_should_stop()) {
		tmp_sample = taskmonitor_new_sample(tmp_taskmonitor);
		if (IS_ERR_OR_NULL(tmp_sample)) {
			taskmonitor_unset_pid(tmp_taskmonitor);
			return PTR_ERR(tmp_sample);
		}
		taskmonitor_add_sample(tmp_taskmonitor, tmp_sample);
		schedule_timeout_uninterruptible(msecs_to_jiffies(1000));
	}
	return 0;
}

static ssize_t sysfs_show_taskmonitor(struct kobject *p_kobject,
				      struct kobj_attribute *p_attr,
				      char *p_buf)
{
	int ret;
	int offset;
	int count = 0;
	struct task_monitor *tmp_mon = glob_taskmonitor;
	struct task_sample *tmp_sample;

	char *tmpBuf = kzalloc(PAGE_SIZE * sizeof(char), GFP_KERNEL);
	if (!tmpBuf) {
		pr_err("Not enough memory for buffer");
		return 0;
	}

	mutex_lock(&tmp_mon->mutex);

	list_for_each_entry_reverse(tmp_sample, &tmp_mon->samples, list) {
		ret = snprintf(
			tmpBuf, PAGE_SIZE,
			"pid %d usr %llu sys %llu vm_total %lu vm_stack %lu vm_data %lu\n",
			pid_nr(tmp_mon->pid), tmp_sample->utime,
			tmp_sample->stime, tmp_sample->total, tmp_sample->stack,
			tmp_sample->data);

		offset = count + ret;
		if (offset > PAGE_SIZE - 1) {
			break;
		}
		memcpy(p_buf + PAGE_SIZE - offset, tmpBuf, ret);
		count += ret;
	}

	memmove(p_buf, p_buf + PAGE_SIZE - count, count);
	p_buf[count] = '\0';

	mutex_unlock(&tmp_mon->mutex);
	kfree(tmpBuf);

	return count;
}

static ssize_t sysfs_store_taskmonitor(struct kobject *p_kobject,
				       struct kobj_attribute *p_attr,
				       const char *p_buf, size_t p_count)
{
	int err;
	struct task_monitor *tmp_taskmonitor = glob_taskmonitor;
	if (sysfs_streq(p_buf, "start")) {
		err = taskmonitor_start(tmp_taskmonitor);
		if (err)
			return err;

		return p_count;
	}

	if (sysfs_streq(p_buf, "stop")) {
		taskmonitor_stop(tmp_taskmonitor);
		return p_count;
	}

	return -EINVAL;
}

static long ioctl_call(struct file *p_file, unsigned int p_cmd,
		       unsigned long p_arg)
{
	int ret;
	pid_t pid;
	void __user *ptr = (void __user *)p_arg;
	struct task_monitor *tmp_taskmonitor = glob_taskmonitor;
	struct task_sample *tmp_sample;
	char *ret_buffer;

	switch (p_cmd) {
	case TM_START:
		return taskmonitor_start(tmp_taskmonitor);

	case TM_STOP:
		taskmonitor_stop(tmp_taskmonitor);
		return 0;

	case TM_GET:
		tmp_sample = taskmonitor_new_sample(tmp_taskmonitor);
		if (IS_ERR_OR_NULL(tmp_sample))
			return tmp_sample ? PTR_ERR(tmp_sample) : -EINVAL;

		ret_buffer = kzalloc(256 * sizeof(char), GFP_KERNEL);
		if (!ret_buffer) {
			taskmonitor_free_sample(tmp_sample);
			return 0;
		}

		sprintf(ret_buffer, "pid %d usr %llu sys %llu",
			pid_nr(tmp_taskmonitor->pid), tmp_sample->utime,
			tmp_sample->stime);

		ret = copy_to_user(ptr, ret_buffer, 256 * sizeof(char));
		taskmonitor_free_sample(tmp_sample);
		kfree(ret_buffer);
		return ret;

	case TM_PID:
		ret = copy_from_user(&pid, ptr, sizeof(pid));
		if (ret)
			return ret;

		if (pid < 0) {
			if (!tmp_taskmonitor->pid)
				return -EINVAL;

			pid = pid_nr(tmp_taskmonitor->pid);
			return copy_to_user(ptr, &pid, sizeof(pid));
		} else {
			return taskmonitor_set_pid(tmp_taskmonitor, pid);
		}

	default:
		return -ENOTTY;
	}
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
		taskmonitor_free_sample(sample);
		taskmonitor->sample_count--;
		count++;
	}

	mutex_unlock(&taskmonitor->mutex);

	return count;
}

module_param_named(target, target_param, int, 0660);

static int __init taskmonitor_init(void)
{
	int err;
	struct task_monitor *monitor;

	monitor = taskmonitor_new();
	if (IS_ERR(monitor))
		return PTR_ERR(monitor);

	glob_taskmonitor = monitor;

	if (target_param) {
		err = taskmonitor_set_pid(monitor, target_param);
		if (err)
			goto err_monitor;

		err = taskmonitor_start(monitor);
		if (err)
			goto err_monitor;
	}

	err = sysfs_create_file(kernel_kobj, &taskmonitor_attr.attr);
	pr_info("Sysfs result %d", err);
	if (err)
		goto err_monitor;

	major_number = register_chrdev(0, "taskmonitor", &taskmonitor_fops);
	if (major_number < 0) {
		err = major_number;
		goto err_chrdev;
	}
	pr_info("Major number is: %d\n", major_number);

	return 0;

err_chrdev:
	sysfs_remove_file(kernel_kobj, &taskmonitor_attr.attr);

err_monitor:
	taskmonitor_free(monitor);
	return err;
}

static void __exit taskmonitor_exit(void)
{
	unregister_chrdev(major_number, "taskmonitor");
	sysfs_remove_file(kernel_kobj, &taskmonitor_attr.attr);
	taskmonitor_free(glob_taskmonitor);
}

module_init(taskmonitor_init);
module_exit(taskmonitor_exit);