#include "asm-generic/errno-base.h"
#include "asm/page_types.h"
#include "linux/gfp_types.h"
#include "linux/init.h"
#include "linux/kobject.h"
#include "linux/kthread.h"
#include "linux/module.h"
#include "linux/moduleparam.h"
#include "linux/pid.h"
#include "linux/printk.h"
#include "linux/sched.h"
#include "linux/sched/stat.h"
#include "linux/sched/task.h"
#include "linux/slab.h"
#include "linux/stddef.h"
#include "linux/sysfs.h"
#include "linux/types.h"

MODULE_DESCRIPTION("A module for monitoring a target task");
MODULE_AUTHOR("Jonas Dohmen");
MODULE_LICENSE("GPL");

struct task_monitor {
	struct pid *myPid;
};

//Task4 stuff
static int target = -1;
static struct pid *myPid;
struct task_monitor *myTM;
static struct task_struct *myTaskStruct;
static struct task_struct *myThread;
static int thread_error;

//Task5 stuff

struct task_sample {
	u64 utime;
	u64 stime;
} mySample;
static ssize_t show_taskmonitor(struct kobject *, struct kobj_attribute *,
				char *);
static ssize_t store_taskmonitor(struct kobject *, struct kobj_attribute *,
				 const char *, size_t);
static struct kobj_attribute myAttr =
	__ATTR(taskmonitor, 0600, show_taskmonitor, store_taskmonitor);
static bool threadRunning;

module_param(target, int, 0660);

int monitor_pid(pid_t pid)
{
	struct pid *tmp_pid;

	// Find the struct pid for the given pid
	tmp_pid = find_get_pid(pid);
	if (!tmp_pid) {
		pr_err("No process with the given id (%d) exists\n", pid);
		return -ESRCH;
	}

	// Allocate memory for the task_monitor struct
	myTM = (struct task_monitor *)kmalloc(sizeof(struct task_monitor),
					      GFP_KERNEL);
	if (!myTM) {
		pr_err("Could not allocate memory for task_monitor\n");
		put_pid(tmp_pid); // Release the struct pid reference
		return -ENOMEM; // Return standard error code for "Memory allocation failed"
	}

	// Initialize the task_monitor struct
	myTM->myPid = tmp_pid;
	myTaskStruct = get_pid_task(myTM->myPid, PIDTYPE_PID);
	if (!myTaskStruct) {
		pr_err("Could not get task struct\n");
		put_pid(tmp_pid);
		kfree(myTM);
		return -EINVAL;
	}

	//pr_info("Monitoring process with id %d\n", pid);
	return 0;
}

int monitor_fn(void *arg)
{
	while (!kthread_should_stop()) {
		if (pid_alive(myTaskStruct)) {
			mySample.stime = myTaskStruct->stime;
			mySample.utime = myTaskStruct->stime;
			pr_info("pid %d usr %llu sys %llu\n", target,
				mySample.utime, mySample.stime);
		} else {
			pr_err("PID no longer alive\n");
			thread_error = -EINVAL;
			threadRunning = false;
			break;
		}
		set_current_state(
			TASK_UNINTERRUPTIBLE); // Mark the thread as interruptible
		schedule_timeout(msecs_to_jiffies(1000));
	}

	return thread_error;
}

static int startMonThread(void)
{
	myThread = kthread_run(monitor_fn, NULL, "my_thread");
	if (IS_ERR(myThread)) {
		pr_err("Failed to create thread\n");
		return PTR_ERR(myThread);
	}
	threadRunning = true;
	return 0;
}

static ssize_t show_taskmonitor(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	if (pid_alive(myTaskStruct) && !threadRunning) {
		mySample.stime = myTaskStruct->stime;
		mySample.utime = myTaskStruct->stime;
	}
	return snprintf(buf, PAGE_SIZE, "pid %d usr %llu sys %llu\n", target,
			mySample.utime, mySample.stime);
}

static ssize_t store_taskmonitor(struct kobject *kobj,
				 struct kobj_attribute *attr, const char *buf,
				 size_t count)
{
	if (strcmp(buf, "start") == 0) {
		if (threadRunning) {
			//pr_info("Thread running already\n");
		} else {
			pr_info("starting monitor thread\n");
			startMonThread();
		}
	} else if (strcmp(buf, "stop") == 0) {
		if (threadRunning) {
			pr_info("halting monitor thread\n");
			kthread_stop(myThread);
			threadRunning = false;
		} else {
			//pr_info("Already dead\n");
		}

	} else {
		//pr_info("The hec ?\n");
	}
	return count;
}

static int __init taskmonitor_init(void)
{
	if (target == -1) {
		pr_err("No process id given, exiting\n");
		return -EINVAL;
	}

	if (monitor_pid(target)) {
		pr_err("We got a problem here\n");
		return -EINVAL;
	}

	//pr_info("Yay, the process exists, let's monitor\n");

	myThread = kthread_run(monitor_fn, NULL, "my_thread");
	if (IS_ERR(myThread)) {
		pr_err("Failed to create thread\n");
		return PTR_ERR(myThread);
	}
	threadRunning = true;
	// mykobject = kobject_create_and_add("taskmonitor", kernel_kobj);
	// if(!mykobject) {
	//     return -ENOMEM;
	// }

	if (sysfs_create_file(kernel_kobj, &myAttr.attr)) {
		//kobject_put(mykobject);
		pr_err("Failed to create sysfs file\n");
		return -ENOMEM;
	}

	return 0;
}

static void __exit taskmonitor_exit(void)
{
	if (myThread && threadRunning) {
		kthread_stop(myThread);
		//pr_info("Killed thread\n");
	}
	if (myTM) {
		if (myTM->myPid) {
			put_pid(myPid);
			//pr_info("Puting away myPid inside myTM\n");
		}
		kfree(myTM);
		//pr_info("Puting away myTM\n");
	}
	if (myTaskStruct) {
		put_task_struct(myTaskStruct);
		//pr_info("Cleaning task_struct");
	}
	//kobject_put(mykobject);
	sysfs_remove_file(kernel_kobj, &myAttr.attr);
	//pr_info("Unloading taskmonitor module");
}

module_init(taskmonitor_init);
module_exit(taskmonitor_exit);
