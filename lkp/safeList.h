#include "asm-generic/errno-base.h"
#include "linux/list.h"
#include "linux/mutex.h"
#include "linux/types.h"

// static void ts_list_add(struct list_head *new, struct list_head *head, struct mutex* mutex)
// {
//     mutex_lock(mutex);
//     list_add(new, head);
//     mutex_unlock(mutex);
// }

static void ts_list_add_tail(struct list_head *head, struct list_head *new,
			     struct mutex *mutex)
{
	mutex_lock(mutex);
	list_add_tail(new, head);
	mutex_unlock(mutex);
}

// static void ts_list_del (struct list_head* item, struct mutex* mutex)
// {
//     mutex_lock(mutex);
//     list_del(item);
//     mutex_unlock(mutex);
// }
