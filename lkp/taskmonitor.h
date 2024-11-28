#ifndef TASKMONIOCTL_H
#define TASKMONIOCTL_H

#include <linux/ioctl.h>

#define IOCTL_TYPE 'N'                // 'N' is the type for this ioctl
#define TM_STOP _IO(IOCTL_TYPE, 1)
#define TM_START _IO(IOCTL_TYPE, 2)
#define TM_GET _IOR(IOCTL_TYPE, 3, char*)
#define TM_PID _IOWR(IOCTL_TYPE, 4, pid_t)

#endif
