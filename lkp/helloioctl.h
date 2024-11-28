#ifndef HELLOIOCTL_H
#define HELLOIOCTL_H

#include <linux/ioctl.h>

#define IOCTL_TYPE 'N'                // 'N' is the type for this ioctl
#define HELLO _IOR(IOCTL_TYPE, 1, char*)

#endif
