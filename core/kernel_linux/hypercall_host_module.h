#ifndef __HYPERCALL_HOST_MODULE_H_
#define __HYPERCALL_HOST_MODULE_H_

#include <linux/ioctl.h>

#define HYPERCALL_DEVICE_PATH "/dev/dynamorio_hypercall"

#define HYPERCALL_DEVICE_NAME "dynamorio_hypercall"

#define HYPERCALL_IOCTL_DEQUEUE _IOWR(0xFF, 0, hypercall_t*)

#define HYPERCALL_IOCTL_CLEAR _IO(0xFF, 1)

#endif
