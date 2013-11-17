#ifndef __DYNAMORIO_CONTROLLER_MODULE_H_
#define __DYNAMORIO_CONTROLLER_MODULE_H_

#include <linux/ioctl.h>
#include "kernel_interface.h"

#define DYNAMORIO_DEVICE_PATH "/dev/dynamorio_controller"

#define DYNAMORIO_DEVICE_NAME "dynamorio_controller"

typedef struct {
    char options[KERNEL_ENV_VALUE_MAX];
} dynamorio_init_cmd_t;

#define DYNAMORIO_IOCTL_INIT _IOW(0xFF, 0, dynamorio_init_cmd_t *)

typedef struct {
} dynamorio_exit_cmd_t;

#define DYNAMORIO_IOCTL_EXIT _IOW(0xFF, 1, dynamorio_exit_cmd_t *)

#define DYNAMORIO_KSTATS_MAX_SIZE 4096*2LU

typedef struct {
    unsigned long size;
    /* beginning of variable sized array */
    char data;
} stats_buffer_t;

typedef struct {
    /* Input. */
    int cpu;
    /* Output. */
    stats_buffer_t buffer;
    char more_data[DYNAMORIO_KSTATS_MAX_SIZE];
} dynamorio_kstats_cmd_t;

#define DYNAMORIO_IOCTL_KSTATS _IOWR(0xff, 2, dynamorio_kstats_cmd_t *)

#define DYNAMORIO_STATS_MAX_SIZE 100*1024LU

typedef struct {
    /* Output. */
    stats_buffer_t buffer;
    char more_data[DYNAMORIO_STATS_MAX_SIZE];
} dynamorio_stats_cmd_t;

#define DYNAMORIO_IOCTL_STATS _IOWR(0xff, 3, dynamorio_stats_cmd_t *)


#endif
