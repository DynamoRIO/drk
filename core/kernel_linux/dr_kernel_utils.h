#ifndef __KERNEL_UTIL_H_
#define __KERNEL_UTIL_H_

#include <linux/module.h>

typedef ssize_t	(*dr_stat_show_t)(int cpu, char *buf);

typedef struct dr_stat_attr {
    struct attribute attr;
    char name_buffer[10];
    int cpu;
} dr_stat_attr_t;

typedef struct {
    struct kobject kobj;
    dr_stat_attr_t *attrs;
    dr_stat_show_t show;
    struct list_head list;
} dr_stat_t;

typedef struct {
    struct list_head list;
} dr_stats_t;

int
dr_stats_init(dr_stats_t* stats);

/* Can only be called during module initilization routines. */
int
dr_cpu_stat_alloc(dr_stats_t *stats, const char* name,
                  dr_stat_show_t show, struct module *module);

void
dr_stats_free(dr_stats_t *stat);

int
dr_cpu_count(void);

#endif
