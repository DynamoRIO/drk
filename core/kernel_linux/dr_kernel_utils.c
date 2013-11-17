#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include "dr_kernel_utils.h"
MODULE_LICENSE("Dual BSD/GPL");

int
dr_cpu_count(void)
{
    /* Keep this consistent with kernel_get_processor_count()! */
    return num_present_cpus();
}
EXPORT_SYMBOL_GPL(dr_cpu_count);

#define to_dr_stat(obj) container_of(obj, dr_stat_t, kobj)
#define to_dr_stat_attr(_attr) container_of(_attr, dr_stat_attr_t, attr)

static ssize_t
dr_stat_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
    dr_stat_t *stat = to_dr_stat(kobj);
    dr_stat_attr_t *stat_attr = to_dr_stat_attr(attr);
    return stat->show(stat_attr->cpu, buf);
}

static ssize_t
dr_stat_store(struct kobject *kobj, struct attribute *attr, const char *buf,
              size_t count)
{
    printk("store not supported for dr_stats\n");
    /* TODO(peter): Support updating stats? */
    return 0;
}

static struct sysfs_ops dr_stat_sysfs_ops = {
    .show = dr_stat_show,
    .store = dr_stat_store,
};

static void
dr_stat_release(struct kobject *kobj)
{
    dr_stat_t *stat = to_dr_stat(kobj);
    kfree(stat->attrs);
    kfree(stat);
}

static struct kobj_type dr_stat_ktype = {
    .release = dr_stat_release,
    .sysfs_ops = &dr_stat_sysfs_ops,
};

int
dr_cpu_stat_alloc(dr_stats_t *stats, const char* name,
                  dr_stat_show_t show, struct module *module)
{
    int i;
    int retval;
    dr_stat_t *stat = kzalloc(sizeof(dr_stat_t), GFP_ATOMIC);
    if (!stat) {
        return -ENOMEM;
    }
    stat->show = show;
    kobject_init(&stat->kobj, &dr_stat_ktype);
    retval = kobject_add(&stat->kobj, &module->mkobj.kobj, "%s", name);
    if (retval) {
        goto error_add;
    }
    stat->attrs = kmalloc(sizeof(dr_stat_attr_t) * num_possible_cpus(),
                          GFP_ATOMIC);
    if (!stat->attrs) {
        retval = -ENOMEM;
        goto error_attrs;
    }
    for (i = 0; i < dr_cpu_count(); i++) {
        stat->attrs[i].attr.name = stat->attrs[i].name_buffer;
        snprintf(stat->attrs[i].name_buffer, 10, "cpu%d", i);
        stat->attrs[i].attr.mode = 0444;
        stat->attrs[i].cpu = i;
        retval = sysfs_create_file(&stat->kobj, &stat->attrs[i].attr);
        if (retval) {
            goto error_sysfs;
        }
    }
    list_add_tail(&stat->list, &stats->list);
    return 0;
error_sysfs:
    kfree(stat->attrs);
error_attrs:
    kobject_put(&stat->kobj);
error_add:
    kfree(stat);
    return retval;
}
EXPORT_SYMBOL_GPL(dr_cpu_stat_alloc);

void
dr_stats_free(dr_stats_t *stats)
{
    while (!list_empty(&stats->list)) {
        dr_stat_t *stat = list_first_entry(&stats->list, dr_stat_t, list);
        list_del(&stat->list);
        kobject_put(&stat->kobj);
    }
}
EXPORT_SYMBOL_GPL(dr_stats_free);

int
dr_stats_init(dr_stats_t *stats)
{
    INIT_LIST_HEAD(&stats->list);
    return 0;
}
EXPORT_SYMBOL_GPL(dr_stats_init);
