#include <linux/percpu.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/sched.h>
#include "dynamorio_controller_module.h"
#include "dynamorio_module_interface.h"
#include "simple_tests.h"
MODULE_LICENSE("Dual BSD/GPL");

static int device_major;
static bool initialized = false;
static bool exited = false;
static dr_exports_t dr_exports;
DEFINE_PER_CPU(dr_cpu_exports_t, dr_cpu_exports);

static void
smp_init_and_takeover(void* info)
{
    printk("init and takeover\n");
    dr_smp_init(&get_cpu_var(dr_cpu_exports));
    dynamorio_app_take_over();
    run_tests();
}

static void
smp_exit(void *info)
{
    dr_smp_exit();
}

static int
init_ioctl(struct inode* inode, struct file* file,
           unsigned int ioctl_num, unsigned long ioctl_param)
{
    dynamorio_init_cmd_t cmd;
    if (initialized) {
        printk("Module already initialized. You can't initialize it twice "
               "because the .data segment is only initialized when the "
               "module is loaded. Use the exit command then reload it.\n");
        return -EPERM;
    }
    if (copy_from_user(&cmd, (void*) ioctl_param, sizeof(cmd)) != 0) {
        printk("Could not copy options from userspace.\n");
        return -EINVAL;
    }
    #if 0
    if (num_present_cpus() != num_online_cpus()) {
        /* We require all CPUs to be online because we use on_each_cpu, which
         * calls smp_init_and_takeover only on online CPUs. */
        printk("There are %d present cpus, however only %d of them are online."
               " All present CPUs must be online during initilization. See"
               " /sys/devices/system/cpu/ to enable CPUs.\n",
               num_present_cpus(), num_online_cpus());
        return -EPERM;
    }
    #endif
    initialized = true;
    dr_pre_smp_init(&dr_exports, cmd.options);
    on_each_cpu(smp_init_and_takeover, NULL, false /* wait */);
    /* We will return here on the calling CPU, but it will be under DR's
     * control. */
    return 0;
}

static int
exit_ioctl(struct inode* inode, struct file* file,
           unsigned int ioctl_num, unsigned long ioctl_param)
{
    dynamorio_exit_cmd_t cmd;
    if (!initialized) {
        printk("Module is not yet initialized.\n");
        return -EPERM;
    }
    if (exited) {
        printk("Module already exited.\n");
        return -EPERM;
    }
    if (copy_from_user(&cmd, (void*) ioctl_param, sizeof(cmd)) != 0) {
        printk("Could not copy options from userspace.\n");
        return -EINVAL;
    }
    exited = true;
    on_each_cpu(smp_exit, NULL, false /* wait */);
    /* We will return here on the calling CPU under native control. */
    return 0;
}

static int
copy_export_to_user(void *data, unsigned long size, unsigned long max_size,
                    stats_buffer_t *buffer)
{
    if (size > max_size) {
        printk("User buffer is too small (%luB) to hold kstats (%luB).\n", 
               max_size, size);
        return -EINVAL;
    }
    if (copy_to_user(&buffer->data, data, size)) {
        printk("Could not copy data to the user-supplied buffer %p.\n",
               &buffer->data);
        return -EINVAL;
    }
    if (copy_to_user(&buffer->size, &size, sizeof(size))) {
        printk("Could not copy kstats size to user-supplied field %p.\n",
               &buffer->size);
        return -EINVAL;
    }
    return 0;
}

static int
kstats_ioctl(struct inode* inode, struct file* file,
             unsigned int ioctl_num, unsigned long ioctl_param)
{
    dynamorio_kstats_cmd_t __user *kstats;
    dr_cpu_exports_t *exports;
    int cpu;

    kstats = (dynamorio_kstats_cmd_t __user *) ioctl_param;

    if (!initialized) {
        printk("Module not yet initlized. You can't retrieve kstats now.");
        return -EPERM;
    }

    if (copy_from_user(&cpu, &kstats->cpu, sizeof(cpu)) != 0) {
        printk("Could not copy cpu # from userspace.\n");
        return -EINVAL;
    }

    if (cpu >= num_possible_cpus()) {
        printk("Invalid CPU # (%d).\n", cpu);
        return -EINVAL;
    }

    exports = &per_cpu(dr_cpu_exports, cpu);


    if (exports->kstats_data == NULL) {
        printk("exports->kstats_data is NULL. Make sure to specify the -kstats"
               " option and define KSTATS in your build.\n");
        return -EPERM;
    }

    return copy_export_to_user(exports->kstats_data, exports->kstats_size,
                               DYNAMORIO_KSTATS_MAX_SIZE, &kstats->buffer);
}

static int
stats_ioctl(struct inode* inode, struct file* file,
            unsigned int ioctl_num, unsigned long ioctl_param)
{
    dynamorio_stats_cmd_t __user *stats;
    stats = (dynamorio_stats_cmd_t __user *) ioctl_param;

    if (!initialized) {
        printk("Module not yet initlized. You can't retrieve stats now.");
        return -EPERM;
    }

    return copy_export_to_user(dr_exports.stats_data, dr_exports.stats_size,
                               DYNAMORIO_STATS_MAX_SIZE, &stats->buffer);
}

static int device_ioctl(struct inode* inode,
                        struct file* file,
                        unsigned int ioctl_num,
                        unsigned long ioctl_param) {
    switch (ioctl_num) {
    case DYNAMORIO_IOCTL_INIT:
        return init_ioctl(inode, file, ioctl_num, ioctl_param);
    case DYNAMORIO_IOCTL_EXIT:
        return exit_ioctl(inode, file, ioctl_num, ioctl_param);
    case DYNAMORIO_IOCTL_KSTATS:
        return kstats_ioctl(inode, file, ioctl_num, ioctl_param);
    case DYNAMORIO_IOCTL_STATS:
        return stats_ioctl(inode, file, ioctl_num, ioctl_param);
    default:
        printk("Uknwown ioctl number %d.\n", ioctl_num);
    }
    return 0;
}

static struct file_operations fops = {
    .read = NULL,
    .write = NULL,
    .open = NULL,
    .release = NULL,
    .ioctl = device_ioctl,
};

static int mod_init(void) {
    device_major = register_chrdev(0, DYNAMORIO_DEVICE_NAME, &fops);
    if (device_major < 0) {
        printk("Registering the character device failed with %d.\n",
            device_major);
        return device_major;
    }
    printk("Registered device name=%s, major=%d.\n",
        DYNAMORIO_DEVICE_NAME, device_major);
    return 0;
}

static void mod_exit(void) {
    unregister_chrdev(device_major, DYNAMORIO_DEVICE_NAME);
}

module_init(mod_init);
module_exit(mod_exit);
