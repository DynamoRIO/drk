#include <linux/module.h>
#include "kernel_interface.h"
MODULE_LICENSE("Dual BSD/GPL");

static ulong dr_heap_size = 257*1024*1024;
module_param(dr_heap_size, ulong, S_IRUSR);

static int mod_init(void) {
    if (!kernel_module_init(dr_heap_size)) {
        return -1;
    }
    return 0;
}

static void mod_exit(void) {
    kernel_module_exit();
}

module_init(mod_init);
module_exit(mod_exit);
