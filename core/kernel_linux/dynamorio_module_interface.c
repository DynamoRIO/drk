#include <linux/module.h>
#include <linux/string.h>

#include "dynamorio_module_interface.h"

extern void os_terminate(void* dcontext, int flags);
extern void os_write(int fd, const void* buf, unsigned long count);
extern void os_set_options(const char* options);

EXPORT_SYMBOL_GPL(dr_pre_smp_init);
EXPORT_SYMBOL_GPL(dr_smp_init);
EXPORT_SYMBOL_GPL(dr_smp_exit);
EXPORT_SYMBOL_GPL(dynamorio_app_take_over);

void dr_terminate(const char* reason) {
	os_write(1 /* stdout */, reason, strlen(reason));
	os_terminate(NULL, 0);
}
EXPORT_SYMBOL_GPL(dr_terminate);
