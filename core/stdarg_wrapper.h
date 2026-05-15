#ifndef __STDARG_WRAPPER_H_
#define __STDARG_WRAPPER_H_

#include "configure.h"

#if defined(LINUX_KERNEL) && !defined(__USER_UNIT_TEST)
#    include <linux/stdarg.h>
#else
#    include <stdarg.h>
#endif

#endif /* __STDARG_WRAPPER_H_ */
