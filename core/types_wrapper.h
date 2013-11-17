#ifndef __TYPES_H_
#define __TYPES_H_

#include "configure.h"

#ifdef LINUX_KERNEL
#  include <linux/types.h>     /* Fix for case 5341. */
#else
#  include <sys/types.h>
#endif

#endif
