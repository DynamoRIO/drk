#include "configure.h"

#ifdef LINUX_KERNEL
#  include <asm/sigcontext.h>
#else
#  include <signal.h>
#endif
