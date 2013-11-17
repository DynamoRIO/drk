#include "simple_tests.h"

/* You're supposed to use CPUID to get the size of the xsave buffer. I'm
 * assuming it'll be smaller than 1 page.
 */
static char xsave_buffer[4096];

void
xsave_main(void)
{
    asm volatile("mov %0, %%rdi\n"
                /* TODO(peter): I need to setup CR4.OSXSAVE and CR0.TS properly
                 * to use xsave. */
#if 0
                /* xsave64 (%rdi) */
                 ".byte 0x48,0x0f,0xae,0x27"
#endif

                 :
                 : "r" (xsave_buffer));
}
