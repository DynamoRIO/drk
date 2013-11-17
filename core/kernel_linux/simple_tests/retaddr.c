#include "simple_tests.h"

void
retaddr_main(void) {
    unsigned long rip;
    asm volatile("call next_instr\n"
                 "next_instr:\n"
                 "pop %0\n" : "=m"(rip));
    DR_ASSERT(rip > (unsigned long) &retaddr_main && rip <= (unsigned long) &retaddr_main + 50);
}
