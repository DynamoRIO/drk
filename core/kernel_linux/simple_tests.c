#include "dynamorio_module_interface.h"
#include "simple_tests.h"

void
run_tests(void) {
    /*exception_main(); */
    /* repstr_main(); */ /* Too slow with memcheck. */
    fib_main();
    eflags_main();
    retaddr_main();
	recurse_main();
    xsave_main();
    wrap_main1(1,2,3,4,5,6);
    wrap_main2(1,2,3,4,5,6);
}
