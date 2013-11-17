#ifndef __DYNAMORIO_TESTS_H_
#define __DYNAMORIO_TESTS_H_

#include "dynamorio_module_interface.h"
#include "dynamorio_module_assert_interface.h"
#include <linux/kernel.h>

/* The tests. */
extern void exception_main(void);
extern void repstr_main(void);
extern void fib_main(void);
extern void eflags_main(void);
extern void retaddr_main(void);
extern void recurse_main(void);
extern void xsave_main(void);
extern int wrap_main1(int a1, int a2, int a3, int a4, int a5, int a6);
extern int wrap_main2(int a1, int a2, int a3, int a4, int a5, int a6);

/* Runs all of the tests. */
extern void run_tests(void);

#endif
