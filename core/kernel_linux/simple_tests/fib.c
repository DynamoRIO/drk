#include "simple_tests.h"

static int
fib (int n) {
	if (n == 0) return 0;
	if (n == 1) return 1;
    return fib(n-1) + fib(n-2);
}

void
fib_main(void) {
	DR_ASSERT_EQ(0, fib(0));
	DR_ASSERT_EQ(1, fib(1));
	DR_ASSERT_EQ(1, fib(2));
	DR_ASSERT_EQ(2, fib(3));
	DR_ASSERT_EQ(144, fib(12));
	DR_ASSERT_EQ(2178309, fib(32));
}
