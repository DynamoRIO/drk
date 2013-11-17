#include "simple_tests.h"
#include <linux/module.h>

#define N 20

static void
my_memset(void *dst, int c, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        ((unsigned char*) dst)[i] = (unsigned char) c;
    }
}

static void
assert_eq(const unsigned char *dst, int c, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        DR_ASSERT_EQ(dst[i], (unsigned char) c);
    }
}

#define N 20

static unsigned char buf[N];

void
repstr_main(void) {
    /* This test does a much better test when interrupts are enabled.
     * TODO(peter): Enable interrupts during testing.
     */
    int j;
    for (j = 0; j < 10000000; j++) {
        /* Test 9 at a time because it hits the 8 byte and 1 byte reps
         * instructions in memset.
         */
        int i = 9;
        my_memset(buf, 0xaa, N);
        assert_eq(buf, 0xaa, N);
        memset(buf, 0xbb, i);
        assert_eq(buf, 0xbb, i);
        assert_eq(buf + i, 0xaa, N - i);
    }
}
