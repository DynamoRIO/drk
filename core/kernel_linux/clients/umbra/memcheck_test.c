#include "memcheck.h"
#include <linux/irqflags.h>
#include <linux/module.h>
#include <linux/mm.h>

static unsigned long expected_val;
static unsigned long actual_val;

#define TEST_OP(expected, op, actual, format) do {\
    memcheck_disable_reporting();\
    expected_val = (typeof(expected_val)) (expected);\
    actual_val = (typeof(actual_val)) (actual);\
    if (!((expected_val) op (actual_val))) {\
        buf += sprintf(buf, __FILE__ ":%d Assertion failed: "\
                           #expected " (" #format ") " #op " " #actual " (" #format ")\n",\
                           __LINE__, (typeof(expected)) expected_val,\
                           (typeof(actual)) actual_val);\
        memcheck_enable_reporting();\
        goto done_failure;\
    }\
    memcheck_enable_reporting();\
} while (0)


#define TEST_PTR_EQ(expected, actual) TEST_OP(expected, ==, actual, %p)
#define TEST_PTR_NE(expected, actual) TEST_OP(expected, !=, actual, %p)
#define TEST_NOT_NULL(actual) TEST_PTR_NE(NULL, actual);

#define TEST_INT_EQ(expected, actual) TEST_OP(expected, ==, actual, %d)
#define TEST_INT_GE(min_expected, actual) TEST_OP(min_expected, <=, actual, %d)

#define TEST_ASSERT(x) do {\
    if (!(x)) {\
        buf += sprintf(buf, __FILE__ ":%d Assertion failed: " #x "\n", __LINE__);\
        goto done_failure;\
    }\
} while (0)

#define TEST_NO_REPORTS() do {\
        TEST_INT_EQ(0, memcheck_num_reports());\
        TEST_PTR_EQ(NULL, memcheck_get_report());\
} while (0)

#define TEST_REPORT(raddr, rtype)  do {\
        TEST_INT_GE(1, memcheck_num_reports());\
        report = memcheck_get_report();\
        TEST_INT_EQ(rtype, report->type);\
        TEST_PTR_EQ(raddr, report->addr);\
} while (0)

#define TEST_1_REPORT(raddr, rtype) do {\
        TEST_REPORT(raddr, rtype);\
        TEST_NO_REPORTS();\
} while (0)

#define TEST_1_UNADDRESSABLE(raddr)\
    TEST_1_REPORT(raddr, MEMCHECK_ERROR_UNADDRESSABLE)

#define TEST_UNADDRESSABLE(raddr)\
    TEST_REPORT(raddr, MEMCHECK_ERROR_UNADDRESSABLE)

#define TEST_1_UNDEFINED_READ(raddr)\
    TEST_1_REPORT(raddr, MEMCHECK_ERROR_UNDEFINED_READ)

#define TEST_UNDEFINED_READ(raddr)\
    TEST_REPORT(raddr, MEMCHECK_ERROR_UNDEFINED_READ)


#define STOS_FUNC(suffix) \
    void\
    stos ## suffix (volatile void *dest, unsigned long val) {\
        asm volatile("stos" #suffix :\
                     : "a"(val), "D" (dest)\
                     : "memory");\
    }

#define REP_STOS_FUNC(suffix) \
    void\
    rep_stos ## suffix (volatile void *dest, unsigned long val, size_t n) {\
        asm volatile("cld; rep stos" #suffix :\
            : "a"(val), "D" (dest), "c" (n) \
            : "memory");\
    }

#define MOVS_FUNC(suffix)\
    void\
    movs ## suffix (volatile void *dest, volatile void *src) {\
        asm volatile("movs" #suffix :\
                     : "D" (dest), "S" (src) \
                     : "memory");\
    }

#define REP_MOVS_FUNC(suffix)\
    void\
    rep_movs ## suffix (volatile void *dest, volatile void *src, size_t n) {\
        asm volatile("cld; rep movs" #suffix :\
                     : "D" (dest), "S" (src), "c" (n) \
                     : "memory");\
    }

#define STR_FUNCS(suffix)\
    STOS_FUNC(suffix)\
    REP_STOS_FUNC(suffix)\
    MOVS_FUNC(suffix)\
    REP_MOVS_FUNC(suffix)

STR_FUNCS(b)
STR_FUNCS(w)
STR_FUNCS(l)
STR_FUNCS(q)

static struct kmem_cache *memcheck_init_test_cache;

static void *memcheck_init_test_obj;

static void memcheck_test_cache_ctor(void *x)
{
}

#define TEST_CACHE_OBJ_SIZE 5

/* We read from the vsyscall memory. This is obviously a bit of a hack. It would
 * be nice to scan the page table to find some RW user memory. */
#define READABLE_USER_ADDRESS ((volatile char *) 0xffffffffff600000)

int
memcheck_test_kernel_init(void)
{
    /* Allocate with a ctor to ensure that we aren't aliased with another cache.
     */
    memcheck_init_test_cache = kmem_cache_create("memcheck_init_test_cache",
                                                 TEST_CACHE_OBJ_SIZE, 0,
                                                 GFP_ATOMIC,
                                                 &memcheck_test_cache_ctor);
    if (!memcheck_init_test_cache) {
        return -ENOMEM;
    }
    memcheck_init_test_obj = kmem_cache_alloc(memcheck_init_test_cache,
                                              GFP_KERNEL);
    if (!memcheck_init_test_obj) {
        kmem_cache_destroy(memcheck_init_test_cache);
        return -ENOMEM;
    }
    return 0;
}

void
memcheck_test_kernel_exit(void)
{
    kmem_cache_free(memcheck_init_test_cache, memcheck_init_test_obj);
    kmem_cache_destroy(memcheck_init_test_cache);
}

char backup[100];

volatile char *x;
volatile char y;
volatile char z;
volatile char yb;
volatile unsigned short y2;
volatile unsigned int y4;
volatile unsigned long y8;

#if 0
#define X1 ((unsigned short *) x)
#define X2 ((unsigned short *) x)
#define X4 ((unsigned int *) x)
#define X8 ((unsigned long *) x)
#endif

#define X1P(i) ((unsigned short *) &x[i])
#define X2P(i) ((unsigned short *) &x[i])
#define X4P(i) ((unsigned int *) &x[i])
#define X8P(i) ((unsigned long *) &x[i])

#define X1 X1P(0)
#define X2 X2P(0)
#define X4 X4P(0)
#define X8 X8P(0)

ssize_t
memcheck_test_main(char *buf, bool check_addr, bool check_defined)
{
    memcheck_report_t *report;
    void *to_free_from_cache_no_ctor = NULL;
    void *to_free_from_cache_5 = NULL;
    void *to_free_from_cache_17 = NULL;
    char *orig_buf = buf;
    unsigned long flags;
    int num_disabled_reports_before;

    /* Create test caches before disabling interrupts because kmem_cache_create can
     * block. */
    struct kmem_cache *cache_no_ctor =
        kmem_cache_create("memcheck_test_cache_no_ctor",
                          8, 0, GFP_ATOMIC, NULL);

    struct kmem_cache *cache_5 = kmem_cache_create("memcheck_test_cache_5",
                                                   5, 0, GFP_ATOMIC,
                                                   &memcheck_test_cache_ctor);

    struct kmem_cache *cache_17 = kmem_cache_create("memcheck_test_cache_17",
                                                    17, 0, GFP_ATOMIC,
                                                    &memcheck_test_cache_ctor);
    local_irq_save(flags);
    preempt_disable();
    /* Disable reporting between test cases so we don't hit infinite recursion
     * in case of an unexpected error report. */
    memcheck_disable_reporting();
    num_disabled_reports_before = memcheck_num_disabled_reports();
    memcheck_enable_reporting();

    if (!check_addr) {
        TEST_ASSERT(!check_defined);
        goto done_success;
    }

    /* Can't do tests until interrupts are disabled. */
    TEST_NOT_NULL(cache_5);
    TEST_NOT_NULL(cache_17);
    TEST_NOT_NULL(cache_no_ctor);
    memcheck_reset_reports();
    TEST_INT_EQ(0, memcheck_num_reports());
    TEST_PTR_EQ(NULL, memcheck_get_report());

    /* Test read and write allocated memory. */
    {
        x = (kmalloc(8, GFP_ATOMIC | __GFP_ZERO));
        yb = X1[0];
        y2 = X2[0];
        y4 = X4[0];
        y8 = X8[0];
        X1[0] = yb;
        X2[0] = y2;
        X4[0] = y4;
        X8[0] = y8;
        TEST_NO_REPORTS();
    }

    /* Test read and write after free: __kmalloc. */
    {
        /* Call __kmalloc instead of kmalloc because gcc inlines calls to
         * kmem_cache_alloc instead of __kmalloc when the size is an immediate.
         * See the use of __builtin_constant_p in kmalloc in slub_def.h.
         */
        x = __kmalloc(5, GFP_ATOMIC | __GFP_ZERO);
        kfree((char*) x);
        y = x[0];
        printk("%p\n", x);
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);
        x[0] = y;
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);
    }

    /* Test reading and writing unallocated memory: __kmalloc. */
    {
        x = __kmalloc(1, GFP_ATOMIC | __GFP_ZERO);
        y = x[1];
        TEST_1_REPORT(&x[1], MEMCHECK_ERROR_UNADDRESSABLE);
        x[1] = y;
        kfree((char*) x);
        TEST_1_REPORT(&x[1], MEMCHECK_ERROR_UNADDRESSABLE);
    }

    /* Test reading and writing unallocated memory: kmem_cache_alloc. */
    {
        x = kmem_cache_alloc(cache_5, GFP_ATOMIC | __GFP_ZERO);
        to_free_from_cache_5 = (void*) x;
        y = x[5];
        TEST_1_REPORT(&x[5], MEMCHECK_ERROR_UNADDRESSABLE);
        x[5] = y;
        TEST_1_REPORT(&x[5], MEMCHECK_ERROR_UNADDRESSABLE);
        kmem_cache_free(cache_5, (char*) x);
        to_free_from_cache_5 = NULL;
    }

    /* Test read and write after free: kmem_cache_free. */
    {
        x = kmem_cache_alloc(cache_5, GFP_ATOMIC | __GFP_ZERO);
        kmem_cache_free(cache_5, (char*) x);
        y = x[0];
        TEST_1_REPORT(x, MEMCHECK_ERROR_UNADDRESSABLE);
        x[0] = y;
        TEST_1_REPORT(x, MEMCHECK_ERROR_UNADDRESSABLE);
    }

    /* Test shadow initialization for slabs that existed before attaching. */
    {
        TEST_PTR_EQ((void*) PAGE_ALIGN((size_t) memcheck_init_test_obj),
                    memcheck_init_test_obj);
        x = memcheck_init_test_obj;
        y = x[0];
        y = x[TEST_CACHE_OBJ_SIZE - 1];
        TEST_NO_REPORTS();
        /* Test reading a metadata byte. */
        y = x[TEST_CACHE_OBJ_SIZE];
        TEST_1_REPORT(&x[TEST_CACHE_OBJ_SIZE], MEMCHECK_ERROR_UNADDRESSABLE);
        /* Test reading a data byte of the next object. */
        x = memcheck_init_test_obj + memcheck_init_test_cache->size;
        y = x[0];
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);
    }

    /* Test multiple byte accesses: all unaddressable. */
    {
        x = __kmalloc(8, GFP_ATOMIC | __GFP_ZERO);
        kfree((char*) x);

        y2 = X2[0];
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);
        X2[0] = y2;
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);

        y4 = X4[0];
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);
        X4[0] = y4;
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);

        y8 = X8[0];
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);
        X8[0] = y8;
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);
    }

    /* Test multiple byte accesses: some unaddressable. */
    {
        x = __kmalloc(1, GFP_ATOMIC | __GFP_ZERO);

        y2 = X2[0];
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);
        X2[0] = y2;
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);

        y4 = X4[0];
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);
        X4[0] = y4;
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);

        y8 = X8[0];
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);
        X8[0] = y8;
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);

        kfree((char*) x);
    }

    /* Test multiple byte accesses: last unaddressable. */
    {
        x = __kmalloc(1, GFP_ATOMIC | __GFP_ZERO);
        y2 = X2[0];
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);
        X2[0] = y2;
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);
        kfree((char*) x);

        x = __kmalloc(3, GFP_ATOMIC | __GFP_ZERO);
        y4 = X4[0];
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);
        X4[0] = y4;
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);
        kfree((char*) x);

        x = __kmalloc(7, GFP_ATOMIC | __GFP_ZERO);
        y8 = X8[0];
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);
        X8[0] = y8;
        TEST_1_REPORT(&x[0], MEMCHECK_ERROR_UNADDRESSABLE);
        kfree((char*) x);
    }

    /* Test single string ops. */
    {
        x = kmem_cache_alloc(cache_17, GFP_ATOMIC | __GFP_ZERO);
        to_free_from_cache_17 = (char*) x;

        /* Test writing just to the end of the buffer. */
        stosb(X1P(16), 0);
        stosw(X2P(15), 0);
        stosl(X4P(13), 0);
        stosq(X8P(9), 0);
        TEST_NO_REPORTS();

         /* Test writing a single byte past the end of the buffer. */
        yb = *X1P(17);
        TEST_1_UNADDRESSABLE(X1P(17));
        stosb(X1P(17), y);
        TEST_1_UNADDRESSABLE(X1P(17));

        y2 = *X2P(16);
        TEST_1_UNADDRESSABLE(X2P(16));
        stosw(X2P(16), y2);
        TEST_1_UNADDRESSABLE(X2P(16));

        y4 = *X4P(14);
        TEST_1_UNADDRESSABLE(X4P(14));
        stosl(X4P(14), y4);
        TEST_1_UNADDRESSABLE(X4P(14));

        y8 = *X8P(10);
        TEST_1_UNADDRESSABLE(X8P(10));
        stosq(X8P(10), y8);
        TEST_1_UNADDRESSABLE(X8P(10));

        kmem_cache_free(cache_17, (char*) x);
        to_free_from_cache_17 = NULL;
    }

    /* Test rep string ops. */
    {
        x = kmem_cache_alloc(cache_17, GFP_ATOMIC | __GFP_ZERO);
        to_free_from_cache_17 = (char*) x;

        /* Backup the contents of x and the other bytes that we're going to
         * overwrite so we don't have to save and restore on every update. */
        TEST_NO_REPORTS(); 
        memcpy(backup, (char*) x, sizeof(backup));
        memcheck_reset_reports();

        /* Test writing multiple b/w/l/q words to the start of the buffer. */
        rep_stosb(x, 0, 17);
        rep_stosw(x, 0, 8);
        rep_stosl(x, 0, 4);
        rep_stosq(x, 0, 2);
        TEST_NO_REPORTS();

        /* Test writing enough b/w/l/q past the end of the buffer to generate 1
         * report. */
        rep_stosb(x, 0, 18);
        TEST_1_UNADDRESSABLE(x + 17);
        rep_stosw(x, 0, 9);
        TEST_1_UNADDRESSABLE(x + 16);
        rep_stosl(x, 0, 5);
        TEST_1_UNADDRESSABLE(x + 16);
        rep_stosq(x, 0, 3);
        TEST_1_UNADDRESSABLE(x + 16);

        /* Test writing enough b/w/l/q past the end of the buffer to generate 2
         * reports. */
        rep_stosb(x + 17, 0, 2);
        TEST_UNADDRESSABLE(x + 17);
        TEST_1_UNADDRESSABLE(x + 18);
        rep_stosw(x + 17, 0, 2);
        TEST_UNADDRESSABLE(x + 17);
        TEST_1_UNADDRESSABLE(x + 19);
        rep_stosl(x + 17, 0, 2);
        TEST_UNADDRESSABLE(x + 17);
        TEST_1_UNADDRESSABLE(x + 21);
        rep_stosq(x + 17, 0, 2);
        TEST_UNADDRESSABLE(x + 17);
        TEST_1_UNADDRESSABLE(x + 25);

        TEST_NO_REPORTS(); 
        memcpy((char*) x, backup, sizeof(backup));
        memcheck_reset_reports();

        kmem_cache_free(cache_17, (char*) x);
        to_free_from_cache_17 = NULL;
    }

    /* Test getting two reports from the same instruction: movs and rep movs */
    {
        x = kmem_cache_alloc(cache_17, GFP_ATOMIC | __GFP_ZERO);
        to_free_from_cache_17 = (char*) x;

        TEST_NO_REPORTS(); 
        memcpy(backup, (char*) x, sizeof(backup));
        memcheck_reset_reports();

        /* Copy from allocated to allocated. */
        movsb(x, x);
        movsb(x, x + 1);
        movsw(x, x + 2);
        movsl(x, x + 4);
        movsq(x, x + 8);
        TEST_NO_REPORTS();

        /* Only source unaddressable. */
        movsb(x, x + 17);
        TEST_1_UNADDRESSABLE(x + 17);
        movsw(x, x + 17);
        TEST_1_UNADDRESSABLE(x + 17);
        movsl(x, x + 17);
        TEST_1_UNADDRESSABLE(x + 17);
        movsq(x, x + 17);
        TEST_1_UNADDRESSABLE(x + 17);

        /* Only dest unaddressable. */
        movsb(x + 17, x);
        TEST_1_UNADDRESSABLE(x + 17);
        movsw(x + 17, x);
        TEST_1_UNADDRESSABLE(x + 17);
        movsl(x + 17, x);
        TEST_1_UNADDRESSABLE(x + 17);
        movsq(x + 17, x);
        TEST_1_UNADDRESSABLE(x + 17);

        /* Both source and dest unaddressable. */
        movsb(x + 17, x + 17);
        TEST_UNADDRESSABLE(x + 17);
        TEST_1_UNADDRESSABLE(x + 17);
        /* Test that sources are reported before destinations. */
        movsb(x + 18, x + 17);
        TEST_UNADDRESSABLE(x + 17);
        TEST_1_UNADDRESSABLE(x + 18);
        rep_movsb(x + 25, x + 17, 3);
        TEST_UNADDRESSABLE(x + 17);
        TEST_UNADDRESSABLE(x + 25);
        TEST_UNADDRESSABLE(x + 18);
        TEST_UNADDRESSABLE(x + 26);
        TEST_UNADDRESSABLE(x + 19);
        TEST_1_UNADDRESSABLE(x + 27);

        TEST_NO_REPORTS(); 
        memcpy((char*) x, backup, sizeof(backup));
        memcheck_reset_reports();

        kmem_cache_free(cache_17, (char*) x);
        to_free_from_cache_17 = NULL;
    }

    /* Test kmalloc with an allocation larger than 2 pages. The slub allocator
     * doesn't use a slub page for large allocations, instead it uses
     * __get_free_pages directly. We want to test that it's permission is set to
     * unknown after kfree.
     */
    {
        x = __kmalloc(SLUB_MAX_SIZE + 1, GFP_ATOMIC | __GFP_ZERO);
        y = x[0];
        x[0] = y;
        TEST_NO_REPORTS();
        kfree((char*)x);
        y = x[0];
        x[0] = y;
        TEST_NO_REPORTS();
    }

    /* TODO(peter): It would be nice to have a test that hits the __slab_free
     * path. As far as I know, there isn't a way of forcing the slub allocator
     * to free a page. The test for SLUB_MAX_SIZE hits page freeing in a
     * different path (i.e., kfree of a large page). */

    /* Test reading from a user memory location.  */
    {
        /* Test reading from a non-absolute/rip-rel user address. */
        x = READABLE_USER_ADDRESS;
        /* reading unknown user address */
        y = x[0];
        /* reading unknown which was propagated */
        movsb(&y, x);
        z = y;
        TEST_NO_REPORTS();

        /* Test reading from an absolute/rip-rel user address. */
        y = READABLE_USER_ADDRESS[0];
        TEST_NO_REPORTS();
    }

    buf += sprintf(buf, "Addressability tests passed!\n");

    if (!check_defined) {
        goto done_success;
    }

    /* Test reading an undefined value. */
    {
        x = __kmalloc(8, GFP_ATOMIC); 
        yb = X1[0];
        TEST_1_UNDEFINED_READ(x);
        y2 = X2[0];
        TEST_1_UNDEFINED_READ(x);
        y4 = X4[0];
        TEST_1_UNDEFINED_READ(x);
        y8 = X8[0];
        TEST_1_UNDEFINED_READ(x);
        kfree((char*)x);
    }

    /* Test reading an undefined value: no ctor. */
    {
        x = kmem_cache_alloc(cache_no_ctor, GFP_ATOMIC);
        to_free_from_cache_no_ctor = (char*)x;
        y = x[0];
        TEST_1_UNDEFINED_READ(x);
        kmem_cache_free(cache_no_ctor, (char*)x);
        to_free_from_cache_no_ctor = NULL;
    }

    /* Test reading a defined value: all defined. */
    {
        x = __kmalloc(8, GFP_ATOMIC); 
        rep_stosb(x, 0, 8);
        yb = X1[0];
        y2 = X2[0];
        y4 = X4[0];
        y8 = X8[0];
        TEST_NO_REPORTS();
        kfree((char*)x);
    }

    /* Test reading a defined value: just 1st defined. */
    {
        x = __kmalloc(8, GFP_ATOMIC); 
        x[0] = 1;
        yb = X1[0];
        y2 = X2[0];
        y4 = X4[0];
        y8 = X8[0];
        kfree((char*)x);;
        TEST_NO_REPORTS();
    }

    /* Test reading a defined value: just last defined. */
    {
        x = __kmalloc(8, GFP_ATOMIC); 
        x[7] = 1;
        y8 = X8[0];
        kfree((char*)x);;

        x = __kmalloc(8, GFP_ATOMIC); 
        x[3] = 1;
        y4 = X4[0];
        kfree((char*)x);;

        x = __kmalloc(8, GFP_ATOMIC); 
        x[1] = 1;
        y2 = X2[0];
        kfree((char*)x);;

        x = __kmalloc(8, GFP_ATOMIC); 
        x[0] = 1;
        yb = X1[0];
        kfree((char*)x);;
        TEST_NO_REPORTS();
    }

    /* Test reading a defined value: defined by __GFP_ZERO. */
    {
        x = __kmalloc(8, GFP_ATOMIC | __GFP_ZERO); 
        yb = x[0];
        yb = x[7];
        kfree((char*)x);;
        TEST_NO_REPORTS();

        x = kmem_cache_alloc(cache_no_ctor, GFP_ATOMIC | __GFP_ZERO); 
        to_free_from_cache_no_ctor = (char*) x;
        yb = x[0];
        yb = x[7];
        TEST_NO_REPORTS();
        kmem_cache_free(cache_no_ctor, (char*) x);
        to_free_from_cache_no_ctor = NULL;
    }

    /* Test reading a defined value: defined by ctor. */
    {
        x = kmem_cache_alloc(cache_5, GFP_ATOMIC);
        to_free_from_cache_5 = (char*) x;
        y = x[0];
        y = x[4];
        TEST_NO_REPORTS();
        kmem_cache_free(cache_5, (char*) x);
        to_free_from_cache_5 = NULL;

        x = kmem_cache_alloc(cache_5, GFP_ATOMIC | __GFP_ZERO);
        to_free_from_cache_5 = (char*)x;
        y = x[0];
        y = x[4];
        TEST_NO_REPORTS();
        kmem_cache_free(cache_5, (char*) x);
        to_free_from_cache_5 = NULL;
    }

    /* Test reading a defined value: allocated before initialization. */
    {
        x = memcheck_init_test_obj;
        y = x[0];
        TEST_NO_REPORTS();
    }

    /* Test reading an unknown value. */
    {
        x = (char*) &memcheck_test_main;
        y = x[0];
        TEST_NO_REPORTS();
    }

    /* Test propagation. */
    {

        /* propagation of defined */
        x = __kmalloc(16, GFP_ATOMIC);
        x[0] = 1;
        movsb(x + 1, x);
        y = x[1];
        kfree((char*)x);;
        TEST_NO_REPORTS();

        /* propagation of undefined */
        x = __kmalloc(16, GFP_ATOMIC);
        x[1] = 1;
        y = x[1];
        TEST_NO_REPORTS();
        movsb(x + 1, x);
        y = x[1];
        kfree((char*)x);;
        TEST_1_UNDEFINED_READ(x + 1);

        /* propagation of unknown */
        x = (char*) &memcheck_test_main;
        movsb(x, &memcheck_test_main);
        y = x[1];
        TEST_NO_REPORTS();
    }

    /* Test extent of propagation. */
    {
        /* undefined -> defined */
        x = __kmalloc(24, GFP_ATOMIC);
        rep_stosb(x, 0, 8);
        movsb(x + 16, x);
        y = x[16];
        TEST_NO_REPORTS();
        y = x[15];
        TEST_1_UNDEFINED_READ(x + 15);
        y = x[17];
        TEST_1_UNDEFINED_READ(x + 17);
        y2 = X2P(16)[0];
        TEST_NO_REPORTS();
        kfree((char*)x);;

        /* undefined -> unknown */
        x = __kmalloc(24, GFP_ATOMIC);
        movsb(x + 16, &memcheck_test_main);
        y = x[16];
        TEST_NO_REPORTS();
        y = x[15];
        TEST_1_UNDEFINED_READ(x + 15);
        y = x[17];
        TEST_1_UNDEFINED_READ(x + 17);
        y2 = X2P(16)[0];
        TEST_NO_REPORTS();
        kfree((char*)x);;

        /* defined -> unknown */
        x = __kmalloc(24, GFP_ATOMIC | __GFP_ZERO);
        movsb(x + 16, &memcheck_test_main);
        y = x[16];
        y = x[15];
        y = x[17];
        TEST_NO_REPORTS();
        y2 = X2P(16)[0];
        TEST_NO_REPORTS();
        kfree((char*)x);
    }

    buf += sprintf(buf, "Definedness tests passed!\n");

done_success:
    TEST_NO_REPORTS();

    /* Make sure that we didn't loose any reports due to disabling. */
    TEST_INT_EQ(num_disabled_reports_before, memcheck_num_disabled_reports());

    /* Reenable everything and continue. */
    memcheck_enable_reporting();
    buf += sprintf(buf, "All memcheck tests passed!\n");
done_failure:
    preempt_enable();
    local_irq_restore(flags);
    if (cache_17) {
        if (to_free_from_cache_17) {
            kmem_cache_free(cache_17, to_free_from_cache_17);
        }
        kmem_cache_destroy(cache_17);
    }
    if (cache_5) {
        if (to_free_from_cache_5) {
            kmem_cache_free(cache_5, to_free_from_cache_5);
        }
        kmem_cache_destroy(cache_5);
    }
    if (cache_no_ctor) {
        if (to_free_from_cache_no_ctor) {
            kmem_cache_free(cache_no_ctor, to_free_from_cache_no_ctor);
        }
        kmem_cache_destroy(cache_no_ctor);
    }
    return buf - orig_buf;
}
