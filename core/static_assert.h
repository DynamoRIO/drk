#ifndef __STATIC_ASSERT_H_
#define __STATIC_ASSERT_H_

#if 0
#define ASSERT_CONCAT_(a, b) a##b
#define ASSERT_CONCAT(a, b) ASSERT_CONCAT_(a, b)
#define STATIC_ASSERT(e) enum { ASSERT_CONCAT(assert_line_, __LINE__) = 1/(!!(e)) }
#endif

#define STATIC_ASSERT_HELPER(expr, msg) \
    (!!sizeof (struct { unsigned int STATIC_ASSERTION__##msg: (expr) ? 1 : -1; }))
#define STATIC_ASSERT(expr, msg) \
    extern int (*assert_function__(void)) [STATIC_ASSERT_HELPER(expr, msg)]

#define ASSERT_TYPE_SIZE(expected_size, struct_name) \
    STATIC_ASSERT(expected_size == sizeof(struct_name), type)




#endif
