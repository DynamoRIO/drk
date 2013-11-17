#ifndef __DR_ASSERT_H_
#define __DR_ASSERT_H_

#include "dynamorio_module_interface.h"

#define DR_STRINGIFY(x) #x
#define DR_TOSTRING(x) DR_STRINGIFY(x)

#define DR_ASSERT(x)\
    do {\
        if (!(x)) {\
            panic("Assertion failed (" __FILE__ ":" DR_TOSTRING(__LINE__)"): "\
                         #x);\
        }\
    } while(0)

#define DR_ASSERT_EQ(a, b) DR_ASSERT((a) == (b));

#endif
