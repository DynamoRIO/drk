#ifndef __BASIC_TYPES_H_
#define __BASIC_TYPES_H_

#include "static_assert.h"


#if !defined(_GLOBALS_SHARED_H_) && !defined(_DR_DEFINES_H_)
typedef unsigned char byte;
typedef unsigned int uint32;
typedef unsigned long int uint64;
#endif

#ifndef __USER_UNIT_TEST
#include "types_wrapper.h"
#define basic_assert(x) do { if (!(x)) *((char*)0x0) = 0;} while(0)
#else
#include <assert.h>
#define basic_assert(x) assert(x)
#include <sys/types.h>
#include <stdbool.h>
#endif


#endif

