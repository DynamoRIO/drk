#ifndef __CR_H_
#define __CR_H_

#include "basic_types.h"

typedef struct {
  uint64 reserved1 : 3;
  uint64 page_level_writethrough : 1;
  uint64 page_level_cache_disable : 1;
  uint64 reserved2 : 7;
  uint64 l4_pfn : 40;
  uint64 reserved3 : 12;
} __attribute__((__packed__)) cr3_t;
ASSERT_TYPE_SIZE(8, cr3_t);

typedef struct {
  uint64 protection_enabled : 1;
  uint64 monitor_coprocessor : 1;
  uint64 emulation : 1;
  uint64 task_switched : 1;
  uint64 extension_type : 1;
  uint64 numeric_error : 1;
  uint64 reserved1 : 10;
  uint64 write_protect : 1;
  uint64 reserved2 : 1;
  uint64 aligntment_mask : 1;
  uint64 reserved3 : 10;
  uint64 not_writethrough : 1;
  uint64 cache_disabled : 1;
  uint64 paging : 1;
  uint64 reserved4 : 32;
} __attribute__((__packed__)) cr0_t;
ASSERT_TYPE_SIZE(8, cr0_t);

static inline void get_cr3(cr3_t* output) {
  asm volatile (
    "mov %%cr3, %%rax\n"
    "mov %%rax, %0\n" : "=m" (*output) : : "rax" );
}

static inline unsigned long get_cr2(void) {
  unsigned long output;
  asm volatile (
    "mov %%cr2, %%rax\n"
    "mov %%rax, %0\n" : "=m" (output) : : "rax" );
  return output;
}

static inline void get_cr0(cr0_t* output) {
  asm volatile (
    "mov %%cr0, %%rax\n"
    "mov %%rax, %0\n" : "=m" (*output) : : "rax" );
}

#endif
