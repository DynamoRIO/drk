#ifndef __PAGING_H_
#define __PAGING_H_

#include "basic_types.h"
#include "static_assert.h"


/* Hole caused by canonical addressing. The high 16 bits of a virtual
   address must have the same value as the 48th bit (1 indexed). All of the
   functions in this file treat the hole as a non-present region. */
#define VM_HOLE_START ((void*) 0x0000800000000000)
#define VM_HOLE_END ((void*) 0xffff7fffffffffff)

typedef struct {
    union {
        struct {
            uint32 pf_offset : 12; // page frame byte offset
            uint32 l1_index : 9;   // page table (PT) index
            uint32 l2_index : 9;   // page-directory table (PDT) index 
            uint32 l3_index : 9;   // page-directory pointer table (PDPT) index
            uint32 l4_index : 9;   // page-map level-4 table (PML4T) index
            uint32 sign_extension_bits : 16;
        } __attribute__((__packed__));
        struct {
            void* virtual_address;
        } __attribute__((__packed__));
    };
} __attribute__((__packed__)) virtual_address_t;
ASSERT_TYPE_SIZE(8, virtual_address_t);

// Generic structure describing entries in page tables L1 through L4.
typedef struct {
  uint64 present : 1;
  uint64 writable : 1;
  uint64 user : 1;
  uint64 page_level_writethrough : 1;
  uint64 page_level_cache_disable : 1;
  uint64 accessed : 1;
  // The dirty, size, and global bits are only available for the lowest level of
  // the page translation hierarchy. What is the lowest level depends on the
  // value of the size bit on level 3 and level 2. See the AMD64 developer
  // documentation for an explanation of page table entires.
  uint64 dirty : 1;
  uint64 size : 1;
  uint64 global : 1;
  uint64 available1 : 3;
  uint64 next_pfn : 40;
  uint64 available2 : 11;
  uint64 not_executable : 1;
} __attribute__((__packed__)) generic_page_table_entry_t;
ASSERT_TYPE_SIZE(8, generic_page_table_entry_t);

#define PAGE_TABLE_ENTIRES_PER_LEVEL 512
#define PAGE_TABLE_SIZEOF_LEVEL\
    (PAGE_TABLE_ENTIRES_PER_LEVEL * sizeof(generic_page_table_entry_t))

static inline int get_page_table_size(generic_page_table_entry_t* table) {
    return PAGE_TABLE_ENTIRES_PER_LEVEL;
}

extern generic_page_table_entry_t* get_l4_page_table(void);

extern generic_page_table_entry_t* follow_page_table_entry(
    generic_page_table_entry_t* entry);

typedef struct {
  bool writable;
  bool executable;
  bool user;
} vm_access_t;

// A region of virtual memory. The start and end addresses define a closed
// interval: [start, end]. So, on a 64-bit machine, the last 4KB
// of memory have the address range [0xfffffffffffff000, 0xffffffffffffffff].
typedef struct {
  void* start;  
  void* end;
  bool present;
  vm_access_t access;
} vm_region_t;

static inline bool vm_region_has_same_permissions(
    const vm_region_t* a, const vm_region_t* b) {
  return (!a->present && !b->present) ||
         (a->present && 
          b->present &&
          a->access.writable == b->access.writable &&
          a->access.executable == b->access.executable &&
          a->access.user == b->access.user);
}

static inline bool vm_region_is_executable(const vm_region_t* region) {
  return region->present && region->access.executable;
}

static inline bool vm_region_are_adjacent(
    const vm_region_t* a, const vm_region_t* b) {
  if (a->end == (void*) 0xfffffffffffffffful) {
    return false;
  }
  return a->end + 1 == b->start;
}

typedef void(*depth_first_traversal_callback_t)(unsigned long pfn, void* arg);

extern void depth_first_traverse_page_table(
    generic_page_table_entry_t *l4,
    depth_first_traversal_callback_t callback,
    void *arg);

typedef void(*page_table_traversal_callback_t)(const vm_region_t*, void*);

extern void traverse_page_table(
    generic_page_table_entry_t* l4,
    bool truncate_nx,
    page_table_traversal_callback_t callback,
    void* arg);

extern void traverse_page_table_contiguous(
    generic_page_table_entry_t* l4,
    page_table_traversal_callback_t callback,
    void* arg);

/* For the given byte, returns the PFN that the byte resides on
 * and the range of virtual addresses that share the same mapping.
 */
extern bool page_table_get_page(generic_page_table_entry_t* l4,
                                void* virtual_address,
                                vm_region_t* region,
                                unsigned long* pfn,
                                generic_page_table_entry_t** parent,
                                int* parent_level);

bool page_table_get_physical_address(generic_page_table_entry_t* l4,
                                     void* virtual_address,
                                     unsigned long* physical_address);

extern void page_table_get_region(generic_page_table_entry_t* l4,
                                  void* virtual_address,
                                  vm_region_t* region);

extern bool page_table_readable_without_exception(
        generic_page_table_entry_t* l4,
        void* start,
        size_t size);

extern bool page_table_writable_without_exception(
        generic_page_table_entry_t* l4,
        void* start,
        size_t size);

#endif
