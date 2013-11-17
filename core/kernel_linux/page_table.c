#include "page_table.h"
#include "cr.h"

#ifndef __USER_UNIT_TEST
# include <asm/io.h> /* for phys_to_virt */
# include <asm/page.h> /* for virt_to_phys */
#endif

#define _1GB (1ul << 30)
#define _2MB (2ul << 20)
#define _4KB (4ul << 10)

/* Size must be a power of 2. */
#define ALIGN_BACKWARD(x, size) ((void*) ((unsigned long) x & (~(size - 1))))

#define PFN_TO_PA(pfn) ((pfn) << 12)

#define virt_to_pfn(virt) (((unsigned long) virt_to_phys((virt))) >> 12)

generic_page_table_entry_t* follow_page_table_entry(
    generic_page_table_entry_t* entry) {
  return (generic_page_table_entry_t*)
    phys_to_virt(PFN_TO_PA((uint64) entry->next_pfn));
}

generic_page_table_entry_t* get_l4_page_table(void) {
    cr3_t cr3;
    get_cr3(&cr3);
    return (generic_page_table_entry_t*)
        (uint64) phys_to_virt(PFN_TO_PA(cr3.l4_pfn));
}

bool page_table_get_page(generic_page_table_entry_t* l4,
                         void* virtual_address,
                         vm_region_t* region,
                         unsigned long* pfn,
                         generic_page_table_entry_t** parent,
                         int *parent_level) {
    virtual_address_t index;
    generic_page_table_entry_t* entry;
    region->present = false;
    *parent = 0;
    *parent_level = -1;

    if (virtual_address >= VM_HOLE_START && virtual_address <= VM_HOLE_END) {
        return false;
    }

    index.virtual_address = virtual_address;
    entry = &l4[index.l4_index];
    *parent = entry;
    *parent_level = 4;

    if (!entry->present) {
        return false;
    }
    region->access.writable = entry->writable;
    region->access.executable = !entry->not_executable;
    region->access.user = entry->user;
    entry = &follow_page_table_entry(entry)[index.l3_index];
    *parent = entry;
    *parent_level = 3;

    if (!entry->present) {
        return false;
    }
    region->access.writable &= entry->writable;
    region->access.executable &= !entry->not_executable;
    region->access.user &= entry->user;
    if (entry->size) {
        region->present = true;
        region->start = (void*) ALIGN_BACKWARD(virtual_address, _1GB);
        region->end = region->start + _1GB - 1;
        *pfn = entry->next_pfn + index.l1_index + (index.l2_index << 9);
        return true;
    };
    entry = &follow_page_table_entry(entry)[index.l2_index];
    *parent = entry;
    *parent_level = 2;

    if (!entry->present) {
        return false;
    }
    region->access.writable &= entry->writable;
    region->access.executable &= !entry->not_executable;
    region->access.user &= entry->user;
    if (entry->size) {
        region->present = true;
        region->start = (void*) ALIGN_BACKWARD(virtual_address, _2MB);
        region->end = region->start + _2MB - 1;
        *pfn = entry->next_pfn + index.l1_index;
        return true;
    }
    entry = &follow_page_table_entry(entry)[index.l1_index];
    *parent = entry;
    *parent_level = 1;

    if (!entry->present) {
        return false;
    }
    region->present = true;
    region->access.writable &= entry->writable;
    region->access.executable &= !entry->not_executable;
    region->access.user &= entry->user;
    region->start = (void*) ALIGN_BACKWARD(virtual_address, _4KB);
    region->end = region->start + _4KB - 1;
    *pfn = entry->next_pfn;
    return true;
}

bool page_table_get_physical_address(generic_page_table_entry_t* l4,
                                     void* virtual_address,
                                     unsigned long* physical_address) {
    vm_region_t region;
    unsigned long pfn;
    virtual_address_t index;
    generic_page_table_entry_t* parent;
    int parent_level;
    if (!page_table_get_page(l4, virtual_address, &region, &pfn, &parent,
                             &parent_level)) {
        return false;
    }
    index.virtual_address = virtual_address;
    *physical_address = PFN_TO_PA(pfn) + (unsigned long) (index.pf_offset);
    return true;
}



typedef struct {
    void* address_to_find;
    vm_region_t* output;
    bool found;
} get_region_arg_t;

static void get_region_callback(
        const vm_region_t* region,
        void* void_arg) {
    get_region_arg_t* arg = (get_region_arg_t*) void_arg;
    if (arg->address_to_find >= region->start &&
            arg->address_to_find <= region->end) {
        *arg->output = *region;
        arg->found = true;
        /* TODO(peter): implement return false to truncate the search. */
    }
}

void page_table_get_region(generic_page_table_entry_t* l4,
                           void* virtual_address,
                           vm_region_t* region) {
    /* TODO(peter): Do a traversal that starts at the VM region containing
     * virtual_address and traverses the page table backwards and forwards to
     * find its extent. Traversing the entire page table is probably going to be
     * too slow. */
    get_region_arg_t arg;
    arg.output = region;
    arg.address_to_find = virtual_address;
    arg.found = false;
    traverse_page_table_contiguous(l4, get_region_callback, &arg);
    basic_assert(arg.found);
}

static void
depth_first_traverse_page_table_recursive(
    generic_page_table_entry_t *table, int level, 
    depth_first_traversal_callback_t callback, void *arg)
{
    int i;
    for (i = 0; i < get_page_table_size(table); i++) {
        generic_page_table_entry_t* entry = &table[i];
        if (entry->present) {
            int pfns;
            int j;
            if (level == 1) {
                pfns = (4 << 10) >> 12;   /* single 4KB page */
            } else if (level == 2 && entry->size) {
                pfns = (2 << 20) >> 12;   /* 2MB / 4KB pages */
            } else if (level == 3 && entry->size) {
                pfns = (1 << 30) >> 12;   /* 1GB / 4KB pages */
            } else {
                pfns = 0;
                depth_first_traverse_page_table_recursive(
                    follow_page_table_entry(entry), level - 1, callback, arg);
            }
            for (j = 0; j < pfns; j++) {
                /* Leaves. */
                callback(entry->next_pfn + j, arg);
            }
        }
    }
    /* Intenral nodes. */
    callback(virt_to_pfn(table), arg);
}

void
depth_first_traverse_page_table(generic_page_table_entry_t *l4,
                                depth_first_traversal_callback_t callback,
                                void *arg)
{
    depth_first_traverse_page_table_recursive(l4, 4, callback, arg);
}

static bool address_is_canonical(void* address) {
  return address < VM_HOLE_START || address > VM_HOLE_END;
}

static void non_canonical_address(void) {}

static void traverse_page_table_recursive(
    generic_page_table_entry_t* table,
    int level,
    bool truncate_nx,
    vm_region_t* parent,
    page_table_traversal_callback_t callback,
    void* arg) {
  /* TODO(peter) If traverse_page_table_recursive turns out to be slow, it
  can be optimized by loop unrolling and specialization. This HOLE_START
  check always happens when level == 4 and i == 256. The level and
  entry->size checks can be specialized for each level. */
  int i;
  void* start = parent->start;
  for (i = 0; i < get_page_table_size(table); i++) {
    vm_region_t child;
    generic_page_table_entry_t* entry = &table[i];
    if (!address_is_canonical(entry)) {
        non_canonical_address();
        basic_assert(false);
    }

    if (start == VM_HOLE_START) {
        basic_assert(level == 4);
        basic_assert(i == 256);
        child.start = start;
        child.present = false;
        child.end = VM_HOLE_END;
        callback(&child, arg);
        start = VM_HOLE_END + 1;
    }

    child.present = entry->present;
    child.access.executable =
        parent->access.executable & !entry->not_executable;
    child.access.writable = parent->access.writable & entry->writable;
    child.access.user = parent->access.user & entry->user;
    child.start = start;

    start += (1ul << (12 + 9 * (level - 1)));
    child.end = start - 1;

    if ((truncate_nx && entry->not_executable) ||
        (!entry->present) ||
        (level == 1) ||
        (level == 2 && entry->size) ||
        (level == 3 && entry->size)) {
      callback(&child, arg);
    } else {
      traverse_page_table_recursive(
          follow_page_table_entry(entry),
          level - 1,
          truncate_nx,
          &child,
          callback,
          arg);
    }
  }
}

void traverse_page_table(
    generic_page_table_entry_t* l4,
    bool truncate_nx,
    page_table_traversal_callback_t callback,
    void* arg) {
  vm_region_t start_region;
  start_region.start = (void*) 0;
  start_region.present = true;
  start_region.access.writable = true;
  start_region.access.executable = true;
  start_region.access.user = true;
  traverse_page_table_recursive(
    l4, 4, truncate_nx, &start_region, callback, arg);
}

typedef struct {
  page_table_traversal_callback_t callback;
  void* arg;
  vm_region_t current_region;
  bool active;
} contiguous_callback_arg_t;

static void contiguous_callback(
    const vm_region_t* region,
    void* arg) {
  contiguous_callback_arg_t* callback_arg = (contiguous_callback_arg_t*) arg;
  vm_region_t* current_region = &callback_arg->current_region;

  if (!callback_arg->active) {
    *current_region = *region;
    callback_arg->active = true;
  } else if (!vm_region_are_adjacent(current_region, region) ||
             !vm_region_has_same_permissions(current_region, region)) {
    callback_arg->callback(current_region, callback_arg->arg);
    *current_region = *region;
  } else {
    current_region->end = region->end;
  }
}

void traverse_page_table_contiguous(
    generic_page_table_entry_t* l4,
    page_table_traversal_callback_t callback,
    void* arg) {
  contiguous_callback_arg_t callback_arg;
  callback_arg.callback = callback;
  callback_arg.arg = arg;
  callback_arg.active = false;
  traverse_page_table(l4, false, contiguous_callback, &callback_arg);
  basic_assert(callback_arg.active);
  callback(&callback_arg.current_region, arg);
}

#ifndef __USER_UNIT_TEST
static bool
is_write_protect_enabled(void)
{
    cr0_t cr0;
    get_cr0(&cr0);
    return cr0.write_protect;
}
#endif

static bool can_access_without_exception(generic_page_table_entry_t* l4,
                                         void* start,
                                         size_t size,
                                         bool write) {
    void* end = start + size - 1;
    /* Check for wrap around. */
    if (end < start) {
        return false;
    }

    write &= is_write_protect_enabled();

    for (;;) {
        vm_region_t region;
        unsigned long pfn;
        generic_page_table_entry_t* parent;
        int parent_level;
        /* TODO(peter): Repeatedly calling page_table_get_page on consecutive
         * pages is inefficient because most of the traversal is the same
         * between consecutive calls. If this proves to be slow, I could
         * implement a page table traversal that starts at given virtual address
         * and stops early. */
        if (!page_table_get_page(l4, start, &region, &pfn, &parent,
                                 &parent_level)) {
            return false;
        }
        if (write && !region.access.writable) {
            return false;
        }
        if (region.end >= end) {
            return true;
        }
        start = region.end + 1;
    }
}

bool page_table_readable_without_exception(generic_page_table_entry_t* l4,
                                           void* start,
                                           size_t size) {
    return can_access_without_exception(l4, start, size, false /* !write */);
}

bool page_table_writable_without_exception(generic_page_table_entry_t* l4,
                                           void* start,
                                           size_t size) {
    return can_access_without_exception(l4, start, size, true /* write */);
}
