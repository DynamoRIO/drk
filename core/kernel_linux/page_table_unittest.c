#include "basic_types.h"

#define MOCK_PAGE_OFFSET 4096ul

/* Define mocks. */
#define phys_to_virt(x) ((void*) (((uint64) (x)) + MOCK_PAGE_OFFSET))
#define virt_to_phys(x) ((void*) (((uint64) (x)) - MOCK_PAGE_OFFSET))

static bool write_protect_enabled = true;

static void
set_write_protect_enabled(bool enabled)
{
    write_protect_enabled = enabled;
}

static bool
is_write_protect_enabled()
{
    return write_protect_enabled;
}


#include "page_table.h"
#include "page_table.c"

#include <sys/mman.h>
#include <assert.h>
#include "string_wrapper.h"
#include <stdio.h>
#include <stdlib.h>

#define PAGE_TABLE_SIZE (512 * sizeof(generic_page_table_entry_t))
#define _1GB (1ul << 30)
#define _2MB (2ul << 20)
#define _4KB (4ul << 10)

static bool is_page_aligned(void* address) {
  return (((uint64) address) & 0xfff) == 0;
}

generic_page_table_entry_t* alloc_page_table(void) {
  generic_page_table_entry_t* table = (generic_page_table_entry_t*) mmap(
      NULL, PAGE_TABLE_SIZE, PROT_READ | PROT_WRITE,
      MAP_ANONYMOUS | MAP_SHARED, -1, 0);
  assert(table != MAP_FAILED);
  memset(table, 0, PAGE_TABLE_SIZE);
  return table; 
}

void free_page_table(generic_page_table_entry_t* table) {
  assert(is_page_aligned(table));
  munmap(table, PAGE_TABLE_SIZE);
}

typedef struct {
  void* data;
  size_t size;
  size_t capacity;
  size_t elem_size;
} vector_t;

void vector_init(vector_t* vector, unsigned long elem_size) {
  vector->size = 0;
  vector->capacity = 0;
  vector->data = NULL;
  vector->elem_size = elem_size;
}

void vector_free(vector_t* vector) {
  free(vector->data);
}

void vector_append(vector_t* vector, void *elem) {
  if (vector->size == vector->capacity) {
    vector->capacity = (vector->capacity + 1) * 2;
    void* tmp = malloc(vector->capacity * vector->elem_size);
    memcpy(tmp, vector->data, vector->size * vector->elem_size);
    free(vector->data);
    vector->data = tmp;
  }

  memcpy(vector->data + vector->size * vector->elem_size, elem,
         vector->elem_size);
  vector->size++;
}

void* vector_get(vector_t *vector, size_t i)
{
   return vector->data + i * vector->elem_size; 
}

#define VECTOR_TYPE(name, type) \
typedef struct {\
  type* data;\
  size_t size;\
  size_t capacity;\
  size_t elem_size;\
} name ## _vector_t;\
\
void name ## _vector_init(name ## _vector_t *vector)\
{\
    vector_init((vector_t*) vector, sizeof(type));\
}\
\
void name ## _vector_free(name ## _vector_t *vector)\
{\
    vector_free((vector_t*) vector);\
}\

VECTOR_TYPE(vm_region, vm_region_t);
VECTOR_TYPE(pfn, unsigned long);

void region_recorder_callback(const vm_region_t* region, void* arg) {
  vector_t* vector = (vector_t*) arg;
  vector_append(vector, (void*) region);
}

void pfn_recorder_callback(unsigned long pfn, void* arg) {
  vector_t* vector = (vector_t*) arg;
  vector_append(vector, (void*) &pfn);
}

#define assert_sequential(first, seq_start, n) do {\
    int i;\
    for (i = 0; i < n; i++) {\
        assert((first)[i] == seq_start + i);\
    }\
} while(0)


int main() {

    {
        pfn_vector_t pfns;
        generic_page_table_entry_t* l4 = alloc_page_table();
        generic_page_table_entry_t* l3 = alloc_page_table();
        l4[0].present = 1;
        l4[0].next_pfn = virt_to_pfn(l3);
        assert(follow_page_table_entry(&l4[0]) == l3);

        pfn_vector_init(&pfns);
        depth_first_traverse_page_table(l4, pfn_recorder_callback, &pfns);
        assert(pfns.size == 2);
        assert(pfns.data[0] == virt_to_pfn(l3));
        assert(pfns.data[1] == virt_to_pfn(l4));

        pfn_vector_free(&pfns);
        free_page_table(l4);
        free_page_table(l3);
    }

    {
        pfn_vector_t pfns;
        vm_region_vector_t regions;
        vm_region_t region;
        unsigned long pfn;
        unsigned long pa;
        generic_page_table_entry_t* l4 = alloc_page_table();
        generic_page_table_entry_t* l3 = alloc_page_table();
        generic_page_table_entry_t* l2 = alloc_page_table();
        generic_page_table_entry_t* l1 = alloc_page_table();
        generic_page_table_entry_t* parent;
        int parent_level;
        virtual_address_t va;

        // Test 1: An empty page table.
        vm_region_vector_init(&regions);
        traverse_page_table_contiguous(l4, region_recorder_callback, &regions);
        assert(regions.size == 1);
        assert(!regions.data[0].present);
        assert(regions.data[0].start == (void*) 0x0ul);
        assert(regions.data[0].end == (void*) -1ul);

        /* Allocate three pages (1GB, 2MB, and 4KB) to virtually contiguous
         * addresses [0, 1GB + 2MB + 4KB - 1]. */
        l4[0].present = 1;
        l4[0].writable = 1;
        l4[0].next_pfn = virt_to_pfn(l3);

        l3[0].present = 1;
        l3[0].writable = 1;
        l3[0].size = 1;
        l3[0].next_pfn = 5555;
        l3[1].present = 1;
        l3[1].writable = 1;
        l3[1].next_pfn = virt_to_pfn(l2);

        l2[0].present = 1;
        l2[0].writable = 1;
        l2[0].size = 1;
        l2[0].next_pfn = 3333;
        l2[1].present = 1;
        l2[1].writable = 1;
        l2[1].next_pfn = virt_to_pfn(l1);

        l1[0].present = 1;
        l1[0].writable = 1;
        l1[0].next_pfn = 1111;
        
        // Test 2: all three regions have the same RWXU permissions.
        vm_region_vector_free(&regions);
        vm_region_vector_init(&regions);
        traverse_page_table_contiguous(l4, region_recorder_callback, &regions);
        assert(regions.size == 2);
        assert(regions.data[0].start == (void*) 0x0ul);
        assert(regions.data[0].end == (void*) (_1GB + _2MB + _4KB - 1ul));
        assert(regions.data[0].present);
        assert(regions.data[0].access.writable);
        assert(regions.data[0].access.executable);
        assert(!regions.data[0].access.user);
        assert(regions.data[1].start == (void*) (_1GB + _2MB + _4KB));
        assert(regions.data[1].end == (void*) -1ul);
        assert(!regions.data[1].present);

        // Test 3: using the page table get region interface.
        page_table_get_region(l4, (void*) (_1GB * 3ul), &region);
        assert(!region.present);
        assert(region.start == (void*) (_1GB + _2MB + _4KB));
        assert(region.end == (void*) -1ul);
        page_table_get_region(l4, (void*) _1GB, &region);
        assert(region.start == (void*) 0x0ul);
        assert(region.end == (void*) (_1GB + _2MB + _4KB - 1ul));
        assert(region.present);
        assert(region.access.writable);
        assert(region.access.executable);
        assert(!region.access.user);

        // Test page_table_get_page.
        assert(page_table_get_page(l4, (void*) (2), &region, &pfn, &parent,
                                   &parent_level));
        assert(region.present);
        assert(region.start == (void*) 0);
        assert(region.end - region.start + 1 == _1GB);
        assert(pfn == 5555);
        assert(parent_level == 3);
        assert(parent == &l3[0]);

        assert(page_table_get_page(l4, (void*) (_4KB), &region, &pfn, &parent,
                                   &parent_level));
        assert(region.present);
        assert(region.start == (void*) 0);
        assert(region.end - region.start + 1 == _1GB);
        assert(pfn == 5555 + 1);
        assert(parent_level == 3);
        assert(parent == &l3[0]);

        assert(page_table_get_page(l4, (void*) (_1GB + 2), &region, &pfn,
                                   &parent, &parent_level));
        assert(region.present);
        assert(region.start == (void*) _1GB);
        assert(region.end - region.start + 1 == _2MB);
        assert(pfn == 3333);
        assert(parent_level == 2);
        assert(parent == &l2[0]);

        assert(page_table_get_page(l4, (void*) (_1GB + _4KB * 2), &region, &pfn,
                                   &parent, &parent_level));
        assert(region.present);
        assert(region.start == (void*) _1GB);
        assert(region.end - region.start + 1 == _2MB);
        assert(pfn == 3333 + 2);
        assert(parent_level == 2);
        assert(parent == &l2[0]);

        assert(page_table_get_page(l4, (void*) (_1GB + _2MB + 2), &region, &pfn,
                                   &parent, &parent_level));
        assert(region.present);
        assert(region.start == (void*) (_1GB + _2MB));
        assert(region.end - region.start + 1 == _4KB);
        assert(pfn == 1111);
        assert(parent_level == 1);
        assert(parent == &l1[0]);

        assert(!page_table_get_page(l4, (void*) (_1GB + _2MB + _4KB), &region,
                                    &pfn, &parent, &parent_level));
        assert(!region.present);
        assert(parent_level == 1);
        assert(parent == &l1[1]);
        assert(!page_table_get_page(l4, (void*) (-1), &region, &pfn, &parent,
                                    &parent_level));
        assert(!region.present);
        assert(parent_level == 4);
        assert(parent == &l4[511]);

        va.virtual_address = 0;
        va.l3_index = 2;
        assert(!page_table_get_page(l4, va.virtual_address, &region, &pfn,
                                    &parent, &parent_level));
        assert(!region.present);
        assert(parent_level == 3);
        assert(parent == &l3[2]);

        va.virtual_address = 0;
        va.l3_index = 1;
        va.l2_index = 2;
        assert(!page_table_get_page(l4, va.virtual_address, &region, &pfn,
                                    &parent, &parent_level));
        assert(!region.present);
        assert(parent_level == 2);
        assert(parent == &l2[2]);

        va.virtual_address = 0;
        va.l3_index = 1;
        va.l2_index = 1;
        va.l1_index = 1;
        assert(!page_table_get_page(l4, va.virtual_address, &region, &pfn,
                                    &parent, &parent_level));
        assert(!region.present);
        assert(parent_level == 1);
        assert(parent == &l1[1]);

        // Test page_table_get_physical_address.
        assert(page_table_get_physical_address(l4, (void*) (2), &pa));
        assert(pa == ((5555) << 12) + 2);
        assert(page_table_get_physical_address(l4, (void*) (_4KB), &pa));
        assert(pa == (5556 << 12));
        assert(!page_table_get_physical_address(l4, (void*) (-1), &pa));

        // Test the page_table_readable/writable_without_exception interface.
        set_write_protect_enabled(true);
        assert(page_table_readable_without_exception(l4, (void*) (0), _1GB + _2MB + _4KB));
        assert(page_table_writable_without_exception(l4, (void*) (0), _1GB + _2MB + _4KB));
        assert(!page_table_readable_without_exception(l4, (void*) (0), _1GB + _2MB + _4KB + 1));
        assert(!page_table_readable_without_exception(l4, (void*) (0), _1GB * 3));
        assert(!page_table_writable_without_exception(l4, (void*) (0), _1GB + _2MB + _4KB + 1));
        assert(!page_table_writable_without_exception(l4, (void*) (0), _1GB * 3));

        // Test 4: make the 2mb page non-writable.
        // Check to see that the region is split into three regions.
        vm_region_vector_free(&regions);
        vm_region_vector_init(&regions);
        l2[0].writable = 0;

        assert(page_table_writable_without_exception(l4, (void*) 0, 1));
        set_write_protect_enabled(false);
        assert(page_table_writable_without_exception(l4, (void*) _1GB, 1));
        set_write_protect_enabled(true);
        assert(!page_table_writable_without_exception(l4, (void*) _1GB, 1));
        assert(page_table_writable_without_exception(l4, (void*) (_1GB + _2MB), 1));

        traverse_page_table_contiguous(l4, region_recorder_callback, &regions);
        assert(regions.size == 4);
        assert(regions.data[0].start == (void*) 0x0ul);
        assert(regions.data[0].end == (void*) _1GB - 1ul);
        assert(regions.data[0].present);
        assert(regions.data[0].access.writable);
        assert(regions.data[0].access.executable);
        assert(!regions.data[0].access.user);

        assert(regions.data[1].start == (void*) _1GB);
        assert(regions.data[1].end == (void*) _1GB + _2MB - 1ul);
        assert(regions.data[1].present);
        assert(!regions.data[1].access.writable);
        assert(regions.data[1].access.executable);
        assert(!regions.data[1].access.user);

        assert(regions.data[2].start == (void*) _1GB + _2MB);
        assert(regions.data[2].end == (void*) _1GB + _2MB + _4KB - 1ul);
        assert(regions.data[2].present);
        assert(regions.data[2].access.writable);
        assert(regions.data[2].access.executable);
        assert(!regions.data[2].access.user);

        assert(regions.data[3].start == (void*) (_1GB + _2MB + _4KB));
        assert(regions.data[3].end == (void*) -1ul);
        assert(!regions.data[3].present);
        vm_region_vector_free(&regions);

		// Test 5: Check that the page_table_get_region picks up the split region.
        page_table_get_region(l4, (void*) (_1GB + 42), &region);
        assert(region.start == (void*) (_1GB));
        assert(region.end == (void*) (_1GB + _2MB - 1ul));
        assert(!region.access.writable);
        assert(region.access.executable);
        assert(!region.access.user);

        // Test depth_first_traverse_page_table
        pfn_vector_init(&pfns);
        depth_first_traverse_page_table(l4, pfn_recorder_callback, &pfns);
        assert(pfns.size == 1 +                   // l4
                            1 + ((_1GB) >> 12) +  // l3 + 1GB page
                            1 + ((_2MB) >> 12) +  // l2 + 2MB page
                            1 + 1);               // l1 + 4KB page
        assert_sequential(&pfns.data[0],          5555, (_1GB) >> 12);
        assert_sequential(&pfns.data[_1GB >> 12], 3333, (_2MB) >> 12);
        assert(pfns.data[((_1GB + _2MB) >> 12) + 0] == 1111);
        assert(pfns.data[((_1GB + _2MB) >> 12) + 1] == virt_to_pfn(l1));
        assert(pfns.data[((_1GB + _2MB) >> 12) + 2] == virt_to_pfn(l2));
        assert(pfns.data[((_1GB + _2MB) >> 12) + 3] == virt_to_pfn(l3));
        assert(pfns.data[((_1GB + _2MB) >> 12) + 4] == virt_to_pfn(l4));
        pfn_vector_free(&pfns);

        free_page_table(l4);
        free_page_table(l3);
        free_page_table(l2);
        free_page_table(l1);

    }

    /* Test some tricky bits with the hole in the VM. */
    {
        vm_region_vector_t regions;
        vm_region_t region;
        unsigned long pfn;
        generic_page_table_entry_t* l4 = alloc_page_table();
        generic_page_table_entry_t* l3_before = alloc_page_table();
        generic_page_table_entry_t* l3_after = alloc_page_table();
        generic_page_table_entry_t* parent;
        int parent_level;

        /* Simple test when empty. Make sure that the code doesn't screw up when
         * accesssing the hole. */
        page_table_get_region(l4, VM_HOLE_START, &region);
        assert(!region.present);
        assert(region.start == (void*) 0ul);
        assert(region.end == (void*) -1ul);
        assert(!page_table_get_page(l4, VM_HOLE_START, &region, &pfn, &parent,
                                    &parent_level));
        assert(parent == NULL);
        assert(!page_table_get_page(l4, VM_HOLE_START + 10, &region, &pfn,
                                    &parent, &parent_level));
        assert(parent == NULL);
        assert(!page_table_get_page(l4, VM_HOLE_END, &region, &pfn, &parent,
                                    &parent_level));
        assert(parent == NULL);
        assert(!page_table_readable_without_exception(l4, VM_HOLE_START, 1));
        assert(!page_table_readable_without_exception(l4, VM_HOLE_START + 10, 1));
        assert(!page_table_readable_without_exception(l4, VM_HOLE_END, 1));
        assert(!page_table_writable_without_exception(l4, VM_HOLE_START, 1));
        assert(!page_table_writable_without_exception(l4, VM_HOLE_START + 10, 1));
        assert(!page_table_writable_without_exception(l4, VM_HOLE_END, 1));

        /* Add a R-X 1GB page before and after the hole. */
        l4[255].present = 1;
        l4[255].next_pfn = virt_to_pfn(l3_before);
        l3_before[511].present = 1;
        l3_before[511].size = 1;

        l4[256].present = 1;
        l4[256].next_pfn = virt_to_pfn(l3_after);
        l3_after[0].present = 1;
        l3_after[0].size = 1;

        vm_region_vector_init(&regions);
        traverse_page_table_contiguous(l4, region_recorder_callback, &regions);
        assert(regions.size == 5);
        assert(!regions.data[0].present);
        assert(regions.data[0].start == (void*) 0);
        assert(regions.data[0].end == VM_HOLE_START - _1GB - 1);
        assert(regions.data[1].present);
        assert(regions.data[1].start == VM_HOLE_START - _1GB);
        assert(regions.data[1].end == VM_HOLE_START - 1);
        assert(!regions.data[2].present);
        assert(regions.data[2].start == VM_HOLE_START);
        assert(regions.data[2].end == VM_HOLE_END);
        assert(regions.data[3].present);
        assert(regions.data[3].start == VM_HOLE_END + 1);
        assert(regions.data[3].end == VM_HOLE_END + _1GB);
        assert(!regions.data[4].present);
        assert(regions.data[4].start == VM_HOLE_END + _1GB + 1);
        assert(regions.data[4].end == (void*) -1);
        vm_region_vector_free(&regions);

        page_table_get_region(l4, VM_HOLE_START - 1, &region);
        assert(region.present);
        assert(!region.access.writable);
        assert(region.access.executable);
        assert(!region.access.user);
        assert(region.start == VM_HOLE_START - _1GB);
        assert(region.end == VM_HOLE_START - 1);

        page_table_get_region(l4, VM_HOLE_START, &region);
        assert(!region.present);
        assert(region.start == VM_HOLE_START);
        assert(region.end == VM_HOLE_END);

        page_table_get_region(l4, VM_HOLE_END + 1, &region);
        assert(region.present);
        assert(!region.access.writable);
        assert(region.access.executable);
        assert(!region.access.user);
        assert(region.start == VM_HOLE_END + 1);
        assert(region.end == VM_HOLE_END + _1GB);

        free_page_table(l3_after);
        free_page_table(l3_before);
        free_page_table(l4);
    }

  return 0;
}
