#ifndef __PAGE_POOL_H_
#define __PAGE_POOL_H_

#ifndef __USER_UNIT_TEST
#    include "dr_api.h"
#endif

typedef uint64 umbra_pfn_t;

typedef struct _pagepool_t {
    umbra_pfn_t next_pfn;
    size_t free_pages;
    size_t num_pages;
} pagepool_t;

pagepool_t *
pagepool_kernel_init(size_t num_pages);
void
pagepool_kernel_exit(pagepool_t *pagepool);

bool
pagepool_empty(pagepool_t *pagepool);
umbra_pfn_t
pagepool_alloc(pagepool_t *pagepool);
void
pagepool_free(pagepool_t *pagepool, umbra_pfn_t pfn);

#endif
