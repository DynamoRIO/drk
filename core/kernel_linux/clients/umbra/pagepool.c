#ifndef __USER_UNIT_TEST
#  include <linux/gfp.h>
#  include <linux/mm.h>
#  include <linux/vmalloc.h>
#endif
#include "pagepool.h"

typedef union _poolpage_t {
    struct {
        pfn_t next_pfn;
    };
    byte bytes[PAGE_SIZE];
} poolpage_t;

static inline poolpage_t*
page_to_poolpage(struct page* page)
{
    return (poolpage_t*) page_address(page);
}

static inline poolpage_t*
pfn_to_poolpage(pfn_t pfn)
{
    return page_to_poolpage(pfn_to_page(pfn));
}

pagepool_t*
pagepool_kernel_init(size_t num_pages)
{
    pagepool_t *pool;
    pfn_t *prev = NULL;
    size_t i;

    pool = kmalloc(sizeof(pagepool_t), GFP_KERNEL);
    if (!pool) {
        return NULL;
    }

    prev = &pool->next_pfn;
    for (i = 0; ; i++) {
        struct page *linux_page;
        pool->free_pages = i;
        if (i == num_pages) {
            break;
        }
        linux_page = alloc_page(GFP_KERNEL);
        if (!linux_page) {
            DR_ASSERT(false && "could not allocate all of the requested pages");
            break;
        }
        *prev = page_to_pfn(linux_page);
        prev = &page_to_poolpage(linux_page)->next_pfn;
    }
    pool->num_pages = pool->free_pages;
    return pool;
}

bool
pagepool_empty(pagepool_t *pagepool)
{
    return pagepool->free_pages == 0;
}

pfn_t
pagepool_alloc(pagepool_t *pagepool)
{
    pfn_t pfn;
    if (pagepool_empty(pagepool)) {
        DR_ASSERT(false && "pagepool is empty, cannot alloc");
        return -1;
    }
    pagepool->free_pages -= 1;
    pfn = pagepool->next_pfn;
    pagepool->next_pfn = pfn_to_poolpage(pfn)->next_pfn;
    return pfn;
}

void
pagepool_kernel_exit(pagepool_t *pool)
{
    DR_ASSERT(pool->num_pages == pool->free_pages);
    while (!pagepool_empty(pool)) {
        free_page((unsigned long) pfn_to_poolpage(pagepool_alloc(pool)));
    }
    kfree(pool);
}

void
pagepool_free(pagepool_t *pool, pfn_t pfn)
{
    pfn_to_poolpage(pfn)->next_pfn = pool->next_pfn;
    pool->next_pfn = pfn;
    pool->free_pages += 1;
}
