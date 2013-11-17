#include "basic_types.h"
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#define PAGE_SIZE 4096
#define FAKE_PAGE_SHIFT 4

struct page {
    unsigned long unused;
    char data[PAGE_SIZE];
};

unsigned long
page_address(struct page *page)
{
    return (unsigned long) &page->data;
}

struct page*
pfn_to_page(unsigned long pfn)
{
    /* The opposite of the normal transformation. I just want to test that
     * pfn_to_page is being used (same with page_to_pfn). */
    return (struct page*) (pfn >> FAKE_PAGE_SHIFT);
}

unsigned long
page_to_pfn(struct page *page)
{
    return ((unsigned long) page) << FAKE_PAGE_SHIFT;
}

static struct page *last_alloc = NULL;

struct page*
alloc_page(unsigned flags)
{
    last_alloc = malloc(sizeof(struct page));
    return last_alloc;
}

void free_page(unsigned long addr)
{
    free((void*)(addr - __builtin_offsetof(struct page, data)));
}

#define GFP_KERNEL 0
#define DR_ASSERT(x) assert(x)

#define kmalloc(size, flags) malloc(size)
#define kfree(addr) free(addr)

#define printk(...) printf(__VA_ARGS__)

#include "pagepool.c"

int
main(void)
{
    pagepool_t *pool;
    pfn_t pfn1, pfn2;

    pool = pagepool_kernel_init(0);
    assert(pagepool_empty(pool));
    pagepool_kernel_exit(pool);

    pool = pagepool_kernel_init(1);
    assert(!pagepool_empty(pool));
    pfn1 = pagepool_alloc(pool);
    assert(pfn_to_page(pfn1) == last_alloc);
    assert(pagepool_empty(pool));
    pagepool_free(pool, pfn1);
    assert(!pagepool_empty(pool));
    pagepool_kernel_exit(pool);

    pool = pagepool_kernel_init(2);
    assert(!pagepool_empty(pool));
    pfn1 = pagepool_alloc(pool);
    assert(!pagepool_empty(pool));
    pfn2 = *((pfn_t *) &pfn_to_page(pfn1)->data[0]);
    assert(pfn2 == pagepool_alloc(pool));
    assert(pagepool_empty(pool));
    pagepool_free(pool, pfn1);
    pagepool_free(pool, pfn2);
    pagepool_kernel_exit(pool);

    return 0;
}
