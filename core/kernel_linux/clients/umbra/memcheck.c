#include <linux/spinlock.h>
#include <linux/bit_spinlock.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <asm/stacktrace.h>
#include "dr_api.h"
#include "umbra.h"
#include "global.h"
#include "shadow.h"
#include "utils.h"
#include "dr_kernel_utils.h"
#include "memcheck.h"

#define MAX_NUM_MEMCHECK_REPORTS 64

typedef struct {
    /* Do addressability checking. Required for any other checks. When false,
     * the following is still done:
     *  o repstr converted to explicit loops
     *  o shadow calculated for all memory references
     */
    bool check_addr;

    /* Check and propagate definedness. */
    bool check_defined;

    /* Check the ends of kernel stacks. */
    bool check_stack;
} memcheck_options_t;

typedef struct {
    memcheck_options_t options;
    bool exited;
} memcheck_proc_info_t;

static memcheck_proc_info_t memcheck_proc_info;

#define MEMCHECK_OPTION(name) memcheck_proc_info.options.name

typedef struct {
    bool in_slub_function;
    bool in_slub_function_sticky;
    byte *stringop_pc;
    byte *cache_pc;
    byte *code_cache_start;
    byte *slowpath_code[DR_REG_STOP_64 + 1];
    byte *code_cache_end;

    /* Shadow for movs's read operand. */
    /* TODO(peter): Ensure that this is cache aligned. */
    reg_t movs_read_shadow;

    bool check_def_enabled;

    /* Error reports. */
    bool reporting_enabled;
    bool reset_report_count;
    int report_count; 
    int report_read_index;
    int report_write_index;
    memcheck_report_t reports[MAX_NUM_MEMCHECK_REPORTS];

    /* Statistics. */
    uint64 num_init_addressable_bytes;
    uint64 num_init_unaddressable_bytes;
    uint64 num_reports;
    uint64 num_missed_reports;
    uint64 num_disabled_reports;
    uint64 num_slowpath_exits;
    uint64 num_slowpath_slub_function;
    uint64 num_slowpath_false_negatives;
    uint64 num_eos_read;
} memcheck_tls_t;

#ifdef DEBUG
static memcheck_tls_t *mtls[100];
#endif

/* For easy access from stat reporting and error reporting code. They can't use
 * dr_get_current_drcontext b/c they run in the kernel context. */
DEFINE_PER_CPU(memcheck_tls_t*, memcheck_tls);

#define CODE_CACHE_SIZE PAGE_SIZE*2

static inline memcheck_tls_t *
memcheck_tls(umbra_info_t *info)
{
    return (memcheck_tls_t*) info->client_tls_data;
}

static inline memcheck_tls_t *
get_memcheck_tls(void)
{
    return memcheck_tls(umbra_get_info());
}

/* The number of CPUs that we've called flush_cpu_slab on. We don't use a proper
 * barrier because of deadlock: smp_init in dynamo.c waits for the main CPU to
 * finish initilization (including its thread init routine) before calling the
 * other CPUs' thread init routines. 
 */
int slab_flush_count;
void *slab_flush_mutex;

typedef enum {
    PERMISSION_UNKNOWN                 = 0x0,  /* 0000 0000 */
    PERMISSION_UNADDRESSABLE           = 0x1,  /* 0000 0001 */
    PERMISSION_ADDRESSABLE             = 0x2,  /* 0000 0010 */
    PERMISSION_DEFINED                 = 0x4,  /* 0000 0100 */
    /* Different variants of PERMISSION_UNADDRESSABLE. They are all true when
     * anded with PERMISSION_UNADDRESSABLE but have extra higher bits set for
     * debugging. */
    PERMISSION_UNADDRESSABLE_INIT      = 0x9,  /* 0000 1001 */
    PERMISSION_UNADDRESSABLE_KFREE     = 0x11, /* 0001 0001 */
    PERMISSION_UNADDRESSABLE_SLAB_FREE = 0x19, /* 0001 1001 */
    PERMISSION_UNADDRESSABLE_GET_PAGE  = 0x21, /* 0010 0001 */
    PERMISSION_UNADDRESSABLE_EOS       = 0x29, /* 0010 1001 */
} permission_t;

static inline reg_t
get_n_byte_mask(reg_t single_byte_mask, size_t n)
{
    reg_t mask;
    DR_ASSERT((single_byte_mask & 0xff) == single_byte_mask);
    DR_ASSERT(n <= sizeof(reg_t));
    memset(&mask, single_byte_mask, n);
    return mask;
}

static inline reg_t
get_8_byte_mask(reg_t single_byte_mask)
{
    return get_n_byte_mask(single_byte_mask, 8);
}

#define KSYM(name, type, decl) decl;
struct {
#include "ksymsx.h"
} kernel_symbols;
#undef KSYM

static bool
slub_function_on_stack(dr_mcontext_t *mc);

static void
set_shadow_permission(memory_map_t *map, void *first, void *last,
                      permission_t permission) {
    void *shd_addr[MAX_NUM_SHADOWS];
    reg_t shd_size[MAX_NUM_SHADOWS];
    compute_shd_memory_addr_ex(map, first, shd_addr);
    compute_shd_memory_size(last - first + 1, shd_size);
    /* For now, we assume 1:1 app:shadow. Encapsulate shadow modifiacations here
     * so the ratio can be easily changed in the future.
     */
    DR_ASSERT(shd_size[0] == last - first + 1);
    memset(shd_addr[0], permission, shd_size[0]);
}

static byte
get_shadow_byte(memory_map_t *map, byte *addr)
{
    void *shd_addr[MAX_NUM_SHADOWS];
    compute_shd_memory_addr_ex(map, addr, shd_addr);
    return *(byte*) shd_addr[0];
}

static permission_t
get_byte_permission(memory_map_t *map, byte *addr)
{
    return (permission_t) get_shadow_byte(map, addr);
}

typedef void (*for_each_map_callback_t)(memory_map_t *map, void *first,
                                        void *last, void *data);

#define FOR_EACH_MAP(start, size, map, current_last, code) \
do {\
    umbra_info_t *info = umbra_get_info();\
\
    /* Don't support wraparound. */\
    DR_ASSERT(start + size >= start || start + size == 0);\
    for (;;) {\
        if (size == 0) {\
            break;\
        }\
        map = memory_map_thread_lazy_add(info, start);\
        current_last = min(start + size - 1, map->app_end - 1);\
        code\
        if (start + size < map->app_end ||\
            map->app_end == 0) {\
            break;\
        }\
        size -= map->app_end - start;\
        start = map->app_end;\
    }\
} while(0)

static void
set_memory_permission(void *start, size_t size, permission_t permission)
{
    memory_map_t *map;
    void *last;
    FOR_EACH_MAP(start, size, map, last,
        set_shadow_permission(map, start, last, permission);
    );
}

static bool
test_shadow(void *start, size_t size, permission_t permission, bool all)
{
    memory_map_t *map;
    void *last;
    size_t i;
    FOR_EACH_MAP(start, size, map, last,
        for (i = 0; i + start <= last; i++) {
            bool match;
            permission_t byte_permission = get_byte_permission(map, start + i);
            if (permission == PERMISSION_UNKNOWN) {
                match = byte_permission == PERMISSION_UNKNOWN;
            } else {
                match = TESTALL(permission, byte_permission);
            }
            /* TODO(peter): Make this faster with multi-byte comparisons. */
            if (match) {
                if (!all) {
                    return true;
                } 
            } else if (all) {
                return false;
            }
        }
    );
    return all;
}

/* Do any bytes have the given permission? */
inline static bool
test_shadow_any(void *start, size_t size, permission_t permission)
{
    return test_shadow(start, size, permission, false);
}

/* Do none of bytes have the given permission? */
inline static bool
test_shadow_none(void *start, size_t size, permission_t permission)
{
    return !test_shadow_any(start, size, permission);
}

/* Do all of the bytes have the given permission? */
inline static bool
test_shadow_all(void *start, size_t size, permission_t permission)
{
    return test_shadow(start, size, permission, true);
}

#ifdef DEBUG
/* Note that is_memory_ok_to_free ignores PERMISSION_UNKNOWN. This is necessary
 * because memory freed with kfree can have PERMISSION_UNKNOWN because kmalloc
 * (which is inlined and thus not intercepted by us) calls kmalloc_large (which
 * we don't intercept) which returns memory directly from the page allocator
 * (which is unknown to us).
 */
static bool
is_memory_ok_to_free(void *start, size_t size)
{
    return test_shadow_none(start, size, PERMISSION_UNADDRESSABLE);
}

static bool
is_memory_ok_to_alloc(void *start, size_t size)
{
    memory_map_t *map;
    void *last;
    size_t i;
    FOR_EACH_MAP(start, size, map, last,
        for (i = 0; i + start <= last; i++) {
            /* TODO(peter): Make this faster with multi-byte comparisons. */
            permission_t perm = get_byte_permission(map, start + i);
            if (TESTANY(PERMISSION_ADDRESSABLE | PERMISSION_DEFINED, perm)) {
                return false;
            }
            #if 0
            /* When allocations are larger than SLUB_MAX_SIZE, they can be
             * returned from unknown memory as opposed to unaddressable because
             * kmalloc_large uses __get_free_pages directly. */
            if (size <= SLUB_MAX_SIZE && perm == PERMISSION_UNKNOWN) {
                return false; 
            }
            #endif
        }
    );
    return true;
}
#endif

static bool
safe_ksize(const void *x, size_t *size)
{
    if (ZERO_OR_NULL_PTR(x)) {
	/* kfree(NULL or ZERO_SIZE_PTR) is a nop, however calling ksize(NULL or
         * ZERO_SIZE_PTR) is an error. */
        *size = 0;
    } else if (!virt_addr_valid((unsigned long) x)) {
        /* kfree and ksize rely on virt_to_head_page(x), which requires
         * virt_addr_valid(x) via virt_to_page(x). Rather than having ksize
         * barf, we flag an error here. 
         */
        *size = 0;
        printk("safe_ksize !virt_addr_valid(%p)\n", x);
        return false;
    } else {
        struct page *page = virt_to_head_page(x);
        if (!PageSlab(page) && !PageCompound(page)) {
            /* Don't call ksize in this case because we'll hit WARN_ON. Just
             * emulate what ksize does in this case after WARN_ON.  */
            *size = PAGE_SIZE << compound_order(page);
            printk("safe_ksize !PageSlab && !PageCompound (%p, %p)\n", x, page);
            return false;
        }
        *size = ksize(x);
    }
    return true;
}

static void
set_page_permission(struct page *slab, permission_t permission)
{
    /* Whenever the slub frees a page, it frees a compound page, so this check
     * isn't necessary. However, on some error paths (i.e., when a page is being
     * freed that isn't a compound page, the allocator frees that single page,
     * which has the same effect as us using 0 as the order. */
    size_t size = PAGE_SIZE << (PageCompound(slab) ? compound_order(slab) : 0);
    set_memory_permission(page_address(slab), size, permission);
}


/* We need to do the kfree wrapping in pre_kfree because ksize doesn't work once
 * the memory has been deallocated. */
static inline void
pre_kfree(dr_mcontext_t *mc, const void *x)
{
    struct page *page;
    size_t size;

    if (ZERO_OR_NULL_PTR(x)) {
        return;
    }
    /* We can only be certain that a single byte was allocated by kmalloc
     * (kmalloc returns NULL for 0 byte requests).
     * TODO(peter): We could have a separate designation for redzone bytes, so
     * we could check for addressable or redzone. */
#ifdef DEBUG
    DR_ASSERT(is_memory_ok_to_free((void*) x, 1));
#endif
    page = virt_to_head_page(x);
    /* For non-slab pages (i.e., large pages returned by kmalloc_large
     * indirectly through both __kmalloc and kmalloc), kfree directly returns
     * the page to the page allocator with put_page. We don't see that call b/c
     * we wrap __slab_free instead of put_page, so we set the page to
     * PERMISSION_UNKNOWN here. */
    if (!PageSlab(page)) {
        set_page_permission(page, PERMISSION_UNKNOWN);
        return;
    }
    /* It's an error if safe_ksize returns false because the kernel is trying to
     * deallocate memory that couldn't have possibly been allocated with
     * kmalloc. */
    if (!safe_ksize(x, &size)) {
#ifdef DEBUG
        DR_ASSERT(false);
#endif
        return;
    }
    set_memory_permission((void*) x, size, PERMISSION_UNADDRESSABLE_KFREE);
}

static inline void
post_kfree(dr_mcontext_t *mc, bool args_valid, reg_t void_ret, const void *x)
{
}

static inline void
pre___kmalloc(dr_mcontext_t *mc, size_t size, gfp_t flags)
{
}

static void
track_allocation(bool args_valid, void *addr, size_t size, gfp_t flags,
                 bool has_ctor)
{
    size_t max_size;
    bool could_be_defined;
    /* We'd get better coverage if ksize returned the kmem_cache.size instead of
     * kmem_cache.objsize.  */
    if (safe_ksize(addr, &max_size)) {
#ifdef DEBUG
        DR_ASSERT(!args_valid || max_size >= size);
#endif
    } else {
        max_size = 0;
#ifdef DEBUG
        DR_ASSERT(false);
#endif
    }
#ifdef DEBUG
    /* TODO(peter): This check can fail because we miss slabs due to CPUs being
     * set offline before startup. See comment in
     * memcheck_init_shadow_slab_cache. */
    DR_ASSERT(is_memory_ok_to_alloc(addr, max_size));
#endif
    could_be_defined = TESTANY(flags, __GFP_ZERO) || !args_valid || has_ctor;
    set_memory_permission(addr, args_valid ? size : max_size,
                          could_be_defined ? PERMISSION_DEFINED :
                                             PERMISSION_ADDRESSABLE);
}

static inline void
post___kmalloc(dr_mcontext_t *mc, bool args_valid, void *ret, size_t size, gfp_t flags)
{
    track_allocation(args_valid, ret, size, flags, false);
}

static inline void
pre___kmalloc_track_caller(dr_mcontext_t *mc, size_t size, gfp_t flags, unsigned long caller)
{
    pre___kmalloc(mc, size, flags);
}

static inline void
post___kmalloc_track_caller(dr_mcontext_t *mc, bool args_valid, void *ret, size_t size, gfp_t flags, unsigned long caller)
{
    post___kmalloc(mc, args_valid, ret, size, flags);
}

static inline void
pre___kmalloc_node(dr_mcontext_t *mc, size_t size, gfp_t flags, int node)
{
    pre___kmalloc(mc, size, flags);
}

static inline void
post___kmalloc_node(dr_mcontext_t *mc, bool args_valid, void *ret, size_t size, gfp_t flags, int node)
{
    post___kmalloc(mc, args_valid, ret, size, flags);
}

static inline void
pre___kmalloc_node_track_caller(dr_mcontext_t *mc, size_t size, gfp_t flags, int node, unsigned long caller)
{
    pre___kmalloc_node(mc, size, flags, node);
}

static inline void
post___kmalloc_node_track_caller(dr_mcontext_t *mc, bool args_valid, void *ret, size_t size, gfp_t flags, int node, unsigned long caller)
{
    post___kmalloc_node(mc, args_valid, ret, size, flags, node);
}

static inline void
pre_kmem_cache_alloc(dr_mcontext_t *mc, struct kmem_cache *cachep, gfp_t flags)
{
    pre___kmalloc(mc, cachep->objsize, flags);
}

static inline void
post_kmem_cache_alloc(dr_mcontext_t *mc, bool args_valid, void *ret, struct kmem_cache *cachep, gfp_t flags)
{
    track_allocation(args_valid, ret, args_valid ? cachep->objsize : 0, flags,
                     args_valid ? cachep->ctor != NULL : true);
}

static inline void 
pre_kmem_cache_alloc_node(dr_mcontext_t *mc, struct kmem_cache *cachep, gfp_t flags, int node)
{
    pre_kmem_cache_alloc(mc, cachep, flags);
}

static inline void 
post_kmem_cache_alloc_node(dr_mcontext_t *mc, bool args_valid, void *ret, struct kmem_cache *cachep, gfp_t flags, int node)
{
    post_kmem_cache_alloc(mc, args_valid, ret, cachep, flags);
}

static inline void
pre_kmem_cache_free(dr_mcontext_t *mc, struct kmem_cache *cachep, void *objp)
{
    /* Do this in pre_kmem_cache_free to be consistent with pre_kfree. */
#ifdef DEBUG
    DR_ASSERT(is_memory_ok_to_free(objp, cachep->objsize));
#endif
    set_memory_permission((void*) objp, cachep->size,
                          PERMISSION_UNADDRESSABLE_SLAB_FREE);
}

static inline void
post_kmem_cache_free(dr_mcontext_t *mc, bool args_valid, reg_t ret, struct kmem_cache *cachep, void *objp)
{
}

static inline void
pre_new_slab(dr_mcontext_t *mc, struct kmem_cache *s, gfp_t flags, int node)
{
}

static inline void
post_new_slab(dr_mcontext_t *mc, bool args_valid, struct page *ret, struct kmem_cache *s, gfp_t flags, int node)
{
    if (!ret) {
        return;
    }
    /* TODO(peter): Check if the slab is unknown? */
    set_page_permission(ret, PERMISSION_UNADDRESSABLE_GET_PAGE);
}

static inline void
pre___free_slab(dr_mcontext_t *mc, struct kmem_cache *s, struct page *page)
{
    /* TODO(peter): Deallocate shadow pages instead of marking them
     * PERMISSION_UNKNOWN. This is complicated because we need to do a TLB
     * shootdown (otherwise, the old shadow page translations might exist in
     * other processors' TLBs).
     */
    /* TODO(peter): Check if the slab is only unaddressable? */
    set_page_permission(page, PERMISSION_UNKNOWN);
}

static inline void
post___free_slab(dr_mcontext_t *mc, bool args_valid, reg_t ret, struct kmem_cache *s, struct page *page)
{
}

static inline void
pre_schedule(dr_mcontext_t *mc)
{
    memcheck_tls_t *tls = get_memcheck_tls();
    tls->in_slub_function = tls->in_slub_function_sticky;
}

static inline void
post_schedule(dr_mcontext_t *mc, bool args_valid, reg_t ret)
{
    memcheck_tls_t *tls = get_memcheck_tls();
    tls->in_slub_function = tls->in_slub_function_sticky;
}

/* Unused wrappers. Just included in_slub_function(). */
static inline void
pre_kmem_cache_shrink(dr_mcontext_t *mc, struct kmem_cache *cachep)
{
}

static inline void
post_kmem_cache_shrink(dr_mcontext_t *mc, bool args_valid, int ret, struct kmem_cache *cachep)
{
}

static inline void
pre_ksize(dr_mcontext_t *mc, const void *x)
{
}

static inline void
post_ksize(dr_mcontext_t *mc, bool args_valid, size_t ret, const void *x)
{
}

static inline void
pre_kmem_cache_create (dr_mcontext_t *mc, const char *name, size_t size, size_t align,
                       unsigned long flags, void (*ctor)(void *))
{
}

static inline void
post_kmem_cache_create (dr_mcontext_t *mc, bool args_valid, struct kmem_cache *ret, const char *name, size_t size,
                        size_t align, unsigned long flags, void (*ctor)(void *))
{
}

static inline void
pre_kmem_cache_destroy(dr_mcontext_t *mc, struct kmem_cache *cachep)
{
}

static inline void
post_kmem_cache_destroy(dr_mcontext_t *mc, bool args_valid, reg_t void_ret, struct kmem_cache *cachep)
{
}

static inline void
pre_flush_cpu_slab(dr_mcontext_t *mc, void *d)
{
}
static inline void
post_flush_cpu_slab(dr_mcontext_t *mc, bool args_valid, reg_t void_ret, void *d)
{
}

static inline void
pre_deactivate_slab(dr_mcontext_t *mc, struct kmem_cache *s, struct kmem_cache_cpu *c) 
{
}

static inline void
post_deactivate_slab(dr_mcontext_t *mc, bool args_valid, reg_t void_ret, struct kmem_cache *s, struct kmem_cache_cpu *c) 
{
}

/* These wrappers are for functions to suppress false positives. */

static inline void
pre_skb_clone(dr_mcontext_t *mc, struct sk_buff *skb, gfp_t gfp_mask)
{
}

static inline void
post_skb_clone(dr_mcontext_t *mc, bool args_valid, struct sk_buff *ret, struct sk_buff *skb, gfp_t gfp_mask)
{
    set_memory_permission(ret, sizeof(*ret), PERMISSION_DEFINED);
}

static void
enable_stack_guard(struct task_struct *tsk)
{
    unsigned long *eos = end_of_stack(tsk);
    DR_ASSERT(eos >= (unsigned long*) 0xffff800000000000);
    /* Can't assert anything about current permission b/c it's probably coming
     * from kmalloc'd memory. */
    set_memory_permission(eos, sizeof(*eos), PERMISSION_UNADDRESSABLE_EOS);
}

static void
disable_stack_guard(struct task_struct *tsk)
{
    unsigned long *eos = end_of_stack(tsk);
    /* Can't assert that all are set to PERMISSION_UNADDRESSABLE_EOS because we
     * could have attached during process creation. So, if we see any
     * PERMISSION_UNADDRESSABLE_EOS, just undo it. If the memory is
     * PERMISSION_ADDRESSABLE or PERMISSION_DEFINED, then the call to kfree or
     * kmem_cache_free will reset the permission. */
    if (test_shadow_any(eos, sizeof(*eos), PERMISSION_UNADDRESSABLE_EOS)) {
        set_memory_permission(eos, sizeof(*eos), PERMISSION_UNKNOWN);
    }
}

/* Functions wrapped for stack checking. */
static inline void
pre_free_task(dr_mcontext_t *mc, struct task_struct *tsk)
{
    if (MEMCHECK_OPTION(check_stack)) {
        disable_stack_guard(tsk);
    }
}

static inline void
post_free_task(dr_mcontext_t *mc, bool args_valid, reg_t void_ret, struct task_struct *tsk)
{
}

static inline void
pre_copy_process(dr_mcontext_t *mc)
{
}

static inline void
post_copy_process(dr_mcontext_t *mc, bool args_valid, struct task_struct *ret)
{
    if (MEMCHECK_OPTION(check_stack) && !IS_ERR(ret)) {
        enable_stack_guard(ret);
    }
}

#define PRE_COMMA_0()
#define PRE_COMMA_1() ,
#define PRE_COMMA_2() ,
#define PRE_COMMA_3() ,
#define PRE_COMMA_4() ,
#define PRE_COMMA_5() ,
#define PRE_COMMA_6() ,

#define ARG_EXPAND_0(aa, unused)
#define ARG_EXPAND_1(aa, t1)                     (t1) (aa[0])
#define ARG_EXPAND_2(aa, t1, t2)                 ARG_EXPAND_1(aa, t1), (t2) (aa[1])
#define ARG_EXPAND_3(aa, t1, t2, t3)             ARG_EXPAND_2(aa, t1, t2), (t3) (aa[2])
#define ARG_EXPAND_4(aa, t1, t2, t3, t4)         ARG_EXPAND_3(aa, t1, t2, t3), (t4) (aa[3])
#define ARG_EXPAND_5(aa, t1, t2, t3, t4, t5)     ARG_EXPAND_4(aa, t1, t2, t3, t4), (t5) (aa[4])
#define ARG_EXPAND_6(aa, t1, t2, t3, t4, t5, t6) ARG_EXPAND_5(aa, t1, t2, t3, t4, t5), (t6) (aa[5])

#define PRE_WRAP() get_memcheck_tls()->in_slub_function = get_memcheck_tls()->in_slub_function_sticky
#define POST_WRAP() get_memcheck_tls()->in_slub_function = get_memcheck_tls()->in_slub_function_sticky

static func_args_t zero_args = {
    .arg = { [0 ... MAX_FUNC_ARGS - 1] = 0 },
};

#define SLUB_FUNCTION(name, ret_type, nargs, ...) \
static void pre_wrapper_ ## name(dr_mcontext_t *mc, func_args_t *args) { \
    PRE_WRAP();\
    pre_ ## name(mc PRE_COMMA_ ## nargs() ARG_EXPAND_ ## nargs(args->arg, __VA_ARGS__));\
}\
static void post_wrapper_ ## name(dr_mcontext_t *mc, func_args_t *args,\
                                  reg_t retval) { \
    bool args_valid = args != NULL;\
    POST_WRAP();\
    if (!args_valid) {\
        args = &zero_args;\
    }\
    post_ ## name(mc, args_valid, (ret_type) retval PRE_COMMA_ ## nargs() ARG_EXPAND_ ## nargs(args->arg, __VA_ARGS__));\
}
#include "slubx.h"
#undef SLUB_FUNCTION

typedef struct {
    const char *name;
    void *start;
    size_t size;
    pre_func_wrapper_t pre_wrapper;
    post_func_wrapper_t post_wrapper;
} function_t;

#define SLUB_FUNCTION(fn_name, ret_type, nargs, ...) \
    static function_t fn_name ## _wrapper =\
        { .name = #fn_name,\
          .pre_wrapper = pre_wrapper_ ## fn_name,\
          .post_wrapper = post_wrapper_ ## fn_name};

#include "slubx.h"
#undef SLUB_FUNCTION

#define SLUB_FUNCTION(fn_name, ret_type, nargs, ...) \
    &fn_name ## _wrapper,
static function_t *wrapped_functions[] =  {
#include "slubx.h"
};
#undef SLUB_FUNCTION

#define NUM_WRAPPED_FUNCTIONS (sizeof(wrapped_functions) / sizeof(wrapped_functions[0]))

static function_t*
get_wrapped_function(void *pc)
{
    int i;
    for (i = 0; i < NUM_WRAPPED_FUNCTIONS; i++) {
        function_t *func = wrapped_functions[i];
        if (pc >= func->start && pc < func->start + func->size) {
            return func;
        }
    }
    return NULL;
}

static bool
in_slub_function(byte *pc)
{
    function_t *func = get_wrapped_function(pc);
    return func && func != &schedule_wrapper;
}

#define SLUB_FUNCTION_SEARCH_DEPTH 4

static bool
safe_read_reg(reg_t *addr, reg_t *out)
{
    size_t read;
    bool ok;
    /* Do base = *((reg_t*) base); safely */
    ok = dr_safe_read(addr, sizeof(reg_t), out, &read);
    return ok && read == sizeof(reg_t);
}

/* Does not check mc->pc! This is intentional because dr_get_mcontext() in clean
 * calls does not give us pc. */
static bool
slub_function_on_stack(dr_mcontext_t *mc)
{
    reg_t base;
    int depth;
    reg_t pc;

    /* In case this is called after a call and before stack linking, 0(%rsp)
     * will hold the return address. For example, if we're interrupted on foo+0 or
     * foo+1:
     *  <somewhere in a slub func>
     *           call foo
     *           ...
     *  foo + 0: push %rbp
     *  foo + 1: mov  %rsp, %rbp
     *
     * Also covers case where we're called when stack is partially linked:
     *  foo_ret + 0: mov %rbp, %rsp
     *  foo_ret + 1: pop %rbp
     *  foo_ret + 2: ret
     * Here, if we're interrupted at foo_ret + 2, then 0(%rsp) holds the return
     * address. If we're interrupted at foo_ret + 1, then 8(%rbp) still points
     * to the return address, so the standard stack trace algorithm works.
     * Finally, note that foo_ret + 0 and foo_ret + 1 can be replaced with
     * the leave instruction, which just gives us the foo_ret + 0 and
     * foo_ret + * 2 cases.
     *
     * TODO(peter): Verify that this works. I've only tested this with schedule,
     * which is always called indirectly by slub functions.
     */
    if (safe_read_reg((reg_t*) mc->xsp, &pc) &&
        in_slub_function((void*) pc)) {
        return true;
    }

    /* Perform a standard stack trace. */
    base = mc->xbp;
    for (depth = 0; depth < SLUB_FUNCTION_SEARCH_DEPTH; depth++) {

        if (!safe_read_reg(((reg_t*) base) + 1, &pc)) {
            return false;
        }
        if (in_slub_function((void*) pc)) {
            return true;
        }
        if (!safe_read_reg((reg_t*) base, &base)) {
            return false;
        }
    }
    return false;
}

static bool
bb_is_interested(umbra_info_t *info, basic_block_t *bb)
{
    return true;
}

static bool
segment_base_always_zero(reg_id_t segment)
{
    return segment != DR_SEG_FS && segment != DR_SEG_GS;
}

static bool
ref_is_interested(umbra_info_t *info, mem_ref_t *ref)
{
    if (opnd_size_in_bytes(opnd_get_size(ref->opnd)) == 0) {
        /* This happens for instructions that don't actually read or write any
         * memory, like invlpg or lea. */
        return false;
    }

    /* TODO(peter): handle gs-relative */
    return !opnd_is_far_base_disp(ref->opnd) ||
           segment_base_always_zero(opnd_get_segment(ref->opnd));
}

static void
mcontext_to_pt_regs(dr_mcontext_t *mc, struct pt_regs *regs)
{
    regs->di = mc->xdi;
    regs->si = mc->xsi;
    regs->bp = mc->xbp;
    regs->sp = mc->xsp;
    regs->bx = mc->xbx;
    regs->dx = mc->xdx;
    regs->cx = mc->xcx;
    regs->ax = mc->xax;
    regs->orig_ax = mc->xax;
#ifdef X64
    regs->r8 = mc->r8;
    regs->r9 = mc->r9;
    regs->r10 = mc->r10;
    regs->r11 = mc->r11;
    regs->r12 = mc->r12;
    regs->r13 = mc->r13;
    regs->r14 = mc->r14;
    regs->r15 = mc->r15;
#endif
    regs->flags = mc->xflags;
    regs->ip = (reg_t) mc->xip;
}

/* Copied from arch/x86/kernel/dumpstack.c */
static void
print_trace_warning_symbol(void *data, char *msg, unsigned long symbol)
{
    printk(data);
    print_symbol(msg, symbol);
    printk("\n");
}

/* Copied from arch/x86/kernel/dumpstack.c */
static void
print_trace_warning(void *data, char *msg)
{
    printk("%s%s\n", (char *)data, msg);
}

/* Copied from arch/x86/kernel/dumpstack.c */
static int
print_trace_stack(void *data, char *name)
{
    printk("%s <%s> ", (char *)data, name);
    return 0;
}

/* Copied from arch/x86/kernel/dumpstack.c */
void
printk_address(unsigned long address, int reliable)
{
    /* N.B. "%pS" is the format specifier for a symbol. */
    printk(" [<%p>] %s%pS\n", (void *) address,
            reliable ? "" : "? ", (void *) address);
}

/* Copied from arch/x86/kernel/dumpstack.c */
static void
print_trace_address(void *data, unsigned long addr, int reliable)
{
    printk_address(addr, reliable);
}

/* Copied from arch/x86/kernel/dumpstack.c */
struct stacktrace_ops dump_trace_ops = {
    .warning = print_trace_warning,
    .warning_symbol = print_trace_warning_symbol,
    .stack = print_trace_stack,
    .address = print_trace_address,
};

static void save_stack_warning(void *data, char *msg)
{
}

static void
save_stack_warning_symbol(void *data, char *msg, unsigned long symbol)
{
}

static int save_stack_stack(void *data, char *name)
{
    return 0;
}

static void save_stack_address(void *data, unsigned long addr, int reliable)
{
    struct stack_trace *trace = data;
    if (!reliable)
        return;
    if (trace->skip > 0) {
        trace->skip--;
        return;
    }
    if (trace->nr_entries < trace->max_entries)
        trace->entries[trace->nr_entries++] = addr;
}

static const struct stacktrace_ops save_stack_ops = {
    .warning = save_stack_warning,
    .warning_symbol = save_stack_warning_symbol,
    .stack = save_stack_stack,
    .address = save_stack_address,
};

static void 
save_stack_trace_regs(struct stack_trace *trace, struct pt_regs *regs)
{
    dump_trace(current, regs, (void*) regs->sp, regs->bp, &save_stack_ops,
               trace);
    if (trace->nr_entries < trace->max_entries)
        trace->entries[trace->nr_entries++] = ULONG_MAX;
}

/* Copied from process_64.c */
void __show_regs(struct pt_regs *regs, int all)
{
    unsigned long cr0 = 0L, cr2 = 0L, cr3 = 0L, cr4 = 0L, fs, gs, shadowgs;
    unsigned long d0, d1, d2, d3, d6, d7;
    unsigned int fsindex, gsindex;
    unsigned int ds, cs, es;

    printk("\n");
    printk(KERN_INFO "RIP: %04lx:[<%016lx>] ", regs->cs & 0xffff, regs->ip);
    printk_address(regs->ip, 1);
    printk(KERN_INFO "RSP: %04lx:%016lx  EFLAGS: %08lx\n", regs->ss,
            regs->sp, regs->flags);
    printk(KERN_INFO "RAX: %016lx RBX: %016lx RCX: %016lx\n",
           regs->ax, regs->bx, regs->cx);
    printk(KERN_INFO "RDX: %016lx RSI: %016lx RDI: %016lx\n",
           regs->dx, regs->si, regs->di);
    printk(KERN_INFO "RBP: %016lx R08: %016lx R09: %016lx\n",
           regs->bp, regs->r8, regs->r9);
    printk(KERN_INFO "R10: %016lx R11: %016lx R12: %016lx\n",
           regs->r10, regs->r11, regs->r12);
    printk(KERN_INFO "R13: %016lx R14: %016lx R15: %016lx\n",
           regs->r13, regs->r14, regs->r15);

    asm("movl %%ds,%0" : "=r" (ds));
    asm("movl %%cs,%0" : "=r" (cs));
    asm("movl %%es,%0" : "=r" (es));
    asm("movl %%fs,%0" : "=r" (fsindex));
    asm("movl %%gs,%0" : "=r" (gsindex));

    rdmsrl(MSR_FS_BASE, fs);
    rdmsrl(MSR_GS_BASE, gs);
    rdmsrl(MSR_KERNEL_GS_BASE, shadowgs);

    if (!all)
        return;

    cr0 = read_cr0();
    cr2 = read_cr2();
    cr3 = read_cr3();
    cr4 = read_cr4();

    printk(KERN_INFO "FS:  %016lx(%04x) GS:%016lx(%04x) knlGS:%016lx\n",
           fs, fsindex, gs, gsindex, shadowgs);
    printk(KERN_INFO "CS:  %04x DS: %04x ES: %04x CR0: %016lx\n", cs, ds,
            es, cr0);
    printk(KERN_INFO "CR2: %016lx CR3: %016lx CR4: %016lx\n", cr2, cr3,
            cr4);

    get_debugreg(d0, 0);
    get_debugreg(d1, 1);
    get_debugreg(d2, 2);
    printk(KERN_INFO "DR0: %016lx DR1: %016lx DR2: %016lx\n", d0, d1, d2);
    get_debugreg(d3, 3);
    get_debugreg(d6, 6);
    get_debugreg(d7, 7);
    printk(KERN_INFO "DR3: %016lx DR6: %016lx DR7: %016lx\n", d3, d6, d7);
}

void
memcheck_reset_reports(void)
{
    DR_ASSERT(irqs_disabled());
    __get_cpu_var(memcheck_tls)->report_count = 0;
    __get_cpu_var(memcheck_tls)->report_read_index = 0;
    __get_cpu_var(memcheck_tls)->report_write_index = 0;
}

void
memcheck_disable_reporting(void)
{
    DR_ASSERT(irqs_disabled());
    __get_cpu_var(memcheck_tls)->reporting_enabled = false;
}

void
memcheck_enable_reporting(void)
{
    DR_ASSERT(irqs_disabled());
    __get_cpu_var(memcheck_tls)->reporting_enabled = true;
}

int
memcheck_num_reports(void)
{
    DR_ASSERT(irqs_disabled());
    return __get_cpu_var(memcheck_tls)->report_count;
}

int memcheck_num_disabled_reports(void)
{
    DR_ASSERT(irqs_disabled());
    return __get_cpu_var(memcheck_tls)->num_disabled_reports;
}

memcheck_report_t *
memcheck_get_report(void)
{
    memcheck_tls_t *tls;
    memcheck_report_t *report;
    DR_ASSERT(irqs_disabled());
    tls = __get_cpu_var(memcheck_tls);
    if (tls->report_count == 0) {
        return NULL;
    }
    tls->report_count--;
    report = &tls->reports[tls->report_read_index];
    tls->report_read_index++;
    tls->report_read_index %= MAX_NUM_MEMCHECK_REPORTS;
    return report;
}

static memcheck_report_t *
memcheck_new_report(void)
{
    memcheck_tls_t *tls;
    memcheck_report_t *report;
    DR_ASSERT(irqs_disabled());
    tls = __get_cpu_var(memcheck_tls);
    if (tls->report_count == MAX_NUM_MEMCHECK_REPORTS) {
        return NULL;
    }
    tls->report_count++;
    report = &tls->reports[tls->report_write_index];
    tls->report_write_index++;
    tls->report_write_index %= MAX_NUM_MEMCHECK_REPORTS;
    return report;
}

static opnd_size_t
get_canonical_opsz(opnd_size_t opsz)
{
    int opsz_bytes = opnd_size_in_bytes(opsz);
    switch (opsz_bytes) {
    case 0:
        /* This should be handled by ref_is_interested. */
        DR_ASSERT(false);
    case 1: return OPSZ_1;
    case 2: return OPSZ_2;
    case 4: return OPSZ_4;
    case 8: return OPSZ_8;
    default:
        /* TODO(peter): Handle unusual operand byte sizes properly: we should
         * scan each byte. In practice, this is not a big deal because it only
         * comes up for fxsave and fxrstor, which probably aren't in kmalloc'd
         * memory. In any case, kmemcheck does not handle them properly; it
         * reverts to 4 bytes for unknown opcodes / prefixes. We revert to 8
         * bytes because we're on 64-bit.
         */
        if (opsz_bytes > 8) {
            return OPSZ_8;
        } else {
            return OPSZ_1;
        }
    }
}

static memcheck_error_type_t
determine_error_type(memcheck_tls_t *tls, byte *addr, mem_ref_t *ref)
{
    opnd_size_t opsz = get_canonical_opsz(opnd_get_size(ref->opnd));
    int size = opnd_size_in_bytes(opsz);
    if (test_shadow_any(addr, size, PERMISSION_UNADDRESSABLE)) {
        if (test_shadow_any(addr, size, PERMISSION_UNADDRESSABLE_EOS)) {
            DR_ASSERT(MEMCHECK_OPTION(check_stack));
            if (ref->type == MemWrite || ref->type == MemModify) {
                return MEMCHECK_ERROR_EOS;
            } else {
                tls->num_eos_read++;
                return MEMCHECK_ERROR_NONE;
            }
        } else {
            return MEMCHECK_ERROR_UNADDRESSABLE;
        }
    } else if (test_shadow_any(addr, size, PERMISSION_UNKNOWN)) {
        /* The inline check misses some bytes being unknown and some being
         * defined or addressable. */
        DR_ASSERT(ref->type == MemRead);
        return MEMCHECK_ERROR_NONE;
    } else {
        DR_ASSERT(ref->type == MemRead &&
                  test_shadow_none(addr, size, PERMISSION_DEFINED) &&
                  test_shadow_none(addr, size, PERMISSION_UNKNOWN));
        return MEMCHECK_ERROR_UNDEFINED_READ;
    }
}

static void
printk_error_report(memcheck_report_t *report)
{
    printk("Memcheck Error: %p ", report->addr);
    switch (report->type) {
    case MEMCHECK_ERROR_UNADDRESSABLE:
        printk("unaddressable");
        break;
    case MEMCHECK_ERROR_UNDEFINED_READ:
        printk("undefined read");
        break;
    case MEMCHECK_ERROR_EOS:
        printk("end of stack");
        break;
    default:
        DR_ASSERT(false);
        printk("unknown error type!");
    }
    __show_regs(&report->regs, 1);
    print_stack_trace(&report->trace, 2);
}

static void
report_memcheck_error(void *drcontext, memcheck_tls_t *tls, dr_mcontext_t *mc,
                      byte *addr, memcheck_error_type_t type)
{
    memcheck_report_t *report;
    
    if (tls->reset_report_count) {
        tls->reset_report_count = false;
        memcheck_reset_reports();
    }

    if (!tls->reporting_enabled) {
        tls->num_disabled_reports++;
        return;
    }
    report = memcheck_new_report();
    if (!report) {
        tls->in_slub_function = true;
        tls->in_slub_function_sticky = true;
        tls->num_missed_reports++;
        printk("Memcheck error reporting disabled. Too many reports.\n");
        return;
    }
    tls->num_reports++;

    /* Make a best attempt to figure out the app pc that corresponds to
     * tls->cache_pc. If it fails, fall back on the fragment tag, then the cache
     * pc.
     */
    mc->pc = dr_app_pc_from_cache_pc(tls->cache_pc);
    DR_ASSERT(mc->pc);
    if (mc->pc == NULL) {
        mc->pc = dr_tag_from_cache_pc(tls->cache_pc);
        DR_ASSERT(mc->pc);
        if (mc->pc == NULL) {
            mc->pc = tls->cache_pc;
        }
    }

    mcontext_to_pt_regs(mc, &report->regs);
    report->addr = addr;
    report->type = type;
    report->trace.entries = report->trace_entries;
    report->trace.skip = 0;
    report->trace.nr_entries = 0;
    report->trace.max_entries = ARRAY_SIZE(report->trace_entries);
    save_stack_trace_regs(&report->trace, &report->regs);
    printk_error_report(report);
}

static void
induce_oops(void)
{
    *((int*) NULL) = 0;
}

void
memcheck_slowpath(mem_ref_t *ref)
{
    dr_mcontext_t mc;
    int app_errno;
    byte *addr;
    memcheck_error_type_t type;
    void *drcontext = dr_get_current_drcontext();
    umbra_info_t *umbra_info = umbra_get_info();
    memcheck_tls_t *tls = memcheck_tls(umbra_info);
#ifdef DEBUG
    void *tag = dr_tag_from_cache_pc(tls->cache_pc);
    DR_ASSERT(tag != NULL);
#endif
    tls->num_slowpath_exits++;

    if (!dr_get_mcontext(drcontext, &mc, &app_errno)) {
        DR_ASSERT(false);
        return;
    }

    if (tls->in_slub_function_sticky) {
        tls->in_slub_function = true;
        return;
    }

    DR_ASSERT(!tls->in_slub_function);
    tls->in_slub_function = slub_function_on_stack(&mc);

    if (tls->in_slub_function) {
        tls->num_slowpath_slub_function++;
        return;
    }

    addr = umbra_get_app_addr(umbra_info, &mc, ref);
    type = determine_error_type(tls, addr, ref);

    if (type == MEMCHECK_ERROR_NONE) {
        tls->num_slowpath_false_negatives++;
        return;
    }

    if (!tls->in_slub_function) {
        report_memcheck_error(drcontext, tls, &mc, addr, type);
    }

    if (type == MEMCHECK_ERROR_EOS) {
        DR_ASSERT(MEMCHECK_OPTION(check_stack));
        mc.rsp = percpu_read(kernel_stack);
        mc.pc = (byte*)(&induce_oops);
        dr_redirect_execution(&mc, 0);
    }
}

static byte*
emit_slowpath_code(void *drcontext, memcheck_tls_t *tls, byte *pc,
                   reg_id_t arg_reg)
{
    instrlist_t *ilist;
    instr_t *instr;
    opnd_t opnd1, opnd2;
    instr_t *done = INSTR_CREATE_label(drcontext);

    ilist = instrlist_create(drcontext);

    /* cmp tls->in_slub_function, true */
    opnd1 = OPND_CREATE_ABSMEM(&tls->in_slub_function, OPSZ_1);
    opnd2 = OPND_CREATE_INT8(true);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);

    /* je done */
    opnd1 = opnd_create_instr(done);
    instr = INSTR_CREATE_jcc(drcontext, OP_je, opnd1);
    instrlist_meta_append(ilist, instr);

    /* memcheck_slowpath() */
    dr_insert_clean_call(drcontext, ilist, NULL, (void*) memcheck_slowpath,
                         false, 1, opnd_create_reg(arg_reg));

    /* done: */
    instrlist_meta_append(ilist, done);

    /* jmp tls->cache_pc */
    opnd1 = OPND_CREATE_ABSMEM(&tls->cache_pc, OPSZ_PTR);
    instr = INSTR_CREATE_jmp_ind(drcontext, opnd1);
    instrlist_meta_append(ilist, instr);

    pc = instrlist_encode(drcontext, ilist, pc, true);
    instrlist_clear_and_destroy(drcontext, ilist);
    return pc;
}

static void
memcheck_code_cache_init(void *drcontext, memcheck_tls_t *tls)
{
    reg_t reg;
    uint prot;
    byte *pc;
    prot = DR_MEMPROT_READ|DR_MEMPROT_WRITE|DR_MEMPROT_EXEC;
    pc = dr_nonheap_alloc(CODE_CACHE_SIZE, prot);
    tls->code_cache_start = pc;
    for (reg = DR_REG_START_64; reg <= DR_REG_STOP_64; reg++) {
        pc = umbra_align_cache_line(pc);
        tls->slowpath_code[reg] = pc;
        pc = emit_slowpath_code(drcontext, tls, pc, reg);
    }
    tls->code_cache_end = pc;
    DR_ASSERT(tls->code_cache_end <= tls->code_cache_start + CODE_CACHE_SIZE);
}

void
memcheck_init_shadow_slab_cache(void *drcontext, memcheck_tls_t *tls,
                                struct kmem_cache *s)
{
}

static bool
get_slub_lock(void)
{
    if (!down_read_trylock(kernel_symbols.slub_lock)) {
        printk("Could not initialize slub shadow because slub_lock is held.\n");
        DR_ASSERT(false);
        return false;
    } else {
        return true;
    }
}

static void
memcheck_flush_cpu_slab(void)
{
    struct kmem_cache *s;
    if (!get_slub_lock()) {
        return;
    }
    list_for_each_entry(s, kernel_symbols.slab_caches, list) {
        kernel_symbols.flush_cpu_slab(s);
    }
    up_read(kernel_symbols.slub_lock);
}

/* Copied from slub.c. */
static struct kmem_cache_node *
get_node(struct kmem_cache *s, int node)
{
#ifdef CONFIG_NUMA
    return s->node[node];
#else
    return &s->local_node;
#endif
}

static __always_inline bool
slab_is_locked(struct page *page)
{
    return bit_spin_is_locked(PG_locked, &page->flags);
}

/* Copied from slub.c. */
static inline void *get_freepointer(struct kmem_cache *s, void *object)
{
    return *(void **)(object + s->offset);
}

/* Copied from slub.c. */
/* Scan freelist */
#define for_each_free_object(__p, __s, __free) \
    for (__p = (__free); __p; __p = get_freepointer((__s), __p))

/* Copied from slub.c. */
/* Loop over all objects in a slab */
#define for_each_object(__p, __s, __addr, __objects) \
    for (__p = (__addr); __p < (__addr) + (__objects) * (__s)->size;\
            __p += (__s)->size)

static void
memcheck_shadow_eos_init(void *drcontext, memcheck_tls_t *tls)
{
    struct task_struct *g, *p;
    if (!MEMCHECK_OPTION(check_stack)) {
        return;
    }
    do_each_thread(g, p) {
        enable_stack_guard(p);
    } while_each_thread(g, p);
}

static void
memcheck_shadow_slub_init(void *drcontext, memcheck_tls_t *tls)
{
    struct kmem_cache *s;
    if (!MEMCHECK_OPTION(check_addr)) {
        return;
    }
    if (!get_slub_lock()) {
        return;
    }
    list_for_each_entry(s, kernel_symbols.slab_caches, list) {
        int node;
        /* TODO(peter): Fix this to properly include slabs that were allocated
         * from offline CPUs. This breaks our unit tests when a CPU was disabled
         * after startup but before attaching.
         */
        for_each_node_state(node, N_NORMAL_MEMORY) {
            struct kmem_cache_node *n = get_node(s, node);
            struct page *page;
            if (spin_is_locked(&n->list_lock)) {
                printk("Cache %s is busy on node %d, skipping\n", s->name, node);
                /* This is an error because any CPU that owns this spinlock
                 * should have its interrupts disabled, thus preventing us from
                 * running at all!
                 */
                DR_ASSERT(false);
                continue;
            }
            /* We only scan the partial lists. The full list (n->full) is empty
             * for non-debug kernel builds. This isn't really a problem though:
             * a full list only has addressable and, as far as we know, defined
             * bytes on it, so PERMISSION_UNKNOWN is okay.
             */
            list_for_each_entry(page, &n->partial, lru) {
                size_t slab_size;
                void *object;
                if (slab_is_locked(page)) {
                    printk("Slab 0x%p busy on %s, skipping\n", page, s->name);
                    /* This is a spinlock too, so this is an error too. */
                    DR_ASSERT(false);
                    continue;
                }
                /* TODO(peter): Change this to add missing entires to page table
                 * directly. Hitting the shadow page fault handler for every new
                 * page is slow. Updating the page tables directly in the
                 * wrappers isn't a good idea because they will incur page
                 * faults rarely.
                 */
                slab_size = PAGE_SIZE << compound_order(page);
                /* First, set the entire slab unaddressable. */
                set_memory_permission(page_address(page), slab_size,
                                      PERMISSION_UNADDRESSABLE_INIT);
                tls->num_init_unaddressable_bytes += slab_size;
                /* Next, make just the non-meta data of all objects defined.  */
                for_each_object(object, s, page_address(page), page->objects) {
                    set_memory_permission(object, s->objsize,
                                          PERMISSION_DEFINED);
                    tls->num_init_unaddressable_bytes -= s->objsize;
                    tls->num_init_addressable_bytes += s->objsize;
                }
                /* Finally, remove the addressability of all free objects. */
                for_each_free_object(object, s, page->freelist) {
                    set_memory_permission(object, s->objsize,
                                          PERMISSION_UNADDRESSABLE_INIT);
                    tls->num_init_addressable_bytes -= s->objsize;
                    tls->num_init_unaddressable_bytes += s->objsize;
                }
            }
        }
    }
    up_read(kernel_symbols.slub_lock);
}

#define ASSERT_CALLED_ONCE()\
do {\
    static int call_count = 0;\
    DR_ASSERT(call_count++ == 0);\
} while(0)

static void
thread_init(void *drcontext, umbra_info_t *info)
{
    memcheck_tls_t *tls = dr_thread_alloc(drcontext, sizeof(*tls));
    memset(tls, 0, sizeof(*tls)); 
    info->client_tls_data = tls;
#ifdef DEBUG
    mtls[dr_get_thread_id(drcontext)] = tls;
#endif
    DR_ASSERT(get_memcheck_tls() == tls);
    DR_ASSERT(memcheck_tls(info) == tls);
    tls->in_slub_function = false;
    tls->in_slub_function_sticky = false;
    memcheck_code_cache_init(drcontext, tls);

    dr_mutex_lock(slab_flush_mutex);
    memcheck_flush_cpu_slab();
    slab_flush_count++;
    if (slab_flush_count == dr_cpu_count()) {
        ASSERT_CALLED_ONCE();
        memcheck_shadow_slub_init(drcontext, tls);
        /* Need to do eos init after slub because stacks are allocated on
         * slub-allocated memory. */
        memcheck_shadow_eos_init(drcontext, tls);
    }
    dr_mutex_unlock(slab_flush_mutex);

    tls->reporting_enabled = true;
    tls->check_def_enabled = true;

    __get_cpu_var(memcheck_tls) = tls;
}

static void
thread_exit(void *drcontext, umbra_info_t *umbra_info)
{
    memcheck_tls_t *tls = memcheck_tls(umbra_info);
    dr_nonheap_free(tls->code_cache_start, CODE_CACHE_SIZE);
    dr_thread_free(umbra_info->drcontext, tls, sizeof(*tls));
    __get_cpu_var(memcheck_tls) = NULL;
}

static opnd_t
opnd_create_zero_disp(reg_t base_reg, opnd_size_t size)
{
    return opnd_create_base_disp(base_reg, REG_NULL, 0, 0, size);
}

static bool
naturally_sign_extended(reg_t value)
{
    return (value >> 31) == 0x1ffffffff || (value >> 31) == 0;
}

static void
insert_movs_read_shadow_unknown(void *drcontext, instrlist_t *ilist,
                                instr_t *where, reg_id_t scratch_reg)
{
    instr_t *instr;
    opnd_t opnd1, opnd2;
    /* load $PERMISSION_UNKNOWN => tls->movs_read_shadow  */
    opnd1 = OPND_CREATE_ABSMEM(&get_memcheck_tls()->movs_read_shadow, OPSZ_PTR);
    DR_ASSERT(PERMISSION_UNKNOWN == 0);
    opnd2 = OPND_CREATE_INT32(PERMISSION_UNKNOWN);
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
}

static void update_check_def(void) {}

/* # Skip if all unknown.
 *  
 *   cmp 0(%shadow_reg), PERMISSION_UKNOWN
 *   je unknown
 *
 * # Error if any unaddressable.
 *
 *   load $PERMISSION_UNADDRESSABLE => %scratch_reg
 *   testb 0(%shadow_reg), %scratch_reg
 *   jz after_slowpath
 *
 * slowpath:
 *   mov %shadow_reg, mem
 *   load done.pc => tls->cache_pc
 *   jmp slowpath[%shadow_reg]
 *   jmp done
 *
 * after_slowpath:
 *
 * if !MEMCHECK_OPTION(check_defined)
 *   # pass
 * elif movs && read
 *   load 0(%shadow_reg) => %shadow_reg
 *   load %shadow_reg => tls->movs_read_shadow
 *   jmp done
 * elif movs && write
 *   load tls->movs_read_shadow => %scratch_reg
 *   load %scratch_reg => 0(%shadow_reg)
 * elif write || modify
 *   mov %scratch_reg, $PERMISSION_DEFINED
 *   load %scratch_reg => 0(%shadow_reg)
 * else # read
 *   mov %scratch_reg, $PERMISSION_DEFINED
 *   test 0(%shadow_reg), %scratch_reg
 *   jz slowpath
 * fi
 *
 * unknown:
 *
 * if MEMCHECK_OPTION(check_defined) && movs && read
 *   load PERMISSION_UNKNOWN => tls->movs_read_shadow
 * fi
 *
 * done:
 */
static void
instrument_update(void *drcontext, umbra_info_t  *umbra_info,
                  mem_ref_t *ref, instrlist_t *ilist, instr_t *where)
{
    instr_t *instr;
    opnd_t opnd1, opnd2;
    instr_t *done, *slowpath, *after_slowpath, *unknown;
    memcheck_tls_t *tls = memcheck_tls(umbra_info);
    reg_id_t shadow_reg = umbra_info->steal_regs[0];
    reg_id_t scratch_reg = umbra_info->steal_regs[1];
    opnd_size_t opsz = get_canonical_opsz(opnd_get_size(ref->opnd));

    if (tls->check_def_enabled) {
        update_check_def();
    }
    
    if (in_slub_function(instr_get_app_pc(ref->instr))) {
        return;
    }

    DR_ASSERT(ref->type == MemRead || ref->type == MemWrite ||
              ref->type == MemModify);

    done = INSTR_CREATE_label(drcontext);
    slowpath = INSTR_CREATE_label(drcontext);
    after_slowpath = INSTR_CREATE_label(drcontext);
    unknown = INSTR_CREATE_label(drcontext);

    /* cmp 0(%shadow_reg), PERMISSION_UNKNOWN */
    opnd1 = opnd_create_zero_disp(shadow_reg, opsz);
    /* It's okay to use int8 because PERMISSION_UNKNOWN is zero. */
    DR_ASSERT(PERMISSION_UNKNOWN == 0);
    opnd2 = OPND_CREATE_INT8(PERMISSION_UNKNOWN);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    
    /* je unknown */
    opnd1 = opnd_create_instr(unknown);
    instr = INSTR_CREATE_jcc_short(drcontext, OP_je, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* TODO(peter): Addressability and definiedness checks can be done without
     * the scratch_reg for 32, 16, and 8-bit addresses. */

    /* mov %scratch_reg, $PERMISSION_UNADDRESSABLE */
    opnd1 = opnd_create_reg(scratch_reg);
    /* Always load the 8 byte mask into %scratch_reg. This is okay because we
     * compare using the appropriately sized sub_register. */
    opnd2 = OPND_CREATE_INT64(get_8_byte_mask(PERMISSION_UNADDRESSABLE));
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* test 0(%shadow_reg), %scratch_reg */
    opnd1 = opnd_create_zero_disp(shadow_reg, opsz);
    opnd2 = opnd_create_reg(reg_64_to_opsz(scratch_reg, opsz));
    instr = INSTR_CREATE_test(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jz after_slowpath */
    opnd1 = opnd_create_instr(after_slowpath);
    instr = INSTR_CREATE_jcc_short(drcontext, OP_jz_short, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* slowpath: */
    instrlist_meta_preinsert(ilist, where, slowpath);

    /* mov %shadow_reg, mem */
    opnd1 = opnd_create_reg(shadow_reg);
    if (naturally_sign_extended((reg_t) ref)) {
        opnd2 = OPND_CREATE_INT32(ref);
    } else {
        opnd2 = OPND_CREATE_INTPTR(ref);
    }
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* load done.pc => tls->cache_pc */
    opnd1 = OPND_CREATE_ABSMEM(&tls->cache_pc, OPSZ_PTR);
    opnd2 = opnd_create_instr(done);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jmp tls->slowpath_code[%shadow_reg] */
    DR_ASSERT(shadow_reg >= DR_REG_START_64);
    DR_ASSERT(shadow_reg <= DR_REG_STOP_64);
    DR_ASSERT(tls->slowpath_code[shadow_reg] >= tls->code_cache_start);
    opnd1 = opnd_create_pc(tls->slowpath_code[shadow_reg]);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* after_slowpath: */
    instrlist_meta_preinsert(ilist, where, after_slowpath);

    if (!MEMCHECK_OPTION(check_defined) || !tls->check_def_enabled) {
    } else if (ref->opcode == OP_movs && ref->type == MemRead) {
        /* load 0(%shadow_reg) => %shadow_reg */
        opnd1 = opnd_create_reg(reg_64_to_opsz(shadow_reg, opsz));
        opnd2 = opnd_create_zero_disp(shadow_reg, opsz);
        instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);

        /* load %shadow_reg => tls->movs_read_shadow */
        opnd1 = OPND_CREATE_ABSMEM(&tls->movs_read_shadow, opsz);
        opnd2 = opnd_create_reg(reg_64_to_opsz(shadow_reg, opsz));
        instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);

        /* jmp done */
        opnd1 = opnd_create_instr(done);
        instr = INSTR_CREATE_jmp_short(drcontext, opnd1);
        instrlist_meta_preinsert(ilist, where, instr);
    } else if (ref->opcode == OP_movs && ref->type == MemWrite) {
        /* load tls->movs_read_shadow => %scratch_reg */
        opnd1 = opnd_create_reg(reg_64_to_opsz(scratch_reg, opsz));
        opnd2 = OPND_CREATE_ABSMEM(&tls->movs_read_shadow, opsz);
        instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);

        /* load scratch_reg => 0(%shadow_reg) */
        opnd1 = opnd_create_zero_disp(shadow_reg, opsz);
        opnd2 = opnd_create_reg(reg_64_to_opsz(scratch_reg, opsz));
        instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);
    } else if (ref->type == MemWrite || ref->type == MemModify) {
        /* mov %scratch_reg, $PERMISSION_DEFINED */
        opnd1 = opnd_create_reg(scratch_reg);
        opnd2 = OPND_CREATE_INT64(get_8_byte_mask(PERMISSION_DEFINED));
        instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);

        /* load %scratch_reg => 0(%shadow_reg) */
        opnd1 = opnd_create_zero_disp(shadow_reg, opsz);
        opnd2 = opnd_create_reg(reg_64_to_opsz(scratch_reg, opsz));
        instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);
    } else if (ref->type == MemRead) {
        /* mov %scratch_reg, $PERMISSION_DEFINED */
        opnd1 = opnd_create_reg(scratch_reg);
        opnd2 = OPND_CREATE_INT64(get_8_byte_mask(PERMISSION_DEFINED));
        instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);

        /* test 0(%shadow_reg), %scratch_reg */
        opnd1 = opnd_create_zero_disp(shadow_reg, opsz);
        opnd2 = opnd_create_reg(reg_64_to_opsz(scratch_reg, opsz));
        instr = INSTR_CREATE_test(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);

        /* jz slowpath */
        opnd1 = opnd_create_instr(slowpath);
        instr = INSTR_CREATE_jcc_short(drcontext, OP_jz_short, opnd1);
        instrlist_meta_preinsert(ilist, where, instr);
    } else {
        DR_ASSERT(false);
    }
    
    /* unknown: */
    instrlist_meta_preinsert(ilist, where, unknown);

    if (MEMCHECK_OPTION(check_defined) && ref->opcode == OP_movs &&
            ref->type == MemRead) {
        insert_movs_read_shadow_unknown(drcontext, ilist, where, shadow_reg);
    }

    /* done: */
    instrlist_meta_preinsert(ilist, where, done);
}


static void
instrument_update_user(void *drcontext, umbra_info_t  *umbra_info,
                       mem_ref_t *ref, instrlist_t *ilist, instr_t *where)
{
    if (MEMCHECK_OPTION(check_defined) && ref->opcode == OP_movs &&
            ref->type == MemRead) {
        insert_movs_read_shadow_unknown(drcontext, ilist, where,
                                        umbra_info->steal_regs[0]);
    }
}

#define PRE instrlist_meta_preinsert
#define PREXL8 instrlist_preinsert

/* Copied from drmemory. */
static instr_t *
create_nonloop_stringop(void *drcontext, instr_t *inst)
{
    instr_t *res;
    int nsrc = instr_num_srcs(inst);
    int ndst = instr_num_dsts(inst);
    uint opc = instr_get_opcode(inst);
    int i;
    DR_ASSERT(instr_is_stringop_loop(inst) && "invalid param");
    switch (opc) {
    case OP_rep_ins:    opc = OP_ins; break;;
    case OP_rep_outs:   opc = OP_outs; break;;
    case OP_rep_movs:   opc = OP_movs; break;;
    case OP_rep_stos:   opc = OP_stos; break;;
    case OP_rep_lods:   opc = OP_lods; break;;
    case OP_rep_cmps:   opc = OP_cmps; break;;
    case OP_repne_cmps: opc = OP_cmps; break;;
    case OP_rep_scas:   opc = OP_scas; break;;
    case OP_repne_scas: opc = OP_scas; break;;
    default: DR_ASSERT(false && "not a stringop loop opcode"); return NULL;
    }
    res = instr_build(drcontext, opc, ndst - 1, nsrc - 1);
    /* We assume xcx is last src and last dst */
    DR_ASSERT(opnd_is_reg(instr_get_src(inst, nsrc - 1)) &&
              opnd_uses_reg(instr_get_src(inst, nsrc - 1), REG_XCX) &&
              "rep opnd order assumption violated");
    DR_ASSERT(opnd_is_reg(instr_get_dst(inst, ndst - 1)) &&
              opnd_uses_reg(instr_get_dst(inst, ndst - 1), REG_XCX) &&
              "rep opnd order assumption violated");
    for (i = 0; i < nsrc - 1; i++)
        instr_set_src(res, i, instr_get_src(inst, i));
    for (i = 0; i < ndst - 1; i++)
        instr_set_dst(res, i, instr_get_dst(inst, i));
    instr_set_translation(res, instr_get_app_pc(inst));
    return res;
}

/* Copied from drmemory. */
/* PR 580123: add fastpath for rep string instrs by converting to normal loop */
static void 
convert_repstr_to_loop(void *drcontext, memcheck_tls_t *tls, instrlist_t *bb)
{
    instr_t *inst, *next_inst;
    bool delete_rest = false;
    uint opc;

    /* Make a rep string instr be its own bb: the loop is going to
     * duplicate the tail anyway, and have to terminate at the added cbr.
     */
    for (inst = instrlist_first(bb);
         inst != NULL;
         inst = next_inst) {
        next_inst = instr_get_next(inst);
        opc = instr_get_opcode(inst);
        if (delete_rest) {
            instrlist_remove(bb, inst);
            instr_destroy(drcontext, inst);
        } else if (instr_is_stringop_loop(inst)) {
            delete_rest = true;
            if (inst != instrlist_first(bb)) {
                instrlist_remove(bb, inst);
                instr_destroy(drcontext, inst);
            }
        }
    }

    /* Convert to a regular loop if it's the sole instr */
    inst = instrlist_first(bb);
    opc = instr_get_opcode(inst);
    if (instr_is_stringop_loop(inst)) {
        app_pc xl8 = instr_get_app_pc(inst);
        opnd_t xcx = instr_get_dst(inst, instr_num_dsts(inst) - 1);
        instr_t *stringop, *loop, *pre_loop, *jecxz, *zero, *iter;
        DR_ASSERT(opnd_uses_reg(xcx, REG_XCX) && "rep string opnd order mismatch");
        DR_ASSERT(inst == instrlist_last(bb) && "repstr not alone in bb");

        pre_loop = INSTR_CREATE_label(drcontext);
        /* hack to handle loop decrementing xcx: simpler if could have 2 cbrs! */
        zero = INSTR_CREATE_mov_imm(drcontext, xcx,
                                    opnd_create_immed_int(1, opnd_get_size(xcx)));
        iter = INSTR_CREATE_label(drcontext);


        /* A rep string instr does check for 0 up front.  DR limits us
         * to 1 cbr so we have to make a meta cbr.  If ecx is uninit
         * the loop* will catch it so we're ok not instrumenting this.
         * I would just jecxz to loop, but w/ instru it can't reach so
         * I have to add yet more meta-jmps that will execute each
         * iter.  Grrr.
         */
        jecxz = INSTR_CREATE_jecxz(drcontext, opnd_create_instr(zero));
        /* be sure to match the same counter reg width */
        instr_set_src(jecxz, 1, xcx);
        PRE(bb, inst, jecxz);
        PRE(bb, inst, INSTR_CREATE_jmp_short(drcontext, opnd_create_instr(iter)));
        PRE(bb, inst, zero);
        /* target the instrumentation for the loop, not loop itself */
        PRE(bb, inst, INSTR_CREATE_jmp(drcontext, opnd_create_instr(pre_loop)));
        PRE(bb, inst, iter);

        stringop = INSTR_XL8(create_nonloop_stringop(drcontext, inst), xl8);
        PREXL8(bb, inst, stringop);
        /* Pad the stringop so that it's at least 2 bytes long. This is
         * necessary because of how interrupts are delayed: the next non-meta
         * instruction is patched with intN (a 2 byte instruction). Because of
         * the non-linear control flow we introduce in this method, it's
         * possible for the stringop to be patched but the loop instruction to
         * be the next non-meta instruction executed.
         *            jecxz zero
         *            jmp iter
         *      zero: mov $1, %rcx
         *            jmp pre_loop
         *      iter: stringop
         *            nop
         *  pre_loop: loop app_pc
         *
         * We're on jecxz zero and rcx == 0 then we'll execute the loop
         * instruction before stringop. Now suppose that we're interrupted on
         * jecxz zero: stringop is patched, but we miss the patch because we
         * jump to pre_loop. If stringop were just 1 byte long, then the patch
         * would overwrite the loop instruction and we'd be screwed with an
         * invalid opcode exception.
         *
         * Make the nop meta so if it's interrupted, then we take the interrupt
         * at the loop instruction that follows. See memcheck_interrupt for how
         * we handle the loop specially.
         */
        if (instr_length(drcontext, stringop) < 2 /* INTN_LENGTH */) {
            DR_ASSERT(instr_length(drcontext, stringop) == 1);
            PRE(bb, inst, INSTR_CREATE_nop(drcontext));
        }

        PRE(bb, inst, pre_loop);
        if (opc == OP_rep_cmps || opc == OP_rep_scas) {
            loop = INSTR_CREATE_loope(drcontext, opnd_create_pc(xl8));
        } else if (opc == OP_repne_cmps || opc == OP_repne_scas) {
            loop = INSTR_CREATE_loopne(drcontext, opnd_create_pc(xl8));
        } else {
            loop = INSTR_CREATE_loop(drcontext, opnd_create_pc(xl8));
        }
        /* be sure to match the same counter reg width */
        instr_set_src(loop, 1, xcx);
        instr_set_dst(loop, 0, xcx);

        PREXL8(bb, inst, INSTR_XL8(loop, xl8));

        /* now throw out the orig instr */
        instrlist_remove(bb, inst);
        instr_destroy(drcontext, inst);
    }
}

static void 
app_to_app_transformation(void *drcontext, umbra_info_t *umbra_info,
                          void *tag, instrlist_t  *ilist, bool for_trace)
{
    memcheck_tls_t *tls = memcheck_tls(umbra_info);
    convert_repstr_to_loop(drcontext, tls, ilist);
}

static bool
mm_is_valid(void *start, void *end)
{
    return start >= (void*) 0xffff800000000000;
}

static void
shadow_page_alloc(umbra_info_t *info, void *start, size_t size)
{
    memset(start, PERMISSION_UNKNOWN, size);
}

static bool 
memcheck_interrupt(umbra_info_t *umbra_info, dr_interrupt_t *interrupt)
{
    memcheck_tls_t *tls = memcheck_tls(umbra_info);
    byte *xip = interrupt->frame->xip;
    
    if (xip >= tls->code_cache_start && xip < tls->code_cache_end) {
        interrupt->frame->xip = (byte*) tls->cache_pc;
    }

    return true;
}

static void
memcheck_option_compatibility(void)
{
    if (!MEMCHECK_OPTION(check_addr)) {
        MEMCHECK_OPTION(check_stack) = false;
        MEMCHECK_OPTION(check_defined) = false;
    }
}

static void
memcheck_options_init(const char *optstr)
{
    char *optstr_copy = dr_global_alloc(strlen(optstr) + 1);
    char *to_free = optstr_copy;
    strcpy(optstr_copy, optstr);
    memcheck_proc_info.options.check_addr = true;
    memcheck_proc_info.options.check_defined = true;
    memcheck_proc_info.options.check_stack = true;
    for (;;) {
        const char *option = strsep(&optstr_copy, ",");
        bool valid = false;
        if (!option || strcmp(option, "") == 0) {
            break; 
        }
#define CHECK_OPTION(name) do {\
        if (strcmp(option, "no_" #name) == 0) {\
            memcheck_proc_info.options.name = false;\
            valid = true;\
        } } while (0)
        CHECK_OPTION(check_addr);
        CHECK_OPTION(check_defined);
        CHECK_OPTION(check_stack);
#undef CHECK_OPTION
        DR_ASSERT(valid);
    }
    dr_global_free(to_free, strlen(optstr) + 1);
}

void
memcheck_exit(void)
{
    memcheck_proc_info.exited = true;
    dr_mutex_destroy(slab_flush_mutex);
}

static void
init_options(client_id_t id)
{
    umbra_client_t *client = &proc_info.client;

    memcheck_options_init(dr_get_options(id));
    memcheck_option_compatibility();

    memset(client, 0, sizeof(umbra_client_t));
    proc_info.options.stat = false;
    client->client_exit = memcheck_exit;
    client->thread_init = thread_init;
    client->thread_exit = thread_exit;
    client->interrupt = memcheck_interrupt;
    client->bb_is_interested = bb_is_interested;
    client->ref_is_interested = ref_is_interested;
    client->instrument_update = MEMCHECK_OPTION(check_addr) ? instrument_update
                                                            : NULL;
    client->instrument_update_user = MEMCHECK_OPTION(check_addr) ? instrument_update_user
                                                                 : NULL;
    client->app_to_app_transformation = app_to_app_transformation;
    client->app_unit_bits[0] = 0;
    client->shd_unit_bits[0] = 0;
    client->num_steal_regs = 2;
    client->memory_map_is_valid = mm_is_valid;
    client->shadow_page_alloc = shadow_page_alloc;
}

static void
init_wrappers(void)
{
    int i;
    if (!MEMCHECK_OPTION(check_addr)) {
        return;
    }
    for (i = 0; i < NUM_WRAPPED_FUNCTIONS; i++) {
        function_t *func = wrapped_functions[i];
        DR_ASSERT(func->size != 0);
        umbra_wrap_func_address(func->start, func->size, func->name, func->pre_wrapper,
                                func->post_wrapper);
    }
}

void
umbra_client_init(client_id_t id)
{
    init_options(id);
    init_wrappers();
    slab_flush_count = 0;
    slab_flush_mutex = dr_mutex_create();
}

static bool
kernel_get_function_bounds(function_t *func)
{
    return dr_kernel_find_symbol(func->name, &func->start, &func->size);
}

static ssize_t
show_memcheck_stats(int cpu, char *buf)
{
    memcheck_tls_t *tls = per_cpu(memcheck_tls, cpu);
    char *orig_buf = buf;
    if (!tls) {
        return sprintf(buf, "cpu not yet initilized\n");
    }
#define PRINT_STAT(name)\
    buf += sprintf(buf, #name ": %lu\n", (unsigned long) tls->name)
    PRINT_STAT(num_init_addressable_bytes);
    PRINT_STAT(num_init_unaddressable_bytes);
    PRINT_STAT(num_reports);
    PRINT_STAT(num_missed_reports);
    PRINT_STAT(num_disabled_reports);
    PRINT_STAT(report_count);
    PRINT_STAT(num_slowpath_exits);
    PRINT_STAT(num_slowpath_slub_function);
    PRINT_STAT(num_slowpath_false_negatives);
    PRINT_STAT(num_eos_read);
#undef PRINT_STAT
    return buf - orig_buf;
}

static ssize_t
enable_checks(int cpu, char *buf)
{
    memcheck_tls_t *tls = per_cpu(memcheck_tls, cpu);
    tls->in_slub_function_sticky = false;
    /* Can't reset the report count because we might not be running on tls's cpu.
     */
    tls->reset_report_count = true;
    return sprintf(buf,
                   "Enabled checks. They will be automatically disabled "
                   "after %d error reports. See dmesg.\n",
                   MAX_NUM_MEMCHECK_REPORTS);
}

static ssize_t
disable_checks(int cpu, char *buf)
{
    memcheck_tls_t *tls = per_cpu(memcheck_tls, cpu);
    tls->in_slub_function_sticky = true;
    return sprintf(buf, "disabled checks\n");
}

static ssize_t
memcheck_test(int cpu, char *buf)
{
    if (memcheck_proc_info.exited) {
        return sprintf(buf, "memcheck already exited\n");
    } else {
        return memcheck_test_main(buf,
                                  MEMCHECK_OPTION(check_addr),
                                  MEMCHECK_OPTION(check_defined));
    }
}

static ssize_t
stackcheck_test(int cpu, char *buf)
{
    while (true) {
        asm volatile("push %rax");
    }
    return 0;
}

static ssize_t
enable_disable_test(int cpu, char *buf)
{
    int i;
    volatile char y;
    volatile char *x = kmalloc(1, GFP_KERNEL);
    for (i = 0; i < MAX_NUM_MEMCHECK_REPORTS + 1000; i++) {
        y = x[1];
    }
    kfree((char*)x);
    return 0;    
}

static dr_stats_t memcheck_stats;

int
umbra_client_kernel_init(void)
{
    int i;
    for (i = 0; i < NUM_WRAPPED_FUNCTIONS; i++) {
        if (!kernel_get_function_bounds(wrapped_functions[i])) {
            printk("kernel_get_function_bounds failed for %s\n",
                   wrapped_functions[i]->name);
            return -EINVAL;
        }
    }

#define KSYM(name, type, decl)\
    if (!dr_kernel_find_symbol(#name, (void**) &kernel_symbols.name, NULL)) {\
        printk("dr_kernel_find_symbol failed for " #name "\n");\
        return -EINVAL;\
    }
#include "ksymsx.h"
#undef KSYM

    if (dr_stats_init(&memcheck_stats)) {
        return -ENOMEM;
    }
#define ALLOC_STAT(name, fn) do {\
    if (dr_cpu_stat_alloc(&memcheck_stats, #name, fn, THIS_MODULE)) {\
        goto failed;\
    } } while (0)
    ALLOC_STAT(memcheck_stats, show_memcheck_stats);
    ALLOC_STAT(memcheck_test, memcheck_test);
    ALLOC_STAT(stackcheck_test, stackcheck_test);
    ALLOC_STAT(memcheck_disable, disable_checks);
    ALLOC_STAT(memcheck_enable, enable_checks);
    ALLOC_STAT(enable_disable_test, enable_disable_test);
#undef ALLOC_STAT
    if (memcheck_test_kernel_init()) {
        goto failed;
    }
    return 0;
failed:
    dr_stats_free(&memcheck_stats);
    return -ENOMEM;
}

void
umbra_client_kernel_exit(void)
{
    memcheck_test_kernel_exit();
    dr_stats_free(&memcheck_stats);
}
