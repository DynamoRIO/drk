    
/* SLUB_FUNCTION(name, nargs) */

#define SLUB_FUNCTION_NORET(name, nargs, ...)\
    SLUB_FUNCTION(name, reg_t, nargs, __VA_ARGS__) 
    
    SLUB_FUNCTION_NORET(kfree, 1, const void *)
    SLUB_FUNCTION(__kmalloc, void *, 2, size_t, gfp_t)
    SLUB_FUNCTION(__kmalloc_node, void *, 3, size_t, gfp_t, int)
    SLUB_FUNCTION(__kmalloc_track_caller, void *, 3, size_t, gfp_t, unsigned long)
    SLUB_FUNCTION(__kmalloc_node_track_caller, void *, 4, size_t, gfp_t, int, unsigned long)
    SLUB_FUNCTION(kmem_cache_alloc, void *, 2, struct kmem_cache*, gfp_t)
    SLUB_FUNCTION(kmem_cache_alloc_node, void *, 3, struct kmem_cache *, gfp_t, int)
    SLUB_FUNCTION_NORET(kmem_cache_free, 2, struct kmem_cache *, void *)
    SLUB_FUNCTION(new_slab, struct page *, 3, struct kmem_cache *, gfp_t, int)
    SLUB_FUNCTION_NORET(__free_slab, 2, struct kmem_cache *, struct page *)
    SLUB_FUNCTION_NORET(schedule, 0)
    /* Include these so the stack traces work properly. */
    SLUB_FUNCTION(kmem_cache_create, struct kmem_cache *, 5, const char *, size_t, size_t, unsigned long, void (*)(void *))
    SLUB_FUNCTION(kmem_cache_shrink, int, 1, struct kmem_cache *)
    SLUB_FUNCTION_NORET(kmem_cache_destroy, 1, struct kmem_cache *)
    SLUB_FUNCTION(ksize, size_t, 1, const void *)
    /* These ones are important because of interprocessor interrupts. On the
     * CPUs that receive the IPIs these functions aren't called by public slab
     * functions. Instead, they're called by smp_call_function. */
     /* TODO(peter): A proper solution would be to detect when a CPU inside of a
      * slab function is issuing an IPI. Doing this would set in_slab on all of
      * the other CPUs.
      */
    SLUB_FUNCTION_NORET(flush_cpu_slab, 1, void *)
    SLUB_FUNCTION_NORET(deactivate_slab, 2, struct kmem_cache *, struct kmem_cache_cpu*)

    /* These functions we need to wrap to suppress false positives with
     * check_defined. */
    SLUB_FUNCTION(skb_clone, struct sk_buff *, 2, struct sk_buff *, gfp_t)

    /* Functions wrapped for stack checking. */
    SLUB_FUNCTION_NORET(free_task, 1, struct task_struct *)
    /* copy_process has a bunch of arguments, but we don't care about them. */
    SLUB_FUNCTION(copy_process, struct task_struct *, 0)
