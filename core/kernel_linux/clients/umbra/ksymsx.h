#define KSYM_VAR(name, type)\
    KSYM(name, type, type name)

#define KSYM_FPTR(name, ret_type, ...)\
    KSYM(name, ret_type (*)(__VA_ARGS__), ret_type (*name)(__VA_ARGS__))

    KSYM_VAR(slub_lock, struct rw_semaphore*)
    KSYM_VAR(slab_caches, struct list_head*)
    KSYM_FPTR(flush_cpu_slab, void, void*)
