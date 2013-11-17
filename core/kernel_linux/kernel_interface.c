#include <linux/module.h>
#include <linux/cpumask.h>
#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/mm.h>

#include "dynamorio_module_interface.h"
#include "dynamorio_module_assert_interface.h"
#include "kernel_interface.h"
#include "hypercall_guest.h"
#include "page_table.h"

/* Used by kernel_find_dynamorio_module_bounds. */
void* dynamorio_dummy_symbol;
EXPORT_SYMBOL_GPL(dynamorio_dummy_symbol);

static void* heap = NULL;
static size_t heap_size;

struct dynamorio_page {
    char data[4096];
} __attribute__((packed));

ASSERT_TYPE_SIZE(4096, struct dynamorio_page);
DEFINE_PER_CPU_ALIGNED(struct dynamorio_page, dynamorio_page);

static void
zero_cpu_private_data(void) {
    int i;
    for (i = 0; i < kernel_get_online_processor_count(); i++) {
        memset(kernel_get_cpu_private_data(i), 0, sizeof(struct dynamorio_page));
    }
}

typedef struct {
    unsigned long address;
    struct module *module;
    bool has_size;
    size_t size;
    const char *name;
} kernel_symbol_t;

static void
get_symbol_size(kernel_symbol_t *symbol)
{
    char *buffer = NULL;
    char *c;
    unsigned long offset;

    symbol->has_size = false;
    buffer = kmalloc(strlen(symbol->name) + 100, GFP_ATOMIC);
    if (!buffer) {
        goto done;
    }
    sprint_symbol(buffer, symbol->address);
    c = buffer;
    for (;;) {
        if (*c == '\0') {
            goto done;
        }
        if (*c == '+') {
            break;
        }
        c++;
    }
    if (sscanf(c, "+%lx/%lx", &offset, &symbol->size) != 2) {
        goto done;
    }
    symbol->has_size = true;

done:
    kfree(buffer);
}

static int
find_kernel_sybmol_callback(void *data, const char *name, struct module *module,
                            unsigned long address)
{
    kernel_symbol_t *symbol = (kernel_symbol_t*) data;
    if (strcmp(name, symbol->name) == 0) {
        symbol->module = module;
        symbol->address = address;
        get_symbol_size(symbol);
        return 1;
    }
    return 0;
}

static bool 
find_kernel_symbol(kernel_symbol_t *symbol)
{
    if (kallsyms_on_each_symbol(find_kernel_sybmol_callback, symbol)) {
        return true;
    }
    printk("find_kernel_symbol failed for %s\n", symbol->name);
    return false;
}

bool
kernel_find_symbol(const char *name, void **address, size_t *size) {
    kernel_symbol_t symbol;
    symbol.name = name;
    if (find_kernel_symbol(&symbol)) {
        *address = (void*) symbol.address;
        if (symbol.has_size) {
            if (size) {
                *size = symbol.size;
            }
        } else {
            if (size) {
                *size = 0;
            }
        }
        return true;
    } else {
        return false;
    }
}

static void*
find_kernel_symbol_address(const char *name)
{
    kernel_symbol_t symbol;
    symbol.name = name;
    if (find_kernel_symbol(&symbol)) {
        return (void*) symbol.address;
    } else {
        return NULL;
    }
}

/* These functions aren't exported with EXPORT_SYMBOL, so we aren't supposed to
 * be able to access them within our module. So we use
 * find_kernel_symbol_address. */
kernel_symbol_t native_load_gs_index_symbol;
kernel_symbol_t gs_change_symbol;
static void* (*module_alloc_address)(unsigned long) = NULL;
static unsigned long (*module_kallsyms_lookup_name_address)(const char *name) = NULL;

bool
kernel_module_init(size_t dr_heap_size)
{
#ifdef HYPERCALL_DEBUGGING
    if (!hypercall_init()) {
        return false;
    }
#endif
    /* Some OS interfaces, such as get_thread_private_dcontext, rely on the TLS
     * initially being all 0. */
    zero_cpu_private_data();
    native_load_gs_index_symbol.name = "native_load_gs_index";
    if (!find_kernel_symbol(&native_load_gs_index_symbol)) {
        return false;
    }
    gs_change_symbol.name = "gs_change";
    if (!find_kernel_symbol(&gs_change_symbol)) {
        return false;
    }
    module_alloc_address = find_kernel_symbol_address("module_alloc");
    if (!module_alloc_address) {
        return false;
    }
    module_kallsyms_lookup_name_address =
        find_kernel_symbol_address("module_kallsyms_lookup_name");
    if (!module_kallsyms_lookup_name_address) {
        return false;
    }

    /* Use module_alloc so the heap is located close (i.e., 32-bit reachable) to
     * the module's text and data. The Linux kernel allocates only 1.5 GB of
     * virtual address space for modules, so we'll be close enough. See
     * Documentation/x86/x86_64/mm.txt.
     *
     * Allocate the heap here instead of in kernel_allocate_heap because
     * interrupts will probably be disabled when kernel_allocate_heap is called.
     * Because module_alloc uses vmalloc, it cannot be called when interrupts
     * are disabled.
     */
    heap_size = dr_heap_size;
    heap = module_alloc_address(heap_size);
    if (!heap) {
        printk("Failed to allocate %luB using module_alloc.\n", heap_size);
        return false;;
    }
    return true;
}

void kernel_module_exit()
{
    if (heap != NULL) {
        kernel_free_heap(heap);
    }
    heap = NULL;
}

bool
kernel_interface_init(void)
{
    return true;
}

void
kernel_interface_exit(void)
{
}

void*
kernel_load_shared_library(char* name)
{
    struct module* module;
    /* We're supposed to lock module_mutex here to use find_module. However, we
     * are screwed if we have to block because DR code should not be
     * interrupted. A better hack would be to use mutex_trylock, but the
     * kernel's module loader links mutex_trylock to the one defined in utils.c,
     * not one in Linux's linux/mutex.c :-(.
     */
    if (mutex_is_locked(&module_mutex)) {
        DR_ASSERT(false);
        return NULL;
    }
    module = find_module(name);
    return module;
}

#define MAX_QUALIFIED_NAME_LEN 256

void*
kernel_lookup_library_routine(void* lib, char* name)
{
    struct module* module = (struct module*) lib;
    /* Build a string with the format mod_name:routine_name. */
    int qualified_name_len = strlen(module->name) + strlen(name) + 1;
    /* Statically allocate because we can't access DR's heap from here. */
    char qualified_name[MAX_QUALIFIED_NAME_LEN];
    if (qualified_name_len + 1 > sizeof(qualified_name)) {
        DR_ASSERT(false);
        return NULL;
    }
    strcpy(qualified_name, module->name);
    qualified_name[strlen(module->name)] = ':';
    strcpy(qualified_name + strlen(module->name) + 1, name);
    DR_ASSERT(qualified_name[qualified_name_len] == '\0');
    return (void*) module_kallsyms_lookup_name_address(qualified_name);
}

static void
get_module_bounds(struct module *module, byte **start, byte **end)
{
    *start = (byte*) module->module_core;
    *end = (byte*) module->module_core + module->core_size;
}

bool
kernel_shared_library_bounds(void *lib, byte *addr, byte **start, byte **end)
{
    struct module* module = (struct module*) lib;
    DR_ASSERT(module != NULL);
    if (module == NULL) {
        return false;
    }
    get_module_bounds(module, start, end);
    DR_ASSERT(addr >= *start && addr < *end);
    return true;
}

byte*
kernel_get_module_base(byte *pc)
{
    byte *start, *end;
    struct module* module = __module_address((unsigned long)pc);
    if (module == NULL) {
        return NULL;
    }
    get_module_bounds(module, &start, &end);
    return start;
}

bool
kernel_find_dynamorio_module_bounds(byte **start, byte **end)
{
    const struct kernel_symbol *sym;
    struct module *this_module;
    sym = find_symbol("dynamorio_dummy_symbol", &this_module, NULL, true, true);
    if (sym == NULL) {
        return false;
    }
    get_module_bounds(this_module, start, end);
    return true;
}

static void
assert_heap_mapped(void *heap, size_t size) {
    struct task_struct *g, *p;
    do_each_thread(g, p) {
        vm_region_t region;
        if (!p->mm) {
            continue;
        }
        DR_ASSERT(p->mm->pgd);
        page_table_get_region((generic_page_table_entry_t *)p->mm->pgd, heap,
                              &region);
        DR_ASSERT(region.present);
        DR_ASSERT(region.start <= heap);
        DR_ASSERT(region.end >= heap + size - 1);
        DR_ASSERT(region.access.writable);
        DR_ASSERT(region.access.executable);
        DR_ASSERT(!region.access.user);
    } while_each_thread(g, p);
}

void *
kernel_allocate_heap(size_t size)
{

    /* TODO(peter): The heap size should be passed to kernel_module_init. */
    if (heap_size >= size) {
        assert_heap_mapped(heap, size);
        return heap;
    } else {
        return NULL;
    }
}

void
kernel_free_heap(void* heap)
{
    vfree(heap);
    heap = NULL;
}

int
kernel_get_online_processor_count()
{
    return num_online_cpus();
}

int
kernel_get_present_processor_count()
{
	return num_present_cpus();
}

void
kernel_init_cpu_private_data(size_t *size, size_t *gs_offset)
{
    *gs_offset = (size_t) &per_cpu_var(dynamorio_page);
    *size = sizeof(struct dynamorio_page);
}

void *
kernel_get_cpu_private_data(int cpu) {
    return &per_cpu(dynamorio_page, cpu);
}

int
kernel_get_cpu_id(void) {
    return smp_processor_id();
}

void
kernel_run_on_all_cpus(void (*func) (void *info), void *info)
{
    on_each_cpu(func, info, false/* wait */);
}

void
kernel_printk(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);
}

#define KERNEL_ENV_MAX 20

typedef struct {
    char name[KERNEL_ENV_NAME_MAX];
    char value[KERNEL_ENV_VALUE_MAX];
} kernel_env_t;

static kernel_env_t env_vars[KERNEL_ENV_MAX];
static int env_count = 0;

void
kernel_setenv(const char* name, const char* value)
{
    DR_ASSERT(env_count < KERNEL_ENV_MAX);
    DR_ASSERT(strlen(name) < KERNEL_ENV_NAME_MAX);
    DR_ASSERT(strlen(value) < KERNEL_ENV_VALUE_MAX);
    strncpy(env_vars[env_count].name, name, KERNEL_ENV_NAME_MAX);
    strncpy(env_vars[env_count].value, value, KERNEL_ENV_VALUE_MAX);
    env_count += 1;
}

const char*
kernel_getenv(const char* name)
{
    int i;
    for (i = 0; i < env_count; i++) {
        if (strcmp(name, env_vars[i].name) == 0) {
            return (const char*) env_vars[i].value;
        }
    }
    return NULL;
}

static bool
pc_within_symbol(void *pc, kernel_symbol_t *symbol) {
    return symbol->has_size &&
           pc >= (void*) symbol->address &&
           pc < (void*) (symbol->address + symbol->size);
}

bool
kernel_native_swapgs(void* pc)
{
    /* This is a shameful hack. We want to allow the swapgs instructions inside
     * of native_load_gs_index. 
     *
     * TODO(peter): We might also need to allow some of the swapgs instructions
     * in the fixup routines (e.g., bad_gs in entry_64.S). I'm not sure yet
     * because we are suppressing all swapgs instructions elsewhere, so
     * everything might just cancel out. In general, this could be fixed by not
     * using thread-local storage or emulating swapgs; both alternatives would
     * be painful.
     *
     * TODO(peter): Is there a more robust way to get the end of native_load_gs_index
     * than adding 30 bytes to its starting address?
     */
    return pc_within_symbol(pc, &native_load_gs_index_symbol) ||
           pc_within_symbol(pc, &gs_change_symbol);
#if 0
    return pc >= (void*) native_load_gs_index_address &&
           pc <= (void*) (((char*) native_load_gs_index_address) + 30);
#endif
}

bool
is_kernel_code(void *pc)
{
    unsigned long p = (unsigned long) pc;
    /* Taken from Documentation/x86/x86_64/mm.txt */
    return (p >= 0xffffffff80000000 && p < 0xffffffffa0000000) ||
           (p >= 0xffffffffa0000000 && p < 0xfffffffffff00000);

    /* Could be less strict and check that pc > 0x00007fffffffffff */
}
