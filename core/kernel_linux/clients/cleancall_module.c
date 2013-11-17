#include <linux/module.h>
#include "dr_api.h"
#include "dr_kernel_utils.h"
MODULE_LICENSE("Dual BSD/GPL");

typedef struct {
    uint64 count;
} instr_count_t;

void
clean_call(uint instruction_count)
{
    instr_count_t *count = dr_get_tls_field(dr_get_current_drcontext());
    count->count++;
}

/* Pointer to count for each CPU. */
static instr_count_t **cpu_instr_count;

static void
thread_init_event(void *drcontext)
{
    instr_count_t *instr_count =
        (instr_count_t*) dr_thread_alloc(drcontext, sizeof(instr_count_t));
    memset(instr_count, 0, sizeof(instr_count_t));
    cpu_instr_count[dr_get_thread_id(drcontext)] = instr_count;
    dr_set_tls_field(drcontext, instr_count);
    printk("Allocated instr_count %p for dcontext %p\n", instr_count, drcontext);
}

static void
thread_exit_event(void *drcontext) 
{
    cpu_instr_count[dr_get_thread_id(drcontext)] = NULL;
    dr_thread_free(drcontext, dr_get_tls_field(drcontext),
                   sizeof(instr_count_t));
}


static dr_emit_flags_t
bb_event(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
         bool translating) {
    uint num_instrs = 0;
    instr_t *instr;

    for (instr = instrlist_first(bb); instr != NULL; instr = instr_get_next(instr)) {
        num_instrs++;
    }

    /* Only do basic blocks with 5 instructions because inserting a clean call
     * on every basic block makes the system too slow!
     */
    if (num_instrs != 5) {
        return DR_EMIT_DEFAULT;
    }

    dr_insert_clean_call(drcontext, bb, instrlist_first(bb), clean_call, false,
                         1, OPND_CREATE_INT32(num_instrs));
    return DR_EMIT_DEFAULT;    
}

void
drinit(client_id_t id)
{
    printk("drinit %d\n", id);
    dr_register_thread_init_event(thread_init_event);
    dr_register_thread_exit_event(thread_exit_event);
    dr_register_bb_event(bb_event);
}

static dr_stats_t stats;

static ssize_t
show_cpu_instr_count(int cpu, char *buf)
{
    if (!cpu_instr_count[cpu]) {
        return sprintf(buf, "cpu %d not yet initilized\n", cpu);
    } else {
        return sprintf(buf, "%lu\n", cpu_instr_count[cpu]->count);
    }
}

static int __init
instrcount_init(void)
{
    cpu_instr_count = kzalloc(dr_cpu_count() * sizeof(instr_count_t*),
                              GFP_KERNEL);
    if (!cpu_instr_count) {
        return -ENOMEM;
    }
    if (dr_stats_init(&stats)) {
        kfree(cpu_instr_count);
        return -ENOMEM;
    }
    if (dr_cpu_stat_alloc(&stats, "instrcount", show_cpu_instr_count, THIS_MODULE)) {
        dr_stats_free(&stats);
        kfree(cpu_instr_count);
        return -ENOMEM;
    }
    return 0;
}

static void __exit
instrcount_exit(void)
{
    dr_stats_free(&stats);
    kfree(cpu_instr_count);
}

module_init(instrcount_init);
module_exit(instrcount_exit);
