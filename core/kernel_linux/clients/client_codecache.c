#include <linux/module.h>
#include "dr_api.h"
#include "dr_kernel_utils.h"
MODULE_LICENSE("Dual BSD/GPL");

typedef struct {
    uint64 count;
    byte* retaddr;
    byte* cache_start;
    byte* cache_end;
} client_info_t;

#define CLIENT_CACHE_SIZE 128

/* Pointer to count for each CPU. */
static client_info_t **cpu_client_info;

static byte*
emit_client_code(void *drcontext, client_info_t *client, byte *pc)
{
    instrlist_t *ilist = instrlist_create(drcontext);
    instr_t *where;
    instrlist_init(ilist);
    where = instrlist_first(ilist);
    /* Insert (save eflags, inc, restore eflags). */
    dr_save_arith_flags(drcontext, ilist, where, SPILL_SLOT_1);
    instrlist_meta_preinsert(ilist, where,
        INSTR_CREATE_inc(drcontext,
                         OPND_CREATE_ABSMEM((byte *) &client->count, OPSZ_8)));
    dr_restore_arith_flags(drcontext, ilist, where, SPILL_SLOT_1);
    instrlist_meta_append(ilist,
        INSTR_CREATE_jmp_ind(drcontext,
                             OPND_CREATE_ABSMEM(&client->retaddr, OPSZ_PTR)));
    return instrlist_encode(drcontext, ilist, pc, true);
}

static void
thread_init_event(void *drcontext)
{
    client_info_t * client =
        (client_info_t*) dr_thread_alloc(drcontext, sizeof(client_info_t));
    dr_set_tls_field(drcontext, client);
    memset(client, 0, sizeof(client_info_t));
    cpu_client_info[dr_get_thread_id(drcontext)] = client;
    client->cache_start = dr_thread_alloc(drcontext, CLIENT_CACHE_SIZE);
    client->cache_end = emit_client_code(drcontext, client, client->cache_start);
}

static void
thread_exit_event(void *drcontext)
{
    client_info_t *client = (client_info_t*) dr_get_tls_field(drcontext);
    cpu_client_info[dr_get_thread_id(drcontext)] = NULL;
    dr_thread_free(drcontext, client->cache_start, CLIENT_CACHE_SIZE);
    dr_thread_free(drcontext, client, sizeof(client_info_t));
}

static dr_emit_flags_t
bb_event(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
         bool translating) {
    instr_t *first = instrlist_first(bb);
    client_info_t *client = dr_get_tls_field(drcontext);
    instr_t *label = INSTR_CREATE_label(drcontext);

    instrlist_meta_preinsert(bb, first,
        INSTR_CREATE_mov_st(drcontext,
                            OPND_CREATE_ABSMEM((byte*) &client->retaddr, OPSZ_PTR),
                            opnd_create_instr(label)));
    instrlist_meta_preinsert(bb, first,
        INSTR_CREATE_jmp(drcontext,
                         opnd_create_pc(client->cache_start)));
    instrlist_meta_preinsert(bb, first, label);
    instrlist_meta_preinsert(bb, first, INSTR_CREATE_nop(drcontext));

    return DR_EMIT_DEFAULT;    
}

static bool
interrupt_event(void *drcontext, dr_interrupt_t *interrupt)
{
    client_info_t *client = (client_info_t*) dr_get_tls_field(drcontext);
    if (interrupt->frame->xip >= client->cache_start &&
        interrupt->frame->xip < client->cache_end) {
        interrupt->frame->xip = client->retaddr;
    }
    return true;
}

void
drinit(client_id_t id)
{
    printk("drinit %d\n", id);
    dr_register_interrupt_event(interrupt_event);
    dr_register_thread_init_event(thread_init_event);
    dr_register_thread_init_event(thread_exit_event);
    dr_register_bb_event(bb_event);
}

static dr_stats_t stats;

static ssize_t
show_cpu_info(int cpu, char *buf)
{
    if (!cpu_client_info[cpu]) {
        return sprintf(buf, "cpu %d not yet initilized\n", cpu);
    } else {
        return sprintf(buf, "%lu\n", cpu_client_info[cpu]->count);
    }
}

static int __init
instrcount_init(void)
{
    cpu_client_info = kzalloc(dr_cpu_count() * sizeof(client_info_t*),
                              GFP_KERNEL);
    if (!cpu_client_info) {
        return -ENOMEM;
    }
    if (dr_stats_init(&stats)) {
        kfree(cpu_client_info);
        return -ENOMEM;
    }
    if (dr_cpu_stat_alloc(&stats, "bbcount", show_cpu_info, THIS_MODULE)) {
        kfree(cpu_client_info);
        dr_stats_free(&stats);
        return -ENOMEM;
    }
    return 0;
}

static void __exit
instrcount_exit(void)
{
    kfree(cpu_client_info);
}

module_init(instrcount_init);
module_exit(instrcount_exit);
