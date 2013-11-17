#include <linux/module.h>
#include "dr_api.h"
#include "dr_kernel_utils.h"
MODULE_LICENSE("Dual BSD/GPL");

#define TESTALL(mask, var) (((mask) & (var)) == (mask))
#define TESTANY(mask, var) (((mask) & (var)) != 0)

static bool eflags_opt;

typedef struct {
    bool (*include)(instr_t *instr);
    const char *name;
} instr_counter_t;

static bool
always_include(instr_t *instr)
{
    return true;
}

instr_counter_t instr_counters[] = {
    {always_include, "total"},
    {instr_is_stringop, "stringop"},
    {instr_is_stringop_loop, "stringop_loop"},
};

#define NUM_INSTR_COUNTERS (sizeof(instr_counters) / sizeof(instr_counters[0]))

typedef struct {
    uint64 dynamic_count[NUM_INSTR_COUNTERS];
    uint64 static_count[NUM_INSTR_COUNTERS];
    uint64 eflags_saved;
    uint64 eflags_dead;
} instr_count_tls_t;

/* For easy access from stat reporting and error reporting code. They can't use
 * dr_get_current_drcontext b/c they run in the kernel context. */
DEFINE_PER_CPU(instr_count_tls_t*, instr_count_tls);

static instr_count_tls_t*
get_instr_count_tls(void)
{
    return __get_cpu_var(instr_count_tls);
}

static void
set_instr_count_tls(instr_count_tls_t* tls)
{
    /* GIANT HACK! Use Linux's per_cpu variable for instrcount TLS because DR
     * only provides TLS for a single client
     * (dcontext->client_data->user_field). We'd like to use instrcount with
     * other clients.
     */
    __get_cpu_var(instr_count_tls) = tls;
}

static void
thread_init_event(void *drcontext)
{
    instr_count_tls_t *tls = dr_thread_alloc(drcontext,
                                             sizeof(instr_count_tls_t));
    memset(tls, 0, sizeof(instr_count_tls_t));
    set_instr_count_tls(tls);
}

static void
thread_exit_event(void *drcontext)
{
    dr_thread_free(drcontext, get_instr_count_tls(), sizeof(instr_count_tls_t));
    set_instr_count_tls(NULL);
}

static dr_emit_flags_t
bb_event(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
         bool translating) {
    bool any_counters = false;
    uint64 instr_count[NUM_INSTR_COUNTERS];
    instr_t *instr;
    instr_t *first = instrlist_first(bb);
    instr_t *where = first;
    instr_count_tls_t *tls = get_instr_count_tls();
    int i;
    bool eflags_saved = true;

    for (instr = first; instr != NULL; instr = instr_get_next(instr)) {
        /* Since it doesn't matter where we insert, look for a place 
           where the eflags are dead. */
        uint flags = instr_get_arith_flags(instr);
        if (TESTALL(EFLAGS_WRITE_6, flags) && !TESTANY(EFLAGS_READ_6, flags)) {
            where = instr;
            eflags_saved = false;
            break;
        }
    }

    if (!eflags_opt) {
        eflags_saved = true;
    }

    for (i = 0; i < NUM_INSTR_COUNTERS; i++) {
        instr_count[i] = 0;
        for (instr = first; instr != NULL; instr = instr_get_next(instr)) {
            if (instr_counters[i].include(instr)) {
                instr_count[i]++;
                tls->static_count[i]++;
                any_counters = true;
            }
        }
    }

    if (!any_counters) {
        return DR_EMIT_DEFAULT;
    }

    /* Insert (save eflags, inc, restore eflags). */
    if (eflags_saved) {
        tls->eflags_saved++;
        dr_save_arith_flags(drcontext, bb, where, SPILL_SLOT_1);
    } else {
        tls->eflags_dead++;
    }
    for (i = 0; i < NUM_INSTR_COUNTERS; i++) {
        uint64 *count = &tls->dynamic_count[i];
        if (instr_count[i] == 0) {
            continue;
        }
        instrlist_meta_preinsert(bb, where,
            INSTR_CREATE_add(drcontext,
                             OPND_CREATE_ABSMEM((byte *) count, OPSZ_8),
                             OPND_CREATE_INT_32OR8(instr_count[i])));
    }
    if (eflags_saved) {
        dr_restore_arith_flags(drcontext, bb, where, SPILL_SLOT_1);
    }

    return DR_EMIT_DEFAULT;
}

void
drinit(client_id_t id)
{
    printk("drinit %d\n", id);
    if (strcmp(dr_get_options(id), "no_eflags_opt") == 0) {
        eflags_opt = false;
    } else {
        eflags_opt = true;
    }
    dr_register_thread_init_event(thread_init_event);
    dr_register_thread_exit_event(thread_exit_event);
    dr_register_bb_event(bb_event);
}

static dr_stats_t stats;

static ssize_t
show_cpu_instr_count(int cpu, char *buf, bool dynamic)
{
    instr_count_tls_t *tls = per_cpu(instr_count_tls, cpu);
    char *orig_buf = buf;
    int i;
    if (!tls) {
        buf += sprintf(buf, "cpu %d not yet initilized\n", cpu);
        return buf - orig_buf;
    }
    for (i = 0; i < NUM_INSTR_COUNTERS; i++) {
        buf += sprintf(buf, "%s: %lu\n", instr_counters[i].name,
                       dynamic ? tls->dynamic_count[i] :
                                 tls->static_count[i]);
    }
    return buf - orig_buf;
}

static ssize_t
show_cpu_dynamic_instr_count(int cpu, char *buf)
{
    return show_cpu_instr_count(cpu, buf, true);
}

static ssize_t
show_cpu_static_instr_count(int cpu, char *buf)
{
    return show_cpu_instr_count(cpu, buf, false);
}

static ssize_t
show_cpu_instr_count_stats(int cpu, char *buf)
{
    instr_count_tls_t *tls = per_cpu(instr_count_tls, cpu);
    char *orig_buf = buf;
    buf += sprintf(buf, "eflags_saved: %lu\n", tls->eflags_saved);
    buf += sprintf(buf, "eflags_dead: %lu\n", tls->eflags_dead);
    return buf - orig_buf;
}

static int __init
instrcount_init(void)
{
    if (dr_stats_init(&stats)) {
        return -ENOMEM;
    }
#define ALLOC_STAT(name, fn) do {\
    if (dr_cpu_stat_alloc(&stats, #name, fn, THIS_MODULE)) {\
        goto failed;\
    } } while (0)
    ALLOC_STAT(dynamic, show_cpu_dynamic_instr_count);
    ALLOC_STAT(static, show_cpu_static_instr_count);
    ALLOC_STAT(stats, show_cpu_instr_count_stats);
#undef ALLOC_STAT
    return 0;
failed:
    dr_stats_free(&stats);
    return -ENOMEM;
}

static void __exit
instrcount_exit(void)
{
    dr_stats_free(&stats);
}

module_init(instrcount_init);
module_exit(instrcount_exit);
