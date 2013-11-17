#include <linux/module.h>
#include "dr_api.h"
#include "dr_kernel_utils.h"
MODULE_LICENSE("Dual BSD/GPL");

#define MAX_BB_INSTRS 1024

typedef struct _frag_stats_t {
    struct _frag_stats_t *next;
    unsigned long execution_count;
} frag_stats_t;

typedef struct {
    ushort *histogram;
    ushort *histogram_tail;
    uint64 max_tail_expansion;
    ushort instr_pairs[OP_LAST];
    bool use_last_fragment;
    void *last_fragment_tag;
    int last_fragment_length;

    frag_stats_t* frag_stats;
} bb_stats_t;

#if 0
static frag_stats_t*
create_frag_stats(void *drcontext, bb_stats_t *bb_stats)
{
    frag_stats_t *next = dr_thread_alloc(drcontext, sizeof(*next));
    memset(next, 0, sizeof(next));
    next->next = bb_stats->frag_stats;
    bb_stats->frag_stats = next;
    return next;
}
#endif

DEFINE_PER_CPU(bb_stats_t*, bb_stats_tls);

static bb_stats_t*
get_bb_stats_tls(void)
{
    return __get_cpu_var(bb_stats_tls);
}

static void
set_bb_stats_tls(bb_stats_t* tls)
{
    /* GIANT HACK! Use Linux's per_cpu variable for instrcount TLS because DR
     * only provides TLS for a single client
     * (dcontext->client_data->user_field). We'd like to use instrcount with
     * other clients.
     */
    __get_cpu_var(bb_stats_tls) = tls;
}

static ushort*
alloc_histogram(void *drcontext) {
    ushort *histogram = dr_thread_alloc(drcontext,
                                        (MAX_BB_INSTRS + 1) * sizeof(*histogram));
    memset(histogram, 0, (MAX_BB_INSTRS + 1) * sizeof(*histogram));
    return histogram;
}

static void
thread_init_event(void *drcontext)
{
    bb_stats_t *bb_stats =
        (bb_stats_t*) dr_thread_alloc(drcontext, sizeof(bb_stats_t));
    memset(bb_stats, 0, sizeof(bb_stats_t));
    bb_stats->histogram = alloc_histogram(drcontext);
    bb_stats->histogram_tail = alloc_histogram(drcontext);
    set_bb_stats_tls(bb_stats);
}

static dr_emit_flags_t
bb_event(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
         bool translating) {
    
    bb_stats_t *bb_stats = get_bb_stats_tls();

    if (bb_stats->use_last_fragment) {
        bb_stats->use_last_fragment = false;
        bb_stats->max_tail_expansion +=
            bb_stats->last_fragment_length *
            dr_fragment_size(drcontext, bb_stats->last_fragment_tag);
    }

    DR_ASSERT(!translating || !dr_is_emulating_interrupt_return(drcontext));

    if (!translating) {
        int length = instrlist_length(bb);
        DR_ASSERT(length <= MAX_BB_INSTRS);
        if (!dr_is_emulating_interrupt_return(drcontext)) {
            DR_ASSERT(bb_stats->histogram[length] < USHORT_MAX);
            bb_stats->histogram[length] += 1;
            bb_stats->last_fragment_tag = tag; 
            bb_stats->last_fragment_length = length;
            bb_stats->use_last_fragment = true;

            if (length == 2) {
                instr_t *first = instrlist_first(bb);
                //instr_t *second = instr_get_next(first);
                bb_stats->instr_pairs[instr_get_opcode(first)]++;
            }
        } else {
            DR_ASSERT(bb_stats->histogram_tail[length] < USHORT_MAX);
            bb_stats->histogram_tail[length] += 1;
        }
    }

    return DR_EMIT_DEFAULT;    
}

void
drinit(client_id_t id)
{
    printk("drinit %d\n", id);
    dr_register_thread_init_event(thread_init_event);
    dr_register_bb_event(bb_event);
}

static dr_stats_t stats;

static ssize_t
show_cpu_max_tail_expansion(int cpu, char *buf)
{
    bb_stats_t *tls = per_cpu(bb_stats_tls, cpu);
    if (!tls) {
        return sprintf(buf, "cpu %d not yet initilized\n", cpu);
    } else {
        return sprintf(buf, "%lu\n", tls->max_tail_expansion);
    }
}

static ssize_t
sprint_histogram(char *buf, ushort *histogram)
{
    int i;
    char *orig_buf = buf;
    for (i = 0; i <= MAX_BB_INSTRS; i++) {
        if (histogram[i] > 0) {
            buf += sprintf(buf, "%d:%u\n", i, histogram[i]);
        }
    }
    return buf - orig_buf;
}

static ssize_t
show_cpu_length_hisotgram(int cpu, char *buf)
{
    bb_stats_t *bb_stats = per_cpu(bb_stats_tls, cpu);
    if (!bb_stats) {
        return sprintf(buf, "cpu %d not yet initilized\n", cpu);
    }
    return sprint_histogram(buf, bb_stats->histogram);
}

static ssize_t
show_cpu_length_hisotgram_tail(int cpu, char *buf)
{
    bb_stats_t *bb_stats = per_cpu(bb_stats_tls, cpu);
    if (!bb_stats) {
        return sprintf(buf, "cpu %d not yet initilized\n", cpu);
    }
    return sprint_histogram(buf, bb_stats->histogram_tail);
}

static ssize_t
show_cpu_instr_pairs(int cpu, char *buf)
{
    int i;
    //int  j;
    char *orig_buf = buf;
    bb_stats_t *bb_stats = per_cpu(bb_stats_tls, cpu);
    if (!bb_stats) {
        return sprintf(buf, "cpu %d not yet initilized\n", cpu);
    }
    for (i = 0; i < OP_LAST; i++) {
        //bool printed = false;
        #if 0
        int total = 0;
        for (j = 0; j < OP_LAST; j++) {
            total += bb_stats->instr_pairs[i];
        /*
            if (bb_stats->instr_pairs[i][j] > 0) {
                if (!printed) {
                    buf += sprintf(buf, "%d:", i);
                    printed = true;
                }
                buf += sprintf(buf, " %d=%d", j, bb_stats->instr_pairs[i][j]);
            }
            */
        }
        /*
        if (printed) {
            buf += sprintf(buf, "\n");
        }
        */
        #endif
        if (bb_stats->instr_pairs[i] > 0) {
            buf += sprintf(buf, "%d %d\n", i, bb_stats->instr_pairs[i]);
        }
    }
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
    ALLOC_STAT(max_tail_expansion, show_cpu_max_tail_expansion);
    ALLOC_STAT(length_histogram, show_cpu_length_hisotgram);
    ALLOC_STAT(length_histogram_tail, show_cpu_length_hisotgram_tail);
    ALLOC_STAT(instr_pairs, show_cpu_instr_pairs);
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
