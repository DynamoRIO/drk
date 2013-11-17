#include "controller_stats_interface.h"
#include "configure.h"
#include <cstring>
#include <stdexcept>
#include <sstream>
#include <sys/types.h>
#define NOT_DYNAMORIO_CORE_PROPER
#define NOT_DYNAMORIO_CORE
typedef void* dcontext_t;
typedef unsigned long timestamp_t;
typedef pid_t thread_id_t;
typedef int file_t;
extern "C" {
#include "stats.h"
#include "lib/dr_stats.h"
}
using namespace std;



#ifdef KSTATS
static void
dump_kstat(kstat_variable_t *var, const char *name,
           const char *desc, ostream &out) {
    out << "\"" << name << "\" : {" << endl;
#define PRINT_LAST_FIELD(field) \
    out << "  \""#field"\" : " << var->field << endl
#define PRINT_FIELD(field) \
    out << "  \""#field"\" : " << var->field << ", " << endl
        PRINT_FIELD(num_self);
        PRINT_FIELD(total_self);
        PRINT_FIELD(total_sub);
        PRINT_FIELD(min_cum);
        PRINT_FIELD(max_cum);
        PRINT_LAST_FIELD(total_outliers);
#undef PRINT_FIELD
    out << "}," << endl;
}

/* Copied from stats.c */
static void
kstat_init_variable(kstat_variable_t *kv, const char *name)
{
    memset(kv, 0x0, sizeof(kstat_variable_t));
    kv->name = name;
    kv->min_cum = (timestamp_t)-1;
}

/* Copied from stats.c */
static void
kstat_merge_var(kstat_variable_t *destination, kstat_variable_t *source)
{
    destination->num_self += source->num_self;
    destination->total_self += source->total_self;
    destination->total_sub += source->total_sub;
    destination->total_outliers += source->total_outliers;
    if (destination->min_cum > source->min_cum) 
        destination->min_cum = source->min_cum;
    if (destination->max_cum < source->max_cum) 
        destination->max_cum = source->max_cum;
}

/* Copied from stats.c */
static void
kstats_evaluate_expressions(kstat_variables_t *kvars)
{
    /* sum can be recomputed at any time and target is reinitialized,
     * all chained KSTAT_SUM equations should appear in evaluation order
     */
#define KSTAT_SUM(desc, name, var1, var2)               \
        kstat_init_variable(&kvars->name, #name);       \
        kstat_merge_var(&kvars->name, &kvars->var1);    \
        kstat_merge_var(&kvars->name, &kvars->var2);
#define KSTAT_DEF(desc, name)   /* nothing to do */
#include "kstatsx.h"    
#undef KSTAT_SUM
#undef KSTAT_DEF
}

/* equivalent to KSTAT_DEF for the rest of the file */
#define KSTAT_SUM(desc, name, var1, var2) KSTAT_DEF(desc, name)
#endif

void
dump_kstats(char *buffer, unsigned long buffer_size, ostream& out)
{
#ifdef KSTATS
    kstat_variables_t *ks;
    if (sizeof(*ks) != buffer_size) {
        stringstream ss;
        ss << "dump_kstats: sizeof(kstat_variables_t) [" << sizeof(*ks) << "]";
        ss << " != buffer_size [" << buffer_size << "].";
        throw runtime_error(ss.str());
    }
    ks = (kstat_variables_t *) buffer;
    kstats_evaluate_expressions(ks);
    out << "{";
#define KSTAT_DEF(desc, name)                   \
    if (ks->name.num_self)                      \
        dump_kstat(&ks->name, #name, desc, out);
#include "kstatsx.h"                                          
#undef KSTAT_DEF
    out << "\"__end\" : 0" << endl;
    out << "}" << endl;
#else
    out << "configure with KSTATS defined!" << endl;
#endif
}

void
dump_stats(char *buffer, unsigned long buffer_size, ostream& out)
{
    dr_statistics_t *stats = (dr_statistics_t*) buffer;
    out << "{" << endl;
    for (uint i = 0; i < stats->num_stats; i++) {
        single_stat_t *stat = &stats->stats[i];
        out << "  \"" << stat->name << "\": " << stat->value << "," << endl;
    }
    out << "  \"__end\" : 0" << endl;
    out << "}" << endl;
}
