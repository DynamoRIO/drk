#include <linux/module.h>
#include "dr_api.h"
MODULE_LICENSE("Dual BSD/GPL");

static dr_emit_flags_t
bb_event(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
         bool translating) {
    return DR_EMIT_DEFAULT;    
}

void
drinit(client_id_t id)
{
    dr_register_bb_event(bb_event);
}
