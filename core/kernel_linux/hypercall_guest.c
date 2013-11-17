#include "configure.h"

#ifdef HYPERCALL_DEBUGGING

#include "hypercall.h"
#include "page_table.h"
/* For kvm_hypercall3 */
#include <asm/kvm_para.h> 

bool
hypercall_send(hypercall_t* hypercall) {
    unsigned long physical_address;
    if (hypercall->size > HYPERCALL_MAX_SIZE) {
        return false;
    }
    if (!page_table_get_physical_address(get_l4_page_table(),
                                         hypercall,
                                         &physical_address)) {
        return false;
    }
    kvm_hypercall2(HYPERCALL_DYNAMORIO_NR, physical_address, hypercall->size);
    return true;
}

bool
hypercall_init(void) {
    bool ok;
    hypercall_init_t hypercall;
    hypercall.hypercall.type = HYPERCALL_INIT;
    hypercall.hypercall.size = sizeof(hypercall);
    ok = hypercall_send(&hypercall.hypercall);
    basic_assert(ok);
    return ok;
}

#endif
