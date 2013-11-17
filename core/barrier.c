#include "barrier.h"

void
barrier_init(barrier_t *barrier, int count)
{
    barrier->count = count;
    ASSIGN_INIT_LOCK_FREE(barrier->lock, barrier_lock);
}

void
barrier_destroy(barrier_t *barrier)
{
    DELETE_LOCK(barrier->lock);
}

bool
barrier_wait(barrier_t *barrier)
{
    int count;
    mutex_lock(&barrier->lock);
    ASSERT(barrier->count > 0);
    barrier->count -= 1;
    count = barrier->count;
    mutex_unlock(&barrier->lock);
    if (count == 0) {
        return true;
    }
    for (;;) {
        mutex_lock(&barrier->lock);
        count = barrier->count; 
        mutex_unlock(&barrier->lock);
        if (count == 0) {
            return false;
        }
    }
}
