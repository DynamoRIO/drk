#ifndef __USER_UNIT_TEST
#include "globals.h"
#include "utils.h"
#endif

typedef struct _barrier_t {
    mutex_t lock;
    int count;
} barrier_t;

void barrier_init(barrier_t *barrier, int count);
void barrier_destroy(barrier_t *barrier);
/* Returns true for only exactly one thread (i.e., the thread that is the "last"
 * to reach the barrier.)
 */
bool barrier_wait(barrier_t *barrier);
