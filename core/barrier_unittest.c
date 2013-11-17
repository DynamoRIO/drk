#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

typedef pthread_mutex_t mutex_t;

#define ASSERT(x) assert((x))

#define ASSIGN_INIT_LOCK_FREE(lock, type) pthread_mutex_init(&(lock), NULL)

#define DELETE_LOCK(lock) pthread_mutex_destroy(&(lock))

void mutex_lock(pthread_mutex_t* mutex) {
    pthread_mutex_lock(mutex);
}

void mutex_unlock(pthread_mutex_t* mutex) {
    pthread_mutex_unlock(mutex);
}

#include "barrier.c"

barrier_t b;
int x;
pthread_mutex_t m;
bool first;
void* thread_main(void* unused) {
    pthread_mutex_lock(&m);
    x += 1;
    pthread_mutex_unlock(&m);
    if (barrier_wait(&b)) {
        pthread_mutex_lock(&m);
        assert(first);
        first = false;
        pthread_mutex_unlock(&m);
    }
    return NULL;
}

#define N 20
int main() {
    int i;
    pthread_mutex_init(&m, NULL);
    x = 0;
    first = true;
    pthread_t threads[N];
    barrier_init(&b,  N + 1);

    for (i = 0; i < N; i++) {
        pthread_create(&threads[i], NULL, thread_main, NULL);
    }

    if (barrier_wait(&b)) {
        pthread_mutex_lock(&m);
        assert(first);
        first = false;
        pthread_mutex_unlock(&m);
    }
    assert(x == N);

    for (i = 0; i < N; i++) {
        pthread_join(threads[i], NULL);
    }
    return 0;
}
