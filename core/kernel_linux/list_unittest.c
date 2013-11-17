#include <stdio.h>
#include <assert.h>
#include "list.h"

typedef struct {
    struct list_head list;
    int x;
} elem_t;

int main(void) {
    struct list_head head; 
    elem_t e[10];
    int i;
    INIT_LIST_HEAD(&head);
    for (i = 0; i < 10; i++) {
        e[i].x = i;
        list_add_tail(&e[i].list, &head);
    }

    for (i = 0;;i++) {
        int x;
        if (list_empty(&head)) break;
        x = list_entry(head.next, elem_t, list)->x;
        assert(x == i);
        list_del(&e[i].list);
    }
    return 0;
}
