#ifndef __HYPERCALL_H_
#define __HYPERCALL_H_

/* Print hypercall:
    Has NR 3, buffer's physical address in a0, and buffer length in a1.
*/
#define HYPERCALL_DYNAMORIO_NR 3

/* The size of a hypercall (metadata + body) cannot be more than
 * HYPERCALL_MAX_SIZE bytes. */
#define HYPERCALL_MAX_SIZE 2048

typedef enum {
    HYPERCALL_NOP,
    HYPERCALL_INIT,
    HYPERCALL_OPEN,
    HYPERCALL_CLOSE,
    HYPERCALL_WRITE,
    HYPERCALL_FLUSH,
} hypercall_type_t;

typedef struct {
    hypercall_type_t type;
    /* The size of the entire hypercall_t structure. For exmaple, for a
     * hypercall_write_t, size includes sizeof(hypercall_write_t) (which
     * includes hypercall_t by composition) and the length of the print buffer.
     */
    unsigned long size;
} __attribute__((__packed__)) hypercall_t;

typedef struct {
    hypercall_t hypercall;
} __attribute__((__packed__)) hypercall_nop_t;

/* Call made at the beginning of initialization. */
typedef struct {
    hypercall_t hypercall;
} __attribute__((__packed__)) hypercall_init_t;

/* Opens a file for writing. If the file already exists, it will be overwritten. */
typedef struct {
    hypercall_t hypercall;
    /* Given by the guest (i.e., made up). fd cannot be stderr or stdout.  fd is
     * given by the guest and used for future close and write calls. fd must be
     * non-negative and cannot be stdin (0), stdout (1), or stderr (2).  So, fd
     * must be > 2. */
    int fd;
    /* The file's name on the host's file system. &name is to be interpreted as
     * a null-terminated C string. */
    char fname;
} __attribute__((__packed__)) hypercall_open_t;

/* Closes the given file on the host. */
typedef struct {
    hypercall_t hypercall;
    int fd;
} __attribute__((__packed__)) hypercall_close_t;

typedef struct {
    hypercall_t hypercall;
    int fd;
    unsigned long count;
    /* The buffer starts at &buffer, but it can be longer than a single byte.
     * The size of this entire structure is indicated by hypercall.size. */
    char buffer;
} __attribute__((__packed__)) hypercall_write_t;

/* Flushes all writes to the given fd. */
typedef struct {
    hypercall_t hypercall;
    int fd;
} __attribute__((__packed__)) hypercall_flush_t;


#endif
