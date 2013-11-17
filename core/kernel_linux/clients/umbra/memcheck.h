#ifndef __MEMCHECK_H__
#define __MEMCHECK_H__

#include <asm/ptrace.h>
#include <linux/stacktrace.h>

typedef enum {
    /* Reading or writing to unaddressable memory. */
    MEMCHECK_ERROR_UNADDRESSABLE,
    /* Reading an undefined value. */
    MEMCHECK_ERROR_UNDEFINED_READ,
    /* Wrote from end of stack. */
    MEMCHECK_ERROR_EOS,
    /* Not an error. Used for error checking on the slowpath. */
    MEMCHECK_ERROR_NONE,
} memcheck_error_type_t;

typedef struct {
    memcheck_error_type_t type;
    void *addr;
    struct pt_regs regs;
    struct stack_trace trace;
    unsigned long trace_entries[32]; 
} memcheck_report_t;

/* These all have to be called with interrupts disabled. */
void memcheck_enable_check_define(bool enable);
void memcheck_reset_reports(void);
void memcheck_disable_reporting(void);
void memcheck_enable_reporting(void);
int memcheck_num_reports(void);
int memcheck_num_disabled_reports(void);
memcheck_report_t *memcheck_get_report(void);

/* Unit test. */
ssize_t memcheck_test_main(char *buf, bool check_addr, bool check_defined);
int memcheck_test_kernel_init(void);
void memcheck_test_kernel_exit(void);

#endif
