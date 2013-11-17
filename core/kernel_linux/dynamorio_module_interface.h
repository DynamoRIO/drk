#ifndef __DYNAMORIO_MODULE_INTERFACE_H_
#define __DYNAMORIO_MODULE_INTERFACE_H_

/* Exported information per-cpu. */
typedef struct {
    /* The address and size of the kstats data. A user-mode program will be
     * compiled with same DR headers as the main DR kernel module, so it will be
     * able to read the information in this structure.
     */
    void *kstats_data;
    unsigned long kstats_size;
} dr_cpu_exports_t;

typedef struct {
    void *stats_data;
    unsigned long stats_size;
} dr_exports_t;

extern void dr_pre_smp_init(dr_exports_t *exports, const char* options);
extern void dr_smp_init(dr_cpu_exports_t *cpu_exports);
extern void dr_smp_exit(void);
extern void dynamorio_app_take_over(void);
extern void dr_terminate(const char* reason);

#endif
