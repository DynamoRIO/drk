/*********************************************************************
 * Copyright (c) 2010 Massachusetts Institute of Technology          *
 *                                                                   *
 * Permission is hereby granted, free of charge, to any person       *
 * obtaining a copy of this software and associated documentation    *
 * files (the "Software"), to deal in the Software without           *
 * restriction, including without limitation the rights to use,      *
 * copy, modify, merge, publish, distribute, sublicense, and/or sell *
 * copies of the Software, and to permit persons to whom the         *
 * Software is furnished to do so, subject to the following          *
 * conditions:                                                       *
 *                                                                   *
 * The above copyright notice and this permission notice shall be    *
 * included in all copies or substantial portions of the Software.   *
 *                                                                   *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,   *
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES   *
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND          *
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT       *
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,      *
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING      *
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR     *
 * OTHER DEALINGS IN THE SOFTWARE.                                   *
 *********************************************************************/

/*
 * global.c -- global header files for all the data structure used by
 *             multiple files.
 */


#ifndef _GLOBAL_H_
#define _GLOBAL_H_  1

#include <linux/module.h>
#include "dr_api.h"


#ifdef X64
# define ADDR_TOTAL_BITS    64
# define PTR_SIZE           8
/* 8G for 64-bit address space */
# define ADDRESS_SPACE_UNIT_ALIGN_BITS 32
# define ADDRESS_SPACE_UNIT_ALIGN_SIZE ((reg_t)1  << ADDRESS_SPACE_UNIT_ALIGN_BITS)
# define ADDRESS_SPACE_UNIT_ALIGN_MASK ((reg_t)-1 << ADDRESS_SPACE_UNIT_ALIGN_BITS)
#else
# define ADDR_TOTAL_BITS    32
# define PTR_SIZE           4
# define ADDRESS_SPACE_UNIT_ALIGN_BITS 28
# define ADDRESS_SPACE_UNIT_ALIGN_SIZE ((reg_t)1  << ADDRESS_SPACE_UNIT_ALIGN_BITS)
# define ADDRESS_SPACE_UNIT_ALIGN_MASK ((reg_t)-1 << ADDRESS_SPACE_UNIT_ALIGN_BITS)
#endif

#define  STACK_ALIGN_SIZE   PTR_SIZE

#define PAGE_ALIGN_BITS    12
#define PAGE_ALIGN_MASK    ((reg_t)(-1) << PAGE_ALIGN_BITS)



/* The sum of following four bits should be the same as
 * ADDR_TOTAL_BITS
 */
#define ADDR_IGNORE_BITS    0
#define ADDR_SHADOW_BITS    12
#define ADDR_OFFSET_BITS    20
#define ADDR_TAG_BITS       (ADDR_TOTAL_BITS - ADDR_OFFSET_BITS - ADDR_SHADOW_BITS - ADDR_IGNORE_BITS)


#define ADDR_SHADOW_MASK  ((1 << ADDR_SHADOW_BITS) - 1)

#define PAGE_TABLE_BITS       12
#define REF_FAST_CHECK_MASK   ~((1 << PAGE_TABLE_BITS) - 1)
#ifdef X64
# define HASH_ENTRY_BITS       4
#else
# define HASH_ENTRY_BITS       2
#endif
#define REF_HASH_TABLE_BITS   16
#define REF_HASH_TABLE_SIZE   (1 << REF_HASH_TABLE_BITS)
#define REF_HASH_TABLE_MASK   ((REF_HASH_TABLE_SIZE - 1) << HASH_ENTRY_BITS)

#define OP_call_fall -1
#define OP_cbr_fall  -2


#define REG_SPILL_START REG_XAX
#ifdef X64
# define REG_SPILL_STOP REG_R15
#else
# define REG_SPILL_STOP REG_EDI
#endif
#define NUM_SPILL_REGS  (REG_SPILL_STOP - REG_SPILL_START + 1)

#define UMBRA_REG_TO_POS(reg, pos) do {        \
    DR_ASSERT(reg >= REG_SPILL_START);        \
    DR_ASSERT(reg <= REG_SPILL_STOP);         \
    pos = reg - REG_SPILL_START;              \
    } while (0);

#define UMBRA_POS_TO_REG(reg, pos) do {            \
    DR_ASSERT(pos >= 0 && pos <= NUM_SPILL_REGS); \
    reg = pos + REG_SPILL_START;                  \
    } while(0);

#ifdef DOUBLE_SHADOW
# define MAX_NUM_SHADOWS 2
#else
# define MAX_NUM_SHADOWS 1
#endif


#define MASK_SW_READ_B     0x01
#define MASK_SW_READ_W     0x0101
#define MASK_SW_READ_D     0x01010101
#define MASK_SW_WRITE_B    0x02
#define MASK_SW_WRITE_W    0x0202
#define MASK_SW_WRITE_D    0x02020202
#define MASK_RET_PROTECT_B 0x04
#define MASK_RET_PROTECT_W 0x0404
#define MASK_RET_PROTECT_D 0x04040404

#ifdef LINUX_KERNEL
#define KERNEL_TEXT_BASE ((void*) 0xffffffff80000000)
#define KERNEL_TEXT_SIZE (512 * 1024 * 1024)
#endif


enum WatchAction {WA_NONE, WA_INT, WA_FUNC, WA_COUNT_SEP, WA_COUNT_SUM, WA_MARK};

typedef struct _watchpoint_t watchpoint_t;
struct _watchpoint_t {
    int id;
    int pc;
    int addr;
    int size;
    int condition;
    int action;
    watchpoint_t *next;
};



enum MemOpndType {MemNULL, MemRead, MemWrite, MemModify};


enum {
    PC_MALLOC = 0,
    PC_CALLOC,
    PC_REALLOC,
    PC_FREE,
    NUM_FUNCS,
};



typedef struct _offset_slot_t {
#ifdef PAGE_REF_COUNT
    uint64 count;
#else
    ptr_int_t tag;
    ptr_int_t offset;
#endif
} offset_slot_t;



typedef struct _module_info_t {
    app_pc old_func[NUM_FUNCS];
    app_pc new_func[NUM_FUNCS];
} module_info_t;


enum {
    LIBC_malloc = 0,
    LIBC_calloc,
    LIBC_realloc,
    LIBC_free,
    LIBC_last
};

typedef struct _replace_func_t {
    byte *old_func;
    byte *new_func;
    char *name;
} replace_func_t;




#define MAX_NUM_STEAL_REGS 4



typedef struct _reg_status_t {
    reg_id_t reg;    /* register id */
    bool used;       /* if used for mem addresing */
    bool dead;       /* if a dead reg in app  */
    bool steal;      /* if steal by umbra      */
    bool restore_now;/* if need instrument for restore value */
    bool save_now;   /* if need instrument for save    value */
    int  count;      /* usage count in a bb */
} reg_status_t;


typedef struct _ref_cache_t {
    reg_t tag;    /* also app_base */
    reg_t offset[MAX_NUM_SHADOWS];
} ref_cache_t;


typedef struct _mem_ref_t mem_ref_t;
struct _mem_ref_t {
    int    id;
    app_pc pc;
    int    opcode;
    enum MemOpndType type;
    instr_t *instr;
    opnd_t   opnd;
    reg_t  count;
    ref_cache_t *cache;
    reg_t  note[4];
};


typedef struct _basic_block_t {
    int    id;
    app_pc tag;
    uint   flags;
    int    length;
    void  *bytes;
    int    edge_in;
    int    edge_out;
    int    count;
    mem_ref_t *refs;
    int    num_refs;
    int    num_app_instrs;
}basic_block_t;


typedef struct _link_edge_t link_edge_t;
struct _link_edge_t {
    int    id;
    app_pc dst_tag;
    int    src_bb;
    int    dst_bb;
    uint   flags;
    int    opcode;
    int    next_in;
    int    next_out;
    int    count;
};



typedef struct _func_t {
    int    id;
    int   entry;
    app_pc pc;
}func_t;



typedef struct _code_hash_t code_hash_t;
struct _code_hash_t {
    app_pc    tag;
    int       length;
    int       bb;
    code_hash_t *next;
};

typedef struct _ref_hash_t {
    reg_t  tag;
    reg_t  value;
} ref_hash_t;

typedef struct _table_t {
    /* Basic Block Table */
    int         num_bbs;
    int         max_num_bbs;
    basic_block_t *bb_table;
    /* Link Edge Table */
    int         num_edges;
    int         max_num_edges;
    link_edge_t   *edge_table;
    /* Mem Ref Table */
    int         num_refs;
    int         max_num_refs;
    mem_ref_t     *ref_table;
    /* Func List Table */
    int         num_funcs;
    int         max_num_funcs;
    func_t   *func_table;
    /* Ref Cache Table */
    int         num_ref_cache;
    int         max_num_ref_cache;
    ref_cache_t *ref_cache_table;
    /* Hashtable for code */
    int         code_hash_size;
    int         code_hash_mask;
    code_hash_t  **code_hash_table;
    /* app bytes */
    int         bytes_size;
    int         max_bytes_size;
    app_pc      bytes_table;
    app_pc      bytes_ptr;
} table_t;



typedef struct _ref_group_t {
    int leader;
    int offset;
} ref_group_t;


typedef struct _mem_opnd_t mem_opnd_t;
struct _mem_opnd_t {
    mem_ref_t *ref;
    reg_id_t   base;
    reg_id_t   index;
    int        disp;
    ref_group_t  group;
};


typedef struct _ilist_info_t {
    basic_block_t *bb;
    int  num_mems;
    int  num_instrs;
    int  num_steals;
    bool translate; /* if insert translation code */
    reg_id_t reg_addr;
    reg_status_t aflags;
    reg_status_t eax;
    reg_status_t regs[NUM_SPILL_REGS];
    mem_opnd_t *mems;
} ilist_info_t;

typedef struct _syscacll_info_t {
    int   sysnum;
    reg_t params[6];
} syscall_info_t;


typedef struct _memory_mod_t memory_mod_t;
typedef struct _memory_map_t memory_map_t;

#define MOD_UNIT_BITS 16
#define MOD_UNIT_SIZE (1 << MOD_UNIT_BITS)
#define MOD_UNIT_MASK ((reg_t)-1 << MOD_UNIT_BITS)
struct _memory_mod_t {
    void *app_base;
    void *app_end;
    void *shd_base[MAX_NUM_SHADOWS];
    void *shd_end[MAX_NUM_SHADOWS];
    memory_map_t *map;
    memory_mod_t *next;
};


struct _memory_map_t {
    void *app_base;
    void *app_end;
    void *shd_base[MAX_NUM_SHADOWS];
    void *shd_end[MAX_NUM_SHADOWS];
    reg_t offset[MAX_NUM_SHADOWS];
    reg_t app_prot;
    memory_map_t *next;
    memory_mod_t *mods;
};

typedef struct _wrap_func_stack_t {
    void *stack;
    void *app_ret;
} wrap_func_stack_t;

typedef struct _umbra_info_t {
    void   *client_tls_data;
    void   *drcontext;
    int     tid;
    file_t  log;
    /* Last map looked up by memory_map_thread_lazy_add */
    memory_map_t * last_lazy_add;
    /* last reference module */
    reg_t   last_map_tag;
    reg_t   last_map_offset[MAX_NUM_SHADOWS];
    /* app stack module */
    reg_t   stack_map_tag;
    reg_t   stack_map_offset[MAX_NUM_SHADOWS];
    /* context switch */
    reg_t   aflags;
    reg_t   spill_regs[NUM_SPILL_REGS];
    reg_t   app_stack;
    reg_t   cache_pc;
    reg_t   umbra_stack[4];
    reg_t   umbra_stack_ptr;
    reg_t   umbra_stack_ptr_off;
    syscall_info_t syscall;
    /* tables for umbra data structures */
    table_t table;
    /* code cache */
    app_pc  code_cache_start;
    app_pc  code_cache_end;
    app_pc  map_check_pc[NUM_SPILL_REGS];
    app_pc  map_search_pc[NUM_SPILL_REGS];
    app_pc  clean_call_pc[NUM_SPILL_REGS];
    app_pc  app_ret;
#ifndef LINUX_KERNEL
    app_pc  post_func;
#endif
#define MAX_STACK_DEPTH 16
    wrap_func_stack_t  wrap_func_stack[MAX_STACK_DEPTH];
    int     stack_depth;
    /* translation table */
    memory_map_t *maps;
    ref_cache_t  *stack_ref_cache;
    /* client */
    reg_id_t  steal_regs[MAX_NUM_STEAL_REGS];
    /* statics */
    reg_t     num_app_instrs;
    reg_t     num_app_refs;
    reg_t     num_ref_caches;
    reg_t     num_dyn_instrs;
#ifdef LINUX_KERNEL
    reg_t     num_dyn_user_refs;
#endif
    reg_t     num_dyn_refs;
    reg_t     num_bb_inline_checks;
    reg_t     num_trace_inline_checks;
    reg_t     num_fast_lookups;
    reg_t     num_map_checks;
    reg_t     num_map_searchs;
    reg_t     num_clean_calls;
    reg_t     num_aflags_restores;
    reg_t     num_reg_restores;
    reg_t     num_sigs;
    reg_t     num_pre_wrap_calls;
    reg_t     num_post_wrap_calls;
    reg_t     num_post_without_pre;
    reg_t     num_pre_wrap_intr;
    reg_t     num_post_wrap_intr;
    reg_t     num_pages_for_page_table;
    reg_t     num_pages_for_shadow;
    reg_t     num_ro_pages_in_shadow;
    reg_t     num_dead_regs;
    reg_t     num_spill_regs;
    reg_t     num_dead_aflags;
    reg_t     num_spill_aflags;

    /* table stats */
    reg_t     num_table_bytes;
    reg_t     num_table_bb;
    reg_t     num_table_ref;
    reg_t     num_table_ref_cache;
    reg_t     num_table_edge;
    reg_t     num_table_func;
    reg_t     num_table_code_hash;
} umbra_info_t;


typedef struct _umbra_client_t {
    /* different options */
    bool opt_merge;
    bool orig_addr;
    int  app_unit_bits[MAX_NUM_SHADOWS];
    int  shd_unit_bits[MAX_NUM_SHADOWS];
    int  num_steal_regs;

    void (*client_exit)(void);
    void (*thread_init)(void *drcontext,
                        umbra_info_t *umbra_info);
    void (*thread_exit)(void *drcontext,
                        umbra_info_t *umbra_info);
    bool (*bb_is_interested)(umbra_info_t*, basic_block_t*);
    bool (*ref_is_interested)(umbra_info_t*, mem_ref_t*);
    void (*instrument_update)(void         *drcontext,
                              umbra_info_t  *umbra_info,
                              mem_ref_t    *ref,
                              instrlist_t  *ilist,
                              instr_t      *where);
    void (*instrument_update_ex)(void         *drcontext,
                                 umbra_info_t  *umbra_info,
                                 mem_opnd_t    *mem,
                                 instrlist_t  *ilist,
                                 instr_t      *where);
#ifdef LINUX_KERNEL
    void (*instrument_update_user)(void         *drcontext,
                                   umbra_info_t  *umbra_info,
                                   mem_ref_t    *ref,
                                   instrlist_t  *ilist,
                                   instr_t      *where);
    void (*shadow_page_alloc)(umbra_info_t *umbra_info,
                              void *addr, size_t size); 
    bool (*interrupt)(umbra_info_t *umbra_info, dr_interrupt_t *interrupt);
#endif
    void (*app_to_app_transformation)(void *drcontext,
				                      umbra_info_t *umbra_info,
                                      void *tag,
                                      instrlist_t *bb,
                                      bool for_trace);

    void (*pre_umbra_instrument_bb)(void          *drcontext,
				    umbra_info_t *umbra_info,
				    void          *tag,
				    instrlist_t   *ilist,
				    bool          for_trace);
    void (*post_umbra_instrument_bb)(void *drcontext,
                                     umbra_info_t *umbra_info,
                                     void *tag,
                                     instrlist_t  *ilist,
                                     bool for_trace);
    void (*shadow_memory_module_destroy)(memory_map_t *map);
  void (*shadow_memory_module_create) (memory_map_t *map);
  bool (*memory_map_is_valid)(void *start, void *end);
  bool (*pre_syscall)(void *drcontext, umbra_info_t *info, int sysnum);
  void (*post_syscall)(void *drcontext, umbra_info_t *info, int sysnum);
    dr_signal_action_t
    (*signal_handler)(void *drcontext, dr_siginfo_t *siginfo, umbra_info_t *info);
} umbra_client_t;


typedef struct _option_t {
    /* optimization to remove the map check,
     * only works in 64-bit address space
     * ref EMS64 paper in ISMM'10
     */
    bool opt_ems64;
    /* optimization to perform fast inline map check */
    bool opt_inline_check;
    /* optimization to add map check */
    bool opt_map_check;
    /* optimization to add hashtable lookup */
    bool opt_hash_lookup;
    /* optimization to perform smart aflags stealing */
    bool opt_aflags_stealing;
    /* enable unsafe aflags stealing */
    bool opt_unsafe_aflags_stealing;
    /* optimization to perform smart reg stealing */
    bool opt_regs_stealing;
    /* enable unsafe register stealing */
    bool opt_unsafe_regs_stealing;
    /* optimization on trace creation */
    bool opt_trace;
    /* optimization to use one reference cache for
     * a group of app references that access memory nearby.
     */
    bool opt_group;
    /* option to collect program execution statistics */
    bool stat;
    /* adaptive memory allocation for memory reducing */
    bool adapt_alloc;
    /* swap stack for lean procedure */
    bool swap_stack;
    /* double shadowing */
    bool double_shadow;
}option_t;


typedef struct _proc_info_t {
    void         *mutex;         /* lock for updating proc_info   */
    memory_map_t *maps;          /* mapping table from app to shd */
    void         *heap_brk;      /* system heap boundary */
    void         *stack_top;     /* system stack top     */
    int           num_threads;   /* num of threads started        */
    int           num_offs;      /* num of translation offsets    */
    process_id_t  pid;           /* process id                    */
    file_t        log;           /* umbra process log file        */
    option_t      options;       /* umbra runtime options         */

    reg_t         unit_bits;      /* address space unit bits      */
    reg_t         unit_mask;      /* address space unit mask      */
    reg_t         unit_size;      /* address space unit size      */
    reg_t         bin_map_tag;    /* executable memory map tag    */
    /* executable memory map offsets */
    reg_t         bin_map_offset[MAX_NUM_SHADOWS];
#ifndef LINUX_KERNEL
    reg_t         lib_map_tag;    /* library memory map tag       */
    /* library memory map offsets */
    reg_t         lib_map_offset[MAX_NUM_SHADOWS];
#endif
    reg_t         offs[16];       /* traslation offsets           */
    reg_t bb_tag;
    reg_t bb_pc;

    umbra_client_t client;        /* umbra client data structure  */
    reg_t   num_instrs;
} proc_info_t;
extern proc_info_t proc_info;

#define MAX_FUNC_ARGS 6

typedef struct {
    reg_t arg[MAX_FUNC_ARGS];
} func_args_t;

typedef void (*pre_func_wrapper_t)(dr_mcontext_t *mc, func_args_t *args);
typedef void (*post_func_wrapper_t)(dr_mcontext_t *mc, func_args_t *args,
                                    reg_t return_value);

typedef struct _wrap_func_t {
    const char *modname;
    const char *name;
    app_pc func;
    size_t size;
    post_func_wrapper_t post_func;
    pre_func_wrapper_t pre_func;
    void  *next;
} wrap_func_t;
extern wrap_func_t *wrap_funcs;

/* umbra client init function */
void
umbra_client_init(client_id_t id);

#ifdef LINUX_KERNEL
int
umbra_client_kernel_init(void);

void
umbra_client_kernel_exit(void);
#endif

void
umbra_wrap_func(const char *modname,
                const char *name,
                pre_func_wrapper_t pre_func,
                post_func_wrapper_t post_func);

void
umbra_wrap_func_address(app_pc func,
                        size_t func_size,
                        const char *name,
                        pre_func_wrapper_t pre_func,
                        post_func_wrapper_t post_func);

reg_t
umbra_get_arg(int index);

reg_t
umbra_get_ret_value(void);

umbra_info_t *
umbra_get_info(void);

byte *
umbra_get_app_addr(umbra_info_t *info, dr_mcontext_t *mc, mem_ref_t *opnd);


#endif /* _GLOBAL_H_ */

