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
 * Utility functions
 *
 * Author:
 *     Qin Zhao
 */

#ifndef _UTILS_H_
#define _UTILS_H_ 1

#include "umbra.h"
#include "global.h"

#ifdef   assert
#  undef assert
#endif

#define TESTALL(mask, var) (((mask) & (var)) == (mask))
#define TESTANY(mask, var) (((mask) & (var)) != 0)

#define ALIGN_BACKWARD(x, alignment) (((ptr_uint_t)x) & (~((ptr_uint_t)(alignment)-1)))
#define ALIGN_FORWARD(x, alignment) \
    ((((ptr_uint_t)x) + ((alignment)-1)) & (~((ptr_uint_t)(alignment)-1)))
#define SET_TO_NOPS(addr, size) memset(addr, 0x90, size)


/* save reg before where in ilist */
void
umbra_save_reg(void         *drcontext,
               umbra_info_t *info,
               instrlist_t  *ilist,
               instr_t      *where,
               reg_id_t      reg);

/* restore reg before where in ilist */
void
umbra_restore_reg(void         *drcontext,
                  umbra_info_t *info,
                  instrlist_t  *ilist,
                  instr_t      *where,
                  reg_id_t      reg);

/* save aflags from eax */
void
umbra_save_eax_aflags(void        *drcontext,
                     umbra_info_t *info,
                     instrlist_t *ilist,
                     instr_t     *where);

/* restore aflags into eax */
void
umbra_restore_eax_aflags(void        *drcontext,
                        umbra_info_t *info,
                        instrlist_t *ilist,
                        instr_t     *where);

/*
 * IR Manipulation Utility Function
 */
void
instrlist_truncate(void *drcontext, instrlist_t *ilist, instr_t *instr);

bool instr_writes_to_aflags(instr_t *instr);

bool
instr_uses_aflags(instr_t *instr);

bool
instr_writes_to_any_aflags(instr_t *instr);

bool
instr_writes_to_all_aflags(instr_t *instr);

bool
instr_reads_from_aflags(instr_t *instr);

bool 
isntr_writes_to_aflags(instr_t *instr);

instr_t *
instr_get_next_app_instr(instr_t *instr);

bool
ref_is_stack_mem(basic_block_t *bb, mem_ref_t *ref);

bool
ref_is_tls(opnd_t opnd);

bool
ref_is_local_var(basic_block_t *bb, mem_ref_t *ref);

bool
ref_is_far_var(mem_ref_t *ref);

file_t
umbra_open_thread_log(thread_id_t tid);

file_t
umbra_open_proc_log(process_id_t tid);

app_pc
umbra_align_cache_line(app_pc pc);

#endif /* _UTILS_H_ */
