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

#include "utils.h"

#include "dr_api.h"
#include "analyzer.h"

#ifdef LINUX
# ifndef LINUX_KERNEL
#  include <unistd.h>    /* sleep */
# endif
#else
#endif

#ifndef LINUX_KERNEL
# include <string.h>
#endif


/* save reg before where in ilist */
void
umbra_save_reg(void         *drcontext,
               umbra_info_t *info,
               instrlist_t  *ilist,
               instr_t      *where,
               reg_id_t      reg)
{
    int slot;
    instr_t *instr;

    DR_ASSERT(reg >= REG_SPILL_START && reg <= REG_SPILL_STOP);
    slot  = reg - REG_SPILL_START;
    instr = INSTR_CREATE_mov_st(drcontext,
                                OPND_CREATE_ABSMEM(&info->spill_regs[slot],
                                                   OPSZ_PTR),
                                opnd_create_reg(reg));
    instrlist_meta_preinsert(ilist, where, instr);
}
    

/* restore reg before where in ilist */
void
umbra_restore_reg(void         *drcontext,
                  umbra_info_t *info,
                  instrlist_t  *ilist,
                  instr_t      *where,
                  reg_id_t      reg)
{
    int slot;
    instr_t *instr;

    DR_ASSERT(reg >= REG_SPILL_START &&
              reg <= REG_SPILL_STOP);
    slot  = reg - REG_SPILL_START;
    instr = INSTR_CREATE_mov_ld(drcontext,
                                opnd_create_reg(reg),
                                OPND_CREATE_ABSMEM(&info->spill_regs[slot],
                                                   OPSZ_PTR));
    instrlist_meta_preinsert(ilist, where, instr);
}


/* save aflags from eax */
void
umbra_save_eax_aflags(void         *drcontext,
                      umbra_info_t *info,
                      instrlist_t  *ilist,
                      instr_t      *where)
{
    instr_t *instr;

    instr = INSTR_CREATE_mov_st(drcontext, 
                                OPND_CREATE_ABSMEM(&info->aflags,
                                                   OPSZ_4),
                                opnd_create_reg(REG_EAX));
    instrlist_meta_preinsert(ilist, where, instr);
}


/* restore aflags into eax */
void
umbra_restore_eax_aflags(void         *drcontext,
                         umbra_info_t *info,
                         instrlist_t  *ilist,
                         instr_t      *where)
{
    instr_t *instr;

    instr = INSTR_CREATE_mov_ld(drcontext,
                                opnd_create_reg(REG_EAX),
                                OPND_CREATE_ABSMEM(&info->aflags,
                                                   OPSZ_4)),
    instrlist_meta_preinsert(ilist, where, instr);
}


/* Remove the rest instructions from ilist after instr (including instr) */
void
instrlist_truncate(void *drcontext, instrlist_t *ilist, instr_t *instr)
{
    instr_t *next_instr;

    DR_ASSERT_MSG(instr != NULL, "Wrong instr to truncate!");
    for(; instr != NULL; instr = next_instr) {
        next_instr = instr_get_next(instr);
        instrlist_remove(ilist, instr);
        instr_destroy(drcontext, instr);
    }
}


/* return if instruction */
bool
instr_uses_aflags(instr_t *instr)
{
    uint aflags;
    
    aflags = instr_get_arith_flags(instr);
    if (TESTANY(EFLAGS_READ_6, aflags) || 
        TESTANY(EFLAGS_WRITE_6, aflags))
        return true;

    return false;
}


bool
instr_writes_to_any_aflags(instr_t *instr)
{
    uint aflags;
    
    aflags = instr_get_arith_flags(instr);
    if (TESTANY(EFLAGS_WRITE_6, aflags))
        return true;

    return false;    
}


bool
instr_writes_to_all_aflags(instr_t *instr)
{
    uint aflags;
    
    aflags = instr_get_arith_flags(instr);
    if (TESTALL(EFLAGS_WRITE_6, aflags))
        return true;

    return false;   
}


bool
ref_is_string_ref(mem_ref_t *ref)
{
    if (!opcode_is_rep_ins(ref->opcode))
        return false;
    if (!opnd_is_far_base_disp(ref->opnd))
        return false;

    return true;
}


bool
ref_is_stack_mem(basic_block_t *bb, mem_ref_t *ref)
{
    if (!opnd_is_base_disp(ref->opnd))
        return false;
    if (opnd_get_base(ref->opnd) == REG_XSP)
        return true;
    return false;
}


bool
ref_is_tls(opnd_t opnd)
{
    reg_id_t seg;
    if (opnd_is_far_base_disp(opnd)) {
        seg = opnd_get_segment(opnd);
        if (seg == SEG_FS || seg == SEG_GS)
            return true;
    }
    return false;
}


bool
ref_is_local_var(basic_block_t *bb, mem_ref_t *ref)
{
    if (ref_is_stack_mem(bb, ref) &&
        opnd_get_index(ref->opnd) != REG_NULL)
        return true;
    
    return false;
}


bool
ref_is_far_var(mem_ref_t *ref) 
{
    if (opnd_is_far_base_disp(ref->opnd))
        return true;
    return false;
}


file_t
umbra_open_thread_log(thread_id_t tid)
{
#ifdef LINUX_KERNEL
    return our_stdout;
#else
    char   name[128];
    int    len;
    file_t logfile;

    /* XXX: Windows need a absolute path */
    name[0] = '\0';
    len = dr_snprintf(name, sizeof(name)/sizeof(name[0]),
                      "umbra.%s.%d.thread.log", 
                      dr_get_application_name(), tid);
    DR_ASSERT(len > 0);
    name[sizeof(name)/sizeof(name[0])-1] = '\0';
    logfile = dr_open_file(name, DR_FILE_READ | DR_FILE_WRITE_APPEND);
    DR_ASSERT(logfile != INVALID_FILE);
    return logfile;
#endif
}


file_t 
umbra_open_proc_log(process_id_t pid)
{
#ifdef LINUX_KERNEL
    return our_stdout;
#else
    char   name[128];
    int    len;
    file_t logfile;

    /* XXX: Windows need a absolute path */
    name[0] = '\0';
    len = dr_snprintf(name, sizeof(name)/sizeof(name[0]),
                      "umbra.%s.%d.proc.log", 
                      dr_get_application_name(), pid);
    DR_ASSERT(len > 0);
    name[sizeof(name)/sizeof(name[0])-1] = '\0';
    logfile = dr_open_file(name, DR_FILE_READ | DR_FILE_WRITE_APPEND);
    DR_ASSERT(logfile != INVALID_FILE);
    return logfile;
#endif
}


app_pc
umbra_align_cache_line(app_pc pc)
{
    app_pc new_pc;

    new_pc = (app_pc)ALIGN_FORWARD(pc, proc_get_cache_line_size());
    SET_TO_NOPS(pc, new_pc - pc);
    return new_pc;
}


reg_id_t 
reg_to_32bit(reg_id_t reg)
{
    if (reg_is_32bit(reg))
        return reg;
    if (reg_is_64bit(reg)) 
        return (reg + (REG_START_32 - REG_START_64));
    
    DR_ASSERT(false);
    return REG_NULL;
}


bool
instr_writes_to_aflags(instr_t *instr)
{
    return instr_writes_to_any_aflags(instr);
}


bool
instr_reads_from_aflags(instr_t *instr)
{
    uint aflags;
    
    aflags = instr_get_arith_flags(instr);
    if (TESTANY(EFLAGS_READ_6, aflags))
        return true;
    return false;
}

instr_t *
instr_get_next_app_instr(instr_t *instr)
{
    while (instr != NULL) {
        instr = instr_get_next(instr);
        if (instr_get_app_pc(instr) != NULL && 
            !instr_is_meta_may_fault(instr))
            return instr;
    }
    return NULL;
}
