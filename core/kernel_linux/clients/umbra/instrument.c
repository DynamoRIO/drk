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
 * Module Name:
 *     Instrumentor -- instrument.c 
 *
 * Description:
 *     Perform instrumentation for umbra  
 *
 * Author: 
 *     Qin Zhao
 */

#include "umbra.h"
#include "table.h"
#include "instrument.h"
#include "shadow.h"
#include "optimize.h"
#include "cfg.h"
#ifndef LINUX_KERNEL
#  include <string.h>
#  include <stddef.h>  /* offsetof */
#endif

#define CODE_CACHE_SIZE (PAGE_SIZE << 2)

//#define EXP_MEMCHK
#ifdef EXP_MEMCHK
reg_t  limit = (reg_t)0x1 << 35;
reg_t *limit_ptr = &limit;
#define SMS_TABLE_SIZE (0x1 << 19)
reg_t *SMS_table[SMS_TABLE_SIZE];
#endif

//#define EXP_SMS64
#ifdef EXP_SMS64
#define L1_TABLE_SIZE (0x1 << 16)
#define L2_TABLE_SIZE (0x1 << 20)
reg_t **L1_table[L1_TABLE_SIZE];
reg_t *L2_table[L2_TABLE_SIZE];
#endif

static reg_id_t ARG_REGS[] = {
#if defined(LINUX) && defined(X64)
    REG_RDI,
    REG_RSI,
    REG_RDX,
    REG_RCX,
    REG_R8,
    REG_R9,
#else
# error Registers are not the same for windows / 32 bit.
#endif
};

#ifdef LINUX_KERNEL
static const void *min_kernel_addr = (void*) 0xffff800000000000;
#endif

/* 
 *            Note for the implementation
 *
 * instrument.c is used for instrumenting every basic block.
 * the information of the basic block instruction list is maintained
 * in ilist_info for optimal instrumtation point and scheme
 */

/*
 * # context switch 
 *   save aflags
 *   save %reg
 * # fast check ref cache 
 *   lea [ref]   => %r1
 *   %r1 & mask  => %r1
 *   cmp %r1, cache->tag
 *   je .update
 *   cmp %r1, min_kernel_addr
 *   jb .update_user
 *   mov r1 => cache->tag
 * # slow lookup                         
 *   mov next_pc => info->cache_pc   *  save app_stack_ptr
 *   jmp slow_lookup_code[r1]        *  load umbra_stack_ptr
 *                                   *  call slow_lookup_code[r1]
 *                                   *  restore app_stack  
 *   mov r1 => cache->offset 
 *   jmp .update                     * slow path has to skip user update
 * # update_user
 * .update_user
 *   ...
 *   jmp .restore_context
 * # update
 * .update
 *   lea [ref]   => %r1
 *   %r1 - cache->offset => %r1
 *   ... # update
 *  .restore_context
 * # context switch
 *   restore r1
 *   restore eflags
 * # application code
 *   ...
 */

/*---------------------------------------------------------------------*
 *                 instrlist info management routines                  *
 *---------------------------------------------------------------------*/

/* insert count increament */
static void
preinsert_count_inc(void        *drcontext, 
                    instrlist_t *ilist,
                    instr_t     *where,
                    reg_t       *count,
                    int          num)
{
    opnd_t opnd1, opnd2;
    instr_t *instr;
    opnd1 = OPND_CREATE_ABSMEM(count, OPSZ_PTR);
    if (num < 128)
        opnd2 = OPND_CREATE_INT8(num);
    else
        opnd2 = OPND_CREATE_INT32(num);
    instr = INSTR_CREATE_add(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
}


/* init reg_status for all registers  */
static void
ilist_info_regs_init(void         *drcontext, 
                     ilist_info_t *ilist_info)
{
    int i;
    reg_status_t *status;

    for (i = 0; i < NUM_SPILL_REGS; i++) {
        status = &ilist_info->regs[i];
        memset(status, 0, sizeof(reg_status_t));
        UMBRA_POS_TO_REG(status->reg, i);
    }
}


static void
ilist_info_regs_exit(void         *drcontext, 
                     ilist_info_t *ilist_info)
{
    /* do nothing */
}


/* 
 * this function is called after instrumenting shadow memory 
 * update code, it clears all registers that marked as used
 * for memory reference calculation.
 */
static void 
ilist_info_regs_reset(reg_status_t *regs)
{
    int i;
    for (i = 0; i < NUM_SPILL_REGS; i++) 
        regs[i].used = false;
}

static bool
is_implicit_stack_ref(mem_ref_t *ref)
{
    switch (ref->opcode) {
    case OP_push_imm:
    case OP_pushf:
    case OP_call:
    case OP_call_ind:
    case OP_push:
        /* The stack destination is the implicit second operand for all of these
         * instructions. */
        return opnd_same(instr_get_dst(ref->instr, 1), ref->opnd);
    }
    return false;
}


static void
ref_get_base_disp(mem_ref_t *ref, reg_id_t *base, reg_id_t *index, int *disp)
{
    if (opnd_is_base_disp(ref->opnd)) {
        *base  = opnd_get_base(ref->opnd);
        *index = opnd_get_index(ref->opnd);
        *disp  = opnd_get_disp(ref->opnd);
    } else {
        *base  = REG_NULL;
        *index = REG_NULL;
        *disp  = 0;
    }

    if (is_implicit_stack_ref(ref)) {
        *disp -= STACK_ALIGN_SIZE;
    }
}

static instr_t *
instr_create_and_decode(void *drcontext, byte *pc)
{
    instr_t *instr = instr_create(drcontext);
    decode(drcontext, pc, instr);
    return instr;
}
                
byte *
umbra_get_app_addr(umbra_info_t *umbra_info, dr_mcontext_t *mc, mem_ref_t *ref)
{
    reg_t addr;
    reg_id_t base, index;
    int disp, offset;

    if (IF_X64(opnd_is_rel_addr(ref->opnd) ||)
        opnd_is_abs_addr(ref->opnd)) {
        return opnd_get_addr(ref->opnd);
    } else {
        /* We need to re-decode the instruction b/c ref->instr points to a
         * potentially deleted instr from the bb's ilist. */
        instr_t *old_instr = ref->instr;
    	DR_ASSERT(opnd_is_base_disp(ref->opnd));
        ref->instr = instr_create_and_decode(umbra_info->drcontext, ref->pc);
        ref_get_base_disp(ref, &base, &index, &disp);
        instr_destroy(umbra_info->drcontext, ref->instr); 
        ref->instr = old_instr;
    }

    if (proc_info.client.opt_merge == true) {
    	/* TODO(peter): preinsert_calc_app_addr uses mem->group.offset.
    	 * I need to look into this if we enable the grouping optimization.
    	 */
        offset = 0;
    	DR_ASSERT(false);
    } else {
        offset = 0;
    }

    /* Emulate lea */
    addr = reg_get_value(base, mc) +
           reg_get_value(index, mc) * opnd_get_scale(ref->opnd) +
           disp + offset;
    return (byte*) addr;
}

/* init mem_opnd data structure */
static void
ilist_info_mems_init(void         *drcontext,
                     umbra_info_t *umbra_info,
                     ilist_info_t *ilist_info)
{
    basic_block_t *bb;
    umbra_client_t *client;
    int i, j;

    client = &proc_info.client;
    bb     = ilist_info->bb;
    if (bb->num_refs == 0)
        return;
    ilist_info->mems = 
        dr_thread_alloc(drcontext,
                        sizeof(mem_opnd_t) * bb->num_refs);
    for (i = 0, j = 0; i < bb->num_refs; i++) {
        if (client->ref_is_interested(umbra_info, &bb->refs[i])) {
            ilist_info->mems[j].ref   = &bb->refs[i];
            ref_get_base_disp(&bb->refs[i],
                              &ilist_info->mems[j].base,
                              &ilist_info->mems[j].index,
                              &ilist_info->mems[j].disp);
            ilist_info->mems[j].group.leader = j;
            ilist_info->mems[j].group.offset = 0;
            j++;
        }
    }
    ilist_info->num_mems = j;
}


/* initialize ref_group */
static void
ref_group_init(ref_group_t ref_group[])
{
    int i;
    
    for (i = 0; i < NUM_SPILL_REGS; i++) {
        ref_group[i].leader = -1;
        ref_group[i].offset =  0;
    }
}


/* check if reg update is static known */
static bool
reg_update_is_known(instr_t *instr, ref_group_t ref_group[], reg_id_t reg, int pos)
{
    int opcode = instr_get_opcode(instr);
    int offset = 0;

    /* for case like eax + sizeof(element) => eax */
    if ((opcode == OP_add || opcode == OP_sub) &&
        opnd_is_immed_int(instr_get_src(instr, 0))) {
        offset = opnd_get_immed_int(instr_get_src(instr, 0));
        if (opcode == OP_add)
            ref_group[pos].offset += offset;
        else
            ref_group[pos].offset -= offset;
        return true;
    }
    if (opcode == OP_inc) {
        ref_group[pos].offset += 1;
        return true;
    } else if (opcode == OP_dec) {
        ref_group[pos].offset -= 1;
        return true;
    }
    
    /* for case like push, pop */
    if (reg != REG_XSP)
        return false;
    
    if (opcode == OP_push || opcode == OP_push_imm || opcode == OP_pushf || 
        opcode == OP_call || opcode == OP_call_ind) {
        ref_group[pos].offset -= STACK_ALIGN_SIZE;
        return true;
    }
 
    if (opcode == OP_pusha) {
        /* only 32-bit instr */
        ref_group[pos].offset -= 32;
        return true;
    }
    
    if (opcode == OP_pop || opcode == OP_ret) {
        /* pop %rsp */
        if (opcode == OP_pop && opnd_same(instr_get_dst(instr, 0),
                                          opnd_create_reg(REG_XSP)))
            return false;
        ref_group[pos].offset += STACK_ALIGN_SIZE;
        return true;
    }

    if (opcode == OP_popf) {
        ref_group[pos].offset += STACK_ALIGN_SIZE;
        return true;
    }

    if (opcode == OP_popa) {
        ref_group[pos].offset += 32;
        return true;
    }

    /* XXX: add ENTER and LEAVE Instr */
    return false;
}


/* update ref group */
static void
ref_group_update(ilist_info_t *ilist_info, 
                 ref_group_t   ref_group[], 
                 instr_t      *instr)
{
    int i;
    reg_id_t reg;

    for (i = 0; i < NUM_SPILL_REGS; i++) {
        UMBRA_POS_TO_REG(reg, i);
        /* count how many times a reg is used */
        if (register_is_used(instr, reg))
            ilist_info->regs[i].count++;
        if (register_is_updated(instr, reg) &&
            !reg_update_is_known(instr, ref_group, reg, i)) {
            ref_group[i].leader = -1;
            ref_group[i].offset = 0;
        }
    }
}


/* update mem_opnd */
static void
ilist_info_mems_update(ilist_info_t *ilist_info,
                       ref_group_t ref_group[], 
                       instr_t *instr)
{
    int i;
    int pos;

    /* find the ref and set its group */
    for (i = 0; i < ilist_info->num_mems; i++) {
        if (ilist_info->mems[i].ref->instr == instr &&
            ilist_info->mems[i].base  != REG_NULL   &&
            ilist_info->mems[i].index == REG_NULL) {
            UMBRA_REG_TO_POS(ilist_info->mems[i].base, pos);
            if (ref_group[pos].leader == -1) {
                ref_group[pos].leader = i;
                ref_group[pos].offset = 0;
            }
            ilist_info->mems[i].group.leader = ref_group[pos].leader;
            ilist_info->mems[i].group.offset = ref_group[pos].offset;
        }
    }
}


/*
 * this optimization function try to 
 * find memory references that can be grouped together
 * so that only one translation lookup is performed
 */
static void
ilist_info_mems_opt(void         *drcontext,
                    umbra_info_t  *umbra_info,
                    ilist_info_t *ilist_info, 
                    instrlist_t  *ilist)
{
    instr_t *instr;
    ref_group_t ref_group[NUM_SPILL_REGS];

    ref_group_init(ref_group);

    for (instr  = instrlist_first(ilist);
         instr != NULL;
         instr  = instr_get_next(instr)) {
        /* only interested in application instruction */
        if (instr_get_app_pc(instr) != NULL) {
            ilist_info_mems_update(ilist_info, ref_group, instr);
            ref_group_update(ilist_info, ref_group, instr);
        }
    }
}


static void 
ilist_info_ilist_analysis(void         *drcontext,
                          umbra_info_t  *umbra_info,
                          ilist_info_t *ilist_info, 
                          instrlist_t  *ilist)
{
    ilist_info_mems_init(drcontext, umbra_info, ilist_info);
    if (proc_info.options.opt_group == true)
        ilist_info_mems_opt(drcontext, umbra_info, ilist_info, ilist); 
}


static void
ilist_info_aflags_init(void          *drcontext, 
                       umbra_info_t   *umbra_info,
                       ilist_info_t  *ilist_info, 
                       basic_block_t *bb)
{
    memset(&ilist_info->aflags, false, sizeof(reg_status_t));
    memset(&ilist_info->eax,    false, sizeof(reg_status_t));
    if (proc_info.options.opt_aflags_stealing == true)
        optimize_cfg_aflags(drcontext, umbra_info, ilist_info, bb);
}


static void
ilist_info_init(void          *drcontext, 
                umbra_info_t   *umbra_info,
                ilist_info_t  *ilist_info, 
                basic_block_t *bb)
{
    memset(ilist_info, 0, sizeof(ilist_info_t));

    ilist_info->bb = bb;
    ilist_info->mems        = NULL;
    ilist_info->num_mems    = 0;
    ilist_info->translate   = false;
    ilist_info->num_steals  = 
        proc_info.client.num_steal_regs;

    ilist_info_aflags_init(drcontext, umbra_info, ilist_info, bb);
    ilist_info_regs_init(drcontext, ilist_info);
}


static void
ilist_info_exit(void *drcontext, ilist_info_t *info)
{
    basic_block_t *bb = info->bb;

    if (info->aflags.dead == true) {
        BB_SET_AFLAGS_DEAD(bb);
    }

    ilist_info_regs_exit(drcontext, info);
    if (info->mems != NULL)
        dr_thread_free(drcontext, info->mems,
                       sizeof(mem_opnd_t) * bb->num_refs);
}


static void
ilist_info_reset(ilist_info_t *info)
{
    info->translate = false;
    ilist_info_regs_reset(info->regs);
}


static void
ilist_info_update_aflags(instr_t *instr, ilist_info_t *info)
{
    /* remember, this is backward scan */
    uint aflags;

    aflags = instr_get_arith_flags(instr);
    if (TESTANY(EFLAGS_READ_6, aflags)) {
        if (info->aflags.dead  == true) {
            info->aflags.dead  =  false;
            info->aflags.steal =  false;
        }
    } else if (TESTALL(EFLAGS_WRITE_6, aflags)) {
        info->aflags.dead  = true;
    }
}


static void
ilist_info_update_regs(instr_t *instr, ilist_info_t *info)
{
    int i;
    reg_status_t *regs = info->regs;

    for(i = 0; i < NUM_SPILL_REGS; i++) {
        if (register_is_used(instr, regs[i].reg)) {
            regs[i].count--;
            if (regs[i].dead == true) {
                regs[i].dead = false;
                if (regs[i].steal == true && i != 0) {
                    /* the reg is not dead, so cannot be 
                     * used as steal reg. 
                     */
                    regs[i].steal = false;
                    info->num_steals++;
                }
            }
            if (register_is_dead(instr, regs[i].reg)) {
                regs[i].dead = true;
            }
        }
    }
}


static void
ilist_info_update(void         *drcontext, 
                  umbra_info_t  *umbra_info, 
                  ilist_info_t *ilist_info,
                  instr_t      *instr)
{
    /* regs usage update */
    ilist_info_update_regs(instr, ilist_info);
    /* aflags usage update */
    ilist_info_update_aflags(instr, ilist_info);
}


static void
ilist_info_find_steal_reg(ilist_info_t *ilist_info)
{
    int i, min_cnt, min_pos;
    reg_status_t *regs = ilist_info->regs;
    
    /* set the last reg */
    min_pos = NUM_SPILL_REGS;
    min_cnt = 10000;
    for (i = 0; i < NUM_SPILL_REGS; i++) {
        umbra_get_info()->num_spill_regs++;
        /* skip special registers: stack (xsp) and aflag reg (xax) */
        if (regs[i].reg == REG_XSP || regs[i].reg == REG_XAX) 
            continue;
        /* skip base pointer to make stack traces easier */
        if (regs[i].reg == REG_XBP)
            continue;
        /* skip registers that we stolen already */
        if (regs[i].steal == true)
            continue;
        /* skip registers that used for mem reference */
        if (regs[i].used == true)
            continue;
        /* find a dead reg, use it directly */
        if (regs[i].dead == true) {
            regs[i].steal = true;
            if (proc_info.options.opt_regs_stealing == false) {
                regs[i].restore_now = true;
            } else {
                umbra_get_info()->num_dead_regs++;
            }
            return;
        }
        /* find the reg with min use count */
        if (regs[i].count <= min_cnt) {
            min_pos = i;
            min_cnt = regs[i].count;
        }
    }
    DR_ASSERT(min_pos < NUM_SPILL_REGS);
    regs[min_pos].steal       = true;
    regs[min_pos].restore_now = true;
}


static void
ilist_info_steal_regs(ilist_info_t *ilist_info)
{
    int i;
    reg_status_t *regs = ilist_info->regs;

    for (; 
         ilist_info->num_steals > 0; 
         ilist_info->num_steals--) {
        ilist_info_find_steal_reg(ilist_info);
    }

    /* use the first steal register for addr */
    /* XXX: skip eax since it is used for aflags stealing */
    for (i = 1; i < NUM_SPILL_REGS; i++) {
        if (regs[i].steal == true) {
            ilist_info->reg_addr = regs[i].reg;
            break;
        }
    }
}


static void
ilist_info_steal_aflags(ilist_info_t *ilist_info)
{
    reg_status_t *aflags = &ilist_info->aflags;
    reg_status_t *xax    = &ilist_info->regs[0];

    /* aflags is steal already, use it directly */
    if (aflags->steal == true)
        return;
    
    /* new aflags stealing */
    aflags->steal = true;
    if (proc_info.options.opt_aflags_stealing == false) {
        aflags->restore_now = true;
        xax->restore_now = true;
        return;
    }

    /* do not need to spill code if dead */
    if (aflags->dead == true)
        return;
    
    /* we do need steal the aflags, restore now */
    aflags->restore_now = true;

    /* need steal xax too */
    xax->steal = true;
    if (xax->dead == false)
        xax->restore_now = true;
}


static bool
should_instrument_update(ilist_info_t  *ilist_info,
                         instr_t       *where,
                         umbra_client_t *client)
{
    int  i, j;
    bool instrument = false;

    for (i = ilist_info->num_mems - 1; i >= 0; i--) {
        if (client->opt_merge == true) 
            j = ilist_info->mems[i].group.leader;
        else
            j = i;
        if (ilist_info->mems[j].ref->instr == where) {
            ilist_info->translate = true;
            instrument = true;
            break;
        }
    }
    if (instrument) {
        /* find which register is used for memory reference */
        for (i = 0; i < NUM_SPILL_REGS; i++) {
            if (register_is_used_for_mem(where, ilist_info->regs[i].reg))
                ilist_info->regs[i].used = true;
        }
        /* find register to steal */
        ilist_info_steal_aflags(ilist_info);
        ilist_info_steal_regs(ilist_info);
    }
    return instrument;
}


static bool
should_insert_aflags_stealing(ilist_info_t *ilist_info, 
                              instr_t *instr,
                              instr_t *prev)
{
    bool instrument = false;
    reg_status_t *aflags = &ilist_info->aflags;
    reg_status_t *eax    = &ilist_info->eax;
    umbra_get_info()->num_spill_aflags++;

    if (aflags->steal == false)
        return false;

    if (proc_info.options.opt_aflags_stealing == false) {
        aflags->save_now = true;
        eax->steal       = true;
        eax->restore_now = true;
        ilist_info->regs[0].save_now = true;        
        return true;
    }

    if (aflags->dead == true)
        return false;

    if (!proc_info.options.opt_unsafe_aflags_stealing) {
        umbra_get_info()->num_dead_aflags++;
    	aflags->save_now = true;
    	eax->steal = true;
    	eax->restore_now = true;
    	ilist_info->regs[0].save_now = true;
    	return true;
    }

    /* save aflags now if reach start or prev writes aflags */
    if (prev == NULL || instr_uses_aflags(prev)) {
        aflags->save_now = true;
        instrument = true;
    }

    /* if XAX is to be used by application, mark eax need to be stolen 
     */
    /* XXX: the code here is not very clear to me! 
     * this may handle the case that instr is the first instr in 
     * instrlist?
     */
    if (register_is_used(instr, REG_XAX)) {
        if (aflags->restore_now == false || 
            /* not the instr cause aflags stealing */
            register_is_used_for_mem(instr, REG_XAX)) {
            /* for case 1 like
             * save rax
             * save aflags => eax
             * save eax 
             * restore rax
             * calculate [rax]
             * ...
             * restore eax
             * restore aflags
             * restore rax
             * [rax] => rbx
             */
            if (eax->steal == false) {
                eax->steal = true;
                eax->restore_now = true;
                instrument = true;
            }
        }
    }

    if (aflags->save_now == false && 
        prev != NULL && register_is_used(prev, REG_XAX)) {
        if (eax->steal == false) {
            /* for case like:
             * 
             * use rax by app
             * restore eax
             * ...
             * restore aflags from eax
             */

            eax->steal = true;
            eax->restore_now = true;
            instrument = true;
        }
        if (register_is_updated(prev, REG_XAX) &&
            ilist_info->regs[0].dead == false) {
            /* for case like:
             * save rax for aflags
             * ...
             * update rax by app
             * save rax again 
             * ...
             * restore rax
             */
            ilist_info->regs[0].save_now = true;
            instrument = true;
        }
    }

    return instrument;
}


/* Idea of register stealling 
 * 1. for dead register, use it directly
 * 2. for steal register, expand its range as large as possible
 */
static bool
should_insert_regs_stealing(ilist_info_t *ilist_info,
                            instr_t      *instr,
                            instr_t      *prev)
{
    int i;
    reg_status_t *regs = ilist_info->regs;

    for (i = 1; i < NUM_SPILL_REGS; i++) {
        if (regs[i].steal == false)
            continue;
        if (proc_info.options.opt_regs_stealing == false) {
            /* naively, we save the register right before steal it */
            regs[i].save_now = true;
        }
        else {
            /* however we can optimize the register stealing, 
             * by expanding the register stealing ragne
             * when steal a register, we push the reg save operation
             * as early as possible:
             * 1. no more prev instr 
             * 2. or reg will be used by app
             * in this way, the steal reg can hopefully used by several 
             * memory reference. 
             * In another word, we try to use one register stealling for 
             * more than one memory reference instruction.
             */
            if (prev == NULL || register_is_used(prev, regs[i].reg) ||
                !proc_info.options.opt_unsafe_regs_stealing) {
                if (!regs[i].dead)
                    regs[i].save_now = true;
            }
        }
    }
    /* the restore_now is only updated */
    for (i = 1; i < NUM_SPILL_REGS; i++) {
        if (regs[i].save_now == true || regs[i].restore_now == true)
            return true;
    }
    return false;
}


static bool
should_instrument_context_switch(ilist_info_t  *ilist_info,
                                 instr_t       *prev, 
                                 instr_t       *instr,
                                 umbra_client_t *client)
{
    bool instrument = false;
    /* check if any aflags stealing code should be inserted */
    if (should_insert_aflags_stealing(ilist_info, instr, prev))
        instrument = true;
    if (should_insert_regs_stealing(ilist_info, instr, prev))
        instrument = true;
    return instrument;
}

/* This function decide if the instrumentation should be performed
 * There are several cases that the instrumentation should be performed
 * 1. if there is memory reference (could be optimized to merge together)
 *    context switch, update, lookup
 * 2. if aflags is restored later, it might be saved 
 * 3. if reg_addr is updated
 */

static bool
should_start_instrumentation(ilist_info_t  *ilist_info,
                             instr_t       *prev, 
                             instr_t       *where,
                             umbra_client_t *client)
{
    bool   instrument = false;
    app_pc pc;

    pc = instr_get_app_pc(where);

    /* if there is an interested memory reference,
     * insert context switch, lookup, and update code 
     */
    if (should_instrument_update(ilist_info, where, client))
        instrument = true;
    if (should_instrument_context_switch(ilist_info, prev, where, client))
        instrument = true;
    return instrument;
}



/*---------------------------------------------------------------------*
 *                 Routines for instrument inline code                 *
 *---------------------------------------------------------------------*/


static void
preinsert_calculate_app_addr(void        *drcontext,
                             mem_opnd_t  *mem,
                             reg_id_t     reg,
                             instrlist_t *ilist,
                             instr_t     *where)
{
    instr_t *instr;
    opnd_t   opnd1, opnd2;
    int      offset = 0;

    opnd1 = opnd_create_reg(reg);
    if (IF_X64(opnd_is_rel_addr(mem->ref->opnd) ||) 
        opnd_is_abs_addr(mem->ref->opnd)) 
        return;

    if (proc_info.client.opt_merge == true)
        offset = mem->group.offset;
    /* lea [ref] => %r1 */        
    opnd2 = OPND_CREATE_MEM_lea(mem->base,
                                mem->index,
                                opnd_get_scale(mem->ref->opnd),
                                mem->disp + offset);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
}

#ifdef EXP_SMS64
static void
instrument_exp_sms64(void          *drcontext,
                     umbra_info_t  *umbra_info,
                     reg_id_t       reg,
                     instrlist_t   *ilist,
                     instr_t       *where)
{
    instr_t *instr;
    opnd_t   opnd1, opnd2;
    reg_id_t r1 = reg;
    reg_id_t r2 = umbra_info->steal_regs[1];
    reg_id_t r3 = umbra_info->steal_regs[2];
    instr_t *fast = INSTR_CREATE_label(drcontext);
    /* r1 => r2 */
    opnd1 = opnd_create_reg(r2);
    opnd2 = opnd_create_reg(r1);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* shr %r2, 32 */
    opnd1 = opnd_create_reg(r2);
    opnd2 = OPND_CREATE_INT8(32);
    instr = INSTR_CREATE_shr(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* and %r2, 0xffff */
    opnd1 = opnd_create_reg(r2);
    opnd2 = OPND_CREATE_INT32(0xffff);
    instr = INSTR_CREATE_and(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* cmp table[r2], 0*/
    opnd1 = opnd_create_base_disp(REG_NULL, r2, 8, 
                                  (int)L1_table, OPSZ_4);
    opnd2 = OPND_CREATE_INT32(0);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* jne */
    opnd1 = opnd_create_instr(fast);
    instr = INSTR_CREATE_jcc(drcontext, OP_jne, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);
    /* mov */
    opnd1 = opnd_create_base_disp(REG_NULL, r2, 8,
                                  (int)L1_table, OPSZ_4);
    opnd2 = OPND_CREATE_INT32((int)L2_table);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* do something to simulate the slow path */
    /* r1 => r3 */
    opnd1 = opnd_create_reg(r3);
    opnd2 = opnd_create_reg(r1);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* r3 & unit_mask */
    opnd1 = opnd_create_reg(r3);
    opnd2 = OPND_CREATE_ABSMEM(&proc_info.unit_mask, OPSZ_PTR);
    instr = INSTR_CREATE_and(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* load label.pc => umbra_info->cache_pc */
    opnd1 = OPND_CREATE_ABSMEM(&umbra_info->cache_pc, OPSZ_PTR);
    opnd2 = opnd_create_instr(fast);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* jmp */
    int pos;
    UMBRA_REG_TO_POS(r3, pos);
    opnd1 = opnd_create_pc(umbra_info->map_check_pc[pos]);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);  /* jmp */
    instrlist_meta_preinsert(ilist, where, instr);
    /* fast path */
    instrlist_meta_preinsert(ilist, where, fast);
    /* r1 => r3 */
    opnd1 = opnd_create_reg(r3);
    opnd2 = opnd_create_reg(r1);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* mov L1_table[%r2] => %r2 */
    opnd1 = opnd_create_reg(r2);
    opnd2 = opnd_create_base_disp(REG_NULL, r2, 8, 
                                  (int)L1_table, OPSZ_8);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* shr %r3, 16 => %r3 */
    opnd1 = opnd_create_reg(r3);
    opnd2 = OPND_CREATE_INT8(12);
    instr = INSTR_CREATE_shr(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* and %r3, 0x7ffff, %r3 */
    opnd1 = opnd_create_reg(r3);
    opnd2 = OPND_CREATE_INT32(0xfffff);
    instr = INSTR_CREATE_and(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* add %r1, %r2[%r3] => %r1 */
    opnd1 = opnd_create_reg(r1);
    opnd2 = opnd_create_base_disp(r2, r3, 8, 0, OPSZ_8);
    instr = INSTR_CREATE_add(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
}
#endif

#ifdef EXP_MEMCHK
static void
instrument_exp_memchk(void          *drcontext,
                      umbra_info_t  *umbra_info,
                      reg_id_t       reg,
                      instrlist_t   *ilist,
                      instr_t       *where)
{
    instr_t *instr;
    opnd_t   opnd1, opnd2;
    reg_id_t r1 = reg;
    reg_id_t r2 = umbra_info->steal_regs[1];
    instr_t *fast = INSTR_CREATE_label(drcontext);

    /* cmp %r1, 32G */
    opnd1 = opnd_create_reg(r1);
    opnd2 = OPND_CREATE_ABSMEM(limit_ptr, OPSZ_PTR);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* jl fast_path */
    opnd1 = opnd_create_instr(fast);
    instr = INSTR_CREATE_jcc(drcontext, OP_jl, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);
    /* do something to simulate the slow path */
    /* r1 => r2 */
    opnd1 = opnd_create_reg(r2);
    opnd2 = opnd_create_reg(r1);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* r2 & unit_mask */
    opnd1 = opnd_create_reg(r2);
    opnd2 = OPND_CREATE_ABSMEM(&proc_info.unit_mask, OPSZ_PTR);
    instr = INSTR_CREATE_and(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* load label.pc => umbra_info->cache_pc */
    opnd1 = OPND_CREATE_ABSMEM(&umbra_info->cache_pc, OPSZ_PTR);
    opnd2 = opnd_create_instr(fast);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* jmp */
    int pos;
    UMBRA_REG_TO_POS(r2, pos);
    opnd1 = opnd_create_pc(umbra_info->map_check_pc[pos]);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);  /* jmp */
    instrlist_meta_preinsert(ilist, where, instr);
    /* fast_path: */
    instrlist_meta_preinsert(ilist, where, fast);
    /* r1 => r2*/
    opnd1 = opnd_create_reg(r2);
    opnd2 = opnd_create_reg(r1);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* shr %r2, 16 */
    opnd1 = opnd_create_reg(r2);
    opnd2 = OPND_CREATE_INT8(16);
    instr = INSTR_CREATE_shr(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* and %r2, 0x7ffff */
    opnd1 = opnd_create_reg(r2);
    opnd2 = OPND_CREATE_INT32(0x7ffff);
    instr = INSTR_CREATE_and(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* add %r1, table[r2] */
    opnd1 = opnd_create_reg(r1);
    opnd2 = opnd_create_base_disp(REG_NULL, r2, 8,
                                  (int)SMS_table, OPSZ_8);
    instr = INSTR_CREATE_add(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
}
#endif


static void
preinsert_calculate_shd_addr(void          *drcontext,
                             umbra_info_t   *umbra_info,
                             umbra_client_t *client,
                             ilist_info_t  *ilist_info,
                             mem_opnd_t    *mem,
                             reg_id_t       reg,
                             instrlist_t   *ilist,
                             instr_t       *where,
                             reg_t         *offset_ptr)
{
    instr_t *instr;
    opnd_t   opnd1, opnd2;
    int diff;

    if (IF_X64(opnd_is_rel_addr(mem->ref->opnd) ||) 
        opnd_is_abs_addr(mem->ref->opnd)) { 
        /* static address, calculate the shadow address directly
         * and instrument: mov ADDR => reg 
         */ 
        void *addr;
        void *shd_addr[MAX_NUM_SHADOWS];
        addr = opnd_get_addr(mem->ref->opnd);
        if (client->app_unit_bits[0] > 0 && client->shd_unit_bits[0] != 0)
            addr = (void *)((reg_t)addr & (-1 << client->app_unit_bits[0]));
#ifndef LINUX_KERNEL
        if (!memory_mod_app_lookup(addr))
            memory_mod_app_add(addr, 4);
#endif
        compute_shd_memory_addr(addr, shd_addr);
        opnd1 = opnd_create_reg(reg);
        opnd2 = OPND_CREATE_INTPTR(shd_addr[0]);
        instr= INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);
        return;
    }

    if (client->orig_addr) {
        reg_id_t r2 = umbra_info->steal_regs[1];
        /* mov reg => r2 */
        opnd1 = opnd_create_reg(r2);
        opnd2 = opnd_create_reg(reg);
        instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);
    }

    if (client->app_unit_bits[0] > 0 && client->shd_unit_bits[0] != 0) {
        /* reg & mask => reg */
        opnd1 = opnd_create_reg(reg);
        opnd2 = OPND_CREATE_INT32(-1 << client->app_unit_bits[0]);
        instr = INSTR_CREATE_and(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);
    }

    diff  = client->app_unit_bits[0] - client->shd_unit_bits[0];
    opnd1 = opnd_create_reg(reg);
    if (diff > 0) {
        opnd2 = OPND_CREATE_INT8(diff);
        instr = INSTR_CREATE_shr(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);
    } else if(diff < 0) {
        opnd2 = OPND_CREATE_INT8(-diff);
        instr = INSTR_CREATE_shl(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);
    }

#ifdef EXP_MEMCHK
    instrument_exp_memchk(drcontext, umbra_info, reg, ilist, where);
#elif defined(EXP_SMS64)
    instrument_exp_sms64(drcontext, umbra_info, reg, ilist, where);
#elif defined(EXP_SMS32)
    instrument_exp_sms32(drcontext, umbra_info, reg, ilist, where);
#else
    /* reg + offset => reg */
    opnd1 = opnd_create_reg(reg);
    opnd2 = OPND_CREATE_ABSMEM(offset_ptr, OPSZ_PTR);
    instr = INSTR_CREATE_add(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
#endif
}

static void
instrument_update(void         *drcontext,
                  umbra_info_t  *umbra_info,
                  ilist_info_t *ilist_info,
                  mem_opnd_t   *mem,
                  instrlist_t  *ilist,
                  instr_t      **update,
#ifdef LINUX_KERNEL
                  instr_t      **update_user,
#endif
                  instr_t      *where)
{
    mem_ref_t *ref;
    reg_t     *offset_ptr;   
    int i, j;
    umbra_client_t *client;
#ifdef LINUX_KERNEL
    instr_t *restore = where;
    bool could_be_user = true;
    bool could_be_kernel = true;
#endif
    
    client = &proc_info.client;
    ref = ilist_info->mems[mem->group.leader].ref;
    if (ref->cache == NULL) {
        if (opnd_uses_reg(mem->ref->opnd, REG_RSP)) {
            ref->cache = umbra_info->stack_ref_cache;
        } else {
            ref->cache = table_alloc_ref_cache(drcontext, umbra_info);
            ref->cache->tag    = umbra_info->last_map_tag;
            ref->cache->offset[0] = umbra_info->last_map_offset[0];
#ifdef DOUBLE_SHADOW
            ref->cache->offset[1] = umbra_info->last_map_offset[1];
#endif
            if (IF_X64(opnd_is_rel_addr(mem->ref->opnd) ||) 
                opnd_is_abs_addr(mem->ref->opnd)) { 
                void *addr;
                void *shd_addr[MAX_NUM_SHADOWS];
                addr = opnd_get_addr(mem->ref->opnd);
                if (client->app_unit_bits[0] > 0 && client->shd_unit_bits[0] != 0) {
                    addr = (void *)((reg_t)addr & (-1 << client->app_unit_bits[0]));
                }
#ifndef LINUX_KERNEL
                if (!memory_mod_app_lookup(addr)) {
                    memory_mod_app_add(addr, 4);
                }
#else
                if (addr >= min_kernel_addr) {
                    memory_map_thread_lazy_add(umbra_info, addr);
#endif
                    compute_shd_memory_addr(addr, shd_addr);
                    ref->cache->offset[1] = shd_addr[1] - addr;

#ifdef LINUX_KERNEL
                }
                could_be_user = addr < min_kernel_addr;
                could_be_kernel = !could_be_user;
#endif
            }
        }
    }
    offset_ptr = ref->cache->offset;

    for (i = 1, j = 0; i < NUM_SPILL_REGS; i++) {
        if (ilist_info->regs[i].steal == true) 
            umbra_info->steal_regs[j++] = ilist_info->regs[i].reg;
    }

    /* skip opnd that is not interested */
    if (!client->ref_is_interested(umbra_info, mem->ref))
        return;

#ifdef LINUX_KERNEL
    if (could_be_user) {
        /* update_user: */
        *update_user = INSTR_CREATE_label(drcontext);
        instrlist_meta_preinsert(ilist, where, *update_user);

        preinsert_calculate_app_addr(drcontext, 
                                     mem, 
                                     ilist_info->reg_addr,
                                     ilist, 
                                     where);

        if (proc_info.options.stat == true) {
            preinsert_count_inc(drcontext, 
                                ilist,
                                where,
                                &umbra_info->num_dyn_user_refs,
                                1);
        }


        if (proc_info.client.instrument_update_user != NULL)
            proc_info.client.instrument_update_user(drcontext,
                                                    umbra_info,
                                                    mem->ref,
                                                    ilist,
                                                    where);
        /* jmp .restore */
        instrlist_meta_preinsert(ilist, where,
            INSTR_CREATE_jmp(drcontext, opnd_create_instr(restore)));
    }
    
    if (could_be_kernel) {
#endif
        /* update: */
        *update = INSTR_CREATE_label(drcontext);
        instrlist_meta_preinsert(ilist, where, *update);

        preinsert_calculate_app_addr(drcontext, 
                                     mem, 
                                     ilist_info->reg_addr,
                                     ilist, 
                                     where);

        preinsert_calculate_shd_addr(drcontext,
                                     umbra_info, 
                                     &proc_info.client,
                                     ilist_info,
                                     mem,
                                     ilist_info->reg_addr,
                                     ilist,
                                     where,
                                     offset_ptr);

        if (proc_info.options.stat == true) {
            preinsert_count_inc(drcontext, 
                                ilist,
                                where,
                                &umbra_info->num_dyn_refs,
                                1);
        }
        if (proc_info.client.instrument_update != NULL)
            proc_info.client.instrument_update(drcontext,
                                                umbra_info,
                                                mem->ref,
                                                ilist,
                                                where);
#ifdef LINUX_KERNEL
    }
#endif
}


/* 
 * save app_stack_ptr
 * load umbra_stack_ptr
 * call lean_procedure
 * mov reg cache->offset
 * load app_stack_ptr
 * jmp .update
 *   or 
 * mov label.pc => [umbra_info->cache_pc]
 * jmp lean_procedure
 * mov reg cache->offset
 * jmp .update
 */
static void
instrument_lean_call(void         *drcontext,
                     umbra_info_t  *umbra_info,
                     ilist_info_t *ilist_info,
                     mem_opnd_t   *mem,
                     instrlist_t  *ilist,
#ifdef LINUX_KERNEL
                     instr_t      *update_user,
#endif
                     instr_t      *update)

{
    instr_t     *instr, *label;
    opnd_t       opnd1, opnd2;
    ref_cache_t *cache;
    int          pos;
#ifdef LINUX_KERNEL
    instr_t     *where = update_user;
#else
    instr_t     *where = update;
#endif

    if (IF_X64(opnd_is_rel_addr(mem->ref->opnd) ||) 
        opnd_is_abs_addr(mem->ref->opnd)) 
        return;

    cache = ilist_info->mems[mem->group.leader].ref->cache;
    DR_ASSERT(cache != NULL);

    UMBRA_REG_TO_POS(ilist_info->reg_addr, pos);

    if (proc_info.options.swap_stack) {
        /* save app stack */
        opnd1 = OPND_CREATE_ABSMEM(&umbra_info->app_stack, OPSZ_PTR);
        opnd2 = opnd_create_reg(REG_XSP);
        instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);
        /* load umbra stack */
        opnd1 = opnd_create_reg(REG_XSP);
        opnd2 = OPND_CREATE_INTPTR((void *)umbra_info->umbra_stack_ptr);
        instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);
        /* call */
        opnd1 = opnd_create_pc(umbra_info->map_check_pc[pos]);
        instr = INSTR_CREATE_call(drcontext, opnd1); /* call */
        instrlist_meta_preinsert(ilist, where, instr);
        /* mov reg => cache->offset */
        opnd1 = OPND_CREATE_ABSMEM(&cache->offset[0], OPSZ_PTR);
        opnd2 = opnd_create_reg(ilist_info->reg_addr);
        instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);
        /* restore app stack */
        opnd1 = opnd_create_reg(REG_XSP);
        opnd2 = OPND_CREATE_ABSMEM(&umbra_info->app_stack, OPSZ_PTR);
        instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);        
        instrlist_meta_preinsert(ilist, where, instr);
    } else {
        label = INSTR_CREATE_label(drcontext);
        /* load label.pc => umbra_info->cache_pc */
        opnd1 = OPND_CREATE_ABSMEM(&umbra_info->cache_pc, OPSZ_PTR);
        opnd2 = opnd_create_instr(label);
        instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);
        /* jmp */
        opnd1 = opnd_create_pc(umbra_info->map_check_pc[pos]);
        instr = INSTR_CREATE_jmp(drcontext, opnd1);  /* jmp */
        instrlist_meta_preinsert(ilist, where, instr);
        /* label */
        instrlist_meta_preinsert(ilist, where, label);
        /* mov reg => cache->offset[0] */
        opnd1 = OPND_CREATE_ABSMEM(&cache->offset[0], OPSZ_PTR);
        opnd2 = opnd_create_reg(ilist_info->reg_addr);
        instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);
#ifdef DOUBLE_SHADOW
        /* mov last_map_offset[1] => reg */
        opnd1 = opnd_create_reg(ilist_info->reg_addr);
        opnd2 = OPND_CREATE_ABSMEM(&umbra_info->last_map_offset[1], OPSZ_PTR);
        instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);
        /* mov reg => cache->offset[1] */
        opnd1 = OPND_CREATE_ABSMEM(&cache->offset[1], OPSZ_PTR);
        opnd2 = opnd_create_reg(ilist_info->reg_addr);
        instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);
#endif
    }
#ifdef LINUX_KERNEL
    /* jmp .update */
    opnd1 = opnd_create_instr(update);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);
#endif
}


/* 
 *   lea [ref]  => %r1
 *   %r1 & proc_info.unit_mask => %r1
 *   cmp %r1, cache->tag
 *   je .update
 *   cmp %r1, min_kernel_addr
 *   jb .update_user
 *   mov %r1 => cache->tag
 *   ...
 * .update_user
 *   ...
 *   jmp .restore_context
 * .update
 *   ...
 * .restore_context
 */
static void
instrument_inline_check(void         *drcontext, 
                        umbra_info_t  *umbra_info,
                        ilist_info_t *ilist_info,
                        mem_opnd_t   *mem,
                        instrlist_t  *ilist,
#ifdef LINUX_KERNEL
                        instr_t      *update_user,
#endif
                        instr_t      *update,
                        bool          for_trace)
{
    instr_t     *instr;
    opnd_t       opnd1, opnd2;
    ref_cache_t *cache;
#ifdef LINUX_KERNEL
    instr_t     *where = update_user;
#else
    instr_t     *where = update;
#endif

    cache = ilist_info->mems[mem->group.leader].ref->cache;
    DR_ASSERT(cache != NULL);

    if (IF_X64(opnd_is_rel_addr(mem->ref->opnd) ||)
        opnd_is_abs_addr(mem->ref->opnd))
        return;

    preinsert_calculate_app_addr(drcontext, 
                                 mem, 
                                 ilist_info->reg_addr,
                                 ilist,
                                 where);

    if (proc_info.options.opt_inline_check == false)
        return;
    if (proc_info.options.stat == true) {
        if (for_trace) {
            preinsert_count_inc(drcontext, ilist, where, 
                                &umbra_info->num_trace_inline_checks,
                                1);
        } else {
            preinsert_count_inc(drcontext, ilist, where, 
                                &umbra_info->num_bb_inline_checks,
                                1);
        }
    }

    /* %r1 & unit_mask */
    opnd1 = opnd_create_reg(ilist_info->reg_addr);
    opnd2 = OPND_CREATE_ABSMEM(&proc_info.unit_mask, OPSZ_PTR);
    instr = INSTR_CREATE_and(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* cmp %r1, cache->tag */
    opnd1 = opnd_create_reg(ilist_info->reg_addr);
    opnd2 = OPND_CREATE_ABSMEM(&cache->tag, OPSZ_PTR);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* je .update */
    opnd1 = opnd_create_instr(update);
    instr = INSTR_CREATE_jcc(drcontext, OP_je, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    if (!for_trace && proc_info.options.opt_ems64 &&
        mem->ref->count < 2)
        preinsert_count_inc(drcontext, ilist, where,
                            &mem->ref->count, 1);

#ifdef LINUX_KERNEL
    /* cmp %r1, min_kernel_addr */
    opnd1 = opnd_create_reg(ilist_info->reg_addr);
    opnd2 = OPND_CREATE_ABSMEM(&min_kernel_addr, OPSZ_PTR);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* jb .update_user */
    opnd1 = opnd_create_instr(update_user);
    instr = INSTR_CREATE_jcc(drcontext, OP_jb, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);
#endif
    
    opnd1 = OPND_CREATE_ABSMEM(&cache->tag, OPSZ_PTR);
    opnd2 = opnd_create_reg(ilist_info->reg_addr);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
}

/*
 * # ref1's fast check code
 *   ...
 *   je .update
 * # ref1's slow lookup code
 *   ...
 * # ref1's shadow memory update code
 * .update
 *   ...
 * # context restore
 * .restore
 *   ...
 */

static void
instrument_inline_code(void         *drcontext, 
                       umbra_info_t  *umbra_info,
                       ilist_info_t *ilist_info,
                       instrlist_t  *ilist,
                       instr_t      *where,
                       instr_t      *instr,
                       bool          for_trace)
{
    int i, j;
    instr_t *update = NULL;
#ifdef LINUX_KERNEL
    instr_t *update_user = NULL;
#endif
    bool no_check;

    for (i = 0; i < ilist_info->num_mems; i++) {
        if (ilist_info->mems[i].ref->instr != instr)
            continue;

        if (proc_info.options.opt_ems64 == false || for_trace == false)
            no_check = false;
        else
            no_check = true;

        j = ilist_info->mems[i].group.leader;

        /* update meta-data in shadow memory */
        instrument_update(drcontext,
                          umbra_info,
                          ilist_info,
                          &ilist_info->mems[i],
                          ilist,
                          &update,
#ifdef LINUX_KERNEL
                          &update_user,
#endif
                          where);

#if defined(EXP_MEMCHK) || defined(EXP_SMS64)
        continue;
#endif
        if (ilist_info->mems[i].group.leader == i) {
            if (no_check == false || ilist_info->mems[i].ref->count > 1) {
                /* instrument translation lookup at greoup leader */
                /* fast check */
                instrument_inline_check(drcontext,
                                        umbra_info,
                                        ilist_info,
                                        &ilist_info->mems[i],
                                        ilist,
#ifdef LINUX_KERNEL
                                        update_user,
#endif
                                        update,
                                        for_trace);
                /* clean call translation table lookup */
                instrument_lean_call(drcontext,
                                     umbra_info,
                                     ilist_info,
                                     &ilist_info->mems[i],
                                     ilist,
#ifdef LINUX_KERNEL
                                     update_user,
#endif
                                     update);
            }
        }
    }
}

/*---------------------------------------------------------------------*
 *             Routines for instrument context switch code             *
 *---------------------------------------------------------------------*/


/* aflag saving code:
 *   save eax
 *   lahf
 *   seto al
 *   save eax => aflags
 */
static void
instrument_save_aflags(void         *drcontext,
                       umbra_info_t  *umbra_info,
                       ilist_info_t *ilist_info,
                       instrlist_t  *ilist,
                       instr_t      *where)
{
    instr_t *instr;
    int      xax = 0;

    if (ilist_info->aflags.save_now == false)
        return;
    
    ilist_info->aflags.steal    = false;
    ilist_info->aflags.save_now = false;

    /* save xax */
    if (proc_info.options.opt_aflags_stealing == false ||
        ilist_info->regs[xax].dead == false) {
        umbra_save_reg(drcontext, umbra_info, ilist, where, REG_XAX);
    }

    /* lahf */
    instr = INSTR_CREATE_lahf(drcontext);
    instrlist_meta_preinsert(ilist, where, instr);
    /* seto al */
    instr = INSTR_CREATE_setcc(drcontext, OP_seto, opnd_create_reg(REG_AL));
    instrlist_meta_preinsert(ilist, where, instr);

    /* check if xax will be used later */
    if (ilist_info->eax.steal == true) {
        umbra_save_eax_aflags(drcontext, umbra_info, ilist, where);
        ilist_info->eax.steal = false;
        if (proc_info.options.opt_aflags_stealing == false ||
            ilist_info->regs[xax].dead == false)
            umbra_restore_reg(drcontext, umbra_info, ilist, where, REG_XAX);
    }
}


/* flag restoring code:
 *   restore aflags => eax
 *   add 0x7f,%al
 *   sahf
 *   restore eax
 */
static void
instrument_restore_aflags(void         *drcontext,
                          umbra_info_t  *umbra_info,
                          ilist_info_t *ilist_info,
                          instrlist_t  *ilist,
                          instr_t      *where)
{
    opnd_t   opnd1, opnd2;
    instr_t *instr;

    if (ilist_info->regs[0].save_now == true) {
        ilist_info->regs[0].save_now = false;
        umbra_save_reg(drcontext, umbra_info, ilist, where, REG_XAX);
    }

    if (ilist_info->eax.steal == true && 
        ilist_info->eax.restore_now == true) {
        ilist_info->eax.restore_now = false;
        umbra_restore_eax_aflags(drcontext, umbra_info, ilist, where);
    }

    if (ilist_info->aflags.restore_now == true) {
        ilist_info->aflags.restore_now = false;
        if (proc_info.options.stat == true) {
            preinsert_count_inc(drcontext,
                                ilist,
                                where, 
                                &umbra_info->num_aflags_restores,
                                1);
        }
        /* add 0x7f,%al */
        opnd1 = opnd_create_reg(REG_AL);
        opnd2 = OPND_CREATE_INT8(0x7f);
        instr = INSTR_CREATE_add(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, where, instr);
        /* sahf */
        instr = INSTR_CREATE_sahf(drcontext);
        instrlist_meta_preinsert(ilist, where, instr);
    }
    
    /* restore %xax if it is to be used later */
    if (ilist_info->regs[0].restore_now == true) {
        ilist_info->regs[0].restore_now =  false;
        umbra_restore_reg(drcontext, umbra_info, 
                         ilist, where, REG_XAX);
    }
}


static void
instrument_save_regs(void         *drcontext, 
                     umbra_info_t  *umbra_info, 
                     ilist_info_t *ilist_info,
                     instrlist_t  *ilist,
                     instr_t      *where)
{
    int i;
    reg_status_t *regs = ilist_info->regs;
    
    for (i = 1; i < NUM_SPILL_REGS; i++) {
        if (regs[i].save_now == true) {
            regs[i].save_now = false;
            regs[i].steal    = false;
            umbra_save_reg(drcontext, 
                          umbra_info, 
                          ilist, 
                          where, 
                          regs[i].reg);
            /* need to steal one more later */
            ilist_info->num_steals++;
        }
    }
}


static void
instrument_restore_regs(void         *drcontext, 
                        umbra_info_t  *umbra_info, 
                        ilist_info_t *ilist_info,
                        instrlist_t  *ilist,
                        instr_t      *where)
{
    int i;
    reg_status_t *regs = ilist_info->regs;
    /* skip %xax, which is used for aflags */
    for (i = 1; i < NUM_SPILL_REGS; i++) {
        if (regs[i].restore_now == true) {
            regs[i].restore_now = false;
            if (proc_info.options.stat == true) {
                preinsert_count_inc(drcontext,
                                    ilist,
                                    where, 
                                    &umbra_info->num_reg_restores,
                                    1);
            }
            umbra_restore_reg(drcontext, umbra_info, ilist,
                             where, regs[i].reg);
        }
    }
}


static void
instrument_context_restore(void         *drcontext, 
                           umbra_info_t  *umbra_info, 
                           ilist_info_t *ilist_info,
                           instrlist_t  *ilist,
                           instr_t      *where)
{
    instrument_restore_regs(drcontext, umbra_info, ilist_info, ilist, where);
    instrument_restore_aflags(drcontext, umbra_info, ilist_info, ilist, where);
}


static void
instrument_context_save(void         *drcontext, 
                        umbra_info_t  *umbra_info, 
                        ilist_info_t *ilist_info,
                        instrlist_t  *ilist,
                        instr_t      *where)
{
    /* note: save regs must be called before save aflags
     * because eax need to be saved first 
     */
    instrument_save_regs(drcontext, umbra_info, ilist_info, ilist, where);
    instrument_save_aflags(drcontext, umbra_info, ilist_info, ilist, where);
}


static void
instrument_umbra_code(void *drcontext,
                      umbra_info_t  *umbra_info,
                      ilist_info_t *ilist_info,
                      instrlist_t  *ilist,
                      instr_t      *instr,
                      bool for_trace)
{
    instr_t *restore, *update;
    /* 
     * .save
     *   ... # context save
     * .inline_code
     *   ... # shadow translation lookup
     *   ... # shadow update
     * .restore
     *   ... # context restore
     */
    /* .restore */

    restore = INSTR_CREATE_label(drcontext); 
    instrlist_meta_preinsert(ilist, instr, restore);
    instrument_context_restore(drcontext,
                               umbra_info,
                               ilist_info,
                               ilist,
                               instr);

    update = INSTR_CREATE_label(drcontext);
    instrlist_meta_preinsert(ilist, restore, update);
    instrument_inline_code(drcontext, 
                           umbra_info, 
                           ilist_info,
                           ilist, 
                           restore,
                           instr,
                           for_trace);
    instrument_context_save(drcontext,
                            umbra_info,
                            ilist_info,
                            ilist,
                            update);
}


/*---------------------------------------------------------------------*
 *                      Code cache emission routine                    *
 *---------------------------------------------------------------------*/

/* mov info->umbra_stack_ptr_16 => %xsp */
static void
append_restore_app_tag_reg(void *drcontext,
                           reg_id_t app_tag_reg,
                           umbra_info_t *info,
                           instrlist_t *ilist)
{
    instr_t *instr;
    opnd_t   opnd1, opnd2;
    
    /* restore app_tag_reg */
    opnd1 = opnd_create_reg(app_tag_reg);
    if (proc_info.options.swap_stack)
        opnd2 = OPND_CREATE_ABSMEM(&info->umbra_stack_ptr_off, OPSZ_PTR);
    else 
        opnd2 = OPND_CREATE_ABSMEM(&info->app_stack, OPSZ_PTR);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);
}


/* mov %reg => info->last_map_tag */
static void
append_update_last_map_tag(void         *drcontext,
                           umbra_info_t *info,
                           instrlist_t  *ilist,
                           reg_id_t      reg)
{
    instr_t *instr;
    opnd_t   opnd1, opnd2;

    /* mov %reg => info->last_map_tag */
    opnd1 = OPND_CREATE_ABSMEM(&info->last_map_tag, OPSZ_PTR);
    opnd2 = opnd_create_reg(reg);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);
}


/* update last map offset */
static void
append_update_last_map_offset(void         *drcontext,
                              umbra_info_t *info,
                              instrlist_t  *ilist,
                              reg_id_t      reg)
{
    instr_t *instr;
    opnd_t   opnd1, opnd2;

    if (proc_info.options.opt_map_check == false)
        return;
    
    /* reg => info->last_map_offset */
    opnd1 = OPND_CREATE_ABSMEM(&info->last_map_offset, OPSZ_PTR);
    opnd2 = opnd_create_reg(reg);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);
}


/* return back to fragment */
static void
append_return_to_fragment(void         *drcontext,
                          umbra_info_t *info,
                          instrlist_t  *ilist)
{
    instr_t *instr;
    opnd_t   opnd1;

    if (proc_info.options.swap_stack) {
        /* ret */
        instr = INSTR_CREATE_ret(drcontext);
    } else {
        opnd1 = OPND_CREATE_ABSMEM(&info->cache_pc, OPSZ_PTR);
        instr = INSTR_CREATE_jmp_ind(drcontext, opnd1);
    }
    instrlist_meta_append(ilist, instr);
}


/* insert clean call */
static void
append_clean_call(void *drcontext,
                  umbra_info_t *info,
                  instrlist_t *ilist)
{
    /* call shadow_maps_lookup */
    dr_insert_clean_call(drcontext, ilist, NULL,
                         (void *)shadow_memory_map_lookup,
                         false, 0);
}


/* 
 * mov [map_offset] => %reg 
 */
static void
append_load_map_offset(void        *drcontext, 
                       instrlist_t *ilist,
                       reg_id_t     reg,
                       void        *map_offset)
{
    instr_t *instr;
    opnd_t   opnd1, opnd2;
    
    /* mov [map_offset] => %reg */
    opnd1 = opnd_create_reg(reg);
    opnd2 = OPND_CREATE_ABSMEM(map_offset, OPSZ_PTR);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);
}


/* 
 *   cmp reg [map_tag]
 *   jne .end
 */
static void
append_compare_map_tag(void        *drcontext,
                       instrlist_t *ilist,
                       reg_id_t     reg,
                       void        *map_tag,
                       instr_t     *end)
{
    instr_t *instr;
    opnd_t   opnd1, opnd2;
    
    /* cmp reg, *map_tag */
    opnd1 = opnd_create_reg(reg);
    opnd2 = OPND_CREATE_ABSMEM(map_tag, OPSZ_PTR);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* jne [end] */
    opnd1 = opnd_create_instr(end);
    instr = INSTR_CREATE_jcc(drcontext, OP_jne, opnd1);
    instrlist_meta_preinsert(ilist, NULL, instr);
}


static instrlist_t *
build_map_check_ilist(void        *drcontext, 
                      umbra_info_t *info, 
                      reg_id_t     reg)
{
    instr_t     *next;
    instrlist_t *ilist;

    ilist = instrlist_create(drcontext);
    instrlist_init(ilist);

    /* info->last_map_tag check */
    next = INSTR_CREATE_label(drcontext);
    append_compare_map_tag(drcontext, ilist, reg, &info->last_map_tag, next);
    append_load_map_offset(drcontext, ilist, reg, &info->last_map_offset);
    append_return_to_fragment(drcontext, info, ilist);
    instrlist_meta_append(ilist, next);
#ifndef DOUBLE_SHADOW
    /* info->stack_map_tag check */
    next = INSTR_CREATE_label(drcontext);
    append_compare_map_tag(drcontext, ilist, reg, &info->stack_map_tag, next);
    append_load_map_offset(drcontext, ilist, reg, &info->stack_map_offset);
    append_return_to_fragment(drcontext, info, ilist);
    instrlist_meta_append(ilist, next);

    /* proc_info.bin_map_tag check */
    next = INSTR_CREATE_label(drcontext);
    append_compare_map_tag(drcontext, ilist, reg, &proc_info.bin_map_tag, next);
    append_load_map_offset(drcontext, ilist, reg, &proc_info.bin_map_offset);
    append_return_to_fragment(drcontext, info, ilist);
    instrlist_meta_append(ilist, next);

#ifndef LINUX_KERNEL
    /* proc_inf.lib_map_tag check */
    next = INSTR_CREATE_label(drcontext);
    append_compare_map_tag(drcontext, ilist, reg, &proc_info.lib_map_tag, next);
    append_load_map_offset(drcontext, ilist, reg, &proc_info.lib_map_offset);
    append_return_to_fragment(drcontext, info, ilist);
    instrlist_meta_append(ilist, next);
#endif
#endif
    return ilist;
}


static app_pc
emit_map_check_code(void        *drcontext, 
                    umbra_info_t *info, 
                    app_pc       pc, 
                    reg_id_t     reg)
{
    instrlist_t *ilist;

    if (proc_info.options.opt_map_check == true) {
        ilist = build_map_check_ilist(drcontext, info, reg);
        if (proc_info.options.stat == true) {
            preinsert_count_inc(drcontext,
                                ilist,
                                instrlist_first(ilist),
                                &info->num_map_checks,
                                1);
        }
        pc = instrlist_encode(drcontext, ilist, pc, true);
        instrlist_clear_and_destroy(drcontext, ilist);
    }
    return pc;
}


static app_pc
emit_addr_alignment_code(void         *drcontext,
                         umbra_info_t *info,
                         app_pc        pc,
                         reg_id_t      reg)
{
    instrlist_t *ilist;

    ilist = instrlist_create(drcontext);
    instrlist_init(ilist);
    /* update info->num_fast_lookups */
    if (proc_info.options.stat == true) {
        preinsert_count_inc(drcontext,
                            ilist,
                            NULL,
                            &info->num_fast_lookups,
                            1);
    }
    /* align addr: reg = reg & proc_info.unit_mask */
    if (proc_info.options.opt_inline_check == false) {
        instr_t *instr;
        opnd_t   opnd1, opnd2;
        opnd1 = opnd_create_reg(reg);
        opnd2 = OPND_CREATE_ABSMEM(&proc_info.unit_mask, OPSZ_PTR);
        instr = INSTR_CREATE_and(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, NULL, instr);
    }
    /* encode */
    pc = instrlist_encode(drcontext, ilist, pc, true);
    /* clear */
    instrlist_clear_and_destroy(drcontext, ilist);
    return pc;
}


static instrlist_t *
build_map_search_ilist(void *drcontext,
                       umbra_info_t *info,
                       reg_id_t reg)
{
    instrlist_t *ilist;
    instr_t *instr, *end, *test, *match;
    opnd_t   opnd1, opnd2;
#ifdef LINUX_KERNEL
    reg_id_t app_tag_reg = reg == REG_XAX ? REG_XBX : REG_XAX;
#else
    reg_id_t app_tag_reg = REG_XSP;
#endif

    ilist = instrlist_create(drcontext);
    instrlist_init(ilist);

    end   = INSTR_CREATE_label(drcontext);
    match = INSTR_CREATE_label(drcontext);
    if (proc_info.options.stat == true)
        preinsert_count_inc(drcontext,
                            ilist,
                            NULL,
                            &info->num_map_searchs,
                            1);
    if (proc_info.options.swap_stack == false) {
        /* save app_tag_reg */
        opnd1 = OPND_CREATE_ABSMEM(&info->app_stack, OPSZ_PTR);
        opnd2 = opnd_create_reg(app_tag_reg);
        instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
        instrlist_meta_append(ilist, instr);
    }

    /* mov reg => info->last_map_tag */
    append_update_last_map_tag(drcontext, info, ilist, reg);

    /* mov %reg => %rsp */
    opnd1 = opnd_create_reg(app_tag_reg);
    opnd2 = opnd_create_reg(reg);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);

    /* mov info->maps  => %reg */
    opnd1 = opnd_create_reg(reg);
    opnd2 = OPND_CREATE_ABSMEM(&info->maps, OPSZ_PTR);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);
    
    /* test %reg %reg */
    opnd1 = opnd_create_reg(reg);
    opnd2 = opnd_create_reg(reg);
    test  = INSTR_CREATE_test(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, test);
    
    /* jz end */
    opnd1 = opnd_create_instr(end);
    instr = INSTR_CREATE_jcc(drcontext, OP_jz, opnd1);
    instrlist_meta_append(ilist, instr);
    
    /* cmp %rsp app_base */
    opnd1 = opnd_create_reg(app_tag_reg);
    opnd2 = OPND_CREATE_MEMPTR(reg, offsetof(memory_map_t, app_base));
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);
    
    /* je .match */
    opnd1 = opnd_create_instr(match);
    instr = INSTR_CREATE_jcc(drcontext, OP_je, opnd1);
    instrlist_meta_append(ilist, instr);
    
    /* mov [%reg].next => %reg */
    opnd1 = opnd_create_reg(reg);
    opnd2 = OPND_CREATE_MEMPTR(reg, offsetof(memory_map_t, next));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);

    /* jmp .test */
    opnd1 = opnd_create_instr(test);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_append(ilist, instr);

    /* .match */
    instrlist_meta_append(ilist, match);

    /* mov [%reg].offset => %reg */
    opnd1 = opnd_create_reg(reg);
    opnd2 = OPND_CREATE_MEMPTR(reg, offsetof(memory_map_t, offset));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);
    
    /* restore app_tag_reg */
    append_restore_app_tag_reg(drcontext, app_tag_reg, info, ilist);
    
    /* update last map offset */
    append_update_last_map_offset(drcontext, info, ilist, reg);
    append_return_to_fragment(drcontext, info, ilist);
    
    /* .end */
    instrlist_meta_append(ilist, end);
    /* restore app_tag_reg */
    append_restore_app_tag_reg(drcontext, app_tag_reg, info, ilist);

    return ilist;
}


static app_pc
emit_map_search_code(void        *drcontext,
                     umbra_info_t *info,
                     app_pc       pc,
                     reg_id_t     reg)
{
    instrlist_t *ilist;
    
    ilist = build_map_search_ilist(drcontext, info, reg);
    pc = instrlist_encode(drcontext, ilist, pc, true); 
    instrlist_clear_and_destroy(drcontext, ilist);
    return pc;
}


static app_pc
emit_clean_call_code(void         *drcontext, 
                     umbra_info_t *info, 
                     app_pc        pc, 
                     reg_id_t      reg)
{
    instrlist_t *ilist;

    ilist = instrlist_create(drcontext);
    instrlist_init(ilist);
    if (proc_info.options.stat == true) {
        preinsert_count_inc(drcontext, ilist, NULL,
                            &info->num_clean_calls,
                            1);
    }

    append_clean_call(drcontext, info, ilist);
    append_load_map_offset(drcontext, ilist, reg, 
                           &info->last_map_offset);
    append_return_to_fragment(drcontext, info, ilist);
    /* encode */
    pc = instrlist_encode(drcontext, ilist, pc, true);
    /* clear */
    instrlist_clear_and_destroy(drcontext, ilist);

    return pc;
}


/* 
 * # addr alignment code 
 * # map check code
 * # map search code 
 * # clean call 
 */
static app_pc
emit_fast_lookup_with_reg(void        *drcontext, 
                          umbra_info_t *info, 
                          app_pc       pc, 
                          reg_id_t     reg)
{
    int pos;

    UMBRA_REG_TO_POS(reg, pos);
    pc = emit_addr_alignment_code(drcontext, info, pc, reg);
    info->map_check_pc[pos]  = pc;
    pc = emit_map_check_code(drcontext, info, pc, reg);
    info->map_search_pc[pos] = pc;
    pc = emit_map_search_code(drcontext, info, pc, reg);
    info->clean_call_pc[pos] = pc;
    pc = emit_clean_call_code(drcontext, info, pc, reg);

    return pc;
}


static app_pc
emit_fast_lookup_code(void *drcontext, umbra_info_t *info)
{
    reg_id_t reg;
    int      pos;
    app_pc   pc;
    
    pc = info->code_cache_start;
    for (pos = 0; pos < NUM_SPILL_REGS; pos++) {
        UMBRA_POS_TO_REG(reg, pos);
        /* stack reg or aflags reg won't be used */
        if (reg == REG_XSP || reg == REG_XAX)
            continue;
        /* fast lookup */
        pc = umbra_align_cache_line(pc);
        pc = emit_fast_lookup_with_reg(drcontext, info, pc, reg);
    }
    return pc;
}


/* initialize the stack for call to lean procedure of translation lookup code */
static void
umbra_stack_init(void *drcontext, umbra_info_t *info)
{
    info->umbra_stack_ptr = (reg_t)(&info->umbra_stack[3]);
    info->umbra_stack_ptr = ALIGN_BACKWARD(info->umbra_stack_ptr, 
                                           STACK_ALIGN_SIZE);
    info->umbra_stack_ptr_off = info->umbra_stack_ptr - STACK_ALIGN_SIZE;
}


static void
umbra_stack_exit(void *drcontext, umbra_info_t *info)
{
    /* do nothing */
}


static void 
umbra_code_cache_init(void *drcontext, umbra_info_t *info)
{
    uint prot;

    prot = DR_MEMPROT_READ|DR_MEMPROT_WRITE|DR_MEMPROT_EXEC;
    info->code_cache_start = dr_nonheap_alloc(CODE_CACHE_SIZE, prot);
    info->code_cache_end   = emit_fast_lookup_code(drcontext, info);
}


static void
umbra_code_cache_exit(void *drcontext, umbra_info_t *info)
{
    /* free the code cache */
    dr_nonheap_free(info->code_cache_start, CODE_CACHE_SIZE);
    info->code_cache_start = NULL;
    info->code_cache_end   = NULL;
}


/*---------------------------------------------------------------------*
 *                 Exported Function Implementation                    *
 *---------------------------------------------------------------------*/
void
instrument_thread_init(void *drcontext, umbra_info_t *info)
{
    umbra_stack_init(drcontext, info);
    umbra_code_cache_init(drcontext, info);
}


void
instrument_thread_exit(void *drcontext, umbra_info_t *info)
{
#ifdef LINUX_KERNEL
    /* We don't support unloading if there are any wrapped functions. The post
     * wrapper return address might still be on the stack. */
    DR_ASSERT(wrap_funcs == NULL);
#endif
    umbra_code_cache_exit(drcontext, info);
    umbra_stack_exit(drcontext, info);
}


static void
preinsert_instr_count(void        *drcontext,
                      umbra_info_t *info,
                      instrlist_t *ilist)
{
    instr_t *instr, *first = instrlist_first(ilist);
    uint flags;
    int  num_instr = 0;
    bool save = true;
    
    for (instr = first; instr != NULL; instr = instr_get_next(instr)) 
        num_instr++;
    for (instr = first; instr != NULL; instr = instr_get_next(instr)) {
        flags = instr_get_arith_flags(instr);
        if (TESTANY(EFLAGS_READ_6, flags)) {
            save = true;
            break;
        }
        if (TESTALL(EFLAGS_WRITE_6, flags)) {
            save = false;
            break;
        }
    }

    if (save == true)
        dr_save_arith_flags(drcontext, ilist, first, SPILL_SLOT_1);
    preinsert_count_inc(drcontext, ilist, first, 
                        &info->num_dyn_instrs,
                        num_instr);
    if (save == true)
        dr_restore_arith_flags(drcontext, ilist, first, SPILL_SLOT_1);
}

static void
emulate_push(dr_mcontext_t *mc, reg_t value)
{
    mc->xsp -= sizeof(reg_t);
    *((reg_t*) mc->xsp) = value;
}

static reg_t
emulate_pop(dr_mcontext_t *mc)
{
    reg_t value = *((reg_t*) mc->xsp);
    mc->xsp += sizeof(reg_t);
    return value;
}

static reg_t
get_stack_element(dr_mcontext_t *mc, int index) {
    return ((reg_t*) mc->xsp)[index];
}

static reg_t
get_top_of_stack(dr_mcontext_t *mc)
{
    return get_stack_element(mc, 0);
}

static void
my_pre_func(umbra_info_t *info, wrap_func_t *wp)
{
    dr_mcontext_t mc;
    int app_errno;
    func_args_t *args;
    int i;
#ifndef LINUX_KERNEL
    DR_ASSERT(info->stack_depth < MAX_STACK_DEPTH);
    dr_get_mcontext(info->drcontext, &mc, &app_errno);
    info->wrap_func_stack[info->stack_depth].app_ret = info->app_ret;
    info->wrap_func_stack[info->stack_depth].stack   = (void *)mc.xsp;
    info->stack_depth++;
#endif
    dr_get_mcontext(info->drcontext, &mc, &app_errno);
    /* If we're interrupted in this clean call, then we'll get another dispatch
     * at wp->func. To prevent the instrumentation from running twice, we check
     * to see if we've already been here.
     */
    info->num_pre_wrap_calls++;
    if (get_top_of_stack(&mc) == (reg_t) wp->post_func) {
        info->num_pre_wrap_intr++;
        return;
    }
    emulate_push(&mc, mc.xbp);
    mc.xbp = mc.xsp;
    for (i = MAX_FUNC_ARGS - 1; i >= 0; i--) {
        emulate_push(&mc, reg_get_value(ARG_REGS[i], &mc));
    }
    args = (func_args_t*) mc.xsp;
    if (wp->pre_func != NULL) {
        wp->pre_func(&mc, args);
    }
    emulate_push(&mc, (reg_t) wp->post_func);
    dr_set_mcontext(info->drcontext, &mc, &app_errno);
}

#ifndef LINUX_KERNEL
static void
my_post_func_dummy(void)
{
}
#endif

static void
my_post_func(umbra_info_t *info, wrap_func_t *wp, bool ret_on_stack)
{
    dr_mcontext_t mc;
    func_args_t *args;
    int app_errno;
    int i;
#ifndef LINUX_KERNEL
    reg_t *stack;

    DR_ASSERT(info->stack_depth > 0);
    dr_get_mcontext(info->drcontext, &mc, &app_errno);
    /* check if the stack pointer matchs */
    info->stack_depth--;
    DR_ASSERT(info->wrap_func_stack[info->stack_depth].stack == (void *)mc.xsp - 8);
    info->app_ret = info->wrap_func_stack[info->stack_depth].app_ret;
#endif
    dr_get_mcontext(info->drcontext, &mc, &app_errno);
    info->num_post_wrap_calls++;

    if (ret_on_stack) {
        mc.pc = (byte*) emulate_pop(&mc);
    } else {
        mc.pc = (byte*) wp->post_func;
    }

    if (mc.pc != (byte*) wp->post_func) {
        info->num_post_without_pre++;
        if (wp->post_func != NULL) {
            wp->post_func(&mc, NULL, mc.xax);
        }
    } else {
        args = (func_args_t*) mc.xsp;
        if (wp->post_func != NULL) {
            wp->post_func(&mc, args, mc.xax);
        }
        for (i = 0; i < MAX_FUNC_ARGS ; i++) {
            emulate_pop(&mc);
        }
        mc.xsp = mc.xbp;
        mc.xbp = emulate_pop(&mc);
        mc.pc = (app_pc) emulate_pop(&mc);
    }
    dr_redirect_execution(&mc, app_errno);
}

#ifndef LINUX_KERNEL
static void
instrument_pre_wrap_func(void          *drcontext, 
                         umbra_info_t  *umbra_info,
                         basic_block_t *bb, 
                         instrlist_t   *ilist)
{
    instr_t *instr, *first;
    opnd_t opnd1;
    wrap_func_t *wp;

    first = instrlist_first(ilist);
    if (bb->tag == (void *)my_post_func_dummy) {
        /* return */
        instr = INSTR_CREATE_ret(drcontext);
        INSTR_XL8(instr, bb->tag);
        instrlist_preinsert(ilist, first, instr);
        instrlist_truncate(drcontext, ilist, first);
        return;
    }
    for (wp = wrap_funcs; wp != NULL; wp = wp->next) {
        if (bb->tag == (void *)wp->post_func) {
            /* push */
            opnd1 = OPND_CREATE_ABSMEM(&umbra_info->app_ret, OPSZ_PTR);
            instr = INSTR_CREATE_push(drcontext, opnd1);
            instrlist_meta_preinsert(ilist, first, instr);
            /* jmp */
            opnd1 = opnd_create_pc((app_pc)my_post_func_dummy);
            instr = INSTR_CREATE_jmp(drcontext, opnd1);
            INSTR_XL8(instr, bb->tag);
            instrlist_preinsert(ilist, first, instr);
            instrlist_truncate(drcontext, ilist, first);
        }
    }
}
#endif

static void
should_not_reach_here(void) {
    DR_ASSERT(false);
}

static bool
is_function_ret(wrap_func_t *wf, instr_t *instr)
{
    byte *pc = instr_get_app_pc(instr);
    return instr_get_opcode(instr) == OP_ret &&
           pc >= wf->func && pc < wf->func + wf->size;
}

static void
instrument_post_wrap_func(void          *drcontext, 
                          umbra_info_t  *umbra_info,
                          basic_block_t *bb, 
                          instrlist_t   *ilist)
{
    wrap_func_t *wp;
    instr_t *next, *instr, *first;
    opnd_t opnd1;

    first = instrlist_first(ilist);
    for (wp = wrap_funcs; wp != NULL; wp = wp->next) {
        if (bb->tag == wp->func) {
#ifndef LINUX_KERNEL
            /* pop info->app_ret */
            opnd1 = OPND_CREATE_ABSMEM(&umbra_info->app_ret, OPSZ_PTR);
            instr = INSTR_CREATE_pop(drcontext, opnd1);
            instrlist_meta_preinsert(ilist, first, instr);
            /* mov */
            opnd1 = OPND_CREATE_ABSMEM(&umbra_info->post_func, OPSZ_4);
            opnd2 = OPND_CREATE_INT32(wp->post_func);
            instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
            instrlist_meta_preinsert(ilist, first, instr);
            /* push */
            opnd1 = OPND_CREATE_ABSMEM(&umbra_info->post_func, OPSZ_PTR);
            instr = INSTR_CREATE_push(drcontext, opnd1);
            instrlist_meta_preinsert(ilist, first, instr);
#endif
            if (wp->pre_func != NULL) {
                /* simply insert clean call */
                dr_insert_clean_call(drcontext, ilist, first,
                                     (void *)my_pre_func,
                                     false, 2,
                                     OPND_CREATE_INTPTR((void *)umbra_info),
                                     OPND_CREATE_INTPTR((void *)wp));
            }
            return;
        }
        if (bb->tag == (app_pc)wp->post_func) {
            dr_insert_clean_call(drcontext, ilist, first,
                                 (void *)my_post_func,
                                 false, 3,
                                 OPND_CREATE_INTPTR((void *)umbra_info),
                                 OPND_CREATE_INTPTR((void *)wp),
                                 OPND_CREATE_INT32(false));
#ifdef LINUX_KERNEL
            /* We should not reach here because my_post_func calls
             * dr_redirect_execution. */
            opnd1 = opnd_create_pc((app_pc) should_not_reach_here);
            instr = INSTR_CREATE_jmp(drcontext, opnd1);
            INSTR_XL8(instr, (void*)bb->tag);
            instrlist_preinsert(ilist, first, instr);
            instrlist_truncate(drcontext, ilist, first);
#endif
            return;
        }
    }
    /* Try to find the function's ret instruction. If we find it, replace it
     * with a clean call. This is useful if we attach after a function has
     * been called (i.e., the post_func will not be pushed on the stack. */
    for (instr = first, next = first; instr != NULL;
         next = instr_get_next(next), instr = next) {
        for (wp = wrap_funcs; wp != NULL; wp = wp->next) {
            if (is_function_ret(wp, instr)) {
                dr_insert_clean_call(drcontext, ilist, instr, 
                                     (void*) my_post_func,
                                     false, 3,
                                     OPND_CREATE_INTPTR((void *)umbra_info),
                                     OPND_CREATE_INTPTR((void *)wp),
                                     OPND_CREATE_INT32(true));
            }
        }
    }
}


void 
instrument_basic_block(void          *drcontext, 
                       umbra_info_t  *umbra_info,
                       basic_block_t *bb, 
                       instrlist_t   *ilist,
                       bool           for_trace)
{
    instr_t       *instr, *prev;
    ilist_info_t   ilist_info;
    umbra_client_t *client;

#ifdef VERBOSE_INSTRUMENTATION
    dr_fprintf(umbra_info->log, "%p\n", bb->tag);
    if (for_trace)
    instrlist_disassemble(drcontext, bb->tag, ilist, umbra_info->log);
#endif

    if (proc_info.client.pre_umbra_instrument_bb != NULL) {
      proc_info.client.pre_umbra_instrument_bb(drcontext, umbra_info, bb->tag,
                                               ilist, for_trace);
    }
#ifndef LINUX_KERNEL
    instrument_pre_wrap_func(drcontext, umbra_info, bb, ilist);
#endif
    client = &proc_info.client;
    if (proc_info.options.stat == true) 
        preinsert_instr_count(drcontext, umbra_info, ilist);

    /* initlize ilist info */
    ilist_info_init(drcontext, umbra_info, &ilist_info, bb);

    /* forward scan to analyze instrlist */
    ilist_info_ilist_analysis(drcontext, 
                              umbra_info, 
                              &ilist_info, 
                              ilist);

    /* reverse scan and instrument the instrlist */
    if (client->bb_is_interested(umbra_info, bb) == true) {
        for (instr  = instrlist_last(ilist); 
             instr != NULL; 
             instr  = prev) {
            prev = instr_get_prev(instr);
            /* update ilist_info for each instructions */
            ilist_info_update(drcontext, 
                              umbra_info, 
                              &ilist_info,
                              instr);
            /* check if need instrumentation now */
            if (should_start_instrumentation(&ilist_info, 
                                             prev, 
                                             instr, 
                                             client)) {
                instrument_umbra_code(drcontext, 
                                      umbra_info, 
                                      &ilist_info,
                                      ilist, 
                                      instr,
                                      for_trace);
                /* reset ilist info */
                ilist_info_reset(&ilist_info);
            }
        }
    }

    /* finalize ilist info */
    ilist_info_exit(drcontext, &ilist_info);
    instrument_post_wrap_func(drcontext, umbra_info, bb, ilist);
    if (proc_info.client.post_umbra_instrument_bb != NULL) {
      proc_info.client.post_umbra_instrument_bb(drcontext, umbra_info, bb->tag,
                                                ilist, for_trace);
    }
#ifdef VERBOSE_INSTRUMENTATION
    if (for_trace)
    instrlist_disassemble(drcontext, bb->tag, ilist, umbra_info->log);
#endif
}

#ifdef LINUX_KERNEL
bool
instrument_interrupt(umbra_info_t *umbra_info, dr_interrupt_t *interrupt)
{
    if (interrupt->frame->xip >= umbra_info->code_cache_start &&
        interrupt->frame->xip < umbra_info->code_cache_end) {
        /* We don't support using the umbra stack for now because we don't want
         * the kernel's interrupts to be pushed on it.
         */
        DR_ASSERT(!proc_info.options.swap_stack);
        if (!proc_info.options.swap_stack) {
            interrupt->frame->xip = (byte*) umbra_info->cache_pc;
        }
    }
    return true;
}
#endif


/*---------------------------------------------------------------------*
 *                         End of instrument.c                         *
 *---------------------------------------------------------------------*/
