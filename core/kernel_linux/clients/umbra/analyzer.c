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
 *     Analyzer -- analyzer.c 
 *
 * Description:
 *     analyze the application code for instrumentation
 *
 * Author: 
 *     Qin Zhao
 * 
 */


#include "umbra.h"
#include "analyzer.h"
#include "cfg.h"
#include "table.h"
#include "utils.h"

/*
 * Global Function Implementation
 */

/* check if register is used for source memroy access */
static bool 
register_is_used_in_src_mem(instr_t *instr, reg_id_t reg)
{
    int  num_srcs, i;
    opnd_t opnd;

    num_srcs = instr_num_srcs(instr);
    for(i = 0; i < num_srcs; i++) {
        opnd = instr_get_src(instr, i);
        if(opnd_is_memory_reference(opnd) && opnd_uses_reg(opnd, reg))
            return true;        
    }
    return false;
}


/* check if register is used for dest memory access */
static bool 
register_is_used_in_dst_mem(instr_t *instr, reg_id_t reg)
{
    int  num_dsts, i;
    opnd_t opnd;
    
    num_dsts = instr_num_dsts(instr);
    for(i = 0; i < num_dsts; i++) {
        opnd = instr_get_dst(instr, i);
        if(opnd_is_memory_reference(opnd) && opnd_uses_reg(opnd, reg))
            return true;
    }
    return false;
}


/* check if this instr set an register to immed value */
static bool
reg_set_immed(instr_t *instr, reg_id_t reg)
{
    int opcode = instr_get_opcode(instr);

    // for case of r1 = r1 - r1, or r1 = r1 xor r1
    if((opcode == OP_sub || opcode == OP_xor) &&
       (opnd_same(instr_get_src(instr, 0), 
                  instr_get_src(instr, 1))))
        return true;

    if(opcode == OP_mov_ld          && 
       opnd_is_immed(instr_get_src(instr, 0)))
        return true;
    if (opcode == OP_mov_imm)
        return true;

    return false;
}


/*---------------------------------------------------------------------*
 *                        Memory Reference Analysis                    *
 *---------------------------------------------------------------------*/


/* add a new memory reference into bb */
static void
add_mem_ref(void          *drcontext,   
            umbra_info_t  *info, 
            basic_block_t *bb, 
            instr_t       *instr,  
            opnd_t         opnd,  
            int            type)
{
    mem_ref_t *ref, *old_ref, *new_ref;
    int     i;

    ref = table_alloc_ref(drcontext, info);
    ref->pc    = instr_get_app_pc(instr);
    ref->opcode= instr_get_opcode(instr);
    ref->instr = instr;
    ref->type  = type;
    ref->opnd  = opnd;
    ref->cache = NULL;
    bb->num_refs++;

    if(bb->num_refs == 1) {
        bb->refs = ref;
        return;
    }
    
    // make sure refs in a bb is consectuively allocated
    if((ref->id % INIT_REF_TABLE_SIZE) != 0) 
        return;

    old_ref  = bb->refs;
    new_ref  = NULL;
    bb->refs = ref;
    for(i = 1; i < bb->num_refs; i++) {
        if(new_ref == NULL)
            new_ref = ref;
        else
            new_ref = table_alloc_ref(drcontext, info);
        new_ref->pc     = old_ref->pc;
        new_ref->opcode = old_ref->opcode;
        new_ref->type   = old_ref->type;
        new_ref->instr  = old_ref->instr;
        new_ref->opnd   = old_ref->opnd;
        new_ref->count  = old_ref->count;
        new_ref->cache  = old_ref->cache;
        old_ref++;
    }
    ref = table_alloc_ref(drcontext, info);
    ref->pc    = instr_get_app_pc(instr);
    ref->opcode= instr_get_opcode(instr);
    ref->instr = instr;
    ref->type  = type;
    ref->opnd  = opnd;
    ref->count = 0;
    ref->cache = NULL;
}


/* analyze instr in bb for the memory references */
static void
refs_analysis(void          *drcontext, 
              umbra_info_t  *info, 
              basic_block_t *bb, 
              instr_t       *instr)
{
    int i, num_srcs, num_dsts, num_reads, num_writes, opcode;
    opnd_t opnd, reads[4], writes[4];

    if (instr_get_app_pc(instr) == NULL)
        return;
    
    if (instr_is_interrupt(instr))
        return;
    if (instr_is_syscall(instr))
        return;

    /* lea, nop_modrm, and prefetch have memory operand 
     * but do not access memory 
     */
    opcode = instr_get_opcode(instr);
    if (opcode == OP_lea || opcode == OP_nop_modrm ||
        (opcode >= OP_prefetchnta && opcode <= OP_prefetchw))
        return;

    num_reads  = 0;
    num_writes = 0;

    num_srcs = instr_num_srcs(instr);
    for(i = 0; i < num_srcs; i++) {
        opnd = instr_get_src(instr, i);
        if (opnd_is_memory_reference(opnd)) {
            reads[num_reads++] = opnd;
        }
    }

    num_dsts = instr_num_dsts(instr);
    for(i = 0; i < num_dsts; i++) {
        opnd = instr_get_dst(instr, i);
        if (opnd_is_memory_reference(opnd))
            writes[num_writes++] = opnd;
    }

    /* simple mem ref like [mem] +/- src => [mem] */
    if (num_reads == 1 && num_writes == 1 && opnd_same(reads[0], writes[0])) {
        add_mem_ref(drcontext, info, bb, instr, reads[0], MemModify);
        return;
    }

    for (i = 0; i < num_reads; i++) 
        add_mem_ref(drcontext, info, bb, instr, reads[i], MemRead);
    
    for (i = 0; i < num_writes; i++) 
        add_mem_ref(drcontext, info, bb, instr, writes[i], MemWrite);
}



/*---------------------------------------------------------------------*
 *                           Register Analysis                         *
 *---------------------------------------------------------------------*/

static void
regs_analysis(void *drcontext,   umbra_info_t *info, 
              basic_block_t *bb, instr_t *instr)
{
    /* do nothing */
}



/*---------------------------------------------------------------------*
 *                 Exported Function Implementation                    *
 *---------------------------------------------------------------------*/
void 
analyzer_thread_init(void *drcontext, umbra_info_t *info)
{
}

void 
analyzer_thread_exit(void *drcontext, umbra_info_t *info)
{
}


/* update both ref instr and the aflags */
void 
analyzer_update_bb(void          *drcontext, 
                   umbra_info_t  *info, 
                   basic_block_t *bb, 
                   instrlist_t *ilist)
{
    instr_t *instr;
    app_pc   pc;
    uint aflags;
    basic_block_t *tgt;
    link_edge_t   *edge;
    bool aflags_dead;

    /* update aflags based on control flow graph */
    aflags_dead = true;
    if (!BB_IS_LINKED(bb))
        aflags_dead = false; 
    else {
        for (edge      = cfg_bb_get_first_outgoing_edge(info, bb);
             edge->id != 0;
             edge      = cfg_edge_get_next_outgoing_edge(info, edge)) {
            if (EDGE_IS_IND_BRANCH(edge)) {
                aflags_dead = false;
                break;
            } else if (edge->opcode == OP_call_fall) {
                /* do nothing because this is a fake edge */
            } else {
                tgt = cfg_get_bb(info, edge->dst_bb);
                aflags_dead = BB_IS_AFLAGS_DEAD(tgt) && aflags_dead;
            }
        }
    }

    /* reverse scan to discover if the aflags is dead at entry */
    for (instr  = instrlist_last(ilist);
         instr != NULL;
         instr  = instr_get_prev(instr)) {
        int i;
        pc = instr_get_app_pc(instr);
        if (pc == NULL)
            continue;
        aflags = instr_get_arith_flags(instr);
        if (TESTANY(EFLAGS_READ_6, aflags)) {
            aflags_dead = false;
        } else if (TESTALL(EFLAGS_WRITE_6, aflags)) {
            aflags_dead = true;
        }
        for (i = 0; i < bb->num_refs; i++) {
            if (bb->refs[i].pc == pc)
                /* change the instr, the old instr should 
                 * have been destroyed on code emission 
                 */
                bb->refs[i].instr = instr;
        }
    }
    if (aflags_dead == true)
        BB_SET_AFLAGS_DEAD(bb);
}


/*
 * What to analyze:
 * 1) Any Memory Reference  // for memory reference checking
 */
basic_block_t *
analyzer_basic_block(void *drcontext, umbra_info_t *info, basic_block_t *bb, instrlist_t *ilist)
{
    // forward scan instrlist
    instr_t *instr;

    for (instr  = instrlist_first(ilist);
         instr != NULL;
         instr  = instr_get_next(instr)) {
        if (instr_get_app_pc(instr) == NULL)
            continue;
        regs_analysis(drcontext, info, bb, instr);
        refs_analysis(drcontext, info, bb, instr);
        bb->num_app_instrs++;
    }

    info->num_app_instrs += bb->num_app_instrs;
    return bb;
}


/* check if register is updated */
bool
register_is_updated(instr_t *instr, reg_id_t reg)
{
    int opcode;
 
    /* assume syscall and interrupt always change registers */
    if(instr_is_syscall(instr) || instr_is_interrupt(instr))
        return true;

    opcode = instr_get_opcode(instr);

    if(instr_writes_to_reg(instr, reg))
        return true;

    if(reg != REG_ESP)
        return false;

    /* special handling for %rsp, 
     * %rsp is modifed by following instr, but not
     * reported by instr_writes_to_reg(instr, reg)
     */
    if(instr_is_call(instr))
        return true;

    if(opcode == OP_popa  || opcode == OP_pushf ||
       opcode == OP_pusha || opcode == OP_popf)
        return true;
    
    return false;
}


/* check if instr update the whol register */
static bool
instr_writes_to_whole_reg(instr_t *instr, reg_id_t reg)
{
    if (instr_writes_to_exact_reg(instr, reg))
        return true;
#ifdef X64
    reg = reg_64_to_32(reg);
    if (instr_writes_to_exact_reg(instr, reg))
        return true;
#endif
    return false;
}


/* check if register is dead before this intre */
bool 
register_is_dead(instr_t *instr, reg_id_t reg)
{
    int  opcode;

#ifdef LINUX_KERNEL
    /* Could always get an interrupt or exception that pushes onto the kernel
     * stack. */
    if (reg == REG_XSP)
        return false;
#endif

    // when at interupt, register never die
    if(instr_is_syscall(instr) || instr_is_interrupt(instr))
        return false;
    
    opcode = instr_get_opcode(instr);
    // dead reg must be exact dst being written
    if (!instr_writes_to_whole_reg(instr, reg))
        return false;

    // reg is set to be immed
    // r1 = r1 - r1 || r1 = r1 xor r1 || r1 = immed
    if(reg_set_immed(instr, reg))
        return true;

    // dead reg cannot be used 
    if(instr_reg_in_src(instr, reg))
        return false;
    
    // must be a dead reg now
    return true;
}


/* check if a register is used by instr */
bool 
register_is_used(instr_t *instr, reg_id_t reg)
{
    // assume interrupt use all registers 
    if(instr_is_syscall(instr) || instr_is_interrupt(instr))
        return true;
    /*XXX: how about instr like call, popf, ... */
    return instr_uses_reg(instr, reg);
}


/* check if register is used for memory reference */
bool
register_is_used_for_mem(instr_t *instr, reg_id_t reg)
{
    if (instr_get_opcode(instr) == OP_lea)
        return false;

    if (reg == REG_ECX && instr_is_rep_ins(instr))
        return true;

    // check srcs
    if(register_is_used_in_src_mem(instr, reg))
        return true;

    // check dsts
    if(register_is_used_in_dst_mem(instr, reg))
        return true;
    
    return false;
}



/* check if instr will be mangled by DR
 * If an instr is mangled, that instr cannot be used 
 * as operand 
 */
bool 
instr_is_mangled(instr_t *instr)
{
    if((instr_is_exit_cti(instr) && instr_is_cti_short(instr)) ||
       instr_is_syscall(instr)   ||
       instr_is_interrupt(instr) ||
       instr_is_mbr(instr)       ||
       instr_is_call(instr))
        return true;
    return false;
}


/* check if instr is a rep instruction */
bool
instr_is_rep_ins(instr_t *instr)
{
    return opcode_is_rep_ins(instr_get_opcode(instr));
}


/* check if opcode is a rep instruction */
bool 
opcode_is_rep_ins(int opcode)
{
    if(opcode == OP_rep_ins  || opcode == OP_rep_outs   ||
       opcode == OP_rep_movs || opcode == OP_rep_stos  ||
       opcode == OP_rep_lods || opcode == OP_rep_cmps   ||
       opcode == OP_rep_scas || opcode == OP_repne_cmps ||
       opcode == OP_repne_scas)
        return true;
    return false;
}
