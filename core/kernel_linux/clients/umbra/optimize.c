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
 *     Optimizer -- optimize.c 
 *
 * Description:
 *     Perform optimization on the instrumentation.
 *
 * Author: 
 *     Qin Zhao
 *
 */

#include <stddef.h>

#include "umbra.h"
#include "global.h"
#include "table.h"
#include "cfg.h"
#include "optimize.h"
#include "analyzer.h"

typedef struct _ref_info_t {
    ref_cache_t *cache;
} ref_info_t;

/* 
 * The client code is something like this
 +0    L4  8d 96 84 00 00 00    lea    0x00000084(%esi) -> %edx 
 +6    L4  81 e2 00 f0 ff ff    and    $0xfffff000 %edx -> %edx 
 +12   L4  3b 15 50 10 9a 17    cmp    %edx 0x179a1050 
 +18   L4  0f 84 fa ff ff ff    jz     $0x17455ab4 
 +24   L4  89 15 50 10 9a 17    mov    %edx -> 0x179a1050 
 +30   L4  89 25 3c 1a 49 17    mov    %esp -> 0x17491a3c 
 +36   L4  8b 25 40 1a 49 17    mov    0x17491a40 -> %esp 
 +42   L4  ff 35 54 10 9a 17    push   0x179a1054 %esp -> %esp (%esp) 
 +48   L4  e8 50 a6 eb 00       call   $0x18310109 %esp -> %esp (%esp) 
 +53   L4  8b 25 3c 1a 49 17    mov    0x17491a3c -> %esp 
.update
 +59   L4  8d 96 84 00 00 00    lea    0x00000084(%esi) -> %edx 
 +65   L4  81 e2 fc ff ff ff    and    $0xfffffffc %edx -> %edx 
 +71   L4  2b 15 58 10 9a 17    sub    0x179a1058 %edx -> %edx 
 +77   L4  ba 00 00 00 00       mov    $0x00000000 -> %edx 
 +82   L3  8b 96 84 00 00 00    mov    0x00000084(%esi) -> %edx 
 */


static void
ref_info_init(ref_info_t *ref_info) 
{
    int i;
    for (i = 0; i < NUM_SPILL_REGS; i++) {
        ref_info[i].cache = NULL;
    }
}

static instr_t *
analyze_client_code(void *drcontext, 
                    instrlist_t *ilist,
                    instr_t *where,
                    ref_info_t *ref_info)
{
    instr_t *next, *lea, *and, *cmp, *jcc, *sub;
    opnd_t   ref, opnd;
    ref_cache_t *cache;
    reg_id_t reg;
    int      pos, i;

    next = instr_get_next(where);
    if (next == NULL)
        return NULL;
    
    if (instr_get_opcode(where) != OP_lea)
        return next;

    /* lea [ref] => r1 */
    ref = instr_get_src(where, 0);
    if (!opnd_is_base_disp(ref) || opnd_get_index(ref) != REG_NULL)
        return next;

    lea = where;
    and = next;
    cmp = instr_get_next(and);
    jcc = instr_get_next(cmp);

    if (instr_get_app_pc(and) == NULL   &&
        instr_get_opcode(and) == OP_and &&
        instr_get_app_pc(cmp) == NULL   &&
        instr_get_opcode(cmp) == OP_cmp &&
        instr_get_app_pc(jcc) == NULL   &&
        instr_get_opcode(jcc) == OP_jz) {
        /* find pattern of 
         *   lea [ref] => reg
         *   and 0xffffffff00000000 reg
         *   cmp cache->tag  reg
         *   jz
         */
        opnd  = instr_get_src(cmp, 1);
        cache = opnd_get_addr(opnd) - offsetof(ref_cache_t, tag);
        for (i = 0; i < 10; ) {
            lea = instr_get_next(lea);
            if (!instr_is_label(lea))
                i++;
        }
        DR_ASSERT(instr_get_opcode(lea) == OP_lea);
    } else if (instr_get_app_pc(next) == NULL &&
               instr_get_opcode(next) == OP_sub) {
        opnd  = instr_get_src(next, 0);
        cache = opnd_get_addr(opnd) - offsetof(ref_cache_t, offset);
    } else {
        return next;
    }

    reg = opnd_get_base(ref);
    UMBRA_REG_TO_POS(reg, pos);
    if (ref_info[pos].cache == NULL) {
        ref_info[pos].cache = cache;
    } else {
        sub = instr_get_next(lea);
        DR_ASSERT(instr_get_opcode(sub) == OP_sub);
        while (lea != where) {
            next = instr_get_next(where);
            instrlist_remove(ilist, where);
            instr_destroy(drcontext, where);
            where = next;
        }
        opnd = OPND_CREATE_ABSMEM((void *)(reg_t)ref_info[pos].cache + 
                                  offsetof(ref_cache_t, offset),
                                  OPSZ_PTR);
        instr_set_src(sub, 0, opnd);
        if (proc_info.client.app_unit_bits  > 0 && 
            proc_info.client.shd_unit_bits != 0)
            next = instr_get_next(sub); /* reg & mask => reg */
        if (proc_info.client.orig_addr) {
            next = instr_get_next(next); /* mov reg => r2 */
            next = instr_get_next(next); /* r2 & bit_mask => r2 */
        }
    }

    next = instr_get_next(lea);
    return instr_get_next(next);
}



static bool
reg_update_is_limited(instr_t *instr, reg_id_t reg)
{
    int opcode;
    int offset;

    opcode = instr_get_opcode(instr);
    if (opcode == OP_inc || opcode == OP_dec)
        return true;
    if (opcode == OP_and) 
        /* for 0xffffffd0 & reg => reg */
        return true;

    if ((opcode == OP_add || opcode == OP_sub || 
         opcode == OP_adc || opcode == OP_sbb) &&
        opnd_is_immed_int(instr_get_src(instr, 0))) {
        offset = opnd_get_immed_int(instr_get_src(instr, 0));
        if (offset > PAGE_SIZE || offset < -PAGE_SIZE)
            return false;
        return true;
    }
    if (reg != REG_XSP)
        return false;

    if (opcode >= OP_push && opcode <= OP_popa) {
        if (opcode == OP_pop && opnd_same(instr_get_dst(instr, 0),
                                          opnd_create_reg(REG_XSP)))
            return false;
        return true;
    }
    if (opcode >= OP_call && opcode <= OP_call_far_ind)
        return true;
    if (opcode == OP_ret || opcode == OP_ret_far ||
        opcode == OP_enter || opcode == OP_leave ||
        opcode == OP_pushf || opcode == OP_popf)
        return true;
    return false;
}


static instr_t *
analyze_app_code(void *drcontext,
                 instrlist_t *ilist,
                 instr_t *where,
                 ref_info_t *ref_info)
{
    reg_id_t reg;
    int i;
    
    for (i = 0; i < NUM_SPILL_REGS; i++) {
        UMBRA_POS_TO_REG(reg, i);
        if (!instr_writes_to_reg(where, reg)) 
            continue;
        if (reg_update_is_limited(where, reg))
            continue;
        ref_info[i].cache = NULL;
    }
    return instr_get_next(where);
}


void
optimize_cfg_aflags(void         *drcontext, 
                    umbra_info_t  *umbra_info,
                    ilist_info_t *ilist_info,
                    basic_block_t *bb)
{
    basic_block_t *tgt;
    link_edge_t   *edge;
    bool aflags_dead = true;

    if (!BB_IS_LINKED(bb))
        return;

    for (edge   = cfg_bb_get_first_outgoing_edge(umbra_info, bb);
         edge->id != 0;
         edge  = cfg_edge_get_next_outgoing_edge(umbra_info, edge)) {
        if (EDGE_IS_IND_BRANCH(edge))
            return;
        if (edge->opcode == OP_call_fall)
            /* call fall through, not a real cfg edge */
            continue;
        tgt = cfg_get_bb(umbra_info, edge->dst_bb);
        aflags_dead = BB_IS_AFLAGS_DEAD(tgt) && aflags_dead;
    }

    if (aflags_dead == true)
        ilist_info->aflags.dead = true;
    return;
}


static bool
instr_is_reg_save(instr_t *instr, reg_id_t reg, umbra_info_t *info)
{
    opnd_t opnd;
    int    slot;

    if (instr_get_opcode(instr) != OP_mov_st)
        return false;
    opnd = instr_get_src(instr, 0);
    if (!opnd_is_reg(opnd) || opnd_get_reg(opnd) != reg)
        return false;
    slot = reg - REG_SPILL_START;
    opnd = OPND_CREATE_ABSMEM(&info->spill_regs[slot], OPSZ_PTR);
    if (opnd_same(opnd, instr_get_dst(instr, 0)))
        return true;
    return false;
}


static bool
instr_is_reg_restore(instr_t *instr, reg_id_t reg, umbra_info_t *info)
{
    opnd_t opnd;
    int    slot;

    if (instr_get_opcode(instr) != OP_mov_ld)
        return false;
    opnd = instr_get_dst(instr, 0);
    if (!opnd_is_reg(opnd) || opnd_get_reg(opnd) != reg)
        return false;
    slot = reg - REG_SPILL_START;
    opnd = OPND_CREATE_ABSMEM(&info->spill_regs[slot], OPSZ_PTR);
    if (opnd_same(opnd, instr_get_src(instr, 0)))
        return true;
    return false;
}


/* this function to optimize some register stealing code away 
 * for case like below:
 * 
 *  restore %reg
 *  ...
 *  save %reg
 *  
 *  if the %reg is not updated in between, the save %reg can be 
 * optimized out
 */
static void
optimize_register_stealing(void *drcontext, 
                           umbra_info_t *umbra_info,
                           void *tag,
                           instrlist_t *ilist)
{
    instr_t *instr, *nexti;
    instr_t *reg_restore[NUM_SPILL_REGS];
    reg_id_t regs[NUM_SPILL_REGS];
    int i;

    /* skip reg eax */
    for (i = 1; i < NUM_SPILL_REGS; i++) {
        reg_restore[i] = NULL;
        regs[i] = REG_SPILL_START + i;
    }
    
    for (instr = instrlist_first(ilist); instr != NULL; instr = nexti) {
        nexti = instr_get_next(instr);
        if (instr_get_app_pc(instr) != NULL && 
            !instr_is_meta_may_fault(instr)) {
            /* check if app code update register */
            for (i = 1; i < NUM_SPILL_REGS; i++) {
                if (register_is_updated(instr, regs[i])) 
                    reg_restore[i] = NULL;
            }
        } else {
            for (i = 1; i < NUM_SPILL_REGS; i++) {
                if (instr_is_reg_restore(instr, regs[i], umbra_info)) {
                    reg_restore[i] = instr;
                    break; 
                } else if (instr_is_reg_save(instr, regs[i], umbra_info) &&
                           reg_restore[i] != NULL) {
                    instrlist_remove(ilist, instr);
                    instr_destroy(drcontext, instr);
                    break;
                }
            }
        }
    }
}


static void
optimize_shadow_lookup(void *drcontext, umbra_info_t *umbra_info,
                       void *tag,       instrlist_t *ilist)
{
    instr_t *instr, *nexti;
    ref_info_t ref_info[NUM_SPILL_REGS];

    ref_info_init(ref_info);

    for (instr = instrlist_first(ilist); instr != NULL; instr = nexti) {
        if (instr_get_app_pc(instr) == NULL) {
            /* instrumented code */
            nexti = analyze_client_code(drcontext, 
                                        ilist, instr, ref_info);
        } else {
            /* application code */
            nexti = analyze_app_code(drcontext, 
                                     ilist, instr, ref_info);
        }
    }
}


void 
optimize_trace(void *drcontext, 
               umbra_info_t *umbra_info, 
               void *tag,
               instrlist_t *ilist)
{
    if (proc_info.options.opt_trace == false)
        return;
    /* XXX the trace optimization is fragile */
    optimize_register_stealing(drcontext, umbra_info, tag, ilist);
    optimize_shadow_lookup(drcontext, umbra_info, tag, ilist);
}



/*
 * Possible optimizations:
 * - Loop unrolling for inc like changes
 * - code placement (general)
 * - check merge
 * - context switchs reduce
 * - loop invarant
 */


