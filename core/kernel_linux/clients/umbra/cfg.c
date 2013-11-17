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
 *     CFG -- cfg.c 
 *
 * Description:
 *     contruct the control flow graph 
 *
 * Author: 
 *     Qin Zhao
 * 
 */

#include "cfg.h"
#include "table.h"
#include "analyzer.h"

#ifndef LINUX_KERNEL
#  include <string.h>
#endif

static link_edge_t *
cfg_get_edge(umbra_info_t *info, int id);

static link_edge_t *
cfg_bb_get_first_incoming_edge(umbra_info_t *info, basic_block_t *bb)
{
    return cfg_get_edge(info, bb->edge_in);
}


/*---------------------------------------------------------------------*
 *                      CFG Baisc Block Operations                     *
 *---------------------------------------------------------------------*/


static basic_block_t  *
cfg_bb_create(void *drcontext, umbra_info_t *info, app_pc tag)
{
    basic_block_t  *bb;
    
    bb           = table_alloc_bb(drcontext, info);
    bb->tag      = tag;
    bb->flags    = 0;
    bb->length   = 0;
    bb->edge_in  = 0;
    bb->edge_out = 0;
    bb->count    = 0;
    bb->num_refs = 0;
    bb->refs     = 0;
    return bb;
}


static basic_block_t *
cfg_bb_tag_lookup(umbra_info_t *info, app_pc tag)
{
    return table_bb_tag_lookup(info, tag);
}


static void
cfg_bb_add_to_hashtable(void *drcontext, umbra_info_t *info, 
                        basic_block_t *bb)
{
    table_bb_add_to_hashtable(drcontext, info, bb);
}


static void
cfg_bb_add_func_table(void *drcontext, umbra_info_t *info, basic_block_t *bb)
{
    func_t *func;
    func        = table_alloc_func(drcontext, info);
    func->entry = bb->id;
    func->pc    = bb->tag;
    BB_SET_FUNCTION_ENTRY(bb);
}

/*---------------------------------------------------------------------*
 *                         CFG Link Edge Operations                    *
 *---------------------------------------------------------------------*/


/*
 * Edge Related Functions
 */

static link_edge_t *
cfg_edge_create(void *drcontext, umbra_info_t *info)
{
    link_edge_t *edge;
    edge = table_alloc_edge(drcontext, info);
    edge->dst_tag  = NULL;
    edge->src_bb   = 0;
    edge->dst_bb   = 0;
    edge->flags    = 0;
    edge->opcode   = OP_INVALID;
    edge->next_in  = 0;
    edge->next_out = 0;
    edge->count    = 0;
    return edge;
}


static link_edge_t *
cfg_get_edge(umbra_info_t *info, int id)
{
    return table_get_edge(info, id);
}


static link_edge_t *
cfg_edge_get_next_incoming_edge(umbra_info_t *info, link_edge_t *edge)
{
    return cfg_get_edge(info, edge->next_in);
}


/*---------------------------------------------------------------------*
 *                    CFG Baisc Block Link Operation                   *
 *---------------------------------------------------------------------*/

/* link bb with edge out */
static void
cfg_link_bb_edge(basic_block_t *src_bb, link_edge_t *edge)
{
    edge->src_bb     = src_bb->id;
    edge->next_out   = src_bb->edge_out;
    src_bb->edge_out = edge->id;

    /* set edge flags based on src bb */
    /* currently nothing */
}


/* link edge in with bb */
static void
cfg_link_edge_bb(void *drcontext,   umbra_info_t   *info,
                 link_edge_t *edge, basic_block_t *dst_bb)
{
    edge->dst_bb    = dst_bb->id;
    edge->next_in   = dst_bb->edge_in;
    dst_bb->edge_in = edge->id;

    /* set dst bb flags based on edge */
    /* set target bb of call edge as func entry */
    /* XXX: the procedure-link-table entry will be marked 
     * as Function Entry too 
     */
    if(EDGE_IS_FUNCTION_CALL(edge)  && !BB_IS_FUNCTION_ENTRY(dst_bb))
        cfg_bb_add_func_table(drcontext, info, dst_bb);
}


/* lookup the target bb using tag */
static basic_block_t *
cfg_tgt_bb_lookup(void *drcontext, umbra_info_t *info, app_pc tgt_pc)
{
    basic_block_t *tgt_bb;
    tgt_bb = cfg_bb_tag_lookup(info, tgt_pc);
    if (tgt_bb == NULL) {
        tgt_bb = cfg_bb_create(drcontext, info, tgt_pc);
        cfg_bb_add_to_hashtable(drcontext, info, tgt_bb);
    }
    return tgt_bb;
}


/* link all outgoing edges */
static void
cfg_link_outgoing_edges(void          *drcontext, 
                        umbra_info_t   *info,
                        basic_block_t *bb,
                        instrlist_t   *ilist) 
{
    link_edge_t   *edge;
    basic_block_t *tgt_bb;
    instr_t *instr;
    opnd_t   target;
    app_pc   pc;

    if (BB_IS_LINKED(bb))
        return;
    BB_SET_LINKED(bb);
    
    instr = instrlist_last(ilist);

    /* for indirect branch, we link it to a ind branch edge */
    if (instr_is_mbr(instr)) {
        edge = cfg_edge_create(drcontext, info);
        EDGE_SET_IND_BRANCH(edge);
        edge->dst_bb  = 0;
        edge->dst_tag = 0;
        edge->opcode  = instr_get_opcode(instr);
        cfg_link_bb_edge(bb, edge);
        return;
    }

    /* for non-cti, call, and condition branch, 
     * link fall through bb
     */
    if (!instr_is_cti(instr) ||
        instr_is_call(instr) || 
        instr_is_cbr(instr)) {
        /* fall through branch */
        pc   = bb->tag + bb->length;
        edge = cfg_edge_create(drcontext, info);
        if (instr_is_call(instr))
            edge->opcode = OP_call_fall;
        else
            edge->opcode = OP_cbr_fall;
        cfg_link_bb_edge(bb, edge);
        tgt_bb = cfg_tgt_bb_lookup(drcontext, info, pc);
        edge->dst_bb  = tgt_bb->id;
        edge->dst_tag = pc;
        cfg_link_edge_bb(drcontext, info, edge, tgt_bb);
    }

    /* link target bb */
    if (instr_is_cti(instr) && !instr_is_mbr(instr)) {
        target = instr_get_target(instr);
        pc     = opnd_get_pc(target);
        edge   = cfg_edge_create(drcontext, info);
        edge->opcode = instr_get_opcode(instr);
        if (instr_is_call(instr)) {
            EDGE_SET_FUNCTION_CALL(edge);
        }
        cfg_link_bb_edge(bb, edge);
        tgt_bb = cfg_tgt_bb_lookup(drcontext, info, pc);
        edge->dst_bb  = tgt_bb->id;
        edge->dst_tag = pc;
        cfg_link_edge_bb(drcontext, info, edge, tgt_bb);
    }
}


static void
cfg_link_incoming_edges(void          *drcontext, 
                        umbra_info_t   *info,
                        basic_block_t *bb)
{
    /* do nothing as it is linked via link outgoing edges */
}


static void
cfg_bb_link(void          *drcontext, 
            umbra_info_t   *info, 
            basic_block_t *bb, 
            instrlist_t   *ilist)
{
    cfg_link_incoming_edges(drcontext, info, bb);
    cfg_link_outgoing_edges(drcontext, info, bb, ilist);
}


/*---------------------------------------------------------------------*
 *                 CFG Baisc Block Instr List Operation                *
 *---------------------------------------------------------------------*/

/* trim ilist for purpose */
static int 
cfg_bb_trim_ilist(void        *drcontext,
                  umbra_info_t *info,
                  app_pc       tag,
                  instrlist_t *ilist)
{
    instr_t *instr;
    app_pc   pc;
    int      length = 0;

    for(instr  = instrlist_first(ilist); 
        instr != NULL;
        instr  = instr_get_next(instr)) {
        pc = instr_get_app_pc(instr);
        if (pc == NULL)
            continue;
        #if 0
        /* Assertion no longer valid with app-to-app transformations for repstr.
         */
        DR_ASSERT_MSG((tag + length) == instr_get_app_pc(instr), 
                      "BB does not have a continuous code!");
        #endif
        length += instr_length(drcontext, instr);
    }

    return length;
}


/*---------------------------------------------------------------------*
 *                           CFG Print Routines                        *
 *---------------------------------------------------------------------*/

/* print cfg edge */
static void
cfg_edge_print_out(umbra_info_t *info, link_edge_t *edge)
{
    return;
    dr_fprintf(info->log, "\t%d:%d[%p]->%d[%p]", 
               edge->opcode,
               edge->src_bb, cfg_get_bb(info, edge->src_bb)->tag,
               edge->dst_bb, edge->dst_tag);
}


/* print cfg bb */
static void
cfg_bb_print_out(umbra_info_t *info, basic_block_t  *bb)
{
    link_edge_t *edge;

    return;
    dr_fprintf(info->log, "BB[%d]\t%p", bb->id, bb->tag);
    if(BB_IS_FUNCTION_ENTRY(bb))
        dr_fprintf(info->log, "\tFunction");
#ifdef LINUX_GOT_DISPATCH
    if(BB_IS_GOT_DISPATCH(bb))
        dr_fprintf(info->log, "\t GOT Dispatch");
#endif
    dr_fprintf(info->log, "\n\tIncoming:");
    for (edge      = cfg_bb_get_first_incoming_edge(info, bb);
         edge->id != 0;
         edge      = cfg_edge_get_next_incoming_edge(info, edge))
        cfg_edge_print_out(info, edge);
    dr_fprintf(info->log, "\n\tOutgoing:");
    for (edge      = cfg_bb_get_first_outgoing_edge(info, bb);
         edge->id != 0;
         edge      = cfg_edge_get_next_outgoing_edge(info, edge))
        cfg_edge_print_out(info, edge);
    dr_fprintf(info->log, "\n");
}



/*---------------------------------------------------------------------*
 *                 Exported Function Implementation                    *
 *---------------------------------------------------------------------*/

void 
cfg_thread_init(void *drcontext, umbra_info_t *info)
{
    /* do nothing */
}


void 
cfg_thread_exit(void *drcontext, umbra_info_t *info)
{
    int         num_bbs, i;

    num_bbs  = info->table.num_bbs;
    for (i = 1; i < num_bbs; i++) {
        cfg_bb_print_out(info, cfg_get_bb(info, i));
    }
}


basic_block_t *
cfg_basic_block(void *drcontext, umbra_info_t *info, 
                app_pc tag,      instrlist_t *ilist)
{
    basic_block_t *bb;
    int length;

    length = cfg_bb_trim_ilist(drcontext, info, tag, ilist);
    bb = cfg_bb_tag_lookup(info, tag);
    if (bb == NULL) {
        bb = cfg_bb_create(drcontext, info, tag);
        cfg_bb_add_to_hashtable(drcontext, info, bb);
    }

    if (bb->bytes != NULL && bb->length == length &&
        memcmp(bb->bytes, tag, length) == 0) {
        /* an old analyzed bb, it need update instr for every ref */
        analyzer_update_bb(drcontext, info, bb, ilist);
        return bb;
    }

    bb->length = length;
    bb->bytes  = table_alloc_bytes(info, length);
    memcpy(bb->bytes, tag, length);

    /* analyze this basic block */
    bb = analyzer_basic_block(drcontext, info, bb, ilist);
    /* link bb into cfg */
    cfg_bb_link(drcontext, info, bb, ilist);
    
    return bb;
}


link_edge_t *
cfg_bb_get_first_outgoing_edge(umbra_info_t *info, basic_block_t  *bb)
{
    return cfg_get_edge(info, bb->edge_out);
}


link_edge_t *
cfg_edge_get_next_outgoing_edge(umbra_info_t *info, link_edge_t *edge)
{
    return cfg_get_edge(info, edge->next_out);
}


basic_block_t *
cfg_get_bb(umbra_info_t *info, int id)
{
    return table_get_bb(info, id);
}
