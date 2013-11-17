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
 *     CFG -- cfg.h
 *
 * Description:
 *     contruct the control flow graph 
 *
 * Author: 
 *     Qin Zhao
 * 
 */

#ifndef _CFG_H_
#define _CFG_H_ 1

#include "global.h"
#include "umbra.h"


void 
cfg_thread_init(void *drcontext, umbra_info_t *info);

void
cfg_thread_exit(void *drcontext, umbra_info_t *info);

basic_block_t *
cfg_basic_block(void *drcontext, umbra_info_t *info, app_pc tag, instrlist_t *ilist);

link_edge_t *
cfg_bb_get_first_outgoing_edge(umbra_info_t *info, basic_block_t  *bb);

link_edge_t *
cfg_edge_get_next_outgoing_edge(umbra_info_t *info, link_edge_t *edge);

basic_block_t *
cfg_get_bb(umbra_info_t *info, int id);


#define BB_PLACE_HOLD        0x1
#define BB_AFLAGS_DEAD       0x2
#define BB_XBP_FP            0x4
#define BB_FUNCTION_ENTRY    0x8
#define BB_LINKED            0x10
#define BB_XBP_OTHER         0x20

#define BB_SET_PLACE_HOLD(bb)     ((bb)->flags |= BB_PLACE_HOLD)
#define BB_SET_AFLAGS_DEAD(bb)    ((bb)->flags |= BB_AFLAGS_DEAD)
#define BB_SET_XBP_FP(bb)         ((bb)->flags |= BB_XBP_FP)
#define BB_SET_FUNCTION_ENTRY(bb) ((bb)->flags |= BB_FUNCTION_ENTRY)
#define BB_SET_LINKED(bb)         ((bb)->flags |= BB_LINKED)
#define BB_SET_XBP_OTHER(bb)      ((bb)->flags |= BB_XBP_OTHER)

#define BB_UNSET_PLACE_HOLD(bb)     ((bb)->flags &= ~BB_PLACE_HOLD)
#define BB_UNSET_AFLAGS_DEAD(bb)    ((bb)->flags &= ~BB_AFLAGS_DEAD)
#define BB_UNSET_XBP_FP(bb)         ((bb)->flags &= ~BB_XBP_FP)
#define BB_UNSET_FUNCTION_ENTRY(bb) ((bb)->flags &= ~BB_FUNCTION_ENTRY)
#define BB_UNSET_LINKED(bb)         ((bb)->flags &= ~BB_LINKED)
#define BB_UNSET_XBP_OTHER(bb)      ((bb)->flags &= ~BB_XBP_OTHER)

#define BB_IS_PLACE_HOLD(bb)      (((bb)->flags & BB_PLACE_HOLD)     == BB_PLACE_HOLD)
#define BB_IS_AFLAGS_DEAD(bb)     (((bb)->flags & BB_AFLAGS_DEAD)    == BB_AFLAGS_DEAD)
#define BB_IS_XBP_FP(bb)          (((bb)->flags & BB_XBP_FP)         == BB_XBP_FP)
#define BB_IS_FUNCTION_ENTRY(bb)  (((bb)->flags & BB_FUNCTION_ENTRY) == BB_FUNCTION_ENTRY)
#define BB_IS_LINKED(bb)          (((bb)->flags & BB_LINKED)         == BB_LINKED)
#define BB_IS_XBP_OTHER(bb)       (((bb)->flags & BB_XBP_OTHER)      == BB_XBP_OTHER)

/* 
#define BB_SELF_MODIFIED     0x1

#define BB_GOT_DISPATCH      0x4
#define BB_REPLACE_INSTR     0x10
#define BB_EBP_OTHER         0x80

#define BB_SET_SELF_MODIFIED(bb)  ((bb)->flags |= BB_SELF_MODIFIED)
#define BB_SET_GOT_DISPATCH(bb)   ((bb)->flags |= BB_GOT_DISPATCH)
#define BB_SET_REPLACE_INSTR(bb)  ((bb)->flags |= BB_REPLACE_INSTR)
#define BB_SET_EBP_OTHER(bb)      ((bb)->flags |= BB_EBP_OTHER)

#define BB_UNSET_SELF_MODIFIED(bb)  ((bb)->flags &= ~BB_SELF_MODIFIED)
#define BB_UNSET_GOT_DISPATHC(bb)   ((bb)->flags &= ~BB_GOT_DISPATCH)
#define BB_UNSET_REPLACE_INSTR(bb)  ((bb)->flags &= ~BB_REPLACE_INSTR)
#define BB_UNSET_EBP_OTHER(bb)      ((bb)->flags &= ~BB_EBP_OTHER)

#define BB_IS_SELF_MODIFED(bb)    (((bb)->flags & BB_SELF_MODIFIED)  != 0)
#define BB_IS_GOT_DISPATCH(bb)    (((bb)->flags & BB_GOT_DISPATCH)   != 0)
#define BB_IS_REPLACE_INSTR(bb)   (((bb)->flags & BB_REPLACE_INSTR)  != 0)
#define BB_IS_EBP_OTHER(bb)       (((bb)->flags & BB_EBP_OTHER)      != 0)
*/

#define EDGE_FUNCTION_CALL    0x1
#define EDGE_GOT_BRANCH_OUT   0x2
#define EDGE_GOT_BRANCH_IN    0x4
#define EDGE_XBP_FP           0x8
#define EDGE_FUNCTION_RET     0x10
#define EDGE_XBP_OTHER        0x20
#define EDGE_IND_BRANCH       0x40

#define EDGE_SET_FUNCTION_CALL(edge)  ((edge)->flags |= EDGE_FUNCTION_CALL)
#define EDGE_SET_GOT_BRANCH_OUT(edge) ((edge)->flags |= EDGE_GOT_BRANCH_OUT)
#define EDGE_SET_GOT_BRANCH_IN(edge)  ((edge)->flags |= EDGE_GOT_BRANCH_IN)
#define EDGE_SET_XBP_FP(edge)         ((edge)->flags |= EDGE_XBP_FP)
#define EDGE_SET_FUNCTION_RET(edge)   ((edge)->flags |= EDGE_FUNCTION_RET)
#define EDGE_SET_IND_BRANCH(edge)     ((edge)->flags |= EDGE_IND_BRANCH)

#define EDGE_UNSET_FUNCTION_CALL(edge)  ((edge)->flags &= ~EDGE_FUNCTION_CALL)
#define EDGE_UNSET_GOT_BRANCH_OUT(edge) ((edge)->flags &= ~EDGE_GOT_BRANCH_OUT)
#define EDGE_UNSET_GOT_BRANCH_IN(edge)  ((edge)->flags &= ~EDGE_GOT_BRANCH_IN)
#define EDGE_UNSET_XBP_FP(edge)         ((edge)->flags &= ~EDGE_XBP_FP)
#define EDGE_UNSET_FUNCTION_RET(edge)   ((edge)->flags &= ~EDGE_FUNCTION_RET)
#define EDGE_UNSET_IND_BRANCH(edge)     ((edge)->flags &= ~EDGE_IND_BRANCH)

#define EDGE_IS_FUNCTION_CALL(edge)  (((edge)->flags & EDGE_FUNCTION_CALL)  != 0)
#define EDGE_IS_GOT_BRANCH_OUT(edge) (((edge)->flags & EDGE_GOT_BRANCH_OUT) != 0)
#define EDGE_IS_GOT_BRANCH_IN(edge)  (((edge)->flags & EDGE_GOT_BRANCH_IN)  != 0)
#define EDGE_IS_XBP_FP(edge)         (((edge)->flags & EDGE_XBP_FP)         != 0)
#define EDGE_IS_FUNCTION_RET(edge)   (((edge)->flags & EDGE_FUNCTION_RET)   != 0)
#define EDGE_IS_IND_BRANCH(edge)     (((edge)->flags & EDGE_IND_BRANCH)     != 0)


#endif  /* _CFG_H_ */
