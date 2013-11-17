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
 *     Analyzer -- analyzer.h 
 *
 * Description:
 *     analyze the application code  
 *
 * Author: 
 *     Qin Zhao
 * 
 */

#ifndef _ANALYZER_H_
#define _ANALYZER_H_ 1

#include "global.h"
#include "umbra.h"

void 
analyzer_init(void);

void 
analyzer_exit(void);

void 
analyzer_thread_init(void *drcontext, umbra_info_t *info);

void 
analyzer_thread_exit(void *drcontext, umbra_info_t *info);

void
analyzer_update_bb(void *drcontext, umbra_info_t *info, basic_block_t *bb, instrlist_t *ilist);

basic_block_t *
analyzer_basic_block(void *drcontext, umbra_info_t *info, basic_block_t *bb, instrlist_t *ilist);

bool
register_is_updated(instr_t *instr, reg_id_t reg);

bool 
register_is_dead(instr_t *instr, reg_id_t reg);

bool 
register_is_used(instr_t *instr, reg_id_t reg);

bool
register_is_used_for_mem(instr_t *instr, reg_id_t reg);

/* check if instr will be mangled by DR
 * If an instr is mangled, that instr cannot be used 
 * as operand 
 */
bool 
instr_is_mangled(instr_t *instr);

/* check if instr is a rep instructions */
bool
instr_is_rep_ins(instr_t *instr);

bool 
opcode_is_rep_ins(int opcode);

#endif /* _ANALYZER_H_ */

