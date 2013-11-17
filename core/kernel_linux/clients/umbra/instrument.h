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
 *     Instrumentor -- instrument.h
 *
 * Description:
 *     Perform instrumentation for umbra  
 *
 * Author: 
 *     Qin Zhao
 */

#ifndef _INSTRUMENT_H_
#define _INSTRUMENT_H_ 1

#include "dr_api.h"
#include "umbra.h"
#include "global.h"

#include "cfg.h"
#include "utils.h"
#include "analyzer.h"


void
instrument_thread_init(void *drcontext, umbra_info_t *info);

void
instrument_thread_exit(void *drcontext, umbra_info_t *info);

void 
instrument_basic_block(void *drcontext, 
                       umbra_info_t *info,
                       basic_block_t *bb,
                       instrlist_t *ilist,
                       bool  for_trace);







/*
 * Runtime function
 */
void 
umbra_at_jmp_ind(void *drcontext, umbra_info_t *info, basic_block_t *src_bb,
                app_pc src_pc,   app_pc target);

void
umbra_at_call_ind(void *drcontext, umbra_info_t *info, basic_block_t *src_bb,
                 app_pc src_pc,  app_pc target);

void
umbra_at_ret(void *drcontext, umbra_info_t *info, basic_block_t *src_bb,
            app_pc src_pc,   app_pc target);


void
umbra_breakpoint(void);


/*
 * Instrumentation related function
 */
void 
instrument_init(void);

void 
instrument_exit(void);

void 
instrument_thread_init(void *drcontext, umbra_info_t *info);

void 
instrument_thread_exit(void *drcontext, umbra_info_t *info);


bool
instr_to_be_replaced(instr_t *instr);

void
dr_save_aflags_from_eax(void *, umbra_info_t *, instrlist_t *, instr_t *);

void
dr_restore_aflags_to_eax(void *, umbra_info_t *, instrlist_t *, instr_t *where);


#ifdef LINUX_KERNEL
bool
instrument_interrupt(umbra_info_t *umbra_info, dr_interrupt_t *interrupt);
#endif

#endif // INSTRUMENT_H
