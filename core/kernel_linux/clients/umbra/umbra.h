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
 *     Umbra -- umbra.h
 *
 * Description:
 *     header file of Umbra module
 *
 * Author: 
 *     Qin Zhao
 * 
 */


#ifndef _UMBRA_H_
#define _UMBRA_H_ 1

#ifdef LINUX_KERNEL
# include <linux/module.h>
#endif
#include "dr_api.h"

void
umbra_init(client_id_t id);

void
umbra_exit(void);

void 
umbra_thread_init(void *drcontext);

void
umbra_thread_exit(void *drcontext);

void
umbra_fork_init(void *drcontext);

dr_emit_flags_t
umbra_basic_block(void *drcontext,
                  void *tag,
                  instrlist_t *bb,
                  bool  for_trace,
                  bool  translating);

dr_emit_flags_t
umbra_trace(void *drcontext,
            void *tag,
            instrlist_t *bb,
            bool  translating);

dr_custom_trace_action_t
umbra_end_trace(void *drcontext, 
                void *trace_tag, 
                void *next_tag);

void
umbra_delete(void *drcontext, void *tag);

void
umbra_restore_state(void *drcontext, 
                    void *tag,
                    dr_mcontext_t *mcontext,
                    bool restore_memory, 
                    bool app_code_consistent);

bool
umbra_filter_syscall(void *drcontext, int sysnum);

bool 
umbra_pre_syscall(void *drcontext, int sysnum);

void 
umbra_post_syscall(void *drcontext, int sysnum);

void
umbra_module_load(void *drcontext, 
                  const module_data_t *info, 
                  bool loaded);

void
umbra_module_unload(void *drcontext, const module_data_t *info);

#ifdef LINUX_KERNEL

bool
umbra_interrupt(void *drcontext, dr_interrupt_t *info);

int
umbra_kernel_init(void);

void
umbra_kernel_exit(void);

#elif defined(LINUX)

dr_signal_action_t
umbra_signal(void *drcontext, dr_siginfo_t *siginfo);

#else

bool
umbra_exception(void *drcontext, dr_exception_t *excpt);


#endif /* LINUX */

#endif /* _UMBRA_H_ */

/*---------------------------------------------------------------------*
 *                              End of umbra.h                         *
 *---------------------------------------------------------------------*/
