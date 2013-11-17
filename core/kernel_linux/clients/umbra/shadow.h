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
 *     Shadow Memory Manager - shadow.h
 *
 * Description:
 *     Manage shadow memory allocation and free.
 *
 * Author: 
 *     Qin Zhao
 *
 */

#ifndef _SHADOW_H_
#define _SHADOW_H_

#include "global.h"
#include "umbra.h"

void
shadow_init(void);

void
shadow_exit(void);

void 
shadow_thread_init(void *drcontext, umbra_info_t *info);

void 
shadow_thread_exit(void *drcontext, umbra_info_t *info);

void
shadow_maps_free_update(void *drcontext, 
                        umbra_info_t *info,
                        byte *addr);

void
shadow_maps_alloc_update(void *drcontext,
                         umbra_info_t *info,
                         byte *addr,
                         size_t size);

void
shadow_memory_map_lookup(void);

void 
shadow_pre_syscall(void *drcontext, umbra_info_t *info, int sysnum);

void 
shadow_post_syscall(void *drcontext, umbra_info_t *info, int sysnum);

void
shadow_module_load(void *drcontext, 
                   umbra_info_t *umbra_info,
                   const module_data_t *module_info, 
                   bool loaded);

void
shadow_module_unload(void *drcontext, umbra_info_t *umbra_info,
                     const module_data_t *module_info);

void
compute_shd_memory_size(reg_t app_size, reg_t shd_size[MAX_NUM_SHADOWS]);

bool
compute_shd_memory_addr(void *app_addr, void *shd_addr[MAX_NUM_SHADOWS]);

void
compute_shd_memory_addr_ex(memory_map_t *map,
                           void *app_addr, void *shd_addr[MAX_NUM_SHADOWS]);

memory_map_t *
memory_map_app_lookup(memory_map_t *map, void *start);

#ifndef LINUX_KERNEL
memory_mod_t *
memory_mod_app_lookup(void *addr);

bool
memory_mod_app_add(void *addr, reg_t size);
#endif

memory_map_t *
memory_map_thread_lazy_add(umbra_info_t *info, void *addr);

memory_map_t *
memory_map_app_lazy_add(void *addr);

#ifdef LINUX_KERNEL
bool
shadow_interrupt(umbra_info_t *umbra_info, dr_interrupt_t *interrupt);

int
shadow_kernel_init(void);

void
shadow_kernel_exit(void);
#elif defined(LINUX)
dr_signal_action_t
shadow_signal(void         *drcontext, 
              umbra_info_t *umbra_info, 
              dr_siginfo_t *siginfo);
#else
bool
shadow_exception(void           *drcontext, 
                 umbra_info_t   *umbra_info, 
                 dr_exception_t *excpt);
#endif /* LINUX */

#endif  /* _SHADOW_H_ */

