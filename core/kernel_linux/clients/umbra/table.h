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
 *     Table -- table.h
 *
 * Description:
 *     Manage internal data sturcture.
 *
 * Author: 
 *     Qin Zhao
 *
 */

#ifndef _TABLE_H_
#define _TABLE_H_ 1

#include "global.h"
#include "umbra.h"

#define INIT_BB_TABLE_SIZE      8192
#define INIT_EDGE_TABLE_SIZE    (INIT_BB_TABLE_SIZE * 2)
#define INIT_REF_TABLE_SIZE     INIT_EDGE_TABLE_SIZE
#define INIT_FUNC_TABLE_SIZE    1024
#define INIT_REF_CACHE_SIZE     INIT_REF_TABLE_SIZE
#define INIT_HASH_TABLE_SIZE    4096
#define MAX_BYTES_TABLE_SIZE    (1 << 20)

#define CODE_HASH_FUNC(val, mask) ((val) & (mask))

void 
table_init(void);

void 
table_exit(void);

void 
table_thread_init(void *drcontext, umbra_info_t *info);

void 
table_thread_exit(void *drcontext, umbra_info_t *info);

basic_block_t *
table_alloc_bb(void *drcontext, umbra_info_t *info);

link_edge_t *
table_alloc_edge(void *drcontext, umbra_info_t *info);

mem_ref_t *
table_alloc_ref(void *drcontext, umbra_info_t *info);

func_t *
table_alloc_func(void *drcontext, umbra_info_t *info);

ref_cache_t *
table_alloc_ref_cache(void *drcontext, umbra_info_t *info);

app_pc
table_alloc_bytes(umbra_info_t *info, int size);

basic_block_t *
table_get_bb(umbra_info_t *info, int id);

mem_ref_t *
table_get_ref(umbra_info_t *info, int id);

func_t *
table_get_func(umbra_info_t *info, int id);

basic_block_t *
table_bb_tag_lookup(umbra_info_t *info, app_pc tag);

void 
table_bb_add_to_hashtable(void *drcontext, umbra_info_t *info, basic_block_t *bb);

link_edge_t *
table_get_edge(umbra_info_t *info, int id);

void
table_edge_add_to_hashtable(void *drcontext, umbra_info_t *info, link_edge_t *edge);

link_edge_t *
table_edge_lookup_remove(void *drcontext, umbra_info_t *info, app_pc tag);

bool
addr_in_ref_cache(umbra_info_t *info, void *addr);

#endif  /* _TABLE_H_ */

