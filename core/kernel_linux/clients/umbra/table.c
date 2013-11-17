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
 *     Table -- table.c
 *
 * Description:
 *     Manage internal data sturcture.
 *
 * Author: 
 *     Qin Zhao
 *
 */

#include "umbra.h"
#include "table.h"
#ifndef LINUX_KERNEL
# include <string.h>
#endif

/* 
 * Golbal Functions Implementation
 */


/*---------------------------------------------------------------------*
 *                   Table Initialization Routines                     *
 *---------------------------------------------------------------------*/

static void
init_bb_table(void *drcontext, umbra_info_t *info)
{
    info->table.num_bbs     = 1;
    info->table.max_num_bbs = INIT_BB_TABLE_SIZE;
    info->table.bb_table    = 
        dr_thread_alloc(drcontext,  
                        INIT_BB_TABLE_SIZE * sizeof(basic_block_t));
    info->num_table_bb += INIT_BB_TABLE_SIZE * sizeof(basic_block_t);
    memset(info->table.bb_table, 0, 
           INIT_BB_TABLE_SIZE * sizeof(basic_block_t));
}


static void
init_edge_table(void *drcontext, umbra_info_t *info)
{
    info->table.num_edges     = 1;
    info->table.max_num_edges = INIT_EDGE_TABLE_SIZE;
    info->table.edge_table    = 
        dr_thread_alloc(drcontext,
                        INIT_EDGE_TABLE_SIZE * sizeof(link_edge_t));
    info->num_table_edge += INIT_EDGE_TABLE_SIZE * sizeof(link_edge_t);
    memset(info->table.edge_table, 0, 
           INIT_EDGE_TABLE_SIZE * sizeof(link_edge_t));
}


static void
init_ref_table(void *drcontext, umbra_info_t *info)
{
    info->table.num_refs     = 1;
    info->table.max_num_refs = INIT_REF_TABLE_SIZE;
    info->table.ref_table    = 
        dr_thread_alloc(drcontext,   
                        INIT_REF_TABLE_SIZE * sizeof(mem_ref_t));
    info->num_table_ref += INIT_REF_TABLE_SIZE * sizeof(mem_ref_t);
    memset(info->table.ref_table, 0, 
           INIT_REF_TABLE_SIZE * sizeof(mem_ref_t));
}


static void
init_func_table(void *drcontext, umbra_info_t *info)
{
    info->table.num_funcs     = 1;
    info->table.max_num_funcs = INIT_FUNC_TABLE_SIZE;
    info->table.func_table    = 
        dr_thread_alloc(drcontext,    
                        INIT_FUNC_TABLE_SIZE * sizeof(func_t));
    info->num_table_func += INIT_FUNC_TABLE_SIZE * sizeof(func_t);
    memset(info->table.func_table, 0, 
           INIT_FUNC_TABLE_SIZE * sizeof(func_t));
}


static void
init_ref_cache_table(void *drcontext, umbra_info_t *info)
{
    info->table.num_ref_cache     = 1;
    info->table.max_num_ref_cache = INIT_REF_CACHE_SIZE;
    info->table.ref_cache_table   = 
        dr_thread_alloc(drcontext,   
                        INIT_REF_CACHE_SIZE * sizeof(ref_cache_t));
    info->num_table_ref_cache +=  INIT_REF_CACHE_SIZE * sizeof(ref_cache_t);
    memset(info->table.ref_table, 0, 
           INIT_REF_CACHE_SIZE * sizeof(ref_cache_t));
}


static void
init_code_hash(void *drcontext, umbra_info_t *info)
{
    info->table.code_hash_size  = INIT_HASH_TABLE_SIZE;
    info->table.code_hash_mask  = (INIT_HASH_TABLE_SIZE - 1);
    info->table.code_hash_table = 
        dr_thread_alloc(drcontext, 
                        INIT_HASH_TABLE_SIZE * sizeof(code_hash_t *));
    info->num_table_code_hash +=  INIT_HASH_TABLE_SIZE * sizeof(code_hash_t*);
    memset(info->table.code_hash_table, 0, 
           INIT_HASH_TABLE_SIZE * sizeof(code_hash_t *));
}


static void
init_bytes_table(void *drcontext, umbra_info_t *info)
{
    info->table.bytes_size = MAX_BYTES_TABLE_SIZE;
    info->table.max_bytes_size = MAX_BYTES_TABLE_SIZE;
    info->table.bytes_table = 
        dr_thread_alloc(drcontext,
                        MAX_BYTES_TABLE_SIZE);
    info->num_table_bytes +=  MAX_BYTES_TABLE_SIZE;
    info->table.bytes_ptr = info->table.bytes_table;
}


/*---------------------------------------------------------------------*
 *                    Table Finalization Routines                      *
 *---------------------------------------------------------------------*/


static void
fini_bb_table(void *drcontext, umbra_info_t *info)
{
    basic_block_t *bb_table, *next_table;

    for (bb_table  = info->table.bb_table;
         info->table.max_num_bbs > 0;
         info->table.max_num_bbs -= INIT_BB_TABLE_SIZE) {
        next_table = (basic_block_t *)
            bb_table[INIT_BB_TABLE_SIZE - 1].tag;
        dr_thread_free(drcontext, bb_table, 
                       INIT_BB_TABLE_SIZE * sizeof(basic_block_t));
        bb_table   = next_table;
    }
}


static void
fini_edge_table(void *drcontext, umbra_info_t *info)
{
    link_edge_t   *edge_table, *next_table;
    
    for(edge_table = info->table.edge_table;
        info->table.max_num_edges > 0;
        info->table.max_num_edges -= INIT_EDGE_TABLE_SIZE) {
        next_table = (link_edge_t *)
            edge_table[INIT_EDGE_TABLE_SIZE - 1].dst_tag;
        dr_thread_free(drcontext, edge_table,
                       INIT_EDGE_TABLE_SIZE * sizeof(link_edge_t));
        edge_table = next_table;
    }
}


static void
fini_ref_table(void *drcontext, umbra_info_t *info)
{
    mem_ref_t *ref_table, *next_table;
    
    for(ref_table = info->table.ref_table;
        info->table.max_num_refs > 0;
        info->table.max_num_refs -= INIT_REF_TABLE_SIZE) {
        next_table = (mem_ref_t *)
            ref_table[INIT_REF_TABLE_SIZE - 1].pc;
        dr_thread_free(drcontext, ref_table,
                       INIT_REF_TABLE_SIZE * sizeof(mem_ref_t));
        ref_table = next_table;
    }
}


static void
fini_func_table(void *drcontext, umbra_info_t *info)
{
    func_t *func_table, *next_table;
    
    for(func_table = info->table.func_table;
        info->table.max_num_funcs > 0;
        info->table.max_num_funcs -= INIT_FUNC_TABLE_SIZE) {
        next_table = (func_t *)
            func_table[INIT_FUNC_TABLE_SIZE - 1].pc;
        dr_thread_free(drcontext, func_table,
                       INIT_FUNC_TABLE_SIZE * sizeof(func_t));
        func_table = next_table;
    }    
}


static void
fini_ref_cache_table(void *drcontext, umbra_info_t *info)
{
    ref_cache_t *ref_table, *next_table;
    
    for(ref_table = info->table.ref_cache_table;
        info->table.max_num_ref_cache > 0;
        info->table.max_num_ref_cache -= INIT_REF_CACHE_SIZE) {
        next_table = (ref_cache_t *)
            ref_table[INIT_REF_TABLE_SIZE - 1].offset[0];
        dr_thread_free(drcontext, ref_table,
                       INIT_REF_CACHE_SIZE * sizeof(ref_cache_t));
        ref_table = next_table;
    }
}



static void
fini_code_hash(void *drcontext, umbra_info_t *info)
{
    code_hash_t *code, **hash_table;
    int i = 0;

    /* free all code entry */
    hash_table = info->table.code_hash_table;
    for (i = 0; i < info->table.code_hash_size; i++) {
        code = hash_table[i];
        while (code != NULL) {
            hash_table[i] = code->next;
            dr_thread_free(drcontext, code, sizeof(code_hash_t));
            code = hash_table[i];
        }
    }
    /* free code hash table */
    dr_thread_free(drcontext,
                   info->table.code_hash_table,
                   info->table.code_hash_size * sizeof(code_hash_t *));
}


static void
fini_bytes_table(void *drcontext, umbra_info_t *info)
{
    dr_thread_free(drcontext,
                   info->table.bytes_table,
                   MAX_BYTES_TABLE_SIZE);
}
/*---------------------------------------------------------------------*
 *                 Exported Function Implementation                    *
 *---------------------------------------------------------------------*/
void
table_thread_init(void *drcontext, umbra_info_t *info)
{
    init_bb_table(drcontext, info);
    init_edge_table(drcontext, info);
    init_ref_table(drcontext, info);
    init_func_table(drcontext, info);
    init_ref_cache_table(drcontext, info);
    init_code_hash(drcontext, info);
    init_bytes_table(drcontext, info);
}


void
table_thread_exit(void *drcontext, umbra_info_t *info)
{
    fini_bb_table(drcontext, info);
    fini_edge_table(drcontext, info);
    fini_ref_table(drcontext, info);
    fini_func_table(drcontext, info);
    fini_ref_cache_table(drcontext, info);
    fini_code_hash(drcontext, info);
    fini_bytes_table(drcontext, info);
}


basic_block_t *
table_alloc_bb(void *drcontext, umbra_info_t *info)
{
    int i, num_bbs;
    basic_block_t *bb_table;
    basic_block_t *bb;

    num_bbs  = info->table.num_bbs++;
    bb_table = info->table.bb_table;

    for (i = 1; true; i++) {
        if (num_bbs < (i * INIT_BB_TABLE_SIZE))
            break;
        bb_table = (basic_block_t *)
            bb_table[INIT_BB_TABLE_SIZE - 1].tag;
    }

    if((num_bbs % INIT_BB_TABLE_SIZE) == (INIT_BB_TABLE_SIZE - 1)) {
        bb_table[INIT_BB_TABLE_SIZE - 1].id  = num_bbs;
        bb_table[INIT_BB_TABLE_SIZE - 1].tag = (app_pc)
            dr_thread_alloc(drcontext,  
                            INIT_BB_TABLE_SIZE * sizeof(basic_block_t));
        info->num_table_bb += INIT_BB_TABLE_SIZE * sizeof(basic_block_t);
        ++info->table.num_bbs;
        ++num_bbs;
        info->table.max_num_bbs += INIT_BB_TABLE_SIZE;
        bb_table = (basic_block_t *)bb_table[INIT_BB_TABLE_SIZE - 1].tag;
        memset(bb_table, 0, INIT_BB_TABLE_SIZE * sizeof(basic_block_t));
    }

    bb = &bb_table[num_bbs % INIT_BB_TABLE_SIZE];
    bb->id = num_bbs;
    return bb;
}


link_edge_t *
table_alloc_edge(void *drcontext, umbra_info_t *info)
{
    int i, num_edges;
    link_edge_t *edge_table;
    link_edge_t *edge;

    num_edges     = info->table.num_edges++;
    edge_table    = info->table.edge_table;

    for(i = 1; true; i++) {
        if(num_edges < (i * INIT_EDGE_TABLE_SIZE))
            break;
        edge_table = (link_edge_t *)edge_table[INIT_EDGE_TABLE_SIZE - 1].dst_tag;
    }

    if((num_edges % INIT_EDGE_TABLE_SIZE) == (INIT_EDGE_TABLE_SIZE - 1)) {
        edge_table[INIT_EDGE_TABLE_SIZE - 1].id  = num_edges;
        edge_table[INIT_EDGE_TABLE_SIZE - 1].dst_tag = (app_pc)
            dr_thread_alloc(drcontext, INIT_EDGE_TABLE_SIZE * sizeof(link_edge_t));
        info->num_table_edge += INIT_EDGE_TABLE_SIZE * sizeof(link_edge_t);
        ++num_edges;
        ++info->table.num_edges;
        info->table.max_num_edges += INIT_EDGE_TABLE_SIZE;
        edge_table = (link_edge_t *)edge_table[INIT_EDGE_TABLE_SIZE - 1].dst_tag;
        memset(edge_table, 0, INIT_EDGE_TABLE_SIZE * sizeof(link_edge_t));
    }
    
    edge     = &edge_table[num_edges % INIT_EDGE_TABLE_SIZE];
    edge->id = num_edges;
    return edge;
}


mem_ref_t *
table_alloc_ref(void *drcontext, umbra_info_t *info)
{
    int i, num_refs;
    mem_ref_t *ref_table;
    mem_ref_t *ref;

    num_refs     = info->table.num_refs++;
    ref_table    = info->table.ref_table;
    
    for(i = 1; true; i++) {
        if(num_refs < (i * INIT_REF_TABLE_SIZE))
            break;
        ref_table = (mem_ref_t *)ref_table[INIT_REF_TABLE_SIZE - 1].pc;
    }

    if((num_refs % INIT_REF_TABLE_SIZE) == (INIT_REF_TABLE_SIZE - 1)) {
        ref_table[INIT_REF_TABLE_SIZE - 1].id = num_refs;
        ref_table[INIT_REF_TABLE_SIZE - 1].pc = (app_pc)
            dr_thread_alloc(drcontext, INIT_REF_TABLE_SIZE * sizeof(mem_ref_t));
        info->num_table_ref +=  INIT_REF_TABLE_SIZE * sizeof(mem_ref_t);
        info->table.num_refs++;
        num_refs++;
        info->table.max_num_refs += INIT_REF_TABLE_SIZE;
        ref_table = (mem_ref_t *)ref_table[INIT_REF_TABLE_SIZE - 1].pc;
        memset(ref_table, 0, INIT_REF_TABLE_SIZE * sizeof(mem_ref_t));
    }
    
    ref     = &ref_table[num_refs % INIT_REF_TABLE_SIZE];
    ref->id = num_refs;
    ref->count = 0;
    if (proc_info.options.stat == true) {
        info->num_app_refs++;
    }
    return ref;
}


func_t *
table_alloc_func(void *drcontext, umbra_info_t *info)
{
    int i, num_funcs;
    func_t *func_table;
    func_t *func;

    num_funcs  = info->table.num_funcs++;
    func_table = info->table.func_table;

    for(i = 1; true; i++) {
        if(num_funcs < (i * INIT_FUNC_TABLE_SIZE))
            break;
        func_table = (func_t *)func_table[INIT_FUNC_TABLE_SIZE - 1].pc;
    }

    if((num_funcs % INIT_FUNC_TABLE_SIZE) == (INIT_FUNC_TABLE_SIZE - 1)) {
        func_table[INIT_FUNC_TABLE_SIZE - 1].id = num_funcs;
        func_table[INIT_FUNC_TABLE_SIZE - 1].pc = (app_pc)
            dr_thread_alloc(drcontext, INIT_FUNC_TABLE_SIZE * sizeof(func_t));
        info->num_table_func += INIT_FUNC_TABLE_SIZE * sizeof(func_t);
        ++info->table.num_funcs;
        ++num_funcs;
        info->table.max_num_funcs += INIT_FUNC_TABLE_SIZE;
        func_table = (func_t *)func_table[INIT_FUNC_TABLE_SIZE - 1].pc;
        memset(func_table, 0, INIT_FUNC_TABLE_SIZE * sizeof(func_t));
    }
    
    func     = &func_table[num_funcs % INIT_FUNC_TABLE_SIZE];
    func->id = num_funcs;
    return func;
}


ref_cache_t *
table_alloc_ref_cache(void *drcontext, umbra_info_t *info)
{
    int i, num_refs;
    ref_cache_t *ref_table;
    ref_cache_t *ref;

    num_refs  = info->table.num_ref_cache++;
    ref_table = info->table.ref_cache_table;
    
    for(i = 1; true; i++) {
        if(num_refs < (i * INIT_REF_CACHE_SIZE))
            break;
        ref_table = (ref_cache_t *)ref_table[INIT_REF_CACHE_SIZE - 1].offset[0];
    }

    if((num_refs % INIT_REF_CACHE_SIZE) == (INIT_REF_CACHE_SIZE - 1)) {
        ref_table[INIT_REF_CACHE_SIZE - 1].offset[0] = (reg_t)
            dr_thread_alloc(drcontext, INIT_REF_CACHE_SIZE * sizeof(ref_cache_t));
        info->num_table_ref_cache +=  INIT_REF_CACHE_SIZE * sizeof(ref_cache_t);
        ++info->table.num_ref_cache;
        ++num_refs;
        info->table.max_num_ref_cache += INIT_REF_CACHE_SIZE;
        ref_table = (ref_cache_t *)ref_table[INIT_REF_CACHE_SIZE - 1].offset[0];
        memset(ref_table, 0, INIT_REF_CACHE_SIZE * sizeof(ref_cache_t));
    }
    
    ref = &ref_table[num_refs % INIT_REF_CACHE_SIZE];
    if (proc_info.options.stat == true) {
        info->num_ref_caches++;
    }

    return ref;
}


app_pc
table_alloc_bytes(umbra_info_t *info, int size)
{
    app_pc ptr;

    DR_ASSERT(size >= 0 && 
              (info->table.bytes_ptr + size) < 
              (info->table.bytes_table + MAX_BYTES_TABLE_SIZE));
    ptr = info->table.bytes_ptr;
    info->table.bytes_ptr += size;
    return ptr;
}

basic_block_t *
table_get_bb(umbra_info_t *info, int id)
{
    basic_block_t *bb_table;

    DR_ASSERT_MSG((id >= 0) && (id < info->table.max_num_bbs),
                  "Error: bb id out of range!");
    bb_table = info->table.bb_table;

    if (id % INIT_BB_TABLE_SIZE == (INIT_BB_TABLE_SIZE - 1)) 
        return &bb_table[0];

    while(id >= INIT_BB_TABLE_SIZE) {
        id -= INIT_BB_TABLE_SIZE;
        bb_table = (basic_block_t *)bb_table[INIT_BB_TABLE_SIZE - 1].tag;
    }
    
    return &bb_table[id];
}


link_edge_t *
table_get_edge(umbra_info_t *info, int id)
{
    link_edge_t *edge_table;
    
    DR_ASSERT_MSG((id >= 0) && (id < info->table.max_num_edges),
                  "Error: edge id out of range!");
    edge_table = info->table.edge_table;

    while(id >= INIT_EDGE_TABLE_SIZE) {
        id -= INIT_EDGE_TABLE_SIZE;
        edge_table = (link_edge_t *)edge_table[INIT_EDGE_TABLE_SIZE - 1].dst_tag;
    }
    
    return &edge_table[id];
}


mem_ref_t *
table_get_ref(umbra_info_t *info, int id)
{
    mem_ref_t *ref_table;
    DR_ASSERT_MSG((id >=0) && (id < info->table.max_num_refs),
                  "Error: ref id out of range!");
    ref_table = info->table.ref_table;

    while(id >= INIT_REF_TABLE_SIZE) {
        id -= INIT_REF_TABLE_SIZE;
        ref_table = (mem_ref_t *)ref_table[INIT_REF_TABLE_SIZE - 1].pc;
    }
    
    return &ref_table[id];
}


func_t *
table_get_func(umbra_info_t *info, int id)
{
    func_t *func_table;

    DR_ASSERT_MSG((id >= 0) && (id < info->table.max_num_funcs),
           "Error: func id out of range!");
    func_table = info->table.func_table;

    while(id >= INIT_FUNC_TABLE_SIZE) {
        id -= INIT_FUNC_TABLE_SIZE;
        func_table = (func_t *)func_table[INIT_FUNC_TABLE_SIZE - 1].pc;
    }
    
    return &func_table[id];
}


basic_block_t *
table_bb_tag_lookup(umbra_info_t *info, app_pc tag)
{
    uint        index;
    code_hash_t   *code;
    basic_block_t *bb;

    index = CODE_HASH_FUNC((reg_t)tag, info->table.code_hash_mask);
    code  = info->table.code_hash_table[index];
    while(code != NULL) {
        if(code->tag == tag) {
            bb = table_get_bb(info, code->bb);
            return bb;
        }
        code = code->next;
    }
    return NULL;
}


void
table_bb_add_to_hashtable(void *drcontext, 
                          umbra_info_t *info,
                          basic_block_t *bb)
{
    uint        index;
    code_hash_t   *code;
    
    index = CODE_HASH_FUNC((reg_t)bb->tag, 
                           info->table.code_hash_mask);
    code         = dr_thread_alloc(drcontext, sizeof(code_hash_t));
    info->num_table_code_hash += sizeof(code_hash_t);
    code->tag    = bb->tag;
    code->length = bb->length;
    code->bb     = bb->id;
    code->next   = info->table.code_hash_table[index];
    info->table.code_hash_table[index] = code;
}


bool
addr_in_ref_cache(umbra_info_t *info, void *addr)
{
    int last;
    ref_cache_t *ref_table;
    
    ref_table = info->table.ref_cache_table;
    last = INIT_REF_CACHE_SIZE - 1;
    while (true) {
        if (addr >= (void *)&ref_table[0] &&
            addr <  (void *)&ref_table[last])
            return true;
        if (ref_table[last].offset[0] == 0)
            break;
        ref_table = (ref_cache_t *)ref_table[last].offset[0];
    }
    return false;
}
