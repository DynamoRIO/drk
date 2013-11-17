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
 *     Shadow Memory Manager - shadow.c
 *
 * Description:
 *     Manage shadow memory allocation and free.
 *
 * Author: 
 *     Qin Zhao
 *
 */

#include "global.h"
#include "umbra.h"
#include "shadow.h"
#include "utils.h"
#include "table.h"

#ifndef LINUX_KERNEL
#  include <string.h>      /* memset */
#  define _GNU_SOURCE      /* mremap */
#  include <sys/mman.h>    /* mmap   */
#  include <syscall.h>     /* SYS_ */
#  include <errno.h>
#  include <signal.h>
#  include <stddef.h>      /* offsetof */

/* mremap */
#  define _GNU_SOURCE
#  include <unistd.h>
#  include <sys/mman.h>
#else
#   include <linux/sched.h>
#   include <linux/gfp.h>
#   include <linux/mm.h>
#   include <linux/vmalloc.h>
#   include <asm-generic/mman-common.h>
#   include "pagepool.h"
#   include "cr.h"
#   include "page_table.h"
#   include "dr_kernel_utils.h"
#endif

reg_t MAX_MMAP_ADDR;
int   MAX_MMAP_MASK;

#ifdef LINUX_KERNEL
typedef struct {
    void *start;
    void *end;
} address_hole_t;
#define KERNEL_HOLE_START ((void*)0xffffc80000000000)
#define KERNEL_HOLE_END ((void*)0xffffc90000000000)
static void* next_shadow_address;

generic_page_table_entry_t *global_l4;

static bool
possible_shadow_address(void *address)
{
    return address >= KERNEL_HOLE_START && address < KERNEL_HOLE_END;
}

#define SHADOW_MEMORY_SIZE (512 * 1024 * 1024)
pagepool_t *pagepool;
pfn_t global_ro_pfn;
#endif

/* Data structure for memory map fast lookup via hashtable */
#define MAP_HASH_BITS  4
#define MAP_HASH_SIZE  (1 << MAP_HASH_BITS)
#define MAP_HASH_MASK  (MAP_HASH_SIZE - 1)
typedef struct _map_hash_t map_hash_t;
struct _map_hash_t {
    reg_t         tag;
    memory_map_t *map;
    map_hash_t   *next;
};
map_hash_t *app_map_hash[MAP_HASH_SIZE];
map_hash_t *shd_map_hash[MAP_HASH_SIZE];


/* Data structure for protected map fase lookup via hashtable */
#define PROT_MAP_HASH_BITS 8
#define PROT_MAP_HASH_SIZE (1 << PROT_MAP_HASH_BITS)
#define PROT_MAP_HASH_MASK (PROT_MAP_HASH_SIZE - 1)
typedef struct _prot_map_hash_t prot_map_hash_t;
struct _prot_map_hash_t {
    reg_t            tag;
    prot_map_hash_t *next;
};
prot_map_hash_t *prot_map_hash[PROT_MAP_HASH_SIZE];

int num_app_maps  = 0;
int num_shd_maps  = 0;
int num_prot_maps = 0;

#ifdef LINUX_KERNEL
#define MAP_FAILED NULL
#endif

void *os_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
#ifdef LINUX_KERNEL
    DR_ASSERT("not yet implemented" && false);
    return MAP_FAILED;
#else
    return mmap(addr, length, prot, falgs, fd, offset);
#endif
}

void munmap(void *addr, size_t length)
{
#ifdef LINUX_KERNEL
    DR_ASSERT("not yet implemented" && false);
#else
    return munmap(addr, length);
#endif
}



static memory_map_t *
memory_map_shd_lookup(memory_map_t *maps, void *addr);

static bool
memory_map_app_add(void *start, void *end, bool add_shadow_now);

/* initilize all memory map hash table */
static __inline__ void
init_map_hash_table(void)
{
    memset(app_map_hash,  0, sizeof(app_map_hash));
    memset(shd_map_hash,  0, sizeof(shd_map_hash));
    memset(prot_map_hash, 0, sizeof(prot_map_hash));
}


/* rdtsc to get time 
 * XXX: it seems uint64 is unsigned long, which is 32-bit.
 */
static __inline__ uint64 
get_time(void)
{
    uint64 x;
    __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
    return x;
}


/* find the first non-zero byte as the key */
static __inline__ int
get_prot_map_hash_key(reg_t tag)
{
    while (tag != 0 && (tag & PROT_MAP_HASH_MASK) == 0)
        tag = tag >> PROT_MAP_HASH_BITS;
    return tag & PROT_MAP_HASH_MASK;
}


/* check if a memory map starts at base is a prot map */
static bool
prot_map_hash_lookup(void *addr)
{
    reg_t tag;
    int   key;
    prot_map_hash_t *hash;
    
    if (proc_info.options.opt_ems64 == false)
        return false;
    tag  = (reg_t)addr & proc_info.unit_mask;
    key  = get_prot_map_hash_key(tag);
    hash = prot_map_hash[key];
    while (hash != NULL) {
        if (hash->tag == tag)
            return true;
        hash = hash->next;
    }
    return false;
}


static void
prot_map_hash_add(reg_t map_tag)
{
    reg_t size[MAX_NUM_SHADOWS];
    int   i, key;
    void *base;
    memory_map_t *map;

    if (proc_info.options.opt_ems64 == false)
        return;
    compute_shd_memory_size(map_tag, size);
    base = (void *)size[0];
    compute_shd_memory_size(proc_info.unit_size, size);
    for (i = 0; i < proc_info.num_offs; i++) {
        reg_t test_size = 0;
        void *addr;
        prot_map_hash_t *hash;
        while (size[0] > test_size) {
            addr = base + test_size + proc_info.offs[i];
            /* do not maps to itself */
            DR_ASSERT(addr != (void *)map_tag);
            DR_ASSERT(NULL == 
                      memory_map_app_lookup(proc_info.maps, addr));
            map = memory_map_shd_lookup(proc_info.maps, addr);
            if (map != NULL) {
                DR_ASSERT(addr >= map->shd_base[0] && addr < map->shd_end[0]);
            }
            else if (prot_map_hash_lookup(addr) == false) {
                num_prot_maps++;
                hash = dr_global_alloc(sizeof(prot_map_hash_t));
                hash->tag  = (reg_t)addr;
                key = get_prot_map_hash_key(hash->tag);
                hash->next = prot_map_hash[key];
                prot_map_hash[key] = hash;
            }
            test_size += proc_info.unit_size;
        }
    }
}


/* compute the shadow memory size */
void
compute_shd_memory_size(reg_t app_size, reg_t shd_size[MAX_NUM_SHADOWS])
{
    int diff, i;

    for (i = 0; i < MAX_NUM_SHADOWS; i++) {
        shd_size[i] = app_size;
        diff = (proc_info.client.shd_unit_bits[i] -
                proc_info.client.app_unit_bits[i]);
        if (diff > 0)
            shd_size[i] = app_size << diff;
        else if (diff < 0) 
            shd_size[i] = app_size >> (-diff);
    }
}


/* compute the shadow memory address from application address */
bool
compute_shd_memory_addr(void *app_addr, void* shd_addr[MAX_NUM_SHADOWS])
{
    memory_map_t *map;
    /* 1. find the application memory map */
    map = memory_map_app_lookup(proc_info.maps, app_addr);
    /* not an app memory */
    if (map == NULL)
        return false;
    compute_shd_memory_addr_ex(map, app_addr, shd_addr);
    return true;
}

void
compute_shd_memory_addr_ex(memory_map_t *map, void *app_addr,
                           void *shd_addr[MAX_NUM_SHADOWS])
{
    int i;
    reg_t shd_size[MAX_NUM_SHADOWS];
    DR_ASSERT(map->app_base <= app_addr &&
              (app_addr < map->app_end || map->app_end == 0));
    /* 2. first scale the addr */
    compute_shd_memory_size((reg_t)app_addr, shd_size);
    /* 3. update with offset */
    for (i = 0; i < MAX_NUM_SHADOWS; i++)
        shd_addr[i] = (void *)(map->offset[i] + shd_size[i]);
}

static __inline__ void
memory_map_hash_remove(map_hash_t *hashtable[])
{
    int i;
    map_hash_t *hash;

    for (i = 0; i < MAP_HASH_SIZE; i++) {
        hash = hashtable[i];
        while(hash != NULL) {
            hashtable[i] = hash->next;
            dr_global_free(hash, sizeof(map_hash_t));
            hash = hashtable[i];
        }
    }
}


/* find the first non-zero byte as the key */
static __inline__ byte
memory_map_get_map_hash_key(reg_t tag)
{
    while (tag != 0 && (tag & MAP_HASH_MASK)== 0) {
        tag = tag >> MAP_HASH_BITS;
    }
    return tag & MAP_HASH_MASK;
}


/* simple hashtable lookup */
static __inline__ memory_map_t *
memory_map_hash_lookup(map_hash_t *hashtable[], void *addr)
{
    reg_t  tag;
    byte   key;
    map_hash_t *hash;
    
    tag  = (reg_t)addr & proc_info.unit_mask;
    key  = memory_map_get_map_hash_key(tag);
    hash = hashtable[key];
    while (hash != NULL) {
        if (hash->tag == tag)
            return hash->map;
        hash = hash->next;
    }
    return NULL;    
}


/* perform hash lookup on application unit hash table */
static __inline__ memory_map_t *
memory_map_app_hash_lookup(void *addr)
{
    return memory_map_hash_lookup(app_map_hash, addr);
}


/* perform hash lookup on shadow unit hash table */
static __inline__ memory_map_t *
memory_map_shd_hash_lookup(void *addr)
{
    return memory_map_hash_lookup(shd_map_hash, addr);
}


/* add new entry into hashtable, assuming no conflication. */
static __inline__ void
memory_map_hash_add(map_hash_t *hashtable[], memory_map_t *map, reg_t tag) 
{
    map_hash_t *hash;
    byte key;

    key  = memory_map_get_map_hash_key(tag);
    hash = dr_global_alloc(sizeof(map_hash_t));
    hash->tag  = tag;
    hash->map  = map;
    hash->next = hashtable[key];
    hashtable[key] = hash;
}


/* add new unit into application unit hash table */
static __inline__ void
memory_map_app_hash_add(memory_map_t *map)
{
    num_app_maps++;
    memory_map_hash_add(app_map_hash, map, (reg_t)map->app_base);
}


/* add new unit into shadow unit hash table */
static __inline__ void
memory_map_shd_hash_add(memory_map_t *map)
{
    reg_t base;
    int i;
    for (i = 0; i < MAX_NUM_SHADOWS; i++) {
        base = (reg_t)map->shd_base[i] & proc_info.unit_mask;
        while (base < (reg_t)map->shd_end[i] && base != 0) {
            num_shd_maps++;
            memory_map_hash_add(shd_map_hash, map, base);
            prot_map_hash_add(base);
            base += proc_info.unit_size;
        }
    }
    prot_map_hash_add((reg_t)map->app_base);
}


static bool
memory_map_prot_lookup(void *addr)
{
    addr = (void *)((reg_t)addr & proc_info.unit_mask);
    return prot_map_hash_lookup(addr);
}


static void
memory_map_prot_remove(void)
{
    int i;
    prot_map_hash_t *hash;
    
    for (i = 0; i < PROT_MAP_HASH_SIZE; i++) {
        hash = prot_map_hash[i];
        while (hash != NULL) {
            prot_map_hash[i] = hash->next;
            dr_global_free(hash, sizeof(prot_map_hash_t));
            hash = prot_map_hash[i];
        }
    }
}


/* translate platform independent protection bits to native flags */
static __inline__ uint
memprot_to_osprot(uint prot)
{
    uint mmap_prot = 0;
    if (TESTANY(DR_MEMPROT_EXEC, prot))
        mmap_prot |= PROT_EXEC;
    if (TESTANY(DR_MEMPROT_READ, prot))
        mmap_prot |= PROT_READ;
    if (TESTANY(DR_MEMPROT_WRITE, prot))
        mmap_prot |= PROT_WRITE;
    return mmap_prot;
}

/* Allocat shadow memory from OS
 * FIXME: we should use DR's routine instead of mmap directly
 */
static void *
alloc_memory_from_os(void *addr, reg_t size, uint prot, bool fixed)
{
    void *ptr;
    uint flags = MAP_PRIVATE | MAP_ANONYMOUS;

    if (fixed == true)
        flags = flags | MAP_FIXED;
    prot = memprot_to_osprot(prot);
    ptr  = os_mmap(addr, size, prot, flags, -1, 0);
    DR_ASSERT(ptr != MAP_FAILED);
    if (fixed == true) DR_ASSERT(ptr == addr);
    return ptr;
}


/* free shadow memory to OS
 * FIXME: we should use DR's routine instead of munmap.
 */
static void
free_memory_to_os(void *addr, reg_t size)
{
#ifdef LINUX_KERNEL
    DR_ASSERT("not yet implemented" && false);
#else
    munmap(addr, (size_t)size);
#endif
}


/* shadow memory map lookup */
static memory_map_t *
memory_map_shd_lookup(memory_map_t *map, void *addr)
{
    /* global map lookup using hash table */
    if (map == proc_info.maps)
        return memory_map_shd_hash_lookup(addr);

    /* thread local lookup */
    /* shadow memory size may not be unit aligned, so need
     * check if the address is in the boundary
     */
    while (map != NULL) {
        if ((addr >= map->shd_base[0]) && (addr <  map->shd_end[0]))
            return map;
#ifdef DOUBLE_SHADOW
        if ((addr >= map->shd_base[1]) && (addr <  map->shd_end[1]))
            return map;
#endif
    };
    return NULL;
}


/* application memory map lookup */
memory_map_t *
memory_map_app_lookup(memory_map_t *map, void *addr)
{
    void *base;
    /* global map lookup using hash table */
    if (map == proc_info.maps)
        return memory_map_app_hash_lookup(addr);
    /* thread local lookup */
    base = (void *)((reg_t)addr & proc_info.unit_mask);
    while (map != NULL) {
        if (base == map->app_base)
            return map;
        map = map->next;
    }
    return NULL;
}


static __inline__ bool
memory_map_is_valid(void *start, void *end)
{
    reg_t  stride;
    void  *map_base, *map_end;

    /* we do not allows round */
    if (((reg_t)start & proc_info.unit_mask) >
        ((reg_t)end   & proc_info.unit_mask))
        return false;
    
    map_base = (void *)((reg_t)start & proc_info.unit_mask);
    map_end  = map_base + proc_info.unit_size;
    /* map_end != NULL is for round up 
     * from 0xffffffff00000000 to 0x0000000000000000
     */
    while (map_end != NULL && map_end < end)
        map_end += proc_info.unit_size;
    
    stride = 0;
    do {
        /* 1. not an exist app memory map */
        if (NULL != memory_map_app_lookup(proc_info.maps, map_base + stride))
            return false;
        /* 2. not an exist shd memory map */
        if (NULL != memory_map_shd_lookup(proc_info.maps, map_base + stride))
            return false;
        if (proc_info.options.opt_ems64 == true) {
            void *xls_base;
            reg_t xls_size[MAX_NUM_SHADOWS];
            int   i;
            /* 3. not an exist prot memory map */
            if (memory_map_prot_lookup(map_base + stride) == true)
                return false;
            /* 4. units calculated from offsets */
            compute_shd_memory_size((reg_t)map_base + stride, xls_size);
            xls_base = (void *)xls_size[0];
            compute_shd_memory_size(proc_info.unit_size, xls_size);
            for (i = 0; i < proc_info.num_offs; i++) {
                void  *addr = xls_base + proc_info.offs[i];
                reg_t  size = 0;
                while (size < xls_size[0]) {
                    /* 4.1 not an exist app memory map */
                    if (NULL != 
                        memory_map_app_lookup(proc_info.maps, addr + size))
                        return false;
                    /* 4.2 not an exist shd memory map */
                    if (NULL != 
                        memory_map_shd_lookup(proc_info.maps, addr + size))
                        return false;
                    /* 4.3 not itself */
                    if (addr + size >= map_base && 
                        addr + size <= (map_end - 1))
                        return false;
                    size += proc_info.unit_size;
                }
            }
        }
        stride += proc_info.unit_size;
    } while ((map_base + stride != 0) && (map_base + stride < map_end));

    if (proc_info.client.memory_map_is_valid) {
        return proc_info.client.memory_map_is_valid(map_base, map_end);
    } else {
        return true;
    }
}


#ifndef LINUX_KERNEL
/* Check if memory map is valid as a shd map */
static bool
memory_map_shd_is_valid(void *shd_base, void *shd_end)
{
    /* 1. shd map must be in allocable address */
    if (shd_base >= (void *)MAX_MMAP_ADDR ||
        shd_end  >= (void *)MAX_MMAP_ADDR)
        return false;

    /* 2. shd map must ba a valid map */
    return memory_map_is_valid(shd_base, shd_end);
}
#endif


/* Check if memory map is valid as an app map */
static bool
memory_map_app_is_valid(void *app_base, void *app_end)
{
    /* a valid map */
    return memory_map_is_valid(app_base, app_end);
}

#ifndef LINUX_KERNEL
static bool
offset_is_valid_with_base(void *base,
                          reg_t offset,
                          void *shd_base,
                          void *shd_end)
{
    reg_t size[MAX_NUM_SHADOWS], stride;
    
    compute_shd_memory_size((reg_t)base, size);
    base = (void *)size[0] + offset;
    compute_shd_memory_size(proc_info.unit_size, size);
    for (stride = 0; stride < size[0]; stride += proc_info.unit_size) {
        if (memory_map_app_lookup(proc_info.maps, base + stride) != NULL)
            return false;
        if (memory_map_shd_lookup(proc_info.maps, base + stride) != NULL)
            return false;
        if (shd_base <= base + stride && 
            shd_end  >= base + stride + proc_info.unit_size)
            return false;
    }
    return true;
}
#endif

#ifndef LINUX_KERNEL
/* Check if offset is valid for existing arrangment 
 * [shd_base, shd_end) is the new shadow to be added using
 * offset
 */
static bool
memory_map_offset_is_valid(reg_t offset,
                           void *shd_base,
                           void *shd_end)
{
    int i;
    map_hash_t   *hash;

    if (proc_info.options.opt_ems64 == false)
        return true;
    
    for (i = 0; i < MAP_HASH_SIZE; i++) {
        for (hash = app_map_hash[i]; hash != NULL; hash = hash->next) {
            if (hash->map->shd_base[0] == NULL)
                continue;
            if (!offset_is_valid_with_base((void *)hash->tag,
                                           offset,
                                           shd_base,
                                           shd_end))
                return false;
        }
        for (hash = shd_map_hash[i]; hash != NULL; hash = hash->next) {
            if (hash->map->shd_base == NULL)
                continue;
            if (!offset_is_valid_with_base((void *)hash->tag,
                                           offset,
                                           shd_base,
                                           shd_end))
                return false;
        }
    }
    return true;
}
#endif

#ifndef LINUX_KERNEL
static void
memory_map_offset_add(reg_t offset)
{
    int i;
    map_hash_t *hash;

    /* add offset */
    proc_info.offs[proc_info.num_offs++] = offset;
    
    /* add prot_map for the new offset */
    for (i = 0; i < MAP_HASH_SIZE; i++) {
        for (hash = app_map_hash[i]; hash != NULL; hash = hash->next)
            if (hash->map->shd_base != NULL)
                /* skip app map that not compute shadow yet */
                prot_map_hash_add(hash->tag);
        for (hash = shd_map_hash[i]; hash != NULL; hash = hash->next)
            prot_map_hash_add(hash->tag);
    }
}
#endif

#ifndef LINUX_KERNEL
memory_mod_t *
memory_mod_app_lookup(void *addr)
{
    memory_map_t *map;
    memory_mod_t *mod;

    map = memory_map_app_lookup(proc_info.maps, addr);
    DR_ASSERT(map != NULL);
    mod = map->mods;
    while (mod != NULL) {
        if (addr >= mod->app_base && addr <  mod->app_end)
            return mod;
        mod = mod->next;
    }
    return NULL;
}
#endif


/* Reserve shadow memory for [app_base, app_end) */
static bool
memory_mod_shd_add(memory_mod_t *app_mod)
{
    int i;
    memory_map_t map;

    compute_shd_memory_addr(app_mod->app_base, app_mod->shd_base);
    compute_shd_memory_addr(app_mod->app_end, app_mod->shd_end);
    /* notify client */
    map.app_base = app_mod->app_base;
    map.app_end  = app_mod->app_end;
    map.shd_base[0] = app_mod->shd_base[0];
    map.shd_end[0]  = app_mod->shd_end[0];
#ifdef DOUBLE_SHADOW
    map.shd_base[1] = app_mod->shd_base[1];
    map.shd_end[1]  = app_mod->shd_end[1];
#endif
    if (proc_info.client.shadow_memory_module_create != NULL)
        proc_info.client.shadow_memory_module_create(&map);
    else {
        for (i = 0; i < MAX_NUM_SHADOWS; i++) {
            alloc_memory_from_os(app_mod->shd_base[i], 
                                 app_mod->shd_end[i] - app_mod->shd_base[i],
                                 DR_MEMPROT_READ | DR_MEMPROT_WRITE,
                                 true);
        }
    }
    return true;
}


/* if a memory module span several memory maps,
 * we split module into corresponding map
 */
bool
memory_mod_app_add(void *addr, reg_t size)
{
    memory_map_t *map;
    memory_mod_t *mod, *new_mod, *prev;
    void *app_base;
    size_t app_size;
    uint    prot, i;

    /* check if app memory exist */
    if (!dr_query_memory(addr, (byte **)&app_base, &app_size, &prot))
        return false;
    /* init heap might be size 0 */
    if (app_size == 0)
        return true;
    /* not know the size, call from signal handler */
    if (size == 0) {
        addr = app_base;
        size = app_size;
    }
    /* [addr, addr + size) must be in [app_base, app_base + app_size) */
    DR_ASSERT(addr >= app_base && 
              addr + size <= app_base + app_size);

    map = memory_map_app_lookup(proc_info.maps, addr);
    DR_ASSERT(map != NULL);

    app_base = (void *)addr;
    app_size = size;
    /* allocate memmory_mod_t */
    new_mod = dr_global_alloc(sizeof(memory_mod_t));
    new_mod->app_base = app_base;
    new_mod->app_end  = app_base + app_size;
    for (i = 0; i < MAX_NUM_SHADOWS; i++) {
        new_mod->shd_base[i] = NULL;
        new_mod->shd_end[i]  = NULL;
    }
    new_mod->map      = map;
    new_mod->next     = NULL;
    /* insert new app mod */
    mod  = map->mods;
    prev = NULL;
    while (mod != NULL) {
        if (app_base < mod->app_base) {
            if (app_base + app_size > mod->app_base)
                app_size = (reg_t)mod->app_base - (reg_t)app_base;
            break;
        }
        prev = mod;
        mod  = mod->next;
    }
    /* if app_base is in prev's [app_base, app_end)*/
    if (prev != NULL) {
        if (new_mod->app_base < prev->app_end)
            new_mod->app_base = prev->app_end;
        if (new_mod->app_end  < prev->app_end)
            new_mod->app_end  = prev->app_end;
    }
    if (mod != NULL && new_mod->app_end  > mod->app_base)
        new_mod->app_end  = mod->app_base;
    DR_ASSERT(new_mod->app_base != new_mod->app_end);
    /* allocate shadow memory */
    memory_mod_shd_add(new_mod);

    new_mod->next = mod;
    if (prev == NULL)
        map->mods  = new_mod;
    else
        prev->next = new_mod;

    /* merge new_mod and mod */
    if (mod != NULL && new_mod->app_end == mod->app_base) {
        new_mod->app_end = mod->app_end;
        new_mod->shd_end[0] = mod->shd_end[0];
#ifdef DOUBLE_SHADOW
        new_mod->shd_end[1] = mod->shd_end[1];
#endif
        new_mod->next    = mod->next;
        dr_global_free(mod, sizeof(memory_mod_t));
    }

    /* merge prev and new_mod */
    if (prev != NULL && prev->app_end == new_mod->app_base) {
        prev->app_end = new_mod->app_end;
        prev->shd_end[0] = new_mod->shd_end[0];
#ifdef DOUBLE_SHADOW
        prev->shd_end[1] = new_mod->shd_end[1];
#endif
        prev->next    = new_mod->next;
        dr_global_free(new_mod, sizeof(memory_mod_t));
    }
    return true;
}


static void
memory_mod_shd_remove(void *app_base, reg_t app_size)
{
    reg_t shd_size[MAX_NUM_SHADOWS];
    memory_map_t map;
    int i;
    
    compute_shd_memory_addr(app_base, map.shd_base);
    compute_shd_memory_size(app_size, shd_size);
    /* notify client */
    map.app_base = app_base;
    map.app_end  = app_base + app_size;
    for (i = 0; i < MAX_NUM_SHADOWS; i++) {
        map.shd_end[i]  = map.shd_base[i] + shd_size[i];
    }
    if (proc_info.client.shadow_memory_module_destroy != NULL)
        proc_info.client.shadow_memory_module_destroy(&map);
    else {
        for (i = 0; i < MAX_NUM_SHADOWS; i++) 
            free_memory_to_os(map.shd_base[i], shd_size[i]);
    }
}


static void
memory_mod_app_remove(void *app_base, reg_t app_size)
{
    memory_map_t *map;
    memory_mod_t *mod, *new_mod, *prev;
    void *app_end;
    
    /* find the memory map */
    map = memory_map_app_lookup(proc_info.maps, app_base);
    DR_ASSERT(map != NULL);
    /* find the memory mod */
    mod = map->mods;
    DR_ASSERT(mod != NULL);
    prev = NULL;
    while (mod != NULL) {
        if (mod->app_base <= app_base &&
            mod->app_end  >  app_base)
            break;
        prev = mod;
        mod  = mod->next;
    }
    DR_ASSERT(mod != NULL);
    app_end = app_base + app_size;
    DR_ASSERT(mod->app_end >= app_end);
    if (app_end < mod->app_end) {
        new_mod = dr_global_alloc(sizeof(memory_mod_t));
        new_mod->app_base = app_end;
        new_mod->app_end  = mod->app_end;
        compute_shd_memory_addr(new_mod->app_base, new_mod->shd_base);
        compute_shd_memory_addr(new_mod->app_end,  new_mod->shd_end);
        new_mod->map      = mod->map;
        new_mod->next     = mod->next;
        mod->next         = new_mod;
    }
    if (app_base > mod->app_base) {
        mod->app_end = app_base;
    } else {
        if (prev == NULL)
            map->mods  = mod->next;
        else
            prev->next = mod->next;
        dr_global_free(mod, sizeof(memory_mod_t));
    }
    memory_mod_shd_remove(app_base, app_size);
}

#ifndef LINUX_KERNEL
static void
memory_mod_app_move(void *old_base, reg_t old_size,
                    void *new_base, reg_t new_size)
{
    void *new_shd_base[MAX_NUM_SHADOWS];
    void *old_shd_base[MAX_NUM_SHADOWS];
    reg_t new_shd_size[MAX_NUM_SHADOWS];
    reg_t old_shd_size[MAX_NUM_SHADOWS];
    int i;

    if (old_base == new_base) {
        if (old_size > new_size) {
            memory_mod_app_remove(old_base + new_size,
                                  old_size - new_size);
        } else if (old_size < new_size) {
            memory_mod_app_add(old_base + old_size, 
                               new_size - old_size);
        }
        return;
    } 
    DR_ASSERT(memory_map_app_add(new_base, new_base + new_size, true));
    memory_mod_app_add(new_base, new_size);
    compute_shd_memory_addr(new_base, new_shd_base);
    compute_shd_memory_addr(old_base, old_shd_base);
    compute_shd_memory_size(new_size, new_shd_size);
    compute_shd_memory_size(old_size, old_shd_size);
    for (i = 0; i < MAX_NUM_SHADOWS; i++) {
        memmove(old_shd_base[i], new_shd_base[i],
                old_size > new_size ? new_shd_size[i] : old_shd_size[i]);
    }
    memory_mod_app_remove(old_base, old_size);
}
#endif

/* Reserve shadow memory space for [app_start, app_end) */
static bool
memory_map_shd_add(void *app_start, void *app_end)
{
    memory_map_t *map;
    void *shd_base[MAX_NUM_SHADOWS], *shd_end[MAX_NUM_SHADOWS];
    reg_t shd_size[MAX_NUM_SHADOWS], app_size, base, end;
    reg_t offset[MAX_NUM_SHADOWS];
    int i;
#ifndef LINUX_KERNEL
    uint64 rand_val;
#endif

    /* identify the application unit boundary [base, end) and size */
    base = (reg_t)app_start & proc_info.unit_mask;
    end  = base + proc_info.unit_size;
    while (end < (reg_t)app_end && end != 0)
        end += proc_info.unit_size;
    app_size = end - base;
    compute_shd_memory_size(base, shd_size);
    for (i = 0; i < MAX_NUM_SHADOWS; i++) {
        shd_base[i] = (void *)shd_size[i];
    }
    compute_shd_memory_size(app_size, shd_size);
    for (i = 0; i < MAX_NUM_SHADOWS; i++) {
        shd_end[i]  = shd_base[i] + shd_size[i];
    }

#ifdef LINUX_KERNEL
    for (i = 0; i < MAX_NUM_SHADOWS; i++) {
        offset[i] = next_shadow_address - shd_base[i];
        /* Hack! We're adding page size because shadows are allocated based on
         * the first byte of memory addresses. If the Nth byte of an access is
         * past the end of the application unit, then we'll overflow the
         * shadow. Our shadow memory allocation code (i.e., the page fault
         * handler) allows this because it just fills in shadow memory pages as
         * they're requested.
         */
        next_shadow_address += shd_size[i] + PAGE_SIZE;
        DR_ASSERT(next_shadow_address <= KERNEL_HOLE_END);
    }
#else
    /* try to use exist offset */
    for (i = 0; i < MAX_NUM_SHADOWS; i++) {
        offset[i] = 0;
    }
    for (i = 0; i < proc_info.num_offs; i++) {
        offset[0] = proc_info.offs[i];
        if (memory_map_shd_is_valid(shd_base[0] + offset[0],
                                    shd_end[0]  + offset[0])) {
            /* valid memory map with offset, use this offset shd map */
            i++;
            break;
        }
        offset[0] = 0;
    }
#ifdef DOUBLE_SHADOW
    /* try to use exist offset */
    for (; i < proc_info.num_offs; i++) {
        offset[1] = proc_info.offs[i];
        if (memory_map_shd_is_valid(shd_base[1] + offset[1],
                                    shd_end[1]  + offset[1])) {
            /* valid memory map with offset, use this offset shd map */
            break;
        }
        offset[1] = 0;
    }
#endif

    /* if no exist offsets valid, try to find a new one */
    if (proc_info.num_offs == i) {
        for (i = 0; i < MAX_NUM_SHADOWS; i++) {
            if (offset[i] != 0)
                continue;
            while (true) {
                rand_val  = get_time();
                offset[i] = ((rand_val & MAX_MMAP_MASK) << proc_info.unit_bits);
                offset[i] = offset[i] - (reg_t)shd_base[i];
                /* add an valid offset temporarily */
                if (memory_map_shd_is_valid(shd_base[i] + offset[i],
                                            shd_end[i] + offset[i]) &&
                    memory_map_offset_is_valid(offset[i], 
                                               shd_base[i] + offset[i],
                                               shd_end[i]  + offset[i])) {
                    memory_map_offset_add(offset[i]);
                    break;
                }
            }
        }
    }
#endif /* !LINUX_KERNEL */

    /* add the shadow space unit */
    base     = (reg_t)app_start & proc_info.unit_mask;
    compute_shd_memory_size(proc_info.unit_size, shd_size);
    do {
        reg_t temp[MAX_NUM_SHADOWS], unit_shd_size[MAX_NUM_SHADOWS];
        map = memory_map_app_lookup(proc_info.maps, (void *)base);
        DR_ASSERT(map != NULL);
        compute_shd_memory_size((reg_t)map->app_base, temp);
        compute_shd_memory_size(proc_info.unit_size, unit_shd_size);
        for (i = 0; i < MAX_NUM_SHADOWS; i++) {
            map->shd_base[i] = (void *)(temp[i] + offset[i]);
            map->shd_end[i]  = map->shd_base[i] + 
                (shd_size[i] > unit_shd_size[i] ?
                 (shd_size[i] - unit_shd_size[i]) : unit_shd_size[i]);
            map->offset[i]   = offset[i];
        }
        memory_map_shd_hash_add(map);
        base += proc_info.unit_size;
    } while (base < end && base != 0);
    return true;
}


static memory_map_t *
memory_map_create(void *base)
{
    memory_map_t *map;
    int i;
    map = dr_global_alloc(sizeof(memory_map_t));
    map->app_base  = base;
    map->app_end   = base + proc_info.unit_size;
    for (i = 0; i < MAX_NUM_SHADOWS; i++) {
        map->shd_base[i]  = NULL;
        map->shd_end[i]   = NULL;
        map->offset[i]    = 0;
    }
    map->next      = proc_info.maps;
    map->mods      = 0;
    proc_info.maps = map;
    return map;
}




/* Reserve application memory space
 * and reserve shadow memory space if add_shadow_now is true
 * Note: add_shadow_now should be always true except at
 * program start.
 */
static bool
memory_map_app_add(void *start, void *end, bool add_shadow_now)
{
    memory_map_t *map;
    void *base;
    int   num_units, num_exists;

    base = (void *)((reg_t)start & proc_info.unit_mask);
    /* [start, end) is in an exist app map unit */
    /* XXX: not handle case that multiple units but some exist */
    num_units  = 0;
    num_exists = 0;
    do {
        num_units++;
        if (NULL != memory_map_app_lookup(proc_info.maps, base))
            num_exists++;
        base += proc_info.unit_size;
    } while (base != NULL && base < end);
    /* all units have exist map */
    /* XXX: the shadow units may not continuous as app units */
    if (num_units == num_exists)
        return true;
    /* some not all units have maps */
    if (num_exists != 0)
        return false;

    /* memory map is valid as a app map */
    base = (void *)((reg_t)start & proc_info.unit_mask);
    if (memory_map_app_is_valid(base, end) == false)
        return false;
    /* create map unit for it */
    do {
        map = memory_map_create(base);
        memory_map_app_hash_add(map);
#ifndef LINUX_KERNEL
        /* tries to mark the first and last page non-accessible 
         * to avoid memory mod span multiple units 
         */
        if (base >= end || (base + PAGE_SIZE) <= start)
            os_mmap(base, 
                    PAGE_SIZE, PROT_NONE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                    -1, 0);
#endif
        base += proc_info.unit_size;
#ifndef LINUX_KERNEL
        if ((base - PAGE_SIZE) >= end || base <= start)
            os_mmap(base + proc_info.unit_size - PAGE_SIZE, 
                    PAGE_SIZE, PROT_NONE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                    -1, 0);
#endif
    } while (base < end && base != 0);

    /* add corresponding shadow unit */
    if (add_shadow_now)
        memory_map_shd_add(start, end);
    
    return true;
}


static void
memory_map_pull_update(void *drcontext, umbra_info_t *info)
{
    memory_map_t *local, *global;

    global = proc_info.maps;
    while (global != NULL) {
        local = memory_map_app_lookup(info->maps, global->app_base);
        if (local == NULL) {
            local  = dr_thread_alloc(drcontext, sizeof(memory_map_t));
            *local = *global;
            local->next = info->maps;
            info->maps  = local;
            /* local copy do not maintain modules info */
            local->mods = NULL; 
        }
        global = global->next;
    }
}


static void
reserve_shd_mem_space(void)
{
    memory_map_t *map;
    int i;

    map = proc_info.maps;
#ifdef X64
    while (map != NULL) {
        if (map->shd_base[0] == NULL)
            memory_map_shd_add(map->app_base, map->app_end);
        map = map->next;
    }
    /* assume the first app map is the binary map */
    map = proc_info.maps;
    proc_info.bin_map_tag    = (reg_t)map->app_base;
    for (i = 0; i< MAX_NUM_SHADOWS; i++) {
        proc_info.bin_map_offset[i] = map->offset[i];
    }
#ifndef LINUX_KERNEL
    /* assume the second app map is the libray map */
    if (map->next != NULL) {
        map = map->next;
        proc_info.lib_map_tag    = (reg_t)map->app_base;
        for (i = 0; i < MAX_NUM_SHADOWS; i++) {
            proc_info.lib_map_offset[i] = map->offset[i];
        }
    }
#endif
#else
    DR_ASSERT(proc_info.options.opt_ems64 == false);
    /* FIXME: for 32-bit, we can simply reserve all possible 
     * shadow address space unit. 
     */
#endif 
}


#ifndef LINUX_KERNEL
static void
shadow_save_syscall(void *drcontext, int sysnum, umbra_info_t *info)
{
    int i;
    info->syscall.sysnum = sysnum;
    for (i = 0; i < 6; i++) {
        info->syscall.params[i] = dr_syscall_get_param(drcontext, i);
    }
}


static void
shadow_pre_mmap(void *drcontext, umbra_info_t *info)
{
    shadow_save_syscall(drcontext, SYS_mmap, info);
}


static void
shadow_post_mmap(void *drcontext, umbra_info_t *info)
{
    reg_t result, app_size;
    void *app_start, *app_end;
    

    result = dr_syscall_get_result(drcontext);
    if (result == -1)
        return;

    app_start = (app_pc)result;
    app_size  = info->syscall.params[1];
    app_end   = (void *)(result + app_size);
#ifdef VERBOSE_MEMORY
    dr_fprintf(info->log, "mmap: %p, %llu\n", app_start, app_size);
#endif 
            
    dr_mutex_lock(proc_info.mutex);
    if (!memory_map_app_add(app_start, app_end, true))
        DR_ASSERT(false);
    if (memory_mod_app_lookup(app_start) == NULL)
        memory_mod_app_add(app_start, app_size);
    memory_map_pull_update(drcontext, info);
    dr_mutex_unlock(proc_info.mutex);
}


static void
shadow_pre_munmap(void *drcontext, umbra_info_t *info)
{
    shadow_save_syscall(drcontext, SYS_munmap, info);
}


static void
shadow_post_munmap(void *drcontext, umbra_info_t *info)
{
    reg_t  result;
    void  *app_base;
    reg_t  app_size;

    result = dr_syscall_get_result(drcontext);
    if (result == -1)
        return;

    app_base = (void *)info->syscall.params[0];
    app_size = info->syscall.params[1];
    if (app_size == 0)
        return;

#ifdef VERBOSE_MEMORY
    dr_fprintf(info->log, "munmap: %p, %llu\n", app_base, app_size);
#endif
    dr_mutex_lock(proc_info.mutex);
    memory_mod_app_remove(app_base, app_size);
    dr_mutex_unlock(proc_info.mutex);
}


static void
shadow_pre_mremap(void *drcontext, umbra_info_t *info)
{
    shadow_save_syscall(drcontext, SYS_mremap, info);
}


static void
shadow_post_mremap(void *drcontext, umbra_info_t *info)
{
    reg_t result;
    app_pc old_base, new_base;
    reg_t  old_size, new_size;

    result = dr_syscall_get_result(drcontext);
    if (result == -1)
        return;
    old_base = (app_pc)info->syscall.params[0];
    old_size = info->syscall.params[1];
    new_base = (app_pc)result;
    new_size = info->syscall.params[2];
#ifdef VERBOSE_MEMORY
    dr_fprintf(info->log, "mremap %p(%x) => %p(%x)\n", 
               old_base, old_size, new_base, new_size);
#endif
    /*XXX: handle move memory to new base */
    dr_mutex_lock(proc_info.mutex);
    memory_mod_app_move(old_base, old_size, new_base, new_size);
    dr_mutex_unlock(proc_info.mutex);
}


static void
shadow_pre_brk(void *drcontext, umbra_info_t *info)
{
    shadow_save_syscall(drcontext, SYS_brk, info);
}


static void
shadow_post_brk(void *drcontext, umbra_info_t *info)
{
    reg_t result;
    
    result = dr_syscall_get_result(drcontext);
    if (result == -1)
        return;
#ifdef VERBOSE_MEMORY
    dr_fprintf(info->log, "brk %p \n", result);
#endif
    dr_mutex_lock(proc_info.mutex);
    if ((void *)result > proc_info.heap_brk) 
        /* expand heap */
        memory_mod_app_add(proc_info.heap_brk,
                           result - (reg_t)proc_info.heap_brk);
    else if ((void *)result < proc_info.heap_brk)
        /* shrink heap */
        memory_mod_app_remove((void *)result,
                              (reg_t)proc_info.heap_brk - result);
    proc_info.heap_brk = (void *)result;
    dr_mutex_unlock(proc_info.mutex);
}
#endif /* !LINUX_KERNEL */


void
shadow_maps_free_update(void *drcontext, umbra_info_t *info, 
                        byte *addr)
{
    /* do nothing now */
}


void
shadow_maps_alloc_update(void *drcontext, umbra_info_t *info, 
                         byte *addr,      size_t size)
{
}


void
shadow_maps_access_update(void *drcontext, umbra_info_t *info,
                          byte *addr)
{
}


void 
shadow_thread_init(void *drcontext, umbra_info_t *info)
{
    int i;
    dr_mutex_lock(proc_info.mutex);
    memory_map_pull_update(drcontext, info);
    info->last_map_tag     = (reg_t)proc_info.maps->app_base;
    for (i = 0; i < MAX_NUM_SHADOWS; i++) {
        info->last_map_offset[i]  = (reg_t)proc_info.maps->offset[i];
    }
    dr_mutex_unlock(proc_info.mutex);
    info->stack_ref_cache  = NULL;
    DR_ASSERT(info->maps != NULL);
    info->last_lazy_add = info->maps;
}


void 
shadow_thread_exit(void *drcontext, umbra_info_t *info)
{
    memory_map_t *map;

    map = info->maps;
    dr_fprintf(info->log, "Num of Signals %d\n", info->num_sigs);
    while (map != NULL) {
        info->maps = map->next;
        dr_thread_free(drcontext, map, sizeof(memory_map_t));
        map = info->maps;
    }
}

memory_map_t *
memory_map_app_lazy_add(void *addr)
{
    memory_map_t *map = memory_map_app_lookup(proc_info.maps, addr);
    if (map == NULL) {
        DR_ASSERT(memory_map_app_add(addr, addr + 1, true));
    }
    map = memory_map_app_lookup(proc_info.maps, addr);
    DR_ASSERT(map != NULL);
    return map;
}


memory_map_t *
memory_map_thread_lazy_add(umbra_info_t *info, void *addr)
{
    void *base = (void *)((reg_t)addr & proc_info.unit_mask);
    memory_map_t *map;
    if (base == info->last_lazy_add->app_base) {
        return info->last_lazy_add;
    }
    map = memory_map_app_lookup(info->maps, addr);
    if (map) {
        info->last_lazy_add = map;
        return map;
    }
    dr_mutex_lock(proc_info.mutex);
    map = memory_map_app_lazy_add(addr);
    DR_ASSERT(map != NULL);
    memory_map_pull_update(info->drcontext, info);
    dr_mutex_unlock(proc_info.mutex);
    map = memory_map_app_lookup(info->maps, addr);
    DR_ASSERT(map);
    info->last_lazy_add = map;
    return map;
}


void
shadow_memory_map_lookup(void)
{
    void *drcontext;
    umbra_info_t *info;
    memory_map_t *map;
    int i;
    
    drcontext = dr_get_current_drcontext();
    info = dr_get_tls_field(drcontext);
    /* mmap lookup */
    dr_mutex_lock(proc_info.mutex);
#ifndef LINUX_KERNEL
    map = memory_map_app_lookup(proc_info.maps, 
                                (void *)info->last_map_tag);
#else
    map = memory_map_app_lazy_add((void*)info->last_map_tag);
#endif
    DR_ASSERT(map != NULL);
    memory_map_pull_update(drcontext, info);
    dr_mutex_unlock(proc_info.mutex);
    /* update last ref map */
    info->last_map_tag    = (reg_t)map->app_base;
    for (i = 0; i < MAX_NUM_SHADOWS; i++) {
        info->last_map_offset[i] = map->offset[i];
    }
}


void
shadow_pre_syscall(void *drcontext, umbra_info_t *info, int sysnum)
{
#ifndef LINUX_KERNEL
    if (proc_info.client.pre_syscall != NULL) {
      proc_info.client.pre_syscall(drcontext, info, sysnum);
    }
    switch (sysnum) {
    case SYS_mmap:
        shadow_pre_mmap(drcontext, info);
        break;
    case SYS_munmap:
        shadow_pre_munmap(drcontext, info);
        break;
    case SYS_mremap:
        shadow_pre_mremap(drcontext, info);
        break;
    case SYS_brk:
        shadow_pre_brk(drcontext, info);
        break;
    default:
        /* do nothing */
        break;
    }
#endif
}


void
shadow_post_syscall(void *drcontext, umbra_info_t *info, int sysnum)
{
#ifndef LINUX_KERNEL
    if (proc_info.client.post_syscall != NULL) {
      proc_info.client.post_syscall(drcontext, info, sysnum);
    }
    switch (sysnum) {
    case SYS_mmap:
        shadow_post_mmap(drcontext, info);
        break;
    case SYS_munmap:
        shadow_post_munmap(drcontext, info);
        break;
    case SYS_mremap:
        shadow_post_mremap(drcontext, info);
        break;
    case SYS_brk:
        shadow_post_brk(drcontext, info);
    default:
        break;
    }
#endif
}


void
shadow_module_load(void *drcontext, 
                   umbra_info_t *umbra_info,
                   const module_data_t *module_info, 
                   bool loaded)
{
    /* Do nothing */
}


void
shadow_module_unload(void *drcontext, 
                     umbra_info_t *umbra_info,
                     const module_data_t *module_info)
{
    /* do nothing */
}


static void
get_proc_mem_info(void)
{
#ifdef LINUX_KERNEL
    MAX_MMAP_ADDR = 0xffffffffffffffff;
    MAX_MMAP_MASK = (MAX_MMAP_ADDR >> 33) - 1;
    next_shadow_address = KERNEL_HOLE_START;
#else
    void *pc;

    /* get system heap module */
    proc_info.heap_brk  = sbrk(0);

    /* get max mmap address */
#ifdef X64    
    MAX_MMAP_ADDR = (reg_t)1 << 33;
    while (true) {
        pc = mmap((void *)((MAX_MMAP_ADDR << 1) - PAGE_SIZE), 
                  PAGE_SIZE, PROT_NONE, 
                  MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
        if (pc == MAP_FAILED)
            break;
        DR_ASSERT(munmap(pc, PAGE_SIZE) == 0);
        MAX_MMAP_ADDR = MAX_MMAP_ADDR << 1;
    }
    MAX_MMAP_MASK = (MAX_MMAP_ADDR >> 33) - 1;
#else
    /* FIXME: find the 32-bit MAX_MMAP_ADDR */
#endif
#endif
}


static void
reserve_app_mem_space(void)
{
#ifdef LINUX_KERNEL
    /* TODO(peter): Initally we could use traverse_page_table_contiguous to add
     * all of the existing kernel regions. We still have to implement lazy
     * shadow allocation, so I'm using that for everything now. We still need to
     * allocate a single map for the instrument_thread_init code to work properly.
     */
     DR_ASSERT(memory_map_app_add(KERNEL_TEXT_BASE,
                                  KERNEL_TEXT_BASE + KERNEL_TEXT_SIZE,
                                  false));
#else
    void *pc   = NULL;
    dr_mem_info_t info;

    /* iterate memory backwards, i.e. from 0xff****ff to 0x00****00 */
    do {
        DR_ASSERT(dr_query_memory_ex(pc - 1, &info));
        pc = info.base_pc;
        switch(info.type) {
        case DR_MEMTYPE_FREE:  /* Unallocated memory */
            break;             /* Simply skip        */
        case DR_MEMTYPE_IMAGE: /* Fall through       */
        case DR_MEMTYPE_DATA:
            /* Allocated memory, reserve app space for them */
            DR_ASSERT(memory_map_app_add(info.base_pc, 
                                         info.base_pc + info.size,
                                         false));
            break;
        default:
            DR_ASSERT(false);
        }
    } while (pc != NULL);
#endif
}

#ifndef LINUX_KERNEL
static void
memory_mod_app_init(void)
{
    void *pc   = NULL;
    dr_mem_info_t info;

    /* iterate memory backwards, i.e. from 0xff****ff to 0x00****00 */
    do {
        DR_ASSERT(dr_query_memory_ex(pc - 1, &info));
        pc = info.base_pc;
        switch(info.type) {
        case DR_MEMTYPE_FREE:  /* Unallocated memory */
            break;             /* Simply skip        */
        case DR_MEMTYPE_IMAGE: /* Fall through       */
        case DR_MEMTYPE_DATA:
            /* XXX: I should not shadow the DR's memory, but DR starts 
             * interpreting code from some DR code, i.e. dynamorio_take_over,
             * so have to shadow all memory.
             */
            /* Allocated shadow memory for exist app memory */
            if (info.size == PAGE_SIZE && info.prot == DR_MEMPROT_NONE)
                continue;
            if (memory_map_app_lookup(proc_info.maps, info.base_pc))
                memory_mod_app_add(info.base_pc, info.size);
            break;
        default:
            DR_ASSERT(false);
        }
    } while (pc != NULL);
    proc_info.stack_top = NULL;
}
#endif

static void
client_init_page(umbra_info_t *umbra, void *address)
{
    if (proc_info.client.shadow_page_alloc) {
        proc_info.client.shadow_page_alloc(
            umbra,
            (void*) ALIGN_BACKWARD(address, PAGE_SIZE),
            PAGE_SIZE);
    }
}

void
shadow_init(void)
{
    init_map_hash_table();
    get_proc_mem_info();
    reserve_app_mem_space();
    reserve_shd_mem_space();
#ifdef LINUX_KERNEL
    global_l4 = page_address(pfn_to_page(pagepool_alloc(pagepool)));
    memset(global_l4, 0,
           sizeof(generic_page_table_entry_t) * PAGE_TABLE_ENTIRES_PER_LEVEL);
    global_ro_pfn = pagepool_alloc(pagepool);
    client_init_page(umbra_get_info(),
                     page_address(pfn_to_page(global_ro_pfn)));
#else
    /* For now, on linux, we don't use memory mods. We just allocate pages for
     * shadow memory on demand.
     */
    memory_mod_app_init();
#endif
}

static ssize_t
show_pagepool_stats(int cpu, char *buf) {
    char *orig_buf = buf;
    buf += sprintf(buf, "free_pages: %lu\n", pagepool->free_pages);
    return buf - orig_buf;
}

#ifdef LINUX_KERNEL

static dr_stats_t shadow_stats;

int
shadow_kernel_init(void)
{
    if (dr_stats_init(&shadow_stats)) {
        return -ENOMEM;
    }
    if (dr_cpu_stat_alloc(&shadow_stats, "pagepool_stats", show_pagepool_stats, THIS_MODULE)) {
        goto stats_free;
    }
    pagepool = pagepool_kernel_init(SHADOW_MEMORY_SIZE / PAGE_SIZE);
    if (!pagepool) {
        goto stats_free;
    }
    return 0;
stats_free:
    dr_stats_free(&shadow_stats);
    return -ENOMEM;
}

void
shadow_kernel_exit(void)
{
    dr_stats_free(&shadow_stats);
    pagepool_kernel_exit(pagepool);
}

#endif


static void
shadow_memory_modules_remove(memory_mod_t *mods)
{
    memory_mod_t *temp;
    while (mods != NULL) {
        temp = mods;
        mods = mods->next;
        memory_mod_app_remove(temp->app_base, 
                              temp->app_end - temp->app_base);
    }
}

#ifdef LINUX_KERNEL
static void
return_to_pagepool(unsigned long pfn, void *arg)
{
    if (pfn != global_ro_pfn) {
        pagepool_free(pagepool, pfn);
    }
}

static void
remove_shadow_mappings(void)
{
    struct task_struct *g, *p;
    generic_page_table_entry_t *l4;
    int i;
    do_each_thread(g, p) {
        if (!p->mm) {
            continue;
        }
        l4 = (generic_page_table_entry_t*) p->mm->pgd;
        for (i = 0; i < PAGE_TABLE_ENTIRES_PER_LEVEL; i++) {
            if (global_l4[i].present) {
                memset(&l4[i], 0, sizeof(generic_page_table_entry_t));
                DR_ASSERT(!l4[i].present);
            }
        }
    } while_each_thread(g, p);
}
#endif

void
shadow_exit(void)
{
    memory_map_t *map;

    dr_mutex_lock(proc_info.mutex);
    map = proc_info.maps;
    while (map != NULL) {
        if (map->mods != NULL)
            shadow_memory_modules_remove(map->mods);
        proc_info.maps = map->next;
        dr_global_free(map, sizeof(memory_map_t));
        map = proc_info.maps;
    }
    memory_map_hash_remove(app_map_hash);
    memory_map_hash_remove(shd_map_hash);
    memory_map_prot_remove();
#ifdef LINUX_KERNEL
    remove_shadow_mappings();
    depth_first_traverse_page_table(global_l4, return_to_pagepool, NULL);
    pagepool_free(pagepool, global_ro_pfn);
#endif
    dr_mutex_unlock(proc_info.mutex);
}


instrlist_t *
decode_fault_code_fragment(void *drcontext, 
                           app_pc start_pc, 
                           app_pc fault_pc)
{
    instrlist_t *ilist;
    instr_t     *instr;
    app_pc       pc;

    ilist = instrlist_create(drcontext);
    pc = start_pc;
    while (pc < fault_pc) {
        instr = instr_create(drcontext);
        instr_init(drcontext, instr);
        pc = decode(drcontext, pc, instr);
        instrlist_append(ilist, instr);
    }
    return ilist;
}

#ifndef LINUX_KERNEL
static ref_cache_t *
get_ref_cache(void *drcontext, 
              umbra_info_t *umbra_info,
              app_pc start_pc,
              app_pc fault_pc)
{
    instrlist_t *ilist;
    instr_t *instr;
    ref_cache_t *cache = NULL;
    opnd_t opnd;
    void  *addr;
    
    ilist = decode_fault_code_fragment(drcontext, start_pc, fault_pc);
    for (instr  = instrlist_last(ilist);
         instr != NULL && cache == NULL;
         instr  = instr_get_prev(instr)) {
        if (instr_get_opcode(instr) != OP_add)
            continue;
        opnd = instr_get_src(instr, 1);
        if (!opnd_is_reg(opnd))
            continue;
        opnd = instr_get_src(instr, 0);
        if (!opnd_is_abs_addr(opnd) &&
            !opnd_is_rel_addr(opnd))
            continue;
        addr = opnd_get_addr(opnd);
        if (!addr_in_ref_cache(umbra_info, addr))
            continue;
        cache = (ref_cache_t *)
            (addr - offsetof(ref_cache_t, offset));
    }
    instrlist_clear_and_destroy(drcontext, ilist);
    if (cache == NULL) {
        dr_printf("Error\n");
#ifndef LINUX_KERNEL
        sleep(20);
#endif
    }
    DR_ASSERT(cache != NULL);
    return cache;
}

static reg_t 
compute_app_memory_size(reg_t shd_size)
{
    int diff;
    diff = (proc_info.client.app_unit_bits - 
            proc_info.client.shd_unit_bits);
    if (diff > 0)
        return (shd_size << diff);
    else if (diff < 0)
        return (shd_size >> (-diff));
    return shd_size;
}


static void *
compute_app_memory_addr(void *shd_addr, reg_t offset)
{
    return (void *)
        (compute_app_memory_size((reg_t)shd_addr - offset));
}

static void
set_reg_in_mcontext(dr_mcontext_t *mcontext,
                    reg_id_t reg,
                    reg_t    value)
{
    switch (reg) {
    case REG_XAX:
        mcontext->xax = value;
        break;
    case REG_XBX:
        mcontext->xbx = value;
        break;
    case REG_XCX:
        mcontext->xcx = value;
        break;
    case REG_XDX:
        mcontext->xdx = value;
        break;
    case REG_XDI:
        mcontext->xdi = value;
        break;
    case REG_XSI:
        mcontext->xsi = value;
        break;
    case REG_XBP:
        mcontext->xbp = value;
        break;
    case REG_XSP:
        mcontext->xsp = value;
        break;
#ifdef X64
    case REG_R8:
        mcontext->r8  = value;
        break;
    case REG_R9:
        mcontext->r9  = value;
        break;
    case REG_R10:
        mcontext->r10 = value;
        break;
    case REG_R11:
        mcontext->r11 = value;
        break;
    case REG_R12:
        mcontext->r12 = value;
        break;
    case REG_R13:
        mcontext->r13 = value;
        break;
    case REG_R14:
        mcontext->r14 = value;
        break;
    case REG_R15:
        mcontext->r15 = value;
        break;
#endif
    default:
        DR_ASSERT(false);
    }
}

static void
update_mcontext(void *drcontext, 
                umbra_info_t *umbra_info, 
                dr_siginfo_t *siginfo, 
                void *shd_addr)
{
    instr_t instr;
    opnd_t opnd;
    int num_opnds, i;

    instr_init(drcontext, &instr);
    decode(drcontext, siginfo->raw_mcontext.pc, &instr);
    
    num_opnds = instr_num_srcs(&instr);
    for (i = 0; i < num_opnds; i++) {
        opnd = instr_get_src(&instr, i);
        if (!opnd_is_memory_reference(opnd))
            continue;
        if (siginfo->access_address !=
            opnd_compute_address(opnd, &siginfo->raw_mcontext))
            continue;
        DR_ASSERT(opnd_is_base_disp(opnd) &&
                  opnd_get_index(opnd) == REG_NULL);
        set_reg_in_mcontext(&siginfo->raw_mcontext,
                            opnd_get_base(opnd),
                            (reg_t)shd_addr - opnd_get_disp(opnd));
        instr_free(drcontext, &instr);
        return;
    }
    num_opnds = instr_num_dsts(&instr);
    for (i = 0; i < num_opnds; i++) {
        opnd = instr_get_dst(&instr, i);
        if (!opnd_is_memory_reference(opnd))
            continue;
        if (siginfo->access_address !=
            opnd_compute_address(opnd, &siginfo->raw_mcontext))
            continue;
        DR_ASSERT(opnd_is_base_disp(opnd) &&
                  opnd_get_index(opnd) == REG_NULL);
        set_reg_in_mcontext(&siginfo->raw_mcontext,
                            opnd_get_base(opnd),
                            (reg_t)shd_addr - opnd_get_disp(opnd));
        instr_free(drcontext, &instr);
        return;
    }
}

static void
expand_app_stack(void)
{
    memory_mod_t *mod, *new_mod;
    reg_t size = PAGE_SIZE << 10;
    int i;

    mod = memory_mod_app_lookup(proc_info.stack_top);
    new_mod = dr_global_alloc(sizeof(memory_mod_t));
    new_mod->app_end  = proc_info.stack_top;
    proc_info.stack_top -= size;
    new_mod->app_base = proc_info.stack_top;
    memory_mod_shd_add(new_mod);
    mod->app_base = new_mod->app_base;
    for (i = 0; i < MAX_NUM_SHADOWS; i++) {
        mod->shd_base[i] = new_mod->shd_base[i];
    }
    dr_global_free(new_mod, sizeof(memory_mod_t));
}
#endif

#ifdef LINUX_KERNEL

static void
create_pte(generic_page_table_entry_t *entry, vm_access_t *access,
           pfn_t next_pfn, bool zero_entry)
{
    /* TODO(peter): Are we setting this to the right kind of memory wrt caching?
     */
    memset(entry, 0, sizeof(generic_page_table_entry_t));
    entry->writable = access->writable;
    entry->user = access->user;
    entry->not_executable = access->executable;
    entry->next_pfn = next_pfn;
    if (zero_entry) {
        memset(follow_page_table_entry(entry), 0, PAGE_TABLE_SIZEOF_LEVEL);
    }
    /* TODO(peter): AFAIK, this fence is necessary because we don't want
     * processors to see that this entry is present before we finish creating
     * the mapping. */
    asm volatile("mfence");
    entry->present = 1;
}

static void
invlpg(void *address)
{
    asm volatile ("invlpg %0" :: "m" (address));
}

static vm_access_t rw_access = {
    .writable = true,
    .executable = false,
    .user = false,
};

static vm_access_t ro_access = {
    .writable = false,
    .executable = false,
    .user = false,
};

static void
insert_page_table_mapping(umbra_info_t *umbra,
                          generic_page_table_entry_t *l4,
                          pagepool_t *pool,
                          void *address,
                          bool is_write)
{
    vm_region_t region;
    generic_page_table_entry_t *parent;
    int parent_level;
    virtual_address_t va;
    uint64 pfn;
    
    va.virtual_address = address;

    /* Check if this has already mapped in l4. If it is, copy in the global
     * entry.
     * TODO(peter): If this becomes a performance bottleneck (unlikely), then we
     * can do the more common check first (i.e., level 1 failing).
     */
    if (!l4[va.l4_index].present && global_l4[va.l4_index].present) {
        l4[va.l4_index] = global_l4[va.l4_index];
    }

    page_table_get_page(l4, address, &region, &pfn,
                        &parent, &parent_level);

    if (!region.present) {
        DR_ASSERT(parent_level <= 4 && parent_level >= 1);
        switch(parent_level) {
        case 4: create_pte(parent, &rw_access, pagepool_alloc(pool), true);
                global_l4[va.l4_index] = *parent;
                parent = &follow_page_table_entry(parent)[va.l3_index];
                umbra->num_pages_for_page_table++;
        case 3: create_pte(parent, &rw_access, pagepool_alloc(pool), true);
                parent = &follow_page_table_entry(parent)[va.l2_index];
                umbra->num_pages_for_page_table++;
        case 2: create_pte(parent, &rw_access, pagepool_alloc(pool), true);
                parent = &follow_page_table_entry(parent)[va.l1_index];
                umbra->num_pages_for_page_table++;
        case 1:
            if (is_write) {
                create_pte(parent, &rw_access, pagepool_alloc(pool), false);
                client_init_page(umbra, address);
                umbra->num_pages_for_shadow++;
            } else {
                create_pte(parent, &ro_access, global_ro_pfn, false);
                umbra->num_ro_pages_in_shadow++;
            }
        }
        /* No need to vall invlpg(address) because x86 does not cache
         * non-present mappings.
         */
    } else if (is_write) {
        DR_ASSERT(parent_level == 1);     
        if (!region.access.writable) {
            create_pte(parent, &rw_access, pagepool_alloc(pool), false);
            invlpg(address);
            client_init_page(umbra, address);
            umbra->num_ro_pages_in_shadow--;
            umbra->num_pages_for_shadow++;
        } else {
            invlpg(address);
        }
    }

#ifdef DEBUG
    DR_ASSERT(page_table_get_page(l4, address, &region, &pfn, &parent,
                                  &parent_level));
    DR_ASSERT(region.present);
    DR_ASSERT(!is_write || region.access.writable);
#endif
}

static bool
page_fault_is_write(dr_interrupt_t *interrupt)
{
    /* See section 6.15 in Intel 3A. */
    return TESTALL(0x2, interrupt->frame->error_code);
}

bool
shadow_interrupt(umbra_info_t *umbra_info, dr_interrupt_t *interrupt)
{
    byte *address;
    if (interrupt->vector != VECTOR_PAGE_FAULT) {
        return true;
    }
    address = (byte*) get_cr2();
    if (!possible_shadow_address(address)) {
        return true;
    }
    dr_mutex_lock(proc_info.mutex);
    insert_page_table_mapping(umbra_info, get_l4_page_table(), pagepool,
                              address,
                              page_fault_is_write(interrupt));
    dr_mutex_unlock(proc_info.mutex);

    return false;
}
#elif defined(LINUX)
dr_signal_action_t
shadow_signal(void *drcontext, umbra_info_t *umbra_info, dr_siginfo_t *siginfo)
{
    void  *addr;
    memory_map_t *map;
    dr_signal_action_t action;
    ref_cache_t *cache;
    int i;

    umbra_info->num_sigs++;

    if (proc_info.client.signal_handler != NULL)
        return proc_info.client.signal_handler(drcontext, siginfo, umbra_info);

    if (siginfo->raw_mcontext_valid == false ||
        (siginfo->sig != SIGSEGV && siginfo->sig != SIGBUS))
        return DR_SIGNAL_DELIVER;

    /* the sig is not from a fragment, I have no way to 
     * find the right offset, notify the user 
     */
    if (siginfo->fault_fragment_info.cache_start_pc == NULL)
        return DR_SIGNAL_DELIVER;
    addr = siginfo->access_address;
    action = DR_SIGNAL_SUPPRESS;

    dr_mutex_lock(proc_info.mutex);
    cache = get_ref_cache(drcontext, umbra_info,
                          siginfo->fault_fragment_info.cache_start_pc,
                          siginfo->raw_mcontext.pc);
    /* get original app addr */
    /* XXX: If there are two offset, which one I should use? */
    for (i = 0; i < MAX_NUM_SHADOWS; i++) {
        addr = compute_app_memory_addr(addr, cache->offset[i]);
        map  = memory_map_app_lookup(proc_info.maps, addr);
        if (map != NULL) 
            break;
    }

    if (map == NULL)
        action = DR_SIGNAL_DELIVER;
    else {
        cache->tag    = (reg_t)map->app_base;
        for (i = 0; i < MAX_NUM_SHADOWS; i++) {
            cache->offset[i] = map->offset[i];
        }
    }

    /* check if valid app memory */
    if (action == DR_SIGNAL_SUPPRESS) {
        if (memory_mod_app_lookup(addr) == NULL &&
            !memory_mod_app_add(addr, 0)) {
            if (addr <  proc_info.stack_top &&
                addr >= proc_info.stack_top - (PAGE_SIZE << 10)) 
                expand_app_stack();
            else 
                action = DR_SIGNAL_DELIVER;
        }
    }

    /* correct the shd_addr if translation was wrong */
    if (action == DR_SIGNAL_SUPPRESS) {
        void *shd_addr[MAX_NUM_SHADOWS];
        compute_shd_memory_addr(addr, shd_addr);
        dr_fprintf(umbra_info->log, 
                   "signal received at %p (%p) for accessing %p (%p->%p)\n",
                   siginfo->fault_fragment_info.tag, 
                   siginfo->fault_fragment_info.cache_start_pc,
                   addr, siginfo->access_address, shd_addr[0]);
        if (shd_addr[0] != siginfo->access_address) {
            /* wrong translation */
            update_mcontext(drcontext, umbra_info, siginfo, shd_addr[0]);
            cache->tag += 1;
            if (siginfo->fault_fragment_info.is_trace)
                dr_delete_fragment(drcontext,
                                   siginfo->fault_fragment_info.tag);
        }
    }
    
    dr_mutex_unlock(proc_info.mutex);
    return action;
}

#elif defined(WINDOWS)

bool
shadow_exception(void           *drcontext, 
                 umbra_info_t   *umbra_info, 
                 dr_exception_t *excpt)
{
    return true;
}

#endif /* LINUX */
