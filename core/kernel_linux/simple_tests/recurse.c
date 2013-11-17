/* **********************************************************
 * Copyright (c) 2003 VMware, Inc.  All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */


/* Modified by Peter Feiner (peter@cs.toronto.edu) in 2011. */

#include <linux/mm.h>
#include <linux/string.h>

#include "simple_tests.h"


#define GOAL 25

static const char* expected =
    "foo 25\n"
    "bar 24\n"
    "foo 23\n"
    "bar 22\n"
    "foo 21\n"
    "bar 20\n"
    "foo 19\n"
    "bar 18\n"
    "foo 17\n"
    "bar 16\n"
    "foo 15\n"
    "bar 14\n"
    "foo 13\n"
    "bar 12\n"
    "foo 11\n"
    "bar 10\n"
    "foo 9\n"
    "bar 8\n"
    "foo 7\n"
    "bar 6\n"
    "foo 5\n"
    "bar 4\n"
    "foo 3\n"
    "bar 2\n"
    "foo 1\n"
    "bar 0\n"
    "25 326\n";

typedef struct {
    char *data;
    unsigned long length;
    unsigned long capacity;
} buffer_t;

static void buffer_init(buffer_t *buffer) {
    buffer->length = 0;
    buffer->capacity = strlen(expected) + 1;
    buffer->data = kmalloc(buffer->capacity, GFP_ATOMIC);
    DR_ASSERT(buffer != NULL);
}

static void free_buffer(buffer_t* buffer) {
    kfree(buffer->data);
}

static void print_buffer(buffer_t* buffer, const char* fmt, ...) {
    char* start = buffer->data + buffer->length;
    unsigned long n = buffer->capacity - buffer->length;
    va_list args;
    va_start(args, fmt);
    /* don't add +1 b/c we want to overwrite null terminators. */
    buffer->length += vsnprintf(start, n, fmt, args);
    va_end(args);
    DR_ASSERT(buffer->length <= buffer->capacity);
}

static int foo(buffer_t* buffer, int n);

static int bar(buffer_t* buffer, int n)
{
    print_buffer(buffer, "bar %d\n", n);
    if (n==0) return 1;
    if (n % 2 == 0)
        return n + foo(buffer, n-1);
    if (n % 2 == 1)
        return n + bar(buffer, n-1);
    print_buffer(buffer, "\tdone with bar %d\n", n);
    return 0;
}

static int foo(buffer_t* buffer, int n)
{
    print_buffer(buffer, "foo %d\n", n);
    if (n==0) return 1;
    if (n % 2 == 0)
        return n + foo(buffer, n-1);
    if (n % 2 == 1)
        return n + bar(buffer, n-1);
    print_buffer(buffer, "\tdone with foo %d\n", n);
    return 0;
}


void
recurse_main(void) {
    int i, t = 0;
    buffer_t buffer;
    buffer_init(&buffer);
    for (i=GOAL; i<=GOAL; i++) {
        t = foo(&buffer, i);
        print_buffer(&buffer, "%d %d\n", i, t);
    }
    DR_ASSERT_EQ(0, strcmp(expected, buffer.data));
    free_buffer(&buffer);
}

