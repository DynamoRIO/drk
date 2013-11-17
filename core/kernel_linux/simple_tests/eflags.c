/* **********************************************************
 * Copyright (c) 2005-2008 VMware, Inc.  All rights reserved.
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

/*
 *  Modified by Peter Feiner (peter@cs.toronto.edu) in 2011.
 */

#include "basic_types.h"
#include "simple_tests.h"

/* asm routine */
void test_eflags_pos(uint pos);

/*
 * eflags we care about:
 *  11 10  9  8  7  6  5  4  3  2  1  0
 *  OF DF       SF ZF    AF    PF    CF 
 */
const char *flags[] = {
    "CF", "", "PF", "", "AF", "", "ZF", "SF", "",  "", "DF", "OF"
};

const uint eflag_pos[] = {
    0, 2, 4, 6, 7, 10, 11
};
#define NUM_FLAGS (sizeof(eflag_pos)/sizeof(eflag_pos[0]))

void
test_flag(uint eflags, uint pos, bool set)
{
    if ((set && ((eflags & (1 << pos)) == 0)) ||
        (!set && ((eflags & (1 << pos)) != 0)))
        DR_ASSERT(false);
}

void
eflags_main(void)
{
    uint i;

    for (i=0; i<NUM_FLAGS; i++) {
        test_eflags_pos(eflag_pos[i]);
    }
}
