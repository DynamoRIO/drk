/* *******************************************************************************
 * Copyright (c) 2011 Massachusetts Institute of Technology  All rights reserved.
 * *******************************************************************************/

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
 * * Neither the name of MIT nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL MIT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef DR_CLIENT_TOOLS_H
#define DR_CLIENT_TOOLS_H

/* Common definitions for test suite clients. */

/* Provide assertion macros that only use dr_fprintf.  The asserts provided by
 * dr_api.h cannot be used in the test suite because they pop up message boxes
 * on Windows.
 */
#define ASSERT_MSG(x, msg) \
    ((void)((!(x)) ? \
            (dr_fprintf(STDERR, "ASSERT FAILURE: %s:%d: %s (%s)", \
                     __FILE__,  __LINE__, #x, msg), \
             dr_abort(), 0) : 0))
#define ASSERT(x) ASSERT_MSG(x, "")

/* Redefine DR_ASSERT* to alias ASSERT*.  This makes it easier to import sample
 * clients into the test suite. */
#undef DR_ASSERT_MSG
#undef DR_ASSERT
#define DR_ASSERT_MSG ASSERT_MSG
#define DR_ASSERT ASSERT

/* Standard pointer-width integer alignment macros.  Not provided by dr_api.h.
 */
#define ALIGN_BACKWARD(x, alignment) \
        (((ptr_uint_t)x) & (~((ptr_uint_t)(alignment)-1)))
#define ALIGN_FORWARD(x, alignment) \
        ((((ptr_uint_t)x) + (((ptr_uint_t)alignment)-1)) & \
         (~(((ptr_uint_t)alignment)-1)))

#endif /* DR_CLIENT_TOOLS_H */