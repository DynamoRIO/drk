#include "asm_defines.asm"
START_FILE

DECL_EXTERN(test_flag)

#define FUNCNAME test_eflags_pos
        DECLARE_FUNC(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        /* We don't bother w/ SEH64 directives, though we're an illegal leaf routine! */
        mov      REG_XCX, ARG1
        push     REG_XCX /* save */
        CALLC1(set_flag, REG_XCX)
        mov      REG_XCX, PTRSZ [REG_XSP]
        PUSHF
        pop      REG_XAX
        /* having DF set messes up printing for x64 */
        push     0
        POPF
        CALLC3(test_flag, REG_XAX, REG_XCX, 1)

        mov      REG_XCX, PTRSZ [REG_XSP]
        CALLC1(clear_flag, REG_XCX)
        mov      REG_XCX, PTRSZ [REG_XSP]
        PUSHF
        pop      REG_XAX
        /* having DF set messes up printing for x64 */
        push     0
        POPF
        CALLC3(test_flag, REG_XAX, REG_XCX, 0)

        pop      REG_XCX /* clean up */
        ret
        END_FUNC(FUNCNAME)

    /* void set_flag(uint pos) */
#undef FUNCNAME
#define FUNCNAME set_flag
        DECLARE_FUNC(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        /* We don't bother w/ SEH64 directives, though we're an illegal leaf routine! */
        PUSHF
        pop      REG_XAX
        mov      REG_XCX, ARG1
        mov      REG_XDX, 1
        shl      REG_XDX, cl
        or       REG_XAX, REG_XDX
        push     REG_XAX
        POPF
        ret
        END_FUNC(FUNCNAME)

    /* void clear_flag(uint pos) */
#undef FUNCNAME
#define FUNCNAME clear_flag
        DECLARE_FUNC(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        /* We don't bother w/ SEH64 directives, though we're an illegal leaf routine! */
        PUSHF
        pop      REG_XAX
        mov      REG_XCX, ARG1
        mov      REG_XDX, 1
        shl      REG_XDX, cl
        not      REG_XDX
        and      REG_XAX, REG_XDX
        push     REG_XAX
        POPF
        ret
        END_FUNC(FUNCNAME)

END_FILE
