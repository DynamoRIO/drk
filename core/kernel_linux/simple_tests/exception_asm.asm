#include "asm_defines.asm"
START_FILE

        DECLARE_FUNC(exception_main)
GLOBAL_LABEL(exception_main:)
        mov rdi, rsp
        inc rdi
        mov rsi, HEX(2)
        mov rbp, HEX(3)
        /* mov rsp, HEX(4)*/
        mov rbx, HEX(5)
        mov rdx, HEX(6)
        mov rcx, HEX(7)
        mov rax, HEX(8)
        mov r8,  HEX(9)
        mov r9,  HEX(a)
        mov r10, HEX(b)
        mov r11, HEX(c)
        mov r12, HEX(d)
        mov r13, HEX(e)
        mov r14, HEX(f)
        mov r15, HEX(10)
        /* generate an exception without an error code */
        int3
        /* generate an exception with an error code */
        movq rdi, [rbx]
        ret

        END_FUNC(FUNCNAME)
