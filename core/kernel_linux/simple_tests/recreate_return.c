/* This tests recreating return values that are overwritten by the x86 interrupt
 * stack frame push. This happens when an interrupt arrives after the pop part
 * of the ret emulation.
 *
 * This test is pretty weak because it hopes that an interrupt
 * arrives at the right time.
 * TODO(peter): This test is useless because (1) interrupts are disabled while
 * we run these tests and (2) it's quite unlikely that we'd get interrupts at
 * the right places. It would be nice to have a hook into some exception handler
 * that we could trigger after a certain number of instructions have run or
 * something. I'm going to leave this code here because it was useful in
 * debugging the return recreation; I just stuck it in the controller kernel
 * module's kstats ioctl (which runs with interrupts enabled) and changed the
 * while loop to while(true).
 */

#if 0
static void testa(void) { }
static void testb(void) { }

static void test_recreate_return(void) {
    int j = 0;
    while (true) {
        j++;
        if (j % 2 == 0) {
            /* Force interrupt stack frame alignment by doing rsp -= 8 before
             * testa() and rsp -= 0 before testb(). 
             * TODO(peter): This whole thing should be written in assembly
             * because popping rax with optimizations enabled could crash (i.e.
             * we're changing rsp and rax without telling the compiler),
             */
            asm volatile ("push %rax");
            testa();
            asm volatile ("pop %rax");
        } else {
            testb();
        }
    }
}
#endif
