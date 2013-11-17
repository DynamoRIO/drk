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
 *     dr_client -- dr_client.c
 *
 * Description:
 *     client file to register Umbra callbacks with DynamoRIO
 *
 * Author: 
 *     Qin Zhao
 * 
 */


//#include <unistd.h>       /* sleep */

#ifdef LINUX_KERNEL
# include <linux/module.h>
#endif
#include "dr_api.h"
#include "umbra.h"

#ifdef LINUX_KERNEL
MODULE_LICENSE("Dual BSD/GPL");
#endif


/*---------------------------------------------------------------------*
 *            Event Functions Declaration & Implementation             *
 *---------------------------------------------------------------------*/


static void
event_init(client_id_t id)
{
    dr_log(NULL, LOG_ALL, 1, "Client 'Umbra' initializing\n");
    umbra_init(id);
}


static void
event_exit(void)
{
    dr_log(NULL, LOG_ALL, 1, "Client 'Umbra' exit\n");
    umbra_exit();
}


static dr_emit_flags_t
event_bb(void *drcontext, 
         void *tag, 
         instrlist_t *bb,
         bool  for_trace, 
         bool  translating)
{
    dr_log(drcontext, LOG_ALL, 2, "bb: "PFX" %d %d\n", 
           tag, for_trace, translating);
    return umbra_basic_block(drcontext, tag, bb, for_trace, translating);
}


static dr_emit_flags_t
event_trace(void *drcontext, 
            void *tag, 
            instrlist_t *trace,
            bool  translating)
{
    dr_log(drcontext, LOG_ALL, 2, "trace: "PFX" %d\n", 
           tag, translating);
    return umbra_trace(drcontext, tag, trace, translating);
}


static dr_custom_trace_action_t
event_end_trace(void *drcontext, 
                void *trace_tag, 
                void *next_tag)
{
    dr_log(drcontext, LOG_ALL, 2, "end_trace "PFX", "PFX"\n", 
           trace_tag, next_tag);  
    return umbra_end_trace(drcontext, trace_tag, next_tag);
}


static void
event_delete(void *drcontext, void *tag)
{
    dr_log(drcontext, LOG_ALL, 2, "delete "PFX"\n", tag);
    umbra_delete(drcontext, tag);
}


static void
event_restore_state(void *drcontext, 
                    void *tag, 
                    dr_mcontext_t *mcontext,
                    bool restore_memory, 
                    bool app_code_consistent)
{
    dr_log(drcontext, LOG_ALL, 2, "restore_state "PFX"\n", tag);
    umbra_restore_state(drcontext, tag, mcontext, 
                        restore_memory, app_code_consistent);
}


static void
event_thread_init(void *drcontext)
{
    dr_log(drcontext, LOG_ALL, 1, "Client 'Umbra' thread init\n");
    umbra_thread_init(drcontext);
}


static void
event_thread_exit(void *drcontext)
{
    dr_log(drcontext, LOG_ALL, 2, "Client 'Umbra' thread exit\n");
    umbra_thread_exit(drcontext);
}


static void
event_fork_init(void *drcontext)
{
    dr_log(NULL, LOG_ALL, 2, "Client 'Umbra' fork init\n");
    umbra_fork_init(drcontext);
}


static void
event_module_load(void *drcontext, 
                  const module_data_t *info,
                  bool loaded)
{
    dr_log(drcontext, LOG_ALL, 2, "Load module "PFX"\n", info);
    umbra_module_load(drcontext, info, loaded);
}


static void
event_module_unload(void *drcontext, const module_data_t *info)
{
    dr_log(drcontext, LOG_ALL, 2, "Unload module: "PFX"\n", info);
    umbra_module_unload(drcontext, info);
}


static bool 
event_filter_syscall(void *drcontext, int sysnum)
{
    dr_log(drcontext, LOG_ALL, 2, "event_filter_syscall "PFX"\n", sysnum);
    return umbra_filter_syscall(drcontext, sysnum);
}


static bool 
event_pre_syscall(void *drcontext, int sysnum)
{
    dr_log(drcontext, LOG_ALL, 2, "event_pre_syscall "PFX"\n", sysnum);
    return umbra_pre_syscall(drcontext, sysnum);
}


static void 
event_post_syscall(void *drcontext, int sysnum)
{
    dr_log(drcontext, LOG_ALL, 2, "event_post_syscall "PFX"\n", sysnum);
    umbra_post_syscall(drcontext, sysnum);
}

#ifdef LINUX_KERNEL

/* TODO(peter): Add some interrupt handling code here. */

static bool
event_interrupt(void *drcontext, dr_interrupt_t *interrupt)
{
    return umbra_interrupt(drcontext, interrupt);
}

#elif defined(LINUX)

static dr_signal_action_t
event_signal(void *drcontext, dr_siginfo_t *siginfo)
{
    dr_log(drcontext, LOG_ALL, 2, "Signal %d\n", siginfo->sig);
    return umbra_signal(drcontext, siginfo);
}

#else 

static bool
event_exception(void *dcontext, dr_exception_t *excpt)
{
    dr_log(drcontext, LOG_ALL, 2, "Exception\n");
    return umbra_exception(drcontext, excpt);
}

#endif /* LINUX */


/*---------------------------------------------------------------------*
 *              Exported Top Functions Implementation                  *
 *---------------------------------------------------------------------*/

DR_EXPORT void
#ifdef LINUX_KERNEL
drinit(client_id_t id)
#else
dr_init(client_id_t id)
#endif
{
    /* register all events */
    dr_register_exit_event          (event_exit);
    dr_register_bb_event            (event_bb);
    dr_register_trace_event         (event_trace);
    dr_register_end_trace_event     (event_end_trace);
    dr_register_delete_event        (event_delete);
    dr_register_restore_state_event (event_restore_state);
    dr_register_thread_init_event   (event_thread_init);
    dr_register_thread_exit_event   (event_thread_exit);
    dr_register_fork_init_event     (event_fork_init);
    dr_register_module_load_event   (event_module_load);
    dr_register_module_unload_event (event_module_unload);
    dr_register_filter_syscall_event(event_filter_syscall);
    dr_register_pre_syscall_event   (event_pre_syscall);
    dr_register_post_syscall_event  (event_post_syscall);
#ifdef LINUX_KERNEL
    dr_register_interrupt_event(event_interrupt);
#elif defined(LINUX)
    dr_register_signal_event        (event_signal);
#else
    dr_register_exception_event     (event_exception);
#endif /* LINUX */

    /* client-self init event */
    event_init(id);
}


#ifdef LINUX_KERNEL

static int __init
kernel_init(void)
{
    return umbra_kernel_init();
}

static void __exit
kernel_exit(void)
{
    umbra_kernel_exit();
}

module_init(kernel_init);
module_exit(kernel_exit);

#endif

/*---------------------------------------------------------------------*
 *                           End of dr_client.c                        *
 *---------------------------------------------------------------------*/
