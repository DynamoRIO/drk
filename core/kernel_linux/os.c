#include "globals.h"
#include "hypercall.h"
#include "hypercall_guest.h"
#include "kernel_interface.h"
#include "module_shared.h"
#include "page_table.h"
#include "string_wrapper.h"
#include "utils.h"
#include "msr.h"
#include "instr.h"
#include "decode.h"
#include "instr_create.h"
#include "fragment.h"
#include "instrlist.h"
#include "arch_exports.h"
#include "segment_descriptor.h"
#include "fcache.h"
#include "cr.h"
#include "monitor.h"

#ifdef CLIENT_INTERFACE
# include "instrument.h"
#endif

/* For inline ASM. */
#ifdef X64
# define ASM_XAX "rax"
# define ASM_XDX "rdx"
# define ASM_XBP "rbp"
# define ASM_XSP "rsp"
#else
# define ASM_XAX "eax"
# define ASM_XDX "edx"
# define ASM_XBP "ebp"
# define ASM_XSP "esp"
#endif

app_pc vsyscall_syscall_end_pc = NULL;
app_pc vsyscall_sysenter_return_pc = NULL;
app_pc vsyscall_page_start = NULL;

DR_API file_t our_stdin = 0;
DR_API file_t our_stdout = 1;
DR_API file_t our_stderr = 2;

#define MAX_NUM_CLIENT_TLS 64

#ifdef DEBUG
/* These are handy to access through the debugger. There had better not be more
 * than 100 CPUs ... */
static dcontext_t *dcontexts[100];
#endif

/* pc values delimiting dynamorio module */
static app_pc dynamorio_module_start = NULL;
static app_pc dynamorio_module_end = NULL;

/* exported for debug to avoid rank order in print_vm_area() */
/* TODO(peter): We should remove this because we don't keep track of memory
 * areas. */
vm_area_vector_t *all_memory_areas;

static bool heap_already_reserved = false;

static bool os_initilized = false;

static bool in_assert_not_ported = false;

#define ASSERT_NOT_PORTED(x) assert_not_ported(__FILE__, __LINE__, __func__)

static void assert_not_ported(const char* file, int line, const char* func) {
    print_file(STDERR, "%s:%d - %s not ported.\n", file, line, func);
    if (!in_assert_not_ported) {
        in_assert_not_ported = true;
#ifdef DEBUG
        ASSERT_NOT_IMPLEMENTED(false);
#else
        os_terminate(NULL, 0);
#endif
    } else {
        print_file(STDERR, "not ported recursion\n");
        os_terminate(NULL, 0);
    }
}

typedef enum {
    INTERRUPTED_USER,
    INTERRUPTED_FRAGMENT,
    INTERRUPTED_GENCODE,
    INTERRUPTED_DYNAMORIO,
#ifdef CLIENT_INTERFACE
    INTERRUPTED_CLIENT_LIB,
    INTERRUPTED_CLIENT_GENCODE,
#endif
} interrupted_location_t;

typedef struct {
    /* Keep a copy of the frame because part of it might be overwritten when we
     * restore the application's memory (i.e., the return address on the stack).
     */
    interrupt_stack_frame_t frame;
    /* Keep a pointer around so we can reset eflags.IF. */
    interrupt_stack_frame_t *raw_frame;
    dr_mcontext_t *mcontext;
    interrupt_vector_t vector;
    interrupted_location_t location;
} interrupt_context_t;

typedef struct {
    uint64 msr_lstar;
    system_table_register_t idtr;
    byte *vector_target[VECTOR_END];
} system_state_t;

#define MAX_NUM_PATCHES 2

typedef struct {
    system_state_t native_state;

    /* State of the pending interrupt. */
    bool pending_interrupt;
    bool use_interrupted_mcontext;
    dr_mcontext_t interrupted_mcontext;
    interrupt_vector_t interrupt_vector;
    reg_t interrupt_error_code;
    reg_t interrupt_system_xflags;
    /* True iff the interrupt frame has EFLAGS_IF set. This is relevant in
     * fcache_return because, after recording the interrupt, we iret to
     * fcache_return with IF disabled; if interrupted at the right point,
     * fcache_return will save the modified IF value in dcontext. We can't
     * simply unset IF on all interrupt stack frames for asynchronous vectors
     * because of intN.
     */
    bool interrupt_frame_if;
    bool interrupted_in_ibl;
    cache_pc interrupted_ibl_pc;
    fragment_t *interrupted_fragment;
    bool need_to_link_interrupted_fragment;

    int num_patches;
    cache_pc patch_pc[MAX_NUM_PATCHES];
    byte patch_buffer[MAX_NUM_PATCHES][INTN_LENGTH];
#ifdef DEBUG
    /* Keep track of where the interrupt came from for debugging. */
    interrupted_location_t interrupted_location;
    interrupt_stack_frame_t interrupt_stack_frame;
#endif

    /* The IDT begins at ALIGN_FORWARD(idt, proc_get_cache_line_size()). The
     * heap allocation starts at idt. */
    void *idt;

    /* The fragment we created for syscall entry. */
    fragment_t *syscall_entry_frag;
} os_thread_data_t;


#define IDT_ALIGNMENT (proc_get_cache_line_size())

#define IDT_SIZE \
    (((sizeof(gate_descriptor_t) + sizeof(system_descriptor_extra_t)) * VECTOR_END))

#define UNALIGNED_IDT_SIZE (IDT_SIZE + IDT_ALIGNMENT)

typedef struct os_local_state_t {
    local_state_extended_t state;
    struct os_local_state_t *self;
#ifdef CLIENT_INTERFACE
    void *client_tls[MAX_NUM_CLIENT_TLS];
#endif
} os_local_state_t;

/* Offsets from the GS segment. */
static tls_offset_t tls_local_state_offset;
static tls_offset_t tls_self_offset;
static tls_offset_t tls_dcontext_offset;


void
os_modules_init(void)
{
}

void
os_modules_exit(void)
{
}

void
os_module_area_init(module_area_t *ma, app_pc base, size_t view_size,
                    bool at_map, const char *filepath, uint64 inode
                    HEAPACCT(which_heap_t which))
{
    ASSERT_NOT_PORTED(false);
}

void
free_module_names(module_names_t *mod_names HEAPACCT(which_heap_t which))
{
    ASSERT_NOT_PORTED(false);
}

void
os_module_area_reset(module_area_t *ma HEAPACCT(which_heap_t which))
{
    ASSERT_NOT_PORTED(false);
}

generic_func_t
get_proc_address_ex(module_handle_t lib, const char *name, bool *is_indirect_code OUT)
{
    ASSERT_NOT_PORTED(false);
    return 0;
}

generic_func_t
get_proc_address(module_handle_t lib, const char *name)
{
    ASSERT_NOT_PORTED(false);
    return 0;
}

bool
get_named_section_bounds(app_pc module_base, const char *name,
                         app_pc *start/*OUT*/, app_pc *end/*OUT*/)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
get_module_company_name(app_pc mod_base, char *out_buf, size_t out_buf_size)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

app_pc
get_module_base(app_pc pc)
{
    return kernel_get_module_base(pc);
}

bool
is_range_in_code_section(app_pc module_base, app_pc start_pc, app_pc end_pc,
                         app_pc *sec_start /* OUT */, app_pc *sec_end /* OUT */)
{
    /* Not implemented in original Linux version. */
    ASSERT_NOT_IMPLEMENTED(false);
    return true;
}

bool
os_get_module_info(const app_pc pc, uint *checksum, uint *timestamp,
                   size_t *size, const char **name, size_t *code_size,
                   uint64 *file_version)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
module_get_nth_segment(app_pc module_base, uint n,
                       app_pc *start/*OPTIONAL OUT*/, app_pc *end/*OPTIONAL OUT*/,
                       uint *chars/*OPTIONAL OUT*/)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

size_t
module_get_header_size(app_pc module_base)
{
    ASSERT_NOT_PORTED(false);
    return 0;
}

bool
module_has_text_relocs(app_pc base)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

int
get_libc_errno(void)
{
    ASSERT_NOT_PORTED(false);
    return 0;
}

void
set_libc_errno(int val)
{
    ASSERT_NOT_PORTED(false);
}

static inline os_local_state_t *
get_tls_self(void)
{
    os_local_state_t *self = (os_local_state_t *) get_tls(tls_self_offset);
    ASSERT(self != NULL);
    return self;
}

byte *
os_get_tls_base(dcontext_t *dcontext) {
   return (byte *) get_msr(MSR_GS_BASE);
}


#define WRITE_TLS_SLOT(idx, var)                            \
    IF_NOT_HAVE_TLS(ASSERT_NOT_REACHED());                  \
    ASSERT(sizeof(var) == sizeof(void*));                   \
    asm("mov %0, %%"ASM_XAX : : "m"((var)) : ASM_XAX);      \
    asm("mov %0, %%"ASM_XDX"" : : "m"((idx)) : ASM_XDX);  \
    asm("mov %%"ASM_XAX", %"ASM_SEG":(%%"ASM_XDX")" : : : ASM_XAX, ASM_XDX);

/* FIXME: get_thread_private_dcontext() is a bottleneck, so it would be
 * good to figure out how to easily change this to use an immediate since it is
 * known at compile time -- see comments above for the _IMM versions
 */
#define READ_TLS_SLOT(idx, var)                                    \
    ASSERT(sizeof(var) == sizeof(void*));                          \
    asm("mov %0, %%"ASM_XAX : : "m"((idx)) : ASM_XAX);           \
    asm("mov %"ASM_SEG":(%%"ASM_XAX"), %%"ASM_XAX : : : ASM_XAX);  \
    asm("mov %%"ASM_XAX", %0" : "=m"((var)) : : ASM_XAX);


void
os_init(void)
{
    size_t tls_size;
    size_t tls_gs_offset;
    int i;
    tls_offset_t tls_first_offset;

    /* Call to cache output. */
    get_num_processors();
    ASSERT(get_num_processors() > 0);

    /* Initialize CPU-private data per processor. It's easy to do it here instead
     * of when each processor is initialized (i.e., during os_tls_init), so we
     * know that we can always use this data. */
    kernel_init_cpu_private_data(&tls_size, &tls_gs_offset);
    ASSERT(tls_size >= sizeof(os_local_state_t));
    ASSERT_TRUNCATE(tls_first_offset, tls_offset_t, tls_gs_offset);
    tls_first_offset = (tls_offset_t) tls_gs_offset;
    /* Check for wrapping. */
    ASSERT(tls_first_offset + sizeof(os_local_state_t) > tls_first_offset);
    tls_local_state_offset = tls_first_offset + offsetof(os_local_state_t, state);
    tls_self_offset = tls_first_offset + offsetof(os_local_state_t, self);
    tls_dcontext_offset =
        tls_first_offset + offsetof(os_local_state_t, state) + TLS_DCONTEXT_SLOT;

    for (i = 0; i < kernel_get_present_processor_count(); i++) {
        os_local_state_t* os_tls = kernel_get_cpu_private_data(i);
        memset(os_tls, 0, sizeof(os_local_state_t));
        os_tls->self = os_tls;
        ASSERT(i != INVALID_THREAD_ID);
    }
    os_initilized = true;
}

void *
get_tls(tls_offset_t tls_offs)
{
    void *val;
    reg_t idx = (reg_t) tls_offs;
    READ_TLS_SLOT(idx, val);
    return val;
}

void
set_tls(tls_offset_t tls_offs, void *value)
{
    reg_t idx = (reg_t) tls_offs;
    WRITE_TLS_SLOT(idx, value);
}

tls_offset_t
os_tls_offset(tls_offset_t tls_offs)
{
    ASSERT_TRUNCATE(tls_offs, tls_offset_t, tls_local_state_offset + tls_offs);
    return (tls_offset_t) (tls_local_state_offset + tls_offs);
}

char*
get_application_pid()
{
    return "linux_kernel_pid";
}

char *
get_application_name(void)
{
    return "Linux Kernel";
}

DYNAMORIO_EXPORT const char *
get_application_short_name()
{
    return get_application_name();
}

timestamp_t
get_timer_frequency()
{
    /* TODO(peter): Get a real number from the kernel. */
    ulong cpu_mhz = 1000;
    ulong cpu_khz = 0;
    return cpu_mhz*1000 + cpu_khz;
}

uint
query_time_seconds(void)
{
    return (uint) (query_time_millis() / 1000);
}

uint64
query_time_millis()
{
    uint64 time;
    RDTSC_LL(time);
    time /= get_timer_frequency();
    return (uint) time;
}

void
os_slow_exit(void)
{
}

void
os_fast_exit(void)
{
}

void
os_terminate(dcontext_t *dcontext, terminate_flags_t flags)
{
    if (dcontext == NULL) {
        dcontext = get_thread_private_dcontext();
    }
    if (dcontext != NULL) {
        fcache_enter_func_t go_native = get_fcache_enter_private_routine(dcontext);
        set_fcache_target(dcontext, dcontext->next_tag);
        (*go_native)(dcontext);
    }
    *((int*) 0xfffffffffffffbad) = 0;

}

int 
os_timeout(int time_in_milliseconds)
{
    ASSERT_NOT_PORTED(false);
    return 0;
}

byte *
get_segment_base(uint seg)
{
    switch (seg) {
    case SEG_FS:
        return (byte*) get_msr(MSR_FS_BASE);
    case SEG_GS:
        return (byte*) get_msr(MSR_GS_BASE);
    default:
        /* On X86_64, all other segments have 0 base address (i.e., the
        * segment selectors are ignored.)
        */
        return NULL;
    }
}

local_state_extended_t *
get_local_state_extended() {
    return (local_state_extended_t*) &get_tls_self()->state;
}

local_state_t *
get_local_state()
{
    return (local_state_t*) get_local_state_extended();
}

void
os_tls_init()
{
    /* Everything is done in os_init. */
}

void
os_tls_exit(local_state_t *local_state, bool other_thread)
{
    /* Nothing to do here. */
}

bool
os_tls_calloc(OUT uint *offset, uint num_slots, uint alignment)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
os_tls_cfree(uint offset, uint num_slots)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

/* TODO(peter): Move this to arch. */
static void
get_interrupted_context(interrupt_context_t *interrupt, dr_mcontext_t  *out)
{
    copy_mcontext(interrupt->mcontext, out);
    out->xip = interrupt->frame.xip;
    out->xsp = interrupt->frame.xsp;
    out->xflags = interrupt->frame.xflags;
}

#if 0
/* TODO(peter): Move this to arch. */
static void
redirect_iret_to_fcache_return(dcontext_t *dcontext,
                               interrupt_context_t *interrupt,
                               linkstub_t *l)
{
    interrupt->mcontext->xax = (reg_t) l;
    interrupt->frame.xip = (byte *) fcache_return_routine(dcontext);
}
#endif

/* TODO(peter): Move this to arch. */
static void
emulate_interrupt_arrival(dr_mcontext_t *mcontext, interrupt_vector_t vector,
                          byte *handler, reg_t error_code, reg_t system_xflags,
                          bool frame_if)
{
    interrupt_stack_frame_t *frame;
    reg_t xsp = mcontext->xsp;
    mcontext->xsp = ALIGN_BACKWARD(mcontext->xsp - sizeof(*frame),
                                   INTERRUPT_STACK_FRAME_ALIGNMENT);
    frame = (interrupt_stack_frame_t *) mcontext->xsp;
    ASSERT(mcontext->xsp <= xsp - sizeof(*frame));
    ASSERT(ALIGNED(mcontext->xsp,  INTERRUPT_STACK_FRAME_ALIGNMENT));

    if (!vector_has_error_code(vector)) {
        mcontext->xsp += sizeof(error_code);
    } else {
        frame->error_code = error_code;
    }
    frame->xip = mcontext->xip;
    frame->cs = get_cs();
    frame->xsp = xsp;
    frame->xflags = mcontext->xflags;
    if (frame_if) {
        frame->xflags |= EFLAGS_IF;
    } else {
        frame->xflags &= ~EFLAGS_IF;
    }
    frame->ss = get_ss();
    /* TODO(peter): Maybe we should only touch the flags that we know should be
     * touched (i.e., IF, VM, RF, and NT -- what about IOPL)? See Intel 3A
     * 6.12.1.2.
     */
    mcontext->xflags &= ~EFLAGS_SYSTEM;
    mcontext->xflags |= system_xflags;
    mcontext->xip = handler;

    /* Assume that interrupt delivery is only emulated for kernel interrupts.
     * User interrupts are handled by transferring to dispatch directly (see
     * handle_user_interrupt). */
    ASSERT(is_kernel_code(frame->xip));
    ASSERT(!is_user_address((byte*) frame->xsp));
    /* Interrupts should always be handled on a kernel stack. */
    ASSERT(!is_user_address((byte*) mcontext->xsp));
    ASSERT(!is_dynamo_address((byte*) mcontext->xsp));
}

static void
handle_user_interrupt(dcontext_t *dcontext, interrupt_context_t *interrupt)
{
    os_thread_data_t *ostd = (os_thread_data_t *) dcontext->os_field;
    STATS_INC(num_user_interrupts);
    if (!DYNAMO_OPTION(optimize_sys_call_ret)) {
        ASSERT(dcontext->whereami == WHERE_USERMODE);
    }
    ASSERT(!has_pending_interrupt(dcontext));
    ASSERT(is_user_address((byte *)interrupt->frame.xip));
    ASSERT(is_user_address((byte *)interrupt->frame.xsp));
    ASSERT(TEST(EFLAGS_IF, interrupt->frame.xflags));
    /* Guaranteed by 64-bit x86 architecture. */
    ASSERT(get_ss() == 0);
    interrupt->mcontext->pc =
        ostd->native_state.vector_target[interrupt->vector];
    dcontext->next_tag = interrupt->mcontext->pc;
    ASSERT(!is_dynamo_address(dcontext->next_tag));
    ASSERT(is_kernel_code(dcontext->next_tag));
    /* We push an error code for vectors without error codes. Because we're
     * about to transfer to dispatch using interrupt->mcontext, we have to undo
     * that push. In the kernel interrupt path, we ignore
     * interrupt->mcontext->rsp.
     * 
     * This could be avoided by having specialized code for error
     * and non-error vector entires. Indeed, this is how we used to do it (see
     * r334 of the kinst repository). We abandoned the specialization because it
     * made the C code more complex and probably afforded little performance
     * benefit.
     */
    if (!vector_has_error_code(interrupt->vector)) {
        interrupt->mcontext->rsp += sizeof(interrupt->frame.error_code);
    }
    set_last_exit(dcontext, (linkstub_t*) get_user_interrupt_entry_linkstub());
    transfer_to_dispatch(dcontext, 0 /* errno */, interrupt->mcontext);
    ASSERT_NOT_REACHED();
}

/* Determines point of interruption. We don't expect to see interrupts or
 * exceptions in kernel code that DR calls (unless it's an NMI or SMI, in which
 * case we're screwed anyways), so we don't try to identify it.
 */
static interrupted_location_t 
get_interrupted_location(dcontext_t *dcontext, interrupt_stack_frame_t *frame)
{
    cache_pc pc = (cache_pc) frame->xip;
    /* Most interrupts will happen here. */
    if (!was_kernel_interrupted(frame)) {
        if (!DYNAMO_OPTION(optimize_sys_call_ret)) {
            ASSERT(dcontext->whereami == WHERE_USERMODE);
        }
        return INTERRUPTED_USER;
    } else {
        ASSERT(dcontext->whereami != WHERE_USERMODE);
    }

    if (dcontext->whereami == WHERE_FCACHE) {
        if (in_generated_routine(dcontext, pc)) {
            return INTERRUPTED_GENCODE;
        } else if (!is_on_dstack(dcontext, (byte*) frame->xsp)) {
            /* We aren't on the dstack, so no locks should be held (if we're in
             * kernel entry gencode, then interrupts are disabled and we
             * shouldn't trigger exceptions). Hence it's safe to call in_fcache.
             */
#ifdef CLIENT_INTERFACE
            if (in_fcache(pc)) {
#else
                ASSERT(in_fcache(pc));
#endif
                return INTERRUPTED_FRAGMENT;
#ifdef CLIENT_INTERFACE
            } else {
                ASSERT(is_dynamo_address(frame->xip));
                return INTERRUPTED_CLIENT_GENCODE;
            }
#endif
        } else {
            /* At this point, we could be
             *  - in some DR code that uses exceptions (e.g., TRY..EXCEPT)
             *  - in a clean call preparation after the stack switch (either
             *    crashing on a clean call argument or getting an asynchronous
             *    interrupt before we disable interrupts with the popf). Note
             *    that we can either be in a fragment or in some client gencode.
             *  - in a client lib's clean callee (this only happens with
             *    client-generated exceptions b/c asynchronous interrupts are
             *    blocked in the clean call preparation)
             *
             * Note that the following is impossible
             *  - in some random kernel code that we call (e.g., memcpy) after
             *    whereami = WHERE_FCACHE was set in the dispatcher
             * because we don't do anything that can fault after we set
             * whereami = WHERE_FCACHE
             */
            if (is_in_dynamo_dll(pc)) {
                return INTERRUPTED_DYNAMORIO;
#ifdef CLIENT_INTERFACE
            } else if (is_in_client_lib(pc)) {
                /* clean callee */
                return INTERRUPTED_CLIENT_LIB;
#endif
            } else {
                /* Could either be in clean call preparation or a crashing clean
                 * call argument. If we're in the kernel code, then in_fcache
                 * could deadlock. However, we have interrupts disabled when
                 * we're in the dispatcher and we can't handle exceptions
                 * generated by kernel code, so this situation should never
                 * arise (unless it's an NMI or SMI, in which case we're screwed
                 * anyways). 
                 */
                if (in_fcache(pc)) {
                    return INTERRUPTED_FRAGMENT;
                } else {
                    ASSERT(is_dynamo_address(pc));
                    return INTERRUPTED_CLIENT_GENCODE;
                }
            }
        }
    } else { 
        /* Whenever whereami != WHERE_FCACHE, we should be on the dstack. */
        ASSERT(is_on_dstack(dcontext, (byte *)frame->xsp));
        if (in_generated_routine(dcontext, pc)) {
            /* We run some generated code when whereami != WHERE_FCACHE and not
             * on the dstack (namely the kernel entry points), but these
             * routines should not generate exceptions and they run with
             * interrupts disabled.
             */
             ASSERT_NOT_REACHED();
             return INTERRUPTED_GENCODE;
#ifdef CLIENT_INTERFACE
        } else if (is_in_client_lib(pc)) {
            return INTERRUPTED_CLIENT_LIB;
#endif
        } else {
            /* If we're in kernel code called by DynamoRIO, then we're screwed
             * because interrupts should be disabled and we don't know how to
             * handle the kernel's exceptions.
             */
            ASSERT(is_in_dynamo_dll(pc));
            return INTERRUPTED_DYNAMORIO; 
        }
    }
}

bool
has_pending_interrupt(dcontext_t *dcontext)
{
    os_thread_data_t *ostd = (os_thread_data_t *) dcontext->os_field;
    return ostd->pending_interrupt;
}

/* Returns false iff the fragment isn't unlinked. This happens if the fragment
 * is already unlinked (e.g., for trace creation).
 */
static bool 
unlink_interrupted_fragment(dcontext_t *dcontext, fragment_t *f)
{
    /* N.B., According to unlink_fragment_for_signal in linux/signal.c, there
     * is a race condition here for shared fragments. We're not using shared
     * fragments for now, so I'm not going to investigate this.
     */
    if (TEST(FRAG_LINKED_OUTGOING, f->flags)) {
        SHARED_FLAGS_RECURSIVE_LOCK(f->flags, acquire, change_linking_lock);
        unlink_fragment_outgoing(dcontext, f);
        SHARED_FLAGS_RECURSIVE_LOCK(f->flags, release, change_linking_lock);
        return true;
    } else {
        return false;
    }
}

static void
link_interrupted_fragment(dcontext_t *dcontext, fragment_t *f)
{
    SHARED_FLAGS_RECURSIVE_LOCK(f->flags, acquire, change_linking_lock);
    link_fragment_outgoing(dcontext, f, false);
    SHARED_FLAGS_RECURSIVE_LOCK(f->flags, release, change_linking_lock);
}

static void
unpatch_fragments(dcontext_t *dcontext, os_thread_data_t *ostd)
{
    int i;
    for (i = 0; i < ostd->num_patches; i++) {
        unpatch_interrupt(dcontext, ostd->patch_pc[i], ostd->patch_buffer[i]);
    }
    ostd->num_patches = 0;
    ostd->pending_interrupt = false;
}

static void second_patch(void) {}

static bool
is_patch_interrupt(os_thread_data_t *ostd, interrupt_context_t *interrupt)
{
    int i;
    ASSERT(ostd->num_patches <= MAX_NUM_PATCHES);
    for (i = 0; i < ostd->num_patches; i++) {
        /* intN pushes the pc of the next instruction. Although the Intel docs
         * don't seem to explicitly mention this, intN interrupts are probably
         * all classified as "traps" rather than "faults" (see Section 6.5 in
         * Intel's Programmer Reference Manual, volume 3A).
         */
        if (ostd->patch_pc[i] + INTN_LENGTH == interrupt->frame.xip) {
            return true;
        }
        second_patch();
    }
    return false;
}

static void
patch_fragment(dcontext_t *dcontext, os_thread_data_t *ostd, byte *patch_pc,
               interrupt_vector_t vector)
{
    int patch_index = ostd->num_patches++;
    STATS_INC(num_fragment_interrupt_patches);
    ASSERT(ostd->num_patches <= MAX_NUM_PATCHES);
    ostd->patch_pc[patch_index] = patch_pc;
    patch_interrupt(dcontext, patch_pc, vector,
                    ostd->patch_buffer[patch_index]);
}

void
receive_pending_interrupt(dcontext_t *dcontext)
{
    os_thread_data_t *ostd = (os_thread_data_t *) dcontext->os_field;
    ASSERT(ostd->pending_interrupt);
    ostd->pending_interrupt = false;
    
    /* We used to check for this in handle_kernel_interrupt. This was
     * problematic because some fcache exit processing needed to know if a trace
     * was being built (e.g., in fragment_add_ibl_target when the IBL target is
     * already in the hash table).
     */
    if (is_building_trace(dcontext)) {
        STATS_INC(num_aborted_traces_interrupt);
        trace_abort(dcontext);
    }

    if (ostd->need_to_link_interrupted_fragment) {
        link_interrupted_fragment(dcontext, ostd->interrupted_fragment);
        ostd->need_to_link_interrupted_fragment = false;
    }
    if (ostd->interrupted_in_ibl) {
        ostd->interrupted_in_ibl = false;
        link_ibl_routine(dcontext, ostd->interrupted_ibl_pc);
    }

    if (ostd->use_interrupted_mcontext) {
        copy_mcontext(&ostd->interrupted_mcontext, get_mcontext(dcontext));
    } else {
        get_mcontext(dcontext)->xip = dcontext->next_tag;
    }
    dcontext->next_tag =
        ostd->native_state.vector_target[ostd->interrupt_vector];
    /* receive_pending_interrupt should only be called from the dispatcher, so
     * it's okay to call is_dynamo_address. If we were called from elsewehere,
     * then is_dynamo_address could deadlock. */
    ASSERT(!is_dynamo_address(get_mcontext(dcontext)->xip));
    ASSERT(is_kernel_code(get_mcontext(dcontext)->xip));
    ASSERT(!is_dynamo_address((byte *) get_mcontext(dcontext)->xsp));

    unpatch_fragments(dcontext, ostd);

    emulate_interrupt_arrival(get_mcontext(dcontext), ostd->interrupt_vector,
                              dcontext->next_tag,
                              ostd->interrupt_error_code,
                              ostd->interrupt_system_xflags,
                              ostd->interrupt_frame_if);
}

static void 
record_pending_interrupt(dcontext_t *dcontext, interrupt_context_t *interrupt,
                         dr_mcontext_t *interrupted_mcontext, bool modify_if)
{
    os_thread_data_t *ostd = (os_thread_data_t *) dcontext->os_field;
    ostd->pending_interrupt = true;
    if (interrupted_mcontext) {
        ostd->use_interrupted_mcontext = true;
        /* It's important to copy this because the interrupted_mcontext
         * parameter is stored on the native stack.
         */
        copy_mcontext(interrupted_mcontext, &ostd->interrupted_mcontext);
    } else {
        ostd->use_interrupted_mcontext = false;
    }
    ostd->interrupt_vector = interrupt->vector;
    ostd->interrupt_error_code = interrupt->frame.error_code;
    ostd->interrupt_system_xflags = interrupt->mcontext->xflags & EFLAGS_SYSTEM;
    ostd->interrupt_frame_if = TEST(EFLAGS_IF, interrupt->frame.xflags);
    if (modify_if) {
        /* Disable interrupts until this one is handled. This will result in
         * fcache_return saving the wrong eflags value. However, we account for
         * this; see interrupt_frame_if in os_thread_data_t. */
        interrupt->raw_frame->xflags &= ~EFLAGS_IF;
    }
}

static bool
is_loop_opc(uint opc)
{
    return opc == 0xe0 || opc == 0xe1 || opc == 0xe2;
}

static void
handle_fragment_interrupt(dcontext_t *dcontext, interrupt_context_t *interrupt)
{
    dr_mcontext_t mcontext;
    fragment_t wrapper;
    recreate_success_t res;
    bool waslinking = is_couldbelinking(dcontext);
    os_thread_data_t *ostd = (os_thread_data_t *) dcontext->os_field;
    /* Patches are all undone in handle_interrupt. */
    ASSERT(ostd->num_patches == 0);

    get_interrupted_context(interrupt, &mcontext);

#ifdef DEBUG
    ostd->interrupted_fragment = fragment_pclookup(dcontext, mcontext.pc,
                                                   &wrapper);
#endif
    
    KSTART(recreate_app_state_frag_intr);
    if (!waslinking)
        enter_couldbelinking(dcontext, NULL, false);
    res = recreate_app_state(dcontext, &mcontext, true);
    if (!waslinking)
        enter_nolinking(dcontext, NULL, false);
    KSTOP(recreate_app_state_frag_intr);
    if (res == RECREATE_SUCCESS_STATE) {
        if (interrupt->vector == VECTOR_PAGE_FAULT) {
            KSWITCH(kernel_interrupt_frag_success_page_fault);
        } else if (vector_is_synchronous(interrupt->vector)) {
            KSWITCH(kernel_interrupt_frag_success_other_sync);
        } else {
            KSWITCH(kernel_interrupt_frag_success_async);
        }
        ASSERT(!is_dynamo_address(mcontext.pc));
        ASSERT(is_kernel_code(mcontext.pc));
        ASSERT(!is_user_address((byte*) mcontext.xsp));

        record_pending_interrupt(dcontext, interrupt, NULL, false);
        dcontext->next_tag = mcontext.xip;
        set_last_exit(dcontext,
                      (linkstub_t *) get_kernel_interrupt_entry_linkstub());
        STATS_INC(num_ndelayed_frag_intr);
        transfer_to_dispatch(dcontext, 0, &mcontext);
    } else if (res == RECREATE_DELAY_UNTIL_DISPATCH) {
        /* Switch from kernel_interrupt_handling */
        KSWITCH(kernel_interrupt_frag_delay_dispatch);
        /* TODO(peter): This could happen on an exception in an indirect jump or
         * return when the pop or the memory access fails. recreate_app_state
         * should be modified to not delay exceptions at those points.
         */
        ASSERT(!vector_is_synchronous(interrupt->vector));
        ostd->interrupted_fragment = fragment_pclookup(dcontext, mcontext.pc,
                                                       &wrapper);
        ASSERT(ostd->interrupted_fragment != NULL);
        ostd->need_to_link_interrupted_fragment =
            unlink_interrupted_fragment(dcontext, ostd->interrupted_fragment);
        record_pending_interrupt(dcontext, interrupt, NULL, true);
        STATS_INC(num_delayed_frag_intr);
    } else if (res == RECREATE_DELAY_UNTIL_PC) {
        KSWITCH(kernel_interrupt_frag_delay_pc);
        ASSERT(!vector_is_synchronous(interrupt->vector));
        ASSERT(!vector_has_error_code(interrupt->vector));
        patch_fragment(dcontext, ostd, mcontext.pc, interrupt->vector);
        /* If it's a loop, patch it too. This is a big hack for our repstr
         * emulation. We should really be doing some control flow analysis of
         * the fragment to find all of the possible next non-meta instructions. */
        if (is_loop_opc(mcontext.pc[2])) {
            second_patch();
            patch_fragment(dcontext, ostd, mcontext.pc + 2, interrupt->vector);
        }
        /* Clean calls have the eflags saved on the dstack. We need to clear the
         * saved eflags.IF so interrupts aren't enabled before we run the
         * patched intN instruction. If eflags hasn't been pushed on the dstack
         * yet, then we're just overwriting dead data. */
        if (is_on_dstack(dcontext, (byte*) interrupt->frame.xsp)) {
            clean_call_clear_saved_interrupt_flag(dcontext,
                                                  (byte*) interrupt->frame.xsp);
        }
        /* If a clean callee calls dr_redirect_execution, then we won't execute
         * the patched intN instruction. So we record the interrupt.
         */
        record_pending_interrupt(dcontext, interrupt, NULL, true);
    } else {
        KSWITCH(kernel_interrupt_frag_unknown);
        /* TODO(peter): Handle the failures:
         *  in some meta instructions - patching the next non-meta
         *  in a prefix - patching the next non-meta (for now, we disable
                          prefixes) 
         *  in an inlined IBL lookup - ?? I believe that this is handled by
         *                             unlinking the fragment ??
         *                             -> not a problem because inlined IBL
         *                             lookups are disabled.
         */
        ASSERT_NOT_REACHED();
    }
}

static void
handle_ibl_interrupt(dcontext_t *dcontext, interrupt_context_t *interrupt)
{
    os_thread_data_t *ostd = (os_thread_data_t *) dcontext->os_field;
    KSWITCH(kernel_interrupt_ibl);
    /* Note that fragment unlinking handles inlined IBL heads. See comment above
     * unlink_indirect_exit. */
    ostd->interrupted_in_ibl = true;
    ostd->interrupted_ibl_pc = interrupt->frame.xip;
    unlink_ibl_routine(dcontext, ostd->interrupted_ibl_pc);
    record_pending_interrupt(dcontext, interrupt, NULL, true);
    STATS_INC(num_ibl_interrupts);
}


static void
handle_fcache_enter_interrupt(dcontext_t *dcontext,
                              interrupt_context_t *interrupt)
{
    record_pending_interrupt(dcontext, interrupt, NULL, true);
    KSWITCH(kernel_interrupt_fcache_enter);
    set_last_exit(dcontext,
                  (linkstub_t*) get_kernel_interrupt_entry_linkstub());
    /* Even if we're on the dstack, switching stacks shouldn't be problematic
     * because we don't use any data on the present stack after we switch
     * stacks. If we're on the dstack, we don't want to call dispatch directly
     * because we could overflow the dstack if we kept getting interrupted in
     * fcache_enter.
     */
    dcontext->next_tag = dcontext->next_app_tag;
    ASSERT(!is_dynamo_address(dcontext->next_tag));
    ASSERT(is_kernel_code(dcontext->next_tag));
    STATS_INC(num_fcache_enter_interrupts);
    transfer_to_dispatch(dcontext, 0, get_mcontext(dcontext));
}

static void
handle_fcache_return_interrupt(dcontext_t *dcontext,
                               interrupt_context_t *interrupt)
{
    STATS_INC(num_fcache_return_interrupts);
    KSWITCH(kernel_interrupt_fcache_return);
    record_pending_interrupt(dcontext, interrupt, NULL, true);
    /* Before fcache_return disables interrupts, xax always holds the linkstub
     * ptr. Only after fcache_return disables interrupts, xax is written to
     * dcontext->last_exit. So we could set a linkstub here:
     * 
     * interrupt->mcontext->xax = (reg_t) get_kernel_interrupt_entry_linkstub();
     *
     * Doing this would give us better statistics (i.e., the time spent handling
     * dispatches due to interrupts). However, we'd have to recover the next_tag
     * from direct linkstubs here because receive_pending_interrupt relies on
     * next_tag. We'll live with the inaccurate statistics.
     */
}


static void
handle_kernel_interrupt(dcontext_t *dcontext, interrupt_context_t *interrupt)
{
    ASSERT(dcontext->whereami != WHERE_USERMODE);
#ifdef STACK_GUARD_PAGE
    if (interrupt->vector == VECTOR_PAGE_FAULT &&
        is_stack_overflow(dcontext, (byte *)get_cr2())) {
        SYSLOG_INTERNAL_CRITICAL(PRODUCT_NAME" stack overflow at pc "PFX,
                                 interrupt->frame.xip);
        /* options are already synchronized by the SYSLOG */
        if (TEST(DUMPCORE_INTERNAL_EXCEPTION, dynamo_options.dumpcore_mask))
            os_dump_core("stack overflow");
        os_terminate(dcontext, TERMINATE_PROCESS);
    }
#endif /* STACK_GUARD_PAGE */

    ASSERT(interrupt->frame.cs == get_cs());

    switch (interrupt->location) {
    case INTERRUPTED_FRAGMENT:
        handle_fragment_interrupt(dcontext, interrupt);
        break;
    case INTERRUPTED_GENCODE:
        ASSERT(!vector_is_synchronous(interrupt->vector));
        if (in_indirect_branch_lookup_code(dcontext, interrupt->frame.xip)) {
            handle_ibl_interrupt(dcontext, interrupt);
        } else if (in_fcache_enter_code(dcontext, interrupt->frame.xip)) {
            handle_fcache_enter_interrupt(dcontext, interrupt);
        } else if (in_fcache_return_code(dcontext, interrupt->frame.xip)) {
            handle_fcache_return_interrupt(dcontext, interrupt);
        } else {
            /* We don't expect interrupts for any other gencode. */
            /* TODO(peter): in_indirect_branch_lookup_code returns false for the
             * unlinked_ibl_entry in ibl_code_t. It might also return false for
             * target_delete_entry and trace_cmp_unlinked. These cases are
             * benign but they'll hit the os_terminate below. We need to
             * identify these paths and process them like fcache_return.
             * TODO(peter): What about trace_cmp_entry?
             */
            os_terminate(dcontext, TERMINATE_PROCESS);
        }
        break;
    case INTERRUPTED_DYNAMORIO:
        /* We don't expect interrupts in DR because we run with IF = 0. 
         * TODO(peter): implement TRY/EXCEPT. */
        ASSERT_NOT_REACHED();
        os_terminate(dcontext, TERMINATE_PROCESS);
        break;
#ifdef CLIENT_INTERFACE
    case INTERRUPTED_CLIENT_LIB:
    case INTERRUPTED_CLIENT_GENCODE:
        /* The client should have handled this interrupt and either suppressed
         * it or replaced interrupt.frame.xip with a fragment code cache address suitable
         * for delaying the interrupt. */
        ASSERT_NOT_REACHED();
        os_terminate(dcontext, TERMINATE_PROCESS);
        break;
#endif
    default:
        os_terminate(dcontext, TERMINATE_PROCESS);
    }
}

static void
nmi_handler(void) {
}

#ifdef CLIENT_INTERFACE
static bool
send_interrupt_to_client(dcontext_t *dcontext, interrupt_context_t *interrupt)
{
    bool res;
    dr_interrupt_t dr_interrupt;
    dr_interrupt.frame = &interrupt->frame;
    dr_interrupt.raw_frame = interrupt->raw_frame;
    dr_interrupt.vector = interrupt->vector;
    dr_interrupt.mcontext = interrupt->mcontext;
    res = instrument_interrupt(dcontext, &dr_interrupt);
    return res;
}
#endif

static void
handle_interrupt(interrupt_stack_frame_t* frame, dr_mcontext_t* mcontext,
                 interrupt_vector_t vector)
{
    dcontext_t *dcontext;
    os_thread_data_t *ostd;
    bool local;
    interrupt_context_t interrupt;
    STATS_INC(num_interrupts);

    if (vector == VECTOR_NMI) {
        nmi_handler();
    }

#ifdef DEBUG
    /* Sanity check for interrupt stack frame. */
    ASSERT(!TEST(EFLAGS_IF, mcontext->xflags));
    ASSERT(mcontext->pc == 0);
    if (vector_has_error_code(vector)) {
        ASSERT(frame->error_code != MAGIC_FAKE_ERROR);
    } else {
        ASSERT(frame->error_code == MAGIC_FAKE_ERROR);
    }
    ASSERT(mcontext->rsp == (reg_t) &frame->error_code);
    ASSERT(mcontext->rsp - 2 * sizeof(reg_t) == (reg_t) &mcontext->pc);
    ASSERT(ALIGNED(mcontext->rsp,  INTERRUPT_STACK_FRAME_ALIGNMENT));
#endif

    dcontext = get_thread_private_dcontext();
    ASSERT(dcontext != NULL);
    ostd = (os_thread_data_t *) dcontext->os_field;
    ASSERT(ostd != NULL);


    ENTERING_DR();
    local = local_heap_protected(dcontext);
    if (local)
        SELF_PROTECT_LOCAL(dcontext, WRITABLE);


#ifdef DEBUG
    /* Make copies of interrupt state for debugging. */
    ostd->interrupted_location = interrupt.location;
    ostd->interrupt_stack_frame = *frame;
#endif

    LOG(THREAD, LOG_ASYNCH, 2,
        "Interrupt: vector = %d, xip = %p, xsp = %p, location = %d\n",
        vector, frame->xip, frame->xsp, interrupt.location);

    interrupt.mcontext = mcontext;
    interrupt.frame = *frame;
    interrupt.raw_frame = frame;
    interrupt.vector = vector;

    if (is_patch_interrupt(ostd, &interrupt)) {
        unpatch_fragments(dcontext, ostd);
        interrupt.raw_frame->xip -= INTN_LENGTH;
        interrupt.frame.xip -= INTN_LENGTH;
        interrupt.raw_frame->xflags |= EFLAGS_IF;
        interrupt.frame.xflags |= EFLAGS_IF;
    }

#ifdef CLIENT_INTERFACE
    if (send_interrupt_to_client(dcontext, &interrupt))  {
#endif
#ifdef DEBUG
        DOKSTATS({
            kstat_stack_t *ks = &dcontext->thread_kstats->stack_kstats; 
            kstat_variable_t *var = ks->node[ks->depth - 1].var;
            kstat_variables_t *vars = &dcontext->thread_kstats->vars_kstats;
            /* Have to be in fcache (fcache_default or fcache_trace_trace) or in
             * usermode. Can't be interrupted when we're processing an
             * interrupt.
             *
             * TODO(peter): We can take an exception when we have an interrupt
             * pending. By design, no native exceptions will be triggered (b/c
             * their handlers might inspect the pending interrupt), but
             * exceptions that DR causes can still fire.
             */
            ASSERT(var == &vars->delaying_patched_interrupt ||
                   var == &vars->fcache_default ||
                   var == &vars->fcache_trace_trace ||
                   var == &vars->usermode);
        });
#endif
        /* This could be in usermode, fcache_default, or fcache_trace_trace. */
        KSTOP_NOT_MATCHING_NOT_PROPAGATED(usermode);
        /* We KSWITCH later in this function if we're handling a user interrupt.
         * */
        KSTART(kernel_interrupt_handling);

        ASSERT(!has_pending_interrupt(dcontext));
        interrupt.location = get_interrupted_location(dcontext,
                                                      &interrupt.frame);
    
#if 0
        ASSERT(ostd->num_patches == 0 ||
               interrupt.location == INTERRUPTED_FRAGMENT);
#endif
    
        if (interrupt.location == INTERRUPTED_USER) {
            KSWITCH(user_interrupt_handling);
            handle_user_interrupt(dcontext, &interrupt);
            ASSERT_NOT_REACHED();
        } else {
            handle_kernel_interrupt(dcontext, &interrupt);
            if (ostd->num_patches > 0) {
                KSWITCH(delaying_patched_interrupt);
            }
            /* If this returns, then we iret to whatever was interrupted. The
             * state in mcontext and frame are restored. */
        }
#ifdef CLIENT_INTERFACE
    }
#endif

    if (local)
        SELF_PROTECT_LOCAL(dcontext, READONLY);
    EXITING_DR();
}

interrupt_handler_t
os_get_interrupt_handler(interrupt_vector_t vector)
{
    return handle_interrupt;
}

static void
optimize_syscall_entry(dcontext_t *dcontext)
{
    os_thread_data_t *ostd = (os_thread_data_t *) dcontext->os_field;
    fragment_t *f;
    f = build_basic_block_fragment(dcontext,
                                   (byte*) ostd->native_state.msr_lstar,
                                   FRAG_CANNOT_DELETE, true, true
                                   _IF_CLIENT(false) _IF_CLIENT(NULL));
    ostd->syscall_entry_frag = f;
    optimize_syscall_code(dcontext, f);
}


void
os_fragment_thread_reset_free(dcontext_t *dcontext) {
    os_thread_data_t *ostd = (os_thread_data_t *) dcontext->os_field;
    /* TODO(peter): What happens when there's a reset init? We had better change
     * os_warm_fcache to be called fragment_thread_reset_init or some such.
     */
    if (DYNAMO_OPTION(optimize_sys_call_ret)) {
        /* TODO(peter): We need a callback to know when special fragments are
         * deleted. This would be a more general solution than setting
         * FRAG_CANNOT_DELETE on fragments that we warm the cache with.
         */
        ostd->syscall_entry_frag->flags &= ~FRAG_CANNOT_DELETE;
    }
}

void
os_warm_fcache(dcontext_t *dcontext) {
    /* TODO(peter): We want to warm this with the syscall and vector entry
     * points and patch those routines to jump directly into the cache where
     * possible.
     */
    if (DYNAMO_OPTION(optimize_sys_call_ret)) {
        optimize_syscall_entry(dcontext);
        return;
    }
    
}

static bool
is_within_segment(byte *base, uint64 limit, byte *addr, uint64 size)
{
    /* TODO(peter): I'm not sure how overflow is handled. Just assert that it
     * doesn't happen.  */
    ASSERT(addr + size >= addr);
    ASSERT(base + limit + 1 >= base);

    /* Addresses are always issued to the hardware as a positive offset from the
     * beginning of some segment. If we do some internal translation that
     * involves addr < base, then we've made some internal error.
     */
    ASSERT(addr >= base);

    /* Last valid byte in segment is (base + limit + 1). */
    return addr + size <= base + limit + 1; 
}


static void
assert_no_gates(dcontext_t *dcontext, descriptor_t *table, uint64 limit)
{
    descriptor_t *curr = table;
    for (;;) {
        if (!is_within_segment((byte *)table, limit, (byte *)curr,
                               sizeof(*curr))) {
            break;
        }
        ASSERT(get_descriptor_kind(curr) != GATE_DESCRIPTOR);
        if (is_system_desciptor(curr)) {
            curr += 1;
        }
        curr += 1;
    }
}

static void
handle_lldt(dcontext_t *dcontext, segment_selector_t *ldt_selector)
{
    system_table_register_t gdtr;
    descriptor_t *ldt_desc;
    segment_t ldt_seg;

    if (ldt_selector->table_indicator == 0 && ldt_selector->index == 0) {
        /* Nothing to check because LDTR points to null segment selector. Any
         * subsequent references to LDT will fail. [Intel 2A - LLDT]
         */
        return;
    }

    /* TODO(peter): These assertions should trigger exceptions. */
    /* TODO(peter): Check all of the exception conditions specified in [Intel 2A
     * - LLDT]. Namely, #PF, #SS, #UD, and #GP for canonical addressing. */
    ASSERT(ldt_selector->table_indicator == TABLE_INDICATOR_GDT);
    get_gdtr(&gdtr);
    ASSERT(is_within_segment((byte*) gdtr.base, gdtr.limit,
                             (byte*) &gdtr.base[ldt_selector->index],
                             sizeof(*ldt_desc)));
    ldt_desc = &gdtr.base[ldt_selector->index];
    ASSERT(ldt_desc->generic.present);
    ASSERT(get_descriptor_kind(ldt_desc) == SYSTEM_SEGMENT_DESCRIPTOR);
    ASSERT(ldt_desc->segment.system_type == SYSTEM_TYPE_LDT);

    get_segment((descriptor_t*) ldt_desc, &ldt_seg);

    /* TODO(peter): We should intercept call gates. For now we just assert that
     * they don't exist.
     */
    assert_no_gates(dcontext, (descriptor_t*) ldt_seg.base, ldt_seg.limit);
}

static void
handle_lgdt(dcontext_t *dcontext, system_table_register_t *gdtr)
{
    /* TODO(peter): We should intercept call gates. For now we just assert that
     * they don't exist.
     */
    assert_no_gates(dcontext, gdtr->base, gdtr->limit);
}


static void
hijack_call_gates(dcontext_t *dcontext) {
    system_table_register_t gdtr;
    segment_selector_t ldt_selector;
    get_gdtr(&gdtr);
    /* TODO(peter): We're not getting the cached LDT values here. We'd
     * need to use VMX extensions to get this information. For now, we'll use
     * this potentially stale view of the LDT.
     */
    get_ldt_selector(&ldt_selector);

    handle_lldt(dcontext, &ldt_selector);
    handle_lgdt(dcontext, &gdtr);
}

static void
handle_lidt(dcontext_t *dcontext, system_table_register_t *idtr)
{
    interrupt_vector_t vector;
    os_thread_data_t *ostd = (os_thread_data_t *) dcontext->os_field;
    system_table_register_t new_idtr;

    /* TODO(peter): Support an IDT with fewer than VECTOR_END entires. x86
     * generates a #GP if a vector references a descriptor beyond the limit of
     * the IDT.
     */
    ASSERT(idtr->limit == IDT_SIZE - 1);

    /* Instead of allocating room for a new IDT, This could be done by
     * overwriting the same IDT each time we encounter lidt. I'm not doing this
     * because any faults that occour before we finish setting up the new IDT
     * would be a pain to debug. There should be no performance hit because lidt
     * is rare.
     */
    if (ostd->idt) {
        heap_free(dcontext, ostd->idt, UNALIGNED_IDT_SIZE HEAPACCT(ACCT_OTHER));
    }
    ostd->idt = heap_alloc(dcontext, UNALIGNED_IDT_SIZE HEAPACCT(ACCT_OTHER));
    new_idtr.base = (descriptor_t *) ALIGN_FORWARD(ostd->idt, IDT_ALIGNMENT);
    new_idtr.limit = (ushort) (IDT_SIZE - 1);

    for (vector = VECTOR_START; vector < VECTOR_END; vector++) {
        descriptor_t *native = &idtr->base[vector * 2];
        descriptor_t *new = &new_idtr.base[vector * 2];
        ASSERT(is_system_desciptor(native)); 
        ASSERT(get_descriptor_kind(native) == GATE_DESCRIPTOR);
        /* TODO(peter): support trap gates. The only difference is that trap
         * gates do not set IF=0. We need interrupts disabled, so we could
         * support them by always using interrupt gates and just changing IF on
         * the fabricated interrupt stack frame.
         */
        ASSERT(native->gate.system_type == SYSTEM_TYPE_INTERRUPT_GATE);
        ASSERT(native->gate.target_selector.selector == get_cs());
        ostd->native_state.vector_target[vector] =
                get_gate_target_offset(&native->gate);
        *new = *native;
        set_gate_target_offset(&new->gate,
                               get_vector_entry(dcontext, vector));
        ASSERT(get_gate_target_offset(&new->gate) ==
               get_vector_entry(dcontext, vector));
    }

    ostd->native_state.idtr = *idtr;
    set_idtr(&new_idtr);
}

static void
hijack_vectors(dcontext_t *dcontext)
{
    system_table_register_t idtr;
    get_idtr(&idtr);
    handle_lidt(dcontext, &idtr);
}

/* Hijacks all of the kernel entry points on 64-bit x86:
 *
 *  - interrupt / exception vectors
 *  - syscall / sysenter entry points
 *  - call gates
 *
 * 64-bit mode does not have task gates.
 *
 * TODO(peter): Determine if interprocessor interrupts enter through something
 * other than vectors. As far as I can tell from the Intel docs, IPIs only come
 * through vectors, but the Linux source code implies otherwise (in entry_64.S).
 *
 * TODO(peter): Determine if task gates really aren't a problem. According to
 * the Intel docs, task switches are illegal in 64-bit mode. I want to verify
 * this.
 */
static void
hijack_entry_points(dcontext_t *dcontext)
{
    /* TODO(peter): We need to hijack sysenter. */
    set_msr(MSR_LSTAR, (uint64) get_syscall_entry(dcontext));
    hijack_call_gates(dcontext);
    hijack_vectors(dcontext);
}

app_pc
os_get_native_syscall_entry(dcontext_t *dcontext) {
    os_thread_data_t *ostd = (os_thread_data_t *) dcontext->os_field;
    ASSERT(ostd != NULL);
    return (app_pc) ostd->native_state.msr_lstar;
}

void
os_thread_init(dcontext_t *dcontext)
{
    os_thread_data_t *ostd = (os_thread_data_t *)
        heap_alloc(dcontext, sizeof(os_thread_data_t) HEAPACCT(ACCT_OTHER));
    dcontext->os_field = ostd;
    memset(ostd, 0, sizeof(*ostd));

    ostd->native_state.msr_lstar = get_msr(MSR_LSTAR);
}

void
os_thread_after_arch_init(dcontext_t *dcontext)
{
    hijack_entry_points(dcontext);
}

void
os_thread_exit(dcontext_t *dcontext)
{
    os_thread_data_t *ostd = (os_thread_data_t *) dcontext->os_field;

    /* Restore interrupt handlers. */
    heap_free(dcontext, ostd->idt, UNALIGNED_IDT_SIZE HEAPACCT(ACCT_OTHER));
    set_idtr(&ostd->native_state.idtr);

    /* Restore syscall entry point. */
    set_msr(MSR_LSTAR, ostd->native_state.msr_lstar);

    heap_free(dcontext, ostd, sizeof(os_thread_data_t) HEAPACCT(ACCT_OTHER));
}

void
os_thread_under_dynamo(dcontext_t *dcontext)
{
    /* This is called when a CPU enters the kernel. */
    /* TODO(peter): This isn't called because we don't use the start API. */
}

void
os_thread_not_under_dynamo(dcontext_t *dcontext)
{
    /* This is called when a CPU returns to user space. */
}

void
os_run_on_all_threads(void (*func) (void *info), void *info) {
    kernel_run_on_all_cpus(func, info);
}

process_id_t
get_process_id()
{
    return 1234;
}

process_id_t
get_parent_id(void)
{
    ASSERT_NOT_PORTED(false);
    return 0;
}

thread_id_t 
get_sys_thread_id(void)
{
    return kernel_get_cpu_id();
}

thread_id_t 
get_thread_id(void)
{
    /* kernel_get_cpu_id is reentrant and fast
     * (it just reads gs:[&per_cpu_var(cpu_number)])
     */
    return kernel_get_cpu_id();
}

thread_id_t
get_tls_thread_id(void)
{
    return get_thread_id();
}

dcontext_t*
get_thread_private_dcontext(void)
{
    /* 
     * Note 1: we rely on kernel_module_init to zero out the CPU-private
     * data. If this didn't happen, then we could return non-null here before
     * os_init() is called. This originally happened when loading, initializing,
     * unloading, loading, then finally initializing our module.
     *
     * Note 2: get_thread_private_dcontext is a bottleneck in the original DR. We could
     * inline get_tls here. Also, we could implement get_thread_private_dcontext
     * using Linux's DEFINE_PER_CPU_* macros and implement
     * get_thread_private_dcontext in kernel_interface.c. However, we would not
     * be able to place dcontext in the middle of the spill state, which other
     * parts of DR might depend on.
     */
    if (!os_initilized) {
       return NULL;
    } else {
       return (dcontext_t *) get_tls(tls_dcontext_offset);
    }
}

void
set_thread_private_dcontext(dcontext_t *dcontext)
{
    set_tls(tls_dcontext_offset, dcontext);
#ifdef DEBUG
    dcontexts[get_thread_id()] = dcontext;
#endif
}

void
os_heap_free(void *p, size_t size, heap_error_code_t *error_code)
{
    ASSERT(heap_already_reserved);
    kernel_free_heap(p);
    heap_already_reserved = false;
    *error_code = HEAP_ERROR_SUCCESS;
}

void *
os_heap_reserve(void *preferred, size_t size, heap_error_code_t *error_code,
                bool executable)
{
    /* Always return NULL because don't have any way of guaranteeing an
     * allocation at a specific address. */
    *error_code = HEAP_ERROR_NOT_AT_PREFERRED;
    return NULL;
}

/* HEAP */

void *
os_heap_reserve_in_region(void *start, void *end, size_t size,
                          heap_error_code_t *error_code, bool executable)
{
    void* heap;
    if (heap_already_reserved) {
        ASSERT(false);
        return NULL;
    }
    heap_already_reserved = true;

    if (!executable) {
        ASSERT(false);
        return NULL;
    }

    heap = kernel_allocate_heap(size);
    if (heap != NULL) {
        if (heap > start &&
            heap + size > heap && /* overflow */
            heap + size <= end) {
            *error_code = HEAP_ERROR_SUCCESS;
        } else {
            *error_code = HEAP_ERROR_CANT_RESERVE_IN_REGION;
        }
    }
    return heap;
}

bool
os_heap_commit(void *p, size_t size, uint prot, heap_error_code_t *error_code)
{
    /* TODO(peter): Implement the change in prot. For now, everything we
     * allocate is RWX.
     */
    *error_code = HEAP_ERROR_SUCCESS;
    return true;
}

void
os_heap_decommit(void *p, size_t size, heap_error_code_t *error_code)
{
    *error_code = HEAP_ERROR_SUCCESS;
}

bool
os_heap_systemwide_overcommit(heap_error_code_t last_error_code)
{
    /* Conservative answer: yes. */
    return true;
}

bool
os_heap_get_commit_limit(size_t *commit_used, size_t *commit_limit)
{
    /* TODO(peter): This could be implemented easily: the commit limit will
     * simply be the amount of memory we initially steal from the OS and the commit
     * used will be whatever has been allocated. Note that this isn't
     * implemented in DR Linux.
     */
    return false;
}

void
thread_yield()
{
    SPINLOCK_PAUSE();
}

void
thread_sleep(uint64 milliseconds)
{
    ASSERT_NOT_PORTED(false);
}

bool
thread_suspend(thread_record_t *tr)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
thread_resume(thread_record_t *tr)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
thread_terminate(thread_record_t *tr)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
is_thread_terminated(dcontext_t *dcontext)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
thread_get_mcontext(thread_record_t *tr, dr_mcontext_t *mc)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
thread_set_mcontext(thread_record_t *tr, dr_mcontext_t *mc)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
is_thread_currently_native(thread_record_t *tr)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

static int num_online_processors = 0;

int
get_num_processors()
{
    /* Assume that this is called at init time, so synchronization isn't
     * necessary. */
    if (num_online_processors == 0) {
        num_online_processors = kernel_get_online_processor_count();
    }
    return num_online_processors;
}

shlib_handle_t 
load_shared_library(char* name)
{
    return kernel_load_shared_library(name);
}

shlib_routine_ptr_t
lookup_library_routine(shlib_handle_t lib, char *name)
{
    return kernel_lookup_library_routine(lib, name);
}

void
unload_shared_library(shlib_handle_t lib)
{
    /* This is intentionally a nop. Instrumentation modules
     * need to be unloaded manually using rmmod */
}

void
shared_library_error(char *buf, int maxlen)
{
    strncpy(buf,
            "Error locating kernel module. The module must already be loaded.",
            maxlen);
    buf[maxlen-1] = '\0'; /* strncpy won't put on trailing null if maxes out */
}

bool
shared_library_bounds(IN shlib_handle_t lib, IN byte *addr,
                      OUT byte **start, OUT byte **end)
{
    return kernel_shared_library_bounds(lib, addr, start, end);
}

/* FILES */

bool
os_file_exists(const char *fname, bool is_dir)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
os_get_file_size(const char *file, uint64 *size)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
os_get_file_size_by_handle(file_t fd, uint64 *size)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
os_create_dir(const char *fname, create_directory_flags_t create_dir_flags)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

int
dup_syscall(int fd)
{
    ASSERT_NOT_PORTED(false);
    return 0;
}

#if 0
static file_t
next_open_fd(void) {
    /* Skip stdin, stdout, stderr */
    static file_t previous = 2;
    return atomic_add_exchange_int(&previous, 1);
}
#endif

file_t
os_open(const char *fname, int os_open_flags)
{
    return INVALID_FILE;
#if 0
    /* TODO(peter): Test this. */
    char buffer[HYPERCALL_MAX_SIZE];
    hypercall_open_t *hypercall = (hypercall_open_t*) &buffer[0];
    size_t size;
    file_t file;
    if (os_open_flags & OS_OPEN_READ) {
        ASSERT_NOT_PORTED(false);
    }
    /* strlen does not include the '\0' byte, however the hypercall->fname
     * placeholder gives us 1 byte of storage. */
    size = sizeof(*hypercall) + strlen(fname);
    hypercall->hypercall.size = size;
    hypercall->hypercall.type = HYPERCALL_OPEN;
    hypercall->fd = next_open_fd();
    strcpy(&hypercall->fname, fname);
    if (!hypercall_send(&hypercall->hypercall)) {
        file = INVALID_FILE;
    } else {
        file = hypercall->fd;
    }
    return file;
#endif
}

file_t
os_open_directory(const char *fname, int os_open_flags)
{
    ASSERT_NOT_PORTED(false);
    return 0;
}

void
os_close(file_t f)
{
#ifdef HYPERCALL_DEBUGGING
    /* We don't want to try supporting closing stdin, stdout, or stderr. */
    if (f > 2) {
        bool ok;
        hypercall_close_t hypercall;
        hypercall.hypercall.type = HYPERCALL_CLOSE;
        hypercall.hypercall.size = sizeof(hypercall);
        hypercall.fd = f;
        ok = hypercall_send(&hypercall.hypercall);
        ASSERT(ok);
    } else {
        ASSERT_NOT_PORTED();
    }
#endif
}

ssize_t
os_write(file_t f, const void *buf, size_t count)
{
#ifdef HYPERCALL_DEBUGGING
    char buffer[HYPERCALL_MAX_SIZE];
    hypercall_write_t *hypercall = (hypercall_write_t*) &buffer[0];
    size_t size;
    ssize_t actual_count;

    /* Can't handle invalid files (< 0) or stdin (0) */
    ASSERT_MESSAGE("Can't write to stdin or invalid files.", f > 0);

    /* subtract 1 for the hypercall->buffer placeholder */
    size = MIN(sizeof(*hypercall) - 1 + count, HYPERCALL_MAX_SIZE);
    actual_count = size - sizeof(*hypercall) + 1;

    hypercall->hypercall.size = size;
    hypercall->hypercall.type = HYPERCALL_WRITE;
    hypercall->fd = f;
    hypercall->count = actual_count;
    memcpy(&hypercall->buffer, buf, actual_count);

    if (!hypercall_send(&hypercall->hypercall)) {
        actual_count = -1;
        ASSERT(false);
    }
    return actual_count;
#else
    kernel_printk("%s", buf);
    return count;
#endif
}

ssize_t 
os_read(file_t f, void *buf, size_t count)
{
    ASSERT_NOT_PORTED(false);
    return 0;
}

void
os_flush(file_t f)
{
#ifdef HYPERCALL_DEBUGGING
    bool ok;
    hypercall_flush_t hypercall;
    hypercall.hypercall.type = HYPERCALL_FLUSH;
    hypercall.hypercall.size = sizeof(hypercall);
    hypercall.fd = f;
    ok = hypercall_send(&hypercall.hypercall);
    ASSERT(ok);
#endif
}

bool
os_seek(file_t f, int64 offset, int origin)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

int64
os_tell(file_t f)
{
    ASSERT_NOT_PORTED(false);
    return 0;
}

bool
os_delete_file(const char *name)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
os_rename_file(const char *orig_name, const char *new_name, bool replace)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
os_delete_mapped_file(const char *filename)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

byte *
os_map_file(file_t f, size_t *size INOUT, uint64 offs, app_pc addr, uint prot,
            bool copy_on_write, bool image, bool fixed)
{
    ASSERT_NOT_PORTED(false);
    return NULL;
}

bool
os_unmap_file(byte *map, size_t size)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
os_get_disk_free_space(/*IN*/ file_t file_handle,
                       /*OUT*/ uint64 *AvailableQuotaBytes /*OPTIONAL*/,
                       /*OUT*/ uint64 *TotalQuotaBytes /*OPTIONAL*/,
                       /*OUT*/ uint64 *TotalVolumeBytes /*OPTIONAL*/)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

/* MEMORY */

bool
safe_read_ex(const void *base, size_t size, void *out_buf, size_t *bytes_read)
{
    /* TODO(peter): Reimplement this like DynamoRIO Linux: do the read and
     * respond to a page fault. */
    if (is_readable_without_exception(base, size)) {
        memcpy(out_buf, base, size);
        if (bytes_read) {
            *bytes_read = size;
        }
        return true;
    } else {
        if (bytes_read) {
            *bytes_read = 0;
        }
        return false;
    }
}

bool
safe_read(const void *base, size_t size, void *out_buf)
{
    return safe_read_ex(base, size, out_buf, NULL); 
}

bool
safe_write_ex(void *base, size_t size, const void *in_buf, size_t *bytes_written)
{
    /* TODO(peter): Reimplement this like DynamoRIO Linux: do the write and
     * respond to a page fault. */
    if (!page_table_writable_without_exception(
            get_l4_page_table(), base, size)) {
        *bytes_written = 0;
        return false;
    }

    memcpy(base, in_buf, size);
    *bytes_written = size;
    return true;
}

bool
is_readable_without_exception(const byte *pc, size_t size)
{
    return is_readable_without_exception_query_os((void*) pc, size);
}

bool
is_readable_without_exception_query_os(byte *pc, size_t size)
{
    return page_table_readable_without_exception(
            get_l4_page_table(), (void*) pc, size);
}

bool
is_user_address(byte *pc)
{
    ptr_uint_t a = (ptr_uint_t) pc;
    return (a <= 0x00007fffffffffff) ||
           /* [vsyscall] in /proc/self/maps */
           (a >= 0xffffffffff600000 && a < 0xffffffffff601000);
}

bool 
os_set_protection(byte *pc, size_t length, uint prot/*MEMPROT_*/)
{
    /* TODO(peter): Implement this. */    
    return true;
}

bool
set_protection(byte *pc, size_t length, uint prot/*MEMPROT_*/)
{
    /* TODO(peter): Implement this. */    
    return true;
}

bool
change_protection(byte *pc, size_t length, bool writable)
{
    /* TODO(peter): Implement this. */    
    return true;
}

bool
make_writable(byte *pc, size_t size)
{
    /* TODO(peter): Implement this. */    
    return true;
}

void
make_unwritable(byte *pc, size_t size)
{
    /* TODO(peter): Implement this. */    
}

bool
get_memory_info(const byte *pc, byte **base_pc, size_t *size,
                uint *prot /* OUT optional, returns MEMPROT_* value */)
{
    return get_memory_info_from_os(pc, base_pc, size, prot);
}

static inline uint
vm_region_prot(const vm_region_t *region)
{
    uint prot = DR_MEMPROT_NONE;
    if (region->present) {
        prot |= DR_MEMPROT_READ;
        if (region->access.writable) {
            prot |= DR_MEMPROT_WRITE;
        }
        if (region->access.executable) {
            prot |= DR_MEMPROT_EXEC;
        }
    }
    return prot;
}

bool
query_memory_ex_from_os(const byte *pc, OUT dr_mem_info_t *info)
{
    vm_region_t region;
    /* TODO(peter): page_table_get_region is way too slow. For now, just get the
     * single page's attributes. page_table_get_region can be made faster using
     * caching -- which adds complexity of cache consistency (i.e., mov cr3,
     * invlpg) -- or a better page_table_get_region algorithm (the current
     * algorithm scans over the entire page table -- very brutal!)
     */
#if 0
    page_table_get_region(get_l4_page_table(), (void*) pc, &region);
#else
    unsigned long pfn;
    generic_page_table_entry_t *parent;
    int parent_level;
    page_table_get_page(get_l4_page_table(), (void*) pc, &region, &pfn,
                        &parent, &parent_level);
#endif
    info->base_pc = region.start;
    info->size = region.end - region.start + 1;
    info->prot = vm_region_prot(&region);
    if (region.present) {
        /* TODO(peter): This should be DR_MEMTYPE_IMAGE in some situations
         * (i.e., when the region holds a module or kernel code). */
        info->type = DR_MEMTYPE_DATA;
    } else {
        info->type = DR_MEMTYPE_FREE;
    }
    return true;
}

bool
get_memory_info_from_os(const byte *pc, byte **base_pc, size_t *size,
                        uint *prot /* OUT optional, returns MEMPROT_* value */)
{
    /* Copied from original linux/os.c */
    dr_mem_info_t info;
    if (!query_memory_ex_from_os(pc, &info) || info.type == DR_MEMTYPE_FREE)
        return false;
    if (base_pc != NULL)
        *base_pc = info.base_pc;
    if (size != NULL)
        *size = info.size;
    if (prot != NULL)
        *prot = info.prot;
    return true;
}

void
all_memory_areas_lock()
{
    /* Intentionally made a no-op. */
}

void
all_memory_areas_unlock()
{
    /* Intentionally made a no-op. */
}


void
update_all_memory_areas(app_pc start, app_pc end_in, uint prot, int type)
{
    /* Intentionally made a no-op. */
}

bool
remove_from_all_memory_areas(app_pc start, app_pc end)
{
    /* Intentionally made a no-op. */
    return true;
}

static void
find_executable_vm_areas_callback(const vm_region_t *region, void *arg)
{
    int *count = (int *) arg;
    if (region->present && !region->access.user) {
        if (app_memory_allocation(NULL,
                                  region->start,
                                  region->end - region->start + 1,
                                  vm_region_prot(region),
                                  false /* !image */
                                  _IF_DEBUG("find_executable_vm_areas"))) {
            *count += 1;
        }
    }
}

int
find_executable_vm_areas(void)
{
    /* TODO(peter): The code below adds memory areas for the current CPU.
     * different CPUs may have different mappings, so this could be
     * completely broken. We need to expand the vmareas module to allow
     * for different VM mappings for different threads.
     */
    int count = 0;
    traverse_page_table_contiguous(get_l4_page_table(),
                                   find_executable_vm_areas_callback,
                                   &count);
    return count;
}

int
find_dynamo_library_vm_areas(void)
{
    add_dynamo_vm_area(get_dynamorio_dll_start(), get_dynamorio_dll_end(),
                       MEMPROT_READ|MEMPROT_WRITE|MEMPROT_EXEC,
                       true /* from image */ _IF_DEBUG("dynamorio.ko"));
    return 1;
}

bool
get_stack_bounds(dcontext_t *dcontext, byte **base, byte **top)
{
    vm_region_t stack;
    page_table_get_region(get_l4_page_table(),
                          (app_pc) get_mcontext(dcontext)->xsp,
                          &stack);
    ASSERT(stack.present);
    *base = stack.start;
    *top = stack.end;
    return true;
}



bool
ignorable_system_call(int num)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
is_clone_thread_syscall(dcontext_t *dcontext)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
is_sigreturn_syscall(dcontext_t *dcontext)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
was_sigreturn_syscall(dcontext_t *dcontext)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
pre_system_call(dcontext_t *dcontext)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

void
post_system_call(dcontext_t *dcontext)
{
    ASSERT_NOT_PORTED(false);
}

bool
is_in_dynamo_dll(app_pc pc)
{
    ASSERT(dynamorio_module_start != NULL);
    return (pc >= dynamorio_module_start && pc < dynamorio_module_end);
}

static void 
find_dynamorio_module_bounds(void)
{
    DEBUG_DECLARE(bool ret =) kernel_find_dynamorio_module_bounds(
        &dynamorio_module_start, &dynamorio_module_end);
    ASSERT(ret);
}

app_pc
get_dynamorio_dll_start(void)
{
    if (dynamorio_module_start == NULL) {
        find_dynamorio_module_bounds();
    }
    return dynamorio_module_start;
}

app_pc
get_dynamorio_dll_end(void)
{
    if (dynamorio_module_start == NULL) {
        find_dynamorio_module_bounds();
    }
    return dynamorio_module_end;
}

/* Start of code copied from the original linux port. */

/* in utils.c, exported only for our hack! */
extern void deadlock_avoidance_unlock(mutex_t *lock, bool ownable);

void
mutex_wait_contended_lock(mutex_t *lock)
{
    IF_CLIENT_INTERFACE(dcontext_t *dcontext = get_thread_private_dcontext();)
    /* FIXME: we don't actually use system calls to synchronize on Linux,
     * one day we would use futex(2) on this path (PR 295561). 
     * For now we use a busy-wait lock.
     * If we do use a true wait need to set client_thread_safe_for_synch around it */

    /* we now have to undo our earlier request */
    atomic_dec_and_test(&lock->lock_requests);

    while (!mutex_trylock(lock)) {
#ifdef CLIENT_INTERFACE
        if (dcontext != NULL && IS_CLIENT_THREAD(dcontext) &&
            (mutex_t *)dcontext->client_data->client_grab_mutex == lock)
            dcontext->client_data->client_thread_safe_for_synch = true;
#endif
        thread_yield();
#ifdef CLIENT_INTERFACE
        if (dcontext != NULL && IS_CLIENT_THREAD(dcontext) &&
            (mutex_t *)dcontext->client_data->client_grab_mutex == lock)
            dcontext->client_data->client_thread_safe_for_synch = false;
#endif
    }

#ifdef DEADLOCK_AVOIDANCE
    /* HACK: trylock's success causes it to do DEADLOCK_AVOIDANCE_LOCK, so to
     * avoid two in a row (causes assertion on owner) we unlock here
     * In the future we will remove the trylock here and this will go away.
     */
    deadlock_avoidance_unlock(lock, true);
#endif

    return;
    
}

void
mutex_notify_released_lock(mutex_t *lock)
{
    /* nothing to do here */
}

/* read_write_lock_t implementation doesn't expect the contention path
   helpers to guarantee the lock is held (unlike mutexes) so simple
   yields are still acceptable.
*/
void
rwlock_wait_contended_writer(read_write_lock_t *rwlock)
{
    thread_yield();
}

void
rwlock_notify_writer(read_write_lock_t *rwlock)
{
    /* nothing to do here */
}

void
rwlock_wait_contended_reader(read_write_lock_t *rwlock)
{
    thread_yield();
}

void
rwlock_notify_readers(read_write_lock_t *rwlock)
{
    /* nothing to do here */
}

/***************************************************************************/

/* events are un-signaled when successfully waited upon. */
typedef struct linux_event_t {
    volatile bool signaled;
    mutex_t lock;
} linux_event_t;


/* FIXME: this routine will need to have a macro wrapper to let us assign different ranks to 
 * all events for DEADLOCK_AVOIDANCE.  Currently a single rank seems to work.
 */
event_t
create_event()
{
    event_t e = (event_t) global_heap_alloc(sizeof(linux_event_t) HEAPACCT(ACCT_OTHER));
    e->signaled = false;
    ASSIGN_INIT_LOCK_FREE(e->lock, event_lock); /* FIXME: we'll need to pass the event name here */
    return e;
}

void
destroy_event(event_t e)
{
    DELETE_LOCK(e->lock);
    global_heap_free(e, sizeof(linux_event_t) HEAPACCT(ACCT_OTHER));
}

/* FIXME PR 295561: use futex */
void
signal_event(event_t e)
{
    mutex_lock(&e->lock);
    e->signaled = true;
    LOG(THREAD_GET, LOG_THREADS, 3,"thread %d signalling event "PFX"\n",get_thread_id(),e);
    mutex_unlock(&e->lock);
}

void
reset_event(event_t e)
{
    mutex_lock(&e->lock);
    e->signaled = false;
    LOG(THREAD_GET, LOG_THREADS, 3,"thread %d resetting event "PFX"\n",get_thread_id(),e);
    mutex_unlock(&e->lock);
}

/* FIXME: compare use and implementation with  man pthread_cond_wait */
/* FIXME PR 295561: use futex */
void
wait_for_event(event_t e)
{
#ifdef DEBUG
    dcontext_t *dcontext = get_thread_private_dcontext();
#endif
    /* Use a user-space event on Linux, a kernel event on Windows. */
    LOG(THREAD, LOG_THREADS, 3, "thread %d waiting for event "PFX"\n",get_thread_id(),e);
    while (true) {
        if (e->signaled) {
            mutex_lock(&e->lock);
            if (!e->signaled) {
                /* some other thread beat us to it */
                LOG(THREAD, LOG_THREADS, 3, "thread %d was beaten to event "PFX"\n",
                    get_thread_id(),e);
                mutex_unlock(&e->lock);
            } else {
                /* reset the event */
                e->signaled = false;
                mutex_unlock(&e->lock);
                LOG(THREAD, LOG_THREADS, 3,
                    "thread %d finished waiting for event "PFX"\n", get_thread_id(),e);
                return;
            }
        }
        thread_yield();
    }
}

/* End of code copied from the original Linux port. */

uint
os_random_seed()
{
    /* Return the low 32 bits of the cycle count. */
    return (uint) get_cycle_count();
}

void
take_over_primary_thread()
{
    ASSERT_NOT_PORTED(false);
}

bool
os_current_user_directory(char *directory_prefix /* INOUT */,
                          uint directory_len,
                          bool create)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
os_validate_user_owned(file_t file_or_directory_handle)
{
    ASSERT_NOT_PORTED(false);
    return true;
}

bool
os_check_option_compatibility(void)
{
    #define MAKE_OPTION_FALSE(opt) do {\
        if (DYNAMO_OPTION(opt)) {\
            dynamo_options.opt = false;\
            changed_options = true;\
        }\
    } while(0)

    #define MAKE_OPTION_TRUE(opt) do {\
        if (!DYNAMO_OPTION(opt)) {\
            dynamo_options.opt = true;\
            changed_options = true;\
        }\
    } while(0)
    bool changed_options = false;

    /* Linux reserves the bottom of the address space for applications, so
     * it would be impossible for us to locate the heap in the lower 4GB.
     */
    MAKE_OPTION_FALSE(heap_in_lower_4GB);

    /* We use kernel functions to reserve memory, so, because of reentrancy,
     * we have to make this reservation up front. Once we've taken over, we
     * can't reserve any more memory.
     */
    MAKE_OPTION_FALSE(switch_to_os_at_vmm_reset_limit);

    /* We have to use VM reservations because we can't request memory from
     * the kernel once we've taken over.
     */
    MAKE_OPTION_TRUE(vm_reserve);

    /* We can't support this because initialization requires all CPUs to be
     * in DR simultaneously.
     */
    MAKE_OPTION_FALSE(single_thread_in_DR);

    /* We want to use thread-private BBs. For now, it's necessary because we
     * rely on patching thread-private gencode and for bootstrapping TLS at
     * entry points. */
    MAKE_OPTION_FALSE(shared_bbs);

    /* We want to use thread-private traces. For now, it's necessary because we
     * rely on patching thread-private gencode and for bootstrapping TLS at
     * entry points. */
    MAKE_OPTION_FALSE(shared_traces);

    /* We need threads to have their own IBL routines for patching. */
    MAKE_OPTION_FALSE(shared_trace_ibl_routine);

    /* Don't support separate stubs because they make translating from stub
     * PC to fragment difficult. We need to do this translation in interrupt
     * handling.
     */
    MAKE_OPTION_FALSE(separate_private_stubs);
    MAKE_OPTION_FALSE(separate_shared_stubs);
    MAKE_OPTION_FALSE(free_private_stubs);
    MAKE_OPTION_FALSE(unsafe_free_shared_stubs);


    /* Any of these unsafe options will make us fail miserably. If the eflags
     * aren't restored properly across IBL, then the kernel crashes. I know this
     * because I wasn't properly restoring eflags in interrupted IBL routines.*/
    MAKE_OPTION_FALSE(unsafe_ignore_overflow);
    MAKE_OPTION_FALSE(unsafe_ignore_eflags);
    MAKE_OPTION_FALSE(unsafe_ignore_eflags_trace);
    MAKE_OPTION_FALSE(unsafe_ignore_eflags_prefix);
    MAKE_OPTION_FALSE(unsafe_ignore_eflags_ibl);
    
    #undef MAKE_OPTION_FALSE

    return changed_options;
}

void 
report_diagnostics(IN const char *message,
                   IN const char *name,
                   security_violation_t violation_type)
{
    /* Not implemented in the original Linux version. */
}

void
diagnost_exit()
{
}

bool
check_for_unsupported_modules()
{
    ASSERT_NOT_PORTED(false);
    return true;
}

void
pcprofile_fragment_deleted(dcontext_t *dcontext, fragment_t *f)
{
    ASSERT_NOT_PORTED(false);
}

void
pcprofile_thread_exit(dcontext_t *dcontext) {
    ASSERT_NOT_PORTED(false);
}

void *
get_clone_record(reg_t xsp)
{
    ASSERT_NOT_PORTED(false);
    return NULL;
}

reg_t
get_clone_record_app_xsp(void *record)
{
    ASSERT_NOT_PORTED(false);
    return 0;
}

byte *
get_clone_record_dstack(void *record)
{
    ASSERT_NOT_PORTED(false);
    return NULL;
}

app_pc
signal_thread_inherit(dcontext_t *dcontext, void *clone_record)
{
    ASSERT_NOT_PORTED(false);
    return NULL;
}

void
thread_set_self_context(void *cxt)
{
    ASSERT_NOT_PORTED(false);
}

void
thread_set_self_mcontext(dr_mcontext_t *mc)
{
    ASSERT_NOT_PORTED(false);
}

void
master_signal_handler_C(int sig, /*siginfo_t *siginfo, kernel_ucontext_t *ucxt,*/
                        byte *xsp)
{
    ASSERT_NOT_PORTED(false);
}

void
receive_pending_signal(dcontext_t *dcontext)
{
    ASSERT_NOT_PORTED(false);
}

void
os_forge_exception(app_pc target_pc, exception_type_t type)
{
    ASSERT_NOT_PORTED(false);
}

void
os_dump_core(const char *msg)
{
    print_file(STDERR, "Core dump: %s\n", msg);
    os_terminate(NULL, 0);
}

bool
set_itimer_callback(dcontext_t *dcontext, int which, uint millisec,
                    void (*func)(dcontext_t *, dr_mcontext_t *))
{
    ASSERT_NOT_PORTED(false);
    return true;
}

uint
get_itimer_frequency(dcontext_t *dcontext, int which)
{
    ASSERT_NOT_PORTED(false);
    return 0;
}

void
dr_setjmp_sigmask(dr_jmp_buf_t *buf)
{
    ASSERT_NOT_PORTED(false);
}

bool make_copy_on_writable(byte *pc, size_t size)
{
    ASSERT_NOT_PORTED(false);
    return false;
}

void mem_stats_snapshot(void) {
    /* Not implemented in the original linux version. */
}

bool
is_mapped_as_image(app_pc module_base)
{
    ASSERT_NOT_PORTED(false);
    return false;
}

void
print_modules(file_t f, bool dump_xml)
{
    ASSERT_NOT_PORTED(false);
}
