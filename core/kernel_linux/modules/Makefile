EXTRA_CFLAGS=-O2 -g $(DR_INCLUDE_FLAGS) -Werror -Wframe-larger-than=4096

EXTRA_AFLAGS=$(DR_INCLUDE_FLAGS)\
 -Xassembler -mmnemonic=intel -Xassembler -msyntax=intel -Xassembler -mnaked-reg\
 -Xassembler --noexecstack -Xassembler --64

obj-m += dynamorio_controller.o
dynamorio_controller-objs :=\
../../kernel_linux/dynamorio_controller_module.o\
../../kernel_linux/simple_tests/wrap.o\
../../kernel_linux/simple_tests/recurse.o\
../../kernel_linux/simple_tests/retaddr.o\
../../kernel_linux/simple_tests/eflags.o\
../../kernel_linux/simple_tests/eflags_asm.o\
../../kernel_linux/simple_tests/fib.o\
../../kernel_linux/simple_tests/xsave.o\
../../kernel_linux/simple_tests/exception_asm.o\
../../kernel_linux/simple_tests/repstr.o\
../../kernel_linux/simple_tests.o

################################################################################
## TODO i#20: Re-enable this module once the previous module has been ported.
## obj-m += dynamorio.o
## dynamorio-objs :=\
## ../../exports.o\
## ../../buildmark.o\
## ../../config.o\
## ../../dispatch.o\
## ../../dynamo.o\
## ../../emit.o\
## ../../fcache.o\
## ../../fragment.o\
## ../../hashtable.o\
## ../../heap.o\
## ../../hotpatch.o\
## ../../instrlist.o\
## ../../io.o\
## ../../link.o\
## ../../loader_shared.o\
## ../../moduledb.o\
## ../../module_list.o\
## ../../monitor.o\
## ../../nudge.o\
## ../../options.o\
## ../../perfctr.o\
## ../../perscache.o\
## ../../rct.o\
## ../../stats.o\
## ../../synch.o\
## ../../unit-rct.o\
## ../../utils.o\
## ../../barrier.o\
## ../../vmareas.o\
## ../../x86/arch.o\
## ../../x86/decode.o\
## ../../x86/decode_fast.o\
## ../../x86/decode_table.o\
## ../../x86/disassemble.o\
## ../../x86/emit_utils.o\
## ../../x86/encode.o\
## ../../x86/instr.o\
## ../../x86/instrument.o\
## ../../x86/interp.o\
## ../../x86/loadtoconst.o\
## ../../x86/mangle.o\
## ../../x86/optimize.o\
## ../../x86/proc.o\
## ../../x86/retcheck.o\
## ../../x86/sideline.o\
## ../../x86/steal_reg.o\
## ../../x86/x86_code.o\
## ../../x86/asm_defines.o\
## ../../x86/x86.o\
## ../../kernel_linux/os.o\
## ../../kernel_linux/hypercall_guest.o\
## ../../kernel_linux/page_table.o\
## ../../kernel_linux/kernel_interface.o\
## ../../kernel_linux/dynamorio_module_interface.o\
## ../../kernel_linux/dynamorio_module.o
################################################################################

################################################################################
## TODO i#20: Re-enable this module once the previous modules have been ported.
## obj-m += dr_kernel_utils.o
## dr_kernel_utils-objs :=\
## ../../kernel_linux/dr_kernel_utils.o
################################################################################

################################################################################
## TODO i#20: Re-enable the clients once the core modules have been ported.
## obj-m += instrcount.o
## instrcount-objs :=\
## ../../kernel_linux/clients/instrcount_module.o

## obj-m += stress_dead_reg.o
## stress_dead_reg-objs :=\
## ../../kernel_linux/clients/stress_dead_reg_module.o

## obj-m += cleancall.o
## cleancall-objs :=\
## ../../kernel_linux/clients/cleancall_module.o

## obj-m += client_codecache.o
## client_codecache-objs :=\
## ../../kernel_linux/clients/client_codecache.o

## obj-m += client_cleancall_codecache.o
## client_cleancall_codecache-objs :=\
## ../../kernel_linux/clients/client_cleancall_codecache.o
################################################################################

################################################################################
## We are skipping umbra for now due to its tight coupling with the kernel and not a high priority.
## obj-m += umbra.o
## umbra-objs :=\
## ../../kernel_linux/clients/umbra/analyzer.o\
## ../../kernel_linux/clients/umbra/cfg.o\
## ../../kernel_linux/clients/umbra/dr_client.o\
## ../../kernel_linux/clients/umbra/instrument.o\
## ../../kernel_linux/clients/umbra/optimize.o\
## ../../kernel_linux/clients/umbra/shadow.o\
## ../../kernel_linux/clients/umbra/table.o\
## ../../kernel_linux/clients/umbra/umbra.o\
## ../../kernel_linux/clients/umbra/utils.o\
## ../../kernel_linux/clients/umbra/memcheck.o\
## ../../kernel_linux/clients/umbra/memcheck_test.o\
## ../../kernel_linux/clients/umbra/pagepool.o
################################################################################

################################################################################
## TODO i#20: Re-enable the clients once the core modules have been ported.
## obj-m += bb_stats.o
## bb_stats-objs :=\
## ../../kernel_linux/clients/bb_stats.o

## obj-m += null.o
## null-objs :=\
## ../../kernel_linux/clients/null.o
################################################################################
