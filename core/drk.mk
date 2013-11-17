.DELETE_ON_ERROR:
# REQUIRED - The kernel being instrumented.
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

# OPTIONAL - If you're running DRK on kernel running in a KVM VM, this is the
# KVM host's kernel. See HYPERCALL_DEBUGGING in configure.h.
HOST_KERNELDIR ?= /lib/modules/$(shell uname -r)/build

API_INCLUDE_DIR ?= lib/include

.PHONY: default
.PHONY: scons
.PHONY: test

DR_CORE_DIR := $(shell pwd)
DR_INCLUDE_FLAGS := -DDR_REG_ENUM_COMPATIBILITY -DX86_64 -DLINUX -DLINUX_KERNEL\
					-I$(DR_CORE_DIR)/$(API_INCLUDE_DIR)\
					-I$(DR_CORE_DIR)/kernel_linux\
					-I$(DR_CORE_DIR)/lib\
					-I$(DR_CORE_DIR)/x86\
					-I$(DR_CORE_DIR)

MODULES_MAKE =-C $(KERNELDIR) M=$(DR_CORE_DIR)/kernel_linux/modules\
			  DR_CORE_DIR=$(DR_CORE_DIR) DR_INCLUDE_FLAGS="$(DR_INCLUDE_FLAGS)"

HOST_MODULES_MAKE=-C $(HOST_KERNELDIR) M=$(DR_CORE_DIR)/kernel_linux/host_modules\
			      DR_CORE_DIR=$(DR_CORE_DIR) DR_INCLUDE_FLAGS="$(DR_INCLUDE_FLAGS)"

ASM_FILES= $(shell find . -name '*.asm' | sed 's/\.asm/.S/g')

default: exports.c api_headers scons $(ASM_FILES) 
	cp kernel_linux/host_modules/Module.symvers.in kernel_linux/host_modules/Module.symvers
	cp kernel_linux/modules/Module.symvers.in kernel_linux/modules/Module.symvers
	$(MAKE) $(MODULES_MAKE) modules
	$(MAKE) $(HOST_MODULES_MAKE) modules
	
scons:
	scons -j10

test: scons
	./run_unittests.py

exports.c: $(API_INCLUDE_DIR) exports.py
	./exports.py $(API_INCLUDE_DIR)	> exports.c

api_headers: $(API_INCLUDE_DIR)	

$(API_INCLUDE_DIR): $(shell find . -name '*.h' | grep -v $(API_INCLUDE_DIR) | grep -v 'kernel_linux/clients') lib/genapi.pl
	mkdir -p $(API_INCLUDE_DIR)
	touch $(API_INCLUDE_DIR)
	./lib/genapi.pl -header $(API_INCLUDE_DIR) "$(shell ./defines.py configure.h) -DAPI_EXPORT_ONLY"
	cp lib/dr_api.h $(API_INCLUDE_DIR)/dr_api.h
	sed -i 's/$${VERSION_NUMBER_INTEGER}/200/' $(API_INCLUDE_DIR)/dr_api.h
	./defines.py configure.h | grep -v '\-DDEBUG'; sed -i "s/\$${DEBUG}/$$?/" $(API_INCLUDE_DIR)/dr_api.h

%.S: %.asm
	cpp  $(DR_INCLUDE_FLAGS) -Ddynamorio_EXPORTS -E $^ -o $@
	sed -i 's/@N@/\n/g' $@

clean:
	$(MAKE) $(MODULES_MAKE) clean
	$(MAKE) $(HOST_MODULES_MAKE) clean
	scons -c
	rm -f $$(find . -name '*.S')
	rm -f $$(find . -name '*.o')
	rm -f $$(find . -name '.*.o.cmd')
	rm -rf lib/include
	rm -f exports.c
