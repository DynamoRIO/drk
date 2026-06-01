.DELETE_ON_ERROR:
.RECIPEPREFIX = >
# REQUIRED - The kernel being instrumented.
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

API_INCLUDE_DIR ?= lib/include

.PHONY: default
.PHONY: scons
.PHONY: test

DR_CORE_DIR := $(shell pwd)
DR_INCLUDE_FLAGS := -DDR_REG_ENUM_COMPATIBILITY -DLINUX_KERNEL -DDYNAMORIO_INTERNAL\
                    -I$(DR_CORE_DIR)/../build\
                    -I$(DR_CORE_DIR)/$(API_INCLUDE_DIR)\
                    -I$(DR_CORE_DIR)\
                    -I$(DR_CORE_DIR)/lib\
                    -I$(DR_CORE_DIR)/drlibc\
                    -I$(DR_CORE_DIR)/kernel_linux\
                    -I$(DR_CORE_DIR)/unix\
                    -I$(DR_CORE_DIR)/x86\
                    -I$(DR_CORE_DIR)/arch\
                    -I$(DR_CORE_DIR)/arch/x86\
                    -I$(DR_CORE_DIR)/ir\
                    -I$(DR_CORE_DIR)/ir/x86

MODULES_MAKE =-C $(KERNELDIR) M=$(DR_CORE_DIR)/kernel_linux/modules\
              DR_CORE_DIR=$(DR_CORE_DIR) DR_INCLUDE_FLAGS="$(DR_INCLUDE_FLAGS)"

ASM_FILES= $(shell find . -name '*.asm' | grep -vE 'aarch64|aarchxx|arm|riscv64' | sed 's/\.asm/.S/g')

# TODO i#20: Re-enable scons to build utility programs and tests.
# default: exports.c api_headers scons $(ASM_FILES)
default: exports.c api_headers $(ASM_FILES)
> cp kernel_linux/modules/Module.symvers.in kernel_linux/modules/Module.symvers
> $(MAKE) $(MODULES_MAKE) KBUILD_MODPOST_WARN=1 modules

scons:
> scons -j10

test: scons
> ./run_unittests.py

exports.c: $(API_INCLUDE_DIR) exports.py
> ./exports.py $(API_INCLUDE_DIR) > exports.c

api_headers: $(API_INCLUDE_DIR)

$(API_INCLUDE_DIR):
> mkdir -p $(API_INCLUDE_DIR)
> cp -r ../build/include/* $(API_INCLUDE_DIR)/

%.S: %.asm
> cpp  $(DR_INCLUDE_FLAGS) -Ddynamorio_EXPORTS -E $^ -o $@
> sed -i 's/@N@/\n/g' $@

clean:
> $(MAKE) $(MODULES_MAKE) clean
# TODO i#20: Re-enable scons to build utility programs and tests.
# scons -c
> rm -f $$(find . -name '*.S')
> rm -f $$(find . -name '*.o')
> rm -f $$(find . -name '.*.o.cmd')
> rm -rf lib/include
> rm -f exports.c
