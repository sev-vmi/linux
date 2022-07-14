# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the x86 low level entry code
#

OBJECT_FILES_NON_STANDARD_entry_64_compat.o := y

CFLAGS_REMOVE_common.o		= $(CC_FLAGS_FTRACE)

CFLAGS_common.o			+= -fno-stack-protector

obj-y				:= entry_$(BITS).o syscall_$(BITS).o
obj-y				+= common.o

obj-y				+= vdso/
obj-y				+= vsyscall/

obj-$(CONFIG_PREEMPTION)	+= thunk_$(BITS).o
obj-$(CONFIG_IA32_EMULATION)	+= entry_64_compat.o syscall_32.o

