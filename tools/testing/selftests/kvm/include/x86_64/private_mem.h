/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2022, Google LLC.
 */

#ifndef SELFTEST_KVM_PRIVATE_MEM_H
#define SELFTEST_KVM_PRIVATE_MEM_H

#include <stdint.h>
#include <kvm_util.h>

void kvm_hypercall_map_shared(uint64_t gpa, uint64_t size);
void kvm_hypercall_map_private(uint64_t gpa, uint64_t size);

void vm_unback_private_mem(struct kvm_vm *vm, uint64_t gpa, uint64_t size);

void vm_allocate_private_mem(struct kvm_vm *vm, uint64_t gpa, uint64_t size);

typedef void (*guest_code_fn)(void);
typedef void (*io_exit_handler)(struct kvm_vm *vm, uint32_t uc_arg1);

struct test_setup_info {
	uint64_t test_area_gpa;
	uint64_t test_area_size;
	uint32_t test_area_slot;
};

struct vm_setup_info {
	enum vm_mem_backing_src_type test_mem_src;
	struct test_setup_info test_info;
	guest_code_fn guest_fn;
	io_exit_handler ioexit_cb;
};

void execute_vm_with_private_test_mem(struct vm_setup_info *info);

#endif /* SELFTEST_KVM_PRIVATE_MEM_H */
