// SPDX-License-Identifier: GPL-2.0
/*
 * tools/testing/selftests/kvm/lib/kvm_util.c
 *
 * Copyright (C) 2022, Google LLC.
 */
#define _GNU_SOURCE /* for program_invocation_name */
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/kvm_para.h>

#include <test_util.h>
#include <kvm_util.h>
#include <private_mem.h>
#include <processor.h>

static inline uint64_t __kvm_hypercall_map_gpa_range(uint64_t gpa, uint64_t size,
	uint64_t flags)
{
	return kvm_hypercall(KVM_HC_MAP_GPA_RANGE, gpa, size >> PAGE_SHIFT, flags, 0);
}

static inline void kvm_hypercall_map_gpa_range(uint64_t gpa, uint64_t size,
	uint64_t flags)
{
	uint64_t ret;

	GUEST_ASSERT_2(IS_PAGE_ALIGNED(gpa) && IS_PAGE_ALIGNED(size), gpa, size);

	ret = __kvm_hypercall_map_gpa_range(gpa, size, flags);
	GUEST_ASSERT_1(!ret, ret);
}

void kvm_hypercall_map_shared(uint64_t gpa, uint64_t size)
{
	kvm_hypercall_map_gpa_range(gpa, size, KVM_MAP_GPA_RANGE_DECRYPTED);
}

void kvm_hypercall_map_private(uint64_t gpa, uint64_t size)
{
	kvm_hypercall_map_gpa_range(gpa, size, KVM_MAP_GPA_RANGE_ENCRYPTED);
}

static void vm_update_private_mem(struct kvm_vm *vm, uint64_t gpa, uint64_t size,
	bool unback_mem)
{
	int restricted_fd;
	uint64_t restricted_fd_offset, guest_phys_base, fd_offset;
	struct kvm_memory_attributes attr;
	struct kvm_userspace_memory_region_ext *region_ext;
	struct kvm_userspace_memory_region *region;
	int fallocate_mode = 0;
	int ret;

	region_ext = kvm_userspace_memory_region_ext_find(vm, gpa, gpa + size);
	TEST_ASSERT(region_ext != NULL, "Region not found");
	region = &region_ext->region;
	TEST_ASSERT(region->flags & KVM_MEM_PRIVATE,
		"Can not update private memfd for non-private memslot\n");
	restricted_fd = region_ext->restricted_fd;
	restricted_fd_offset = region_ext->restricted_offset;
	guest_phys_base = region->guest_phys_addr;
	fd_offset = restricted_fd_offset + (gpa - guest_phys_base);

	if (unback_mem)
		fallocate_mode = (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE);

	printf("restricted_fd %d fallocate_mode 0x%x for offset 0x%lx size 0x%lx\n",
		restricted_fd, fallocate_mode, fd_offset, size);
	ret = fallocate(restricted_fd, fallocate_mode, fd_offset, size);
	TEST_ASSERT(ret == 0, "fallocate failed\n");
	attr.attributes = unback_mem ? 0 : KVM_MEMORY_ATTRIBUTE_PRIVATE;
	attr.address = gpa;
	attr.size = size;
	attr.flags = 0;
	if (unback_mem)
		printf("undoing encryption for gpa 0x%lx size 0x%lx\n", gpa, size);
	else
		printf("doing encryption for gpa 0x%lx size 0x%lx\n", gpa, size);

	vm_ioctl(vm, KVM_SET_MEMORY_ATTRIBUTES, &attr);
}

void vm_unback_private_mem(struct kvm_vm *vm, uint64_t gpa, uint64_t size)
{
	vm_update_private_mem(vm, gpa, size, true);
}

void vm_allocate_private_mem(struct kvm_vm *vm, uint64_t gpa, uint64_t size)
{
	vm_update_private_mem(vm, gpa, size, false);
}

static void handle_vm_exit_map_gpa_hypercall(struct kvm_vm *vm,
				struct kvm_vcpu *vcpu)
{
	uint64_t gpa, npages, attrs, size;

	TEST_ASSERT(vcpu->run->hypercall.nr == KVM_HC_MAP_GPA_RANGE,
		"Unhandled Hypercall %lld\n", vcpu->run->hypercall.nr);
	gpa = vcpu->run->hypercall.args[0];
	npages = vcpu->run->hypercall.args[1];
	size = npages << MIN_PAGE_SHIFT;
	attrs = vcpu->run->hypercall.args[2];
	pr_info("Explicit conversion off 0x%lx size 0x%lx to %s\n", gpa, size,
		(attrs & KVM_MAP_GPA_RANGE_ENCRYPTED) ? "private" : "shared");

	if (attrs & KVM_MAP_GPA_RANGE_ENCRYPTED)
		vm_allocate_private_mem(vm, gpa, size);
	else
		vm_unback_private_mem(vm, gpa, size);

	vcpu->run->hypercall.ret = 0;
}

static void vcpu_work(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
	struct vm_setup_info *info)
{
	struct ucall uc;
	uint64_t cmd;

	/*
	 * Loop until the guest is done.
	 */

	while (true) {
		vcpu_run(vcpu);

		if (vcpu->run->exit_reason == KVM_EXIT_IO) {
			cmd = get_ucall(vcpu, &uc);
			if (cmd != UCALL_SYNC)
				break;

			TEST_ASSERT(info->ioexit_cb, "ioexit cb not present");
			info->ioexit_cb(vm, uc.args[1]);
			continue;
		}

		if (vcpu->run->exit_reason == KVM_EXIT_HYPERCALL) {
			handle_vm_exit_map_gpa_hypercall(vm, vcpu);
			continue;
		}

		TEST_FAIL("Unhandled VCPU exit reason %d\n",
			vcpu->run->exit_reason);
		break;
	}

	if (vcpu->run->exit_reason == KVM_EXIT_IO && cmd == UCALL_ABORT)
		TEST_FAIL("%s at %s:%ld, val = %lu", (const char *)uc.args[0],
			  __FILE__, uc.args[1], uc.args[2]);
}

/*
 * Execute guest vm with private memory memslots.
 *
 * Input Args:
 *   info - pointer to a structure containing information about setting up a VM
 *     with private memslots
 *
 * Output Args: None
 *
 * Return: None
 *
 * Function called by host userspace logic in selftests to execute guest vm
 * logic. It will install test_mem_slot : containing the region of memory that
 * would be used to test private/shared memory accesses to a memory backed by
 * private memslots
 */
void execute_vm_with_private_test_mem(struct vm_setup_info *info)
{
	struct kvm_vm *vm;
	struct kvm_enable_cap cap;
	struct kvm_vcpu *vcpu;
	uint64_t test_area_gpa, test_area_size;
	struct test_setup_info *test_info = &info->test_info;

	TEST_ASSERT(info->guest_fn, "guest_fn not present");
	vm = vm_create_with_one_vcpu(&vcpu, info->guest_fn);

	vm_check_cap(vm, KVM_CAP_EXIT_HYPERCALL);
	cap.cap = KVM_CAP_EXIT_HYPERCALL;
	cap.flags = 0;
	cap.args[0] = (1 << KVM_HC_MAP_GPA_RANGE);
	vm_ioctl(vm, KVM_ENABLE_CAP, &cap);

	TEST_ASSERT(test_info->test_area_size, "Test mem size not present");

	test_area_size = test_info->test_area_size;
	test_area_gpa = test_info->test_area_gpa;
	vm_userspace_mem_region_add(vm, info->test_mem_src, test_area_gpa,
		test_info->test_area_slot, test_area_size / vm->page_size,
		KVM_MEM_PRIVATE);
	vm_allocate_private_mem(vm, test_area_gpa, test_area_size);

	pr_info("Mapping test memory pages 0x%zx page_size 0x%x\n",
		test_area_size/vm->page_size, vm->page_size);
	virt_map(vm, test_area_gpa, test_area_gpa, test_area_size/vm->page_size);

	vcpu_work(vm, vcpu, info);

	kvm_vm_free(vm);
}
