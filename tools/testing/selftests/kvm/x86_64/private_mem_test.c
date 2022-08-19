// SPDX-License-Identifier: GPL-2.0
/*
 * tools/testing/selftests/kvm/lib/kvm_util.c
 *
 * Copyright (C) 2022, Google LLC.
 */
#define _GNU_SOURCE /* for program_invocation_short_name */
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
#include <linux/memfd.h>

#include <test_util.h>
#include <kvm_util.h>
#include <private_mem.h>
#include <processor.h>

#define TEST_AREA_SLOT		10
#define TEST_AREA_GPA		0xC0000000
#define TEST_AREA_SIZE		(2 * 1024 * 1024)
#define GUEST_TEST_MEM_OFFSET	(1 * 1024 * 1024)
#define GUEST_TEST_MEM_SIZE	(10 * 4096)

#define VM_STAGE_PROCESSED(x)	pr_info("Processed stage %s\n", #x)

#define TEST_MEM_DATA_PATTERN1	0x66
#define TEST_MEM_DATA_PATTERN2	0x99
#define TEST_MEM_DATA_PATTERN3	0x33
#define TEST_MEM_DATA_PATTERN4	0xaa
#define TEST_MEM_DATA_PATTERN5	0x12

static bool verify_mem_contents(void *mem, uint32_t size, uint8_t pattern)
{
	uint8_t *buf = (uint8_t *)mem;

	for (uint32_t i = 0; i < size; i++) {
		if (buf[i] != pattern)
			return false;
	}

	return true;
}

static void populate_test_area(void *test_area_base, uint64_t pattern)
{
	memset(test_area_base, pattern, TEST_AREA_SIZE);
}

static void populate_guest_test_mem(void *guest_test_mem, uint64_t pattern)
{
	memset(guest_test_mem, pattern, GUEST_TEST_MEM_SIZE);
}

static bool verify_test_area(void *test_area_base, uint64_t area_pattern,
	uint64_t guest_pattern)
{
	void *guest_test_mem = test_area_base + GUEST_TEST_MEM_OFFSET;
	void *test_area2_base = guest_test_mem + GUEST_TEST_MEM_SIZE;
	uint64_t test_area2_size = (TEST_AREA_SIZE - (GUEST_TEST_MEM_OFFSET +
			GUEST_TEST_MEM_SIZE));

	return (verify_mem_contents(test_area_base, GUEST_TEST_MEM_OFFSET, area_pattern) &&
		verify_mem_contents(guest_test_mem, GUEST_TEST_MEM_SIZE, guest_pattern) &&
		verify_mem_contents(test_area2_base, test_area2_size, area_pattern));
}

#define GUEST_STARTED			0
#define GUEST_PRIVATE_MEM_POPULATED	1
#define GUEST_SHARED_MEM_POPULATED	2
#define GUEST_PRIVATE_MEM_POPULATED2	3

/*
 * Run memory conversion tests with explicit conversion:
 * Execute KVM hypercall to map/unmap gpa range which will cause userspace exit
 * to back/unback private memory. Subsequent accesses by guest to the gpa range
 * will not cause exit to userspace.
 *
 * Test memory conversion scenarios with following steps:
 * 1) Access private memory using private access and verify that memory contents
 *   are not visible to userspace.
 * 2) Convert memory to shared using explicit conversions and ensure that
 *   userspace is able to access the shared regions.
 * 3) Convert memory back to private using explicit conversions and ensure that
 *   userspace is again not able to access converted private regions.
 */
static void guest_conv_test_fn(void)
{
	void *test_area_base = (void *)TEST_AREA_GPA;
	void *guest_test_mem = (void *)(TEST_AREA_GPA + GUEST_TEST_MEM_OFFSET);
	uint64_t guest_test_size = GUEST_TEST_MEM_SIZE;

	GUEST_SYNC(GUEST_STARTED);

	populate_test_area(test_area_base, TEST_MEM_DATA_PATTERN1);
	GUEST_SYNC(GUEST_PRIVATE_MEM_POPULATED);
	GUEST_ASSERT(verify_test_area(test_area_base, TEST_MEM_DATA_PATTERN1,
		TEST_MEM_DATA_PATTERN1));

	kvm_hypercall_map_shared((uint64_t)guest_test_mem, guest_test_size);

	populate_guest_test_mem(guest_test_mem, TEST_MEM_DATA_PATTERN2);

	GUEST_SYNC(GUEST_SHARED_MEM_POPULATED);
	GUEST_ASSERT(verify_test_area(test_area_base, TEST_MEM_DATA_PATTERN1,
		TEST_MEM_DATA_PATTERN5));

	kvm_hypercall_map_private((uint64_t)guest_test_mem, guest_test_size);

	populate_guest_test_mem(guest_test_mem, TEST_MEM_DATA_PATTERN3);
	GUEST_SYNC(GUEST_PRIVATE_MEM_POPULATED2);

	GUEST_ASSERT(verify_test_area(test_area_base, TEST_MEM_DATA_PATTERN1,
		TEST_MEM_DATA_PATTERN3));
	GUEST_DONE();
}

static void conv_test_ioexit_fn(struct kvm_vm *vm, uint32_t uc_arg1)
{
	void *test_area_hva = addr_gpa2hva(vm, TEST_AREA_GPA);
	void *guest_test_mem_hva = (test_area_hva + GUEST_TEST_MEM_OFFSET);
	uint64_t guest_mem_gpa = (TEST_AREA_GPA + GUEST_TEST_MEM_OFFSET);
	uint64_t guest_test_size = GUEST_TEST_MEM_SIZE;

	switch (uc_arg1) {
	case GUEST_STARTED:
		populate_test_area(test_area_hva, TEST_MEM_DATA_PATTERN4);
		VM_STAGE_PROCESSED(GUEST_STARTED);
		break;
	case GUEST_PRIVATE_MEM_POPULATED:
		TEST_ASSERT(verify_test_area(test_area_hva, TEST_MEM_DATA_PATTERN4,
				TEST_MEM_DATA_PATTERN4), "failed");
		VM_STAGE_PROCESSED(GUEST_PRIVATE_MEM_POPULATED);
		break;
	case GUEST_SHARED_MEM_POPULATED:
		TEST_ASSERT(verify_test_area(test_area_hva, TEST_MEM_DATA_PATTERN4,
				TEST_MEM_DATA_PATTERN2), "failed");
		populate_guest_test_mem(guest_test_mem_hva, TEST_MEM_DATA_PATTERN5);
		VM_STAGE_PROCESSED(GUEST_SHARED_MEM_POPULATED);
		break;
	case GUEST_PRIVATE_MEM_POPULATED2:
		TEST_ASSERT(verify_test_area(test_area_hva, TEST_MEM_DATA_PATTERN4,
				TEST_MEM_DATA_PATTERN5), "failed");
		VM_STAGE_PROCESSED(GUEST_PRIVATE_MEM_POPULATED2);
		break;
	default:
		TEST_FAIL("Unknown stage %d\n", uc_arg1);
		break;
	}
}

static void execute_memory_conversion_test(enum vm_mem_backing_src_type test_mem_src)
{
	struct vm_setup_info info;
	struct test_setup_info *test_info = &info.test_info;

	info.test_mem_src = test_mem_src;
	test_info->test_area_gpa = TEST_AREA_GPA;
	test_info->test_area_size = TEST_AREA_SIZE;
	test_info->test_area_slot = TEST_AREA_SLOT;
	info.ioexit_cb = conv_test_ioexit_fn;

	info.guest_fn = guest_conv_test_fn;
	execute_vm_with_private_test_mem(&info);
}

int main(int argc, char *argv[])
{
	/* Tell stdout not to buffer its content */
	setbuf(stdout, NULL);

	execute_memory_conversion_test(VM_MEM_SRC_ANONYMOUS_AND_RESTRICTED_MEMFD);

	/* Needs 2MB Hugepages */
	if (get_free_huge_2mb_pages() >= 1) {
		printf("Running private mem test with 2M pages\n");
		execute_memory_conversion_test(VM_MEM_SRC_ANON_HTLB2M_AND_RESTRICTED_MEMFD);
	} else
		printf("Skipping private mem test with 2M pages\n");

	return 0;
}
