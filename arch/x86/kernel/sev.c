// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2019 SUSE
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#define pr_fmt(fmt)	"SEV: " fmt

#include <linux/sched/debug.h>	/* For show_regs() */
#include <linux/percpu-defs.h>
#include <linux/mem_encrypt.h>
#include <linux/printk.h>
#include <linux/mm_types.h>
#include <linux/set_memory.h>
#include <linux/memblock.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/cpumask.h>
#include <linux/log2.h>
#include <linux/efi.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/cpumask.h>
#include <linux/iommu.h>

#include <asm/cpu_entry_area.h>
#include <asm/stacktrace.h>
#include <asm/sev.h>
#include <asm/insn-eval.h>
#include <asm/fpu/internal.h>
#include <asm/processor.h>
#include <asm/realmode.h>
#include <asm/setup.h>
#include <asm/traps.h>
#include <asm/svm.h>
#include <asm/smp.h>
#include <asm/cpu.h>
#include <asm/apic.h>
#include <asm/efi.h>
#include <asm/cpuid.h>
#include <asm/setup.h>
#include <asm/apic.h>
#include <asm/iommu.h>

#define DR7_RESET_VALUE        0x400

/*
 * The first 16KB from the RMP_BASE is used by the processor for the
 * bookkeeping, the range need to be added during the RMP entry lookup.
 */
#define RMPTABLE_CPU_BOOKKEEPING_SZ	0x4000
#define RMPENTRY_SHIFT			8
#define rmptable_page_offset(x)	(RMPTABLE_CPU_BOOKKEEPING_SZ + (((unsigned long)x) >> RMPENTRY_SHIFT))

/* For early boot hypervisor communication in SEV-ES enabled guests */
static struct ghcb boot_ghcb_page __bss_decrypted __aligned(PAGE_SIZE);

/*
 * Needs to be in the .data section because we need it NULL before bss is
 * cleared
 */
static struct ghcb __initdata *boot_ghcb;

/* Secrets page used to get keys for communicating with SNP FW. */
struct snp_secrets_page_layout *secrets_layout;

static unsigned long rmptable_start __ro_after_init;
static unsigned long rmptable_end __ro_after_init;


/* #VC handler runtime per-CPU data */
struct sev_es_runtime_data {
	struct ghcb ghcb_page;

	/* Physical storage for the per-CPU IST stack of the #VC handler */
	char ist_stack[EXCEPTION_STKSZ] __aligned(PAGE_SIZE);

	/*
	 * Physical storage for the per-CPU fall-back stack of the #VC handler.
	 * The fall-back stack is used when it is not safe to switch back to the
	 * interrupted stack in the #VC entry code.
	 */
	char fallback_stack[EXCEPTION_STKSZ] __aligned(PAGE_SIZE);

	/*
	 * Reserve one page per CPU as backup storage for the unencrypted GHCB.
	 * It is needed when an NMI happens while the #VC handler uses the real
	 * GHCB, and the NMI handler itself is causing another #VC exception. In
	 * that case the GHCB content of the first handler needs to be backed up
	 * and restored.
	 */
	struct ghcb backup_ghcb;

	/*
	 * Mark the per-cpu GHCBs as in-use to detect nested #VC exceptions.
	 * There is no need for it to be atomic, because nothing is written to
	 * the GHCB between the read and the write of ghcb_active. So it is safe
	 * to use it when a nested #VC exception happens before the write.
	 *
	 * This is necessary for example in the #VC->NMI->#VC case when the NMI
	 * happens while the first #VC handler uses the GHCB. When the NMI code
	 * raises a second #VC handler it might overwrite the contents of the
	 * GHCB written by the first handler. To avoid this the content of the
	 * GHCB is saved and restored when the GHCB is detected to be in use
	 * already.
	 */
	bool ghcb_active;
	bool backup_ghcb_active;

	/*
	 * Cached DR7 value - write it on DR7 writes and return it on reads.
	 * That value will never make it to the real hardware DR7 as debugging
	 * is currently unsupported in SEV-ES guests.
	 */
	unsigned long dr7;

	/*
	 * SEV-SNP requires that the GHCB must be registered before using it.
	 * The flag below will indicate whether the GHCB is registered, if its
	 * not registered then sev_es_get_ghcb() will perform the registration.
	 */
	bool snp_ghcb_registered;
};

struct ghcb_state {
	struct ghcb *ghcb;
};

static DEFINE_PER_CPU(struct sev_es_runtime_data*, runtime_data);
DEFINE_STATIC_KEY_FALSE(sev_es_enable_key);

static DEFINE_PER_CPU(struct sev_es_save_area *, snp_vmsa);

static void __init setup_vc_stacks(int cpu)
{
	struct sev_es_runtime_data *data;
	struct cpu_entry_area *cea;
	unsigned long vaddr;
	phys_addr_t pa;

	data = per_cpu(runtime_data, cpu);
	cea  = get_cpu_entry_area(cpu);

	/* Map #VC IST stack */
	vaddr = CEA_ESTACK_BOT(&cea->estacks, VC);
	pa    = __pa(data->ist_stack);
	cea_set_pte((void *)vaddr, pa, PAGE_KERNEL);

	/* Map VC fall-back stack */
	vaddr = CEA_ESTACK_BOT(&cea->estacks, VC2);
	pa    = __pa(data->fallback_stack);
	cea_set_pte((void *)vaddr, pa, PAGE_KERNEL);
}

static __always_inline bool on_vc_stack(struct pt_regs *regs)
{
	unsigned long sp = regs->sp;

	/* User-mode RSP is not trusted */
	if (user_mode(regs))
		return false;

	/* SYSCALL gap still has user-mode RSP */
	if (ip_within_syscall_gap(regs))
		return false;

	return ((sp >= __this_cpu_ist_bottom_va(VC)) && (sp < __this_cpu_ist_top_va(VC)));
}

/*
 * This function handles the case when an NMI is raised in the #VC
 * exception handler entry code, before the #VC handler has switched off
 * its IST stack. In this case, the IST entry for #VC must be adjusted,
 * so that any nested #VC exception will not overwrite the stack
 * contents of the interrupted #VC handler.
 *
 * The IST entry is adjusted unconditionally so that it can be also be
 * unconditionally adjusted back in __sev_es_ist_exit(). Otherwise a
 * nested sev_es_ist_exit() call may adjust back the IST entry too
 * early.
 *
 * The __sev_es_ist_enter() and __sev_es_ist_exit() functions always run
 * on the NMI IST stack, as they are only called from NMI handling code
 * right now.
 */
void noinstr __sev_es_ist_enter(struct pt_regs *regs)
{
	unsigned long old_ist, new_ist;

	/* Read old IST entry */
	new_ist = old_ist = __this_cpu_read(cpu_tss_rw.x86_tss.ist[IST_INDEX_VC]);

	/*
	 * If NMI happened while on the #VC IST stack, set the new IST
	 * value below regs->sp, so that the interrupted stack frame is
	 * not overwritten by subsequent #VC exceptions.
	 */
	if (on_vc_stack(regs))
		new_ist = regs->sp;

	/*
	 * Reserve additional 8 bytes and store old IST value so this
	 * adjustment can be unrolled in __sev_es_ist_exit().
	 */
	new_ist -= sizeof(old_ist);
	*(unsigned long *)new_ist = old_ist;

	/* Set new IST entry */
	this_cpu_write(cpu_tss_rw.x86_tss.ist[IST_INDEX_VC], new_ist);
}

void noinstr __sev_es_ist_exit(void)
{
	unsigned long ist;

	/* Read IST entry */
	ist = __this_cpu_read(cpu_tss_rw.x86_tss.ist[IST_INDEX_VC]);

	if (WARN_ON(ist == __this_cpu_ist_top_va(VC)))
		return;

	/* Read back old IST entry and write it to the TSS */
	this_cpu_write(cpu_tss_rw.x86_tss.ist[IST_INDEX_VC], *(unsigned long *)ist);
}

static inline u64 sev_es_rd_ghcb_msr(void)
{
	return __rdmsr(MSR_AMD64_SEV_ES_GHCB);
}

static __always_inline void sev_es_wr_ghcb_msr(u64 val)
{
	u32 low, high;

	low  = (u32)(val);
	high = (u32)(val >> 32);

	native_wrmsr(MSR_AMD64_SEV_ES_GHCB, low, high);
}

static int vc_fetch_insn_kernel(struct es_em_ctxt *ctxt,
				unsigned char *buffer)
{
	return copy_from_kernel_nofault(buffer, (unsigned char *)ctxt->regs->ip, MAX_INSN_SIZE);
}

static enum es_result __vc_decode_user_insn(struct es_em_ctxt *ctxt)
{
	char buffer[MAX_INSN_SIZE];
	int insn_bytes;

	insn_bytes = insn_fetch_from_user_inatomic(ctxt->regs, buffer);
	if (insn_bytes == 0) {
		/* Nothing could be copied */
		ctxt->fi.vector     = X86_TRAP_PF;
		ctxt->fi.error_code = X86_PF_INSTR | X86_PF_USER;
		ctxt->fi.cr2        = ctxt->regs->ip;
		return ES_EXCEPTION;
	} else if (insn_bytes == -EINVAL) {
		/* Effective RIP could not be calculated */
		ctxt->fi.vector     = X86_TRAP_GP;
		ctxt->fi.error_code = 0;
		ctxt->fi.cr2        = 0;
		return ES_EXCEPTION;
	}

	if (!insn_decode_from_regs(&ctxt->insn, ctxt->regs, buffer, insn_bytes))
		return ES_DECODE_FAILED;

	if (ctxt->insn.immediate.got)
		return ES_OK;
	else
		return ES_DECODE_FAILED;
}

static enum es_result __vc_decode_kern_insn(struct es_em_ctxt *ctxt)
{
	char buffer[MAX_INSN_SIZE];
	int res, ret;

	res = vc_fetch_insn_kernel(ctxt, buffer);
	if (res) {
		ctxt->fi.vector     = X86_TRAP_PF;
		ctxt->fi.error_code = X86_PF_INSTR;
		ctxt->fi.cr2        = ctxt->regs->ip;
		return ES_EXCEPTION;
	}

	ret = insn_decode(&ctxt->insn, buffer, MAX_INSN_SIZE, INSN_MODE_64);
	if (ret < 0)
		return ES_DECODE_FAILED;
	else
		return ES_OK;
}

static enum es_result vc_decode_insn(struct es_em_ctxt *ctxt)
{
	if (user_mode(ctxt->regs))
		return __vc_decode_user_insn(ctxt);
	else
		return __vc_decode_kern_insn(ctxt);
}

static enum es_result vc_write_mem(struct es_em_ctxt *ctxt,
				   char *dst, char *buf, size_t size)
{
	unsigned long error_code = X86_PF_PROT | X86_PF_WRITE;
	char __user *target = (char __user *)dst;
	u64 d8;
	u32 d4;
	u16 d2;
	u8  d1;

	/*
	 * This function uses __put_user() independent of whether kernel or user
	 * memory is accessed. This works fine because __put_user() does no
	 * sanity checks of the pointer being accessed. All that it does is
	 * to report when the access failed.
	 *
	 * Also, this function runs in atomic context, so __put_user() is not
	 * allowed to sleep. The page-fault handler detects that it is running
	 * in atomic context and will not try to take mmap_sem and handle the
	 * fault, so additional pagefault_enable()/disable() calls are not
	 * needed.
	 *
	 * The access can't be done via copy_to_user() here because
	 * vc_write_mem() must not use string instructions to access unsafe
	 * memory. The reason is that MOVS is emulated by the #VC handler by
	 * splitting the move up into a read and a write and taking a nested #VC
	 * exception on whatever of them is the MMIO access. Using string
	 * instructions here would cause infinite nesting.
	 */
	switch (size) {
	case 1:
		memcpy(&d1, buf, 1);
		if (__put_user(d1, target))
			goto fault;
		break;
	case 2:
		memcpy(&d2, buf, 2);
		if (__put_user(d2, target))
			goto fault;
		break;
	case 4:
		memcpy(&d4, buf, 4);
		if (__put_user(d4, target))
			goto fault;
		break;
	case 8:
		memcpy(&d8, buf, 8);
		if (__put_user(d8, target))
			goto fault;
		break;
	default:
		WARN_ONCE(1, "%s: Invalid size: %zu\n", __func__, size);
		return ES_UNSUPPORTED;
	}

	return ES_OK;

fault:
	if (user_mode(ctxt->regs))
		error_code |= X86_PF_USER;

	ctxt->fi.vector = X86_TRAP_PF;
	ctxt->fi.error_code = error_code;
	ctxt->fi.cr2 = (unsigned long)dst;

	return ES_EXCEPTION;
}

static enum es_result vc_read_mem(struct es_em_ctxt *ctxt,
				  char *src, char *buf, size_t size)
{
	unsigned long error_code = X86_PF_PROT;
	char __user *s = (char __user *)src;
	u64 d8;
	u32 d4;
	u16 d2;
	u8  d1;

	/*
	 * This function uses __get_user() independent of whether kernel or user
	 * memory is accessed. This works fine because __get_user() does no
	 * sanity checks of the pointer being accessed. All that it does is
	 * to report when the access failed.
	 *
	 * Also, this function runs in atomic context, so __get_user() is not
	 * allowed to sleep. The page-fault handler detects that it is running
	 * in atomic context and will not try to take mmap_sem and handle the
	 * fault, so additional pagefault_enable()/disable() calls are not
	 * needed.
	 *
	 * The access can't be done via copy_from_user() here because
	 * vc_read_mem() must not use string instructions to access unsafe
	 * memory. The reason is that MOVS is emulated by the #VC handler by
	 * splitting the move up into a read and a write and taking a nested #VC
	 * exception on whatever of them is the MMIO access. Using string
	 * instructions here would cause infinite nesting.
	 */
	switch (size) {
	case 1:
		if (__get_user(d1, s))
			goto fault;
		memcpy(buf, &d1, 1);
		break;
	case 2:
		if (__get_user(d2, s))
			goto fault;
		memcpy(buf, &d2, 2);
		break;
	case 4:
		if (__get_user(d4, s))
			goto fault;
		memcpy(buf, &d4, 4);
		break;
	case 8:
		if (__get_user(d8, s))
			goto fault;
		memcpy(buf, &d8, 8);
		break;
	default:
		WARN_ONCE(1, "%s: Invalid size: %zu\n", __func__, size);
		return ES_UNSUPPORTED;
	}

	return ES_OK;

fault:
	if (user_mode(ctxt->regs))
		error_code |= X86_PF_USER;

	ctxt->fi.vector = X86_TRAP_PF;
	ctxt->fi.error_code = error_code;
	ctxt->fi.cr2 = (unsigned long)src;

	return ES_EXCEPTION;
}

static enum es_result vc_slow_virt_to_phys(struct ghcb *ghcb, struct es_em_ctxt *ctxt,
					   unsigned long vaddr, phys_addr_t *paddr)
{
	unsigned long va = (unsigned long)vaddr;
	unsigned int level;
	phys_addr_t pa;
	pgd_t *pgd;
	pte_t *pte;

	pgd = __va(read_cr3_pa());
	pgd = &pgd[pgd_index(va)];
	pte = lookup_address_in_pgd(pgd, va, &level);
	if (!pte) {
		ctxt->fi.vector     = X86_TRAP_PF;
		ctxt->fi.cr2        = vaddr;
		ctxt->fi.error_code = 0;

		if (user_mode(ctxt->regs))
			ctxt->fi.error_code |= X86_PF_USER;

		return ES_EXCEPTION;
	}

	if (WARN_ON_ONCE(pte_val(*pte) & _PAGE_ENC))
		/* Emulated MMIO to/from encrypted memory not supported */
		return ES_UNSUPPORTED;

	pa = (phys_addr_t)pte_pfn(*pte) << PAGE_SHIFT;
	pa |= va & ~page_level_mask(level);

	*paddr = pa;

	return ES_OK;
}

/* Include code shared with pre-decompression boot stage */
#include "sev-shared.c"

static void snp_register_ghcb(struct sev_es_runtime_data *data, unsigned long paddr)
{
	if (data->snp_ghcb_registered)
		return;

	snp_register_ghcb_early(paddr);

	data->snp_ghcb_registered = true;
}

/*
 * Nothing shall interrupt this code path while holding the per-CPU
 * GHCB. The backup GHCB is only for NMIs interrupting this path.
 *
 * Callers must disable local interrupts around it.
 */
static noinstr struct ghcb *__sev_get_ghcb(struct ghcb_state *state)
{
	struct sev_es_runtime_data *data;
	struct ghcb *ghcb;

	WARN_ON(!irqs_disabled());

	data = this_cpu_read(runtime_data);
	ghcb = &data->ghcb_page;

	if (unlikely(data->ghcb_active)) {
		/* GHCB is already in use - save its contents */

		if (unlikely(data->backup_ghcb_active)) {
			/*
			 * Backup-GHCB is also already in use. There is no way
			 * to continue here so just kill the machine. To make
			 * panic() work, mark GHCBs inactive so that messages
			 * can be printed out.
			 */
			data->ghcb_active        = false;
			data->backup_ghcb_active = false;

			instrumentation_begin();
			panic("Unable to handle #VC exception! GHCB and Backup GHCB are already in use");
			instrumentation_end();
		}

		/* Mark backup_ghcb active before writing to it */
		data->backup_ghcb_active = true;

		state->ghcb = &data->backup_ghcb;

		/* Backup GHCB content */
		*state->ghcb = *ghcb;
	} else {
		state->ghcb = NULL;
		data->ghcb_active = true;
	}

	/* SEV-SNP guest requires that GHCB must be registered. */
	if (sev_feature_enabled(SEV_SNP))
		snp_register_ghcb(data, __pa(ghcb));

	return ghcb;
}

static noinstr void __sev_put_ghcb(struct ghcb_state *state)
{
	struct sev_es_runtime_data *data;
	struct ghcb *ghcb;

	WARN_ON(!irqs_disabled());

	data = this_cpu_read(runtime_data);
	ghcb = &data->ghcb_page;

	if (state->ghcb) {
		/* Restore GHCB from Backup */
		*ghcb = *state->ghcb;
		data->backup_ghcb_active = false;
		state->ghcb = NULL;
	} else {
		/*
		 * Invalidate the GHCB so a VMGEXIT instruction issued
		 * from userspace won't appear to be valid.
		 */
		vc_ghcb_invalidate(ghcb);
		data->ghcb_active = false;
	}
}

void noinstr __sev_es_nmi_complete(void)
{
	struct ghcb_state state;
	struct ghcb *ghcb;

	ghcb = __sev_get_ghcb(&state);

	vc_ghcb_invalidate(ghcb);
	ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_NMI_COMPLETE);
	ghcb_set_sw_exit_info_1(ghcb, 0);
	ghcb_set_sw_exit_info_2(ghcb, 0);

	sev_es_wr_ghcb_msr(__pa_nodebug(ghcb));
	VMGEXIT();

	__sev_put_ghcb(&state);
}

static u64 get_jump_table_addr(void)
{
	struct ghcb_state state;
	unsigned long flags;
	struct ghcb *ghcb;
	u64 ret = 0;

	local_irq_save(flags);

	ghcb = __sev_get_ghcb(&state);

	vc_ghcb_invalidate(ghcb);
	ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_AP_JUMP_TABLE);
	ghcb_set_sw_exit_info_1(ghcb, SVM_VMGEXIT_GET_AP_JUMP_TABLE);
	ghcb_set_sw_exit_info_2(ghcb, 0);

	sev_es_wr_ghcb_msr(__pa(ghcb));
	VMGEXIT();

	if (ghcb_sw_exit_info_1_is_valid(ghcb) &&
	    ghcb_sw_exit_info_2_is_valid(ghcb))
		ret = ghcb->save.sw_exit_info_2;

	__sev_put_ghcb(&state);

	local_irq_restore(flags);

	return ret;
}

static void pvalidate_pages(unsigned long vaddr, unsigned int npages, bool validate)
{
	unsigned long vaddr_end;
	int rc;

	vaddr = vaddr & PAGE_MASK;
	vaddr_end = vaddr + (npages << PAGE_SHIFT);

	while (vaddr < vaddr_end) {
		rc = pvalidate(vaddr, RMP_PG_SIZE_4K, validate);
		if (WARN(rc, "Failed to validate address 0x%lx ret %d", vaddr, rc))
			sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_PVALIDATE);

		vaddr = vaddr + PAGE_SIZE;
	}
}

static void __init early_set_page_state(unsigned long paddr, unsigned int npages, enum psc_op op)
{
	unsigned long paddr_end;
	u64 val;

	paddr = paddr & PAGE_MASK;
	paddr_end = paddr + (npages << PAGE_SHIFT);

	while (paddr < paddr_end) {
		/*
		 * Use the MSR protocol because this function can be called before the GHCB
		 * is established.
		 */
		sev_es_wr_ghcb_msr(GHCB_MSR_PSC_REQ_GFN(paddr >> PAGE_SHIFT, op));
		VMGEXIT();

		val = sev_es_rd_ghcb_msr();

		if (WARN(GHCB_RESP_CODE(val) != GHCB_MSR_PSC_RESP,
			 "Wrong PSC response code: 0x%x\n",
			 (unsigned int)GHCB_RESP_CODE(val)))
			goto e_term;

		if (WARN(GHCB_MSR_PSC_RESP_VAL(val),
			 "Failed to change page state to '%s' paddr 0x%lx error 0x%llx\n",
			 op == SNP_PAGE_STATE_PRIVATE ? "private" : "shared",
			 paddr, GHCB_MSR_PSC_RESP_VAL(val)))
			goto e_term;

		paddr = paddr + PAGE_SIZE;
	}

	return;

e_term:
	sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_PSC);
}

void __init early_snp_set_memory_private(unsigned long vaddr, unsigned long paddr,
					 unsigned int npages)
{
	if (!sev_feature_enabled(SEV_SNP))
		return;

	 /*
	  * Ask the hypervisor to mark the memory pages as private in the RMP
	  * table.
	  */
	early_set_page_state(paddr, npages, SNP_PAGE_STATE_PRIVATE);

	/* Validate the memory pages after they've been added in the RMP table. */
	pvalidate_pages(vaddr, npages, 1);
}

void __init early_snp_set_memory_shared(unsigned long vaddr, unsigned long paddr,
					unsigned int npages)
{
	if (!sev_feature_enabled(SEV_SNP))
		return;

	/*
	 * Invalidate the memory pages before they are marked shared in the
	 * RMP table.
	 */
	pvalidate_pages(vaddr, npages, 0);

	 /* Ask hypervisor to mark the memory pages shared in the RMP table. */
	early_set_page_state(paddr, npages, SNP_PAGE_STATE_SHARED);
}

void __init snp_prep_memory(unsigned long paddr, unsigned int sz, enum psc_op op)
{
	unsigned long vaddr, npages;

	vaddr = (unsigned long)__va(paddr);
	npages = PAGE_ALIGN(sz) >> PAGE_SHIFT;

	if (op == SNP_PAGE_STATE_PRIVATE)
		early_snp_set_memory_private(vaddr, paddr, npages);
	else if (op == SNP_PAGE_STATE_SHARED)
		early_snp_set_memory_shared(vaddr, paddr, npages);
	else
		WARN(1, "invalid memory op %d\n", op);
}

static int vmgexit_psc(struct snp_psc_desc *desc)
{
	int cur_entry, end_entry, ret;
	struct snp_psc_desc *data;
	struct ghcb_state state;
	struct ghcb *ghcb;
	struct psc_hdr *hdr;
	unsigned long flags;

	local_irq_save(flags);

	ghcb = __sev_get_ghcb(&state);
	if (unlikely(!ghcb))
		panic("SEV-SNP: Failed to get GHCB\n");

	/* Copy the input desc into GHCB shared buffer */
	data = (struct snp_psc_desc *)ghcb->shared_buffer;
	memcpy(ghcb->shared_buffer, desc, sizeof(*desc));

	hdr = &data->hdr;
	cur_entry = hdr->cur_entry;
	end_entry = hdr->end_entry;

	/*
	 * As per the GHCB specification, the hypervisor can resume the guest
	 * before processing all the entries. Checks whether all the entries
	 * are processed. If not, then keep retrying.
	 *
	 * The stragtegy here is to wait for the hypervisor to change the page
	 * state in the RMP table before guest access the memory pages. If the
	 * page state was not successful, then later memory access will result
	 * in the crash.
	 */
	while (hdr->cur_entry <= hdr->end_entry) {
		ghcb_set_sw_scratch(ghcb, (u64)__pa(data));

		ret = sev_es_ghcb_hv_call(ghcb, NULL, SVM_VMGEXIT_PSC, 0, 0);

		/*
		 * Page State Change VMGEXIT can pass error code through
		 * exit_info_2.
		 */
		if (WARN(ret || ghcb->save.sw_exit_info_2,
			 "SEV-SNP: PSC failed ret=%d exit_info_2=%llx\n",
			 ret, ghcb->save.sw_exit_info_2)) {
			ret = 1;
			goto out;
		}

		/*
		 * Sanity check that entry processing is not going backward.
		 * This will happen only if hypervisor is tricking us.
		 */
		if (WARN(hdr->end_entry > end_entry || cur_entry > hdr->cur_entry,
	"SEV-SNP:  PSC processing going backward, end_entry %d (got %d) cur_entry %d (got %d)\n",
			 end_entry, hdr->end_entry, cur_entry, hdr->cur_entry)) {
			ret = 1;
			goto out;
		}

		/* Verify that reserved bit is not set */
		if (WARN(hdr->reserved, "Reserved bit is set in the PSC header\n")) {
			ret = 1;
			goto out;
		}
	}

out:
	__sev_put_ghcb(&state);
	local_irq_restore(flags);

	return 0;
}

static void __set_page_state(struct snp_psc_desc *data, unsigned long vaddr,
			     unsigned long vaddr_end, int op)
{
	struct psc_hdr *hdr;
	struct psc_entry *e;
	unsigned long pfn;
	int i;

	hdr = &data->hdr;
	e = data->entries;

	memset(data, 0, sizeof(*data));
	i = 0;

	while (vaddr < vaddr_end) {
		if (is_vmalloc_addr((void *)vaddr))
			pfn = vmalloc_to_pfn((void *)vaddr);
		else
			pfn = __pa(vaddr) >> PAGE_SHIFT;

		e->gfn = pfn;
		e->operation = op;
		hdr->end_entry = i;

		/*
		 * The GHCB specification provides the flexibility to
		 * use either 4K or 2MB page size in the RMP table.
		 * The current SNP support does not keep track of the
		 * page size used in the RMP table. To avoid the
		 * overlap request, use the 4K page size in the RMP
		 * table.
		 */
		e->pagesize = RMP_PG_SIZE_4K;

		vaddr = vaddr + PAGE_SIZE;
		e++;
		i++;
	}

	if (vmgexit_psc(data))
		sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_PSC);
}

static void set_page_state(unsigned long vaddr, unsigned int npages, int op)
{
	unsigned long vaddr_end, next_vaddr;
	struct snp_psc_desc *desc;

	vaddr = vaddr & PAGE_MASK;
	vaddr_end = vaddr + (npages << PAGE_SHIFT);

	desc = kmalloc(sizeof(*desc), GFP_KERNEL_ACCOUNT);
	if (!desc)
		panic("SEV-SNP: failed to allocte memory for PSC descriptor\n");

	while (vaddr < vaddr_end) {
		/*
		 * Calculate the last vaddr that can be fit in one
		 * struct snp_psc_desc.
		 */
		next_vaddr = min_t(unsigned long, vaddr_end,
				   (VMGEXIT_PSC_MAX_ENTRY * PAGE_SIZE) + vaddr);

		__set_page_state(desc, vaddr, next_vaddr, op);

		vaddr = next_vaddr;
	}

	kfree(desc);
}

void snp_set_memory_shared(unsigned long vaddr, unsigned int npages)
{
	if (!sev_feature_enabled(SEV_SNP))
		return;

	pvalidate_pages(vaddr, npages, 0);

	set_page_state(vaddr, npages, SNP_PAGE_STATE_SHARED);
}

void snp_set_memory_private(unsigned long vaddr, unsigned int npages)
{
	if (!sev_feature_enabled(SEV_SNP))
		return;

	set_page_state(vaddr, npages, SNP_PAGE_STATE_PRIVATE);

	pvalidate_pages(vaddr, npages, 1);
}

static int rmpadjust(void *va, bool vmsa)
{
	u64 attrs;
	int err;

	/*
	 * The RMPADJUST instruction is used to set or clear the VMSA bit for
	 * a page. A change to the VMSA bit is only performed when running
	 * at VMPL0 and is ignored at other VMPL levels. If too low of a target
	 * VMPL level is specified, the instruction can succeed without changing
	 * the VMSA bit should the kernel not be in VMPL0. Using a target VMPL
	 * level of 1 will return a FAIL_PERMISSION error if the kernel is not
	 * at VMPL0, thus ensuring that the VMSA bit has been properly set when
	 * no error is returned.
	 */
	attrs = 1;
	if (vmsa)
		attrs |= RMPADJUST_VMSA_PAGE_BIT;

	/* Instruction mnemonic supported in binutils versions v2.36 and later */
	asm volatile (".byte 0xf3,0x0f,0x01,0xfe\n\t"
		      : "=a" (err)
		      : "a" (va), "c" (RMP_PG_SIZE_4K), "d" (attrs)
		      : "memory", "cc");

	return err;
}

#define __ATTR_BASE		(SVM_SELECTOR_P_MASK | SVM_SELECTOR_S_MASK)
#define INIT_CS_ATTRIBS		(__ATTR_BASE | SVM_SELECTOR_READ_MASK | SVM_SELECTOR_CODE_MASK)
#define INIT_DS_ATTRIBS		(__ATTR_BASE | SVM_SELECTOR_WRITE_MASK)

#define INIT_LDTR_ATTRIBS	(SVM_SELECTOR_P_MASK | 2)
#define INIT_TR_ATTRIBS		(SVM_SELECTOR_P_MASK | 3)

static int wakeup_cpu_via_vmgexit(int apic_id, unsigned long start_ip)
{
	struct sev_es_save_area *cur_vmsa, *vmsa;
	struct ghcb_state state;
	unsigned long flags;
	struct ghcb *ghcb;
	int cpu, err, ret;
	u8 sipi_vector;
	u64 cr4;

	if ((sev_hv_features & GHCB_HV_FT_SNP_AP_CREATION) != GHCB_HV_FT_SNP_AP_CREATION)
		return -EOPNOTSUPP;

	/*
	 * Verify the desired start IP against the known trampoline start IP
	 * to catch any future new trampolines that may be introduced that
	 * would require a new protected guest entry point.
	 */
	if (WARN_ONCE(start_ip != real_mode_header->trampoline_start,
		      "Unsupported SEV-SNP start_ip: %lx\n", start_ip))
		return -EINVAL;

	/* Override start_ip with known protected guest start IP */
	start_ip = real_mode_header->sev_es_trampoline_start;

	/* Find the logical CPU for the APIC ID */
	for_each_present_cpu(cpu) {
		if (arch_match_cpu_phys_id(cpu, apic_id))
			break;
	}
	if (cpu >= nr_cpu_ids)
		return -EINVAL;

	cur_vmsa = per_cpu(snp_vmsa, cpu);

	/*
	 * A new VMSA is created each time because there is no guarantee that
	 * the current VMSA is the kernels or that the vCPU is not running. If
	 * an attempt was done to use the current VMSA with a running vCPU, a
	 * #VMEXIT of that vCPU would wipe out all of the settings being done
	 * here.
	 */
	vmsa = (struct sev_es_save_area *)get_zeroed_page(GFP_KERNEL);
	if (!vmsa)
		return -ENOMEM;

	/* CR4 should maintain the MCE value */
	cr4 = native_read_cr4() & X86_CR4_MCE;

	/* Set the CS value based on the start_ip converted to a SIPI vector */
	sipi_vector		= (start_ip >> 12);
	vmsa->cs.base		= sipi_vector << 12;
	vmsa->cs.limit		= 0xffff;
	vmsa->cs.attrib		= INIT_CS_ATTRIBS;
	vmsa->cs.selector	= sipi_vector << 8;

	/* Set the RIP value based on start_ip */
	vmsa->rip		= start_ip & 0xfff;

	/* Set VMSA entries to the INIT values as documented in the APM */
	vmsa->ds.limit		= 0xffff;
	vmsa->ds.attrib		= INIT_DS_ATTRIBS;
	vmsa->es		= vmsa->ds;
	vmsa->fs		= vmsa->ds;
	vmsa->gs		= vmsa->ds;
	vmsa->ss		= vmsa->ds;

	vmsa->gdtr.limit	= 0xffff;
	vmsa->ldtr.limit	= 0xffff;
	vmsa->ldtr.attrib	= INIT_LDTR_ATTRIBS;
	vmsa->idtr.limit	= 0xffff;
	vmsa->tr.limit		= 0xffff;
	vmsa->tr.attrib		= INIT_TR_ATTRIBS;

	vmsa->efer		= 0x1000;	/* Must set SVME bit */
	vmsa->cr4		= cr4;
	vmsa->cr0		= 0x60000010;
	vmsa->dr7		= 0x400;
	vmsa->dr6		= 0xffff0ff0;
	vmsa->rflags		= 0x2;
	vmsa->g_pat		= 0x0007040600070406ULL;
	vmsa->xcr0		= 0x1;
	vmsa->mxcsr		= 0x1f80;
	vmsa->x87_ftw		= 0x5555;
	vmsa->x87_fcw		= 0x0040;

	/*
	 * Set the SNP-specific fields for this VMSA:
	 *   VMPL level
	 *   SEV_FEATURES (matches the SEV STATUS MSR right shifted 2 bits)
	 */
	vmsa->vmpl		= 0;
	vmsa->sev_features	= sev_status >> 2;

	/* Switch the page over to a VMSA page now that it is initialized */
	ret = rmpadjust(vmsa, true);
	if (ret) {
		pr_err("set VMSA page failed (%u)\n", ret);
		free_page((unsigned long)vmsa);

		return -EINVAL;
	}

	/* Issue VMGEXIT AP Creation NAE event */
	local_irq_save(flags);

	ghcb = __sev_get_ghcb(&state);

	vc_ghcb_invalidate(ghcb);
	ghcb_set_rax(ghcb, vmsa->sev_features);
	ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_AP_CREATION);
	ghcb_set_sw_exit_info_1(ghcb, ((u64)apic_id << 32) | SVM_VMGEXIT_AP_CREATE);
	ghcb_set_sw_exit_info_2(ghcb, __pa(vmsa));

	sev_es_wr_ghcb_msr(__pa(ghcb));
	VMGEXIT();

	if (!ghcb_sw_exit_info_1_is_valid(ghcb) ||
	    lower_32_bits(ghcb->save.sw_exit_info_1)) {
		pr_alert("SNP AP Creation error\n");
		ret = -EINVAL;
	}

	__sev_put_ghcb(&state);

	local_irq_restore(flags);

	/* Perform cleanup if there was an error */
	if (ret) {
		err = rmpadjust(vmsa, false);
		if (err)
			pr_err("clear VMSA page failed (%u), leaking page\n", err);
		else
			free_page((unsigned long)vmsa);

		vmsa = NULL;
	}

	/* Free up any previous VMSA page */
	if (cur_vmsa) {
		err = rmpadjust(cur_vmsa, false);
		if (err)
			pr_err("clear VMSA page failed (%u), leaking page\n", err);
		else
			free_page((unsigned long)cur_vmsa);
	}

	/* Record the current VMSA page */
	per_cpu(snp_vmsa, cpu) = vmsa;

	return ret;
}

void snp_set_wakeup_secondary_cpu(void)
{
	if (!sev_feature_enabled(SEV_SNP))
		return;

	/*
	 * Always set this override if SEV-SNP is enabled. This makes it the
	 * required method to start APs under SEV-SNP. If the hypervisor does
	 * not support AP creation, then no APs will be started.
	 */
	apic->wakeup_secondary_cpu = wakeup_cpu_via_vmgexit;
}

int sev_es_setup_ap_jump_table(struct real_mode_header *rmh)
{
	u16 startup_cs, startup_ip;
	phys_addr_t jump_table_pa;
	u64 jump_table_addr;
	u16 __iomem *jump_table;

	jump_table_addr = get_jump_table_addr();

	/* On UP guests there is no jump table so this is not a failure */
	if (!jump_table_addr)
		return 0;

	/* Check if AP Jump Table is page-aligned */
	if (jump_table_addr & ~PAGE_MASK)
		return -EINVAL;

	jump_table_pa = jump_table_addr & PAGE_MASK;

	startup_cs = (u16)(rmh->trampoline_start >> 4);
	startup_ip = (u16)(rmh->sev_es_trampoline_start -
			   rmh->trampoline_start);

	jump_table = ioremap_encrypted(jump_table_pa, PAGE_SIZE);
	if (!jump_table)
		return -EIO;

	writew(startup_ip, &jump_table[0]);
	writew(startup_cs, &jump_table[1]);

	iounmap(jump_table);

	return 0;
}

/*
 * This is needed by the OVMF UEFI firmware which will use whatever it finds in
 * the GHCB MSR as its GHCB to talk to the hypervisor. So make sure the per-cpu
 * runtime GHCBs used by the kernel are also mapped in the EFI page-table.
 */
int __init sev_es_efi_map_ghcbs(pgd_t *pgd)
{
	struct sev_es_runtime_data *data;
	unsigned long address, pflags;
	int cpu;
	u64 pfn;

	if (!sev_es_active())
		return 0;

	pflags = _PAGE_NX | _PAGE_RW;

	for_each_possible_cpu(cpu) {
		data = per_cpu(runtime_data, cpu);

		address = __pa(&data->ghcb_page);
		pfn = address >> PAGE_SHIFT;

		if (kernel_map_pages_in_pgd(pgd, pfn, address, 1, pflags))
			return 1;
	}

	return 0;
}

static enum es_result vc_handle_msr(struct ghcb *ghcb, struct es_em_ctxt *ctxt)
{
	struct pt_regs *regs = ctxt->regs;
	enum es_result ret;
	u64 exit_info_1;

	/* Is it a WRMSR? */
	exit_info_1 = (ctxt->insn.opcode.bytes[1] == 0x30) ? 1 : 0;

	ghcb_set_rcx(ghcb, regs->cx);
	if (exit_info_1) {
		ghcb_set_rax(ghcb, regs->ax);
		ghcb_set_rdx(ghcb, regs->dx);
	}

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_MSR, exit_info_1, 0);

	if ((ret == ES_OK) && (!exit_info_1)) {
		regs->ax = ghcb->save.rax;
		regs->dx = ghcb->save.rdx;
	}

	return ret;
}

/*
 * This function runs on the first #VC exception after the kernel
 * switched to virtual addresses.
 */
static bool __init setup_ghcb(void)
{
	/* First make sure the hypervisor talks a supported protocol. */
	if (!sev_es_negotiate_protocol())
		return false;

	/* If SNP is active, make sure that hypervisor supports the feature. */
	if (sev_feature_enabled(SEV_SNP) && !(sev_hv_features & GHCB_HV_FT_SNP))
		sev_es_terminate(SEV_TERM_SET_GEN, GHCB_SNP_UNSUPPORTED);

	/*
	 * Clear the boot_ghcb. The first exception comes in before the bss
	 * section is cleared.
	 */
	memset(&boot_ghcb_page, 0, PAGE_SIZE);

	/* Alright - Make the boot-ghcb public */
	boot_ghcb = &boot_ghcb_page;

	/* SEV-SNP guest requires that GHCB GPA must be registered. */
	if (sev_feature_enabled(SEV_SNP))
		snp_register_ghcb_early(__pa(&boot_ghcb_page));

	return true;
}

#ifdef CONFIG_HOTPLUG_CPU
static void sev_es_ap_hlt_loop(void)
{
	struct ghcb_state state;
	struct ghcb *ghcb;

	ghcb = __sev_get_ghcb(&state);

	while (true) {
		vc_ghcb_invalidate(ghcb);
		ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_AP_HLT_LOOP);
		ghcb_set_sw_exit_info_1(ghcb, 0);
		ghcb_set_sw_exit_info_2(ghcb, 0);

		sev_es_wr_ghcb_msr(__pa(ghcb));
		VMGEXIT();

		/* Wakeup signal? */
		if (ghcb_sw_exit_info_2_is_valid(ghcb) &&
		    ghcb->save.sw_exit_info_2)
			break;
	}

	__sev_put_ghcb(&state);
}

/*
 * Play_dead handler when running under SEV-ES. This is needed because
 * the hypervisor can't deliver an SIPI request to restart the AP.
 * Instead the kernel has to issue a VMGEXIT to halt the VCPU until the
 * hypervisor wakes it up again.
 */
static void sev_es_play_dead(void)
{
	play_dead_common();

	/* IRQs now disabled */

	sev_es_ap_hlt_loop();

	/*
	 * If we get here, the VCPU was woken up again. Jump to CPU
	 * startup code to get it back online.
	 */
	start_cpu0();
}
#else  /* CONFIG_HOTPLUG_CPU */
#define sev_es_play_dead	native_play_dead
#endif /* CONFIG_HOTPLUG_CPU */

#ifdef CONFIG_SMP
static void __init sev_es_setup_play_dead(void)
{
	smp_ops.play_dead = sev_es_play_dead;
}
#else
static inline void sev_es_setup_play_dead(void) { }
#endif

static void __init alloc_runtime_data(int cpu)
{
	struct sev_es_runtime_data *data;

	data = memblock_alloc(sizeof(*data), PAGE_SIZE);
	if (!data)
		panic("Can't allocate SEV-ES runtime data");

	per_cpu(runtime_data, cpu) = data;
}

static void __init init_ghcb(int cpu)
{
	struct sev_es_runtime_data *data;
	int err;

	data = per_cpu(runtime_data, cpu);

	err = early_set_memory_decrypted((unsigned long)&data->ghcb_page,
					 sizeof(data->ghcb_page));
	if (err)
		panic("Can't map GHCBs unencrypted");

	memset(&data->ghcb_page, 0, sizeof(data->ghcb_page));

	data->ghcb_active = false;
	data->backup_ghcb_active = false;
	data->snp_ghcb_registered = false;
}

void __init sev_es_init_vc_handling(void)
{
	int cpu;

	BUILD_BUG_ON(offsetof(struct sev_es_runtime_data, ghcb_page) % PAGE_SIZE);

	if (!sev_es_active())
		return;

	if (!sev_es_check_cpu_features())
		panic("SEV-ES CPU Features missing");

	/* Enable SEV-ES special handling */
	static_branch_enable(&sev_es_enable_key);

	/* Initialize per-cpu GHCB pages */
	for_each_possible_cpu(cpu) {
		alloc_runtime_data(cpu);
		init_ghcb(cpu);
		setup_vc_stacks(cpu);
	}

	sev_es_setup_play_dead();

	/* Secondary CPUs use the runtime #VC handler */
	initial_vc_handler = (unsigned long)kernel_exc_vmm_communication;
}

static void __init vc_early_forward_exception(struct es_em_ctxt *ctxt)
{
	int trapnr = ctxt->fi.vector;

	if (trapnr == X86_TRAP_PF)
		native_write_cr2(ctxt->fi.cr2);

	ctxt->regs->orig_ax = ctxt->fi.error_code;
	do_early_exception(ctxt->regs, trapnr);
}

static long *vc_insn_get_reg(struct es_em_ctxt *ctxt)
{
	long *reg_array;
	int offset;

	reg_array = (long *)ctxt->regs;
	offset    = insn_get_modrm_reg_off(&ctxt->insn, ctxt->regs);

	if (offset < 0)
		return NULL;

	offset /= sizeof(long);

	return reg_array + offset;
}

static long *vc_insn_get_rm(struct es_em_ctxt *ctxt)
{
	long *reg_array;
	int offset;

	reg_array = (long *)ctxt->regs;
	offset    = insn_get_modrm_rm_off(&ctxt->insn, ctxt->regs);

	if (offset < 0)
		return NULL;

	offset /= sizeof(long);

	return reg_array + offset;
}
static enum es_result vc_do_mmio(struct ghcb *ghcb, struct es_em_ctxt *ctxt,
				 unsigned int bytes, bool read)
{
	u64 exit_code, exit_info_1, exit_info_2;
	unsigned long ghcb_pa = __pa(ghcb);
	enum es_result res;
	phys_addr_t paddr;
	void __user *ref;

	ref = insn_get_addr_ref(&ctxt->insn, ctxt->regs);
	if (ref == (void __user *)-1L)
		return ES_UNSUPPORTED;

	exit_code = read ? SVM_VMGEXIT_MMIO_READ : SVM_VMGEXIT_MMIO_WRITE;

	res = vc_slow_virt_to_phys(ghcb, ctxt, (unsigned long)ref, &paddr);
	if (res != ES_OK) {
		if (res == ES_EXCEPTION && !read)
			ctxt->fi.error_code |= X86_PF_WRITE;

		return res;
	}

	exit_info_1 = paddr;
	/* Can never be greater than 8 */
	exit_info_2 = bytes;

	ghcb_set_sw_scratch(ghcb, ghcb_pa + offsetof(struct ghcb, shared_buffer));

	return sev_es_ghcb_hv_call(ghcb, ctxt, exit_code, exit_info_1, exit_info_2);
}

static enum es_result vc_handle_mmio_twobyte_ops(struct ghcb *ghcb,
						 struct es_em_ctxt *ctxt)
{
	struct insn *insn = &ctxt->insn;
	unsigned int bytes = 0;
	enum es_result ret;
	int sign_byte;
	long *reg_data;

	switch (insn->opcode.bytes[1]) {
		/* MMIO Read w/ zero-extension */
	case 0xb6:
		bytes = 1;
		fallthrough;
	case 0xb7:
		if (!bytes)
			bytes = 2;

		ret = vc_do_mmio(ghcb, ctxt, bytes, true);
		if (ret)
			break;

		/* Zero extend based on operand size */
		reg_data = vc_insn_get_reg(ctxt);
		if (!reg_data)
			return ES_DECODE_FAILED;

		memset(reg_data, 0, insn->opnd_bytes);

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

		/* MMIO Read w/ sign-extension */
	case 0xbe:
		bytes = 1;
		fallthrough;
	case 0xbf:
		if (!bytes)
			bytes = 2;

		ret = vc_do_mmio(ghcb, ctxt, bytes, true);
		if (ret)
			break;

		/* Sign extend based on operand size */
		reg_data = vc_insn_get_reg(ctxt);
		if (!reg_data)
			return ES_DECODE_FAILED;

		if (bytes == 1) {
			u8 *val = (u8 *)ghcb->shared_buffer;

			sign_byte = (*val & 0x80) ? 0xff : 0x00;
		} else {
			u16 *val = (u16 *)ghcb->shared_buffer;

			sign_byte = (*val & 0x8000) ? 0xff : 0x00;
		}
		memset(reg_data, sign_byte, insn->opnd_bytes);

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

	default:
		ret = ES_UNSUPPORTED;
	}

	return ret;
}

/*
 * The MOVS instruction has two memory operands, which raises the
 * problem that it is not known whether the access to the source or the
 * destination caused the #VC exception (and hence whether an MMIO read
 * or write operation needs to be emulated).
 *
 * Instead of playing games with walking page-tables and trying to guess
 * whether the source or destination is an MMIO range, split the move
 * into two operations, a read and a write with only one memory operand.
 * This will cause a nested #VC exception on the MMIO address which can
 * then be handled.
 *
 * This implementation has the benefit that it also supports MOVS where
 * source _and_ destination are MMIO regions.
 *
 * It will slow MOVS on MMIO down a lot, but in SEV-ES guests it is a
 * rare operation. If it turns out to be a performance problem the split
 * operations can be moved to memcpy_fromio() and memcpy_toio().
 */
static enum es_result vc_handle_mmio_movs(struct es_em_ctxt *ctxt,
					  unsigned int bytes)
{
	unsigned long ds_base, es_base;
	unsigned char *src, *dst;
	unsigned char buffer[8];
	enum es_result ret;
	bool rep;
	int off;

	ds_base = insn_get_seg_base(ctxt->regs, INAT_SEG_REG_DS);
	es_base = insn_get_seg_base(ctxt->regs, INAT_SEG_REG_ES);

	if (ds_base == -1L || es_base == -1L) {
		ctxt->fi.vector = X86_TRAP_GP;
		ctxt->fi.error_code = 0;
		return ES_EXCEPTION;
	}

	src = ds_base + (unsigned char *)ctxt->regs->si;
	dst = es_base + (unsigned char *)ctxt->regs->di;

	ret = vc_read_mem(ctxt, src, buffer, bytes);
	if (ret != ES_OK)
		return ret;

	ret = vc_write_mem(ctxt, dst, buffer, bytes);
	if (ret != ES_OK)
		return ret;

	if (ctxt->regs->flags & X86_EFLAGS_DF)
		off = -bytes;
	else
		off =  bytes;

	ctxt->regs->si += off;
	ctxt->regs->di += off;

	rep = insn_has_rep_prefix(&ctxt->insn);
	if (rep)
		ctxt->regs->cx -= 1;

	if (!rep || ctxt->regs->cx == 0)
		return ES_OK;
	else
		return ES_RETRY;
}

static enum es_result vc_handle_mmio(struct ghcb *ghcb,
				     struct es_em_ctxt *ctxt)
{
	struct insn *insn = &ctxt->insn;
	unsigned int bytes = 0;
	enum es_result ret;
	long *reg_data;

	switch (insn->opcode.bytes[0]) {
	/* MMIO Write */
	case 0x88:
		bytes = 1;
		fallthrough;
	case 0x89:
		if (!bytes)
			bytes = insn->opnd_bytes;

		reg_data = vc_insn_get_reg(ctxt);
		if (!reg_data)
			return ES_DECODE_FAILED;

		memcpy(ghcb->shared_buffer, reg_data, bytes);

		ret = vc_do_mmio(ghcb, ctxt, bytes, false);
		break;

	case 0xc6:
		bytes = 1;
		fallthrough;
	case 0xc7:
		if (!bytes)
			bytes = insn->opnd_bytes;

		memcpy(ghcb->shared_buffer, insn->immediate1.bytes, bytes);

		ret = vc_do_mmio(ghcb, ctxt, bytes, false);
		break;

		/* MMIO Read */
	case 0x8a:
		bytes = 1;
		fallthrough;
	case 0x8b:
		if (!bytes)
			bytes = insn->opnd_bytes;

		ret = vc_do_mmio(ghcb, ctxt, bytes, true);
		if (ret)
			break;

		reg_data = vc_insn_get_reg(ctxt);
		if (!reg_data)
			return ES_DECODE_FAILED;

		/* Zero-extend for 32-bit operation */
		if (bytes == 4)
			*reg_data = 0;

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

		/* MOVS instruction */
	case 0xa4:
		bytes = 1;
		fallthrough;
	case 0xa5:
		if (!bytes)
			bytes = insn->opnd_bytes;

		ret = vc_handle_mmio_movs(ctxt, bytes);
		break;
		/* Two-Byte Opcodes */
	case 0x0f:
		ret = vc_handle_mmio_twobyte_ops(ghcb, ctxt);
		break;
	default:
		ret = ES_UNSUPPORTED;
	}

	return ret;
}

static enum es_result vc_handle_dr7_write(struct ghcb *ghcb,
					  struct es_em_ctxt *ctxt)
{
	struct sev_es_runtime_data *data = this_cpu_read(runtime_data);
	long val, *reg = vc_insn_get_rm(ctxt);
	enum es_result ret;

	if (!reg)
		return ES_DECODE_FAILED;

	val = *reg;

	/* Upper 32 bits must be written as zeroes */
	if (val >> 32) {
		ctxt->fi.vector = X86_TRAP_GP;
		ctxt->fi.error_code = 0;
		return ES_EXCEPTION;
	}

	/* Clear out other reserved bits and set bit 10 */
	val = (val & 0xffff23ffL) | BIT(10);

	/* Early non-zero writes to DR7 are not supported */
	if (!data && (val & ~DR7_RESET_VALUE))
		return ES_UNSUPPORTED;

	/* Using a value of 0 for ExitInfo1 means RAX holds the value */
	ghcb_set_rax(ghcb, val);
	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_WRITE_DR7, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (data)
		data->dr7 = val;

	return ES_OK;
}

static enum es_result vc_handle_dr7_read(struct ghcb *ghcb,
					 struct es_em_ctxt *ctxt)
{
	struct sev_es_runtime_data *data = this_cpu_read(runtime_data);
	long *reg = vc_insn_get_rm(ctxt);

	if (!reg)
		return ES_DECODE_FAILED;

	if (data)
		*reg = data->dr7;
	else
		*reg = DR7_RESET_VALUE;

	return ES_OK;
}

static enum es_result vc_handle_wbinvd(struct ghcb *ghcb,
				       struct es_em_ctxt *ctxt)
{
	return sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_WBINVD, 0, 0);
}

static enum es_result vc_handle_rdpmc(struct ghcb *ghcb, struct es_em_ctxt *ctxt)
{
	enum es_result ret;

	ghcb_set_rcx(ghcb, ctxt->regs->cx);

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_RDPMC, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (!(ghcb_rax_is_valid(ghcb) && ghcb_rdx_is_valid(ghcb)))
		return ES_VMM_ERROR;

	ctxt->regs->ax = ghcb->save.rax;
	ctxt->regs->dx = ghcb->save.rdx;

	return ES_OK;
}

static enum es_result vc_handle_monitor(struct ghcb *ghcb,
					struct es_em_ctxt *ctxt)
{
	/*
	 * Treat it as a NOP and do not leak a physical address to the
	 * hypervisor.
	 */
	return ES_OK;
}

static enum es_result vc_handle_mwait(struct ghcb *ghcb,
				      struct es_em_ctxt *ctxt)
{
	/* Treat the same as MONITOR/MONITORX */
	return ES_OK;
}

static enum es_result vc_handle_vmmcall(struct ghcb *ghcb,
					struct es_em_ctxt *ctxt)
{
	enum es_result ret;

	ghcb_set_rax(ghcb, ctxt->regs->ax);
	ghcb_set_cpl(ghcb, user_mode(ctxt->regs) ? 3 : 0);

	if (x86_platform.hyper.sev_es_hcall_prepare)
		x86_platform.hyper.sev_es_hcall_prepare(ghcb, ctxt->regs);

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_VMMCALL, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (!ghcb_rax_is_valid(ghcb))
		return ES_VMM_ERROR;

	ctxt->regs->ax = ghcb->save.rax;

	/*
	 * Call sev_es_hcall_finish() after regs->ax is already set.
	 * This allows the hypervisor handler to overwrite it again if
	 * necessary.
	 */
	if (x86_platform.hyper.sev_es_hcall_finish &&
	    !x86_platform.hyper.sev_es_hcall_finish(ghcb, ctxt->regs))
		return ES_VMM_ERROR;

	return ES_OK;
}

static enum es_result vc_handle_trap_ac(struct ghcb *ghcb,
					struct es_em_ctxt *ctxt)
{
	/*
	 * Calling ecx_alignment_check() directly does not work, because it
	 * enables IRQs and the GHCB is active. Forward the exception and call
	 * it later from vc_forward_exception().
	 */
	ctxt->fi.vector = X86_TRAP_AC;
	ctxt->fi.error_code = 0;
	return ES_EXCEPTION;
}

static enum es_result vc_handle_exitcode(struct es_em_ctxt *ctxt,
					 struct ghcb *ghcb,
					 unsigned long exit_code)
{
	enum es_result result;

	switch (exit_code) {
	case SVM_EXIT_READ_DR7:
		result = vc_handle_dr7_read(ghcb, ctxt);
		break;
	case SVM_EXIT_WRITE_DR7:
		result = vc_handle_dr7_write(ghcb, ctxt);
		break;
	case SVM_EXIT_EXCP_BASE + X86_TRAP_AC:
		result = vc_handle_trap_ac(ghcb, ctxt);
		break;
	case SVM_EXIT_RDTSC:
	case SVM_EXIT_RDTSCP:
		result = vc_handle_rdtsc(ghcb, ctxt, exit_code);
		break;
	case SVM_EXIT_RDPMC:
		result = vc_handle_rdpmc(ghcb, ctxt);
		break;
	case SVM_EXIT_INVD:
		pr_err_ratelimited("#VC exception for INVD??? Seriously???\n");
		result = ES_UNSUPPORTED;
		break;
	case SVM_EXIT_CPUID:
		result = vc_handle_cpuid(ghcb, ctxt);
		break;
	case SVM_EXIT_IOIO:
		result = vc_handle_ioio(ghcb, ctxt);
		break;
	case SVM_EXIT_MSR:
		result = vc_handle_msr(ghcb, ctxt);
		break;
	case SVM_EXIT_VMMCALL:
		result = vc_handle_vmmcall(ghcb, ctxt);
		break;
	case SVM_EXIT_WBINVD:
		result = vc_handle_wbinvd(ghcb, ctxt);
		break;
	case SVM_EXIT_MONITOR:
		result = vc_handle_monitor(ghcb, ctxt);
		break;
	case SVM_EXIT_MWAIT:
		result = vc_handle_mwait(ghcb, ctxt);
		break;
	case SVM_EXIT_NPF:
		result = vc_handle_mmio(ghcb, ctxt);
		break;
	default:
		/*
		 * Unexpected #VC exception
		 */
		result = ES_UNSUPPORTED;
	}

	return result;
}

static __always_inline void vc_forward_exception(struct es_em_ctxt *ctxt)
{
	long error_code = ctxt->fi.error_code;
	int trapnr = ctxt->fi.vector;

	ctxt->regs->orig_ax = ctxt->fi.error_code;

	switch (trapnr) {
	case X86_TRAP_GP:
		exc_general_protection(ctxt->regs, error_code);
		break;
	case X86_TRAP_UD:
		exc_invalid_op(ctxt->regs);
		break;
	case X86_TRAP_PF:
		write_cr2(ctxt->fi.cr2);
		exc_page_fault(ctxt->regs, error_code);
		break;
	case X86_TRAP_AC:
		exc_alignment_check(ctxt->regs, error_code);
		break;
	default:
		pr_emerg("Unsupported exception in #VC instruction emulation - can't continue\n");
		BUG();
	}
}

static __always_inline bool on_vc_fallback_stack(struct pt_regs *regs)
{
	unsigned long sp = (unsigned long)regs;

	return (sp >= __this_cpu_ist_bottom_va(VC2) && sp < __this_cpu_ist_top_va(VC2));
}

static bool vc_raw_handle_exception(struct pt_regs *regs, unsigned long error_code)
{
	struct ghcb_state state;
	struct es_em_ctxt ctxt;
	enum es_result result;
	struct ghcb *ghcb;
	bool ret = true;

	ghcb = __sev_get_ghcb(&state);

	vc_ghcb_invalidate(ghcb);
	result = vc_init_em_ctxt(&ctxt, regs, error_code);

	if (result == ES_OK)
		result = vc_handle_exitcode(&ctxt, ghcb, error_code);

	__sev_put_ghcb(&state);

	/* Done - now check the result */
	switch (result) {
	case ES_OK:
		vc_finish_insn(&ctxt);
		break;
	case ES_UNSUPPORTED:
		pr_err_ratelimited("Unsupported exit-code 0x%02lx in #VC exception (IP: 0x%lx)\n",
				   error_code, regs->ip);
		ret = false;
		break;
	case ES_VMM_ERROR:
		pr_err_ratelimited("Failure in communication with VMM (exit-code 0x%02lx IP: 0x%lx)\n",
				   error_code, regs->ip);
		ret = false;
		break;
	case ES_DECODE_FAILED:
		pr_err_ratelimited("Failed to decode instruction (exit-code 0x%02lx IP: 0x%lx)\n",
				   error_code, regs->ip);
		ret = false;
		break;
	case ES_EXCEPTION:
		vc_forward_exception(&ctxt);
		break;
	case ES_RETRY:
		/* Nothing to do */
		break;
	default:
		pr_emerg("Unknown result in %s():%d\n", __func__, result);
		/*
		 * Emulating the instruction which caused the #VC exception
		 * failed - can't continue so print debug information
		 */
		BUG();
	}

	return ret;
}

static __always_inline bool vc_is_db(unsigned long error_code)
{
	return error_code == SVM_EXIT_EXCP_BASE + X86_TRAP_DB;
}

/*
 * Runtime #VC exception handler when raised from kernel mode. Runs in NMI mode
 * and will panic when an error happens.
 */
DEFINE_IDTENTRY_VC_KERNEL(exc_vmm_communication)
{
	irqentry_state_t irq_state;

	/*
	 * With the current implementation it is always possible to switch to a
	 * safe stack because #VC exceptions only happen at known places, like
	 * intercepted instructions or accesses to MMIO areas/IO ports. They can
	 * also happen with code instrumentation when the hypervisor intercepts
	 * #DB, but the critical paths are forbidden to be instrumented, so #DB
	 * exceptions currently also only happen in safe places.
	 *
	 * But keep this here in case the noinstr annotations are violated due
	 * to bug elsewhere.
	 */
	if (unlikely(on_vc_fallback_stack(regs))) {
		instrumentation_begin();
		panic("Can't handle #VC exception from unsupported context\n");
		instrumentation_end();
	}

	/*
	 * Handle #DB before calling into !noinstr code to avoid recursive #DB.
	 */
	if (vc_is_db(error_code)) {
		exc_debug(regs);
		return;
	}

	irq_state = irqentry_nmi_enter(regs);

	instrumentation_begin();

	if (!vc_raw_handle_exception(regs, error_code)) {
		/* Show some debug info */
		show_regs(regs);

		/* Ask hypervisor to sev_es_terminate */
		sev_es_terminate(SEV_TERM_SET_GEN, GHCB_SEV_ES_GEN_REQ);

		/* If that fails and we get here - just panic */
		panic("Returned from Terminate-Request to Hypervisor\n");
	}

	instrumentation_end();
	irqentry_nmi_exit(regs, irq_state);
}

/*
 * Runtime #VC exception handler when raised from user mode. Runs in IRQ mode
 * and will kill the current task with SIGBUS when an error happens.
 */
DEFINE_IDTENTRY_VC_USER(exc_vmm_communication)
{
	/*
	 * Handle #DB before calling into !noinstr code to avoid recursive #DB.
	 */
	if (vc_is_db(error_code)) {
		noist_exc_debug(regs);
		return;
	}

	irqentry_enter_from_user_mode(regs);
	instrumentation_begin();

	if (!vc_raw_handle_exception(regs, error_code)) {
		/*
		 * Do not kill the machine if user-space triggered the
		 * exception. Send SIGBUS instead and let user-space deal with
		 * it.
		 */
		force_sig_fault(SIGBUS, BUS_OBJERR, (void __user *)0);
	}

	instrumentation_end();
	irqentry_exit_to_user_mode(regs);
}

bool __init handle_vc_boot_ghcb(struct pt_regs *regs)
{
	unsigned long exit_code = regs->orig_ax;
	struct es_em_ctxt ctxt;
	enum es_result result;

	/* Do initial setup or terminate the guest */
	if (unlikely(!boot_ghcb && !setup_ghcb()))
		sev_es_terminate(SEV_TERM_SET_GEN, GHCB_SEV_ES_GEN_REQ);

	vc_ghcb_invalidate(boot_ghcb);

	result = vc_init_em_ctxt(&ctxt, regs, exit_code);
	if (result == ES_OK)
		result = vc_handle_exitcode(&ctxt, boot_ghcb, exit_code);

	/* Done - now check the result */
	switch (result) {
	case ES_OK:
		vc_finish_insn(&ctxt);
		break;
	case ES_UNSUPPORTED:
		early_printk("PANIC: Unsupported exit-code 0x%02lx in early #VC exception (IP: 0x%lx)\n",
				exit_code, regs->ip);
		goto fail;
	case ES_VMM_ERROR:
		early_printk("PANIC: Failure in communication with VMM (exit-code 0x%02lx IP: 0x%lx)\n",
				exit_code, regs->ip);
		goto fail;
	case ES_DECODE_FAILED:
		early_printk("PANIC: Failed to decode instruction (exit-code 0x%02lx IP: 0x%lx)\n",
				exit_code, regs->ip);
		goto fail;
	case ES_EXCEPTION:
		vc_early_forward_exception(&ctxt);
		break;
	case ES_RETRY:
		/* Nothing to do */
		break;
	default:
		BUG();
	}

	return true;

fail:
	show_regs(regs);

	while (true)
		halt();
}

static inline u64 __snp_get_msg_seqno(void)
{
	u64 count;

	if (!secrets_layout)
		return 0;

	/* Read the current message sequence counter from secrets pages */
	count = secrets_layout->os_area.msg_seqno_0;

	/* The sequence counter must begin with 1 */
	if (!count)
		return 1;

	return count + 1;
}

/* Return a non-zero on success */
u64 snp_get_msg_seqno(void)
{
	u64 count = __snp_get_msg_seqno();

	/*
	 * The message sequence counter for the SNP guest request is a  64-bit value
	 * but the version 2 of GHCB specification defines a 32-bit storage for the
	 * it. If the counter exceeds the 32-bit value then return zero. The PSP
	 * firmware treats zero as an invalid number and will fail the message
	 * request.
	 */
	if (count >= UINT_MAX) {
		pr_err_ratelimited("SNP guest request message sequence counter overflow\n");
		return 0;
	}

	return count;
}
EXPORT_SYMBOL_GPL(snp_get_msg_seqno);

static void snp_inc_msg_seqno(void)
{
	if (!secrets_layout)
		return;

	/*
	 * The counter is also incremented by the PSP, so increment it by 2
	 * and save in secrets page.
	 */
	secrets_layout->os_area.msg_seqno_0 += 2;
}

int snp_issue_guest_request(u64 exit_code, struct snp_guest_request_data *input,
			    unsigned long *fw_err)
{
	struct ghcb_state state;
	unsigned long flags;
	struct ghcb *ghcb;
	int ret;

	if (!sev_feature_enabled(SEV_SNP))
		return -ENODEV;

	local_irq_save(flags);

	ghcb = __sev_get_ghcb(&state);
	if (!ghcb) {
		ret = -EIO;
		goto e_restore_irq;
	}

	vc_ghcb_invalidate(ghcb);

	if (exit_code == SVM_VMGEXIT_EXT_GUEST_REQUEST) {
		ghcb_set_rax(ghcb, input->data_gpa);
		ghcb_set_rbx(ghcb, input->data_npages);
	}

	ret = sev_es_ghcb_hv_call(ghcb, NULL, exit_code, input->req_gpa, input->resp_gpa);
	if (ret)
		goto e_put;

	if (ghcb->save.sw_exit_info_2) {
		/* Number of expected pages are returned in RBX */
		if (exit_code == SVM_VMGEXIT_EXT_GUEST_REQUEST &&
		    ghcb->save.sw_exit_info_2 == SNP_GUEST_REQ_INVALID_LEN)
			input->data_npages = ghcb_get_rbx(ghcb);

		if (fw_err)
			*fw_err = ghcb->save.sw_exit_info_2;

		ret = -EIO;
		goto e_put;
	}

	/* The command was successful, increment the sequence counter */
	snp_inc_msg_seqno();

e_put:
	__sev_put_ghcb(&state);
e_restore_irq:
	local_irq_restore(flags);

	return ret;
}
EXPORT_SYMBOL_GPL(snp_issue_guest_request);

static struct platform_device guest_req_device = {
	.name		= "snp-guest",
	.id		= -1,
};

static struct snp_secrets_page_layout *map_secrets_page(void)
{
	u64 pa_data = boot_params.cc_blob_address;
	struct snp_secrets_page_layout *layout;
	struct cc_blob_sev_info info;
	void *map;

	/*
	 * The CC blob contains the address of the secrets page, check if the
	 * blob is present.
	 */
	if (!pa_data)
		return 0;

	map = early_memremap(pa_data, sizeof(info));
	memcpy(&info, map, sizeof(info));
	early_memunmap(map, sizeof(info));

	/* Verify that secrets page address is passed */
	if (!info.secrets_phys || info.secrets_len != PAGE_SIZE)
		return NULL;

	layout = (__force void *)ioremap_encrypted(info.secrets_phys, PAGE_SIZE);
	return layout;
}

static int __init add_snp_guest_request(void)
{
	struct snp_guest_platform_data data;

	if (!sev_feature_enabled(SEV_SNP))
		return -ENODEV;

	secrets_layout = map_secrets_page();
	if (!secrets_layout)
		return -ENODEV;

	/*
	 * The secrets page contains three VMPCK that can be used for
	 * communicating with the PSP. We choose the VMPCK0 to encrypt guest
	 * messages send and receive by the Linux. Provide the key and
	 * id through the platform data to the driver.
	 */
	data.vmpck_id = 0;
	memcpy_fromio(data.vmpck, secrets_layout->vmpck0, sizeof(data.vmpck));

	platform_device_add_data(&guest_req_device, &data, sizeof(data));

	if (platform_device_register(&guest_req_device))
		goto e_fail;

	return 0;

e_fail:
	pr_err("Failed to register SNP guest device\n");
	iounmap(secrets_layout);
	secrets_layout = NULL;
	return 0;
}
device_initcall(add_snp_guest_request);

#undef pr_fmt
#define pr_fmt(fmt)	"SEV-SNP: " fmt

static int __snp_enable(unsigned int cpu)
{
	u64 val;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return 0;

	rdmsrl(MSR_AMD64_SYSCFG, val);

	val |= MSR_AMD64_SYSCFG_SNP_EN;
	val |= MSR_AMD64_SYSCFG_SNP_VMPL_EN;

	wrmsrl(MSR_AMD64_SYSCFG, val);

	return 0;
}

static __init void snp_enable(void *arg)
{
	__snp_enable(smp_processor_id());
}

static int __mfdm_enable(unsigned int cpu)
{
	u64 val;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return 0;

	rdmsrl(MSR_AMD64_SYSCFG, val);

	val |= MSR_AMD64_SYSCFG_MFDM;

	wrmsrl(MSR_AMD64_SYSCFG, val);

	return 0;
}

static __init void mfdm_enable(void *arg)
{
	__mfdm_enable(smp_processor_id());
}

static bool get_rmptable_info(u64 *start, u64 *len)
{
	u64 calc_rmp_sz, rmp_sz, rmp_base, rmp_end, nr_pages;

	rdmsrl(MSR_AMD64_RMP_BASE, rmp_base);
	rdmsrl(MSR_AMD64_RMP_END, rmp_end);

	if (!rmp_base || !rmp_end) {
		pr_info("Memory for the RMP table has not been reserved by BIOS\n");
		return false;
	}

	rmp_sz = rmp_end - rmp_base + 1;

	/*
	 * Calculate the amount the memory that must be reserved by the BIOS to
	 * address the full system RAM. The reserved memory should also cover the
	 * RMP table itself.
	 *
	 * See PPR Family 19h Model 01h, Revision B1 section 2.1.5.2 for more
	 * information on memory requirement.
	 */
	nr_pages = totalram_pages();
	calc_rmp_sz = (((rmp_sz >> PAGE_SHIFT) + nr_pages) << 4) + RMPTABLE_CPU_BOOKKEEPING_SZ;

	if (calc_rmp_sz > rmp_sz) {
		pr_info("Memory reserved for the RMP table does not cover full system RAM (expected 0x%llx got 0x%llx)\n",
			calc_rmp_sz, rmp_sz);
		return false;
	}

	*start = rmp_base;
	*len = rmp_sz;

	pr_info("RMP table physical address 0x%016llx - 0x%016llx\n", rmp_base, rmp_end);

	return true;
}

static __init int __snp_rmptable_init(void)
{
	u64 rmp_base, sz;
	void *start;
	u64 val;

	if (!get_rmptable_info(&rmp_base, &sz))
		return 1;

	start = memremap(rmp_base, sz, MEMREMAP_WB);
	if (!start) {
		pr_err("Failed to map RMP table 0x%llx+0x%llx\n", rmp_base, sz);
		return 1;
	}

	/*
	 * Check if SEV-SNP is already enabled, this can happen if we are coming from
	 * kexec boot.
	 */
	rdmsrl(MSR_AMD64_SYSCFG, val);
	if (val & MSR_AMD64_SYSCFG_SNP_EN)
		goto skip_enable;

	/* Initialize the RMP table to zero */
	memset(start, 0, sz);

	/* Flush the caches to ensure that data is written before SNP is enabled. */
	wbinvd_on_all_cpus();

	/* MFDM must be enabled on all the CPUs prior to enabling SNP. */
	on_each_cpu(mfdm_enable, NULL, 1);

	/* Enable SNP on all CPUs. */
	on_each_cpu(snp_enable, NULL, 1);


skip_enable:
	rmptable_start = (unsigned long)start;
	rmptable_end = rmptable_start + sz;

	return 0;
}

static int __init snp_rmptable_init(void)
{
	if (!boot_cpu_has(X86_FEATURE_SEV_SNP))
		return 0;

	if (!iommu_sev_snp_supported())
		goto nosnp;

	if (__snp_rmptable_init())
		goto nosnp;

	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "x86/rmptable_init:online", __snp_enable, NULL);

	return 0;

nosnp:
	setup_clear_cpu_cap(X86_FEATURE_SEV_SNP);
	return 1;
}

/*
 * This must be called after the PCI subsystem. This is because before enabling
 * the SNP feature we need to ensure that IOMMU supports the SEV-SNP feature.
 * The iommu_sev_snp_support() is used for checking the feature, and it is
 * available after subsys_initcall().
 */
fs_initcall(snp_rmptable_init);

static struct rmpentry *__snp_lookup_rmpentry(u64 pfn, int *level)
{
	unsigned long vaddr, paddr = pfn << PAGE_SHIFT;
	struct rmpentry *entry, *large_entry;

	if (!pfn_valid(pfn))
		return ERR_PTR(-EINVAL);

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return ERR_PTR(-ENXIO);

	vaddr = rmptable_start + rmptable_page_offset(paddr);
	if (unlikely(vaddr > rmptable_end))
		return ERR_PTR(-ENXIO);

	entry = (struct rmpentry *)vaddr;

	/* Read a large RMP entry to get the correct page level used in RMP entry. */
	vaddr = rmptable_start + rmptable_page_offset(paddr & PMD_MASK);
	large_entry = (struct rmpentry *)vaddr;
	*level = RMP_TO_X86_PG_LEVEL(rmpentry_pagesize(large_entry));

	return entry;
}

void dump_rmpentry(u64 pfn)
{
	unsigned long pfn_end;
	struct rmpentry *e;
	int level;

	e = __snp_lookup_rmpentry(pfn, &level);
	if (!e) {
		pr_alert("failed to read RMP entry pfn 0x%llx\n", pfn);
		return;
	}

	if (rmpentry_assigned(e)) {
		pr_alert("RMPEntry paddr 0x%llx [assigned=%d immutable=%d pagesize=%d gpa=0x%lx"
			" asid=%d vmsa=%d validated=%d]\n", pfn << PAGE_SHIFT,
			rmpentry_assigned(e), rmpentry_immutable(e), rmpentry_pagesize(e),
			rmpentry_gpa(e), rmpentry_asid(e), rmpentry_vmsa(e),
			rmpentry_validated(e));
		return;
	}

	/*
	 * If the RMP entry at the faulting pfn was not assigned, then we do not
	 * know what caused the RMP violation. To get some useful debug information,
	 * let iterate through the entire 2MB region, and dump the RMP entries if
	 * one of the bit in the RMP entry is set.
	 */
	pfn = pfn & ~(PTRS_PER_PMD - 1);
	pfn_end = pfn + PTRS_PER_PMD;

	while (pfn < pfn_end) {
		e = __snp_lookup_rmpentry(pfn, &level);
		if (!e)
			return;

		if (e->low || e->high)
			pr_alert("RMPEntry paddr 0x%llx: [high=0x%016llx low=0x%016llx]\n",
				 pfn << PAGE_SHIFT, e->high, e->low);
		pfn++;
	}
}
EXPORT_SYMBOL_GPL(dump_rmpentry);

/*
 * Return 1 if the RMP entry is assigned, 0 if it exists but is not assigned,
 * and -errno if there is no corresponding RMP entry.
 */
int snp_lookup_rmpentry(u64 pfn, int *level)
{
	struct rmpentry *e;

	e = __snp_lookup_rmpentry(pfn, level);
	if (IS_ERR(e))
		return PTR_ERR(e);

	return !!rmpentry_assigned(e);
}
EXPORT_SYMBOL_GPL(snp_lookup_rmpentry);

int psmash(u64 pfn)
{
	unsigned long paddr = pfn << PAGE_SHIFT;
	int ret;

	if (!pfn_valid(pfn))
		return -EINVAL;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return -ENXIO;

	/* Binutils version 2.36 supports the PSMASH mnemonic. */
	asm volatile(".byte 0xF3, 0x0F, 0x01, 0xFF"
		      : "=a"(ret)
		      : "a"(paddr)
		      : "memory", "cc");

	return ret;
}
EXPORT_SYMBOL_GPL(psmash);

static int restore_direct_map(u64 pfn, int npages)
{
	int i, ret = 0;

	for (i = 0; i < npages; i++) {
		ret = set_direct_map_default_noflush(pfn_to_page(pfn + i));
		if (ret)
			goto cleanup;
	}

cleanup:
	WARN(ret > 0, "Failed to restore direct map for pfn 0x%llx\n", pfn + i);
	return ret;
}

static int invalid_direct_map(unsigned long pfn, int npages)
{
	int i, ret = 0;

	for (i = 0; i < npages; i++) {
		ret = set_direct_map_invalid_noflush(pfn_to_page(pfn + i));
		if (ret)
			goto cleanup;
	}

	return 0;

cleanup:
	restore_direct_map(pfn, i);
	return ret;
}

static int rmpupdate(u64 pfn, struct rmpupdate *val)
{
	unsigned long paddr = pfn << PAGE_SHIFT;
	int ret, level, npages;

	if (!pfn_valid(pfn))
		return -EINVAL;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return -ENXIO;

	level = RMP_TO_X86_PG_LEVEL(val->pagesize);
	npages = page_level_size(level) / PAGE_SIZE;

	/*
	 * If page is getting assigned in the RMP table then unmap it from the
	 * direct map.
	 */
	if (val->assigned) {
		if (invalid_direct_map(pfn, npages)) {
			pr_err("Failed to unmap pfn 0x%llx pages %d from direct_map\n",
			       pfn, npages);
			return -EFAULT;
		}
	}

	/* Binutils version 2.36 supports the RMPUPDATE mnemonic. */
	asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFE"
		     : "=a"(ret)
		     : "a"(paddr), "c"((unsigned long)val)
		     : "memory", "cc");

	/*
	 * Restore the direct map after the page is removed from the RMP table.
	 */
	if (!ret && !val->assigned) {
		if (restore_direct_map(pfn, npages)) {
			pr_err("Failed to map pfn 0x%llx pages %d in direct_map\n",
			       pfn, npages);
			return -EFAULT;
		}
	}

	return ret;
}

int rmp_make_private(u64 pfn, u64 gpa, enum pg_level level, int asid, bool immutable)
{
	struct rmpupdate val;

	if (!pfn_valid(pfn))
		return -EINVAL;

	memset(&val, 0, sizeof(val));
	val.assigned = 1;
	val.asid = asid;
	val.immutable = immutable;
	val.gpa = gpa;
	val.pagesize = X86_TO_RMP_PG_LEVEL(level);

	return rmpupdate(pfn, &val);
}
EXPORT_SYMBOL_GPL(rmp_make_private);

int rmp_make_shared(u64 pfn, enum pg_level level)
{
	struct rmpupdate val;

	if (!pfn_valid(pfn))
		return -EINVAL;

	memset(&val, 0, sizeof(val));
	val.pagesize = X86_TO_RMP_PG_LEVEL(level);

	return rmpupdate(pfn, &val);
}
EXPORT_SYMBOL_GPL(rmp_make_shared);
