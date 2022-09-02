/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2009-2010 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#ifndef AMD_IOMMU_H
#define AMD_IOMMU_H

#include <linux/iommu.h>

#include "amd_iommu_types.h"

irqreturn_t amd_iommu_int_thread(int irq, void *data);
irqreturn_t amd_iommu_int_thread_evtlog(int irq, void *data);
irqreturn_t amd_iommu_int_thread_pprlog(int irq, void *data);
irqreturn_t amd_iommu_int_thread_galog(int irq, void *data);
irqreturn_t amd_iommu_int_handler(int irq, void *data);
void amd_iommu_apply_erratum_63(struct amd_iommu *iommu, u16 devid);
void amd_iommu_restart_log(struct amd_iommu *iommu, const char *evt_type,
			   u8 cntrl_intr, u8 cntrl_log,
			   u32 status_run_mask, u32 status_overflow_mask);
void amd_iommu_restart_event_logging(struct amd_iommu *iommu);
void amd_iommu_restart_ga_log(struct amd_iommu *iommu);
void amd_iommu_restart_ppr_log(struct amd_iommu *iommu);
void amd_iommu_set_rlookup_table(struct amd_iommu *iommu, u16 devid);
void iommu_feature_enable(struct amd_iommu *iommu, u8 bit);
bool iommu_feature_enable_and_check(struct amd_iommu *iommu, u8 bit);
void iommu_feature_disable(struct amd_iommu *iommu, u8 bit);
void *__init iommu_alloc_4k_pages(struct amd_iommu *iommu,
				  gfp_t gfp, size_t size);
struct iommu_dev_data *amd_iommu_search_dev_data(struct amd_iommu *iommu,
						 u16 devid);
u8 __iomem * __init iommu_map_mmio_space(u64 address, u64 end);
void set_dte_entry(struct amd_iommu *iommu, u16 devid,
		   struct gcr3_tbl_info *gcr3_info,
		   struct protection_domain *domain, bool ats,
		   bool ppr);
int iommu_flush_dte(struct amd_iommu *iommu, u16 devid);
struct iommu_domain *amd_iommu_domain_alloc(unsigned int type);
void amd_iommu_domain_free(struct iommu_domain *dom);
int amd_iommu_v1_map_pages(struct io_pgtable_ops *ops, unsigned long iova,
			   phys_addr_t paddr, size_t pgsize, size_t pgcount,
			   int prot, gfp_t gfp, size_t *mapped);
unsigned long amd_iommu_v1_unmap_pages(struct io_pgtable_ops *ops,
				       unsigned long iova,
				       size_t pgsize, size_t pgcount,
				       struct iommu_iotlb_gather *gather);

#ifdef CONFIG_AMD_IOMMU_DEBUGFS
void amd_iommu_debugfs_setup(struct amd_iommu *iommu);
#else
static inline void amd_iommu_debugfs_setup(struct amd_iommu *iommu) {}
#endif

extern bool amd_iommu_viommu;

/* Needed for interrupt remapping */
int amd_iommu_prepare(void);
int amd_iommu_enable(void);
void amd_iommu_disable(void);
int amd_iommu_reenable(int mode);
int amd_iommu_enable_faulting(void);
extern int amd_iommu_guest_ir;
extern enum io_pgtable_fmt amd_iommu_pgtable;
extern int amd_iommu_gpt_level;

/* SVA/PASID */
bool amd_iommu_sva_supported(void);
int amd_iommu_set_dev_pasid(struct iommu_domain *domain,
			    struct device *dev, ioasid_t pasid);
void amd_iommu_remove_dev_pasid(struct device *dev, ioasid_t pasid);
int amd_iommu_gcr3_init(struct iommu_dev_data *dev_data, int pasids);
void amd_iommu_gcr3_uninit(struct iommu_dev_data *dev_data);

/* IOPF */
int amd_iommu_iopf_init(struct amd_iommu *iommu);
void amd_iommu_iopf_uninit(struct amd_iommu *iommu);
int amd_iommu_iopf_add_device(struct amd_iommu *iommu, struct device *dev);
int amd_iommu_iopf_remove_device(struct amd_iommu *iommu, struct device *dev);
int amd_iommu_page_response(struct device *dev,
			    struct iopf_fault *evt,
			    struct iommu_page_response *resp);
int amd_iommu_iopf_enable(struct device *dev);
int amd_iommu_iopf_disable(struct device *dev);

struct amd_iommu *get_amd_iommu(unsigned int idx);
u8 amd_iommu_pc_get_max_banks(unsigned int idx);
bool amd_iommu_pc_supported(void);
u8 amd_iommu_pc_get_max_counters(unsigned int idx);
int amd_iommu_pc_get_reg(struct amd_iommu *iommu, u8 bank, u8 cntr,
			 u8 fxn, u64 *value);
int amd_iommu_pc_set_reg(struct amd_iommu *iommu, u8 bank, u8 cntr,
			 u8 fxn, u64 *value);

/* Device capabilities */
int amd_iommu_pdev_enable_cap_pri(struct pci_dev *pdev);
void amd_iommu_pdev_disable_cap_pri(struct pci_dev *pdev);

/* GCR3 setup */
int amd_iommu_set_gcr3(struct iommu_dev_data *dev_data,
		       u32 pasid, unsigned long gcr3);
int amd_iommu_clear_gcr3(struct iommu_dev_data *dev_data, u32 pasid);
int amd_viommu_user_gcr3_update(const void *user_data,
				struct iommu_domain *udom);
int amd_iommu_setup_gcr3_table(struct amd_iommu *iommu,
			       struct pci_dev *pdev,
			       struct iommu_domain *dom,
			       struct iommu_domain *udom,
			       int pasids, bool giov);
int amd_iommu_user_set_gcr3(struct amd_iommu *iommu,
			    struct iommu_domain *dom,
			    struct iommu_domain *udom,
			    struct iommu_dev_data *dev_data,
			    u32 pasid, unsigned long cr3);

int amd_iommu_set_gcr3tbl_trp(struct amd_iommu *iommu, struct pci_dev *pdev,
			      u64 gcr3_tbl, u16 glx, u16 guest_paging_mode);

/* PPR */
int __init amd_iommu_alloc_ppr_log(struct amd_iommu *iommu);
void __init amd_iommu_free_ppr_log(struct amd_iommu *iommu);
void amd_iommu_enable_ppr_log(struct amd_iommu *iommu);
void amd_iommu_poll_ppr_log(struct amd_iommu *iommu);
int amd_iommu_complete_ppr(struct pci_dev *pdev, u32 pasid,
			   int status, int tag);

int amd_iommu_flush_page(struct protection_domain *domain, u32 pasid, u64 address);
void amd_iommu_update_and_flush_device_table(struct protection_domain *domain);
void amd_iommu_domain_update(struct protection_domain *domain);
void amd_iommu_domain_flush_complete(struct protection_domain *domain);
void amd_iommu_domain_flush_tlb_pde(struct protection_domain *domain);
int amd_iommu_flush_tlb(struct protection_domain *domain, u32 pasid);
void amd_iommu_iotlb_sync(struct iommu_domain *domain,
			  struct iommu_iotlb_gather *gather);
int amd_iommu_flush_private_vm_region(struct amd_iommu *iommu, struct protection_domain *pdom,
				      u64 address, size_t size);

void amd_iommu_build_efr(u64 *efr, u64 *efr2);

#ifdef CONFIG_IRQ_REMAP
int amd_iommu_create_irq_domain(struct amd_iommu *iommu);
#else
static inline int amd_iommu_create_irq_domain(struct amd_iommu *iommu)
{
	return 0;
}
#endif

#define PPR_SUCCESS			0x0
#define PPR_INVALID			0x1
#define PPR_FAILURE			0xf

static inline bool is_rd890_iommu(struct pci_dev *pdev)
{
	return (pdev->vendor == PCI_VENDOR_ID_ATI) &&
	       (pdev->device == PCI_DEVICE_ID_RD890_IOMMU);
}

static inline bool check_feature(u64 mask)
{
	return (amd_iommu_efr & mask);
}

static inline bool check_feature2(u64 mask)
{
	return (amd_iommu_efr2 & mask);
}

static inline int check_feature_gpt_level(void)
{
	return ((amd_iommu_efr & FEATURE_GATS_MASK) >> FEATURE_GATS_SHIFT);
}

static inline bool amd_iommu_gt_ppr_supported(void)
{
	return (check_feature(FEATURE_GT) &&
		check_feature(FEATURE_PPR));
}

static inline u64 iommu_virt_to_phys(void *vaddr)
{
	return (u64)__sme_set(virt_to_phys(vaddr));
}

static inline void *iommu_phys_to_virt(unsigned long paddr)
{
	return phys_to_virt(__sme_clr(paddr));
}

static inline
void amd_iommu_domain_set_pt_root(struct protection_domain *domain, u64 root)
{
	domain->iop.root = (u64 *)(root & PAGE_MASK);
	domain->iop.mode = root & 7; /* lowest 3 bits encode pgtable mode */
}

static inline
void amd_iommu_domain_clr_pt_root(struct protection_domain *domain)
{
	amd_iommu_domain_set_pt_root(domain, 0);
}

static inline int get_pci_sbdf_id(struct pci_dev *pdev)
{
	int seg = pci_domain_nr(pdev->bus);
	u16 devid = pci_dev_id(pdev);

	return PCI_SEG_DEVID_TO_SBDF(seg, devid);
}

static inline void *alloc_pgtable_page(int nid, gfp_t gfp)
{
	struct page *page;

	page = alloc_pages_node(nid, gfp | __GFP_ZERO, 0);
	return page ? page_address(page) : NULL;
}

static inline struct amd_iommu *get_amd_iommu_from_dev(struct device *dev)
{
	struct iommu_device *iommu = iommu_get_iommu_dev(dev);

	return container_of(iommu, struct amd_iommu, iommu);
}

static inline struct protection_domain *to_pdomain(struct iommu_domain *dom)
{
	return container_of(dom, struct protection_domain, domain);
}

bool translation_pre_enabled(struct amd_iommu *iommu);
bool amd_iommu_is_attach_deferred(struct device *dev);
int __init add_special_device(u8 type, u8 id, u32 *devid, bool cmd_line);

#ifdef CONFIG_DMI
void amd_iommu_apply_ivrs_quirks(void);
#else
static inline void amd_iommu_apply_ivrs_quirks(void) { }
#endif

void amd_iommu_domain_set_pgtable(struct protection_domain *domain,
				  u64 *root, int mode);
struct dev_table_entry *get_dev_table(struct amd_iommu *iommu);

int iommu_completion_wait(struct amd_iommu *iommu);

extern bool amd_iommu_snp_en;

int amd_viommu_set_trans_info(struct amd_io_pgtable *iop, u16 domid);
#endif
