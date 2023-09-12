// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Advanced Micro Devices, Inc.
 */

#define pr_fmt(fmt)     "AMD-Vi: " fmt
#define dev_fmt(fmt)    pr_fmt(fmt)

#include <linux/iommu.h>
#include <linux/mm_types.h>
#include <linux/mmu_notifier.h>

#include "amd_iommu.h"

static inline bool is_pasid_enabled(struct iommu_dev_data *dev_data)
{
	if (dev_data->gcr3_info.gcr3_tbl != NULL &&
	    dev_data->gcr3_info.pasid_cnt != 0)
		return true;

	return false;
}

static int amd_iommu_pasid_enable(struct iommu_dev_data *dev_data)
{
	struct device *dev = dev_data->dev;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&dev_data->lock, flags);

	if (dev_data->gcr3_info.gcr3_tbl != NULL &&
	    dev_data->gcr3_info.pasid_cnt != 0)
		goto out;

	if (!amd_iommu_sva_supported()) {
		ret = -ENODEV;
		goto out;
	}

	if (!dev_data->pasid_enabled) {
		ret = -EINVAL;
		goto out;
	}

	ret = amd_iommu_gcr3_init(dev_data, dev->iommu->max_pasids);

out:
	spin_unlock_irqrestore(&dev_data->lock, flags);
	return ret;
}

static void amd_iommu_pasid_disable(struct iommu_dev_data *dev_data)
{
	unsigned long flags;

	spin_lock_irqsave(&dev_data->lock, flags);

	if (dev_data->gcr3_info.gcr3_tbl == NULL)
		return;

	if (dev_data->gcr3_info.pasid_cnt != 0)
		return;

	amd_iommu_gcr3_uninit(dev_data);
	spin_unlock_irqrestore(&dev_data->lock, flags);
}

static void sva_mn_invalidate_range(struct mmu_notifier *mn,
				    struct mm_struct *mm,
				    unsigned long start, unsigned long end)
{
	struct protection_domain *sva_pdom;
	struct pdom_pasid_data *pasid_data;
	struct iommu_dev_data *dev_data;

	sva_pdom = container_of(mn, struct protection_domain, mn);

	list_for_each_entry(pasid_data, &sva_pdom->pasid_list, pdom_link) {
		dev_data = pasid_data->dev_data;

		if ((start ^ (end - 1)) < PAGE_SIZE) {
			amd_iommu_flush_page(dev_data->domain,
					     pasid_data->pasid, start);
		} else {
			amd_iommu_flush_tlb(dev_data->domain,
					    pasid_data->pasid);
		}
	}
}

static void sva_mn_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
}

static const struct mmu_notifier_ops sva_mn = {
	.arch_invalidate_secondary_tlbs = sva_mn_invalidate_range,
	.release = sva_mn_release,
};

int amd_iommu_set_dev_pasid(struct iommu_domain *domain,
			    struct device *dev, ioasid_t pasid)
{
	struct protection_domain *sva_pdom = to_pdomain(domain);
	struct iommu_dev_data *dev_data = dev_iommu_priv_get(dev);
	struct pdom_pasid_data *pasid_data;
	int ret = -EINVAL;
	unsigned long flags;

	/* PASID zero is used for requests from the I/O device without PASID */
	if (pasid == 0 || pasid >= dev->iommu->max_pasids)
		return ret;

	/* Use SVA protection domain lock */
	spin_lock_irqsave(&sva_pdom->lock, flags);

	/* Make sure PASID is enabled */
	if (!is_pasid_enabled(dev_data)) {
		ret = amd_iommu_pasid_enable(dev_data);
		if (ret)
			goto out;
	}

	/* Add PASID to protection domain pasid list */
	pasid_data = kzalloc(sizeof(*pasid_data), GFP_KERNEL);
	if (pasid_data == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	pasid_data->pasid = pasid;
	pasid_data->dev_data = dev_data;

	/* Setup GCR3 table */
	ret = amd_iommu_set_gcr3(dev_data, pasid,
				 iommu_virt_to_phys(domain->mm->pgd));
	if (ret)
		goto out_free_pasid_data;

	if (list_empty(&sva_pdom->pasid_list)) {
		sva_pdom->mn.ops = &sva_mn;

		ret = mmu_notifier_register(&sva_pdom->mn, domain->mm);
		if (ret)
			goto out_clear_gcr3;
	}

	list_add(&pasid_data->pdom_link, &sva_pdom->pasid_list);
	spin_unlock_irqrestore(&sva_pdom->lock, flags);
	return ret;

out_clear_gcr3:
	amd_iommu_clear_gcr3(dev_data, pasid);

out_free_pasid_data:
	kfree(pasid_data);

out:
	spin_unlock_irqrestore(&sva_pdom->lock, flags);
	return ret;
}

static struct pdom_pasid_data *get_pdom_pasid_data(struct protection_domain *pdom,
						   struct device *dev, ioasid_t pasid)
{
	struct iommu_dev_data *dev_data = dev_iommu_priv_get(dev);
	struct pdom_pasid_data *pasid_data;

	list_for_each_entry(pasid_data, &pdom->pasid_list, pdom_link) {
		if (pasid_data->pasid == pasid &&
		    pasid_data->dev_data == dev_data)
			return pasid_data;
	}

	return NULL;
}

void amd_iommu_remove_dev_pasid(struct device *dev, ioasid_t pasid)
{
	struct pdom_pasid_data *pasid_data;
	struct protection_domain *sva_pdom;
	struct iommu_domain *domain;
	struct iommu_dev_data *dev_data = dev_iommu_priv_get(dev);
	unsigned long flags;

	if (pasid == 0 || pasid >= dev->iommu->max_pasids)
		return;

	/* Get protection domain */
	domain = iommu_get_domain_for_dev_pasid(dev, pasid, IOMMU_DOMAIN_SVA);
	if (!domain)
		return;
	sva_pdom = to_pdomain(domain);

	/* Ensure that all queued faults have been processed */
	iopf_queue_flush_dev(dev);

	spin_lock_irqsave(&sva_pdom->lock, flags);

	pasid_data = get_pdom_pasid_data(sva_pdom, dev, pasid);
	if (!pasid_data) {
		spin_unlock_irqrestore(&sva_pdom->lock, flags);
		return;
	}

	list_del(&pasid_data->pdom_link);
	kfree(pasid_data);

	/* make it visible */
	smp_wmb();

	/* Update GCR3 table and flush IOTLB */
	amd_iommu_clear_gcr3(dev_data, pasid);

	amd_iommu_pasid_disable(dev_data);

	spin_unlock_irqrestore(&sva_pdom->lock, flags);

	if (list_empty(&sva_pdom->pasid_list))
		mmu_notifier_unregister(&sva_pdom->mn, domain->mm);
}
