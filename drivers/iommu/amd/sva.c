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
#include "../iommu-sva.h"

struct amd_sva_pasid {
	u32			pasid;	/* PASID index */
	struct mm_struct	*mm;	/* mm_struct for the faults */
	struct mmu_notifier	mn;	/* mmu_notifier handle */
	struct list_head	dev_list; /* List of devices for this pasid */
};

struct amd_sva_dev {
	struct device		*dev;
	struct iommu_dev_data	*dev_data;
	struct list_head	list;
	struct rcu_head		rcu;
};

static DEFINE_MUTEX(pasid_mutex);
static DEFINE_XARRAY_ALLOC(sva_pasid_array);


static int sva_pasid_private_add(u32 pasid, void *priv)
{
	return xa_alloc(&sva_pasid_array, &pasid, priv,
			XA_LIMIT(pasid, pasid), GFP_ATOMIC);
}

static void sva_pasid_private_remove(u32 pasid)
{
	xa_erase(&sva_pasid_array, pasid);
}

static void *sva_pasid_private_find(u32 pasid)
{
	return xa_load(&sva_pasid_array, pasid);
}

static struct amd_sva_dev *sva_dev_alloc(struct device *dev)
{
	struct amd_sva_dev *sva_dev;
	struct iommu_dev_data *dev_data = dev_iommu_priv_get(dev);

	sva_dev = kzalloc(sizeof(*sva_dev), GFP_KERNEL);
	if (!sva_dev)
		return NULL;

	sva_dev->dev = dev;
	sva_dev->dev_data = dev_data;
	init_rcu_head(&sva_dev->rcu);

	return sva_dev;
}

static inline void sva_dev_free(struct amd_sva_dev *sva_dev)
{
	kfree_rcu(sva_dev, rcu);
}

static void sva_mn_invalidate_range(struct mmu_notifier *mn,
				    struct mm_struct *mm,
				    unsigned long start, unsigned long end)
{
	struct amd_sva_pasid *sva_pasid;
	struct amd_sva_dev *sva_dev;

	rcu_read_lock();

	sva_pasid = container_of(mn, struct amd_sva_pasid, mn);
	if (!sva_pasid) {
		rcu_read_unlock();
		return;
	}

	list_for_each_entry_rcu(sva_dev, &sva_pasid->dev_list, list) {
		if ((start ^ (end - 1)) < PAGE_SIZE)
			amd_iommu_flush_page(sva_dev->dev_data->domain, sva_pasid->pasid, start);
		else
			amd_iommu_flush_tlb(sva_dev->dev_data->domain, sva_pasid->pasid);
	}

	rcu_read_unlock();
}

static void sva_mn_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct amd_sva_pasid *sva_pasid;
	struct amd_sva_dev *sva_dev;

	rcu_read_lock();

	sva_pasid = container_of(mn, struct amd_sva_pasid, mn);
	if (!sva_pasid) {
		rcu_read_unlock();
		return;
	}

	/* make it visible */
	smp_wmb();

	/*
	 * This might end up being called from exit_mmap(), *before* unbinding
	 * the PASID. In such cases we clear the PASID table and flush IOTLB.
	 */
	list_for_each_entry_rcu(sva_dev, &sva_pasid->dev_list, list)
		amd_iommu_clear_gcr3(sva_dev->dev_data, sva_pasid->pasid);

	rcu_read_unlock();
}

static const struct mmu_notifier_ops sva_mn = {
	.invalidate_range = sva_mn_invalidate_range,
	.release = sva_mn_release,
};

static struct amd_sva_pasid *sva_pasid_alloc(struct mm_struct *mm)
{
	struct amd_sva_pasid *sva_pasid;

	sva_pasid = kzalloc(sizeof(*sva_pasid), GFP_KERNEL);
	if (!sva_pasid)
		return NULL;

	sva_pasid->pasid = mm->pasid;
	sva_pasid->mm = mm;
	sva_pasid->mn.ops = &sva_mn;
	INIT_LIST_HEAD(&sva_pasid->dev_list);

	return sva_pasid;
}

static inline void sva_pasid_free(struct amd_sva_pasid *sva_pasid)
{
	kfree(sva_pasid);
}

static struct amd_sva_dev *pasid_to_sva_dev(struct device *dev,
					    struct amd_sva_pasid *sva_pasid)
{
	struct amd_sva_dev *sva_dev;

	rcu_read_lock();

	list_for_each_entry_rcu(sva_dev, &sva_pasid->dev_list, list) {
		if (sva_dev->dev == dev) {
			rcu_read_unlock();
			return sva_dev;
		}
	}

	rcu_read_unlock();
	return NULL;
}

static int sva_bind_mm(struct device *dev, struct mm_struct *mm)
{
	struct amd_sva_pasid *sva_pasid;
	struct amd_sva_dev *sva_dev;
	struct iommu_dev_data *dev_data = dev_iommu_priv_get(dev);
	int ret = -EINVAL;

	sva_dev = sva_dev_alloc(dev);
	if (!sva_dev)
		return ret;

	sva_pasid = sva_pasid_private_find(mm->pasid);
	if (!sva_pasid) {
		sva_pasid = sva_pasid_alloc(mm);
		if (!sva_pasid)
			goto out_sva_dev;

		ret = sva_pasid_private_add(sva_pasid->pasid, sva_pasid);
		if (ret)
			goto out_sva_pasid;

		ret = amd_iommu_set_gcr3(dev_data, sva_pasid->pasid,
					 iommu_virt_to_phys(sva_pasid->mm->pgd));
		if (ret)
			goto out_pasid_remove;

		ret = mmu_notifier_register(&sva_pasid->mn, mm);
		if (ret)
			goto out_clear_gcr3;
	}

	/* Add sva_dev into list */
	list_add(&sva_dev->list, &sva_pasid->dev_list);
	return 0;

out_clear_gcr3:
	amd_iommu_clear_gcr3(dev_data, sva_pasid->pasid);

out_pasid_remove:
	sva_pasid_private_remove(sva_pasid->pasid);

out_sva_pasid:
	sva_pasid_free(sva_pasid);

out_sva_dev:
	sva_dev_free(sva_dev);
	return ret;
}

static void sva_unbind_mm(struct device *dev, u32 pasid)
{
	struct amd_sva_pasid *sva_pasid;
	struct amd_sva_dev *sva_dev;

	sva_pasid = sva_pasid_private_find(pasid);
	if (!sva_pasid)
		return;

	sva_dev = pasid_to_sva_dev(dev, sva_pasid);
	if (!sva_dev)
		return;

	/* make it visible */
	smp_wmb();

	/* Update GCR3 table and flush IOTLB */
	amd_iommu_clear_gcr3(sva_dev->dev_data, sva_pasid->pasid);

	list_del_rcu(&sva_dev->list);
	sva_dev_free(sva_dev);

	if (list_empty(&sva_pasid->dev_list)) {
		if (sva_pasid->mn.ops)
			mmu_notifier_unregister(&sva_pasid->mn, sva_pasid->mm);

		sva_pasid_private_remove(pasid);
		sva_pasid_free(sva_pasid);
	}
}

int amd_iommu_set_dev_pasid(struct iommu_domain *domain,
			    struct device *dev, ioasid_t pasid)
{
	struct protection_domain *pdom;
	struct mm_struct *mm = domain->mm;
	struct iommu_dev_data *dev_data = dev_iommu_priv_get(dev);
	int ret = -EINVAL;

	/* PASID zero is used for requests from the I/O device without PASID */
	if (pasid == 0 || pasid >= dev->iommu->max_pasids)
		return ret;

	/* Make sure SVA mode is enabled for device default domain */
	pdom = amd_iommu_get_pdomain(dev);

	if (!pdom || pdom->pd_mode != PD_MODE_V2 ||
	    dev_data->gcr3_info.gcr3_tbl == NULL)
		return ret;

	/* Init sva_pasid and bind mm */
	mutex_lock(&pasid_mutex);
	ret = sva_bind_mm(dev, mm);
	mutex_unlock(&pasid_mutex);

	return ret;
}

void amd_iommu_remove_dev_pasid(struct device *dev, ioasid_t pasid)
{
	struct iommu_domain *domain;

	if (pasid == 0 || pasid >= dev->iommu->max_pasids)
		return;

	/* Get SVA domain */
	domain = iommu_get_domain_for_dev_pasid(dev, pasid, 0);
	if (!domain)
		return;

	switch (domain->type) {
	case IOMMU_DOMAIN_SVA:
		/* Ensure that all queued faults have been processed */
		iopf_queue_flush_dev(dev);

		mutex_lock(&pasid_mutex);
		sva_unbind_mm(dev, pasid);
		mutex_unlock(&pasid_mutex);
		break;
	default:
		/* Should never reach here */
		WARN_ON(1);
		break;
	}
}

int amd_iommu_sva_enable(struct device *dev)
{
	struct pci_dev *pdev = dev_is_pci(dev) ? to_pci_dev(dev) : NULL;
	struct amd_iommu *iommu = get_amd_iommu_from_dev(dev);
	struct iommu_dev_data *dev_data = dev_iommu_priv_get(dev);

	if (!pdev || !iommu || !dev_data)
		return -EINVAL;

	if (!amd_iommu_sva_supported())
		return -ENODEV;

	if (!dev_data->pasid_enabled)
		return -EINVAL;

	return amd_iommu_sva_gcr3_init(dev_data, dev->iommu->max_pasids);
}

int amd_iommu_sva_disable(struct device *dev)
{
	struct amd_iommu *iommu = get_amd_iommu_from_dev(dev);
	struct iommu_dev_data *dev_data = dev_iommu_priv_get(dev);

	if (!iommu || !dev_data)
		return -EINVAL;

	return amd_iommu_sva_gcr3_uninit(dev_data);
}
