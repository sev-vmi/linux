// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Advanced Micro Devices, Inc.
 * Author: Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>
 */

#define pr_fmt(fmt)     "AMD-Vi: " fmt
#define dev_fmt(fmt)    pr_fmt(fmt)

#include <linux/iommu.h>
#include <uapi/linux/iommufd.h>

#include "amd_iommu.h"

bool amd_iommu_domain_is_nested(struct protection_domain *pdom)
{
	return (pdom && pdom->parent != NULL);
}

static int nested_gcr3_update(struct iommu_hwpt_amd_v2 *hwpt,
			      struct protection_domain *pdom,
			      struct protection_domain *ppdom,
			      struct device *dev)
{
	struct page *page;
	unsigned long npinned;
	struct pci_dev *pdev;
	struct iommu_dev_data *dev_data = dev_iommu_priv_get(dev);

	pdev = to_pci_dev(dev);
	if (!pdev)
		return -EINVAL;

	pdom->parent = ppdom;
	pdom->guest_domain_id = hwpt->gdom_id;
	pdom->guest_paging_mode = hwpt->flags.guest_paging_mode;

	/* Currently only support 1-level GCR3 table */
	npinned = get_user_pages_fast(hwpt->gcr3_va, 1, FOLL_WRITE, &page);
	if (!npinned) {
		pr_err("Failure locking grc3 page (%#llx).\n", hwpt->gcr3_va);
		return -EINVAL;
	}

	dev_data->gcr3_info.trp_gpa = hwpt->gcr3;
	dev_data->gcr3_info.spa = __sme_set(page_to_pfn(page) << PAGE_SHIFT);

	dev_data->gcr3_info.glx = hwpt->flags.glx;
	dev_data->gcr3_info.giov = hwpt->flags.giov;

	return 0;
}

struct iommu_domain *do_iommu_domain_alloc(unsigned int type,
						  struct device *dev, u32 flags);
struct iommu_domain *
amd_iommu_nested_domain_alloc(struct device *dev, unsigned int type, u32 flags,
			      struct iommu_hwpt_amd_v2 *hwpt,
			      struct iommu_domain *parent)
{
	int ret;
	struct iommu_domain *dom;
	struct protection_domain *pdom;

	pr_debug("%s: Allocating nested domain with parent domid=%#x\n",
		 __func__, to_pdomain(parent)->id);

	dom = do_iommu_domain_alloc(IOMMU_DOMAIN_NESTED, dev, flags);
	if (IS_ERR(dom))
		return ERR_PTR(-ENOMEM);

	pdom = to_pdomain(dom);
	ret = nested_gcr3_update(hwpt, pdom, to_pdomain(parent), dev);
	if (ret)
		goto err_out;

	return dom;

err_out:
	iommu_domain_free(dom);
	return ERR_PTR(-EINVAL);
}
