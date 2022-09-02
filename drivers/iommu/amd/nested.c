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

static struct amd_iommu *get_amd_iommu_from_devid(u16 devid)
{
	struct amd_iommu *iommu;

	for_each_iommu(iommu)
		if (iommu->devid == devid)
			return iommu;
	return NULL;
}

/*
 * Note:
 * Host-DevID is stored in the per-VM DevID mapping table,
 * which is indexed by the Guest-DevID.
 */
static u16 get_hdev_id(struct amd_iommu *iommu, u16 guestId, u16 gdev_id)
{
	struct amd_iommu_vminfo *vminfo;
	void *addr;
	u64 offset;

	vminfo = amd_iommu_get_vminfo(guestId);
	if (!vminfo)
		return -1;

	addr = vminfo->devid_table;
	offset = gdev_id << 4;
	return (*((u64 *)(addr + offset)) >> 24) & 0xFFFF;
}

static int nested_gcr3_update(struct iommu_hwpt_amd_v2 *hwpt, struct iommu_domain *udom)
{
	int ret;
	u16 hdev_id;
	struct pci_dev *pdev;
	struct amd_iommu *iommu;

	iommu = get_amd_iommu_from_devid(hwpt->iommu_id);
	hdev_id = get_hdev_id(iommu, hwpt->gid, hwpt->gdev_id);

	pr_debug("%s: gid=%u, hdev_id=%#x, gcr3=%#llx\n",
		 __func__, hwpt->gid, hdev_id,
		 (unsigned long long) hwpt->gcr3);

	pdev = pci_get_domain_bus_and_slot(0, PCI_BUS_NUM(hdev_id),
					   hdev_id & 0xff);
	if (!pdev)
		return -EINVAL;

	/* Note: Currently only support GCR3TRPMode with nested translation */
	if (!check_feature2(FEATURE_GCR3TRPMODE))
		return -EOPNOTSUPP;

	ret = amd_iommu_set_gcr3tbl_trp(iommu, pdev, hwpt->gcr3, hwpt->glx,
					hwpt->guest_paging_mode);
	if (ret) {
		pr_err("%s: Fail to enable gcr3 (devid=%#x)\n", __func__,
		       pci_dev_id(pdev));
	}

	return ret;
}

static const struct iommu_domain_ops nested_domain_ops = {
	.attach_dev		= amd_iommu_attach_device,
	.free			= amd_iommu_domain_free,
};

struct iommu_domain *amd_iommu_nested_domain_alloc(struct device *dev,
						   struct iommu_hwpt_amd_v2 *hwpt)
{
	int ret;
	struct iommu_domain *dom;
	struct protection_domain *pdom;

	dom = iommu_domain_alloc(dev->bus);
	if (!dom)
		return ERR_PTR(-ENOMEM);

	pdom = to_pdomain(dom);
	dom->type = IOMMU_DOMAIN_NESTED;
	dom->ops = &nested_domain_ops;

	ret = amd_viommu_domain_id_update(hwpt, true);
	if (ret)
		goto err_out;

	ret = nested_gcr3_update(hwpt, dom);
	if (ret)
		goto err_out;

	return dom;

err_out:
	iommu_domain_free(dom);
	return ERR_PTR(-EINVAL);
}
