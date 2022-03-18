// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Advanced Micro Devices, Inc.
 * Author: Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>
 */

#define pr_fmt(fmt)     "AMD-Vi: " fmt
#define dev_fmt(fmt)    pr_fmt(fmt)

#include <linux/iommu.h>
#include <linux/amd-iommu.h>

#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/ioctl.h>
#include <linux/iommufd.h>
#include <uapi/linux/iommufd.h>
#include <linux/mem_encrypt.h>
#include <uapi/linux/amd_viommu.h>

#include <asm/iommu.h>
#include <asm/set_memory.h>

#include "amd_iommu.h"
#include "amd_iommu_types.h"
#include "amd_viommu.h"

#define GET_CTRL_BITS(reg, bit, msk)	(((reg) >> (bit)) & (ULL(msk)))
#define SET_CTRL_BITS(reg, bit1, bit2, msk) \
	((((reg) >> (bit1)) & (ULL(msk))) << (bit2))

#define VIOMMU_MAX_GDEVID	0xFFFF
#define VIOMMU_MAX_GDOMID	0xFFFF

LIST_HEAD(viommu_devid_map);

struct amd_iommu *get_amd_iommu_from_devid(u16 devid)
{
	struct amd_iommu *iommu;

	for_each_iommu(iommu)
		if (iommu->devid == devid)
			return iommu;
	return NULL;
}

static int viommu_enable(struct amd_iommu *iommu)
{
	if (!amd_iommu_viommu)
		return -EINVAL;

	/* The GstBufferTRPMode feature is checked by set and test */
	if (!iommu_feature_enable_and_check(iommu, CONTROL_GSTBUFFERTRPMODE))
		return -EINVAL;

	if (check_feature2(FEATURE_GCR3TRPMODE))
		iommu_feature_enable(iommu, CONTROL_GCR3TRPMODE);
	iommu_feature_enable(iommu, CONTROL_VCMD_EN);
	iommu_feature_enable(iommu, CONTROL_VIOMMU_EN);

	return 0;
}

static int viommu_init_pci_vsc(struct amd_iommu *iommu)
{
	iommu->vsc_offset = pci_find_capability(iommu->dev, PCI_CAP_ID_VNDR);
	if (!iommu->vsc_offset)
		return -ENODEV;

	DUMP_printk("device:%s, vsc offset:%04x\n",
		    pci_name(iommu->dev), iommu->vsc_offset);
	return 0;
}

static int __init viommu_vf_vfcntl_init(struct amd_iommu *iommu)
{
	u32 lo, hi;
	u64 vf_phys, vf_cntl_phys;

	/* Setting up VF and VF_CNTL MMIOs */
	pci_read_config_dword(iommu->dev, iommu->vsc_offset + MMIO_VSC_VF_BAR_LO_OFFSET, &lo);
	pci_read_config_dword(iommu->dev, iommu->vsc_offset + MMIO_VSC_VF_BAR_HI_OFFSET, &hi);
	vf_phys = hi;
	vf_phys = (vf_phys << 32) | lo;
	if (!(vf_phys & 1)) {
		pr_err(FW_BUG "vf_phys disabled\n");
		return -EINVAL;
	}

	pci_read_config_dword(iommu->dev, iommu->vsc_offset + MMIO_VSC_VF_CNTL_BAR_LO_OFFSET, &lo);
	pci_read_config_dword(iommu->dev, iommu->vsc_offset + MMIO_VSC_VF_CNTL_BAR_HI_OFFSET, &hi);
	vf_cntl_phys = hi;
	vf_cntl_phys = (vf_cntl_phys << 32) | lo;
	if (!(vf_cntl_phys & 1)) {
		pr_err(FW_BUG "vf_cntl_phys disabled\n");
		return -EINVAL;
	}

	if (!vf_phys || !vf_cntl_phys) {
		pr_err(FW_BUG "AMD-Vi: Unassigned VF resources.\n");
		return -ENOMEM;
	}

	/* Mapping 256MB of VF and 4MB of VF_CNTL BARs */
	vf_phys &= ~1ULL;
	iommu->vf_base = iommu_map_mmio_space(vf_phys, 0x10000000);
	if (!iommu->vf_base) {
		pr_err("Can't reserve vf_base\n");
		return -ENOMEM;
	}

	vf_cntl_phys &= ~1ULL;
	iommu->vfctrl_base = iommu_map_mmio_space(vf_cntl_phys, 0x400000);

	if (!iommu->vfctrl_base) {
		pr_err("Can't reserve vfctrl_base\n");
		return -ENOMEM;
	}

	pr_debug("%s: IOMMU device:%s, vf_base:%#llx, vfctrl_base:%#llx\n",
		 __func__, pci_name(iommu->dev), vf_phys, vf_cntl_phys);
	return 0;
}

static void *alloc_private_region(struct amd_iommu *iommu,
				  u64 base, size_t size)
{
	int ret;
	void *region;

	region  = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
						get_order(size));
	if (!region)
		return NULL;

	ret = set_memory_uc((unsigned long)region, size >> PAGE_SHIFT);
	if (ret)
		goto err_out;

	if (amd_iommu_v1_map_pages(&iommu->viommu_pdom->iop.iop.ops, base,
				   iommu_virt_to_phys(region), PAGE_SIZE, (size / PAGE_SIZE),
				   IOMMU_PROT_IR | IOMMU_PROT_IW, GFP_KERNEL, NULL))
		goto err_out;

	pr_debug("%s: base=%#llx, size=%#lx\n", __func__, base, size);

	return region;

err_out:
	free_pages((unsigned long)region, get_order(size));
	return NULL;
}

static int alloc_private_vm_region(struct amd_iommu *iommu, u64 **entry,
				   u64 base, size_t size, u16 guestId)
{
	int ret;
	u64 addr = base + (guestId * size);

	*entry = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(size));

	ret = set_memory_uc((unsigned long)*entry, size >> PAGE_SHIFT);
	if (ret)
		return ret;

	pr_debug("%s: entry=%#llx(%#llx), addr=%#llx\n", __func__,
		 (unsigned long  long)*entry, iommu_virt_to_phys(*entry), addr);

	ret = amd_iommu_v1_map_pages(&iommu->viommu_pdom->iop.iop.ops, addr,
				     iommu_virt_to_phys(*entry), PAGE_SIZE, (size / PAGE_SIZE),
				     IOMMU_PROT_IR | IOMMU_PROT_IW, GFP_KERNEL, NULL);
	if (ret)
		return ret;

	return amd_iommu_flush_private_vm_region(iommu, iommu->viommu_pdom, addr, size);
}

static void free_private_vm_region(struct amd_iommu *iommu, u64 **entry,
					u64 base, size_t size, u16 guestId)
{
	size_t ret;
	struct iommu_iotlb_gather gather;
	u64 addr = base + (guestId * size);

	pr_debug("entry=%#llx(%#llx), addr=%#llx\n",
		 (unsigned long  long)*entry,
		 iommu_virt_to_phys(*entry), addr);

	if (!iommu || iommu->viommu_pdom)
		return;
	ret = amd_iommu_v1_unmap_pages(&iommu->viommu_pdom->iop.iop.ops,
				       addr, PAGE_SIZE, (size / PAGE_SIZE), &gather);
	if (ret)
		amd_iommu_iotlb_sync(&iommu->viommu_pdom->domain, &gather);

	free_pages((unsigned long)*entry, get_order(size));
	*entry = NULL;
}

/* Set DTE for IOMMU device */
static void set_iommu_dte(struct amd_iommu *iommu)
{
	u64 dte0, dte1;
	u16 devid = iommu->devid;
	struct protection_domain *pdom = iommu->viommu_pdom;
	struct dev_table_entry *dev_table = get_dev_table(iommu);

	dte0 = iommu_virt_to_phys(pdom->iop.root);
	dte0 |= (pdom->iop.mode & DEV_ENTRY_MODE_MASK) << DEV_ENTRY_MODE_SHIFT;
	dte0 |= DTE_FLAG_IR | DTE_FLAG_IW | DTE_FLAG_V | DTE_FLAG_TV;

	dte1 = dev_table[devid].data[1];
	dte1 &= ~DEV_DOMID_MASK;
	dte1 |= pdom->id;


	dev_table[devid].data[1] = dte1;
	dev_table[devid].data[0] = dte0;

	iommu_flush_dte(iommu, devid);
	iommu_completion_wait(iommu);
}

static int viommu_private_space_init(struct amd_iommu *iommu)
{
	u64 pte_root = 0;
	struct iommu_domain *dom;
	struct protection_domain *pdom;

	/*
	 * Setup page table root pointer, Guest MMIO and
	 * Cmdbuf Dirty Status regions.
	 */
	dom = amd_iommu_domain_alloc(IOMMU_DOMAIN_UNMANAGED);
	if (!dom)
		goto err_out;

	pdom = to_pdomain(dom);
	iommu->viommu_pdom = pdom;

	iommu->guest_mmio = alloc_private_region(iommu,
						 VIOMMU_GUEST_MMIO_BASE,
						 VIOMMU_GUEST_MMIO_SIZE);
	if (!iommu->guest_mmio)
		goto err_out;

	iommu->cmdbuf_dirty_mask = alloc_private_region(iommu,
							VIOMMU_CMDBUF_DIRTY_STATUS_BASE,
							VIOMMU_CMDBUF_DIRTY_STATUS_SIZE);
	if (!iommu->cmdbuf_dirty_mask)
		goto err_out;

	pte_root = iommu_virt_to_phys(pdom->iop.root);
	pr_debug("%s: devid=%#x, pte_root=%#llx(%#llx), guest_mmio=%#llx(%#llx), cmdbuf_dirty_mask=%#llx(%#llx)\n",
		 __func__, iommu->devid, (unsigned long long)pdom->iop.root, pte_root,
		 (unsigned long long)iommu->guest_mmio, iommu_virt_to_phys(iommu->guest_mmio),
		 (unsigned long long)iommu->cmdbuf_dirty_mask,
		 iommu_virt_to_phys(iommu->cmdbuf_dirty_mask));

	return 0;
err_out:
	if (iommu->guest_mmio)
		free_pages((unsigned long)iommu->guest_mmio, get_order(VIOMMU_GUEST_MMIO_SIZE));

	if (dom)
		amd_iommu_domain_free(dom);
	return -ENOMEM;
}

/*
 * When IOMMU Virtualization is enabled, host software must:
 *	- allocate system memory for IOMMU private space
 *	- program IOMMU as an I/O device in Device Table
 *	- maintain the I/O page table for IOMMU private addressing to SPA translations.
 *	- specify the base address of the IOMMU Virtual Function MMIO and
 *	  IOMMU Virtual Function Control MMIO region.
 *	- enable Guest Virtual APIC enable (MMIO Offset 0x18[GAEn]).
 */
int __init iommu_init_viommu(struct amd_iommu *iommu)
{
	int ret = -EINVAL;

	if (!amd_iommu_viommu)
		return 0;

	if (!check_feature(FEATURE_VIOMMU))
		goto err_out;

	ret = viommu_init_pci_vsc(iommu);
	if (ret)
		goto err_out;

	ret = viommu_vf_vfcntl_init(iommu);
	if (ret)
		goto err_out;

	ret = viommu_private_space_init(iommu);
	if (ret)
		goto err_out;

	set_iommu_dte(iommu);

	ret = viommu_enable(iommu);
	if (ret)
		goto err_out;

	return ret;

err_out:
	amd_iommu_viommu = false;
	return ret;
}

static void viommu_uninit_one(struct amd_iommu *iommu, struct amd_iommu_vminfo *vminfo, u16 guestId)
{
	free_private_vm_region(iommu, &vminfo->devid_table,
			       VIOMMU_DEVID_MAPPING_BASE,
			       VIOMMU_DEVID_MAPPING_ENTRY_SIZE,
			       guestId);
	free_private_vm_region(iommu, &vminfo->domid_table,
			       VIOMMU_DOMID_MAPPING_BASE,
			       VIOMMU_DOMID_MAPPING_ENTRY_SIZE,
			       guestId);
}

/*
 * Clear the DevID via VFCTRL registers
 * This function will be called during VM destroy via VFIO.
 */
static void clear_device_mapping(struct amd_iommu *iommu, u16 hDevId, u16 guestId,
				 u16 queueId, u16 gDevId)
{
	u64 val, tmp1, tmp2;
	u8 __iomem *vfctrl;

	/*
	 * Clear the DevID in VFCTRL registers
	 */
	tmp1 = gDevId;
	tmp1 = ((tmp1 & 0xFFFFULL) << 46);
	tmp2 = hDevId;
	tmp2 = ((tmp2 & 0xFFFFULL) << 14);
	val = tmp1 | tmp2 | 0x8000000000000001ULL;
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, guestId);
	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL0_OFFSET);
}

/*
 * Clear the DomID via VFCTRL registers
 * This function will be called during VM destroy via VFIO.
 */
static void clear_domain_mapping(struct amd_iommu *iommu, u16 hDomId, u16 guestId, u16 gDomId)
{
	u64 val, tmp1, tmp2;
	u8 __iomem *vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, guestId);

	tmp1 = gDomId;
	tmp1 = ((tmp1 & 0xFFFFULL) << 46);
	tmp2 = hDomId;
	tmp2 = ((tmp2 & 0xFFFFULL) << 14);
	val = tmp1 | tmp2 | 0x8000000000000001UL;
	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL1_OFFSET);
}

static void viommu_clear_mapping(struct amd_iommu *iommu, u16 guestId)
{
	int i;

	for (i = 0; i <= VIOMMU_MAX_GDEVID; i++)
		clear_device_mapping(iommu, 0, guestId, 0, i);

	for (i = 0; i <= VIOMMU_MAX_GDOMID; i++)
		clear_domain_mapping(iommu, 0, guestId, i);
}

static void viommu_clear_dirty_status_mask(struct amd_iommu *iommu, unsigned int gid)
{
	u32 offset, index, bits;
	u64 *group, val;

	if (gid >= 256 * 256)
		return;

	group = (u64 *)(iommu->cmdbuf_dirty_mask +
		(((gid & 0xFF) << 4) | (((gid >> 13) & 0x7) << 2)));
	offset = (gid >> 8) & 0x1F;
	index = offset >> 6;
	bits = offset & 0x3F;

	val = READ_ONCE(group[index]);
	val &= ~(1ULL << bits);
	WRITE_ONCE(group[index], val);
}

/*
 * Allocate pages for the following regions:
 * - Guest MMIO
 * - DeviceID/DomainId Mapping Table
 * - Cmd buffer
 * - Event/PRR (A/B) logs
 */
static int viommu_init_one(struct amd_iommu *iommu, struct amd_iommu_vminfo *vminfo)
{
	int ret;

	ret = alloc_private_vm_region(iommu, &vminfo->devid_table,
				      VIOMMU_DEVID_MAPPING_BASE,
				      VIOMMU_DEVID_MAPPING_ENTRY_SIZE,
				      vminfo->gid);
	if (ret)
		goto err_out;

	ret = alloc_private_vm_region(iommu, &vminfo->domid_table,
				      VIOMMU_DOMID_MAPPING_BASE,
				      VIOMMU_DOMID_MAPPING_ENTRY_SIZE,
				      vminfo->gid);
	if (ret)
		goto err_out;

	viommu_clear_mapping(iommu, vminfo->gid);
	viommu_clear_dirty_status_mask(iommu, vminfo->gid);

	return 0;
err_out:
	viommu_uninit_one(iommu, vminfo, vminfo->gid);
	return -ENOMEM;
}

int amd_viommu_iommu_init(struct amd_viommu_iommu_info *data)
{
	int ret;
	struct amd_iommu_vminfo *vminfo;
	unsigned int iommu_id = data->iommu_id;
	struct amd_iommu *iommu = get_amd_iommu_from_devid(iommu_id);

	if (!iommu)
		return -ENODEV;

	vminfo = kzalloc(sizeof(*vminfo), GFP_KERNEL);
	if (!vminfo)
		return -ENOMEM;

	ret = amd_iommu_vminfo_alloc(iommu, vminfo);
	if (ret)
		goto err_out;

	ret = viommu_init_one(iommu, vminfo);
	if (ret)
		goto err_out;

	vminfo->init = true;
	data->gid = vminfo->gid;
	vminfo->trans_devid = data->trans_devid;
	pr_debug("%s: iommu_id=%#x, gid=%#x, trans_devid=%#x\n", __func__,
		pci_dev_id(iommu->dev), vminfo->gid, vminfo->trans_devid);

	return ret;

err_out:
	amd_iommu_vminfo_free(iommu, vminfo);
	kfree(vminfo);
	return ret;
}
EXPORT_SYMBOL(amd_viommu_iommu_init);

int amd_viommu_iommu_destroy(struct amd_viommu_iommu_info *data)
{
	unsigned int gid = data->gid;
	struct amd_iommu_vminfo *vminfo;
	unsigned int iommu_id = data->iommu_id;
	struct amd_iommu *iommu = get_amd_iommu_from_devid(iommu_id);

	if (!iommu)
		return -ENODEV;

	vminfo = amd_iommu_get_vminfo(gid);
	if (!vminfo)
		return -EINVAL;

	viommu_uninit_one(iommu, vminfo, gid);

	if (vminfo->init)
		vminfo->init = false;
	return 0;

}
EXPORT_SYMBOL(amd_viommu_iommu_destroy);

static int viommu_set_translate_dte(struct amd_iommu *iommu, u16 gid)
{
	u16 devid;
	u64 val, tmp0, tmp1;
	u8 __iomem *vfctrl;
	struct amd_iommu_vminfo *vminfo;
	struct dev_table_entry *dev_table = get_dev_table(iommu);

	vminfo = amd_iommu_get_vminfo(gid);
	if (!vminfo)
		return -EINVAL;

	/* FIXME: Need to be per vIOMMU instance */
	if (vminfo->trans_init)
		return 0;

	pr_debug("%s: gid=%#x, devid=%#x\n", __func__, gid, vminfo->trans_devid);

	/* Setup DTE for the devid */
	devid = vminfo->trans_devid;
	tmp0 = iommu_virt_to_phys(vminfo->trans_iop->root) & 0xFFFFFFFFFF000ULL;
	tmp0 |= (vminfo->trans_iop->mode & 0x7ULL) << 9;
	tmp0 |= (DTE_FLAG_IR | DTE_FLAG_IW | DTE_FLAG_TV | DTE_FLAG_V);
	tmp1 = vminfo->trans_domid & 0xFFFFULL;

	dev_table[devid].data[0] = tmp0;
	dev_table[devid].data[1] = tmp1;

	iommu_flush_dte(iommu, devid);
	iommu_completion_wait(iommu);

	val = devid & 0xFFFFULL;
	val = val << 16;
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, gid);

	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_MISC_CONTROL_OFFSET);

	vminfo->trans_init = true;
	return 0;
}

static void set_dte_viommu(struct amd_iommu *iommu, u16 hDevId, u16 gid, u16 gDevId)
{
	u64 tmp, dte;
	struct dev_table_entry *dev_table = get_dev_table(iommu);

	// vImuEn
	dte = dev_table[hDevId].data[3];
	dte |= (1ULL << DTE_VIOMMU_EN_SHIFT);

	// GDeviceID
	tmp = gDevId & DTE_VIOMMU_GUESTID_MASK;
	dte |= (tmp << DTE_VIOMMU_GUESTID_SHIFT);

	// GuestID
	tmp = gid & DTE_VIOMMU_GUESTID_MASK;
	dte |= (tmp << DTE_VIOMMU_GDEVICEID_SHIFT);

	dev_table[hDevId].data[3] = dte;

	dte = dev_table[hDevId].data[0];
	dte |= DTE_FLAG_GV;
	dev_table[hDevId].data[0] = dte;

	iommu_flush_dte(iommu, hDevId);
}

static void dump_device_mapping(struct amd_iommu *iommu, u16 guestId, u16 gdev_id)
{
	void *addr;
	u64 offset, val;
	struct amd_iommu_vminfo *vminfo;

	vminfo = amd_iommu_get_vminfo(guestId);
	if (!vminfo)
		return;

	addr = vminfo->devid_table;
	offset = gdev_id << 4;
	val = *((u64 *)(addr + offset));

	pr_debug("%s: guestId=%#x, gdev_id=%#x, base=%#llx, offset=%#llx(val=%#llx)\n", __func__,
		 guestId, gdev_id, (unsigned long long)iommu_virt_to_phys(vminfo->devid_table),
		 (unsigned long long)offset, (unsigned long long)val);
}

/*
 * Program the DevID via VFCTRL registers
 * This function will be called during VM init via VFIO.
 */
static void set_device_mapping(struct amd_iommu *iommu, u16 hDevId,
			       u16 guestId, u16 queueId, u16 gDevId)
{
	u64 val, tmp1, tmp2;
	u8 __iomem *vfctrl;

	pr_debug("%s: iommu_id=%#x, gid=%#x, hDevId=%#x, gDevId=%#x\n",
		__func__, pci_dev_id(iommu->dev), guestId, hDevId, gDevId);

	set_dte_viommu(iommu, hDevId, guestId, gDevId);

	tmp1 = gDevId;
	tmp1 = ((tmp1 & 0xFFFFULL) << 46);
	tmp2 = hDevId;
	tmp2 = ((tmp2 & 0xFFFFULL) << 14);
	val = tmp1 | tmp2 | 0x8000000000000001ULL;
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, guestId);
	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL0_OFFSET);

	wbinvd_on_all_cpus();
}

static void clear_dte_viommu(struct amd_iommu *iommu, u16 hDevId)
{
	struct dev_table_entry *dev_table = get_dev_table(iommu);
	u64 dte = dev_table[hDevId].data[3];

	dte &= ~(1ULL << DTE_VIOMMU_EN_SHIFT);
	dte &= ~(0xFFFFULL << DTE_VIOMMU_GUESTID_SHIFT);
	dte &= ~(0xFFFFULL << DTE_VIOMMU_GDEVICEID_SHIFT);

	dev_table[hDevId].data[3] = dte;

	dte = dev_table[hDevId].data[0];
	dte &= ~DTE_FLAG_GV;
	dev_table[hDevId].data[0] = dte;

	iommu_flush_dte(iommu, hDevId);
}

int amd_viommu_device_update(struct amd_viommu_dev_info *data, bool is_set)
{
	struct pci_dev *pdev;
	struct iommu_domain *dom;
	int gid = data->gid;
	struct amd_iommu *iommu = get_amd_iommu_from_devid(data->iommu_id);
	struct iommu_dev_data *dev_data;

	if (!iommu)
		return -ENODEV;

	clear_dte_viommu(iommu, data->hdev_id);

	if (is_set) {
		set_device_mapping(iommu, data->hdev_id, gid,
				   data->queue_id, data->gdev_id);

		pdev = pci_get_domain_bus_and_slot(0, PCI_BUS_NUM(data->hdev_id),
						   data->hdev_id & 0xff);

		/* Extract guest ID from struct iommu_dev_data */
		dev_data = dev_iommu_priv_get(&pdev->dev);
		if (!dev_data) {
			pr_err("%s: Device not found (devid=%#x)\n",
			       __func__, pci_dev_id(pdev));
			return -EINVAL;
		}

		dev_data->gid = gid;
		dom = iommu_get_domain_for_dev(&pdev->dev);
		if (!dom) {
			pr_err("%s: Domain not found (devid=%#x)\n",
			       __func__, pci_dev_id(pdev));
			return -EINVAL;
		}

		amd_iommu_domain_flush_all(to_pdomain(dom));
	} else {
		clear_device_mapping(iommu, data->hdev_id, gid,
				     data->queue_id, data->gdev_id);
	}
	dump_device_mapping(iommu, gid, data->gdev_id);

	return 0;
}
EXPORT_SYMBOL(amd_viommu_device_update);
