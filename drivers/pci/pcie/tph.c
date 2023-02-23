// SPDX-License-Identifier: GPL-2.0
/*
 * TPH (TLP Processing Hints) interface
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 * Author: Eric Van Tassell (Eric.VanTassell@amd.com)
 */

#include <uapi/linux/pci_regs.h>
#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/msi.h>
#include <linux/pci.h>

#ifdef CONFIG_PCIE_TPH

extern const guid_t pci_acpi_dsm_guid;

/* steering tag table in TPH config spce */
#define TPH_REQR_ST_TABLE_OFFSET	0xC

static void __iomem *tph_msix_desc_addr(struct pci_dev *dev,
					struct msi_desc *desc)
{
	return dev->msix_base + desc->msi_index * PCI_MSIX_ENTRY_SIZE;
}

/*
 * tph_set_reg_field_u32() - Write field_value to TPH register at reg_offset.
 * @dev: pci device
 * @reg_offset: the TPH register offset
 * @mask: the mask of the field
 * @shift: the shift of the field (0 <= shift < 32)
 * @field_val: the value to write
 *
 * Mask @field_val with @mask, shift left @shift bits, and write to @register_offset.
 */
static int tph_set_reg_field_u32(struct pci_dev *dev, u8 reg_offset, u32 mask,
				 u8 shift, u32 field_val)
{
	int ret;
	u32 reg_val;

	if (!dev->tph_cap)
		return -EINVAL;

	/* read the current value */
	ret = pci_read_config_dword(dev, dev->tph_cap + reg_offset,
				    &reg_val);
	if (ret) {
		printk("FIXME:%s: cap:%d, offset:%d, read failed, ret = %d\n",
			__FUNCTION__, dev->tph_cap, reg_offset, ret);
		return ret;
	}

	reg_val &= ~mask;
	reg_val |= (field_val << shift);

	ret = pci_write_config_dword(dev, dev->tph_cap + reg_offset,
				     reg_val);
	if (ret)
		printk("FIXME:%s: cap:%d, offset:%d, write failed, ret = %d\n",
			__FUNCTION__, dev->tph_cap, reg_offset, ret);
	return ret;
}

/*
 * tph_get_reg_field_u32() - Read a field of the TPH register at reg_offset.
 * @dev: pci device
 * @reg_offset: the TPH register offset
 * @mask: the mask of the field(may be 32 1 bits
 * @shift: the shift of the field(0 <= shift <32)
 * @out: where to write the field
 *
 * Read the register at @register_offset, mask the result with @mask,
 * shift @shift
 * bits right and set the u32 pointed at by @out to the result.
 */
static int tph_get_reg_field_u32(struct pci_dev *dev, u8 reg_offset, u32 mask,
				 u8 shift, u32 *out)
{
	u32 val;
	int ret;

	if (!dev->tph_cap)
		return -EINVAL;

	ret = pci_read_config_dword(dev, dev->tph_cap + reg_offset, &val);
	if (ret)
		return ret;

	*out = (val & mask) >> shift;

	return 0;
}

static int tph_get_table_size(struct pci_dev *dev, u16 *sz_out)
{
	int ret;
	u32 tmp;

	ret = tph_get_reg_field_u32(dev, TPH_CAP_REG_OFFSET,
				    TPH_CAP_ST_TABLE_SIZE_MASK,
				    TPH_CAP_ST_TABLE_SIZE_SHIFT, &tmp);
	printk("FIXME:%s: ret = %d, tbl sz = %d\n", __FUNCTION__,
		ret, tmp);
	if (ret)
		return ret;

	*sz_out = (u16)tmp;
	return 0;
}

static int tph_get_root_port_completer_capability(struct pci_dev *dev)
{
	struct pci_dev *rp;
	int ret;
	int val;

	rp = pcie_find_root_port(dev);
	if (!rp) {
		WARN_ONCE(1, "cannot find root port");
		return 0;
	}
	ret = pcie_capability_read_dword(rp, PCI_EXP_DEVCAP2, &val);
	if (ret) {
		WARN_ONCE(1, "cannot read device capabilities 2");
		return 0;
	}

	val = (val & PCIE_DEVCAP2_TPH_CMPLTR_MASK) >> PCIE_DEVCAP2_TPH_CMPLTR_SHIFT;
	return val;
}

static bool completer_support_ok(struct pci_dev *dev,
				 enum tph_requester_enable req_enable)
{
	enum tph_requester_enable cmpltr_support;

	cmpltr_support = tph_get_root_port_completer_capability(dev);

	if (cmpltr_support != TPH_CMPLTR_SUPPORTS_TPH_ONLY &&
	    cmpltr_support != TPH_CMPLTR_SUPPORTS_TPH_AND_EXTENDED_TPH) {
		WARN_ONCE(1, "root port lacks tph completer capability");
		return false;
	}

	if (cmpltr_support == TPH_CMPLTR_SUPPORTS_NONE &&
	    req_enable != TPH_REQ_DISABLE) {
		pr_err("no tph completer found => TPH cannot be enabled\n");
		return false;
	}

	if (cmpltr_support == TPH_CMPLTR_SUPPORTS_TPH_ONLY &&
	    req_enable == TPH_REQ_TPH_EXTENDED) {
		pr_err("requester_enable exceeds completer capability\n");
		return false;
	}
	return true;
}

static bool no_st_mode_supported(struct pci_dev *dev)
{
	bool no_st;
	int ret;
	u32 tmp;

	ret = tph_get_reg_field_u32(dev, TPH_CAP_REG_OFFSET,
				    TPH_CAP_NO_ST_MODE_MASK,
				    TPH_CAP_NO_ST_MODE_SHIFT, &tmp);
	if (ret)
		return false;

	no_st = (bool)tmp;

	if (!no_st) {
		pr_err("TPH devices must support no st mode\n");
		return false;
	}
	return true;
}

void pcie_tph_init(struct pci_dev *dev)
{
	dev->tph_cap = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_TPH);
	dev->stte_req_enable = 0;
}

/*
 * tph_clr_ctrl_reg_en -  Clear the TPH enable bit in the TPH control register
 * so that no PCI write transactions have TPH headers
 */
int tph_clr_ctrl_reg_en(struct pci_dev *dev)
{
	return  tph_set_reg_field_u32(dev, TPH_CTRL_REG_OFFSET, TPH_CTRL_REQ_EN_MASK,
				      TPH_CTRL_REQ_EN_SHIFT, TPH_REQ_DISABLE);
}

/*
 * tph_set_dev_no_st_mode - In the TPH Requester Control Register:
 *        - Set ST Mode Select to "No ST Mode" (0).
 *        - Set "TPH Requester Enable" to TPH only (1).
 */
int tph_set_dev_no_st_mode(struct pci_dev *dev)
{
	int ret;

	ret = tph_set_reg_field_u32(dev, TPH_CTRL_REG_OFFSET,
				    TPH_CTRL_MODE_SEL_MASK,
				    TPH_CTRL_MODE_SEL_SHIFT, TPH_NO_ST_MODE);
	if (ret)
		return ret;

	ret = tph_set_reg_field_u32(dev, TPH_CTRL_REG_OFFSET,
				    TPH_CTRL_REQ_EN_MASK, TPH_CTRL_REQ_EN_SHIFT,
				    TPH_REQ_TPH_ONLY);
	return ret;
}

/*
 * tph_write_control_register() - write TPH control register value to hardware
 */
static int tph_write_control_register(struct pci_dev *dev,
				      u32 tph_control_register)
{
	int ret;

	ret = tph_set_reg_field_u32(dev, TPH_CTRL_REG_OFFSET, ~0L, 0,
				    tph_control_register);
	if (ret)
		goto error_ret;

	return 0;

error_ret:
	/* Something went wrong. Minimize any possible harm by disabling TPH.*/
	printk("FIXME@%s:tph_set_reg_field_u32() failed, clearing tph enable\n", __FUNCTION__);
	tph_clr_ctrl_reg_en(dev);
	return ret;
}

static int tph_set_ctrl_reg_mode_sel(struct pci_dev *dev,
				     enum tph_st_mode_selected st_mode)
{
	int ret;
	u32 control_reg;

	ret = tph_get_reg_field_u32(dev, TPH_CTRL_REG_OFFSET, ~0L, 0,
				    &control_reg);
	if (ret)
		return ret;

	/* clear the mode select and enable fields and set new values*/
	control_reg &= ~(TPH_CTRL_MODE_SEL_MASK);
	control_reg |= ((u32)(st_mode << TPH_CTRL_MODE_SEL_SHIFT) &
			TPH_CTRL_MODE_SEL_MASK);

	ret = tph_write_control_register(dev, control_reg);
	if (ret)
		return ret;
	return 0;
}

static int tph_set_ctrl_reg_en(struct pci_dev *dev,
			       enum tph_requester_enable req_enable)
{
	int ret;
	u32 control_reg;

	ret = tph_get_reg_field_u32(dev, TPH_CTRL_REG_OFFSET, ~0L, 0,
				    &control_reg);
	if (ret)
		return ret;

	/* clear the mode select and enable fields and set new values*/
	control_reg &= ~(TPH_CTRL_REQ_EN_MASK);
	control_reg |= (((u32)req_enable << TPH_CTRL_REQ_EN_SHIFT) &
			TPH_CTRL_REQ_EN_MASK);

	ret = tph_write_control_register(dev, control_reg);
	if (ret)
		return ret;

	return 0;
}

void dump_msix_tags(struct pci_dev *dev)
{
	struct msi_desc *entry;
	void __iomem *vec_ctrl_addr;
	u32 val;

	printk("FIXME:tagz:%s: dev = %p\n", __FUNCTION__, dev);
	msi_lock_descs(&dev->dev);
	msi_for_each_desc(entry, &dev->dev, MSI_DESC_ASSOCIATED) {
		vec_ctrl_addr = tph_msix_desc_addr(dev, entry)
			+ PCI_MSIX_ENTRY_VECTOR_CTRL;
		val = readl(vec_ctrl_addr);
		printk("FIXME:tagz%s: dev:%p, nr: %d, vec_ctrl: 0x%x\n",
			__FUNCTION__, dev, entry->msi_index, val);
	}
	msi_unlock_descs(&dev->dev);
}

/*
 * translate from MSI-X interrupt ordinal number to msi_desc *
 */
static struct msi_desc *tph_msix_nr_to_desc(struct pci_dev *dev, int msix_nr)
{
	struct msi_desc *entry;

	msi_lock_descs(&dev->dev);
	msi_for_each_desc(entry, &dev->dev, MSI_DESC_ASSOCIATED) {
		if (entry->msi_index == msix_nr) {
			msi_unlock_descs(&dev->dev);
			return entry;
		}
	}
	WARN_ONCE(1, "msi-x descriptor not found.\n");
	msi_unlock_descs(&dev->dev);
	return NULL;
}

/*
 * Write the steering tag to the memory mapped vector control register.
 */
static void tph_write_tag_to_msix(struct pci_dev *dev, int msix_nr, u16 tagval)
{
	u32 val;
	void __iomem *vec_ctrl;
	struct msi_desc *msi_desc = tph_msix_nr_to_desc(dev, msix_nr);

	/*
	 * vector control msi-x register looks like
	 * 31       24|23      16|15      8|7        1|    0     |
	 * +----------|----------|---------|----------|----------|
	 * | st upper | st lower |      reserved      | mask bit |
	 * +----------|----------|---------|----------|----------|
	 */
	printk("%s@%d: dev:%p, msixnr:%d, tagval:0x%x\n", __FUNCTION__,
		__LINE__, dev, msix_nr, tagval);

	if (!msi_desc) {
		WARN_ONCE(1, "msix descriptor for #%d not found\n", msix_nr);
		return;
	}

	vec_ctrl = tph_msix_desc_addr(dev, msi_desc) +
		   PCI_MSIX_ENTRY_VECTOR_CTRL;

	val = readl(vec_ctrl);
	val &= 0xffff;
	val |= (tagval << 16);
	writel(val, vec_ctrl);

	/* read back vector ctrl (to flush write) */
	val = readl(vec_ctrl);
	printk("FIXME:tagz:%s entry#: %d, vec_ctrl:0x%x\n", __FUNCTION__,
		msi_desc->msi_index, val);
}

static bool int_vec_mode_supported(struct pci_dev *dev)
{
	u32 tmp;
	int ret;

	/* check that device supports steering tags in msix */
	ret = tph_get_reg_field_u32(dev, TPH_CAP_REG_OFFSET,
				    TPH_CAP_INT_VEC_MODE_MASK,
				    TPH_CAP_INT_VEC_MODE_SHIFT, &tmp);
	if (ret)
		return false;

	return true;
}

static bool msix_nr_in_bounds(struct pci_dev *dev, int msix_nr)
{
	u16 tbl_sz;

	if (tph_get_table_size(dev, &tbl_sz))
		return false;
	printk("FIXME:%s: table size = %d\n", __FUNCTION__, tbl_sz);
	return msix_nr <= tbl_sz; /* FIXME: check n -1 countage*/
}

static bool can_set_stte(struct pci_dev *dev,
			 enum tph_st_mode_selected st_mode,
			 enum tph_requester_enable req_enable, int msix_nr)
{
	printk("FIXME:%s@%d: cap:%d, msix:%d, dis:%d, stmode:%d\n",
		__FUNCTION__, __LINE__, dev->tph_cap, dev->msix_enabled,
		tph_get_option_disabled(), tph_get_option_no_st_mode());

	if (!dev->tph_cap || !dev->msix_enabled ||
	    !int_vec_mode_supported(dev) || tph_get_option_disabled() ||
	    tph_get_option_no_st_mode() || !msix_nr_in_bounds(dev, msix_nr) ||
	    !completer_support_ok(dev, req_enable) ||
		!no_st_mode_supported(dev)) {
		printk("FIXME:%s: FAIL\n", __FUNCTION__);
		return false;
	}
	printk("FIXME:%s: PASS\n", __FUNCTION__);
	return true;
}

#define MINIMUM_DSM_REVISION		7
#define DSM_STEERING_TAG_FUNCTION_INDEX	0xf

/*
 * invoke_dsm - invoke the firmware method to retrieve the steering tags
 * for a core
 * @handle: ACPI handle of the device where the firmwre method is
 * implemented
 * @cpu_uid: ACPI processor UID as specified in MADT
 * @processor_hint:
 *         00b: bi directional data structure - equal read/write access by
 *              host and device
 *         01b: device writes and reads, reads and writes again soon
 *         10b: device writes and host soon reads _or_ host writes and device
 *              soon reads
 *         11b: same as 10b but with temporal re-use priority
 *
 * @target_type: 0 => a processor, 1 => processor container
 * @cache_reference_valid: indicates that the cache_reference parameter is valid
 * @cache_reference: Cache ID of the specific cache
 * @st_tag_out: Where to write the steering tag acquired from the _DSM method.
 *
 * Call the firmware _DSM method to get the steering tag an endpoint device can
 * use to target the cache of a the core on a PCIe write transaction.
 *
 * Return
 *        true: contents of *st_tag_out are valid
 *        false: contents of *st_tag_out are invalid
 */
static bool invoke_dsm(acpi_handle handle, u32 cpu_uid, u8 processor_hint,
		       u8 target_type, bool cache_reference_valid,
		       u64 cache_reference, union st_info *st_tag_out)
{
	void acpi_dump_obj(union acpi_object *);
	union acpi_object in_obj, in_buf[3], *out_obj;

	printk("FIXME:tagz:%s: cpu_uid: %d\n", __FUNCTION__, cpu_uid);
	in_buf[0].integer.type = ACPI_TYPE_INTEGER;
	in_buf[0].integer.value = 0; /* 0 => processor cache steering tags */

	in_buf[1].integer.type = ACPI_TYPE_INTEGER;
	in_buf[1].integer.value = cpu_uid;

	in_buf[2].integer.type = ACPI_TYPE_INTEGER;
	in_buf[2].integer.value = processor_hint & 3;
	in_buf[2].integer.value |= (target_type & 1) << 2;
	in_buf[2].integer.value |= (cache_reference_valid & 1) << 3;
	in_buf[2].integer.value |= (cache_reference << 32);

	in_obj.type = ACPI_TYPE_PACKAGE;
	in_obj.package.count = ARRAY_SIZE(in_buf);
	in_obj.package.elements = in_buf;

	out_obj = acpi_evaluate_dsm(handle,
				    &pci_acpi_dsm_guid, MINIMUM_DSM_REVISION,
				    DSM_STEERING_TAG_FUNCTION_INDEX, &in_obj);

	if (!out_obj) {
		pr_err("%s: acpi_evaluate_dsm() FAIL\n", __func__);
		return false;
	}

	printk("FIXME:%s acpi_evaluate_dsm():PASS: cpu_uid:%d\n",
		__FUNCTION__, cpu_uid);

	if (out_obj->type != ACPI_TYPE_BUFFER) {
		pr_err("%s: acpi_evaluate_dsm(): invalid return type %d\n",
		       __func__, out_obj->type);
		return false;
	}
	st_tag_out->value = *((u64 *)(out_obj->buffer.pointer));
	acpi_dump_obj(out_obj);

	printk("FIXME:tagret:valid(vt:%d, vxt:%d, pt:%d, pxt:%d)\n",
		st_tag_out->v_mem_t_valid, st_tag_out->v_mem_xt_valid,
		st_tag_out->p_mem_t_valid, st_tag_out->p_mem_xt_valid);
	printk("FIXME:tagret:tags(vt:%d, vxt:%d, pt:%d, pxt:%d)\n",
		st_tag_out->v_mem_t, st_tag_out->v_mem_xt,
		st_tag_out->p_mem_t, st_tag_out->p_mem_xt);
	ACPI_FREE(out_obj);

	return true;
}

static int tph_get_table_location(struct pci_dev *dev, u8 *tbl_loc_out)
{
	u32 tmp;
	int ret;

	/* check that device supports steering tags in msix */
	ret = tph_get_reg_field_u32(dev, TPH_CAP_REG_OFFSET,
				    TPH_CAP_ST_TABLE_LOCATION_MASK,
				    TPH_CAP_ST_TABLE_LOCATION_SHIFT, &tmp);
	if (ret)
		return ret;

	switch(tmp) {
	case TPH_TABLE_LOCATION_MSIX:
		printk("%s: table in msix memory\n", __FUNCTION__);
		break;
	case TPH_TABLE_LOCATION_EXTND_CAP_STRUCT:
		printk("%s: table in tph memory\n", __FUNCTION__);
		break;
	default:
		printk("%s: table in unknown location\n", __FUNCTION__);
		break;
	}

	*tbl_loc_out = tmp;
	return 0;
}

/*
 * Steering tags always occupy 16 bits but, if the device only supports,
 * 8 bit tags, the upper 8 bits are 0.
 */
static u16 tph_get_tag(struct pci_dev *dev, enum tph_mtype_tag tag_type,
		       enum tph_requester_enable req_enable,
		       union st_info *st_tag_out)
{
	switch (req_enable) {
	case TPH_REQ_TPH_ONLY: /* 8 bit tags */
		switch (tag_type) {
		case TPH_MTYPE_TAG_VRAM:
			if (st_tag_out->v_mem_t_valid)
				return st_tag_out->v_mem_t;
			WARN_ONCE(1, "v_mem_t not valid\n");
			break;
		case TPH_MTYPE_TAG_NVRAM:
			if (st_tag_out->p_mem_t_valid)
				return st_tag_out->p_mem_t;
			WARN_ONCE(1, "p_mem_t not valid\n");
			break;
		}
		break;
	case TPH_REQ_TPH_EXTENDED: /* 16 bit tags */
		switch (tag_type) {
		case TPH_MTYPE_TAG_VRAM:
			if (st_tag_out->v_mem_xt_valid)
				return st_tag_out->v_mem_xt;
			WARN_ONCE(1, "v_mem_xt not valid\n");
			break;
		case TPH_MTYPE_TAG_NVRAM:
			if (st_tag_out->p_mem_xt_valid)
				return st_tag_out->p_mem_xt;
			WARN_ONCE(1, "p_mem_xt not valid\n");
			break;
		}
		break;
	default:
		WARN_ONCE(1, "no valid tag found\n");
		return 0;
	}
	return 0;
}

static acpi_handle root_complex_acpi_handle(struct pci_dev *dev)
{
	struct pci_dev *root_port;

	root_port = pcie_find_root_port(dev);
	if (!root_port || !root_port->bus || !root_port->bus->bridge) {
		WARN_ONCE(1, "cannot find root port for pci_dev\n");
		return NULL;
	}

	return ACPI_HANDLE(root_port->bus->bridge);
}

/**
 * pcie_tph_set_stte() - set steering tag table entry
 * @dev: pci device
 * @msix_nr: ordinal number of msix interrupt.
 * @cpu: the acpi cpuuid.
 * @tag_type: vram, nvram
 * @req_enable: disable, tph, extended tph
 *
 * Return:
 *        true : success
 *        false: the error code (ex: -EINVAL)
 *
 * If can_set_stte() returns true, we know interrupt vector mode is
 * supported and the fact that we're calling this routine means we should
 * enable it. We disable TPH before updating the tag, update the tag
 * and enable TPH afterwards to avoid potential instability as
 * cautioned about in the "Implementation Note" "ST Table Programming"
 * in the PCI-E specification.
 */
bool pcie_tph_set_stte(struct pci_dev *dev, int msix_nr, int cpu,
		       enum tph_mtype_tag tag_type,
		       enum tph_requester_enable req_enable)
{
	union st_info st_tag_out;
	int offset;
	u16 tagval;
	int ret;
	u8 tbl_loc;

	printk("FIXME:TPH_STTE:%s: dev:%p, msix_nr:%d, cpu:%d\n",
	       __FUNCTION__, dev, msix_nr, cpu);

	if (!can_set_stte(dev, TPH_INTR_VEC_MODE, req_enable, msix_nr))
		return false;

	if (!dev->stte_req_enable)
		dev->stte_req_enable = req_enable;

	if (!invoke_dsm(root_complex_acpi_handle(dev), cpu, 0, 0, false, 0,
			&st_tag_out)) {
		WARN_ONCE(1, "_DSM did not return valid steering tag\n");
		return false; /* can't write a tag we don't have*/
	}

	tph_clr_ctrl_reg_en(dev); /* disable b4 updating tag*/

	tagval = tph_get_tag(dev, tag_type, req_enable, &st_tag_out);
	printk("FIXME:%s@%d: tagval = 0x%x\n", __FUNCTION__, __LINE__, tagval);

	ret = tph_get_table_location(dev, &tbl_loc);
	switch (tbl_loc) {
	case TPH_TABLE_LOCATION_MSIX:
		tph_write_tag_to_msix(dev, msix_nr, tagval);
		break;
	case TPH_TABLE_LOCATION_EXTND_CAP_STRUCT:
		offset = dev->tph_cap +
			 TPH_REQR_ST_TABLE_OFFSET + msix_nr * sizeof(u16);
		pci_write_config_word(dev, offset, tagval);
		break;
	default:
		WARN_ONCE(1, "Unable to write steering tag\n");
		return false;
	}
	/* select interrupt vector mode */
	tph_set_ctrl_reg_mode_sel(dev, TPH_INTR_VEC_MODE);
	tph_set_ctrl_reg_en(dev, req_enable);
	return true;
}
EXPORT_SYMBOL(pcie_tph_set_stte);

void acpi_dump_obj(union acpi_object *obj)
{
	if (obj->type == ACPI_TYPE_ANY) {
		printk("FIXME:%s: null package elt or reference\n",
		       __FUNCTION__);
		return;
	}
	switch (obj->type) {
	case ACPI_TYPE_BUFFER:
		printk("FIXME:%s: ACPI_TYPE_BUFFER, len: 0x%x, ptr: %p\n",
			__FUNCTION__, obj->buffer.length, obj->buffer.pointer);
		break;
	default:
		printk("FIXME:%s: un-elaborated ojb of type 0x%x\n",
			__FUNCTION__, obj->type);
		break;
	}
}
#endif
