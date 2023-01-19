// SPDX-License-Identifier: GPL-2.0
/*
 * TPH (TLP Processing Hints) interface
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 * Author: Eric Van Tassell (Eric.VanTassell@amd.com)
 */

#include <linux/acpi.h>
#include <uapi/linux/pci_regs.h>
#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/msi.h>
#include <linux/pci.h>
#include <linux/msi.h>
#include <linux/pci-acpi.h>

#ifdef CONFIG_PCIE_TPH

/*
 * Set one field of a PCI register at the offset given from the TPH capability
 * offset.
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
	if (ret)
		return ret;

	reg_val &= ~mask;
	reg_val |= (field_val << shift);

	ret = pci_write_config_dword(dev, dev->tph_cap + reg_offset,
				     reg_val);
	return ret;
}

/*
 * tph_get_reg_field_u32() - Read a field of the TPH register at reg_offset.
 * @dev: pci device
 * @reg_offset: the TPH register offset
 * @mask: the 32 bit mask of the field
 * @shift: the shift of the field (0 <= shift <32)
 * @out: where to write the field
 */
int tph_get_reg_field_u32(struct pci_dev *dev, u8 reg_offset, u32 mask,
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
EXPORT_SYMBOL(tph_get_reg_field_u32);

/* Return the number of ST Table entries that can be used */
static int tph_get_table_size(struct pci_dev *dev, u16 *sz_out)
{
	int ret;
	u32 tmp;

	ret = tph_get_reg_field_u32(dev, TPH_CAP_REG_OFFSET,
				    TPH_CAP_ST_TABLE_SIZE_MASK,
				    TPH_CAP_ST_TABLE_SIZE_SHIFT, &tmp);
	if (ret)
		return ret;

	*sz_out = (u16)tmp;
	return 0;
}

/*
 * for a given device and msi_index, return a  pointer to the msi_index(th)
 * MSI Table Entry in the device memory mapped for msix.
 */
static void __iomem *tph_msix_table_entry(struct pci_dev *dev,
					  __le16 msi_index)
{
	int ret;
	void *val;
	u16 tbl_sz;

	ret = tph_get_table_size(dev, &tbl_sz);
	if (ret || msi_index > tbl_sz)
		return NULL;
	val = dev->msix_base + msi_index * PCI_MSIX_ENTRY_SIZE;
	return val;
}

/*
 * Return a pointer to the vector control register at offset 0xc of
 * the msi_index(th) MSI Table Entry.
 */
void __iomem *tph_msix_vector_control(struct pci_dev *dev, __le16 msi_index)
{
	void __iomem *vec_ctrl_addr = tph_msix_table_entry(dev, msi_index);

	if (vec_ctrl_addr)
		vec_ctrl_addr += PCI_MSIX_ENTRY_VECTOR_CTRL;
	return vec_ctrl_addr;
}
EXPORT_SYMBOL(tph_msix_vector_control);

void pcie_tph_init(struct pci_dev *dev)
{
	dev->tph_cap = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_TPH);
}

/*
 * tph_clr_ctrl_reg_en -  Clear the TPH enable bit in the TPH control register
 * so that no PCI write transactions have TPH headers
 */
int pcie_tph_disable(struct pci_dev *dev)
{
	return  tph_set_reg_field_u32(dev, TPH_CTRL_REG_OFFSET, TPH_CTRL_REQ_EN_MASK,
				      TPH_CTRL_REQ_EN_SHIFT, TPH_REQ_DISABLE);
}

/*
 * tph_set_dev_nostmode - In the TPH Requester Control Register:
 *        - Set ST Mode Select to "No ST Mode" (0).
 *        - Set "TPH Requester Enable" to TPH only (1).
 */
int tph_set_dev_nostmode(struct pci_dev *dev)
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
 * translate from MSI-X interrupt index to msi_desc *
 */
static struct msi_desc *tph_msix_index_to_desc(struct pci_dev *dev, int index)
{
	struct msi_desc *entry;

	msi_lock_descs(&dev->dev);
	msi_for_each_desc(entry, &dev->dev, MSI_DESC_ASSOCIATED) {
		if (entry->msi_index == index)
			return entry;
	}
	msi_unlock_descs(&dev->dev);
	return NULL;
}

/*
 * Return true if the device's capability register indicates support for
 * Interrupt Vector Mode.
 */
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

static enum st_table_location tph_get_table_location(struct pci_dev *dev,
						     u8 *tbl_loc_out)
{
	u32 tmp;
	int ret;

	/* check that device supports steering tags in msix */
	ret = tph_get_reg_field_u32(dev, TPH_CAP_REG_OFFSET,
				    TPH_CAP_ST_TABLE_LOCATION_MASK,
				    TPH_CAP_ST_TABLE_LOCATION_SHIFT, &tmp);
	if (ret)
		return ret;

	*tbl_loc_out = (enum st_table_location)tmp;
	return 0;
}

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

#define MINIMUM_DSM_REVISION		7
#define DSM_STEERING_TAG_FUNCTION_INDEX	0xf

static bool invoke_dsm(acpi_handle handle, u32 cpu_uid, u8 processor_hint,
		       u8 target_type, bool cache_reference_valid,
		       u64 cache_reference, union st_info *st_tag_out)
{
	union acpi_object in_obj, in_buf[3], *out_obj;

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

	if (out_obj->type != ACPI_TYPE_BUFFER) {
		pr_err("%s: acpi_evaluate_dsm(): invalid return type %d\n",
		       __func__, out_obj->type);
		return false;
	}
	st_tag_out->value = *((u64 *)(out_obj->buffer.pointer));
	ACPI_FREE(out_obj);

	return true;
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

/*
 * Steering tags always occupy 16 bits but, if the device only supports,
 * 8 bit tags, the upper 8 bits are 0.
 */
static u16 tph_extract_tag(enum tph_mtype_tag tag_type,
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

/**
 * pcie_tph_read_steering_tag() - get steering tag table entry
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
static u16 pcie_tph_read_steering_tag(struct pci_dev *dev, unsigned int cpu,
				      enum tph_mtype_tag tag_type,
				      enum tph_requester_enable req_enable)
{
	union st_info st_tag_out;
	u16 tagval;

	if (!invoke_dsm(root_complex_acpi_handle(dev), cpu, 0, 0, false, 0,
			&st_tag_out)) {
		WARN_ONCE(1, "_DSM did not return valid steering tag\n");
		tagval = 0; /* 0 means "no steering" */
	} else {
		tagval = tph_extract_tag(tag_type, req_enable, &st_tag_out);
	}
	return tagval;
}

/*
 * return true if all of these are true
 *        - the device does advertise the TPH capability
 *        - the device does advertise the MSI-X capability
 *        - the TPH Capability Register indicates Interrupt Vector Mode support
 *        - the kernel command line argument to disable TPH has not been given
 *        - the kernel command line argument to enforce No ST Mode has not
 *          been given
 *        - the msix descriptor index is within the bounds of the msix table
 *        - the level of tph enablement requested by the device driver is
 *          supported by the root port completer
 *        - No ST Mode is supported
 *
 * In that case, setting a steering tag can be expected to behave correctly.
 */
static bool can_set_stte(struct pci_dev *dev,
			 enum tph_st_mode st_mode,
			 enum tph_requester_enable req_enable, int msix_nr)
{
	return false;
}

/*
 * tph_write_control_register() - write TPH control register value to hardware
 */
static int tph_write_control_register(struct pci_dev *dev,
				      u32 value)
{
	int ret;

	ret = tph_set_reg_field_u32(dev, TPH_CTRL_REG_OFFSET, ~0L, 0, value);

	if (ret)
		goto error_ret;

	return 0;

error_ret:
	/* Something went wrong. Minimize any possible harm by disabling TPH.*/
	pcie_tph_disable(dev);
	return ret;
}

/* update the ST Mode Select field of the TPH Control Register */
static int tph_set_ctrl_reg_mode_sel(struct pci_dev *dev,
				     enum tph_st_mode st_mode)
{
	return -EINVAL;
}

/*
 * Write the steering tag to the memory mapped vector control register.
 */
static void tph_write_tag_to_msix(struct pci_dev *dev, int msix_nr, u16 tagval)
{
}

/* update the TPH Requester Enable field of the TPH Control Register */
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

/**
 * pcie_tph_write_steering_tag - set steering tag table entry
 * @dev: pci device
 * @msix_nr: ordinal number of msix interrupt.
 * @tag_type: vram, nvram
 * @req_enable: disable, tph, extended tph
 * @tagval: the steering tag
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
static bool pcie_tph_write_steering_tag(struct pci_dev *dev,
					unsigned int msix_nr,
					enum tph_requester_enable req_enable,
					u16 tagval)
{
	int offset;
	u8  tbl_loc;
	int ret;

	if (!can_set_stte(dev, TPH_INTR_VEC_MODE, req_enable, msix_nr))
		return false;

	pcie_tph_disable(dev); /* disable b4 updating tag*/

	ret = tph_get_table_location(dev, &tbl_loc);
	if (ret)
		return false;

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
 * We disable TPH before updating the tag, update the tag
 * and enable TPH afterwards to avoid potential instability as
 * cautioned about in the "Implementation Note" "ST Table Programming"
 * in the PCI-E specification.
 *
 * FIXME: this comment belongs closer to action
 *
 */
bool pcie_tph_set_stte(struct pci_dev *dev, unsigned int msix_nr,
		       unsigned int cpu, enum tph_mtype_tag tag_type,
		       enum tph_requester_enable req_enable)
{
	u16 tagval;

	tagval = pcie_tph_read_steering_tag(dev, cpu, tag_type, req_enable);

	return pcie_tph_write_steering_tag(dev, msix_nr, req_enable, tagval);
}
EXPORT_SYMBOL(pcie_tph_set_stte);

/*
 * Return true if TPH Steering Tag Table in MSI-X memory (not TPH configuration
 * space.
 */
bool tph_is_st_table_in_msix(struct pci_dev *dev)
{
	u8  cap_tbl_loc;
	int ret;

	ret = tph_get_table_location(dev, &cap_tbl_loc);
	if (ret) {
		WARN_ON(ret);
		return false;
	}

	return cap_tbl_loc == TPH_TABLE_LOCATION_MSIX;
}
EXPORT_SYMBOL(tph_is_st_table_in_msix);

u16 tph_get_tag_from_msix_desc(struct pci_dev *dev, int index)
{
	struct msi_desc *msi_desc = NULL;
	void __iomem *vec_ctrl;
	u32 val = 0;

	msi_desc = tph_msix_index_to_desc(dev, index);
	if (msi_desc) {
		vec_ctrl =
			tph_msix_vector_control(dev, msi_desc->msi_index);
		val = readl(vec_ctrl);
		msi_unlock_descs(&dev->dev);
	}
	return val >> 16;
}
EXPORT_SYMBOL(tph_get_tag_from_msix_desc);

/*
 * Return true if device supports TPH, MSI-X, Interrupt Vector Mode and the
 * Steering Tag Table is in MSI-X memory.
 */
bool pcie_tph_msix_int_vec_capable(struct pci_dev *dev)
{
	if (dev->tph_cap && dev->msix_cap && tph_is_st_table_in_msix(dev) &&
	    int_vec_mode_supported(dev))
		return true;
	return false;
}
EXPORT_SYMBOL(pcie_tph_msix_int_vec_capable);

#endif
