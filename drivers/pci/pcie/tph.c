// SPDX-License-Identifier: GPL-2.0
/*
 * TPH (TLP Processing Hints) interface
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 * Author: Eric Van Tassell (Eric.VanTassell@amd.com)
 */

#include <uapi/linux/pci_regs.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/msi.h>

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
