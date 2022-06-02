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

#endif
