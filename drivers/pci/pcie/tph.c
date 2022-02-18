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

void pcie_tph_init(struct pci_dev *dev)
{
	dev->tph_cap = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_TPH);
}
#endif
