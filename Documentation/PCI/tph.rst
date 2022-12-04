.. SPDX-License-Identifier: GPL-2.0

==============================
TPH Support
==============================

:Authors: - Eric van Tassell <eric.vantassell@amd.com>
          - Wei Huang <wei.huang2@amd.com>

In brief, an endpoint device driver using the TPH interface will:

   - To configure Interrupt Vector Mode use the pcie_tph_set_sttes()
     interface when setting up msi-x interrupts as shown below.

There are two kernel command line options available for control

   - "notph": All API functions will return and error and TPH will not
     be enabled for any endpoint.

    - "nostmode": TPH will be enabled but the ST Mode Select will be set
      to No ST Mode.

 usage example excerpted from drivers/net/ethernet/broadcom/bnxt/bnxt.c::
| for (i = 0, j = 0; i < bp->cp_nr_rings; i++) {
|   ...
|   rc = request_irq(irq->vector, irq->handler, flags, irq->name,
|                    bp->bnapi[i]);
|   ...
|  if (!pcie_tph_set_stte(bp->pdev, i, cpumask_first(irq->cpu_mask),
|                         TPH_MTYPE_TAG_VRAM, TPH_REQ_TPH_ONLY))
|          WARN_ONCE(1, "Error configuring steering tag\n");
|  ...
|  }
|  return rc;

.. kernel-doc:: drivers/pci/pcie/tph.c
   :export:

.. kernel-doc:: drivers/pci/pcie/tph.c
   :identifiers: pcie_tph_set_stte

