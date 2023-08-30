// SPDX-License-Identifier: GPL-2.0-only
/*
 *  (c) 2005-2016 Advanced Micro Devices, Inc.
 *
 *  Written by Jacob Shin - AMD, Inc.
 *  Maintained by: Borislav Petkov <bp@alien8.de>
 */
#include <linux/bitfield.h>
#include <linux/interrupt.h>
#include <linux/notifier.h>
#include <linux/kobject.h>
#include <linux/percpu.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/string.h>
#include <linux/ras.h>

#include <asm/traps.h>
#include <asm/apic.h>
#include <asm/mce.h>
#include <asm/msr.h>
#include <asm/trace/irq_vectors.h>

#include "internal.h"

/* MCA_MISC register, up to 5 per MCA bank */
#define NR_BLOCKS			5
#define THRESHOLD_MAX			0xFFF
#define INT_TYPE_APIC     0x00020000
#define MASK_VALID_HI     0x80000000
#define MASK_CNTP_HI      0x40000000
#define MASK_LOCKED_HI    0x20000000
#define MASK_LVTOFF_HI    0x00F00000
#define MASK_COUNT_EN_HI  0x00080000
#define MASK_INT_TYPE_HI  0x00060000
#define MASK_OVERFLOW_HI  0x00010000
#define MASK_ERR_COUNT_HI 0x00000FFF
#define MISC_VALID			BIT_ULL(63)
#define MISC_CNTP			BIT_ULL(62)
#define MISC_LOCKED			BIT_ULL(61)
#define MISC_INTP			BIT_ULL(60)
#define MISC_THR_LVT_OFFSET		GENMASK_ULL(55, 52)
#define MISC_CNT_EN			BIT_ULL(51)
#define MISC_THR_INTR_TYPE		GENMASK_ULL(50, 49)
#define MISC_OVERFLOW			BIT_ULL(48)
#define MISC_ERRCNT			GENMASK_ULL(43, 32)

/* MCA Interrupt Configuration register, one per CPU */
#define MSR_MCA_INTR_CFG		0xC0000410
#define INTR_CFG_THR_LVT_OFFSET		GENMASK_ULL(15, 12)
#define INTR_CFG_DFR_LVT_OFFSET		GENMASK_ULL(7, 4)
#define INTR_CFG_LEGACY_DFR_INTR_TYPE	GENMASK_ULL(2, 1)
#define INTR_TYPE_APIC			0x1

/* Scalable MCA: */
#define MCI_IPID_MCATYPE	GENMASK_ULL(47, 44)
#define MCI_IPID_HWID		GENMASK_ULL(43, 32)
#define MCI_IPID_MCATYPE_OLD	0xFFFF0000
#define MCI_IPID_HWID_OLD	0xFFF

/* MCA_CONFIG register, one per MCA bank */
#define CFG_CE_INT_EN			BIT_ULL(40)
#define CFG_DFR_INT_TYPE		GENMASK_ULL(38, 37)
#define CFG_MCAX_EN			BIT_ULL(32)
#define CFG_CE_INT_PRESENT		BIT_ULL(10)
#define CFG_DFR_INT_SUPP		BIT_ULL(5)
#define CFG_DFR_LOG_SUPP		BIT_ULL(2)

static DEFINE_PER_CPU(mce_banks_t, mce_dfr_int_banks);

static const char * const th_names[] = {
	"load_store",
	"insn_fetch",
	"combined_unit",
	"decode_unit",
	"northbridge",
	"execution_unit",
};

static const char * const smca_umc_block_names[] = {
	"dram_ecc",
	"misc_umc"
};

#define HWID_MCATYPE(hwid, mcatype) (((hwid) << 16) | (mcatype))

struct smca_hwid {
	unsigned int bank_type;	/* Use with smca_bank_types for easy indexing. */
	u32 hwid_mcatype;	/* (hwid,mcatype) tuple */
};

struct smca_bank {
	const struct smca_hwid *hwid;
	u32 id;			/* Value of MCA_IPID[InstanceId]. */
	u8 sysfs_id;		/* Value used for sysfs name. */
};

static DEFINE_PER_CPU_READ_MOSTLY(struct smca_bank[MAX_NR_BANKS], smca_banks);
static DEFINE_PER_CPU_READ_MOSTLY(u8[N_SMCA_BANK_TYPES], smca_bank_counts);

static const char * const smca_names[] = {
	[SMCA_LS ... SMCA_LS_V2]	= "load_store",
	[SMCA_IF]			= "insn_fetch",
	[SMCA_L2_CACHE]			= "l2_cache",
	[SMCA_DE]			= "decode_unit",
	[SMCA_RESERVED]			= "reserved",
	[SMCA_EX]			= "execution_unit",
	[SMCA_FP]			= "floating_point",
	[SMCA_L3_CACHE]			= "l3_cache",
	[SMCA_CS ... SMCA_CS_V2]	= "coherent_slave",
	[SMCA_PIE]			= "pie",

	/* UMC v2 is separate because both of them can exist in a single system. */
	[SMCA_UMC]			= "umc",
	[SMCA_UMC_V2]			= "umc_v2",
	[SMCA_MA_LLC]			= "ma_llc",
	[SMCA_PB]			= "param_block",
	[SMCA_PSP ... SMCA_PSP_V2]	= "psp",
	[SMCA_SMU ... SMCA_SMU_V2]	= "smu",
	[SMCA_MP5]			= "mp5",
	[SMCA_MPDMA]			= "mpdma",
	[SMCA_NBIO]			= "nbio",
	[SMCA_PCIE ... SMCA_PCIE_V2]	= "pcie",
	[SMCA_XGMI_PCS]			= "xgmi_pcs",
	[SMCA_NBIF]			= "nbif",
	[SMCA_SHUB]			= "shub",
	[SMCA_SATA]			= "sata",
	[SMCA_USB]			= "usb",
	[SMCA_USR_DP]			= "usr_dp",
	[SMCA_USR_CP]			= "usr_cp",
	[SMCA_GMI_PCS]			= "gmi_pcs",
	[SMCA_XGMI_PHY]			= "xgmi_phy",
	[SMCA_WAFL_PHY]			= "wafl_phy",
	[SMCA_GMI_PHY]			= "gmi_phy",
};

static const char *smca_get_name(enum smca_bank_types t)
{
	if (t >= N_SMCA_BANK_TYPES)
		return NULL;

	return smca_names[t];
}

static enum smca_bank_types smca_get_bank_type_old(unsigned int cpu, unsigned int bank)
{
	struct smca_bank *b;

	if (bank >= MAX_NR_BANKS)
		return N_SMCA_BANK_TYPES;

	b = &per_cpu(smca_banks, cpu)[bank];
	if (!b->hwid)
		return N_SMCA_BANK_TYPES;

	return b->hwid->bank_type;
}

static const struct smca_hwid smca_hwid_mcatypes_old[] = {
	/* { bank_type, hwid_mcatype } */

	/* Reserved type */
	{ SMCA_RESERVED, HWID_MCATYPE(0x00, 0x0)	},

	/* ZN Core (HWID=0xB0) MCA types */
	{ SMCA_LS,	 HWID_MCATYPE(0xB0, 0x0)	},
	{ SMCA_LS_V2,	 HWID_MCATYPE(0xB0, 0x10)	},
	{ SMCA_IF,	 HWID_MCATYPE(0xB0, 0x1)	},
	{ SMCA_L2_CACHE, HWID_MCATYPE(0xB0, 0x2)	},
	{ SMCA_DE,	 HWID_MCATYPE(0xB0, 0x3)	},
	/* HWID 0xB0 MCATYPE 0x4 is Reserved */
	{ SMCA_EX,	 HWID_MCATYPE(0xB0, 0x5)	},
	{ SMCA_FP,	 HWID_MCATYPE(0xB0, 0x6)	},
	{ SMCA_L3_CACHE, HWID_MCATYPE(0xB0, 0x7)	},

	/* Data Fabric MCA types */
	{ SMCA_CS,	 HWID_MCATYPE(0x2E, 0x0)	},
	{ SMCA_PIE,	 HWID_MCATYPE(0x2E, 0x1)	},
	{ SMCA_CS_V2,	 HWID_MCATYPE(0x2E, 0x2)	},
	{ SMCA_MA_LLC,	 HWID_MCATYPE(0x2E, 0x4)	},

	/* Unified Memory Controller MCA type */
	{ SMCA_UMC,	 HWID_MCATYPE(0x96, 0x0)	},
	{ SMCA_UMC_V2,	 HWID_MCATYPE(0x96, 0x1)	},

	/* Parameter Block MCA type */
	{ SMCA_PB,	 HWID_MCATYPE(0x05, 0x0)	},

	/* Platform Security Processor MCA type */
	{ SMCA_PSP,	 HWID_MCATYPE(0xFF, 0x0)	},
	{ SMCA_PSP_V2,	 HWID_MCATYPE(0xFF, 0x1)	},

	/* System Management Unit MCA type */
	{ SMCA_SMU,	 HWID_MCATYPE(0x01, 0x0)	},
	{ SMCA_SMU_V2,	 HWID_MCATYPE(0x01, 0x1)	},

	/* Microprocessor 5 Unit MCA type */
	{ SMCA_MP5,	 HWID_MCATYPE(0x01, 0x2)	},

	/* MPDMA MCA type */
	{ SMCA_MPDMA,	 HWID_MCATYPE(0x01, 0x3)	},

	/* Northbridge IO Unit MCA type */
	{ SMCA_NBIO,	 HWID_MCATYPE(0x18, 0x0)	},

	/* PCI Express Unit MCA type */
	{ SMCA_PCIE,	 HWID_MCATYPE(0x46, 0x0)	},
	{ SMCA_PCIE_V2,	 HWID_MCATYPE(0x46, 0x1)	},

	{ SMCA_XGMI_PCS, HWID_MCATYPE(0x50, 0x0)	},
	{ SMCA_NBIF,	 HWID_MCATYPE(0x6C, 0x0)	},
	{ SMCA_SHUB,	 HWID_MCATYPE(0x80, 0x0)	},
	{ SMCA_SATA,	 HWID_MCATYPE(0xA8, 0x0)	},
	{ SMCA_USB,	 HWID_MCATYPE(0xAA, 0x0)	},
	{ SMCA_USR_DP,	 HWID_MCATYPE(0x170, 0x0)	},
	{ SMCA_USR_CP,	 HWID_MCATYPE(0x180, 0x0)	},
	{ SMCA_GMI_PCS,  HWID_MCATYPE(0x241, 0x0)	},
	{ SMCA_XGMI_PHY, HWID_MCATYPE(0x259, 0x0)	},
	{ SMCA_WAFL_PHY, HWID_MCATYPE(0x267, 0x0)	},
	{ SMCA_GMI_PHY,	 HWID_MCATYPE(0x269, 0x0)	},
};

/* Keep sorted first by HWID then by McaType. */
static const u32 smca_hwid_mcatypes[] = {
	/* Reserved type */
	[SMCA_RESERVED]		= HWID_MCATYPE(0x00, 0x0),

	/* System Management Unit MCA type */
	[SMCA_SMU]		= HWID_MCATYPE(0x01, 0x0),
	[SMCA_SMU_V2]		= HWID_MCATYPE(0x01, 0x1),

	/* Microprocessor 5 Unit MCA type */
	[SMCA_MP5]		= HWID_MCATYPE(0x01, 0x2),

	/* MPDMA MCA type */
	[SMCA_MPDMA]		= HWID_MCATYPE(0x01, 0x3),

	/* Parameter Block MCA type */
	[SMCA_PB]		= HWID_MCATYPE(0x05, 0x0),

	/* Northbridge IO Unit MCA type */
	[SMCA_NBIO]		= HWID_MCATYPE(0x18, 0x0),

	/* Data Fabric MCA types */
	[SMCA_CS]		= HWID_MCATYPE(0x2E, 0x0),
	[SMCA_PIE]		= HWID_MCATYPE(0x2E, 0x1),
	[SMCA_CS_V2]		= HWID_MCATYPE(0x2E, 0x2),

	/* PCI Express Unit MCA type */
	[SMCA_PCIE]		= HWID_MCATYPE(0x46, 0x0),
	[SMCA_PCIE_V2]		= HWID_MCATYPE(0x46, 0x1),

	[SMCA_XGMI_PCS]		= HWID_MCATYPE(0x50, 0x0),
	[SMCA_NBIF]		= HWID_MCATYPE(0x6C, 0x0),
	[SMCA_SHUB]		= HWID_MCATYPE(0x80, 0x0),

	/* Unified Memory Controller MCA type */
	[SMCA_UMC]		= HWID_MCATYPE(0x96, 0x0),
	[SMCA_UMC_V2]		= HWID_MCATYPE(0x96, 0x1),

	[SMCA_SATA]		= HWID_MCATYPE(0xA8, 0x0),
	[SMCA_USB]		= HWID_MCATYPE(0xAA, 0x0),

	/* ZN Core (HWID=0xB0) MCA types */
	[SMCA_LS]		= HWID_MCATYPE(0xB0, 0x0),
	[SMCA_IF]		= HWID_MCATYPE(0xB0, 0x1),
	[SMCA_L2_CACHE]		= HWID_MCATYPE(0xB0, 0x2),
	[SMCA_DE]		= HWID_MCATYPE(0xB0, 0x3),
	/* HWID 0xB0 MCATYPE 0x4 is Reserved */
	[SMCA_EX]		= HWID_MCATYPE(0xB0, 0x5),
	[SMCA_FP]		= HWID_MCATYPE(0xB0, 0x6),
	[SMCA_L3_CACHE]		= HWID_MCATYPE(0xB0, 0x7),
	[SMCA_LS_V2]		= HWID_MCATYPE(0xB0, 0x10),

	/* Platform Security Processor MCA type */
	[SMCA_PSP]		= HWID_MCATYPE(0xFF, 0x0),
	[SMCA_PSP_V2]		= HWID_MCATYPE(0xFF, 0x1),

	[SMCA_GMI_PCS]		= HWID_MCATYPE(0x241, 0x0),
	[SMCA_XGMI_PHY]		= HWID_MCATYPE(0x259, 0x0),
	[SMCA_WAFL_PHY]		= HWID_MCATYPE(0x267, 0x0),
	[SMCA_GMI_PHY]		= HWID_MCATYPE(0x269, 0x0),
};

enum smca_bank_types smca_get_bank_type(u64 ipid)
{
	enum smca_bank_types type;
	u32 hwid_mcatype = HWID_MCATYPE(FIELD_GET(MCI_IPID_HWID, ipid),
					FIELD_GET(MCI_IPID_MCATYPE, ipid));

	for (type = 0; type < ARRAY_SIZE(smca_hwid_mcatypes); type++) {
		if (hwid_mcatype == smca_hwid_mcatypes[type])
			return type;
	}

	return N_SMCA_BANK_TYPES;
}
EXPORT_SYMBOL_GPL(smca_get_bank_type);

/*
 * In SMCA enabled processors, we can have multiple banks for a given IP type.
 * So to define a unique name for each bank, we use a temp c-string to append
 * the MCA_IPID[InstanceId] to type's name in get_name().
 *
 * InstanceId is 32 bits which is 8 characters. Make sure MAX_MCATYPE_NAME_LEN
 * is greater than 8 plus 1 (for underscore) plus length of longest type name.
 */
#define MAX_MCATYPE_NAME_LEN	30
static char buf_mcatype[MAX_MCATYPE_NAME_LEN];

struct threshold_block {
	/* This block's number within its bank. */
	unsigned int		block;
	/* MCA bank number that contains this block. */
	unsigned int		bank;
	/* CPU which controls this block's MCA bank. */
	unsigned int		cpu;
	/* MCA_MISC MSR address for this block. */
	u32			address;
	/* Enable/Disable APIC interrupt. */
	bool			interrupt_enable;
	/* Bank can generate an interrupt. */
	bool			interrupt_capable;
	/* Value upon which threshold interrupt is generated. */
	u16			threshold_limit;
	/* sysfs object */
	struct kobject		kobj;
	/* List of threshold blocks within this block's MCA bank. */
	struct list_head	miscj;
	struct list_head	block_list;
};

struct threshold_bank {
	struct kobject		*kobj;
	struct threshold_block	*blocks;
	struct list_head	block_list;
};

static DEFINE_PER_CPU(struct threshold_bank **, threshold_banks);

/*
 * A list of the banks enabled on each logical CPU. Controls which respective
 * descriptors to initialize later in mce_threshold_create_device().
 */
static DEFINE_PER_CPU(u64, bank_map);

static void amd_threshold_interrupt(void);
static void amd_deferred_error_interrupt(void);

static void default_deferred_error_interrupt(void)
{
	pr_err("Unexpected deferred interrupt at vector %x\n", DEFERRED_ERROR_VECTOR);
}
void (*deferred_error_int_vector)(void) = default_deferred_error_interrupt;

static bool smca_ce_interrupt_enabled(u64 mca_config, u64 mca_intr_cfg)
{
	u8 offset = FIELD_GET(INTR_CFG_THR_LVT_OFFSET, mca_intr_cfg);

	if (setup_APIC_eilvt(offset, THRESHOLD_APIC_VECTOR, APIC_EILVT_MSG_FIX, 0))
		return false;

	mce_threshold_vector = amd_threshold_interrupt;
	return true;
}

/* SMCA sets the Deferred Error Interrupt type per bank. */
static void configure_smca_dfr(unsigned int bank, u64 *mca_config)
{
	/* Nothing to do if the bank doesn't support deferred error logging. */
	if (!FIELD_GET(CFG_DFR_LOG_SUPP, *mca_config))
		return;

	/* Nothing to do if the bank doesn't support setting the interrupt type. */
	if (!FIELD_GET(CFG_DFR_INT_SUPP, *mca_config))
		return;

	/*
	 * Nothing to do if the interrupt type is already set. Either it was set by
	 * the OS already. Or it was set by firmware, and the OS should leave it as-is.
	 */
	if (FIELD_GET(CFG_DFR_INT_TYPE, *mca_config))
		return;

	*mca_config |= FIELD_PREP(CFG_DFR_INT_TYPE, INTR_TYPE_APIC);
	set_bit(bank, (void *)this_cpu_ptr(&mce_dfr_int_banks));
}

/* Set appropriate bits in MCA_CONFIG. */
static void configure_smca(unsigned int bank, u64 mca_intr_cfg)
{
	u64 mca_config;

	if (!mce_flags.smca)
		return;

	if (rdmsrl_safe(MSR_AMD64_SMCA_MCx_CONFIG(bank), &mca_config))
		return;

	/*
	 * OS is required to set the MCAX enable bit to acknowledge that it is
	 * now using the new MSR ranges and new registers under each
	 * bank. It also means that the OS will configure deferred
	 * errors in the new MCA_CONFIG register. If the bit is not set,
	 * uncorrectable errors will cause a system panic.
	 */
	mca_config |= FIELD_PREP(CFG_MCAX_EN, 0x1);

	configure_smca_dfr(bank, &mca_config);

	if (FIELD_GET(CFG_CE_INT_PRESENT, mca_config) && smca_thr_handler_enabled(mca_intr_cfg))
		mca_config |= FIELD_PREP(CFG_CE_INT_EN, 0x1);

	wrmsrl(MSR_AMD64_SMCA_MCx_CONFIG(bank), mca_config);
}

static u32 get_block_address(unsigned int bank, unsigned int block)
{
	if (mce_flags.smca) {
		if (!block)
			return MSR_AMD64_SMCA_MCx_MISC(bank);

		return MSR_AMD64_SMCA_MCx_MISCy(bank, block - 1);
	}

	if (bank != 4)
		return mca_msr_reg(bank, MCA_MISC);

	/* Fall back to method we used for older processors: */
	switch (block) {
	case 0:
		return mca_msr_reg(bank, MCA_MISC);
	case 1:
		return 0xC0000408;
	case 2:
		return 0xC0000409;
	default:
		return 0;
	}
}

/*
 * These do the same thing (THRESHOLD_MAX - value), but it helps with code
 * clarity to have separate defines to go from "hw counter to limit" and vice
 * versa.
 */
#define get_limit(val)	(THRESHOLD_MAX - (val))
#define get_errcnt(val) (get_limit(val))

/*
 * The threshold limit may be set before OS by Firmware or other tools.
 * Do a sanity check for a limit of '0', but otherwise use the value saved
 * in the hardware at boot.
 */
static u16 get_boot_threshold_limit(u64 mca_misc)
{
	u16 limit = get_limit(FIELD_GET(MISC_ERRCNT, mca_misc));

	if (!limit)
		limit = THRESHOLD_MAX;

	return limit;
}

static bool threshold_interrupt_capable(unsigned int bank, u64 mca_misc)
{
	/* Legacy bank 4 supports APIC LVT interrupts implicitly since forever. */
	if (!mce_flags.smca && bank == 4)
		return true;

	return FIELD_GET(MISC_INTP, mca_misc);
}

static void configure_threshold_block(struct threshold_bank *thr_bank, unsigned int bank,
				      unsigned int block, u64 mca_intr_cfg)
{
	struct threshold_block *thr_block;
	u8 thr_offset;
	u64 mca_misc;
	u32 address;

	address = get_block_address(bank, block);
	if (!address)
		return;

	if (rdmsrl_safe(address, &mca_misc))
		return;

	if (!FIELD_GET(MISC_VALID, mca_misc))
		return;

	if (!FIELD_GET(MISC_CNTP, mca_misc))
		return;

	if (FIELD_GET(MISC_LOCKED, mca_misc))
		return;

	if (!threshold_interrupt_capable(bank, mca_misc))
		return;

	/*
	 * The same Threshold APIC LVT offset is used per Die (AMD Node).
	 *
	 * Legacy systems provide a field per bank, but it is the same value
	 * for all banks.
	 *
	 * SMCA systems provide a field per CPU. The legacy per-bank field is
	 * still available for backwards-compatibility, but it's redundant.
	 */
	if (mce_flags.smca)
		thr_offset = FIELD_GET(INTR_CFG_THR_LVT_OFFSET, mca_intr_cfg);
	else
		thr_offset = FIELD_GET(MISC_THR_LVT_OFFSET, mca_misc);

	if (setup_APIC_eilvt(thr_offset, THRESHOLD_APIC_VECTOR, APIC_EILVT_MSG_FIX, 0))
		return;

	/* Interrupt support is ready, so allocate memory now for the block. */
	thr_block = kzalloc(sizeof(*thr_block), GFP_KERNEL);
	if (!thr_block)
		return;

	thr_block->block		= block;
	thr_block->bank			= bank;
	thr_block->cpu			= smp_processor_id();
	thr_block->address		= address;
	thr_block->threshold_limit	= get_boot_threshold_limit(mca_misc);
	thr_block->interrupt_capable	= true;
	thr_block->interrupt_enable	= true;

	/* Update block list before enabling the interrupt in hardware. */
	INIT_LIST_HEAD(&thr_block->block_list);
	list_add(&thr_block->block_list, &thr_bank->block_list);

	/* Set the interrupt handler before enabling the interrupt in hardware. */
	mce_threshold_vector = amd_mca_interrupt;

	/* Clear and set the APIC Interrupt type. */
	mca_misc &= ~MISC_THR_INTR_TYPE;
	mca_misc |= FIELD_PREP(MISC_THR_INTR_TYPE, INTR_TYPE_APIC);

	/* Clear and set the threshold limit. */
	mca_misc &= ~MISC_ERRCNT;
	mca_misc |= FIELD_PREP(MISC_ERRCNT, get_errcnt(thr_block->threshold_limit));

	/* Clear the Overflow bit (just in case it was set at boot) and enable the error counter.*/
	mca_misc &= ~MISC_OVERFLOW;
	mca_misc |= FIELD_PREP(MISC_CNT_EN, 1);

	/*
	 * Hardware should be ready to send interrupts. However, the error counter won't
	 * start to increment until MCA initialization (MCA_CTL) is done.
	 */
	wrmsrl(thr_block->address, mca_misc);
}

/*
 * Don't enable thresholding banks for the following conditions:
 * - MC4_MISC thresholding is not supported on Family 0x15.
 * - Prevent possible spurious interrupts from the IF bank on Family 0x17
 *   Models 0x10-0x2F due to Erratum #1114.
 */
static bool quirky_bank(unsigned int bank)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;

	if (c->x86 == 0x15 && bank == 4)
		return true;

	if (c->x86 == 0x17 && (c->x86_model >= 0x10 && c->x86_model <= 0x2F) && bank == 1)
		return true;

	return false;
}

static bool configure_threshold_bank(struct threshold_bank **thr_banks, unsigned int bank,
				     u64 mca_intr_cfg)
{
	struct threshold_bank *thr_bank;
	unsigned int block;

	if (quirky_bank(bank))
		return false;

	if (!thr_banks)
		return false;

	/*
	 * Threshold bank is already allocated and configured. This may happen
	 * when running MCE vendor init during CPU resume/hotplug, etc.
	 */
	if (thr_banks[bank])
		return true;

	thr_bank = kzalloc(sizeof(*thr_bank), GFP_KERNEL);
	if (!thr_bank)
		return false;

	INIT_LIST_HEAD(&thr_bank->block_list);

	for (block = 0; block < NR_BLOCKS; block++)
		configure_threshold_block(thr_bank, bank, block, mca_intr_cfg);

	if (list_empty(&thr_bank->block_list)) {
		kfree(thr_bank);
		return false;
	}

	thr_banks[bank] = thr_bank;
	return true;
}

static void smca_configure_old(unsigned int bank, unsigned int cpu)
{
	u8 *bank_counts = this_cpu_ptr(smca_bank_counts);
	const struct smca_hwid *s_hwid;
	unsigned int i, hwid_mcatype;
	u32 high, low;

	if (rdmsr_safe(MSR_AMD64_SMCA_MCx_IPID(bank), &low, &high)) {
		pr_warn("Failed to read MCA_IPID for bank %d\n", bank);
		return;
	}

	hwid_mcatype = HWID_MCATYPE(high & MCI_IPID_HWID_OLD,
				    (high & MCI_IPID_MCATYPE_OLD) >> 16);

	for (i = 0; i < ARRAY_SIZE(smca_hwid_mcatypes_old); i++) {
		s_hwid = &smca_hwid_mcatypes_old[i];

		if (hwid_mcatype == s_hwid->hwid_mcatype) {
			this_cpu_ptr(smca_banks)[bank].hwid = s_hwid;
			this_cpu_ptr(smca_banks)[bank].id = low;
			this_cpu_ptr(smca_banks)[bank].sysfs_id = bank_counts[s_hwid->bank_type]++;
			break;
		}
	}
}

struct thresh_restart {
	struct threshold_block	*b;
	int			reset;
	int			set_lvt_off;
	int			lvt_off;
	u16			old_limit;
};

static const char *bank4_names(const struct threshold_block *b)
{
	switch (b->address) {
	/* MSR4_MISC0 */
	case 0x00000413:
		return "dram";

	case 0xc0000408:
		return "ht_links";

	case 0xc0000409:
		return "l3_cache";

	default:
		WARN(1, "Funny MSR: 0x%08x\n", b->address);
		return "";
	}
};


static bool lvt_interrupt_supported(unsigned int bank, u32 msr_high_bits)
{
	/*
	 * bank 4 supports APIC LVT interrupts implicitly since forever.
	 */
	if (bank == 4)
		return true;

	/*
	 * IntP: interrupt present; if this bit is set, the thresholding
	 * bank can generate APIC LVT interrupts
	 */
	return msr_high_bits & BIT(28);
}

static int lvt_off_valid(struct threshold_block *b, int apic, u32 lo, u32 hi)
{
	int msr = (hi & MASK_LVTOFF_HI) >> 20;

	if (apic < 0) {
		pr_err(FW_BUG "cpu %d, failed to setup threshold interrupt "
		       "for bank %d, block %d (MSR%08X=0x%x%08x)\n", b->cpu,
		       b->bank, b->block, b->address, hi, lo);
		return 0;
	}

	if (apic != msr) {
		/*
		 * On SMCA CPUs, LVT offset is programmed at a different MSR, and
		 * the BIOS provides the value. The original field where LVT offset
		 * was set is reserved. Return early here:
		 */
		if (mce_flags.smca)
			return 0;

		pr_err(FW_BUG "cpu %d, invalid threshold interrupt offset %d "
		       "for bank %d, block %d (MSR%08X=0x%x%08x)\n",
		       b->cpu, apic, b->bank, b->block, b->address, hi, lo);
		return 0;
	}

	return 1;
};

/* Reprogram MCx_MISC MSR behind this threshold bank. */
static void threshold_restart_bank(void *_tr)
{
	struct thresh_restart *tr = _tr;
	u32 hi, lo;

	/* sysfs write might race against an offline operation */
	if (!this_cpu_read(threshold_banks) && !tr->set_lvt_off)
		return;

	rdmsr(tr->b->address, lo, hi);

	if (tr->b->threshold_limit < (hi & THRESHOLD_MAX))
		tr->reset = 1;	/* limit cannot be lower than err count */

	if (tr->reset) {		/* reset err count and overflow bit */
		hi =
		    (hi & ~(MASK_ERR_COUNT_HI | MASK_OVERFLOW_HI)) |
		    (THRESHOLD_MAX - tr->b->threshold_limit);
	} else if (tr->old_limit) {	/* change limit w/o reset */
		int new_count = (hi & THRESHOLD_MAX) +
		    (tr->old_limit - tr->b->threshold_limit);

		hi = (hi & ~MASK_ERR_COUNT_HI) |
		    (new_count & THRESHOLD_MAX);
	}

	/* clear IntType */
	hi &= ~MASK_INT_TYPE_HI;

	if (!tr->b->interrupt_capable)
		goto done;

	if (tr->set_lvt_off) {
		if (lvt_off_valid(tr->b, tr->lvt_off, lo, hi)) {
			/* set new lvt offset */
			hi &= ~MASK_LVTOFF_HI;
			hi |= tr->lvt_off << 20;
		}
	}

	if (tr->b->interrupt_enable)
		hi |= INT_TYPE_APIC;

 done:

	hi |= MASK_COUNT_EN_HI;
	wrmsr(tr->b->address, lo, hi);
}

static void enable_deferred_error_interrupt(u64 mca_intr_cfg)
{
	u8 dfr_offset;

	if (!mca_intr_cfg)
		return;

	/*
	 * Trust the value from hardware.
	 * If there's a conflict, then setup_APIC_eilvt() will throw an error.
	 */
	dfr_offset = FIELD_GET(INTR_CFG_DFR_LVT_OFFSET, mca_intr_cfg);
	if (setup_APIC_eilvt(dfr_offset, DEFERRED_ERROR_VECTOR, APIC_EILVT_MSG_FIX, 0))
		return;

	deferred_error_int_vector = amd_deferred_error_interrupt;

	if (mce_flags.smca)
		return;

	mca_intr_cfg &= ~INTR_CFG_LEGACY_DFR_INTR_TYPE;
	mca_intr_cfg |= FIELD_PREP(INTR_CFG_LEGACY_DFR_INTR_TYPE, INTR_TYPE_APIC);

	wrmsrl(MSR_MCA_INTR_CFG, mca_intr_cfg);
}

bool amd_filter_mce(struct mce *m)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;

	/* See Family 17h Models 10h-2Fh Erratum #1114. */
	if (c->x86 == 0x17 &&
	    c->x86_model >= 0x10 && c->x86_model <= 0x2F &&
	    m->bank == 1 && XEC(m->status, 0x3f) == 10)
		return true;

	/* NB GART TLB error reporting is disabled by default. */
	if (c->x86 < 0x17) {
		if (m->bank == 4 && XEC(m->status, 0x1f) == 0x5)
			return true;
	}

	return false;
}

static u64 get_mca_intr_cfg(void)
{
	u64 mca_intr_cfg;

	if (!mce_flags.succor)
		return 0;

	if (rdmsrl_safe(MSR_MCA_INTR_CFG, &mca_intr_cfg))
		return 0;

	return mca_intr_cfg;
}

/* cpu init entry point, called from mce.c with preempt off */
void mce_amd_feature_init(struct cpuinfo_x86 *c)
{
	struct threshold_bank **thr_banks = this_cpu_read(threshold_banks);
	unsigned int num_banks = this_cpu_read(mce_num_banks);
	unsigned int bank, cpu = smp_processor_id();
	u64 mca_intr_cfg = get_mca_intr_cfg();
	bool thr_banks_enabled = false;

	enable_deferred_error_interrupt(mca_intr_cfg);

	if (!thr_banks)
		thr_banks = kcalloc(num_banks, sizeof(struct threshold_bank *), GFP_KERNEL);

	for (bank = 0; bank < num_banks; ++bank) {
		if (mce_flags.smca)
			smca_configure_old(bank, cpu);

		configure_smca(bank, mca_intr_cfg);
		thr_banks_enabled |= configure_threshold_bank(thr_banks, bank, mca_intr_cfg);
	}

	if (!thr_banks_enabled) {
		kfree(thr_banks);
		return;
	}

	this_cpu_write(threshold_banks, thr_banks);
}

/*
 * DRAM ECC errors are reported in the Northbridge (bank 4) with
 * Extended Error Code 8.
 */
static bool legacy_mce_is_memory_error(struct mce *m)
{
	return m->bank == 4 && XEC(m->status, 0x1f) == 8;
}

/*
 * DRAM ECC errors are reported in Unified Memory Controllers with
 * Extended Error Code 0.
 */
static bool smca_mce_is_memory_error(struct mce *m)
{
	enum smca_bank_types bank_type;

	if (XEC(m->status, 0x3f))
		return false;

	bank_type = smca_get_bank_type(m->ipid);

	return bank_type == SMCA_UMC || bank_type == SMCA_UMC_V2;
}

bool amd_mce_is_memory_error(struct mce *m)
{
	if (mce_flags.smca)
		return smca_mce_is_memory_error(m);
	else
		return legacy_mce_is_memory_error(m);
}

/*
 * AMD systems do not have an explicit indicator that the value in MCA_ADDR is
 * a system physical address. Therefore, individual cases need to be detected.
 * Future cases and checks will be added as needed.
 *
 * 1) General case
 *	a) Assume address is not usable.
 * 2) Poison errors
 *	a) Indicated by MCA_STATUS[43]: poison. Defined for all banks except legacy
 *	   northbridge (bank 4).
 *	b) Refers to poison consumption in the core. Does not include "no action",
 *	   "action optional", or "deferred" error severities.
 *	c) Will include a usable address so that immediate action can be taken.
 * 3) Northbridge DRAM ECC errors
 *	a) Reported in legacy bank 4 with extended error code (XEC) 8.
 *	b) MCA_STATUS[43] is *not* defined as poison in legacy bank 4. Therefore,
 *	   this bit should not be checked.
 * 4) SMCA UMC DRAM ECC errors
 * 	a) Reported in UMC-type banks with extended error code (XEC) 0.
 * 	b) MCA_ADDR must be translated to a usable value.
 * 	c) Return 'true' if translation services are available.
 */
bool amd_mce_usable_address(struct mce *m)
{
	/* Check special northbridge case 3) first. */
	if (!mce_flags.smca) {
		if (legacy_mce_is_memory_error(m))
			return true;
		else if (m->bank == 4)
			return false;
	}

	/* Check poison bit for all other bank types. */
	if (m->status & MCI_STATUS_POISON)
		return true;

	if (smca_mce_is_memory_error(m) && IS_REACHABLE(CONFIG_AMD_ATL))
		return true;

	/* Assume address is not usable for all others. */
	return false;
}

void amd_mce_get_phys_addr(struct mce_hw_err *err)
{
	unsigned long addr = err->m.addr;
	struct atl_err a_err;

	if (!amd_mce_usable_address(&err->m))
		return;

	if (!smca_mce_is_memory_error(&err->m))
		goto out;

	memset(&a_err, 0, sizeof(struct atl_err));

	a_err.addr = addr;
	a_err.ipid = err->m.ipid;
	a_err.cpu  = err->m.extcpu;

	addr = amd_convert_umc_mca_addr_to_sys_addr(&a_err);
	if (IS_ERR_VALUE(addr))
		return;
out:
	err->phys_addr = addr & MCI_ADDR_PHYSADDR;
}

DEFINE_IDTENTRY_SYSVEC(sysvec_deferred_error)
{
	trace_deferred_error_apic_entry(DEFERRED_ERROR_VECTOR);
	inc_irq_stat(irq_deferred_error_count);
	deferred_error_int_vector();
	trace_deferred_error_apic_exit(DEFERRED_ERROR_VECTOR);
	apic_eoi();
}

/*
 * We have three scenarios for checking for Deferred errors:
 *
 * 1) Non-SMCA systems check MCA_STATUS and log error if found.
 *    This is already handled in machine_check_poll().
 * 2) SMCA systems check MCA_STATUS. If error is found then log it and also
 *    clear MCA_DESTAT.
 * 3) SMCA systems check MCA_DESTAT, if error was not found in MCA_STATUS, and
 *    log it.
 */
static void handle_smca_dfr_error(struct mce_hw_err *err)
{
	struct mce_hw_err err_dfr;
	u64 mca_destat;

	/* Non-SMCA systems don't have MCA_DESTAT/MCA_DEADDR registers. */
	if (!mce_flags.smca)
		return;

	/* Clear MCA_DESTAT if the deferred error was logged from MCA_STATUS. */
	if (err->m.status & MCI_STATUS_DEFERRED)
		goto out;

	/* MCA_STATUS didn't have a deferred error, so check MCA_DESTAT for one. */
	mca_destat = mce_rdmsrl(MSR_AMD64_SMCA_MCx_DESTAT(err->m.bank));

	if (!(mca_destat & MCI_STATUS_VAL))
		return;

	/* Reuse the same data collected from machine_check_poll(). */
	memcpy(&err_dfr, err, sizeof(err_dfr));

	/* Save the MCA_DE{STAT,ADDR} values. */
	err_dfr.m.status = mca_destat;
	err_dfr.m.addr = mce_rdmsrl(MSR_AMD64_SMCA_MCx_DEADDR(err_dfr.m.bank));

	mce_log(&err_dfr);

out:
	wrmsrl(MSR_AMD64_SMCA_MCx_DESTAT(err->m.bank), 0);
}

static void reset_block(struct threshold_block *block)
{
	struct thresh_restart tr;
	u32 low = 0, high = 0;

	if (!block)
		return;

	if (rdmsr_safe(block->address, &low, &high))
		return;

	if (!(high & MASK_OVERFLOW_HI))
		return;

	/* Reset threshold block after logging error. */
	memset(&tr, 0, sizeof(tr));
	tr.b = block;
	threshold_restart_bank(&tr);
}

static void reset_thr_blocks(unsigned int bank)
{
	struct threshold_block *first_block = NULL, *block = NULL, *tmp = NULL;
	struct threshold_bank **bp = this_cpu_read(threshold_banks);

	/*
	 * Validate that the threshold bank has been initialized already. The
	 * handler is installed at boot time, but on a hotplug event the
	 * interrupt might fire before the data has been initialized.
	 */
	if (!bp || !bp[bank])
		return;

	first_block = bp[bank]->blocks;
	if (!first_block)
		return;

	/*
	 * The first block is also the head of the list. Check it first
	 * before iterating over the rest.
	 */
	reset_block(first_block);
	list_for_each_entry_safe(block, tmp, &first_block->miscj, miscj)
		reset_block(block);
}

/*
 * Threshold interrupt handler will service THRESHOLD_APIC_VECTOR. The interrupt
 * goes off when error_count reaches threshold_limit.
 */
static void amd_threshold_interrupt(void)
{
	/* Check all banks for now. This could be optimized in the future. */
	machine_check_poll(MCP_TIMESTAMP, this_cpu_ptr(&mce_poll_banks));
}

/*
 * Deferred error interrupt handler will service DEFERRED_ERROR_VECTOR. The interrupt
 * is triggered when a bank logs a deferred error.
 */
static void amd_deferred_error_interrupt(void)
{
	machine_check_poll(MCP_TIMESTAMP, this_cpu_ptr(&mce_dfr_int_banks));
}

void amd_handle_error(struct mce_hw_err *err)
{
	reset_thr_blocks(err->m.bank);
	handle_smca_dfr_error(err);
}

/*
 * Sysfs Interface
 */
#define to_block(k)	container_of(k, struct threshold_block, kobj)

static ssize_t threshold_limit_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%lu\n", (unsigned long)to_block(kobj)->threshold_limit);
}

static ssize_t threshold_limit_store(struct kobject *kobj, struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	struct threshold_block *b = to_block(kobj);
	struct thresh_restart tr;
	unsigned long new;

	if (kstrtoul(buf, 0, &new) < 0)
		return -EINVAL;

	if (new > THRESHOLD_MAX)
		new = THRESHOLD_MAX;
	if (new < 1)
		new = 1;

	memset(&tr, 0, sizeof(tr));
	tr.old_limit = b->threshold_limit;
	b->threshold_limit = new;
	tr.b = b;

	if (smp_call_function_single(b->cpu, threshold_restart_bank, &tr, 1))
		return -ENODEV;

	return count;
}

static ssize_t error_count_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct threshold_block *b = to_block(kobj);
	u32 lo, hi;

	/* CPU might be offline by now */
	if (rdmsr_on_cpu(b->cpu, b->address, &lo, &hi))
		return -ENODEV;

	return sprintf(buf, "%u\n", ((hi & THRESHOLD_MAX) -
				     (THRESHOLD_MAX - b->threshold_limit)));
}

static ssize_t interrupt_enable_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%lu\n", (unsigned long)to_block(kobj)->interrupt_enable);
}

static ssize_t interrupt_enable_store(struct kobject *kobj, struct kobj_attribute *attr,
				      const char *buf, size_t count)
{
	struct threshold_block *b = to_block(kobj);
	struct thresh_restart tr;
	unsigned long new;

	if (!b->interrupt_capable)
		return -EINVAL;

	if (kstrtoul(buf, 0, &new) < 0)
		return -EINVAL;

	b->interrupt_enable = !!new;

	memset(&tr, 0, sizeof(tr));
	tr.b		= b;

	if (smp_call_function_single(b->cpu, threshold_restart_bank, &tr, 1))
		return -ENODEV;

	return count;
}

static struct kobj_attribute threshold_limit	= __ATTR_RW(threshold_limit);
static struct kobj_attribute error_count	= __ATTR_RO(error_count);
static struct kobj_attribute interrupt_enable	= __ATTR_RW(interrupt_enable);

static struct attribute *threshold_block_attrs[] = {
	&threshold_limit.attr,
	&error_count.attr,
	&interrupt_enable.attr,
	NULL,
};

static umode_t threshold_block_is_visible(struct kobject *kobj, struct attribute *attr, int index)
{
	struct threshold_block *b = to_block(kobj);

	if (strcmp(attr->name, "interrupt_enable") || b->interrupt_capable)
		return attr->mode;

	return 0;
}

static const struct attribute_group threshold_block_group = {
	.attrs		= threshold_block_attrs,
	.is_visible	= threshold_block_is_visible,
};

static const struct attribute_group *threshold_block_groups[] = {
	&threshold_block_group,
	NULL,
};

static void threshold_block_release(struct kobject *kobj);

static const struct kobj_type threshold_ktype = {
	.sysfs_ops		= &kobj_sysfs_ops,
	.default_groups		= threshold_block_groups,
	.release		= threshold_block_release,
};

static const char *get_name(unsigned int cpu, unsigned int bank, struct threshold_block *b)
{
	enum smca_bank_types bank_type;

	if (!mce_flags.smca) {
		if (b && bank == 4)
			return bank4_names(b);

		return th_names[bank];
	}

	bank_type = smca_get_bank_type_old(cpu, bank);
	if (bank_type >= N_SMCA_BANK_TYPES)
		return NULL;

	if (b && (bank_type == SMCA_UMC || bank_type == SMCA_UMC_V2)) {
		if (b->block < ARRAY_SIZE(smca_umc_block_names))
			return smca_umc_block_names[b->block];
		return NULL;
	}

	if (per_cpu(smca_bank_counts, cpu)[bank_type] == 1)
		return smca_get_name(bank_type);

	snprintf(buf_mcatype, MAX_MCATYPE_NAME_LEN,
		 "%s_%u", smca_get_name(bank_type),
			  per_cpu(smca_banks, cpu)[bank].sysfs_id);
	return buf_mcatype;
}

static int allocate_threshold_blocks(unsigned int cpu, struct threshold_bank *tb,
				     unsigned int bank, unsigned int block,
				     u32 address)
{
	struct threshold_block *b = NULL;
	u32 low, high;
	int err;

	if ((bank >= this_cpu_read(mce_num_banks)) || (block >= NR_BLOCKS))
		return 0;

	if (rdmsr_safe(address, &low, &high))
		return 0;

	if (!(high & MASK_VALID_HI)) {
		if (block)
			goto recurse;
		else
			return 0;
	}

	if (!(high & MASK_CNTP_HI)  ||
	     (high & MASK_LOCKED_HI))
		goto recurse;

	b = kzalloc(sizeof(struct threshold_block), GFP_KERNEL);
	if (!b)
		return -ENOMEM;

	b->block		= block;
	b->bank			= bank;
	b->cpu			= cpu;
	b->address		= address;
	b->interrupt_enable	= 0;
	b->interrupt_capable	= lvt_interrupt_supported(bank, high);
	b->threshold_limit	= THRESHOLD_MAX;

	INIT_LIST_HEAD(&b->miscj);

	/* This is safe as @tb is not visible yet */
	if (tb->blocks)
		list_add(&b->miscj, &tb->blocks->miscj);
	else
		tb->blocks = b;

	err = kobject_init_and_add(&b->kobj, &threshold_ktype, tb->kobj, get_name(cpu, bank, b));
	if (err)
		goto out_free;
recurse:
	address = get_block_address(bank, ++block);
	if (!address)
		return 0;

	err = allocate_threshold_blocks(cpu, tb, bank, block, address);
	if (err)
		goto out_free;

	if (b)
		kobject_uevent(&b->kobj, KOBJ_ADD);

	return 0;

out_free:
	if (b) {
		list_del(&b->miscj);
		kobject_put(&b->kobj);
	}
	return err;
}

static int threshold_create_bank(struct threshold_bank **bp, unsigned int cpu,
				 unsigned int bank)
{
	struct device *dev = this_cpu_read(mce_device);
	struct threshold_bank *b = NULL;
	const char *name = get_name(cpu, bank, NULL);
	int err = 0;

	if (!dev)
		return -ENODEV;

	b = kzalloc(sizeof(struct threshold_bank), GFP_KERNEL);
	if (!b) {
		err = -ENOMEM;
		goto out;
	}

	/* Associate the bank with the per-CPU MCE device */
	b->kobj = kobject_create_and_add(name, &dev->kobj);
	if (!b->kobj) {
		err = -EINVAL;
		goto out_free;
	}

	err = allocate_threshold_blocks(cpu, b, bank, 0, mca_msr_reg(bank, MCA_MISC));
	if (err)
		goto out_kobj;

	bp[bank] = b;
	return 0;

out_kobj:
	kobject_put(b->kobj);
out_free:
	kfree(b);
out:
	return err;
}

static void threshold_block_release(struct kobject *kobj)
{
	kfree(to_block(kobj));
}

static void deallocate_threshold_blocks(struct threshold_bank *bank)
{
	struct threshold_block *pos, *tmp;

	list_for_each_entry_safe(pos, tmp, &bank->blocks->miscj, miscj) {
		list_del(&pos->miscj);
		kobject_put(&pos->kobj);
	}

	kobject_put(&bank->blocks->kobj);
}

static void threshold_remove_bank(struct threshold_bank *bank)
{
	if (!bank->blocks)
		goto out_free;

	deallocate_threshold_blocks(bank);

out_free:
	kobject_put(bank->kobj);
	kfree(bank);
}

static void __threshold_remove_device(struct threshold_bank **bp)
{
	unsigned int bank, numbanks = this_cpu_read(mce_num_banks);

	for (bank = 0; bank < numbanks; bank++) {
		if (!bp[bank])
			continue;

		threshold_remove_bank(bp[bank]);
		bp[bank] = NULL;
	}
	kfree(bp);
}

int mce_threshold_remove_device(unsigned int cpu)
{
	struct threshold_bank **bp = this_cpu_read(threshold_banks);

	if (!bp)
		return 0;

	/*
	 * Clear the pointer before cleaning up, so that the interrupt won't
	 * touch anything of this.
	 */
	this_cpu_write(threshold_banks, NULL);

	__threshold_remove_device(bp);
	return 0;
}

/**
 * mce_threshold_create_device - Create the per-CPU MCE threshold device
 * @cpu:	The plugged in CPU
 *
 * Create directories and files for all valid threshold banks.
 *
 * This is invoked from the CPU hotplug callback which was installed in
 * mcheck_init_device(). The invocation happens in context of the hotplug
 * thread running on @cpu.  The callback is invoked on all CPUs which are
 * online when the callback is installed or during a real hotplug event.
 */
int mce_threshold_create_device(unsigned int cpu)
{
	unsigned int numbanks, bank;
	struct threshold_bank **bp;
	int err;

	if (!this_cpu_read(bank_map))
		return 0;

	for (bank = 0; bank < numbanks; ++bank) {
		if (!(this_cpu_read(bank_map) & BIT_ULL(bank)))
			continue;
		err = threshold_create_bank(bp, cpu, bank);
		if (err) {
			__threshold_remove_device(bp);
			return err;
		}
	}

	return 0;
}
