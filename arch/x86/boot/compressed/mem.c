// SPDX-License-Identifier: GPL-2.0-only

#include "../cpuflags.h"
#include "../string.h"
#include "error.h"
#include "tdx.h"
#include "sev.h"
#include <asm/shared/tdx.h>

/*
 * accept_memory() and process_unaccepted_memory() called from EFI stub which
 * runs before decompresser and its early_tdx_detect().
 *
 * Enumerate TDX directly from the early users.
 */
static bool early_is_tdx_guest(void)
{
	static bool once;
	static bool is_tdx;

	if (!IS_ENABLED(CONFIG_INTEL_TDX_GUEST))
		return false;

	if (!once) {
		u32 eax, sig[3];

		cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax,
			    &sig[0], &sig[2],  &sig[1]);
		is_tdx = !memcmp(TDX_IDENT, sig, sizeof(sig));
		once = true;
	}

	return is_tdx;
}

void arch_accept_memory(phys_addr_t start, phys_addr_t end)
{
	/* Platform-specific memory-acceptance call goes here */
	if (early_is_tdx_guest())
		tdx_accept_memory(start, end);
	else if (sev_snp_enabled())
		snp_accept_memory(start, end);
	else
		error("Cannot accept memory: unknown platform\n");
}
