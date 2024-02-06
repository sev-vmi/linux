// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Advanced Micro Devices, Inc.
 * Author: Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>
 */

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/iommu.h>
#include <linux/iommufd.h>
#include <linux/amd-viommu.h>
#include <uapi/linux/iommufd.h>
#include <uapi/linux/amd_viommu.h>

#include "iommufd_private.h"

union amd_viommu_ucmd_buffer {
	struct amd_viommu_iommu_info iommu;
	struct amd_viommu_dev_info dev;
	struct amd_viommu_mmio_data mmio;
};

#define IOCTL_OP(_ioctl, _fn, _struct, _last)                                  \
	[_IOC_NR(_ioctl) - IOMMUFD_VIOMMU_CMD_BASE] = {                        \
		.size = sizeof(_struct) +                                      \
			BUILD_BUG_ON_ZERO(sizeof(union amd_viommu_ucmd_buffer) <          \
					  sizeof(_struct)),                    \
		.min_size = offsetofend(_struct, _last),                       \
		.ioctl_num = _ioctl,                                           \
		.execute = _fn,                                                \
	}

int viommu_iommu_init(struct iommufd_ucmd *ucmd)
{
	int ret;
	struct amd_viommu_iommu_info *data = ucmd->cmd;

	ret = amd_viommu_iommu_init(data);
	if (ret)
		return ret;

	if (copy_to_user(ucmd->ubuffer, data, sizeof(*data)))
		ret = -EFAULT;
	return ret;
}

int viommu_iommu_destroy(struct iommufd_ucmd *ucmd)
{
	struct amd_viommu_iommu_info *data = ucmd->cmd;

	return amd_viommu_iommu_destroy(data);
}

int viommu_device_attach(struct iommufd_ucmd *ucmd)
{
	struct amd_viommu_dev_info *data = ucmd->cmd;

	return amd_viommu_device_update(data, true);
}

int viommu_device_detach(struct iommufd_ucmd *ucmd)
{
	struct amd_viommu_dev_info *data = ucmd->cmd;

	return amd_viommu_device_update(data, false);
}

int viommu_mmio_access(struct iommufd_ucmd *ucmd)
{
	int ret;
	struct amd_viommu_mmio_data *data = ucmd->cmd;

	if (data->is_write) {
		ret = amd_viommu_guest_mmio_write(data);
	} else {
		ret = amd_viommu_guest_mmio_read(data);
		if (ret)
			return ret;

		if (copy_to_user(ucmd->ubuffer, data, sizeof(*data)))
			ret = -EFAULT;
	}
	return ret;
}

int viommu_cmdbuf_update(struct iommufd_ucmd *ucmd)
{
	struct amd_viommu_cmdbuf_data *data = ucmd->cmd;

	return amd_viommu_cmdbuf_update(data);
}

struct iommufd_ioctl_op viommu_ioctl_ops[] = {
	IOCTL_OP(VIOMMU_IOMMU_INIT, viommu_iommu_init,
		 struct amd_viommu_iommu_info, gid),
	IOCTL_OP(VIOMMU_IOMMU_DESTROY, viommu_iommu_destroy,
		 struct amd_viommu_iommu_info, gid),
	IOCTL_OP(VIOMMU_DEVICE_ATTACH, viommu_device_attach,
		 struct amd_viommu_dev_info, queue_id),
	IOCTL_OP(VIOMMU_DEVICE_DETACH, viommu_device_detach,
		 struct amd_viommu_dev_info, queue_id),
	IOCTL_OP(VIOMMU_MMIO_ACCESS, viommu_mmio_access,
		 struct amd_viommu_mmio_data, is_write),
	IOCTL_OP(VIOMMU_CMDBUF_UPDATE, viommu_cmdbuf_update,
		 struct amd_viommu_cmdbuf_data, hva),
};

long iommufd_amd_viommu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct iommufd_ctx *ictx = filp->private_data;
	struct iommufd_ucmd ucmd = {};
	struct iommufd_ioctl_op *op;
	union amd_viommu_ucmd_buffer buf;
	unsigned int nr;
	int ret;

	nr = _IOC_NR(cmd);
	if (nr < IOMMUFD_VIOMMU_CMD_BASE ||
	    (nr - IOMMUFD_VIOMMU_CMD_BASE) >= ARRAY_SIZE(viommu_ioctl_ops))
		return -ENOIOCTLCMD;

	ucmd.ictx = ictx;
	ucmd.ubuffer = (void __user *)arg;
	ret = get_user(ucmd.user_size, (u32 __user *)ucmd.ubuffer);
	if (ret)
		return ret;

	op = &viommu_ioctl_ops[nr - IOMMUFD_VIOMMU_CMD_BASE];
	if (op->ioctl_num != cmd)
		return -ENOIOCTLCMD;
	if (ucmd.user_size < op->min_size)
		return -EOPNOTSUPP;

	ucmd.cmd = &buf;
	ret = copy_struct_from_user(ucmd.cmd, op->size, ucmd.ubuffer,
				    ucmd.user_size);
	if (ret)
		return ret;
	return op->execute(&ucmd);
}
