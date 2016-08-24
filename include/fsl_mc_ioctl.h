/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2014 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#ifndef _FSL_MC_IOCTL_H_
#define _FSL_MC_IOCTL_H_

#include <linux/ioctl.h>
#include "fsl_mc_cmd.h"

#define RESTOOL_IOCTL_TYPE   'R'

#define RESTOOL_GET_ROOT_DPRC_INFO \
	_IOR(RESTOOL_IOCTL_TYPE, 0x1, uint32_t)

#define RESTOOL_SEND_MC_COMMAND \
	         _IOWR(RESTOOL_IOCTL_TYPE, 0xE0, struct mc_command)


#endif /* _FSL_MC_IOCTL_H_ */
