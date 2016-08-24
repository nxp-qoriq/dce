/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2013 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#include <fsl_mc_sys.h>
#include <fsl_mc_cmd.h>
#include <fsl_dpmng.h>
#include <fsl_dpmng_cmd.h>

int mc_get_version(struct fsl_mc_io *mc_io,
		   uint32_t cmd_flags,
		   struct mc_version *mc_ver_info)
{
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPMNG_CMDID_GET_VERSION,
					  cmd_flags,
					  0);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	DPMNG_RSP_GET_VERSION(cmd, mc_ver_info);

	return 0;
}

int mc_get_soc_version(struct fsl_mc_io *mc_io,
		   uint32_t cmd_flags,
		   struct mc_soc_version *mc_platform_info)
{
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPMNG_CMDID_GET_SOC_VERSION,
					  cmd_flags,
					  0);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	DPMNG_RSP_GET_SOC_VERSION(cmd, mc_platform_info);

	return 0;
}