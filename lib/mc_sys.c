/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2013 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#include <fsl_mc_sys.h>
#include <fsl_mc_cmd.h>

static int mc_status_to_error(enum mc_cmd_status status)
{
	switch (status) {
	case MC_CMD_STATUS_OK:
		return 0;
	case MC_CMD_STATUS_AUTH_ERR:
		return -EACCES; /* Token error */
	case MC_CMD_STATUS_NO_PRIVILEGE:
		return -EPERM; /* Permission denied */
	case MC_CMD_STATUS_DMA_ERR:
		return -EIO; /* Input/Output error */
	case MC_CMD_STATUS_CONFIG_ERR:
		return -EINVAL; /* Device not configured */
	case MC_CMD_STATUS_TIMEOUT:
		return -ETIMEDOUT; /* Operation timed out */
	case MC_CMD_STATUS_NO_RESOURCE:
		return -ENAVAIL; /* Resource temporarily unavailable */
	case MC_CMD_STATUS_NO_MEMORY:
		return -ENOMEM; /* Cannot allocate memory */
	case MC_CMD_STATUS_BUSY:
		return -EBUSY; /* Device busy */
	case MC_CMD_STATUS_UNSUPPORTED_OP:
		return -ENOTSUP; /* Operation not supported by device */
	case MC_CMD_STATUS_INVALID_STATE:
		return -ENODEV; /* Invalid device state */
	default:
		break;
	}

	/* Not expected to reach here */
	return -EINVAL;
}

int mc_send_command(struct fsl_mc_io *mc_io, struct mc_command *cmd)
{
	enum mc_cmd_status status;

	if (!mc_io || !mc_io->regs)
		return -EACCES;

	/* --- Call lock function here in case portal is shared --- */
	mc_write_command(mc_io->regs, cmd);

	/* Spin until status changes */
	do {
		status = MC_CMD_HDR_READ_STATUS(ioread64(mc_io->regs));

		/* --- Call wait function here to prevent blocking ---
		 * Change the loop condition accordingly to exit on timeout.
		 */
	} while (status == MC_CMD_STATUS_READY);

	/* Read the response back into the command buffer */
	mc_read_response(mc_io->regs, cmd);

	/* --- Call unlock function here in case portal is shared --- */

	return mc_status_to_error(status);
}

