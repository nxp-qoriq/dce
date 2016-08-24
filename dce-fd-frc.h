/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#ifndef __DCE_FD_FRC_H
#define __DCE_FD_FRC_H

#include "dce-fd.h"
#include "dce-fd-frc.h"

enum dce_cmd {
	DCE_CMD_PROCESS			= 0,
	DCE_CMD_FQID_SCOPE_FLUSH	= 3,
	DCE_CMD_CTX_INVALIDATE		= 4,
	DCE_CMD_ICID_SCOPE_FLUSH	= 6,
	DCE_CMD_NOP			= 7
};

enum dce_scus {
	DCE_SCUS_NORMAL_MODE	= 0,
	DCE_SCUS_UPDATE		= 1,
	DCE_SCUS_UPDATE_DEBUG	= 2
};


#define CLEANUP_FRC 0x10000000

void fd_frc_set_cmd(struct dpaa2_fd *d, enum dce_cmd cmd);
enum dce_cmd fd_frc_get_cmd(const struct dpaa2_fd *d);

void fd_frc_set_nop_token(struct dpaa2_fd *d, u32 token);
u32 fd_frc_get_nop_token(const struct dpaa2_fd *d);

void fd_frc_set_icid_scope_token(struct dpaa2_fd *d, u32 token);
u32 fd_frc_get_icid_scope_token(const struct dpaa2_fd *d);

void fd_frc_set_cic_token(struct dpaa2_fd *d, u32 token);
u32 fd_frc_get_cic_token(const struct dpaa2_fd *d);

void fd_frc_set_fqflush_token(struct dpaa2_fd *d, u32 token);
u32 fd_frc_get_fqflush_token(const struct dpaa2_fd *d);

enum dce_status fd_frc_get_status(const struct dpaa2_fd *d);

void fd_frc_set_scus(struct dpaa2_fd *d, enum dce_scus scus);
enum dce_scus fd_frc_get_scus(const struct dpaa2_fd *d);

void fd_frc_set_usdc(struct dpaa2_fd *d, int enable);
int fd_frc_get_usdc(const struct dpaa2_fd *d);

void fd_frc_set_uspc(struct dpaa2_fd *d, int enable);
int fd_frc_get_uspc(const struct dpaa2_fd *d);

void fd_frc_set_uhc(struct dpaa2_fd *d, int enable);
int fd_frc_get_uhc(const struct dpaa2_fd *d);

void fd_frc_set_ce(struct dpaa2_fd *d, int compression_effort);
int fd_frc_get_ce(const struct dpaa2_fd *d);

void fd_frc_set_cf(struct dpaa2_fd *d, int compression_format);
int fd_frc_get_cf(const struct dpaa2_fd *d);

void fd_frc_set_b64(struct dpaa2_fd *d, int enable);
int fd_frc_get_b64(const struct dpaa2_fd *d);

void fd_frc_set_rb(struct dpaa2_fd *d, int enable);
int fd_frc_get_rb(const struct dpaa2_fd *d);

void fd_frc_set_initial(struct dpaa2_fd *d, int enable);
int fd_frc_get_initial(const struct dpaa2_fd *d);

void fd_frc_set_recycle(struct dpaa2_fd *d, int enable);
int fd_frc_get_recycle(const struct dpaa2_fd *d);

void fd_frc_set_scrf(struct dpaa2_fd *d, int enable);
int fd_frc_get_scrf(const struct dpaa2_fd *d);

void fd_frc_set_z_flush(struct dpaa2_fd *d, int flush);
int fd_frc_get_z_flush(const struct dpaa2_fd *d);

void fd_frc_set_sf(struct dpaa2_fd *d, int enable);
int fd_frc_get_sf(const struct dpaa2_fd *d);

void fd_frc_set_se(struct dpaa2_fd *d, int enable);
int fd_frc_get_se(const struct dpaa2_fd *d);

char *dce_status_string(enum dce_status);

#endif
