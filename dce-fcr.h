/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#ifndef __DCE_FCR_H
#define __DCE_FCR_H

#include "dce-private.h"

/* DCE hw requires FCR to be 64 byte aligned */
#define FCR_ALIGN	64

/* FCR: Flow Context Record */
struct fcr {
	u32 words[32]; /* Do not manipulate directly */
};

/*******************************************************************************
 *
 * fcr APIS
 *
 ******************************************************************************/
void fcr_clear(struct fcr *d);

/* Storage Profile Format and Data Placement Controls */
u32 fcr_get_ffdpc_hi(struct fcr *d);
u32 fcr_get_ffdpc_lo(struct fcr *d);

/* BP2 settings: buffer pool id, pool buffer size */
u32 fcr_get_bp2ac(struct fcr *d);
void fcr_set_bp2ac_bmt(struct fcr *d, int enable);
int fcr_get_bp2ac_bmt(struct fcr *d);
void fcr_set_bp2ac_bpid(struct fcr *d, u32 bpid);
u32 fcr_get_bp2ac_bpid(struct fcr *d);
void fcr_set_bp2ac_pbs(struct fcr *d, u32 pbs);
u32 fcr_get_bp2ac_pbs(struct fcr *d);

/* BP1 settings: buffer pool id, pool buffer size */
u32 fcr_get_bp1ac(struct fcr *d);
void fcr_set_bp1ac_bmt(struct fcr *d, int enable);
int fcr_get_bp1ac_bmt(struct fcr *d);
void fcr_set_bp1ac_bpid(struct fcr *d, u32 bpid);
u32 fcr_get_bp1ac_bpid(struct fcr *d);
void fcr_set_bp1ac_pbs(struct fcr *d, u32 pbs);
u32 fcr_get_bp1ac_pbs(struct fcr *d);

/* next_flc */
void fcr_set_next_flc(struct fcr *d, uint64_t addr);
uint64_t fcr_get_next_flc(struct fcr *d);

#endif
