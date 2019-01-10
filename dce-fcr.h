/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#ifndef __DCE_FCR_H
#define __DCE_FCR_H

#include "dce-private.h"

/* DCE hw requires Flow Context Record to be 64 byte aligned */
#define FCR_ALIGN	64
#define COMP_PENDING_OUTPUT_SZ 8202
#define DECOMP_PENDING_OUTPUT_SZ (24 * 1024)
#define PENDING_OUTPUT_ALIGN 64
#define COMP_HISTORY_SZ (4 * 1024)
#define DECOMP_HISTORY_SZ (32 * 1024)
#define HISTORY_ALIGN 64
#define DECOMP_CONTEXT_SZ 256
#define DECOMP_CONTEXT_ALIGN 64

/* FCR: Stateful/Stateless Compression/Decompression Flow Context Record. Note
 * only the first 64 bytes are needed for stateless */
#define STREAM_CONTEXT_RECORD_SZ 128

struct flow_context_record {
	/* Do not manipulate directly */
	u32 words[STREAM_CONTEXT_RECORD_SZ / sizeof(u32)];
};

/*******************************************************************************
 *
 * Flow Context Record APIS
 *
 ******************************************************************************/
void fcr_clear(struct flow_context_record *d);

/* Storage Profile Format and Data Placement Controls */
u32 fcr_get_ffdpc_hi(struct flow_context_record *d);
u32 fcr_get_ffdpc_lo(struct flow_context_record *d);

/* BP2 settings: buffer pool id, pool buffer size */
u32 fcr_get_bp2ac(struct flow_context_record *d);
void fcr_set_bp2ac_bmt(struct flow_context_record *d, int enable);
int fcr_get_bp2ac_bmt(struct flow_context_record *d);
void fcr_set_bp2ac_bpid(struct flow_context_record *d, u32 bpid);
u32 fcr_get_bp2ac_bpid(struct flow_context_record *d);
void fcr_set_bp2ac_pbs(struct flow_context_record *d, u32 pbs);
u32 fcr_get_bp2ac_pbs(struct flow_context_record *d);

/* BP1 settings: buffer pool id, pool buffer size */
u32 fcr_get_bp1ac(struct flow_context_record *d);
void fcr_set_bp1ac_bmt(struct flow_context_record *d, int enable);
int fcr_get_bp1ac_bmt(struct flow_context_record *d);
void fcr_set_bp1ac_bpid(struct flow_context_record *d, u32 bpid);
u32 fcr_get_bp1ac_bpid(struct flow_context_record *d);
void fcr_set_bp1ac_pbs(struct flow_context_record *d, u32 pbs);
u32 fcr_get_bp1ac_pbs(struct flow_context_record *d);

/* next_flc */
void fcr_set_next_flc(struct flow_context_record *d, uint64_t addr);
uint64_t fcr_get_next_flc(struct flow_context_record *d);

#endif
