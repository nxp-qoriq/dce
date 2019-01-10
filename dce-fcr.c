/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#include "dce-fcr.h"
#include "dce-attr-encoder-decoder.h"

/* DCE_CODE (word_offset, lsb_offset, bit_width) */
static struct dce_attr_code code_ffdpc_lo = DCE_CODE(0, 0, 32);
static struct dce_attr_code code_ffdpc_hi = DCE_CODE(1, 0, 32);
static struct dce_attr_code code_bp2ac = DCE_CODE(2, 0, 32);
static struct dce_attr_code code_bp1ac = DCE_CODE(3, 0, 32);
static struct dce_attr_code code_bp2ac_bmt = DCE_CODE(2, 31, 1);
static struct dce_attr_code code_bp2ac_bpid = DCE_CODE(2, 16, 14);
static struct dce_attr_code code_bp2ac_pbs = DCE_CODE(2, 6, 10);
static struct dce_attr_code code_bp1ac_bmt = DCE_CODE(3, 31, 1);
static struct dce_attr_code code_bp1ac_bpid = DCE_CODE(3, 16, 14);
static struct dce_attr_code code_bp1ac_pbs = DCE_CODE(3, 6, 10);
static struct dce_attr_code code_next_flc_lo = DCE_CODE(4, 0, 32);
static struct dce_attr_code code_next_flc_hi = DCE_CODE(5, 0, 32);

/* Flow Context Record accessors */

void fcr_clear(struct flow_context_record *d)
{
	memset(d, 0, sizeof(*d));
}

u32 fcr_get_ffdpc_hi(struct flow_context_record *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_ffdpc_hi, cl);
}

u32 fcr_get_ffdpc_lo(struct flow_context_record *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_ffdpc_lo, cl);
}

u32 fcr_get_bp2ac(struct flow_context_record *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp2ac, cl);
}

u32 fcr_get_bp1ac(struct flow_context_record *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp1ac, cl);
}

void fcr_set_bp2ac_bmt(struct flow_context_record *d, int enable)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bp2ac_bmt, cl, !!enable);
}

int fcr_get_bp2ac_bmt(struct flow_context_record *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp2ac_bmt, cl);
}

void fcr_set_bp2ac_bpid(struct flow_context_record *d, u32 bpid)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bp2ac_bpid, cl, bpid);
}

u32 fcr_get_bp2ac_bpid(struct flow_context_record *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp2ac_bpid, cl);
}

void fcr_set_bp2ac_pbs(struct flow_context_record *d, u32 pbs)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bp2ac_pbs, cl, pbs);
}

u32 fcr_get_bp2ac_pbs(struct flow_context_record *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp2ac_pbs, cl);
}

void fcr_set_bp1ac_bmt(struct flow_context_record *d, int enable)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bp1ac_bmt, cl, !!enable);
}

int fcr_get_bp1ac_bmt(struct flow_context_record *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp1ac_bmt, cl);
}

void fcr_set_bp1ac_bpid(struct flow_context_record *d, u32 bpid)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bp1ac_bpid, cl, bpid);
}

u32 fcr_get_bp1ac_bpid(struct flow_context_record *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp1ac_bpid, cl);
}

void fcr_set_bp1ac_pbs(struct flow_context_record *d, u32 pbs)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_bp1ac_pbs, cl, pbs);
}

u32 fcr_get_bp1ac_pbs(struct flow_context_record *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_bp1ac_pbs, cl);
}

void fcr_set_next_flc(struct flow_context_record *d, uint64_t addr)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode_64(&code_next_flc_lo, (uint64_t *)cl, addr);
}

uint64_t fcr_get_next_flc(struct flow_context_record *d)
{
	const u32 *cl = dce_cl(d);

	return ((uint64_t)dce_attr_code_decode(&code_next_flc_hi, cl) << 32) |
		(uint64_t)dce_attr_code_decode(&code_next_flc_lo, cl);
}
