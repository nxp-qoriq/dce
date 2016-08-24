/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#include <compat.h>
#include "dce-fd-frc.h"
#include "dce.h"
#include "dce-attr-encoder-decoder.h"

/* DCE_CODE (word_offset, lsb_offset, bit_width) */

/* CMD field */
static struct dce_attr_code code_fd_frc_cmd = DCE_CODE(4, 29, 3);

/* NOP */
static struct dce_attr_code code_fd_frc_nop_token = DCE_CODE(4, 0, 29);

/* ICID Scope Flush */
static struct dce_attr_code code_fd_frc_icid_scope_token = DCE_CODE(4, 0, 29);

/* Context Invalidate */
static struct dce_attr_code code_fd_frc_cic_token = DCE_CODE(4, 0, 29);

/* FQID Scope Flush */
static struct dce_attr_code code_fd_frc_fqflush_token = DCE_CODE(4, 0, 29);

/* PROCESS Request */
static struct dce_attr_code code_fd_frc_scus = DCE_CODE(4, 8, 2);
static struct dce_attr_code code_fd_frc_usdc = DCE_CODE(4, 10, 1);
static struct dce_attr_code code_fd_frc_uspc = DCE_CODE(4, 11, 1);
static struct dce_attr_code code_fd_frc_uhc = DCE_CODE(4, 12, 1);
static struct dce_attr_code code_fd_frc_ce = DCE_CODE(4, 13, 2);
static struct dce_attr_code code_fd_frc_cf = DCE_CODE(4, 16, 2);
static struct dce_attr_code code_fd_frc_b64 = DCE_CODE(4, 18, 1);
static struct dce_attr_code code_fd_frc_rb = DCE_CODE(4, 19, 1);
static struct dce_attr_code code_fd_frc_initial = DCE_CODE(4, 20, 1);
static struct dce_attr_code code_fd_frc_recycle = DCE_CODE(4, 21, 1);
static struct dce_attr_code code_fd_frc_scrf = DCE_CODE(4, 22, 1);
static struct dce_attr_code code_fd_frc_z_flush = DCE_CODE(4, 23, 3);
static struct dce_attr_code code_fd_frc_sf = DCE_CODE(4, 28, 1);

/* PROCESS Response */
static struct dce_attr_code code_fd_frc_status = DCE_CODE(4, 0, 8);
static struct dce_attr_code code_fd_frc_stream_end = DCE_CODE(4, 15, 1);

void fd_frc_set_cmd(struct dpaa2_fd *d, enum dce_cmd cmd)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_cmd, cl, cmd);
}
EXPORT_SYMBOL(fd_frc_set_cmd);

enum dce_cmd fd_frc_get_cmd(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_cmd, cl);
}
EXPORT_SYMBOL(fd_frc_get_cmd);

void fd_frc_set_nop_token(struct dpaa2_fd *d, u32 token)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_nop_token, cl, token);

}
EXPORT_SYMBOL(fd_frc_set_nop_token);

u32 fd_frc_get_nop_token(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_nop_token, cl);
}
EXPORT_SYMBOL(fd_frc_get_nop_token);

void fd_frc_set_icid_scope_token(struct dpaa2_fd *d, u32 token)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_icid_scope_token, cl, token);
}
EXPORT_SYMBOL(fd_frc_set_icid_scope_token);

u32 fd_frc_get_icid_scope_token(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_icid_scope_token, cl);
}
EXPORT_SYMBOL(fd_frc_get_icid_scope_token);

void fd_frc_set_cic_token(struct dpaa2_fd *d, u32 token)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_cic_token, cl, token);
}
EXPORT_SYMBOL(fd_frc_set_cic_token);

u32 fd_frc_get_cic_token(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_cic_token, cl);
}
EXPORT_SYMBOL(fd_frc_get_cic_token);

void fd_frc_set_fqflush_token(struct dpaa2_fd *d, u32 token)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_fqflush_token, cl, token);
}
EXPORT_SYMBOL(fd_frc_set_fqflush_token);

u32 fd_frc_get_fqflush_token(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_fqflush_token, cl);
}
EXPORT_SYMBOL(fd_frc_get_fqflush_token);


enum dce_status fd_frc_get_status(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_status, cl);
}
EXPORT_SYMBOL(fd_frc_get_status);

void fd_frc_set_scus(struct dpaa2_fd *d, enum dce_scus scus)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_scus, cl, scus);
}
EXPORT_SYMBOL(fd_frc_set_scus);

enum dce_scus fd_frc_get_scus(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_scus, cl);
}
EXPORT_SYMBOL(fd_frc_get_scus);

void fd_frc_set_usdc(struct dpaa2_fd *d, int enable)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_usdc, cl, !!enable);
}
EXPORT_SYMBOL(fd_frc_set_usdc);

int fd_frc_get_usdc(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_usdc, cl);
}
EXPORT_SYMBOL(fd_frc_get_usdc);

void fd_frc_set_uspc(struct dpaa2_fd *d, int enable)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_uspc, cl, !!enable);
}
EXPORT_SYMBOL(fd_frc_set_uspc);

int fd_frc_get_uspc(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_uspc, cl);
}
EXPORT_SYMBOL(fd_frc_get_uspc);

void fd_frc_set_uhc(struct dpaa2_fd *d, int enable)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_uhc, cl, !!enable);
}
EXPORT_SYMBOL(fd_frc_set_uhc);

int fd_frc_get_uhc(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_uhc, cl);
}
EXPORT_SYMBOL(fd_frc_get_uhc);

void fd_frc_set_ce(struct dpaa2_fd *d, int compression_effort)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_ce, cl, compression_effort);
}
EXPORT_SYMBOL(fd_frc_set_ce);

int fd_frc_get_ce(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_ce, cl);
}
EXPORT_SYMBOL(fd_frc_get_ce);

void fd_frc_set_cf(struct dpaa2_fd *d, int compression_format)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_cf, cl, compression_format);
}
EXPORT_SYMBOL(fd_frc_set_cf);

int fd_frc_get_cf(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_cf, cl);
}
EXPORT_SYMBOL(fd_frc_get_cf);

void fd_frc_set_b64(struct dpaa2_fd *d, int enable)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_b64, cl, !!enable);
}
EXPORT_SYMBOL(fd_frc_set_b64);

int fd_frc_get_b64(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_b64, cl);
}
EXPORT_SYMBOL(fd_frc_get_b64);

void fd_frc_set_rb(struct dpaa2_fd *d, int enable)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_rb, cl, !!enable);
}
EXPORT_SYMBOL(fd_frc_set_rb);

int fd_frc_get_rb(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_rb, cl);
}
EXPORT_SYMBOL(fd_frc_get_rb);

void fd_frc_set_initial(struct dpaa2_fd *d, int enable)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_initial, cl, !!enable);
}
EXPORT_SYMBOL(fd_frc_set_initial);

int fd_frc_get_initial(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_initial, cl);
}
EXPORT_SYMBOL(fd_frc_get_initial);

void fd_frc_set_recycle(struct dpaa2_fd *d, int enable)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_recycle, cl, !!enable);
}
EXPORT_SYMBOL(fd_frc_set_recycle);

int fd_frc_get_recycle(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_recycle, cl);
}
EXPORT_SYMBOL(fd_frc_get_recycle);

void fd_frc_set_scrf(struct dpaa2_fd *d, int enable)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_scrf, cl, !!enable);
}
EXPORT_SYMBOL(fd_frc_set_scrf);

int fd_frc_get_scrf(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_scrf, cl);
}
EXPORT_SYMBOL(fd_frc_get_scrf);

void fd_frc_set_z_flush(struct dpaa2_fd *d, int flush)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_z_flush, cl, flush);
}
EXPORT_SYMBOL(fd_frc_set_z_flush);

int fd_frc_get_z_flush(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_z_flush, cl);
}
EXPORT_SYMBOL(fd_frc_get_z_flush);

void fd_frc_set_sf(struct dpaa2_fd *d, int enable)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_sf, cl, !!enable);
}
EXPORT_SYMBOL(fd_frc_set_sf);

int fd_frc_get_sf(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_sf, cl);
}
EXPORT_SYMBOL(fd_frc_get_sf);

void fd_frc_set_se(struct dpaa2_fd *d, int enable)
{
	u32 *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_stream_end, cl, !!enable);
}
EXPORT_SYMBOL(fd_frc_set_se);

int fd_frc_get_se(const struct dpaa2_fd *d)
{
	const u32 *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_stream_end, cl);
}
EXPORT_SYMBOL(fd_frc_get_se);


