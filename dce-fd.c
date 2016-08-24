/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#include <compat.h>
#include "dce-fd.h"
#include "dce-attr-encoder-decoder.h"

#define ATTR32(d) (&(d)->words[0])
#define ATTR32_1(d) (&(d)->words[16])

static struct dce_attr_code code_fd_addr_lo = DCE_CODE(0, 0, 32);
static struct dce_attr_code code_fd_addr_hi_17 = DCE_CODE(1, 0, 17);
static struct dce_attr_code code_fd_addr_hi_32 = DCE_CODE(1, 0, 17);
static struct dce_attr_code code_fd_sw_token = DCE_CODE(1, 17, 15);
static struct dce_attr_code code_fd_data_len_18 = DCE_CODE(2, 0, 18);
static struct dce_attr_code code_fd_data_len_32 = DCE_CODE(2, 0, 32);
static struct dce_attr_code code_fd_mem = DCE_CODE(2, 20, 12);
static struct dce_attr_code code_fd_bpid = DCE_CODE(3, 0, 14);
static struct dce_attr_code code_fd_ivp = DCE_CODE(3, 14, 1);
static struct dce_attr_code code_fd_bmt = DCE_CODE(3, 15, 1);
static struct dce_attr_code code_fd_offset = DCE_CODE(3, 16, 12);
static struct dce_attr_code code_fd_format = DCE_CODE(3, 28, 2);
static struct dce_attr_code code_fd_sl = DCE_CODE(3, 30, 1);
static struct dce_attr_code code_fd_frc = DCE_CODE(4, 0, 32);
static struct dce_attr_code code_fd_frc_status = DCE_CODE(4, 0, 8);
static struct dce_attr_code code_fd_err = DCE_CODE(5, 0, 8);
static struct dce_attr_code code_fd_va = DCE_CODE(5, 14, 1);
static struct dce_attr_code code_fd_cbmt = DCE_CODE(5, 15, 1);
static struct dce_attr_code code_fd_asal = DCE_CODE(5, 16, 4);
static struct dce_attr_code code_fd_ptv2 = DCE_CODE(5, 21, 1);
static struct dce_attr_code code_fd_ptv1 = DCE_CODE(5, 22, 1);
static struct dce_attr_code code_fd_pta = DCE_CODE(5, 23, 1);
static struct dce_attr_code code_fd_dropp = DCE_CODE(5, 24, 3);
static struct dce_attr_code code_fd_sc = DCE_CODE(5, 27, 1);
static struct dce_attr_code code_fd_dd = DCE_CODE(5, 28, 4);
static struct dce_attr_code code_fd_flc_lo = DCE_CODE(6, 0, 32);
static struct dce_attr_code code_fd_flc_hi = DCE_CODE(7, 0, 32);

/* Frame List Entry */
static struct dce_attr_code code_fle_sw_token = DCE_CODE(1, 17, 15);
static struct dce_attr_code code_fle_addr_lo = DCE_CODE(0, 0, 32);
static struct dce_attr_code code_fle_addr_hi_17 = DCE_CODE(1, 0, 17);
static struct dce_attr_code code_fle_addr_hi_32 = DCE_CODE(1, 0, 32);
static struct dce_attr_code code_fle_data_len_18 = DCE_CODE(2, 0, 18);
static struct dce_attr_code code_fle_data_len_32 = DCE_CODE(2, 0, 32);
static struct dce_attr_code code_fle_mem = DCE_CODE(2, 20, 12);
static struct dce_attr_code code_fle_bpid = DCE_CODE(3, 0, 14);
static struct dce_attr_code code_fle_ivp = DCE_CODE(3, 14, 1);
static struct dce_attr_code code_fle_bmt = DCE_CODE(3, 15, 1);
static struct dce_attr_code code_fle_offset = DCE_CODE(3, 16, 12);
static struct dce_attr_code code_fle_format = DCE_CODE(3, 28, 2);
static struct dce_attr_code code_fle_sl = DCE_CODE(3, 30, 1);
static struct dce_attr_code code_fle_final = DCE_CODE(3, 31, 1);
static struct dce_attr_code code_fle_frc = DCE_CODE(4, 0, 32);
static struct dce_attr_code code_fle_err = DCE_CODE(5, 0, 8);
static struct dce_attr_code code_fle_fd_compat_1 = DCE_CODE(5, 14, 1);
static struct dce_attr_code code_fle_cbmt = DCE_CODE(5, 15, 1);
static struct dce_attr_code code_fle_asal = DCE_CODE(5, 16, 4);
static struct dce_attr_code code_fle_ptv2 = DCE_CODE(5, 21, 1);
static struct dce_attr_code code_fle_ptv1 = DCE_CODE(5, 22, 1);
static struct dce_attr_code code_fle_pta = DCE_CODE(5, 23, 1);
static struct dce_attr_code code_fle_fd_compat_8 = DCE_CODE(5, 24, 8);
static struct dce_attr_code code_fle_flc_lo = DCE_CODE(6, 0, 32);
static struct dce_attr_code code_fle_flc_hi = DCE_CODE(7, 0, 32);

uint64_t fd_get_addr_64(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return ((uint64_t)dce_attr_code_decode(&code_fd_addr_hi_32,
			p) << 32) |
			(uint64_t)dce_attr_code_decode(&code_fd_addr_lo,
			p);
}
EXPORT_SYMBOL(fd_get_addr_64);

void fd_get_addr_49(const struct dpaa2_fd *d, u32 *hi, u32 *lo)
{
	const u32 *p = ATTR32(d);

	*hi = dce_attr_code_decode(&code_fd_addr_hi_17, p);
	*lo = dce_attr_code_decode(&code_fd_addr_lo, p);
}
EXPORT_SYMBOL(fd_get_addr_49);

void fd_get_addr_64_v2(const struct dpaa2_fd *d, u32 *hi, u32 *lo)
{
	const u32 *p = ATTR32(d);

	*hi = dce_attr_code_decode(&code_fd_addr_hi_32, p);
	*lo = dce_attr_code_decode(&code_fd_addr_lo, p);
}
EXPORT_SYMBOL(fd_get_addr_64_v2);

u32 fd_get_sw_token(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_sw_token, p);
}
EXPORT_SYMBOL(fd_get_sw_token);

u32 fd_get_data_len_18(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_data_len_18, p);
}
EXPORT_SYMBOL(fd_get_data_len_18);

u32 fd_get_data_len_32(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_data_len_32, p);
}
EXPORT_SYMBOL(fd_get_data_len_32);

u32 fd_get_mem(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_mem, p);
}
EXPORT_SYMBOL(fd_get_mem);

u32 fd_get_bpid(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_bpid, p);
}
EXPORT_SYMBOL(fd_get_bpid);

void fd_set_ivp(struct dpaa2_fd *d, bool bpid_invalid)
{
	u32 *p = ATTR32(d);

	dce_attr_code_encode(&code_fd_ivp, p, !!bpid_invalid);
}
EXPORT_SYMBOL(fd_set_ivp);

u32 fd_get_ivp(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_ivp, p);
}
EXPORT_SYMBOL(fd_get_ivp);

u32 fd_get_bmt(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_bmt, p);
}
EXPORT_SYMBOL(fd_get_bmt);

u32 fd_get_offset(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_offset, p);
}
EXPORT_SYMBOL(fd_get_offset);

u32 fd_get_frame_format(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_format, p);
}
EXPORT_SYMBOL(fd_get_frame_format);

u32 fd_get_sl(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_sl, p);
}
EXPORT_SYMBOL(fd_get_sl);

u32 fd_get_frc(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_frc, p);
}
EXPORT_SYMBOL(fd_get_frc);

u32 fd_get_frc_status(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_frc_status, p);
}
EXPORT_SYMBOL(fd_get_frc_status);

u32 fd_get_err(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_err, p);
}
EXPORT_SYMBOL(fd_get_err);

u32 fd_get_va(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_va, p);
}
EXPORT_SYMBOL(fd_get_va);

u32 fd_get_cbmt(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_cbmt, p);
}
EXPORT_SYMBOL(fd_get_cbmt);

u32 fd_get_asal(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_asal, p);
}
EXPORT_SYMBOL(fd_get_asal);

u32 fd_get_ptv2(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_ptv2, p);
}
EXPORT_SYMBOL(fd_get_ptv2);

u32 fd_get_ptv1(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_ptv1, p);
}
EXPORT_SYMBOL(fd_get_ptv1);

u32 fd_get_pta(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_pta, p);
}
EXPORT_SYMBOL(fd_get_pta);

u32 fd_get_dropp(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_dropp, p);
}
EXPORT_SYMBOL(fd_get_dropp);

u32 fd_get_sc(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_sc, p);
}
EXPORT_SYMBOL(fd_get_sc);

u32 fd_get_dd(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fd_dd, p);
}
EXPORT_SYMBOL(fd_get_dd);

void fd_set_flc_64(struct dpaa2_fd *d, uint64_t addr)
{
	u32 *p = ATTR32(d);

	dce_attr_code_encode_64(&code_fd_flc_lo, (uint64_t *)p, addr);
}
EXPORT_SYMBOL(fd_set_flc_64);

uint64_t fd_get_flc_64(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return ((uint64_t)dce_attr_code_decode(&code_fd_flc_hi,
			p) << 32) |
			(uint64_t)dce_attr_code_decode(&code_fd_flc_lo,
			p);
}
EXPORT_SYMBOL(fd_get_flc_64);

void pretty_print_fd(const struct dpaa2_fd *d)
{
	pr_info("FD is\n");
	pr_info("  ADDR = 0x%" PRIx64 "\n", fd_get_addr_64(d));
	if (fd_get_sl(d)) {
		pr_info("  DATA_LENGTH_18 = %u\n", fd_get_data_len_18(d));
		pr_info("  MEM = %u\n", fd_get_mem(d));

	} else {
		pr_info("  DATA_LENGTH_32 = %u\n", fd_get_data_len_32(d));
	}
	pr_info("  BPID = %u\n", fd_get_bpid(d));
	pr_info("  IVP = %u\n", fd_get_ivp(d));
	pr_info("  BMT = %u\n", fd_get_bmt(d));
	pr_info("  OFFSET = %u\n", fd_get_offset(d));
	pr_info("  FORMAT = %u\n", fd_get_frame_format(d));
	pr_info("  SL = %u\n", fd_get_sl(d));
	pr_info("  FRC = 0x%x\n", fd_get_frc(d));
	pr_info("  ERR = %u\n", fd_get_err(d));
	pr_info("  VA = %u\n", fd_get_va(d));
	pr_info("  CBMT = %u\n", fd_get_cbmt(d));
	pr_info("  ASAL = %u\n", fd_get_asal(d));
	pr_info("  PTV2 = %u\n", fd_get_ptv2(d));
	pr_info("  PTV1 = %u\n", fd_get_ptv1(d));
	pr_info("  PTA = %u\n", fd_get_pta(d));
	pr_info("  DROPP = %u\n", fd_get_dropp(d));
	pr_info("  SC = %u\n", fd_get_sc(d));
	pr_info("  DD = %u\n", fd_get_dd(d));
	pr_info("  FLC = 0x%" PRIx64 "\n", fd_get_flc_64(d));
}
EXPORT_SYMBOL(pretty_print_fd);

/* FLE */
uint64_t fle_attr_get_addr_64(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return ((uint64_t)dce_attr_code_decode(&code_fle_addr_hi_32,
			p) << 32) |
			(uint64_t)dce_attr_code_decode(&code_fle_addr_lo,
			p);
}
EXPORT_SYMBOL(fle_attr_get_addr_64);

u32 fle_attr_get_sw_token(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_sw_token, p);
}
EXPORT_SYMBOL(fle_attr_get_sw_token);

void fle_attr_get_addr_49(const struct dpaa2_fd *d,  u32 *hi, u32 *lo)
{
	const u32 *p = ATTR32(d);

	*hi = dce_attr_code_decode(&code_fle_addr_hi_17, p);
	*lo = dce_attr_code_decode(&code_fle_addr_lo, p);
}
EXPORT_SYMBOL(fle_attr_get_addr_49);

void fle_attr_get_addr_64_v2(const struct dpaa2_fd *d,  u32 *hi, u32 *lo)
{
	const u32 *p = ATTR32(d);

	*hi = dce_attr_code_decode(&code_fle_addr_hi_32, p);
	*lo = dce_attr_code_decode(&code_fle_addr_lo, p);
}
EXPORT_SYMBOL(fle_attr_get_addr_64_v2);

u32 fle_attr_get_data_len_18(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_data_len_18, p);
}
EXPORT_SYMBOL(fle_attr_get_data_len_18);

u32 fle_attr_get_data_len_32(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_data_len_32, p);
}
EXPORT_SYMBOL(fle_attr_get_data_len_32);

u32 fle_attr_get_mem(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_mem, p);
}
EXPORT_SYMBOL(fle_attr_get_mem);

u32 fle_attr_get_bpid(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_bpid, p);
}
EXPORT_SYMBOL(fle_attr_get_bpid);

u32 fle_attr_get_ivp(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_ivp, p);
}
EXPORT_SYMBOL(fle_attr_get_ivp);

u32 fle_attr_get_bmt(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_bmt, p);
}
EXPORT_SYMBOL(fle_attr_get_bmt);

u32 fle_attr_get_offset(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_offset, p);
}
EXPORT_SYMBOL(fle_attr_get_offset);

u32 fle_attr_get_frame_format(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_format, p);
}
EXPORT_SYMBOL(fle_attr_get_frame_format);

u32 fle_attr_get_sl(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_sl, p);
}
EXPORT_SYMBOL(fle_attr_get_sl);

u32 fle_attr_get_final(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_final, p);
}
EXPORT_SYMBOL(fle_attr_get_final);

u32 fle_attr_get_frc(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_frc, p);
}
EXPORT_SYMBOL(fle_attr_get_frc);

u32 fle_attr_get_err(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_err, p);
}
EXPORT_SYMBOL(fle_attr_get_err);

u32 fle_attr_get_fd_compat_1(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_fd_compat_1, p);
}
EXPORT_SYMBOL(fle_attr_get_fd_compat_1);

u32 fle_attr_get_cbmt(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_cbmt, p);
}
EXPORT_SYMBOL(fle_attr_get_cbmt);

u32 fle_attr_get_asal(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_asal, p);
}
EXPORT_SYMBOL(fle_attr_get_asal);

u32 fle_attr_get_ptv2(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_ptv2, p);
}
EXPORT_SYMBOL(fle_attr_get_ptv2);

u32 fle_attr_get_ptv1(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_ptv1, p);
}
EXPORT_SYMBOL(fle_attr_get_ptv1);

u32 fle_attr_get_pta(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_pta, p);
}
EXPORT_SYMBOL(fle_attr_get_pta);

u32 fle_attr_get_fd_compat_8(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return dce_attr_code_decode(&code_fle_fd_compat_8, p);
}
EXPORT_SYMBOL(fle_attr_get_fd_compat_8);

void fle_attr_set_flc_64(struct dpaa2_fd *d, uint64_t addr)
{
	const u32 *p = ATTR32(d);

	dce_attr_code_encode_64(&code_fle_flc_lo, (uint64_t *)p, addr);
}
EXPORT_SYMBOL(fle_attr_set_flc_64);

uint64_t fle_attr_get_flc_64(const struct dpaa2_fd *d)
{
	const u32 *p = ATTR32(d);

	return ((uint64_t)dce_attr_code_decode(&code_fle_flc_hi,
			p) << 32) |
			(uint64_t)dce_attr_code_decode(&code_fle_flc_lo,
			p);
}
EXPORT_SYMBOL(fle_attr_get_flc_64);

void pretty_print_fle(const struct dpaa2_fd *d)
{
	pr_info("  ADDR = 0x%" PRIx64 "\n", fle_attr_get_addr_64(d));
	if (fle_attr_get_sl(d)) {
		pr_info("  DATA_LENGTH_18 = %u\n", fle_attr_get_data_len_18(d));
		pr_info("  MEM = %u\n", fle_attr_get_mem(d));

	} else {
		pr_info("  DATA_LENGTH_32 = %u\n", fle_attr_get_data_len_32(d));
	}
	pr_info("  BPID = %u\n", fle_attr_get_bpid(d));
	pr_info("  IVP = %u\n", fle_attr_get_ivp(d));
	pr_info("  BMT = %u\n", fle_attr_get_bmt(d));
	pr_info("  OFFSET = %u\n", fle_attr_get_offset(d));
	pr_info("  FORMAT = %u\n", fle_attr_get_frame_format(d));
	pr_info("  SL = %u\n", fle_attr_get_sl(d));
	pr_info("  FINAL = %u\n", fle_attr_get_final(d));
	pr_info("  FRC = 0x%x\n", fle_attr_get_frc(d));
	pr_info("  ERR = %u\n", fle_attr_get_err(d));
	pr_info("  FD_COMPAT_1 = %u\n", fle_attr_get_fd_compat_1(d));
	pr_info("  CBMT = %u\n", fle_attr_get_cbmt(d));
	pr_info("  ASAL = %u\n", fle_attr_get_asal(d));
	pr_info("  PTV2 = %u\n", fle_attr_get_ptv2(d));
	pr_info("  PTV1 = %u\n", fle_attr_get_ptv1(d));
	pr_info("  PTA = %u\n", fle_attr_get_pta(d));
	pr_info("  FD_COMPAT_8 = %u\n", fle_attr_get_fd_compat_8(d));
	pr_info("  FLC = 0x%" PRIx64 "\n", fle_attr_get_flc_64(d));
}
EXPORT_SYMBOL(pretty_print_fle);

void pretty_print_fle_n(const struct dpaa2_fd *d, int n)
{
	int k;

	pr_info("\n");
	for (k = 0; k < n; k++) {
		pr_info("FL Entry %d\n", k);
		pretty_print_fle(d++);
	}
}
EXPORT_SYMBOL(pretty_print_fle_n);

