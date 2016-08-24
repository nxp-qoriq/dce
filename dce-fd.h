/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#ifndef __DCE_FD_H
#define __DCE_FD_H

#include <linux/types.h>
#include <fsl_dpaa2_fd.h>

/* Frame Descriptor */
uint64_t fd_get_addr_64(const struct dpaa2_fd *d);
void fd_get_addr_49(const struct dpaa2_fd *d, u32 *hi, u32 *lo);
void fd_get_addr_64_v2(const struct dpaa2_fd *d, u32 *hi, u32 *lo);
u32 fd_get_sw_token(const struct dpaa2_fd *d);

u32 fd_get_data_len_18(const struct dpaa2_fd *d);
u32 fd_get_data_len_32(const struct dpaa2_fd *d);
u32 fd_get_mem(const struct dpaa2_fd *d);
u32 fd_get_bpid(const struct dpaa2_fd *d);
u32 fd_get_ivp(const struct dpaa2_fd *d);
u32 fd_get_bmt(const struct dpaa2_fd *d);
u32 fd_get_offset(const struct dpaa2_fd *d);
u32 fd_get_frame_format(const struct dpaa2_fd *d);
u32 fd_get_sl(const struct dpaa2_fd *d);
u32 fd_get_frc(const struct dpaa2_fd *d);
u32 fd_get_frc_status(const struct dpaa2_fd *d);
u32 fd_get_err(const struct dpaa2_fd *d);
u32 fd_get_va(const struct dpaa2_fd *d);
u32 fd_get_cbmt(const struct dpaa2_fd *d);
u32 fd_get_asal(const struct dpaa2_fd *d);
u32 fd_get_ptv2(const struct dpaa2_fd *d);
u32 fd_get_ptv1(const struct dpaa2_fd *d);
u32 fd_get_pta(const struct dpaa2_fd *d);
u32 fd_get_dropp(const struct dpaa2_fd *d);
u32 fd_get_sc(const struct dpaa2_fd *d);
u32 fd_get_dd(const struct dpaa2_fd *d);
void pretty_print_fd(const struct dpaa2_fd *d);

/* set methods */
void fd_set_flc_64(struct dpaa2_fd *d, uint64_t addr);
uint64_t fd_get_flc_64(const struct dpaa2_fd *d);
void fd_set_ivp(struct dpaa2_fd *d, bool bpid_invalid);


/*  Frame list entry (FLE) */
uint64_t fle_attr_get_addr_64(const struct dpaa2_fd *d);
void fle_attr_get_addr_49(const struct dpaa2_fd *d,  u32 *hi, u32 *lo);
void fle_attr_get_addr_64_v2(const struct dpaa2_fd *d,  u32 *hi, u32 *lo);
u32 fle_attr_get_sw_token(const struct dpaa2_fd *d);
u32 fle_attr_get_data_len_18(const struct dpaa2_fd *d);
u32 fle_attr_get_data_len_32(const struct dpaa2_fd *d);
u32 fle_attr_get_mem(const struct dpaa2_fd *d);
u32 fle_attr_get_bpid(const struct dpaa2_fd *d);
u32 fle_attr_get_ivp(const struct dpaa2_fd *d);
u32 fle_attr_get_bmt(const struct dpaa2_fd *d);
u32 fle_attr_get_offset(const struct dpaa2_fd *d);
u32 fle_attr_get_frame_format(const struct dpaa2_fd *d);
u32 fle_attr_get_sl(const struct dpaa2_fd *d);
u32 fle_attr_get_final(const struct dpaa2_fd *d);
u32 fle_attr_get_frc(const struct dpaa2_fd *d);
u32 fle_attr_get_err(const struct dpaa2_fd *d);
u32 fle_attr_get_fd_compat_1(const struct dpaa2_fd *d);
u32 fle_attr_get_cbmt(const struct dpaa2_fd *d);
u32 fle_attr_get_asal(const struct dpaa2_fd *d);
u32 fle_attr_get_ptv2(const struct dpaa2_fd *d);
u32 fle_attr_get_ptv1(const struct dpaa2_fd *d);
u32 fle_attr_get_pta(const struct dpaa2_fd *d);
u32 fle_attr_get_fd_compat_8(const struct dpaa2_fd *d);

void fle_attr_set_flc_64(struct dpaa2_fd *d, uint64_t addr);
uint64_t fle_attr_get_flc_64(const struct dpaa2_fd *d);
void fle_attr_get_flc_64_v2(const struct dpaa2_fd *d,  u32 *hi, u32 *lo);

void pretty_print_fle(const struct dpaa2_fd *d);
void pretty_print_fle_n(const struct dpaa2_fd *d, int n);

#endif
