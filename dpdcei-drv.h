/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#ifndef __DPDCEI_DRV_H
#define __DPDCEI_DRV_H

#include <compat.h>
#include <fsl_qbman_base.h>
#include <fsl_dpdcei.h>
#include <fsl_dpaa2_io.h>
#include <allocator.h>
#include "dce-fcr.h"

/* ls2088 1.0 DCE */
#define ERR010843_DCE_REV 0x0AF0020000000100LLU

/* ls2085 DCE */
#define ERR008704_DCE_REV 0x0AF0020000000000LLU

struct dpdcei {
	uint16_t token;
	struct dpdcei_attr attr;
	u32 rx_fqid;
	u32 tx_fqid;

	/* dpio services */
	struct dpaa2_io *dpio_p;
	struct dpaa2_io_notification_ctx notif_ctx_rx;
	struct dpaa2_io_store *rx_store;

	atomic_t frames_in_flight;

	/* hash index to flow */
	spinlock_t table_lock;
	size_t flow_table_size;
	void **flow_lookup_table;
};

struct dpdcei *dpdcei_setup(struct dpaa2_io *dpio, int dpdcei_id);
void dpdcei_cleanup(struct dpdcei *dpdcei);

struct flc_dma {
	void *virt;
	dma_addr_t phys;
	size_t len;
};

struct dce_flow {
	/* the callback to be invoked when the respose arrives */
	void (*cb)(struct dce_flow *, u32 cmd, const struct dpaa2_fd *fd);
	struct dpdcei *dpdcei;

	/* flow dma memory map to keep driver related resources */
	struct dma_mem mem;

	/* flow memory: both virtual and dma memory */
	struct flc_dma flc;
	atomic_t frames_in_flight;
	/* key used to lookup flow in flow table */
	u32 key;
};

/* This is a rough number used to preallocate a memory map for managing the flow
 * and related resources. 320 is the size of the packaging needed to send a
 * command to DCE. It includes things like the input fd, output fd and SCF
 * storage and the SCF buffer. The 5000 is the maximum number of frames possible
 * on real systems due to pfdr and sfdr memory size.
 * the size must be  0x1000 aligned.
 *
 * Ideally this layer should not care or know about
 * all of this, but passing this information down from the dce.h layer is ugly.
 * In the future the hope is to create a dynamic allocator of dma able memory
 * where the caller does not need to specify a specific map */
#define MAX_RESOURCE_IN_FLIGHT ((320 * 50000) & ~0xFFF)
int dce_flow_create(struct dpdcei *dpdcei, struct dce_flow *flow);
int dce_flow_destroy(struct dce_flow *flow);

int enqueue_fd(struct dce_flow *flow, struct dpaa2_fd *fd);
int enqueue_nop(struct dce_flow *flow);
int enqueue_cic(struct dce_flow *flow);

#endif
