/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#include <linux/types.h>

#include <pthread.h>
#include <signal.h>
#include <sys/prctl.h>
#include <semaphore.h>
#include <compat.h>

#include <fsl_mc_cmd.h>
#include <fsl_mc_sys.h>
#include <fsl_dprc.h>
#include <fsl_dpdcei.h>
#include <fsl_dpdcei_cmd.h>
#include <fsl_qbman_base.h>
#include <vfio_utils.h>
#include <fsl_qbman_portal.h>
#include "dpdcei-drv.h"
#include "dce-private.h"
#include "dce-fd-frc.h"
#include "dce.h"

#define LDPAA_DCE_DESCRIPTION "Freescale LDPAA DCE Driver"

#define DQ_STORE_SIZE 8192

#define CONFIG_FSL_DCE_FLOW_LIMIT 65535

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Freescale Semiconductor, Inc");
MODULE_DESCRIPTION(LDPAA_DCE_DESCRIPTION);

static int setup_flow_lookup_table(struct dpdcei *dpdcei)
{
	dpdcei->flow_table_size = CONFIG_FSL_DCE_FLOW_LIMIT;
	dpdcei->flow_lookup_table = malloc((dpdcei->flow_table_size *
				sizeof(void *)));
	spin_lock_init(&dpdcei->table_lock);
	if (!dpdcei->flow_lookup_table)
		return -ENOMEM;
	memset(dpdcei->flow_lookup_table, 0,
			dpdcei->flow_table_size * sizeof(void *));
	return 0;
}

static int cleanup_flow_lookup_table(struct dpdcei *dpdcei)
{
	unsigned int i;

	spin_lock(&dpdcei->table_lock);
	for (i = 1; i < dpdcei->flow_table_size; i++) {
		if (dpdcei->flow_lookup_table[i] != NULL) {
			pr_err("Attempt to cleanup dpdcei that still has registered flows\n");
			spin_unlock(&dpdcei->table_lock);
			return -EBUSY;
		}
	}
	free(dpdcei->flow_lookup_table);
	dpdcei->flow_lookup_table = NULL;
	spin_unlock(&dpdcei->table_lock);
	return 0;
}

static int find_empty_flow_table_entry(u32 *entry, struct dce_flow *flow)
{
	u32 i;
	struct dpdcei *dpdcei = flow->dpdcei;

	spin_lock(&dpdcei->table_lock);
	for (i = 1; i < dpdcei->flow_table_size; i++) {
		if (dpdcei->flow_lookup_table[i] == NULL) {
			*entry = i;
			dpdcei->flow_lookup_table[i] = flow;
			spin_unlock(&dpdcei->table_lock);
			return 0;
		}
	}
	spin_unlock(&dpdcei->table_lock);
	return -ENOMEM;
}

static void clear_flow_table_entry(struct dce_flow *flow, u32 entry)
{
	struct dpdcei *dpdcei = flow->dpdcei;

	spin_lock(&dpdcei->table_lock);
	BUG_ON(entry >= dpdcei->flow_table_size);
	dpdcei->flow_lookup_table[entry] = NULL;
	spin_unlock(&dpdcei->table_lock);
}

int dce_flow_create(struct dpdcei *dpdcei, struct dce_flow *flow)
{
	int err;

	if (!dpdcei) {
		pr_err("Null dpdcei passed to %s\n", __func__);
		return -EINVAL;
	}

	/* associate flow to dpdcei */
	flow->dpdcei = dpdcei;

	/* Setup dma memory for the flow */
	flow->mem.addr = vfio_setup_dma(MAX_RESOURCE_IN_FLIGHT);
	if (!flow->mem.addr) {
		err = -ENOMEM;
		goto err_dma_mem_setup;
	}
	flow->mem.sz = MAX_RESOURCE_IN_FLIGHT;
	dma_mem_allocator_init(&flow->mem);

	flow->flc.len = sizeof(struct fcr);
	flow->flc.virt = dma_mem_memalign(&flow->mem, FCR_ALIGN,
					sizeof(struct fcr));
	if (!flow->flc.virt) {
		err = -ENOMEM;
		goto err_fcr_alloc;
	}

	err = find_empty_flow_table_entry(&flow->key, flow);
	if (err) {
		pr_err("DCE Hash table full\n");
		goto err_get_table_entry;
	}
	/* set the next_flc to myself, but virtual address */
	fcr_set_next_flc(flow->flc.virt, (uint64_t)flow);
	atomic_set(&flow->frames_in_flight, 0);

	return 0;

err_get_table_entry:
	dma_mem_free(&flow->mem, flow->flc.virt);
err_fcr_alloc:
	vfio_cleanup_dma(flow->mem.addr, flow->mem.sz);
err_dma_mem_setup:
	return err;
}
EXPORT_SYMBOL(dce_flow_create);

#include <err010843.h>
static DEFINE_SPINLOCK(err010843_lock);
static struct dpaa2_fd *err010843_fd;

int dce_flow_destroy(struct dce_flow *flow)
{
	int ret;
	bool scrf_old;

	scrf_old = fd_frc_get_scrf(err010843_fd);
	fd_frc_set_scrf(err010843_fd, true);
	ret = dpaa2_io_service_enqueue_fq(flow->dpdcei->dpio_p,
			flow->dpdcei->tx_fqid, err010843_fd);
	if (ret)
		pr_err("DCE flow cleanup context failed with error %d\n", ret);
	fd_frc_set_scrf(err010843_fd, scrf_old);
	/* FIXME: Should wait for callback using a semaphore */
	usleep(1000);

	flow->flc.phys = 0;
	flow->flc.len = 0;
	clear_flow_table_entry(flow, flow->key);
	dma_mem_free(&flow->mem, flow->flc.virt);
	flow->flc.virt = NULL;
	/*vfio_cleanup_dma(flow->mem.addr, flow->mem.sz);*/
	flow->mem.addr = NULL;
	return 0;
}
EXPORT_SYMBOL(dce_flow_destroy);

int enqueue_fd(struct dce_flow *flow, struct dpaa2_fd *fd)
{
	struct dpdcei *dpdcei = flow->dpdcei;
	enum dce_cmd cmd = fd_frc_get_cmd(fd);
	bool err010843 = false;
	int err = 0;

	/* set the FD[FLC] "flow context pointer" to input flow address */

	/* TODO: update what stashing control is added */
	fd_set_flc_64(fd, (dma_addr_t)flow->flc.virt);

	switch (cmd) {
	case DCE_CMD_NOP:
		fd_frc_set_nop_token(fd, flow->key);
		break;
	case DCE_CMD_CTX_INVALIDATE:
		fd_frc_set_cic_token(fd, flow->key);
		break;
	case DCE_CMD_PROCESS:
		/* Apply workaround frame iff this DCE has ERR010843, is doing
		 * decompression, and is running in stateful mode */
		err010843 = dpdcei->attr.dce_version <= ERR010843_DCE_REV &&
		   dpdcei->attr.engine == DPDCEI_ENGINE_DECOMPRESSION &&
		   fd_frc_get_sf(fd);
		if (err010843)
			spin_lock(&err010843_lock);
		break;
	default:
		pr_err("DCE: Unsupported dce command %d\n", cmd);
		BUG();
		return -EINVAL;
	}

	/* advance head now since consumer can be called during enqueue */
	atomic_inc(&dpdcei->frames_in_flight);
	atomic_inc(&flow->frames_in_flight);

	err = dpaa2_io_service_enqueue_fq(dpdcei->dpio_p, dpdcei->tx_fqid, fd);
	if (err < 0) {
		pr_err("DCE: error enqueueing Tx frame\n");
		atomic_dec(&dpdcei->frames_in_flight);
		atomic_dec(&flow->frames_in_flight);
	}

	if (err010843) {
		/* Insert workaround frame */
		err = dpaa2_io_service_enqueue_fq(dpdcei->dpio_p,
				dpdcei->tx_fqid, err010843_fd);
		spin_unlock(&err010843_lock);
	}

	return err;
}
EXPORT_SYMBOL(enqueue_fd);

int interrupt_count;

static int dpaa2_dce_pull_dequeue_rx(struct dpdcei *dpdcei)
{
	int is_last = 0;
	struct dpaa2_dq *dq;
	const struct dpaa2_fd *fd;
	struct dce_flow *flow = NULL;
	u32 key;
	int pull_count = 0;
	/* Empirically found limits that balance throughput with CPU overhead */
	int max_pulls = 1, max_pull_trys = 10;
	int err, i;

	do {
		/* Pull a batch of up to 16 frames into memory */
		for (i = 0, err = 1; i < max_pull_trys && err; i++)
			err = dpaa2_io_service_pull_fq(dpdcei->dpio_p,
					dpdcei->rx_fqid, dpdcei->rx_store);
		if (err) {
			pr_err("Failed to pull from fq %d. Err %d\n",
					dpdcei->rx_fqid, err);
			return -EIO;
		}
		pull_count++;
		do {
			enum dce_cmd cmd;

			/* Grab frame by frame from store */
			do {
				dq = dpaa2_io_store_next(dpdcei->rx_store, &is_last);
			} while (!is_last && !dq);
			/* is_last or dq is true */

			if (dq) { /* Valid dq was received */
				/* Obtain FD and process it */
				fd = dpaa2_dq_fd(dq);
				/* We are already CPU-affine, and since we
				 * aren't going to start more than one Rx thread
				 * per CPU, we're good enough for now */

				if (fd_frc_get_scrf(fd) ==
						CLEANUP_FRC)
					/* This is a cleanup frame */
					continue;

				if (err010843_fd &&
					dpaa2_fd_get_addr(err010843_fd) ==
						dpaa2_fd_get_addr(fd))
					/* Ignore workaround frame */
					continue;

				cmd = fd_frc_get_cmd(fd);
				switch (cmd) {
				case DCE_CMD_NOP:
					key = fd_frc_get_nop_token(fd);
					flow = dpdcei->flow_lookup_table[key];
					break;
				case DCE_CMD_CTX_INVALIDATE:
					continue;
					key = fd_frc_get_cic_token(fd);
					flow = dpdcei->flow_lookup_table[key];
					break;
				case DCE_CMD_FQID_SCOPE_FLUSH:
					continue;
				case DCE_CMD_PROCESS:
					/* No need for lookup in process. DCE
					 * sets the FLC field correctly in the
					 * outgoing frame based on the NEXT_FLC
					 * field programmed in the Flow Context
					 * Record*/
					flow = (struct dce_flow *)fd_get_flc_64(
							fd);
					break;

				default:
					pr_err("DCE: Unsupported DCE CMD %d\n", cmd);
				}
				atomic_dec(&dpdcei->frames_in_flight);
				atomic_dec(&flow->frames_in_flight);
				flow->cb(flow, cmd, fd);
				pull_count = 0;
			}
		} while (!is_last);
	} while (pull_count < max_pulls);
	interrupt_count++;
	/* max_pulls without seeing a frame. Rearm interrupt and sleep */
	return 0;
}

static void fqdan_cb_rx(struct dpaa2_io_notification_ctx *ctx)
{
	struct dpdcei *dpdcei = container_of(ctx, struct dpdcei,
						   notif_ctx_rx);

	dpaa2_dce_pull_dequeue_rx(dpdcei);
	dpaa2_io_service_rearm(dpdcei->dpio_p, ctx);
}

static int __cold dpdcei_dpio_service_setup(struct dpdcei *dpdcei)
{
	int err;

	/* Register notification callbacks */
	dpdcei->notif_ctx_rx.is_cdan = 0;
	dpdcei->notif_ctx_rx.desired_cpu = -1;
	dpdcei->notif_ctx_rx.cb = fqdan_cb_rx;
	dpdcei->notif_ctx_rx.id = dpdcei->rx_fqid;
	err = dpaa2_io_service_register(dpdcei->dpio_p, &dpdcei->notif_ctx_rx);
	if (err) {
		pr_err("Rx notif register failed 0x%x\n", err);
		return err;
	}
	return 0;
}

static int dpdcei_dpio_service_teardown(struct dpdcei *dpdcei)
{
	int err;

	/* Deregister notification callbacks */
	err = dpaa2_io_service_deregister(dpdcei->dpio_p,
						&dpdcei->notif_ctx_rx);
	if (err) {
		pr_err("dpdcei_dpio_service_teardown failed 0x%x\n", err);
		return err;
	}
	return 0;
}

static int dpdcei_bind_dpio(struct dpdcei *dpdcei,
				struct fsl_mc_io *mc_io, uint16_t dpdcei_handle)
{
	int err;
	struct dpdcei_rx_queue_cfg rx_queue_cfg;

	/* Configure the Tx queue to generate FQDANs */
	rx_queue_cfg.options = DPDCEI_QUEUE_OPT_USER_CTX |
				DPDCEI_QUEUE_OPT_DEST;
	rx_queue_cfg.user_ctx = dpdcei->notif_ctx_rx.qman64;
	rx_queue_cfg.dest_cfg.dest_type = DPDCEI_DEST_DPIO;
	rx_queue_cfg.dest_cfg.dest_id = dpdcei->notif_ctx_rx.dpio_id;
	/* TODO: dpio could have 2 or 8 WQ need to query dpio perhaps
	 *	hard code it to 1 for now */
	rx_queue_cfg.dest_cfg.priority = 0;
	err = dpdcei_set_rx_queue(mc_io, dpdcei_handle, dpdcei->token,
			&rx_queue_cfg);
	if (err) {
		pr_err("dpdcei_set_rx_flow() failed\n");
		return err;
	}

	return 0;
}

static int dpdcei_unbind_dpio(struct dpdcei *dpdcei,
				struct fsl_mc_io *mc_io,
				uint32_t cmd_flags)
{
	int err;

	err = dpdcei_open(mc_io, cmd_flags, dpdcei->attr.id,
				&dpdcei->token);
	if (err) {
		pr_err("%d from dpdcei_open() in %s\n", err, __func__);
		return err;
	}
	dpdcei->notif_ctx_rx.qman64 = 0;
	dpdcei->notif_ctx_rx.dpio_id = 0;

	return 0;
}

static int dpaa2_dce_alloc_store(struct dpdcei *dpdcei)
{
	dpdcei->rx_store = dpaa2_io_store_create(DQ_STORE_SIZE, NULL);
	if (!dpdcei->rx_store) {
		pr_err("dpaa2_io_store_create() failed\n");
		return -ENOMEM;
	}
	return 0;
}

static void dpaa2_dce_free_store(struct dpdcei *dpdcei)
{
	dpaa2_io_store_destroy(dpdcei->rx_store);
}

static void err010843_workaround_setup(uint64_t dce_version);

/**
 * dpdcei_setup() – setup a dpdcei object.
 *
 * Activates a dpdcei object corresponding to the given dpdcei_id
 * and registers it for notification on the given dpio
 *
 * Return a valid dpdcei object for success, or NULL for failure.
 */
struct dpdcei *dpdcei_setup(struct dpaa2_io *dpio, int dpdcei_id)
{
	struct fsl_mc_io *mc_io;
	struct dpdcei_rx_queue_attr rx_attr;
	struct dpdcei_tx_queue_attr tx_attr;
	struct dpdcei *dpdcei = NULL;
	uint32_t frame_count, byte_count;
	int err = 0;

	dpdcei = malloc(sizeof(struct dpdcei));
	if (!dpdcei) {
		pr_err("Unable to allocate memory for dpdcei setup\n");
		goto fail_dpdcei_malloc;
	}
	memset(dpdcei, 0, sizeof(*dpdcei));

	mc_io = malloc(sizeof(struct fsl_mc_io));
	if (!mc_io) {
		pr_err("Unable to allocate memory for mc_io in %s\n", __func__);
		goto err_mc_io_alloc;
	}
	err = mc_io_init(mc_io);
	if (err) {
		pr_err("%d received from mc_io_init() in %s\n", err, __func__);
		goto err_mc_io_init;
	}

	/* initialize lookup table */
	err = setup_flow_lookup_table(dpdcei);
	if (err) {
		pr_err("%d received from setup_flow_lookup_table() in %s\n",
				err, __func__);
		goto err_setup_flow_lookup;
	}

	/* in flight counter initialization */
	atomic_set(&dpdcei->frames_in_flight, 0);

	/* get a handle for the DPDCEI this interface is associated with */
	err = dpdcei_open(mc_io, MC_CMD_FLAG_PRI, dpdcei_id, &dpdcei->token);
	if (err) {
		pr_err("DCE: dpdcei_open() failed\n");
		goto err_dpdcei_open;
	}

	err = dpdcei_reset(mc_io, MC_CMD_FLAG_PRI, dpdcei->token);
	if (err) {
		pr_err("%d received from dpdcei_reset in %s\n", err, __func__);
		goto err_dpdcei_open;
	}

	vfio_force_rescan();

	err = dpdcei_get_attributes(mc_io, MC_CMD_FLAG_PRI, dpdcei->token,
				&dpdcei->attr);
	if (err) {
		pr_err("DCE: dpdcei_get_attributes() failed %d\n", err);
		goto err_dpdcei_get_attr;
	}

	memset(&rx_attr, 0, sizeof(rx_attr));
	memset(&tx_attr, 0, sizeof(tx_attr));

	err = dpdcei_get_rx_queue(mc_io, MC_CMD_FLAG_PRI, dpdcei->token,
			&rx_attr);
	if (err) {
		pr_err("DCE: dpdcei_get_rx_queue() failed %d\n", err);
		goto err_dpdcei_get_attr;
	}

	dpdcei->rx_fqid = rx_attr.fqid;

	err = dpdcei_get_tx_queue(mc_io, MC_CMD_FLAG_PRI, dpdcei->token,
			&tx_attr);
	if (err) {
		pr_err("DCE: dpdcei_get_rx_queue() failed %d\n", err);
		goto err_dpdcei_get_attr;
	}
	dpdcei->tx_fqid = tx_attr.fqid;

	/* DPIO related setup */
	dpdcei->dpio_p = dpio;

	/* dpio store */
	err = dpaa2_dce_alloc_store(dpdcei);
	if (err)
		goto err_alloc_store;

	/* dpio services */
	err = dpdcei_dpio_service_setup(dpdcei);
	if (err)
		goto err_dpio_service_setup;

	/* Check dpdcei TX and RX FQs are reset correctly */
	dpaa2_io_query_fq_count(dpio, dpdcei->tx_fqid,
			&frame_count, &byte_count);
	if (frame_count > 0)
		pr_err("Unexpected, %u frames on TX (to DCE) queue fqid %d\n",
				frame_count, dpdcei->tx_fqid);
	dpaa2_io_query_fq_count(dpio, dpdcei->rx_fqid,
			&frame_count, &byte_count);
	if (frame_count > 0)
		pr_err("Unexpected, %u frames on RX (from DCE) queue fqid %d\n",
				frame_count, dpdcei->rx_fqid);

	assert(dpdcei->notif_ctx_rx.dpio_id == dpio->dpio_desc.dpio_id);

	/* DPDCEI binding to DPIO */
	err = dpdcei_bind_dpio(dpdcei, mc_io, dpdcei->token);
	if (err) {
		pr_err("DCE: Error dpdcei bind %d\n", err);
		goto err_dpdcei_bind;
	}

	/* Enable the dpdcei */
	err = dpdcei_enable(mc_io, MC_CMD_FLAG_PRI, dpdcei->token);
	if (err) {
		pr_err("DCE: dpdcei_enable failed %d\n", err);
		goto err_dpdcei_enable;
	}

#if 0
	/* Invalidate any leftover context */
	struct dpaa2_fd fd = (struct dpaa2_fd){0};
	fd_frc_set_cmd(&fd, DCE_CMD_CTX_INVALIDATE);
	err = dpaa2_io_service_enqueue_fq(dpdcei->dpio_p, dpdcei->tx_fqid, &fd);
	if (err < 0) {
		pr_err("DCE: error enqueueing Tx frame\n");
	}

	sleep(1);
#endif

	/* This environment may trigger ERR010843. Take precautions */
	spin_lock(&err010843_lock);
	if (!err010843_fd)
		err010843_workaround_setup(dpdcei->attr.dce_version);
	spin_unlock(&err010843_lock);

	return dpdcei;

err_dpdcei_enable:
	dpdcei_unbind_dpio(dpdcei, mc_io, dpdcei->token);
err_dpdcei_bind:
	dpdcei_dpio_service_teardown(dpdcei);
err_dpio_service_setup:
	dpaa2_dce_free_store(dpdcei);
err_alloc_store:
err_dpdcei_get_attr:
	dpdcei_close(mc_io, MC_CMD_FLAG_PRI, dpdcei->token);
err_dpdcei_open:
	cleanup_flow_lookup_table(dpdcei);
err_setup_flow_lookup:
	mc_io_cleanup(mc_io);
err_mc_io_init:
	free(mc_io);
err_mc_io_alloc:
	free(dpdcei);
fail_dpdcei_malloc:
	return NULL;
}
EXPORT_SYMBOL(dpdcei_setup);

void dpdcei_cleanup(struct dpdcei *dpdcei)
{
	int err;
	struct fsl_mc_io *mc_io;

	err = atomic_read(&dpdcei->frames_in_flight);
	if (err) {
		pr_err("Attempt to cleanup dpdcei that still has %d frames in flight\n",
				err);
		return;
	}

	err = cleanup_flow_lookup_table(dpdcei);
	if (err) {
		pr_err("%d received from cleanup_flow_lookup_table() in %s\n",
				err, __func__);
		return;
	}

	mc_io = malloc(sizeof(struct fsl_mc_io));
	if (!mc_io) {
		pr_err("Could not malloc mem for mc_io in %s\n", __func__);
		return;
	}

	err = mc_io_init(mc_io);
	if (err) {
		pr_err("%d received from mc_io_init() in %s\n", err, __func__);
		goto err_mc_io_init;
	}

	err = dpdcei_unbind_dpio(dpdcei, mc_io, 0 /* cmd_flags*/);
	if (err)
		pr_err("%d received from dpdcei_unbind_dpio() in %s\n",
				err, __func__);

	err = dpdcei_dpio_service_teardown(dpdcei);
	if (err)
		pr_err("%d received from dpdcei_dpio_service_teardown() in %s\n",
				err, __func__);

	err = dpdcei_open(mc_io, MC_CMD_FLAG_PRI, dpdcei->attr.id,
			&dpdcei->token);
	if (err)
		pr_err("error %d in %s in attempt to dpdcei_open(comp)\n",
				err, __func__);

	err = dpdcei_disable(mc_io, MC_CMD_FLAG_PRI, dpdcei->token);
	if (err)
		pr_err("error %d in %s in attempt to dpdcei_disable(comp)\n",
				err, __func__);

	err = dpdcei_close(mc_io, MC_CMD_FLAG_PRI, dpdcei->token);
	if (err)
		pr_err("error %d in %s in attempt to dpdcei_close(comp)\n",
				err, __func__);

	free(dpdcei);

err_mc_io_init:
	free(mc_io);
}
EXPORT_SYMBOL(dpdcei_cleanup);

#include "dce-scf-decompression.h"

static void err010843_workaround_setup(uint64_t dce_version)
{
	struct err010843_data {
		char output[1];
		char input[267];
		char config[256] __aligned(64);
		char fcr[256] __aligned(64);
		char history[0x8000] __aligned(64);
		struct dpaa2_fd frame_list[3] __aligned(64);
	};
	size_t workaround_size = workaround_file_gz_len;
	struct err010843_data *err010843_data = vfio_setup_dma(0xA000);

	assert(err010843_data);
	assert(workaround_size > 0);
	assert(workaround_size <= sizeof(err010843_data->input));
	memcpy(err010843_data->input, workaround_file_gz, workaround_size);
	err010843_fd = malloc(sizeof(*err010843_fd));
	assert(err010843_fd);
	memset(err010843_fd, 0, sizeof(*err010843_fd));
	dpaa2_fd_set_len(err010843_fd, workaround_size);
	dpaa2_fd_set_addr(err010843_fd,
			(dma_addr_t)err010843_data->frame_list);
	dpaa2_fd_set_format(err010843_fd, dpaa2_fd_list);
	if (dce_version == ERR008704_DCE_REV)
		fd_frc_set_scrf(err010843_fd, true);
	fd_frc_set_sf(err010843_fd, false);
	fd_frc_set_cf(err010843_fd, DCE_CF_GZIP);
	fd_frc_set_recycle(err010843_fd, false);
	fd_frc_set_initial(err010843_fd, false);
	fd_frc_set_z_flush(err010843_fd,
			DCE_Z_NO_FLUSH);
	fcr_set_next_flc((struct fcr *)err010843_data->config,
			(dma_addr_t)err010843_fd);
	scf_d_cfg_set_history_ptr(
			(struct scf_d_cfg *)err010843_data->fcr,
			(dma_addr_t)err010843_data->history);
	fd_set_flc_64(err010843_fd,
			(dma_addr_t)err010843_data->fcr);

	/* Setup output frame list entry */
	dpaa2_fd_set_addr(&err010843_data->frame_list[0],
			(dma_addr_t)err010843_data->output);
	dpaa2_fd_set_len(&err010843_data->frame_list[0],
			sizeof(err010843_data->output));

	/* Setup input frame list entry */
	dpaa2_fd_set_addr(&err010843_data->frame_list[1],
			(dma_addr_t)err010843_data->input);
	dpaa2_fd_set_len(&err010843_data->frame_list[1],
			sizeof(err010843_data->input));

	/* Setup configuration frame list entry */
	dpaa2_fd_set_addr(&err010843_data->frame_list[2],
			(dma_addr_t)err010843_data->config);
	dpaa2_fd_set_len(&err010843_data->frame_list[2],
			sizeof(err010843_data->config));
	dpaa2_sg_set_final(
		(struct dpaa2_sg_entry *)&err010843_data->frame_list[2], 1);

}
