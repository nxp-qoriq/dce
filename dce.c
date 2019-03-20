/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */

#include "dce-internals.h"
#include "dce.h"
#include <fsl_mc_cmd.h>
#include "dce-fd-frc.h"

/**
 * dce_dpdcei_activate() – Activate a compression or decompression dpdcei
 *
 *
 * Activates a dpdcei object corresponding to the given dpdcei_id. The dpdcei
 * object represents either a compression engine or a decompression engine
 * depending on the object properties specified at dpdcei create time and cannot
 * be altered by this function. The object can transparently handle multiple
 * dpdcei_lanes without interference
 *
 * Return 0 for success
 */
struct dpdcei *dce_dpdcei_activate(struct dce_dpdcei_params *params)
{
	struct fsl_mc_io *mc_io = params->mcp;
	struct dpdcei_rx_queue_attr done_queue_attr;
	struct dpdcei_tx_queue_attr todo_queue_attr;
	struct dpdcei *dpdcei = NULL;
	int err = 0;

	dpdcei = malloc(sizeof(struct dpdcei));
	if (!dpdcei) {
		pr_err("Unable to allocate memory for dpdcei setup\n");
		goto fail_dpdcei_malloc;
	}
	memset(dpdcei, 0, sizeof(*dpdcei));

	/* MC portal needed to cleanup dpdcei resources on deactivate */
	dpdcei->mcp = params->mcp;

	/* in flight counter initialization */
	atomic_set(&dpdcei->frames_in_flight, 0);

	/* get a handle for the DPDCEI this interface is associated with */
	err = dpdcei_open(mc_io, MC_CMD_PRIORITY_HIGH, params->dpdcei_id,
							&dpdcei->token);
	if (err) {
		pr_err("DCE: dpdcei_open() failed\n");
		goto err_dpdcei_open;
	}

	err = dpdcei_reset(mc_io, MC_CMD_PRIORITY_HIGH, dpdcei->token);
	if (err) {
		pr_err("%d received from dpdcei_reset in %s\n", err, __func__);
		goto err_dpdcei_open;
	}

	err = dpdcei_get_attributes(mc_io, MC_CMD_PRIORITY_HIGH, dpdcei->token,
				&dpdcei->attr);
	if (err) {
		pr_err("DCE: dpdcei_get_attributes() failed %d\n", err);
		goto err_dpdcei_get_attr;
	}

	memset(&done_queue_attr, 0, sizeof(done_queue_attr));
	memset(&todo_queue_attr, 0, sizeof(todo_queue_attr));

	err = dpdcei_get_rx_queue(mc_io, MC_CMD_PRIORITY_HIGH, dpdcei->token,
			&done_queue_attr);
	if (err) {
		pr_err("DCE: dpdcei_get_rx_queue() failed %d\n", err);
		goto err_dpdcei_get_attr;
	}
	dpdcei->done_queue_fqid = done_queue_attr.fqid;

	err = dpdcei_get_tx_queue(mc_io, MC_CMD_PRIORITY_HIGH, dpdcei->token,
			&todo_queue_attr);
	if (err) {
		pr_err("dpdcei_get_rx_queue() failed %d\n", err);
		goto err_dpdcei_get_attr;
	}
	dpdcei->todo_queue_fqid = todo_queue_attr.fqid;

	err = pthread_mutex_init(&dpdcei->pull_lock, NULL /* Default mutex */);
	if (err) {
		pr_err("Failed to init dpdcei pull mutex\n");
		goto err_pull_lock_init;
	}

	dpdcei->dma_free = params->dma_free;
	dpdcei->dma_opaque = params->dma_opaque;

#define SWP_PULL_STORE_ALIGN 64
#define SWP_PULL_STORE_MAX_DQ 32
	/* dpio store */
	/* qbman 5 and beyond support 32 frames per pull request, but the qbman
	 * library ensures that no issues occur on earlier version of qbman that
	 * only support 16 frames or less */
	dpdcei->store_1.addr = params->dma_alloc(params->dma_opaque,
			SWP_PULL_STORE_ALIGN,
			SWP_PULL_STORE_MAX_DQ * sizeof(struct qbman_result));
	if (!dpdcei->store_1.addr)
		goto err_alloc_store;
	dpdcei->store_1.max_dq = SWP_PULL_STORE_MAX_DQ;

	/* We allocate a second store because two simultaneous pull requests can
	 * be issued thus speeding up the dequeueing of frames */
	dpdcei->store_2.addr = params->dma_alloc(params->dma_opaque,
			SWP_PULL_STORE_ALIGN,
			SWP_PULL_STORE_MAX_DQ * sizeof(struct qbman_result));
	if (!dpdcei->store_2.addr)
		goto err_alloc_store;

	dpdcei->store_2.max_dq = SWP_PULL_STORE_MAX_DQ;

	/* Enable the dpdcei */
	err = dpdcei_enable(mc_io, MC_CMD_PRIORITY_HIGH, dpdcei->token);
	if (err) {
		pr_err("DCE: dpdcei_enable failed %d\n", err);
		goto err_dpdcei_enable;
	}

#if 0
	/* This environment may trigger ERR010843. Take precautions */
	spin_lock(&err010843_lock);
	if (dpdcei->attrs.engine == DPDCEI_ENGINE_DECOMPRESSION &&
	    dpdcei->attrs.version <=  ERR010843_DCE_REV &&
	    !err010843_fd)
		err010843_workaround_setup(dpdcei->attr.dce_version);
	spin_unlock(&err010843_lock);
#endif

	return dpdcei;

err_dpdcei_enable:
	params->dma_free(params->dma_opaque, dpdcei->store_1.addr);
err_alloc_store:
	pthread_mutex_destroy(&dpdcei->pull_lock);
err_pull_lock_init:
err_dpdcei_get_attr:
	dpdcei_close(mc_io, MC_CMD_PRIORITY_HIGH, dpdcei->token);
err_dpdcei_open:
	free(dpdcei);
fail_dpdcei_malloc:
	return NULL;
}

bool dpdcei_is_compression(struct dpdcei *dpdcei)
{
	return dpdcei->attr.engine == DPDCEI_ENGINE_COMPRESSION;
}

#include <fsl_qbman_debug.h>

/**
 * dpdcei_num_ops_todo_queue() - Number of operations on todo queue of dpdcei
 * dpdcei_num_ops_done_queue() - Number of operations on todo queue of dpdcei
 * @swp:	QBMan Software portal to use for issuing query
 * @dpdcei:	DPDCEI object to be checked
 *
 * NOTE: No two thread are allowed to issue a query command on a single swp
 * simultaneously. Even if both threads run on the same core since preemption
 * may swap the threads mid command
 *
 * The todo queue is NOT equivalent to the number of ops in flight, because
 * there can be ops on the done queue and there can be ops in the engine itself
 * which will not show in either queue
 *
 * Return:	0 or greater if the query succeeded. Indicates the number of
 *		frames that were found on the todo queue
 *		less than 0 if the query command failed
 */
int dpdcei_todo_queue_count(struct qbman_swp *swp,
				       struct dpdcei* dpdcei)
{
	int ret;
	struct qbman_fq_query_np_rslt state;

	ret = qbman_fq_query_state(swp, dpdcei->todo_queue_fqid, &state);
	if (ret)
		return ret;
	ret = qbman_fq_state_frame_count(&state);

	return ret;

}

int dpdcei_done_queue_count(struct qbman_swp *swp,
				       struct dpdcei* dpdcei)
{
	int ret;
	struct qbman_fq_query_np_rslt state;

	ret = qbman_fq_query_state(swp, dpdcei->todo_queue_fqid, &state);
	if (ret)
		return ret;
	ret = qbman_fq_state_frame_count(&state);

	return ret;

}

void dce_dpdcei_deactivate(struct dpdcei *dpdcei)
{
	dpdcei->dma_free(dpdcei->dma_opaque, dpdcei->store_1.addr);
	dpdcei->dma_free(dpdcei->dma_opaque, dpdcei->store_2.addr);
	dpdcei_disable(dpdcei->mcp, MC_CMD_PRIORITY_HIGH, dpdcei->token);
	dpdcei_close(dpdcei->mcp, MC_CMD_PRIORITY_HIGH, dpdcei->token);
	free(dpdcei);
}

struct dpdcei_lane *dpdcei_lane_create(struct dpdcei_lane_params *params)
{
	struct dpdcei_lane *lane;
	const unsigned int num_setup_frames = 1;
	struct dce_op_fd_pair_rx ops[num_setup_frames];
	cpu_set_t cpuset;
	struct work_unit *setup_work_unit;
	void *fifo_mem = NULL;
	int timeout = 10000;
	int err;

	if (!params->dpdcei) {
		pr_err("Null dpdcei passed to %s\n", __func__);
		return NULL;
	}

	/* must be affine to enqueue. Otherwise risk chance of pre-emption mid
	 * enqueue and the enqueue getting dropped */
	pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
	if (CPU_COUNT(&cpuset) > 1) {
		pr_err("Thread calling dpdcei_lane_create() is not affine to a single core. This may cause the setup frame to get dropped.\n"
		"Threads calling lane_enqueue_fd_pair() should also be affine to a single core!\n");
		return NULL;
	}

	lane = malloc(sizeof(*lane));
	if (!lane) {
		pr_err("Unable to allocate memory for lane in %s\n", __func__);
		return NULL;
	}

	/* We must make clear the lane struct here. The lane has many
	 * pointers, other functions will assume they are valid if they are not
	 * cleared and attempt to use them */
	*lane = (struct dpdcei_lane){0};

	lane->member_continue = params->member_continue;
	lane->paradigm = params->paradigm;
	lane->compression_format = params->compression_format;
	lane->compression_effort = params->compression_effort;
	lane->encode_base_64 = params->encode_base_64;

	/* associate lane to dpdcei */
	lane->dpdcei = params->dpdcei;

	lane->dma_alloc = params->dma_alloc;
	lane->dma_free = params->dma_free;
	lane->dma_opaque = params->dma_opaque;

	if (lane->paradigm == DCE_STATEFUL_RECYCLE) {
		if (lane->dpdcei->attr.dce_version == ERR011568_DCE_REV)
			pr_warning("Stateful-recycle mode may trigger ERR011568 on this SoC if recycle mode is triggered\n");

		err = pthread_mutex_init(&lane->lock,
				NULL /* DEFAULT MUTEX */);
		if (err) {
			pr_err("Got %d in lane lock init\n", err);
			goto err_mutex_setup;
		}
		/* A mutex cannot be unlocked by a thread other than the one
		 * that locked it. The dequeuer "locks" the semaphore when it
		 * sees a problem frame. The recycler then unlocks the enqueuer
		 * once all problem frames are dealt with. The dequeuer recycler
		 * and enqueuer may be all implemented in one thread or in
		 * multiple threads hence the need for a semaphore
		 */
		err = sem_init(&lane->enqueue_sem,
				0 /* semaphore shared within process only */,
				1 /* allow only one thread */);
		if (err) {
			pr_err("Got %d in enqueue semaphore init\n", errno);
			goto err_mutex_setup;
		}

		/* Reset lane state so the frist frame is seen as initial */
		lane->state = STREAM_END;
	}

	/* Setup memory for DCE to maintain lane state */
	err = alloc_lane_hw_mem(lane);
	if (err)
		goto err_alloc_lane_hw_mem;

	/* Set the NEXT_FLC field in the stream context record. We set the field
	 * to the software address for the lane, and when we send a frame we set
	 * the FLC address to the HW address stored in
	 * lane->flow_context_record. This way we create a sort of cycle where
	 * frames going to DCE have pointers to their respective hw lane (struct
	 * flow_context_record) and frames coming back from DCE come back
	 * updated with a pointer to the dpdcei_lane software object.  This way
	 * we do not have to do a lookup coming back, since their FLC field will
	 * already contain the correct dpdcei_lane pointer.  This is important
	 * because frames from different lanes can  all be sent and received on
	 * the same DPDCEI frame queues. The only distinguishing feature is the
	 * FLC field in each frame */
	fcr_set_next_flc(lane->flow_context_record, (uint64_t)lane);

	/* Note: the above scheme only works for PROCESS frames we will rely on
	 * a different mechanism to distinguish frames of other commands */

	atomic_set(&lane->frames_in_flight, 0);

	assert(params->max_in_flight > 0);

	/* Setup lane circular fifo */
	fifo_mem = lane->dma_alloc(lane->dma_opaque, 64,
			sizeof(struct work_unit) * params->max_in_flight);
	if (!fifo_mem) {
		pr_err("Unable to allocate memory for in flight work\n");
		goto err_setup_circular_fifo;
	}

	circ_fifo_setup(&lane->fifo, fifo_mem,
		sizeof(struct work_unit), params->max_in_flight);

	setup_work_unit = circ_fifo_alloc(&lane->fifo);

	err = send_init_frame(params->swp, lane, setup_work_unit);
	if (err)
		goto err_enqueue_init_frame;

	atomic_inc(&lane->frames_in_flight);

	while (!lane_dequeue_fd_pair(params->swp, lane, ops,
				num_setup_frames /* 1 */) && timeout--)
		pthread_yield(); /* backoff */

	if (timeout < 0) {
		pr_err("Did not receive response from DCE for setup frame\n");
		goto err_init_frame_lost;
	} else if (ops[0].user_context != setup_work_unit) {
		pr_err("RECEIVED an unexpected frame instead of setup frame\n");
		assert(false);
	} else {
		/* Got back setup frame there should be no frames in flight */
		assert(!circ_fifo_num_alloc(&lane->fifo));
	}

	assert(!address_conflicts(4, lane->pending_output.vaddr,
					lane->pending_output.len,
					lane->history.vaddr,
					lane->history.len,
					lane->decomp_context.vaddr,
					lane->decomp_context.len,
					fifo_mem,
					sizeof(struct work_unit) *
					params->max_in_flight));

	return lane;

err_enqueue_init_frame:
	circ_fifo_alloc_undo(&lane->fifo);
err_init_frame_lost:
	lane->dma_free(params->dma_opaque, fifo_mem);
err_setup_circular_fifo:
err_mutex_setup:
err_alloc_lane_hw_mem:
	free(lane);
	return NULL;
}

int dpdcei_lane_destroy(struct dpdcei_lane *lane)
{
	if (atomic_read(&lane->frames_in_flight)) {
		pr_err("Attempt to destroy lane that still has work in flight. call *_dequeue() to clear lane\n");
		return -EBUSY;
	}

	/* TODO: Should send a context invalidate frame here to invalidate the
	 * data cached in DCE */

	lane->dma_free(lane->dma_opaque, lane->fifo.mem);
	free(lane);

	return 0;
}

/**
 * lane_enqueue_fd_pair() - Compress or decompress a frame asynchronously
 * @swp:	Software portal to use in sending work to DCE
 * @lane:	lane in which this op will be processed
 * @op:	Operation instructions including input and output and context
 *
 * Return:	0 on success,
 *		-EBUSY if the device is busy and call must be reattempted
 *		-ENOSPC if the maximum number of inflight ops is exceeded
 *		-EACCES if a stateful session has entered recycle mode and must
 *			cleaned up using dce_recycle_*() function
 */
int lane_enqueue_fd_pair(struct qbman_swp *swp,
			struct dpdcei_lane *lane,
			struct dce_op_fd_pair_tx *op)
{
#ifdef DEBUG
	static struct work_unit *prev_work;
#endif
	struct work_unit *work_unit;
	struct dpaa2_fd *head_fd;
	struct dpaa2_fd *input_fd;
	struct dpaa2_fd *output_fd;
	struct dpaa2_fd *scf_fd;
	int ret;

	if (lane->paradigm == DCE_STATEFUL_RECYCLE) {
		ret = sem_trywait(&lane->enqueue_sem);
		if (ret) {
			/* EBUSY is expected because the lane might be in
			 * recycle mode, or caller might have two simultaneous
			 * enqueuers. Any other error would be an
			 * implementation bug */
			assert(errno == EAGAIN); /* errno is racy .. oh well */
			pthread_mutex_lock(&lane->lock);
			ret = lane->recycle_todo ? -EACCES : -EBUSY;
			pthread_mutex_unlock(&lane->lock);
			return ret;
		}
	}

	assert(!lane->recycle_todo);

	work_unit = circ_fifo_alloc(&lane->fifo);
#ifdef DEBUG
	if (!prev_work)
		prev_work = work_unit - 1;
	if (work_unit != (prev_work + 1) && work_unit !=
			circ_fifo_mem_start(&lane->fifo)) {
		printf("Line %d Mem start is %p and work_unit we got is %p and the previous work_unit was %p\n",
				__LINE__, circ_fifo_mem_start(&lane->fifo),
				work_unit, prev_work);
		getchar();
	}
#endif
	if (!work_unit) {
#ifdef DEBUG
		pr_debug("Too many DCE rquests in flight! backoff!\n");
#endif
		ret = -ENOSPC;
		goto err_no_space;
	}

	memset(work_unit, 0, sizeof(*work_unit));

	/* Must copy the frames over. No way around it because the frames have
	 * to be stored in a contiguous frame list */
	work_unit->store.input_fd = *op->input_fd;
	work_unit->store.output_fd = *op->output_fd;

	/* reorient the pointers in my stack to point to the copy for
	 * convenience in later usage */
	input_fd = &work_unit->store.input_fd;
	output_fd = &work_unit->store.output_fd;

	/* do the same for our scf_fd and the head_fd */
	head_fd = &work_unit->head_fd;
	scf_fd = &work_unit->store.scf_fd;

	/* we only need to do setup work for the SCF because the input and
	 * output were passed in with correct setup by our caller */

	/* SCF */
	dpaa2_sg_set_final((struct dpaa2_sg_entry *)scf_fd, 1);
	dpaa2_fd_set_addr(scf_fd, (dma_addr_t) &work_unit->scf_result);
	dpaa2_fd_set_len(scf_fd, sizeof(struct scf_c_cfg));

	/* FD */
	fd_set_ivp(head_fd, true); /* bpid is invalid */
	dpaa2_fd_set_len(head_fd, dpaa2_fd_get_len(input_fd));
	dpaa2_fd_set_format(head_fd, dpaa2_fd_list);
	dpaa2_fd_set_addr(head_fd, (dma_addr_t)work_unit->store.fd_list_store);
	/* We set the FLC (lane context) field in the FD to the address of the
	 * FCR (lane context record). The FLC field is not strictly always a
	 * pointer to the FCR memory. When the DCE processes the frame it
	 * updates the FLC field to the software dpdcei_lane object that sent
	 * the FD. This way software can match the FD upon dequeueing it to the
	 * correct software owner */
	dpaa2_fd_set_flc(head_fd, (dma_addr_t)lane->flow_context_record);
#ifdef NOP_TEST
	fd_frc_set_cmd(head_fd, DCE_CMD_NOP);
#endif
	fd_frc_set_ce(head_fd, lane->compression_effort);
	if (lane->dpdcei->attr.dce_version == ERR008704_DCE_REV)
		/* hardware bug requires the SCR flush to occur every time */
		fd_frc_set_scrf(head_fd, true);
	fd_frc_set_cf(head_fd, lane->compression_format);
	fd_frc_set_sf(head_fd, !!lane->paradigm);
	if (lane->recycle) {
		/* Why worry about the recycle bit in enqueue_() when it is
		 * taken care of by two dedicated functions recycle_()?
		 * There is one case where this does not work. If an application
		 * calls continue() and discard()s all outstanding operations.
		 * The lane will exit recycle and the application will be
		 * allowed to do regular enqueues. DCE will reject regular
		 * enqueues because the lane is still suspended in DCE. To
		 * clear suspend we must set the recycle bit here */
		fd_frc_set_recycle(head_fd, lane->recycle);
		lane->recycle = false;
	}
	if (lane->paradigm != DCE_STATELESS) {
		/* These setting are assumed by DCE in Stateless mode. Setting
		 * should have no effect, but it was observed to negatively
		 * impact throughput in Stateless mode */
		if (lane->state == STREAM_END) {
			fd_frc_set_initial(head_fd, true);
			lane->state = FULLY_PROCESSED;
		}
		fd_frc_set_z_flush(head_fd, op->flush);
		if (op->flush == DCE_Z_FINISH)
			lane->state = STREAM_END;
	}
	if (lane->reset) {
		/* lane->reset is addressed in the recycle_fd() function when
		 * the user calls continue() or abort() followed by
		 * recycle_fd(). If the application decides to call abort()
		 * followed by discard() of all frames then the reset must be
		 * done in the regular enqueue function instead . */
		struct work_unit *abort_unit;
		struct dpaa2_fd *abort_fd;
		struct circ_fifo *fifo = &lane->fifo;
		/* Enqueue an empty fd with only a recycle bit set to force the
		 * lane to exit recycle mode. This allows the next FD with uspc
		 * set to clear the history and successfully restart the lane */
		abort_unit = lane->dma_alloc(lane->dma_opaque, 0,
							sizeof(*abort_unit));

		assert(!circ_fifo_addr_collision(fifo, abort_unit));
		if (!abort_unit) {
			ret = -ENOSPC;
			goto abort_stream_mem_fail;
		}
		memset(abort_unit, 0, sizeof(*abort_unit));

		dpaa2_fd_set_format(&abort_unit->store.input_fd, dpaa2_fd_null);
		dpaa2_fd_set_len(&abort_unit->store.input_fd, 0);
		dpaa2_fd_set_addr(&abort_unit->store.input_fd,
							(dma_addr_t)NULL);
		dpaa2_fd_set_frc(&abort_unit->store.input_fd, 0xABCDEF22);

		dpaa2_fd_set_len(&abort_unit->store.output_fd,
				lane->pending_output.len);
		dpaa2_fd_set_addr(&abort_unit->store.output_fd,
				(dma_addr_t)lane->pending_output.vaddr);

		dpaa2_sg_set_final(
			(struct dpaa2_sg_entry *)&abort_unit->store.scf_fd, 1);
		dpaa2_fd_set_addr(&abort_unit->store.scf_fd,
				(dma_addr_t) &abort_unit->scf_result);
		dpaa2_fd_set_len(&abort_unit->store.scf_fd,
				sizeof(struct scf_c_cfg));

		abort_fd = &abort_unit->head_fd;
		dpaa2_fd_set_format(abort_fd, dpaa2_fd_list);
		dpaa2_fd_set_len(abort_fd, 0);
		dpaa2_fd_set_addr(abort_fd,
				(dma_addr_t)abort_unit->store.fd_list_store);

		fd_frc_set_recycle(abort_fd, true);
		fd_frc_set_sf(abort_fd, true);
		/* We set the FLC (lane context) field in the FD to the address
		 * of the FCR (lane context record). The FLC field is not
		 * strictly always a pointer to the FCR memory. When the DCE
		 * processes the frame it updates the FLC field to the software
		 * dpdcei_lane object that sent the FD. This way software can match
		 * the FD upon dequeueing it to the correct software owner */
		dpaa2_fd_set_flc(abort_fd,
				(dma_addr_t)lane->flow_context_record);

		abort_unit->finish_cb = finish_lane_abort_fd;

		ret = enqueue_dpdcei(swp, lane->dpdcei, abort_fd);
		if (ret) {
			lane->dma_free(lane->dma_opaque, abort_unit);
			goto abort_stream_enqueue_fail;
		}

		/* resetting the lane state is done through the stream_abort()
		 * and TODO session_reset() functions both should set the
		 * lane state to STREAM_END and cause the next frame (the one
		 * we are setting up here) to have initial set to true */
		assert(fd_frc_get_initial(head_fd));
		lane->reset = false;
	}

	/* Set caller context */
	work_unit->context = op->user_context;

	/* DCE destroys output buffer length information in skipped and
	 * terminated FD. Must maintain in software */
	work_unit->output_length = dpaa2_fd_get_len(output_fd);

#ifdef DEBUG
	pr_info("dce: Before enqueue\n");
	pretty_print_fd(head_fd);
	pretty_print_fle_n(
		(struct fle_attr *)&work_unit->store.list_store[0], 3);

	hexdump(head_fd, sizeof(*head_fd));
	hexdump(work_unit->store.list_store,
			sizeof(work_unit->store.list_store[0])*3);

	if (work_unit->state != FREE) {
		pr_err("Out of order FIFO allocation detected. Paused for debug\n");
		getchar();
	}
#endif
	work_unit->state = TODO;

	work_unit->finish_cb = finish_user_fd;

	/* enqueue request */
	ret = enqueue_dpdcei(swp, lane->dpdcei, head_fd);
	if (lane->paradigm == DCE_STATEFUL_RECYCLE)
		sem_post(&lane->enqueue_sem);
	if (ret)
		goto err_enqueue_fail;

	atomic_inc(&lane->frames_in_flight);

	assert(work_unit->finish_cb == finish_user_fd);

#ifdef DEBUG
	prev_work = work_unit;
#endif

	return 0;

abort_stream_enqueue_fail:
abort_stream_mem_fail:
err_enqueue_fail:
	/* Cannot use circ_fifo_free() because that would change the head index
	 * of the fifo, but we want to return a buffer at the tail index n*/
	work_unit->state = FREE;
	circ_fifo_alloc_undo(&lane->fifo);
err_no_space:
	if (lane->paradigm == DCE_STATEFUL_RECYCLE)
		sem_post(&lane->enqueue_sem);
	return ret;
}

int lane_dequeue_fd_pair(struct qbman_swp *swp,
			struct dpdcei_lane *lane,
			struct dce_op_fd_pair_rx *ops,
			unsigned int num_ops)
{
#ifdef DEBUG
	static struct work_unit *prev_work;
#endif
	struct work_unit *work_unit = circ_fifo_head(&lane->fifo);
	unsigned int i, ret;
#ifdef DEBUG
	if (prev_work != NULL && prev_work != work_unit - 1 &&
			work_unit != lane->fifo.mem)	{
		printf("Line %d Mem start is %p and work_unit we got is %p and the previous work_unit was %p\n",
				__LINE__, lane->fifo.mem, work_unit, prev_work);
		getchar();
	}
#endif
	if (lane->paradigm == DCE_STATEFUL_RECYCLE) {
		ret = pthread_mutex_trylock(&lane->lock);
		if (ret) {
			/* EBUSY is the only expected error because another
			 * thread might have the lock for recycle */
			assert(ret == EBUSY);
			return 0;
		}
	}

	/* Function dequeues available frames from the done queue of the dpdcei.
	 * The frames may belong to different lanes, so it does not pass them
	 * all to this function as this function is local to a particular lane.
	 * Instead the function sets the done flag of all work that it dequeues
	 * regardless of which lane it belongs to and we check the done flag for
	 * the frames that belong to this lane */
	ret = pull_done_queue(swp, lane->dpdcei);
	if (ret)
		/* Pull command failed. Too many pull requests? */
		return 0;

	for (i = 0;
		i < num_ops && work_unit->state == DONE;
		i++, work_unit = circ_fifo_head(&lane->fifo)) {
		/* Ensure that a SUSPEND is never returned mid array. We promise
		 * to only return a SUSPEND FD for i = 0. This makes application
		 * side software much simpler, as a SUSPEND FD locks the enqueue
		 * and recycle functions until a stream_continue() call is made.
		 * e.g. a caller may get 16 FDs. The first 15 are skipped but
		 * the last one is SUSPEND. An application that employs a simple
		 * loop will attempt to send the SKIPPED frames back for
		 * processing will be rejected, and then must employ advanced
		 * algorithms that run through the entire returned array first
		 * to make sure there is no SUSPEND and then to resend the
		 * SKIPPED frames. If it finds a SUSPEND it would have to first
		 * recycle the SUSPEND then reset the loop to the first SKIPPED
		 * frame and continue work. By promising the caller to never
		 * deliver a SUSPEND mid array and only allow it on the very
		 * first container in the array we take the burden off of the
		 * application to create this complex logic */
		if (i > 0) {
			switch (fd_frc_get_status(&work_unit->head_fd)) {
			case OUTPUT_BLOCKED_SUSPEND:
			case MEMBER_END_SUSPEND:
			case ACQUIRE_DATA_BUFFER_DENIED_SUSPEND:
			case ACQUIRE_TABLE_BUFFER_DENIED_SUSPEND:
			case Z_BLOCK_SUSPEND:
			case OLL_REACHED_SUSPEND:
				goto quick_exit;
				break;
			default:
				break;
			}
		}

#ifdef DEBUG
		if (prev_work != NULL && prev_work != work_unit - 1 &&
				work_unit != lane->fifo.mem)	{
			printf("Line %d Mem start is %p and work_unit we got is %p and the previous work_unit was %p\n",
				__LINE__, lane->fifo.mem, work_unit, prev_work);
			getchar();
		}
		prev_work = work_unit;
#endif
		dpaa2_fd_set_frc(&work_unit->store.output_fd, 0x0);
		work_unit->state = FREE;
		/* We should be checking at > 1, but there is a small chance
		 * for a race where the enqueuer alloced the work_unit but did
		 * not yet set it to todo. This is because the enqueuer and
		 * dequeuer do not share the same lock to reduce contention */
		if (circ_fifo_num_alloc(&lane->fifo) > 2) {
			/* If there is a gap of free work units between the
			 * consumer and the producer then there is bug in the
			 * circular fifo usage scheme. Likely in the enqueue
			 * functions.
			 * Long assert line so that removing assert at compile
			 * time also removes the if statement */
			assert(((struct work_unit *)circ_fifo_head_seek(
					&lane->fifo, 1))->state != FREE);
		}
		ops[i].input_fd = work_unit->store.input_fd;
		ops[i].output_fd = work_unit->store.output_fd;
		ops[i].status =
			fd_frc_get_status(&work_unit->head_fd);
		ops[i].flush = fd_frc_get_z_flush(&work_unit->head_fd);
		switch (ops[i].status) {
		case FULLY_PROCESSED:
		case STREAM_END:
			ops[i].input_consumed =
				dpaa2_fd_get_len(&work_unit->store.input_fd);
			break;
		case OUTPUT_BLOCKED_SUSPEND:
		case MEMBER_END_SUSPEND:
		case ACQUIRE_DATA_BUFFER_DENIED_SUSPEND:
		case ACQUIRE_TABLE_BUFFER_DENIED_SUSPEND:
		case Z_BLOCK_SUSPEND:
		case OLL_REACHED_SUSPEND:
			if (!lane->recycle_todo) {
				ret = sem_wait(&lane->enqueue_sem);
				assert(!ret);
			}
			lane->recycler_allowed = false;
			lane->initial_store =
				fd_frc_get_initial(&work_unit->head_fd);
			lane->recycle_todo += circ_fifo_num_alloc(
					&lane->fifo);
			ops[i].input_consumed = scf_c_result_get_bytes_processed(
					(struct scf_c_result *)
					&work_unit->scf_result);
			break;
		case SKIPPED:
			/* DCE will never skip an op unless there was one before
			 * it that was *_SUSPEND. What about the case of an
			 * application recycling the SUSPEND frame before
			 * calling dequeue again to get the SKIPPED frame? Will
			 * not the recycle_todo = 0? This cannot happen because
			 * the recycle_todo is not set to 1 when a SUSPEND frame
			 * is observed. Rather it is set to the total number of
			 * frames in flight when the SUSPEND frame is dequeued.
			 * This means that when we observe the SKIPPED frame
			 * recycle_todo will be a minimum of 1 in the case of
			 * the application recycling or discarding the SUSPEND
			 * frame. The other case when this can happen is if the
			 * application calls discard continuously without first
			 * dequeueing the frames to be discarded. The last
			 * scenario where this can occur is if the driver fails
			 * to prevent the enqueuer from adding more frames to
			 * the lane AFTER it has already observed the SUSPEND
			 * frame. This is prevented in the current design with a
			 * semaphore to lockout the enqueuer from adding to the
			 * SKIPPED frames backlog */
			assert(lane->recycle_todo);
			ops[i].input_consumed = 0;

			/* DCE destroys output buffer length information in
			 * skipped and terminated FDs. Recover from software */
			dpaa2_fd_set_len(&ops[i].output_fd,
					work_unit->output_length);
			break;
		default:
			/* Some other unexpected type of status, no processed */
			ops[i].input_consumed = 0;

			/* DCE destroys output buffer length information in
			 * skipped and terminated FDs. Recover from software */
			dpaa2_fd_set_len(&ops[i].output_fd,
					work_unit->output_length);

			/* A terminal error may occur on a recycle op. It is not
			 * possible to recover the lane state in that case */
			if (lane->paradigm == DCE_STATEFUL_RECYCLE &&
					lane->recycle_todo) {
				lane->recycle_todo = 0;
				lane->recycler_allowed = false;
				/* Unlock regular enqueues */
				ret = sem_post(&lane->enqueue_sem);
				assert(!ret);
			}
			break;
		}
		ops[i].user_context = work_unit->context;
#ifdef DEBUG
		struct work_unit *test = circ_fifo_head(&lane->fifo);
#endif
		circ_fifo_free(&lane->fifo);
		atomic_dec(&lane->frames_in_flight);
#ifdef DEBUG
		if (circ_fifo_head(&lane->fifo) != (test + 1) &&
				circ_fifo_head(&lane->fifo) != lane->fifo.mem) {
			pr_info("bad freer increment detected. Expected to go from %p to %p, instead went to %p\n",
					test, test + 1, circ_fifo_head(&lane->fifo));
			getchar();
		}
#endif
	}

quick_exit:
	if (lane->paradigm == DCE_STATEFUL_RECYCLE) {
		ret = pthread_mutex_unlock(&lane->lock);
		/* No unlock inside assert in case assert is compiled out */
		assert(!ret);
	}
	return i;
}

int lane_stream_continue(struct dpdcei_lane *lane)
{
	int ret;

	/* This function is only useful in RECYCLE state. A lane enters
	 * recycle state when a recoverable error occurs. e.g. Running out of
	 * output buffer memory during decompression and then being able to
	 * continue from where DCE stopped processing
	 */
	assert(lane->paradigm == DCE_STATEFUL_RECYCLE);
	ret = pthread_mutex_lock(&lane->lock);
	assert(!ret);
	/* This function should not be called twice in a row or in combination
	 * with stream_abort()
	 */
	assert(!lane->recycle);
	lane->recycle = true;
	/* This function should not be called if the lane did not encounter a
	 * suspend frame
	 */
	assert(lane->recycle_todo);
	/* recycler_allow[s] recycle() and discard(). This function should not
	 * be called unless the recycler is blocked due to a new suspend op
	 */
	assert(!lane->recycler_allowed);
	lane->recycler_allowed = true;
	/* We change lane state here because it is used during the enqueue to
	 * determine whether to treat the next frame as a new stream or a
	 * continuation of the suspended stream. Normally stream continue would
	 * mean the driver should set initial to false. The issue is that in
	 * recycle the DCE expects the recycle frame to have the same initial
	 * bit set as it was sent in the first time. Meaning that if the first
	 * frame caused a suspend (initial = true) then it should be recycled
	 * with the initial bit set the same way (initial = true)
	 */
	lane->state = lane->initial_store ? STREAM_END : FULLY_PROCESSED;
	ret = pthread_mutex_unlock(&lane->lock);
	assert(!ret);
	return 0;
}

int lane_stream_abort(struct dpdcei_lane *lane)
{
	int ret;

	/* This function is only useful in RECYCLE state. A lane enters
	 * recycle state when a recoverable error occurs. e.g. Running out of
	 * output buffer memory during decompression and then being able to
	 * continue from where DCE stopped processing
	 */
	assert(lane->paradigm == DCE_STATEFUL_RECYCLE);
	ret = pthread_mutex_lock(&lane->lock);
	assert(!ret);
	/* This function should not be called if the lane did not encounter a
	 * suspend frame
	 */
	assert(lane->recycle_todo);
	/* recycle_allow[s] recycle() and discard(). This function should not
	 * be called unless the recycler is blocked due to a new suspend op
	 */
	assert(!lane->recycler_allowed);
	lane->recycler_allowed = true;
	/* We change lane state here because it is used during the enqueue to
	 * determine whether to treat the next frame as a new stream or a
	 * continuation of the suspended stream. Setting the lane state to
	 * STREAM_END informs the lane_enqueue_*() functions that whatever came
	 * before is unrelated to this current frame
	 */
	lane->state = STREAM_END;
	lane->reset = true;
	ret = pthread_mutex_unlock(&lane->lock);
	assert(!ret);
	return 0;
}

int lane_recycle_fd_pair(struct qbman_swp *swp,
			struct dpdcei_lane *lane,
			struct dce_op_fd_pair_tx *op)
{
	struct work_unit *work_unit;
	struct dpaa2_fd *head_fd;
	struct dpaa2_fd *input_fd;
	struct dpaa2_fd *output_fd;
	struct dpaa2_fd *scf_fd;
	int ret;

	/* Recycle mode is only applicable in stateful sessions */
	assert(lane->paradigm == DCE_STATEFUL_RECYCLE);
	ret = pthread_mutex_trylock(&lane->lock);
	if (ret) {
		/* EBUSY is the only expected error because another
		 * thread might have the lock for dequeue
		 */
		assert(ret == EBUSY);
		return -EBUSY;
	}

	if (!lane->recycler_allowed) {
		/* Recycle is only allowed if a suspend frame was received and
		 * one of stream_continue() and stream_abort() is called
		 */
		ret = -EACCES;
		goto err_not_allowed;
	}

	assert(lane->recycle_todo > 0);

	work_unit = circ_fifo_alloc(&lane->fifo);
	if (!work_unit) {
#ifdef DEBUG
		pr_err("Too many DCE requests in flight! backoff!\n");
#endif
		ret = -ENOSPC;
		goto err_no_space;
	}

	memset(work_unit, 0, sizeof(*work_unit));

	/* Must copy the frames over. No way around it because the frames have
	 * to be stored in a contiguous frame list
	 */
	work_unit->store.input_fd = *op->input_fd;
	work_unit->store.output_fd = *op->output_fd;

	/* reorient the pointers in my stack to point to the copy for
	 * convenience in later usage
	 */
	input_fd = &work_unit->store.input_fd;
	output_fd = &work_unit->store.output_fd;

	/* do the same for our scf_fd and the head_fd */
	head_fd = &work_unit->head_fd;
	scf_fd = &work_unit->store.scf_fd;

	/* we only need to do setup work for the SCF because the input and
	 * output were passed in with correct setup by our caller
	 */

	/* SCF */
	dpaa2_sg_set_final((struct dpaa2_sg_entry *)scf_fd, 1);
	dpaa2_fd_set_addr(scf_fd, (dma_addr_t) &work_unit->scf_result);
	dpaa2_fd_set_len(scf_fd, sizeof(struct scf_c_cfg));

	/* FD */
	fd_set_ivp(head_fd, true); /* bpid is invalid */
	dpaa2_fd_set_len(head_fd, dpaa2_fd_get_len(input_fd));
	dpaa2_fd_set_format(head_fd, dpaa2_fd_list);
	dpaa2_fd_set_addr(head_fd, (dma_addr_t)work_unit->store.fd_list_store);
	/* We set the FLC (lane context) field in the FD to the address of the
	 * FCR (lane context record). The FLC field is not strictly always a
	 * pointer to the FCR memory. When the DCE processes the frame it
	 * updates the FLC field to the software dpdcei_lane object that sent
	 * the FD. This way software can match the FD upon dequeueing it to the
	 * correct software owner */
	dpaa2_fd_set_flc(head_fd, (dma_addr_t)lane->flow_context_record);
#ifdef NOP_TEST
	fd_frc_set_cmd(head_fd, DCE_CMD_NOP);
#endif
	fd_frc_set_ce(head_fd, lane->compression_effort);
	if (lane->dpdcei->attr.dce_version == ERR008704_DCE_REV)
		/* hardware bug requires the SCR flush to occur every time */
		fd_frc_set_scrf(head_fd, true);
	fd_frc_set_cf(head_fd, lane->compression_format);
	fd_frc_set_sf(head_fd, !!lane->paradigm);
	/* The recycle bit should only be set if the user calls
	 * stream_continue(). This gives the caller the
	 * responsibility of deciding when to acknowledge that a problem has
	 * occurred in processing a stream of data and how to react
	 */
	if (lane->recycle) {
		fd_frc_set_recycle(head_fd, lane->recycle);
		lane->recycle = false;
	}
	if (lane->state == STREAM_END) {
		fd_frc_set_initial(head_fd, true);
		lane->state = FULLY_PROCESSED;
	}
	fd_frc_set_z_flush(head_fd, op->flush);
	if (op->flush == DCE_Z_FINISH)
		lane->state = STREAM_END;
	if (lane->reset) {
		struct work_unit *abort_unit;
		struct dpaa2_fd *abort_fd;
		struct circ_fifo *fifo = &lane->fifo;
		/* Enqueue an empty fd with only a recycle bit set to force the
		 * flow to exit recycle mode. This allows the next FD with uspc
		 * set to clear the history and successfully restart the flow */
		abort_unit = lane->dma_alloc(lane->dma_opaque, 0,
						sizeof(*abort_unit));

		assert(((uint8_t *) abort_unit < (uint8_t *)fifo->mem) ||
			((uint8_t *)abort_unit > ((uint8_t *)fifo->mem + fifo->num_bufs * fifo->buf_size - 1)));
		if (!abort_unit) {
			ret = -ENOSPC;
			goto abort_stream_mem_fail;
		}
		memset(abort_unit, 0, sizeof(*abort_unit));

		dpaa2_fd_set_format(&abort_unit->store.input_fd, dpaa2_fd_null);
		dpaa2_fd_set_len(&abort_unit->store.input_fd, 0);
		dpaa2_fd_set_addr(&abort_unit->store.input_fd,
							(dma_addr_t)NULL);
		dpaa2_fd_set_frc(&abort_unit->store.input_fd, 0xABCDEF22);

		dpaa2_fd_set_len(&abort_unit->store.output_fd,
				lane->pending_output.len);
		dpaa2_fd_set_addr(&abort_unit->store.output_fd,
				(dma_addr_t)lane->pending_output.vaddr);

		dpaa2_sg_set_final(
			(struct dpaa2_sg_entry *)&abort_unit->store.scf_fd, 1);
		dpaa2_fd_set_addr(&abort_unit->store.scf_fd,
				(dma_addr_t) &abort_unit->scf_result);
		dpaa2_fd_set_len(&abort_unit->store.scf_fd,
				sizeof(struct scf_c_cfg));

		abort_fd = &abort_unit->head_fd;
		dpaa2_fd_set_format(abort_fd, dpaa2_fd_list);
		dpaa2_fd_set_len(abort_fd, 0);
		dpaa2_fd_set_addr(abort_fd,
				(dma_addr_t)abort_unit->store.fd_list_store);
		/* We set the FLC (lane context) field in the FD to the address
		 * of the FCR (lane context record). The FLC field is not
		 * strictly always a pointer to the FCR memory. When the DCE
		 * processes the frame it updates the FLC field to the software
		 * dpdcei_lane object that sent the FD. This way software can
		 * match the FD upon dequeueing it to the correct owner */
		dpaa2_fd_set_flc(head_fd,
				(dma_addr_t)lane->flow_context_record);

		fd_frc_set_recycle(abort_fd, true);
		fd_frc_set_sf(abort_fd, true);

		abort_unit->finish_cb = finish_lane_abort_fd;

		ret = enqueue_dpdcei(swp, lane->dpdcei, abort_fd);
		if (ret) {
			lane->dma_free(lane->dma_opaque, abort_unit);
			goto fail_enqueue;
		}

		/* resetting the lane state is done through the stream_abort()
		 * and TODO session_reset() functions both should set the
		 * lane state to STREAM_END and cause the next frame (the one
		 * we are setting up here) to have initial set to true */
		assert(fd_frc_get_initial(head_fd));
		lane->reset = false;
	}
	fd_frc_set_uspc(head_fd, false);
	fd_frc_set_uhc(head_fd, false);

	/* Set caller context */
	work_unit->context = op->user_context;

	/* DCE destroys output buffer length information in skipped and
	 * terminated FD. Must maintain in software
	 */
	work_unit->output_length = dpaa2_fd_get_len(output_fd);

#ifdef DEBUG
	pr_info("dce: Before enqueue\n");
	pretty_print_fd(head_fd);
	pretty_print_fle_n(
		(struct fle_attr *)&work_unit->store.fd_list_store[0], 3);

	hexdump(head_fd, sizeof(*head_fd));
	hexdump(work_unit->store.fd_list_store,
			sizeof(work_unit->store.fd_list_store[0])*3);
#endif

	work_unit->finish_cb = finish_user_fd;
	work_unit->state = TODO;
	ret = enqueue_dpdcei(swp, lane->dpdcei, head_fd);
	if (ret)
		goto fail_enqueue;

	atomic_inc(&lane->frames_in_flight);

	assert(lane->recycle_todo > 0);
	/* recycle is allowed so long as recycle_todo is above 0, but not
	 * always. If we dequeue a second suspend op we have to pause the
	 * recycler mid recycle to force the application to call stream_continue
	 * or stream_abort before they can continue recycle
	 */
	lane->recycler_allowed = --lane->recycle_todo;
	if (!lane->recycler_allowed) {
		sem_post(&lane->enqueue_sem);
		ret = 1; /* Indicate that the lane has exited recycle mode */
	}
	pthread_mutex_unlock(&lane->lock);
	return ret;

abort_stream_mem_fail:
fail_enqueue:
	/* Cannot use circ_fifo_free() because that would change the head index
	 * of the fifo, but we want to return a buffer at the tail index
	 */
	work_unit->state = FREE;
	circ_fifo_alloc_undo(&lane->fifo);
err_no_space:
err_not_allowed:
	pthread_mutex_unlock(&lane->lock);
	return ret;
}

int lane_recycle_discard(struct dpdcei_lane *lane)
{
	int ret = 0, err;

	err = pthread_mutex_lock(&lane->lock);
	assert(!err);
	if (!lane->recycler_allowed) {
		/* Recycle is only allowed if a suspend frame was received and
		 * one of stream_continue() and stream_abort() is called
		 */
		err = pthread_mutex_unlock(&lane->lock);
		assert(!err);
		return -EACCES;
	}
	assert(lane->recycle_todo > 0);
	lane->recycler_allowed = --lane->recycle_todo;
	if (!lane->recycler_allowed) {
		sem_post(&lane->enqueue_sem);
		ret = 1; /* Indicate that the lane has exited recycle mode */
	}
	err = pthread_mutex_unlock(&lane->lock);
	assert(!err);
	return ret;
}


char *dce_status_string(enum dce_status status)
{
	switch (status) {
	case FULLY_PROCESSED:
		return "FULLY_PROCESSED";
	case STREAM_END:
		return "STREAM_END";
	case INPUT_STARVED:
		return "INPUT_STARVED";
	case MEMBER_END_SUSPEND:
		return "MEMBER_END_SUSPEND";
	case Z_BLOCK_SUSPEND:
		return "Z_BLOCK_SUSPEND";
	case OUTPUT_BLOCKED_SUSPEND:
		return "OUTPUT_BLOCKED_SUSPEND";
	case ACQUIRE_DATA_BUFFER_DENIED_SUSPEND:
		return "ACQUIRE_DATA_BUFFER_DENIED_SUSPEND";
	case ACQUIRE_TABLE_BUFFER_DENIED_SUSPEND:
		return "ACQUIRE_TABLE_BUFFER_DENIED_SUSPEND";
	case OLL_REACHED_SUSPEND:
		return "OLL_REACHED_SUSPEND";
	case OUTPUT_BLOCKED_DISCARD:
		return "OUTPUT_BLOCKED_DISCARD";
	case ACQUIRE_DATA_BUFFER_DENIED_DISCARD:
		return "ACQUIRE_DATA_BUFFER_DENIED_DISCARD";
	case ACQUIRE_TABLE_BUFFER_DENIED_DISCARD:
		return "ACQUIRE_TABLE_BUFFER_DENIED_DISCARD";
	case OLL_REACHED_DISCARD:
		return "OLL_REACHED_DISCARD";
	case HCL_REACHED_DISCARD:
		return "HCL_REACHED_DISCARD";
	case HCL_RELEASE_ABORTED:
		return "HCL_RELEASE_ABORTED";
	case SKIPPED:
		return "SKIPPED";
	case PREVIOUS_FLOW_TERMINATION:
		return "PREVIOUS_FLOW_TERMINATION";
	case SUSPENDED_FLOW_TERMINATION:
		return "SUSPENDED_FLOW_TERMINATION";
	case INVALID_FRAME_LIST:
		return "INVALID_FRAME_LIST";
	case INVALID_FRC:
		return "INVALID_FRC";
	case UNSUPPORTED_FRAME:
		return "UNSUPPORTED_FRAME";
	case FRAME_TOO_SHORT:
		return "FRAME_TOO_SHORT";
	case ZLIB_INCOMPLETE_HEADER:
		return "ZLIB_INCOMPLETE_HEADER";
	case ZLIB_HEADER_ERROR:
		return "ZLIB_HEADER_ERROR";
	case ZLIB_NEED_DICTIONARY_ERROR:
		return "ZLIB_NEED_DICTIONARY_ERROR";
	case GZIP_INCOMPLETE_HEADER:
		return "GZIP_INCOMPLETE_HEADER";
	case GZIP_HEADER_ERROR:
		return "GZIP_HEADER_ERROR";
	case DEFLATE_INVALID_BLOCK_TYPE:
		return "DEFLATE_INVALID_BLOCK_TYPE";
	case DEFLATE_INVALID_BLOCK_LENGTHS:
		return "DEFLATE_INVALID_BLOCK_LENGTHS";
	case DEFLATE_TOO_MANY_LEN_OR_DIST_SYM:
		return "DEFLATE_TOO_MANY_LEN_OR_DIST_SYM";
	case DEFLATE_INVALID_CODE_LENGTHS_SET:
		return "DEFLATE_INVALID_CODE_LENGTHS_SET";
	case DEFLATE_INVALID_BIT_LENGTH_REPEAT:
		return "DEFLATE_INVALID_BIT_LENGTH_REPEAT";
	case DEFLATE_INVALID_LITERAL_LENGTHS_SET:
		return "DEFLATE_INVALID_LITERAL_LENGTHS_SET";
	case DEFLATE_INVALID_DISTANCES_SET:
		return "DEFLATE_INVALID_DISTANCES_SET";
	case DEFLATE_INVALID_LITERAL_LENGTH_CODE:
		return "DEFLATE_INVALID_LITERAL_LENGTH_CODE";
	case DEFLATE_INVALID_DISTANCE_CODE:
		return "DEFLATE_INVALID_DISTANCE_CODE";
	case DEFLATE_INVALID_DISTANCE_TOO_FAR_BACK:
		return "DEFLATE_INVALID_DISTANCE_TOO_FAR_BACK";
	case DEFLATE_INCORRECT_DATA_CHECK:
		return "DEFLATE_INCORRECT_DATA_CHECK";
	case DEFLATE_INCORRECT_LENGTH_CHECK:
		return "DEFLATE_INCORRECT_LENGTH_CHECK";
	case DEFLATE_INVALID_CODE:
		return "DEFLATE_INVALID_CODE";
	case CXM_2BIT_ECC_ERROR:
		return "CXM_2BIT_ECC_ERROR";
	case CBM_2BIT_ECC_ERROR:
		return "CBM_2BIT_ECC_ERROR";
	case DHM_2BIT_ECC_ERROR:
		return "DHM_2BIT_ECC_ERROR";
	case INVALID_BASE64_CODE:
		return "INVALID_BASE64_CODE";
	case INVALID_BASE64_PADDING:
		return "INVALID_BASE64_PADDING";
	case SCF_SYSTEM_MEM_READ_ERROR:
		return "SCF_SYSTEM_MEM_READ_ERROR";
	case PENDING_OUTPUT_SYSTEM_MEM_READ_ERROR:
		return "PENDING_OUTPUT_SYSTEM_MEM_READ_ERROR";
	case HISTORY_WINDOW_SYSTEM_MEM_READ_ERROR:
		return "HISTORY_WINDOW_SYSTEM_MEM_READ_ERROR";
	case CTX_DATA_SYSTEM_MEM_READ_ERROR:
		return "CTX_DATA_SYSTEM_MEM_READ_ERROR";
	case FRAME_DATA_SYSTEM_READ_ERROR:
		return "FRAME_DATA_SYSTEM_READ_ERROR";
	case INPUT_FRAME_TBL_SYSTEM_READ_ERROR:
		return "INPUT_FRAME_TBL_SYSTEM_READ_ERROR";
	case OUTPUT_FRAME_TBL_SYSTEM_READ_ERROR:
		return "OUTPUT_FRAME_TBL_SYSTEM_READ_ERROR";
	case SCF_SYSTEM_MEM_WRITE_ERROR:
		return "SCF_SYSTEM_MEM_WRITE_ERROR";
	case PENDING_OUTPUT_SYSTEM_MEM_WRITE_ERROR:
		return "PENDING_OUTPUT_SYSTEM_MEM_WRITE_ERROR";
	case HISTORY_WINDOW_SYSTEM_MEM_WRITE_ERROR:
		return "HISTORY_WINDOW_SYSTEM_MEM_WRITE_ERROR";
	case CTX_DATA_SYSTEM_MEM_WRITE_ERROR:
		return "CTX_DATA_SYSTEM_MEM_WRITE_ERROR";
	case FRAME_DATA_SYSTEM_MEM_WRITE_ERROR:
		return "FRAME_DATA_SYSTEM_MEM_WRITE_ERROR";
	case FRAME_TBL_SYSTEM_MEM_WRITE_ERROR:
		return "FRAME_TBL_SYSTEM_MEM_WRITE_ERROR";
	default:
		return "Unknown status code";
	}
}

