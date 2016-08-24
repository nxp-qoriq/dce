/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#include "dce-scf-compression.h"
#include "dce-scf-decompression.h"
#include "dce.h"
#include <circ_fifo.h>
/* #define debug */

MODULE_AUTHOR("Freescale Semicondictor, Inc");
MODULE_DESCRIPTION("DCE API");
MODULE_LICENSE("Dual BSD/GPL");

/* dma memories that need to be allocated
 *	memory		size			alignment_req
 *
 *	pending_out_ptr	comp: 8202B		none (64B optimal)
 *	pending_out_ptr	decomp: 28k (1024 * 28)	none (64B optimal)
 *	history_ptr	comp: 4096		64B
 *	history_ptr	decomp: 32768		64B
 *	decomp_ctx_ptr	decomp only 256B	none
 *	extra_ptr	extra_limit defines the length for decompression.
 *			no alignment requirements.
 */


enum work_unit_state {
	FREE = 0,
	TODO = 1,
	DONE = 2
};

/* an internal structure that contains information per DCE interaction, this
 * structure is necessary because if the API is used asynchronously the response
 * comes back on the same frame that was sent. If the same frame struct is used
 * for different transactions with DCE then there is a chance that the second
 * response will overwrite the information written by the first */
struct work_unit {
	enum work_unit_state state;
	union store {
		/* faster if aligned */
		struct dpaa2_fd fd_list_store[3] __aligned(64);
		struct {
			struct dpaa2_fd output_fd;
			struct dpaa2_fd input_fd;
			struct dpaa2_fd scf_fd;
			void *context;
		};
	} store;
	struct scf_c_cfg scf_result __aligned(64); /* must 64 byte align */
	struct dpaa2_fd fd_list;
	/* The output fd length is set to zero by dce for skipped fd. Arguably
	 * that is bad because now software must maintain some state to find out
	 * how big the output buffer was. The correct setup would have been to
	 * force software to rely on status to find out output buffer size
	 */
	size_t output_length;
};

int dce_session_notification_arm(struct dce_session *session, void *context)
{
	struct work_unit *work_unit = circ_fifo_head(&session->fifo);

	session->notify_arm = true;
	session->notification_context = context;
	if (work_unit->state == DONE) {
		session->notify_arm = false;
		session->work_done_callback(context);
		/* Illegal to call try to re-arm() in work_done_callback() */
		assert(session->notify_arm == false);
		return 0;
	}
	return 0;
}

#define ALL_DONE 0xA11D09E

static void sync_callback(struct dce_flow *flow, u32 cmd,
					const struct dpaa2_fd *fd)
{
	union store *store = (void *)dpaa2_fd_get_addr(fd);

	/* Set the output frame to indicate the sync is complete */
	dpaa2_fd_set_addr(&store->output_fd, ALL_DONE);
	(void)cmd;
	(void)flow;
}

/* internal_callback - this is the callback that gets triggered by the DCE flow.
 *
 * This simple callback does simple checking the calls a function to trigger the
 * user callback if all checks were passed */
static void internal_callback(struct dce_flow *flow, u32 cmd,
			    const struct dpaa2_fd *fd)
{
	struct dce_session *session = container_of(flow,
						   struct dce_session,
						   flow);
	union store *store = (void *)dpaa2_fd_get_addr(fd);
	struct work_unit *work_unit =
		container_of(store, struct work_unit, store);
	switch ((enum dce_cmd)cmd) {
	case DCE_CMD_NOP:
#ifdef NOP_TEST
		/*trigger_user_callback(session, fd);*/
#else
		pr_info("Received unexpected NOP response in DCE API\n");
		assert(false); /* it is unexpected that the DCE API will send
				* a NOP command, so we should never be here */
#endif
		break;
	case DCE_CMD_CTX_INVALIDATE:
		pr_info("Received unexpected context invalidate in DCE API\n");
		assert(false); /* we should never be here */
		break;
	case DCE_CMD_PROCESS:
#ifdef debug
		pr_info("Received callback for DCE process command\n");
#endif
		assert(!circ_fifo_empty(&session->fifo));
		work_unit->fd_list = *fd;
		work_unit->state = DONE;
		if (session->notify_arm)
			session->work_done_callback(session->notification_context);
		break;
	default:
		pr_info("Unknown cmd %d\n", cmd);
		break;
	}
}

#define COMP_PENDING_OUTPUT_SZ 8202
#define DECOMP_PENDING_OUTPUT_SZ (24 * 1024)
#define PENDING_OUTPUT_ALIGN 64
#define COMP_HISTORY_SZ (4 * 1024)
#define DECOMP_HISTORY_SZ (32 * 1024)
#define HISTORY_ALIGN 64
#define DECOMP_CONTEXT_SZ 256
#define DECOMP_CONTEXT_ALIGN 64

static void free_dce_internals(struct dce_session *session)
{
	struct dma_mem *mem = &session->flow.mem;

	if (session->pending_output.vaddr)
		dma_mem_free(mem, session->pending_output.vaddr);
	if (session->history.vaddr)
		dma_mem_free(mem, session->history.vaddr);
	if (session->decomp_context.vaddr)
		dma_mem_free(mem, session->decomp_context.vaddr);

	session->pending_output.vaddr = session->history.vaddr =
		session->decomp_context.vaddr = NULL;
	session->pending_output.paddr = session->history.paddr =
		session->decomp_context.paddr = 0;
	session->pending_output.len = session->history.len =
		session->decomp_context.len = 0;
}

static int alloc_dce_internals(struct dce_session *session)
{
	struct dma_mem *mem = &session->flow.mem;
	enum dpdcei_engine engine = session->flow.dpdcei->attr.engine;

	if (engine == DPDCEI_ENGINE_COMPRESSION) {
		session->pending_output.len = COMP_PENDING_OUTPUT_SZ;
		session->pending_output.vaddr = dma_mem_memalign(mem,
			PENDING_OUTPUT_ALIGN, session->pending_output.len);
		session->history.len = COMP_HISTORY_SZ;
		session->history.vaddr = dma_mem_memalign(mem,
			 HISTORY_ALIGN, session->history.len);
	} else if (engine == DPDCEI_ENGINE_DECOMPRESSION) {
		session->pending_output.len = DECOMP_PENDING_OUTPUT_SZ;
		session->pending_output.vaddr = dma_mem_memalign(mem,
				PENDING_OUTPUT_ALIGN,
				session->pending_output.len);
		session->history.len = DECOMP_HISTORY_SZ;
		session->history.vaddr = dma_mem_memalign(mem,
			HISTORY_ALIGN, session->history.len);
		session->decomp_context.len = DECOMP_CONTEXT_SZ;
		session->decomp_context.vaddr = dma_mem_memalign(mem,
			DECOMP_CONTEXT_ALIGN, session->decomp_context.len);
	}
	if (!session->pending_output.vaddr || !session->history.vaddr ||
			(!session->decomp_context.vaddr &&
			 (engine == DPDCEI_ENGINE_DECOMPRESSION))) {
		free_dce_internals(session);
		return -ENOMEM;
	}
	memset(session->pending_output.vaddr, 0, session->pending_output.len);
	memset(session->history.vaddr, 0, session->history.len);
	if (session->decomp_context.vaddr)
		memset(session->decomp_context.vaddr, 0,
				session->decomp_context.len);
	return 0;
}

#define GZIP_ID1	0x1f
#define GZIP_ID2	0x8b
#define GZIP_CM		0x08
#define GZIP_COMP_LEVEL	0x04
#define GZIP_OS		0xff
#define GZIP_TEXT	0x01
#define GZIP_HCRC	0x02
#define GZIP_EXTRA	0x04
#define GZIP_NAME	0x08
#define GZIP_COMMENT	0x10

static void setup_gzip_header(struct scf_c_cfg *d, struct dce_gz_header *header)
{
	uint8_t flg = 0;
	scf_c_cfg_set_id1(d, GZIP_ID1);
	scf_c_cfg_set_id2(d, GZIP_ID2);
	scf_c_cfg_set_cm(d, GZIP_CM);
	scf_c_cfg_set_xfl(d, GZIP_COMP_LEVEL);
	if (!header) {
		/* Caller did not provide a header. Fill in default values */
		scf_c_cfg_set_flg(d, 0 /* No NAME no COMMENT no EXTRA */);
		scf_c_cfg_set_mtime(d, 0 /* seconds since 1970. Vestige */);
		scf_c_cfg_set_os(d, GZIP_OS);
		return;
	}
	if (header->text)
		flg |= GZIP_TEXT;
	if (header->hcrc)
		flg |= GZIP_HCRC;
	if (header->extra_len) {
		flg |= GZIP_EXTRA;
		scf_c_cfg_set_xlen(d, header->extra_len);
	}
	if (header->name_len) {
		flg |= GZIP_NAME;
		scf_c_cfg_set_nlen(d, header->name_len);
	}
	if (header->comment_len) {
		flg |= GZIP_COMMENT;
		scf_c_cfg_set_clen(d, header->comment_len);
	}
	scf_c_cfg_set_flg(d, flg);
	scf_c_cfg_set_mtime(d, header->mtime);
	scf_c_cfg_set_os(d, header->os);
	if (flg & GZIP_EXTRA
	    || flg & GZIP_NAME
	    || flg & GZIP_COMMENT)
		assert(header->meta_data);
	scf_c_cfg_set_extra_ptr(d, header->meta_data);
}

int dce_session_create(struct dce_session *session,
		       struct dce_session_params *params)
{
	void *temp;

	/* We do not create the session struct here to allow our user to nest
	 * the session struct in their own structures and recover the container
	 * of the session using container_of() */
	int ret;

	/* We must make clear the session struct here. The session has many
	 * pointers, other functions will assume they are valid if they are not
	 * cleared and attempt to use them */
	*session = (struct dce_session){0};

	ret = dce_flow_create(params->dpdcei, &session->flow);
	if (ret)
		goto fail_flow_create;
	/* No need to configure the flow context record, because the first frame
	 * will carry an SCR with the correct configuration and DCE will update
	 * the FCR to match */

	session->flow.cb = internal_callback;
	session->paradigm = params->paradigm;
	session->compression_format = params->compression_format;
	session->compression_effort = params->compression_effort;
	session->encode_base_64 = params->encode_base_64;
	session->work_done_callback = params->work_done_callback;

	ret = alloc_dce_internals(session);
	if (ret)
		goto fail_dce_internals;

	/* Setup flow circular fifo */
	temp = dma_mem_memalign(&session->flow.mem, 64, 320 * 30000);
	if (!temp) {
		pr_err("Unable to allocate memory for flow fifo");
		goto err_setup_circular_fifo;
	}

	circ_fifo_setup(&session->fifo, temp,
		sizeof(struct work_unit), 30000);

	struct work_unit *work_unit = circ_fifo_alloc(&session->fifo);
	struct dpaa2_fd *fd_list;
	struct dpaa2_fd *scf_fd;
	struct dce_flow *flow = &session->flow;
	enum dpdcei_engine engine = session->flow.dpdcei->attr.engine;

	memset(work_unit, 0, sizeof(*work_unit));

	fd_list = &work_unit->fd_list;
	scf_fd = &work_unit->store.scf_fd;

	dpaa2_fd_set_addr(fd_list, (dma_addr_t)work_unit->store.fd_list_store);
	fd_set_ivp(fd_list, true); /* bpid is invalid */
	fd_frc_set_sf(fd_list, true);
	dpaa2_fd_set_format(fd_list, dpaa2_fd_list);
	dpaa2_fd_set_format(&work_unit->store.output_fd, dpaa2_fd_null);
	dpaa2_fd_set_format(&work_unit->store.input_fd, dpaa2_fd_null);

	dpaa2_sg_set_final((struct dpaa2_sg_entry *)scf_fd, 1);
	dpaa2_fd_set_addr(scf_fd, (dma_addr_t) &work_unit->scf_result);
	dpaa2_fd_set_len(scf_fd, sizeof(struct scf_c_cfg));
	if (session->paradigm == DCE_STATEFUL_RECYCLE)
		scf_c_cfg_set_pmode((struct scf_c_cfg *)&work_unit->scf_result,
				false);
	else
		scf_c_cfg_set_pmode((struct scf_c_cfg *)&work_unit->scf_result,
				true);

	/* FIXME: CM and FLG should be setup differently for GZIP */
	u8 CM, FLG;

	fd_frc_set_uspc(fd_list, true);
	fd_frc_set_uhc(fd_list, true);

	CM = 0x48; /* 8 means Deflate and 4 means a 4 KB compression
		      window these are the only values allowed in DCE */

	FLG = 0x4B; /* 0b_01_0_01011, 01 is the approximate compression
		       effort, the 0 after indicates no dictionary, the
		       01011 is the checksum for CM and FLG and must
		       make CM_FLG a 16 bit number divisible by 31 */
	scf_c_cfg_set_cm((struct scf_c_cfg *)&work_unit->scf_result, CM);
	scf_c_cfg_set_flg((struct scf_c_cfg *)&work_unit->scf_result, FLG);
	scf_c_cfg_set_next_flc(
		(struct scf_c_cfg *)&work_unit->scf_result,
		(uint64_t)flow);
	if (engine == DPDCEI_ENGINE_COMPRESSION) {
		scf_c_cfg_set_pending_output_ptr(
			(struct scf_c_cfg *)&work_unit->scf_result,
			(dma_addr_t)session->pending_output.vaddr);
		scf_c_cfg_set_history_ptr(
			(struct scf_c_cfg *)&work_unit->scf_result,
			(dma_addr_t)session->history.vaddr);
		if (session->compression_format == DCE_CF_GZIP)
			setup_gzip_header(
				(struct scf_c_cfg *)&work_unit->scf_result,
				params->gz_header);
	} else if (engine == DPDCEI_ENGINE_DECOMPRESSION) {
		scf_d_cfg_set_pending_output_ptr(
			(struct scf_d_cfg *)&work_unit->scf_result,
			(dma_addr_t)session->pending_output.vaddr);
		scf_d_cfg_set_history_ptr(
			(struct scf_d_cfg *)&work_unit->scf_result,
			(dma_addr_t)session->history.vaddr);
		scf_d_cfg_set_decomp_ctx_ptr(
			(struct scf_d_cfg *)&work_unit->scf_result,
			(dma_addr_t)session->decomp_context.vaddr);
	} else {
		ret = -EINVAL;
	}

	/* Temporarily redirect incoming frames to handle this setup frame */
	session->flow.cb = sync_callback;
	ret = enqueue_fd(flow, fd_list);
	if (ret)
		pr_err("dce_session initilization failed with err %d", ret);
	while (dpaa2_fd_get_addr(&work_unit->store.output_fd) != ALL_DONE)
		pthread_yield();
	session->flow.cb = internal_callback;

	circ_fifo_free(&session->fifo);

	if (session->paradigm == DCE_STATEFUL_RECYCLE) {
		ret = pthread_mutex_init(&session->lock,
				NULL /* DEFAULT MUTEX */);
		if (ret) {
			pr_err("Got %d in session lock init\n", ret);
			goto fail_mutex_setup;
		}
		/* A mutex cannot be unlocked by a thread other than the one
		 * that locked it. The dequeuer "locks" the semaphore when it
		 * sees a problem frame. The recycler then unlocks the enqueuer
		 * once all problem frames are dealt with. The dequeuer recycler
		 * and enqueuer may be all implemented in one thread or in
		 * multiple threads hence the need for a semaphore
		 */
		ret = sem_init(&session->enqueue_sem,
				0 /* semaphore shared within process only */,
				1 /* allow only one thread */);
		if (ret) {
			pr_err("Got %d in enqueue semaphore init\n", errno);
			goto fail_mutex_setup;
		}

		/* Reset session state so the frist frame is seen as initial */
		session->state = STREAM_END;
	}

	return 0;

fail_mutex_setup:
err_setup_circular_fifo:
	free_dce_internals(session);
fail_dce_internals:
	dce_flow_destroy(&session->flow);
fail_flow_create:
	return ret;
}
EXPORT_SYMBOL(dce_session_create);

int dce_session_destroy(struct dce_session *session)
{
	/* Attempt to destroy the session while frames in flight */
	if (atomic_read(&session->flow.frames_in_flight))
		return -EBUSY;
	free_dce_internals(session);
	dce_flow_destroy(&session->flow);
	return 0;
}
EXPORT_SYMBOL(dce_session_destroy);

int dce_enqueue_fd_pair(struct dce_session *session,
			struct dce_op_fd_pair_tx *op)
{
	struct dce_flow *flow = &session->flow;
	struct work_unit *work_unit;
	struct dpaa2_fd *fd_list;
	struct dpaa2_fd *input_fd;
	struct dpaa2_fd *output_fd;
	struct dpaa2_fd *scf_fd;
	int ret;

	if (session->paradigm == DCE_STATEFUL_RECYCLE) {
		ret = sem_trywait(&session->enqueue_sem);
		if (ret) {
			/* EBUSY is expected because the session might be in
			 * recycle mode, or caller might have two simultaneous
			 * enqueuers . Any other error would be an
			 * implementation bug
			 */
			assert(errno == EAGAIN); /* errno is racy .. oh well*/
			pthread_mutex_lock(&session->lock);
			ret = session->recycle_todo ? -EACCES : -EBUSY;
			pthread_mutex_unlock(&session->lock);
			return ret;
		}
	}

	assert(!session->recycle_todo);

	work_unit = circ_fifo_alloc(&session->fifo);
	if (!work_unit) {
#ifdef debug
		pr_err("Too many DCE rquests in flight! backoff!\n");
#endif
		ret = -ENOSPC;
		goto err_no_space;
	}

	memset(work_unit, 0, sizeof(*work_unit));

	/* if BMan support is enabled and this is the first frame then we need
	 * to do some setup of the SCF. Currently BMan does not function */
	/* dma_condition(session, work_unit); */

	/* Must copy the frames over. No way around it because the frames have
	 * to be stored in a contiguous frame list */
	work_unit->store.input_fd = *op->input_fd;
	work_unit->store.output_fd = *op->output_fd;

	/* reorient the pointers in my stack to point to the copy for
	 * convenience in later usage */
	input_fd = &work_unit->store.input_fd;
	output_fd = &work_unit->store.output_fd;

	/* do the same for our scf_fd and the fd_list */
	fd_list = &work_unit->fd_list;
	scf_fd = &work_unit->store.scf_fd;

	/* we only need to do setup work for the SCF because the input and
	 * output were passed in with correct setup by our caller */

	/* SCF */
	dpaa2_sg_set_final((struct dpaa2_sg_entry *)scf_fd, 1);
	dpaa2_fd_set_addr(scf_fd, (dma_addr_t) &work_unit->scf_result);
	dpaa2_fd_set_len(scf_fd, sizeof(struct scf_c_cfg));
	/* Should setup steless headers here */

	/* FD */
	fd_set_ivp(fd_list, true); /* bpid is invalid */
	dpaa2_fd_set_len(fd_list, dpaa2_fd_get_len(input_fd));
	dpaa2_fd_set_format(fd_list, dpaa2_fd_list);
	dpaa2_fd_set_addr(fd_list, (dma_addr_t)work_unit->store.fd_list_store);
#ifdef NOP_TEST
	fd_frc_set_cmd(fd_list, DCE_CMD_NOP);
#endif
	fd_frc_set_ce(fd_list, session->compression_effort);
	if (session->flow.dpdcei->attr.dce_version == ERR008704_DCE_REV)
		/* hardware bug requires the SCR flush to occur every time */
		fd_frc_set_scrf(fd_list, true);
	fd_frc_set_cf(fd_list, session->compression_format);
	fd_frc_set_sf(fd_list, !!session->paradigm);
	if (session->recycle) {
		/* Why worry about the recycle bit in enqueue_() when it is
		 * taken care of by two dedicate functions recycle_()?
		 * There is one case where this does not work. If an application
		 * discards all outstanding operations and wishes to resume
		 * enqueues normally. DCE will return rejections since it was
		 * not informed of this decision. The recycle bit set here
		 * ensures that DCE is informed so it can continue work
		 */
		fd_frc_set_recycle(fd_list, session->recycle);
		session->recycle = false;
	}
	if (session->paradigm != DCE_STATELESS) {
		/* These setting are assumed by DCE in Stateless mode. Setting
		 * should have no effect, but it was observed to negatively
		 * impact throughput in Stateless mode */
		if (session->state == STREAM_END) {
			fd_frc_set_initial(fd_list, true);
			session->state = FULLY_PROCESSED;
		}
		fd_frc_set_z_flush(fd_list, op->flush);
		if (op->flush == DCE_Z_FINISH)
			session->state = STREAM_END;
	}
	fd_frc_set_uspc(fd_list, false);
	fd_frc_set_uhc(fd_list, false);

	/* Set caller context */
	work_unit->store.context = op->user_context;

	/* DCE destroys output buffer length information in skipped and
	 * terminated FD. Must maintain in software
	 */
	work_unit->output_length = dpaa2_fd_get_len(output_fd);

#ifdef debug
	pr_info("dce: Before enqueue\n");
	pretty_print_fd(fd_list);
	pretty_print_fle_n(
		(struct fle_attr *)&work_unit->store.fd_list_store[0], 3);

	hexdump(fd_list, sizeof(*fd_list));
	hexdump(work_unit->store.fd_list_store,
			sizeof(work_unit->store.fd_list_store[0])*3);
#endif

	/* enqueue request */
	ret = enqueue_fd(flow, fd_list);
	if (session->paradigm == DCE_STATEFUL_RECYCLE)
		sem_post(&session->enqueue_sem);
	if (ret)
		goto fail_enqueue;

	work_unit->state = TODO;

	return 0;

fail_enqueue:
	/* Cannot use circ_fifo_free() because that would change the head index
	 * of the fifo, but we want to return a buffer at the tail index
	 */
	circ_fifo_alloc_undo(&session->fifo);
err_no_space:
	if (session->paradigm == DCE_STATEFUL_RECYCLE)
		sem_post(&session->enqueue_sem);
	return ret;
}
EXPORT_SYMBOL(dce_enqueue_fd_pair);

#define EMPTY_DPAA_FD {.words = {0, 0, 0, 0, 0, 0, 0, 0} }

int dce_dequeue_fd_pair(struct dce_session *session,
			struct dce_op_fd_pair_rx *ops,
			unsigned int num_ops)
{
	struct work_unit *work_unit = circ_fifo_head(&session->fifo);
	unsigned int i, ret;

	if (session->paradigm == DCE_STATEFUL_RECYCLE) {
		ret = pthread_mutex_trylock(&session->lock);
		if (ret) {
			/* EBUSY is the only expected error because another
			 * thread might have the lock for recycle
			 */
			assert(ret == EBUSY);
			return 0;
		}
	}

	for (i = 0;
		i < num_ops && work_unit->state == DONE;
		i++, work_unit = circ_fifo_head(&session->fifo)) {
		work_unit->state = FREE;
		/* We should be checking at > 1, but there is a small chance
		 * for a race where the enqueuer alloced the work_unit but did
		 * not yet set it to todo. This is because the enqueuer and
		 * dequeuer do not share the same lock to reduce contention
		 */
		if (circ_fifo_num_alloc(&session->fifo) > 2) {
			/* If there is a gap of free work units between the
			 * consumer and the producer then there is bug in the
			 * circular fifo usage scheme. Likely in the enqueue
			 * functions.
			 * Long assert line so that removing assert at compile
			 * time also removes the if statement
			 */
			assert(((struct work_unit *)circ_fifo_head_seek(
					&session->fifo, 1))->state != FREE);
		}
		ops[i].input_fd = work_unit->store.input_fd;
		ops[i].output_fd = work_unit->store.output_fd;
		ops[i].status =
			fd_frc_get_status(&work_unit->fd_list);
		ops[i].flush = fd_frc_get_z_flush(&work_unit->fd_list);
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
			if (!session->recycle_todo) {
				ret = sem_wait(&session->enqueue_sem);
				assert(!ret);
			}
			session->recycler_allowed = false;
			session->recycle_todo += circ_fifo_num_alloc(
					&session->fifo);
			ops[i].input_consumed = scf_c_result_get_bytes_processed(
					(struct scf_c_result *)
					&work_unit->scf_result);
			break;
		case SKIPPED:
			/* DCE will never skip an op unless there was one before
			 * it that was *_SUSPEND
			 */
			assert(session->recycle_todo);
			ops[i].input_consumed = 0;

			/* DCE destroys output buffer length information in
			 * skipped and terminated FDs. Recover from software
			 */
			dpaa2_fd_set_len(&ops[i].output_fd,
					work_unit->output_length);
			break;
		default:
			/* Some other unexpected type of status, no processed */
			ops[i].input_consumed = 0;

			/* DCE destroys output buffer length information in
			 * skipped and terminated FDs. Recover from software
			 */
			dpaa2_fd_set_len(&ops[i].output_fd,
					work_unit->output_length);

			/* A terminal error may occur on a recycle op. It is not
			 * possible to recover the session state in that case
			 */
			if (session->paradigm == DCE_STATEFUL_RECYCLE &&
					session->recycle_todo) {
				session->recycle_todo = 0;
				session->recycler_allowed = false;
				/* Unlock regular enqueues */
				ret = sem_post(&session->enqueue_sem);
				assert(!ret);
			}
			break;
		}
		ops[i].user_context = work_unit->store.context;
		circ_fifo_free(&session->fifo);
	}
	if (session->paradigm == DCE_STATEFUL_RECYCLE) {
		ret = pthread_mutex_unlock(&session->lock);
		/* No unlock inside assert in case assert is compiled out */
		assert(!ret);
	}
	return i;
}
EXPORT_SYMBOL(dce_dequeue_fd_pair);


int dce_stream_abort(struct dce_session *session)
{
	int ret;

	/* This function is only useful in RECYCLE state. A session enters
	 * recycle state when a recoverable error occurs. e.g. Running out of
	 * output buffer memory during decompression and then being able to
	 * continue from where DCE stopped processing
	 */
	assert(session->paradigm == DCE_STATEFUL_RECYCLE);
	ret = pthread_mutex_lock(&session->lock);
	assert(!ret);
	/* This function should not be called twice in a row or in combination
	 * with stream_abort()
	 */
	assert(!session->recycle);
	session->recycle = true;
	/* This function should not be called if the session did not encounter a
	 * suspend frame
	 */
	assert(session->recycle_todo);
	/* recycle_allow[s] recycle() and discard(). This function should not
	 * be called unless the recycler is blocked due to a new suspend op
	 */
	assert(!session->recycler_allowed);
	session->recycler_allowed = true;
	/* We change session state here because it is used during the enqueue to
	 * determine whether to treat the next frame as a new stream or a
	 * continuation of the suspended stream. Setting the session state to
	 * STREAM_END informs the dce_enqueue_*() functions that whatever came
	 * before is unrelated to this current frame
	 */
	session->state = STREAM_END;
	ret = pthread_mutex_unlock(&session->lock);
	assert(!ret);
	return 0;
}
EXPORT_SYMBOL(dce_stream_abort);

int dce_stream_continue(struct dce_session *session)
{
	int ret;

	/* This function is only useful in RECYCLE state. A session enters
	 * recycle state when a recoverable error occurs. e.g. Running out of
	 * output buffer memory during decompression and then being able to
	 * continue from where DCE stopped processing
	 */
	assert(session->paradigm == DCE_STATEFUL_RECYCLE);
	ret = pthread_mutex_lock(&session->lock);
	assert(!ret);
	/* This function should not be called twice in a row or in combination
	 * with stream_abort()
	 */
	assert(!session->recycle);
	session->recycle = true;
	/* This function should not be called if the session did not encounter a
	 * suspend frame
	 */
	assert(session->recycle_todo);
	/* recycler_allow[s] recycle() and discard(). This function should not
	 * be called unless the recycler is blocked due to a new suspend op
	 */
	assert(!session->recycler_allowed);
	session->recycler_allowed = true;
	/* We change session state here because it is used during the enqueue to
	 * determine whether to treat the next frame as a new stream or a
	 * continuation of the suspended stream. Setting the session state to
	 * FULLY_PROCESSED informs the dce_enqueue_*() functions that this frame
	 * should be treated as a continuation of previous data
	 */
	session->state = FULLY_PROCESSED;
	ret = pthread_mutex_unlock(&session->lock);
	assert(!ret);
	return 0;
}
EXPORT_SYMBOL(dce_stream_continue);

int dce_recycle_discard(struct dce_session *session)
{
	int ret;

	ret = pthread_mutex_lock(&session->lock);
	assert(!ret);
	if (!session->recycler_allowed) {
		/* Recycle is only allowed if a suspend frame was received and
		 * one of stream_continue() and stream_abort() is called
		 */
		ret = pthread_mutex_unlock(&session->lock);
		assert(!ret);
		return -EACCES;
	}
	assert(session->recycle_todo > 0);
	session->recycler_allowed = --session->recycle_todo;
	if (!session->recycler_allowed) {
		sem_post(&session->enqueue_sem);
		ret = 1; /* Indicate that the session has exited recycle mode */
	}
	ret = pthread_mutex_unlock(&session->lock);
	assert(!ret);
	return 0;
}
EXPORT_SYMBOL(dce_recycle_discard);


int dce_recycle_fd_pair(struct dce_session *session,
			struct dce_op_fd_pair_tx *op)
{
	struct dce_flow *flow = &session->flow;
	struct work_unit *work_unit;
	struct dpaa2_fd *fd_list;
	struct dpaa2_fd *input_fd;
	struct dpaa2_fd *output_fd;
	struct dpaa2_fd *scf_fd;
	int ret;

	/* Recycle mode is only applicable in stateful sessions */
	assert(session->paradigm == DCE_STATEFUL_RECYCLE);
	ret = pthread_mutex_trylock(&session->lock);
	if (ret) {
		/* EBUSY is the only expected error because another
		 * thread might have the lock for dequeue
		 */
		assert(ret == EBUSY);
		return -EBUSY;
	}

	if (!session->recycler_allowed) {
		/* Recycle is only allowed if a suspend frame was received and
		 * one of stream_continue() and stream_abort() is called
		 */
		ret = -EACCES;
		goto err_not_allowed;
	}

	assert(session->recycle_todo > 0);

	work_unit = circ_fifo_alloc(&session->fifo);
	if (!work_unit) {
#ifdef debug
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

	/* do the same for our scf_fd and the fd_list */
	fd_list = &work_unit->fd_list;
	scf_fd = &work_unit->store.scf_fd;

	/* we only need to do setup work for the SCF because the input and
	 * output were passed in with correct setup by our caller
	 */

	/* SCF */
	dpaa2_sg_set_final((struct dpaa2_sg_entry *)scf_fd, 1);
	dpaa2_fd_set_addr(scf_fd, (dma_addr_t) &work_unit->scf_result);
	dpaa2_fd_set_len(scf_fd, sizeof(struct scf_c_cfg));
	/* Should setup steless headers here */

	/* FD */
	fd_set_ivp(fd_list, true); /* bpid is invalid */
	dpaa2_fd_set_len(fd_list, dpaa2_fd_get_len(input_fd));
	dpaa2_fd_set_format(fd_list, dpaa2_fd_list);
	dpaa2_fd_set_addr(fd_list, (dma_addr_t)work_unit->store.fd_list_store);
#ifdef NOP_TEST
	fd_frc_set_cmd(fd_list, DCE_CMD_NOP);
#endif
	fd_frc_set_ce(fd_list, session->compression_effort);
	if (session->flow.dpdcei->attr.dce_version == ERR008704_DCE_REV)
		/* hardware bug requires the SCR flush to occur every time */
		fd_frc_set_scrf(fd_list, true);
	fd_frc_set_cf(fd_list, session->compression_format);
	fd_frc_set_sf(fd_list, !!session->paradigm);
	/* The recycle bit should only be set if the user calls
	 * stream_continue() or stream_abort(). This gives the caller the
	 * responsibility of deciding when to acknowledge that a problem has
	 * occurred in processing a stream of data and how to react
	 */
	fd_frc_set_recycle(fd_list, session->recycle);
	session->recycle = false;
	if (session->state == STREAM_END) {
		fd_frc_set_initial(fd_list, true);
		session->state = FULLY_PROCESSED;
	}
	fd_frc_set_z_flush(fd_list, op->flush);
	if (op->flush == DCE_Z_FINISH)
		session->state = STREAM_END;
	fd_frc_set_uspc(fd_list, false);
	fd_frc_set_uhc(fd_list, false);

	/* Set caller context */
	work_unit->store.context = op->user_context;

	/* DCE destroys output buffer length information in skipped and
	 * terminated FD. Must maintain in software
	 */
	work_unit->output_length = dpaa2_fd_get_len(output_fd);

#ifdef debug
	pr_info("dce: Before enqueue\n");
	pretty_print_fd(fd_list);
	pretty_print_fle_n(
		(struct fle_attr *)&work_unit->store.fd_list_store[0], 3);

	hexdump(fd_list, sizeof(*fd_list));
	hexdump(work_unit->store.fd_list_store,
			sizeof(work_unit->store.fd_list_store[0])*3);
#endif

	ret = enqueue_fd(flow, fd_list);
	if (ret)
		goto fail_enqueue;

	assert(session->recycle_todo > 0);
	/* recycle is allowed so long as recycle_todo is above 0, but not
	 * always. If we dequeue a second suspend op we have to pause the
	 * recycler mid recycle to force the application to call stream_continue
	 * or stream_abort before they can continue recycle
	 */
	session->recycler_allowed = --session->recycle_todo;
	if (!session->recycler_allowed) {
		sem_post(&session->enqueue_sem);
		ret = 1; /* Indicate that the session has exited recycle mode */
	}
	work_unit->state = TODO;
	pthread_mutex_unlock(&session->lock);
	return ret;

fail_enqueue:
	/* Cannot use circ_fifo_free() because that would change the head index
	 * of the fifo, but we want to return a buffer at the tail index
	 */
	circ_fifo_alloc_undo(&session->fifo);
err_no_space:
err_not_allowed:
	pthread_mutex_unlock(&session->lock);
	return ret;
}
EXPORT_SYMBOL(dce_recycle_fd_pair);

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
