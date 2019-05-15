/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2019 NXP
 * All rights reserved.
 */

#include <assert.h>
#include "dce-internals.h"
#include "dce-scf-decompression.h"

/* Allocates dma memory regions used by DCE to maintain the state of a lane */
int alloc_lane_hw_mem(struct dpdcei_lane *lane)
{
	enum dpdcei_engine engine = lane->dpdcei->attr.engine;

	lane->flow_context_record = lane->dma_alloc(lane->dma_opaque, FCR_ALIGN,
					sizeof(*lane->flow_context_record));
	if (!lane->flow_context_record)
		return -ENOMEM;
	memset(lane->flow_context_record, 0,
			sizeof(*lane->flow_context_record));
	if (lane->paradigm == DCE_STATELESS) {
		/* Ensure no state is maintained in stateless mode */
		lane->pending_output.vaddr = lane->history.vaddr =
					lane->decomp_context.vaddr = NULL;
		lane->pending_output.len = lane->history.len =
					lane->decomp_context.len = 0;
		return 0;
	}
	assert(lane->paradigm == DCE_STATEFUL_RECYCLE);

	if (engine == DPDCEI_ENGINE_COMPRESSION) {
		lane->pending_output.len = COMP_PENDING_OUTPUT_SZ;
		lane->pending_output.vaddr = lane->dma_alloc(lane->dma_opaque,
			PENDING_OUTPUT_ALIGN, lane->pending_output.len);
		lane->history.len = COMP_HISTORY_SZ;
		lane->history.vaddr = lane->dma_alloc(lane->dma_opaque,
			 HISTORY_ALIGN, lane->history.len);
	} else if (engine == DPDCEI_ENGINE_DECOMPRESSION) {
		lane->pending_output.len = DECOMP_PENDING_OUTPUT_SZ;
		lane->pending_output.vaddr = lane->dma_alloc(lane->dma_opaque,
				PENDING_OUTPUT_ALIGN,
				lane->pending_output.len);
		lane->history.len = DECOMP_HISTORY_SZ;
		lane->history.vaddr = lane->dma_alloc(lane->dma_opaque,
			HISTORY_ALIGN, lane->history.len);
		lane->decomp_context.len = DECOMP_CONTEXT_SZ;
		lane->decomp_context.vaddr = lane->dma_alloc(lane->dma_opaque,
			DECOMP_CONTEXT_ALIGN, lane->decomp_context.len);
	}

	if (!lane->pending_output.vaddr || !lane->history.vaddr ||
			(!lane->decomp_context.vaddr &&
			 (engine == DPDCEI_ENGINE_DECOMPRESSION))) {
		free_lane_hw_mem(lane);
		return -ENOMEM;
	}

	memset(lane->pending_output.vaddr, 0, lane->pending_output.len);
	memset(lane->history.vaddr, 0, lane->history.len);

	if (lane->decomp_context.vaddr)
		memset(lane->decomp_context.vaddr, 0,
				lane->decomp_context.len);
	return 0;
}

void free_lane_hw_mem(struct dpdcei_lane *lane)
{
	assert(lane->flow_context_record);
	lane->dma_free(lane->dma_opaque, lane->flow_context_record);

	if (lane->pending_output.vaddr)
		lane->dma_free(lane->dma_opaque, lane->pending_output.vaddr);

	if (lane->history.vaddr)
		lane->dma_free(lane->dma_opaque, lane->history.vaddr);

	if (lane->decomp_context.vaddr)
		lane->dma_free(lane->dma_opaque, lane->decomp_context.vaddr);

	lane->pending_output.vaddr = lane->history.vaddr =
		lane->decomp_context.vaddr = NULL;

	lane->pending_output.len = lane->history.len =
		lane->decomp_context.len = 0;
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

void setup_gzip_header(struct scf_c_cfg *d,
				struct lane_gz_header *header)
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

/**
 * finish_lane_setup_fd() - Receive fd indicating lane setup is complete
 * @fd - Setup frame descriptor
 */
void finish_lane_setup_fd(const struct dpaa2_fd *fd)
{
	struct dpdcei_lane *lane = (struct dpdcei_lane *)fd_get_flc_64(fd);
	struct work_unit *work_unit =
		container_of(dpaa2_fd_get_addr(fd), struct work_unit, store);

	if (!lane) {
		/* May occur because a uspc was sent without correct
		 * NEXT_FLC field */
		printf("Received a frame with no Flow information. Paused for debug\n");
		getchar();
	}

	/* Ensure this is not a mis-directed frame for lane reset */
	if (lane->pending_output.vaddr)
		assert(dpaa2_fd_get_addr(&work_unit->store.output_fd) !=
			(dma_addr_t) lane->pending_output.vaddr);

	assert(!circ_fifo_empty(&lane->fifo));

	/* A normal work_unit may have a user context assigned, but the user
	 * never has access to the work_unit struct. Thus we use the work_unit
	 * pointer as a signature to sign off that this is a driver FD */
	work_unit->context = work_unit;
	work_unit->head_fd = *fd;
	work_unit->state = DONE;
}

/**
 * send_init_frame() - Sets up and sends a lane initialization frame
 * @swp:	Software portal to be used for enqueuing the init frame
 * @lane:	lane being setup
 * @work_unit:	work_unit allocated in dma-able memory for the setup frame
 *
 * Return:	0 on successful setup and enqueue, -EBUSY otherwise
 */
int send_init_frame(struct qbman_swp *swp,
		    struct dpdcei_lane *lane,
		    struct work_unit *work_unit)
{
	struct dpaa2_fd *head_fd;
	struct dpaa2_fd *scf_fd;
	enum dpdcei_engine engine = lane->dpdcei->attr.engine;

	memset(work_unit, 0, sizeof(*work_unit));

	head_fd = &work_unit->head_fd;
	scf_fd = &work_unit->store.scf_fd;

	dpaa2_fd_set_addr(head_fd, (dma_addr_t)work_unit->store.fd_list_store);
	fd_set_ivp(head_fd, true); /* bpid is invalid */
	fd_frc_set_cmd(head_fd, DCE_CMD_PROCESS);
	fd_frc_set_sf(head_fd, true);
	/* We set the FLC (lane context) field in the FD to the address of the
	 * FCR (lane context record). The FLC field is not strictly always a
	 * pointer to the FCR memory. When the DCE processes the frame it
	 * updates the FLC field to the software dpdcei_lane object that sent
	 * the FD. This way software can match the FD upon dequeueing it to the
	 * correct software owner */
	dpaa2_fd_set_flc(head_fd, (dma_addr_t)lane->flow_context_record);
	dpaa2_fd_set_format(head_fd, dpaa2_fd_list);

	dpaa2_fd_set_format(&work_unit->store.output_fd, dpaa2_fd_null);
	dpaa2_fd_set_format(&work_unit->store.input_fd, dpaa2_fd_null);

	dpaa2_sg_set_final((struct dpaa2_sg_entry *)scf_fd, 1);
	dpaa2_fd_set_addr(scf_fd, (dma_addr_t) &work_unit->scf_result);
	dpaa2_fd_set_len(scf_fd, sizeof(struct scf_c_cfg));
	if (lane->paradigm == DCE_STATEFUL_RECYCLE)
		scf_c_cfg_set_pmode((struct scf_c_cfg *)&work_unit->scf_result,
				false);
	else
		scf_c_cfg_set_pmode((struct scf_c_cfg *)&work_unit->scf_result,
				true);

	/* FIXME: CM and FLG should be setup differently for GZIP */
	u8 CM, FLG;

	fd_frc_set_uspc(head_fd, true);
	fd_frc_set_uhc(head_fd, true);

	CM = 0x48; /* 8 means Deflate and 4 means a 4 KB compression
		      window these are the only values allowed in DCE */

	FLG = 0x4B; /* 0b_01_0_01011, 01 is the approximate compression
		       effort, the 0 after indicates no dictionary, the
		       01011 is the checksum for CM and FLG and must
		       make CM_FLG a 16 bit number divisible by 31 */
	scf_c_cfg_set_cm((struct scf_c_cfg *)&work_unit->scf_result, CM);
	scf_c_cfg_set_flg((struct scf_c_cfg *)&work_unit->scf_result, FLG);
	scf_c_cfg_set_next_flc((struct scf_c_cfg *)&work_unit->scf_result,
				(uint64_t)lane);
	if (engine == DPDCEI_ENGINE_COMPRESSION) {
		scf_c_cfg_set_pending_output_ptr(
			(struct scf_c_cfg *)&work_unit->scf_result,
			(dma_addr_t)lane->pending_output.vaddr);
		scf_c_cfg_set_history_ptr(
			(struct scf_c_cfg *)&work_unit->scf_result,
			(dma_addr_t)lane->history.vaddr);
		if (lane->compression_format == DCE_CF_GZIP)
			setup_gzip_header(
				(struct scf_c_cfg *)&work_unit->scf_result,
				lane->gz_header);
	} else if (engine == DPDCEI_ENGINE_DECOMPRESSION) {
		scf_d_cfg_set_pending_output_ptr(
			(struct scf_d_cfg *)&work_unit->scf_result,
			(dma_addr_t)lane->pending_output.vaddr);
		scf_d_cfg_set_history_ptr(
			(struct scf_d_cfg *)&work_unit->scf_result,
			(dma_addr_t)lane->history.vaddr);
		scf_d_cfg_set_decomp_ctx_ptr(
			(struct scf_d_cfg *)&work_unit->scf_result,
			(dma_addr_t)lane->decomp_context.vaddr);
	} else {
		pr_err("Unexpected dpdcei engine type. Only compression and decompression allowed\n");
		return -EINVAL;
	}

	work_unit->context = NULL;

	work_unit->state = TODO;

	work_unit->finish_cb = finish_lane_setup_fd;

	return enqueue_dpdcei(swp, lane->dpdcei, head_fd);
}

void finish_lane_abort_fd(const struct dpaa2_fd *fd)
{
	struct dpdcei_lane *lane = (struct dpdcei_lane *)fd_get_flc_64(fd);
	struct work_unit *work_unit =
		container_of(dpaa2_fd_get_addr(fd), struct work_unit, store);

	if (!lane->pending_output.vaddr) {
		pr_err("Unexpected lane abort handler called on a stateless lane?\n");
		assert(false);
		return;
	}
	if (dpaa2_fd_get_addr(&work_unit->store.output_fd) !=
			(dma_addr_t) lane->pending_output.vaddr) {
		pr_err("Unexpected lane abort handler called but the output address is not what it should be\n");
		assert(false);
		return;
	}
	/* We trick the DCE into emptying the pending output buffer into itself
	 * to force exit the lane from SUSPEND mode */
	lane->dma_free(&lane->dma_opaque, work_unit);
}



/**
 * finish_user_fd() - Process finished work and flag user frames as done
 * @fd:	User frame descriptor
 */
void finish_user_fd(const struct dpaa2_fd *fd)
{
	struct dpdcei_lane *lane;
	enum dce_cmd cmd = fd_frc_get_cmd(fd);
#ifdef DEBUG
	static struct work_unit *prev_work;
#endif
	union store *store = (void *)dpaa2_fd_get_addr(fd);
	struct work_unit *work_unit =
		container_of(store, struct work_unit, store);
#ifdef DEBUG
	if (!prev_work)
		prev_work = lane->fifo.mem;

	if (work_unit != (prev_work + 1) && work_unit != lane->fifo.mem) {
		printf("Line %d Mem start is %p and work_unit we got is %p and the previous work_unit was %p\n",
				__LINE__, lane->fifo.mem, work_unit, prev_work);
		getchar();
	}

	prev_work = work_unit;
#endif

	assert(cmd == DCE_CMD_PROCESS);

	/* No need for lookup in process. DCE sets the FLC field
	 * correctly in the outgoing frame based on the NEXT_FLC field
	 * programmed in the Flow Context Record */
	assert(lane = (struct dpdcei_lane *)fd_get_flc_64(fd));
	assert(!circ_fifo_empty(&lane->fifo));
	work_unit->head_fd = *fd;
#ifdef DEBUG
	pr_info("Received callback for DCE process command\n");
#endif

#ifdef DEBUG
	if (work_unit->state != TODO) {
		pr_info("work_unit found in unexpected state %s. Expected TODO\n",
				work_unit->state == FREE ? "FREE" : "DONE");
		getchar();
	}
	if ((work_unit - 1)->state == TODO) {
		pr_err("previous work_unit found in unexpected state TODO\n");
		getchar();
	}
#endif
	work_unit->state = DONE;
}

/**
 * attempt_pull_fq() - Attempt to issue a pull command once
 * @swp:	Issue pull command on this software portal
 * @fqid:	Target frame queue
 * @store:	dq store accessible to qbman to write out dq responses
 *
 * Return:	0 on success, -EBUSY if the portal is not able to take command
 */
static inline int attempt_pull_fq(struct qbman_swp *swp,
				  u32 fqid,
				  struct dq_store *store)
{
	struct qbman_pull_desc pd;

	store->pull_swp = swp;

	qbman_pull_desc_clear(&pd);
	qbman_pull_desc_set_storage(&pd, store->addr,
				   (dma_addr_t)store->addr /* phys = virt */,
				   1 /* stash dq to L3 cache */);
	qbman_pull_desc_set_numframes(&pd, store->max_dq);
	qbman_pull_desc_set_fq(&pd, fqid);
	return qbman_swp_pull(swp, &pd);
}

/**
 * issue_pull_command() - issue a pull command until it succeeds or reach limit
 * @swp:	Issue pull command on this software portal
 * @fqid:	Target frame queue
 * @store:	dq store accessible to qbman to write out dq responses
 *
 * Return:	0 on success, -EAGAIN otherwise
 */
static inline int issue_pull_command(struct qbman_swp *swp, uint32_t fqid,
						struct dq_store *store)
{
	const unsigned int max_pull_trys = 10;
	int err;
	unsigned int i;
	/* Issue a pull command against the dpdcei */
	for (i = 0, err = 1; i < max_pull_trys && err; i++)
		err = attempt_pull_fq(swp, fqid, store);
	return err;
}

/**
 * dq_store_next() - Return dq when it becomes available
 * @store:		Dequeue storage location at which qman is writing dequeues
 * @is_last:	`returns' true if no more dequeues are available in store
 *
 * Return:	Next dequeue in @store or NULL if it is not yet available
 */
static inline struct qbman_result *dq_store_next(struct dq_store *store,
						 bool *is_last)
{
	int match;
	struct qbman_result *dq = &store->addr[store->idx];

	match = qbman_result_has_new_result(store->pull_swp, dq);
	if (!match) {
		*is_last = 0;
		return NULL;
	}
	store->idx++;

	assert(qbman_result_is_DQ(dq));

	if (qbman_result_DQ_is_pull_complete(dq)) {
		*is_last = 1;
		store->idx = 0;
		store->pull_swp = NULL;
		/*
		 * If we get an empty dequeue result to terminate a zero-results
		 * vdqcr, return NULL to the caller rather than expecting him to
		 * check non-NULL results every time.
		 */
		if (!(qbman_result_DQ_flags((struct qbman_result *)dq) &
					QBMAN_DQ_STAT_VALIDFRAME))
			dq = NULL;
	} else {
		*is_last = 0;
	}
	return dq;
}

static inline int process_pull_response(struct dq_store *store)
{
	bool is_last = false;
	struct qbman_result *dq;
	const struct dpaa2_fd *fd;
	unsigned int count = 0;

	do {
		unsigned int timeout = 1000000;
#ifdef DEBUG
		static struct dpaa2_dq prev_dq;
#endif

		/* Grab frame by frame from store */
		do {
			dq = dq_store_next(store, &is_last);
		} while (!is_last && !dq); /* && --timeout);*/
		/* is_last or dq is true */

		assert(timeout > 0);

		if (dq) { /* Valid dq was received */
			struct work_unit *work_unit;
#ifdef DEBUG
			static struct dpaa2_fd prev_fd;

#endif
			/* Obtain FD and process it */
			fd = (struct dpaa2_fd *)qbman_result_DQ_fd(dq);

			work_unit = container_of(dpaa2_fd_get_addr(fd),
						struct work_unit, store);
			assert(work_unit);
#ifdef DEBUG
			if (prev_fd.simple.addr_lo == fd->simple.addr_lo) {
				pr_info("The following was the last previously saved dequeue entry\n");
				hexdump(&prev_dq, sizeof(prev_dq));
				getchar();
			}
			prev_dq = *dq;
			prev_fd = *fd;
#endif
			count++;
			work_unit->finish_cb(fd);
		}
	} while (!is_last);

	return count;
}

int pull_done_queue(struct qbman_swp *swp, struct dpdcei *dpdcei)
{
	int pull_count = 0;
	/* Empirically found limits that balance throughput with CPU overhead */
	int max_pulls = 3;
	int err;

	err = pthread_mutex_trylock(&dpdcei->pull_lock);

	if (err == EBUSY)
		/* Another thread is dequeueing frames from this dpdcei */
		return 0;

	assert(!err); /* We do not expect any other type of error */

	do {
		/* qman allows up to two simultaneous pulls */
		err = issue_pull_command(swp, dpdcei->done_queue_fqid,
					 &dpdcei->store_1);
		if (err)
			return 0;

		/*err = issue_pull_command(swp, dpdcei->done_queue_fqid,
					&dpdcei->store_2);*/
		/* Will not return if only the second pull fails, because the
		 * first pull succeeded
		if (err)
			assert(err == -EBUSY);
		*/

		pull_count++;

		err = process_pull_response(&dpdcei->store_1);
		atomic_sub(err, &dpdcei->frames_in_flight);

		/*if (!err)
			process_pull_response(&dpdcei->store_2);
			*/

	} while (pull_count < max_pulls);

	err = pthread_mutex_unlock(&dpdcei->pull_lock);
	assert(!err);

	return 0;
}

/******************************************************************************/
/*** DEBUG FUNCTIONS ***/
/******************************************************************************/

static inline int discard_pull_response(struct dq_store *store)
{
	bool is_last = false;
	struct qbman_result *dq;
	unsigned int count = 0;

	do {

		/* Grab frame by frame from store */
		do {
			dq = dq_store_next(store, &is_last);
		} while (!is_last && !dq);
		/* is_last or dq is true */

		if (dq) { /* Valid dq was received */
			count++;
		}
	} while (!is_last);

	return count;
}

/**
 * drain_queue() - debug function for draining done queue
 * @swp:	QBMan software portal
 * @dpdcei:	DPDCEI with done queue to be drained
 *
 * Return:	Number of fds drained
 */
int drain_queue(struct qbman_swp *swp, struct dpdcei *dpdcei)
{
	int pull_count = 0;
	/* Empirically found limits that balance throughput with CPU overhead */
	int max_pulls = 1000;
	int err;

	do {
		/* qman allows up to two simultaneous pulls */
		err = issue_pull_command(swp, dpdcei->done_queue_fqid,
					 &dpdcei->store_1);
		if (err)
			return 0;

		pull_count++;

		err = discard_pull_response(&dpdcei->store_1);
		atomic_sub(err, &dpdcei->frames_in_flight);

	} while (pull_count < max_pulls);

	return 0;
}

#include <stdarg.h>

bool address_conflicts(int count, ...)
{
	va_list arg_list;
	int i, j;
	uint8_t *addresses[count];
	size_t sizes[count];

	va_start(arg_list, count);

	for (i = 0; i < count; i++) {
		addresses[i] = va_arg(arg_list, void *);
		sizes[i] = va_arg(arg_list, size_t);
	}

	for (i = 0; i < count; i++) {
		uint8_t *i_addr;
		size_t i_size;

		i_addr = addresses[i];
		i_size = sizes[i];

		for (j = 0; j < count; j++) {
			if (i == j)
				continue;
			if (i_addr + i_size <= addresses[j] ||
				addresses[j] + sizes[j] <= i_addr)
				continue;
			else
				return true;
		}
	}
	return false;
}
