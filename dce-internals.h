/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2019 NXP
 * All rights reserved.
 */

#ifndef __DCE_INTERNAL
#define __DCE_INTERNAL

#include <compat.h>
#include <fsl_dpdcei.h>
#include <fsl_dpaa2_fd.h>
#include "dce-scf-compression.h"
#include "dce.h"
#include <circ_fifo.h>

/* ls2088 1.0 DCE */
#define ERR010843_DCE_REV 0x0AF0020000000100LLU

/* ls2085 DCE */
#define ERR008704_DCE_REV 0x0AF0020000000000LLU

/* lx2160 rev 1 */
#define ERR011568_DCE_REV 0x0AF002010000009BLLU

struct dq_store {
	struct qbman_result *addr;
	unsigned int max_dq;
	unsigned int idx;
	struct qbman_swp *pull_swp;
};

struct dma_hw_mem {
	void *vaddr;
	size_t len;
	dma_addr_t paddr;
};

struct dpdcei {
	uint16_t token;
	struct dpdcei_attr attr;
	struct fsl_mc_io *mcp;
	u32 done_queue_fqid;
	u32 todo_queue_fqid;
	atomic_t frames_in_flight;

	pthread_mutex_t pull_lock;
	dma_free dma_free;
	void *dma_opaque;
	struct dq_store store_1;
	struct dq_store store_2;
};

enum work_unit_state {
	FREE = 0,
	TODO = 1,
	DONE = 2
};

typedef void (*finish_call_back)(const struct dpaa2_fd *fd);

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
		};
	} store;
	struct scf_c_cfg scf_result __aligned(64); /* must 64 byte align */
	struct dpaa2_fd head_fd;

	/* The output fd length is set to zero by dce for skipped fd. Arguably
	 * that is bad because now software must maintain some state to find out
	 * how big the output buffer was. The correct setup would have been to
	 * force software to rely on status to find out output buffer size */
	size_t output_length;
	void *context;
	finish_call_back finish_cb;
};

#include "dce-fcr.h"

/**
 * dpdcei_lane - struct used to keep track of session state. This struct is not
 * visible to the user */
struct dpdcei_lane {
	struct dpdcei *dpdcei;
	dma_alloc dma_alloc;
	dma_free dma_free;
	void *dma_opaque;
	struct flow_context_record *flow_context_record;
	enum lane_paradigm paradigm;
	enum lane_compression_format compression_format;
	enum lane_compression_effort compression_effort;
	struct lane_gz_header *gz_header;
	bool member_continue;
	unsigned buffer_pool_id;
	unsigned buffer_pool_id2;
	bool release_buffers;
	bool encode_base_64;
	uint8_t state;
	bool recycle;
	bool recycler_allowed;
	bool initial_store;
	bool reset;
	struct circ_fifo fifo;
	struct dma_hw_mem pending_output;
	struct dma_hw_mem history;
	struct dma_hw_mem decomp_context;
	unsigned int recycle_todo;
	pthread_mutex_t lock;
	sem_t enqueue_sem;
	atomic_t frames_in_flight;
	u32 key;
};


int alloc_lane_hw_mem(struct dpdcei_lane *lane);
void free_lane_hw_mem(struct dpdcei_lane *lane);
void setup_gzip_header(struct scf_c_cfg *d,
		       struct lane_gz_header *header);

int send_init_frame(struct qbman_swp *swp,
		    struct dpdcei_lane *lane,
		    struct work_unit *work_unit);
int pull_done_queue(struct qbman_swp *swp, struct dpdcei *dpdcei);
void finish_lane_setup_fd(const struct dpaa2_fd *fd);
void finish_user_fd(const struct dpaa2_fd *fd);
void finish_lane_abort_fd(const struct dpaa2_fd *fd);



/**
 * enqueue_dpdcei() - enqueue a frame to the todo queue of the given dpdcei
 * @swp:	Software portal to use for enqueue
 * @dpdcei:	DCE device instance in which to place fd
 * @fd:		Frame Descriptor to enqueue
 *
 * Return:	0 on success, -EBUSY if the enqueue should be reattempted
 */
static inline int enqueue_dpdcei(struct qbman_swp *swp,
			  struct dpdcei *dpdcei,
			  struct dpaa2_fd *fd)
{

	struct qbman_eq_desc ed;

	assert(dpaa2_fd_get_flc(fd));

	qbman_eq_desc_clear(&ed);
	qbman_eq_desc_set_no_orp(&ed, 0);
	qbman_eq_desc_set_fq(&ed, dpdcei->todo_queue_fqid);

	return qbman_swp_enqueue(swp, &ed, (struct qbman_fd*)fd);
}


int drain_queue(struct qbman_swp *swp, struct dpdcei *dpdcei);

bool address_conflicts(int count, ...);

#endif /* __DCE_INTERNAL */
