/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#ifndef __FSL_DPAA2_IO_H
#define __FSL_DPAA2_IO_H

#include "fsl_dpaa2_fd.h"
#include "dpaa2_io_portal_priv.h"


struct dpaa2_io;
struct dpaa2_io_store;
struct device;


/**
 * DOC: DPIO Service Management
 *
 * The DPIO service provides APIs for users to interact with the datapath
 * by enqueueing and dequeing frame descriptors.
 *
 * The following set of APIs can be used to enqueue and dequeue frames
 * as well as producing notification callbacks when data is available
 * for dequeue.
 */

/**
 * u24 : Define a 24 bit type that acts as an unsigned integer.
 *
 * The QBMan hardware uses 3 byte (24 bit) integers for some resource
 * identifers. Because these identifers can be packed next to other values
 * SW cannot always merely treat them as 32 bit values. Therefore a u24
 * type is defined with endianness conversion helpers so we can deal with this
 * non standard type as we do with normal integers
 */
typedef struct __attribute__ ((__packed__)) u24 { u8 x[3]; } u24;

static inline u32 le24_to_cpu(u24 in)
{
#if defined(__BIG_ENDIAN)
	return (in.x[2] << 8 | in.x[1] << 16 | in.x[0] << 24);
#else
	return (in.x[0] << 8 | in.x[1] << 16 | in.x[2] << 24);
#endif
}

static inline u24 cpu_to_le24(u32 in)
{
	u24 out;
#if defined(__BIG_ENDIAN)
	out.x[0] = (in & 0xff0000) >> 16;
	out.x[1] = (in & 0xff00) >> 8;
	out.x[2] = in & 0xff;
#else
	out.x[0] = in & 0xff;
	out.x[1] = (in & 0xff00) >> 8;
	out.x[2] = (in & 0xff0000) >> 16;
#endif
	return out;
}

static inline u32 u24_to_u32(u24 in)
{
	return in.x[0] << 16 | in.x[1] << 8 | in.x[2];
}

/**
 * struct dpaa2_io_desc - The DPIO descriptor.
 * @receives_notifications: Use notificaton mode.
 * @has_8prio: set for channel with 8 priority WQs.
 * @cpu: the cpu index that at least interrupt handlers will execute on.
 * @stash_affinity: the stash affinity for this portal favour 'cpu'
 * @regs_cena: the cache enabled regs.
 * @regs_cinh: the cache inhibited regs.
 * @dpio_id: The dpio index.
 * @qman_version: the qman version
 *
 * Describe the attributes and features of the DPIO object.
 */
struct dpaa2_io_desc {
	/* non-zero iff the DPIO has a channel */
	int receives_notifications;
	/* ignored unless 'receives_notifications'. Non-zero iff the channel has
	 * 8 priority WQs, otherwise the channel has 2.
	 */
	int has_8prio;
	/* the cpu index that at least interrupt handlers will execute on. */
	int cpu;
	/* Caller-provided flags, determined by bus-scanning and/or creation of
	 * DPIO objects via MC commands.
	 */
	void *regs_cena;
	void *regs_cinh;
	int dpio_id;
	u32 qman_version;
};

struct dpaa2_io *dpaa2_io_create(const int dpio_id, int cpu);
void dpaa2_io_destroy(struct dpaa2_io *dpio);

void dpaa2_io_down(struct dpaa2_io *d);

int dpaa2_io_get_descriptor(struct dpaa2_io *obj, struct dpaa2_io_desc *desc);

int dpaa2_io_irq(struct dpaa2_io *obj);

struct dpaa2_io {
        atomic_t refs;
        struct dpaa2_io_desc dpio_desc;
        struct qbman_swp_desc swp_desc;
        struct qbman_swp *swp;
        struct list_head node;

	/*
	* As part of simplifying assumptions, we provide an
	* irq-safe lock for each type of DPIO operation that
	* isn't innately lockless. The selection algorithms
	* (which are simplified) require this, whereas
	* eventually adherence to cpu-affinity will presumably
	* relax the locking requirements.
	*/
        pthread_mutex_t lock_mgmt_cmd;

        /* Protect the list of notifications */
        pthread_mutex_t lock_notifications;

        struct list_head notifications;
};

/* Notification handling */

/**
 * struct dpaa2_io_notification_ctx - The DPIO notification context structure.
 * @cb: the callback to be invoked when the notification arrives.
 * @is_cdan: Zero/FALSE for FQDAN, non-zero/TRUE for CDAN.
 * @id: FQID or channel ID, needed for rearm.
 * @desired_cpu: the cpu on which the notifications will show up.
 * @dpio_id: the dpio index.
 * @qman64: the 64-bit context value shows up in the FQDAN/CDAN.
 * @node: the list node.
 * @dpio_private: the dpio object internal to dpio_service.
 *
 * When a FQDAN/CDAN registration is made (eg. by DPNI/DPCON/DPAI code), a
 * context of the following type is used. The caller can embed it within a
 * larger structure in order to add state that is tracked along with the
 * notification (this may be useful when callbacks are invoked that pass this
 * notification context as a parameter).
 */
struct dpaa2_io_notification_ctx {
	void (*cb)(struct dpaa2_io_notification_ctx *);
	int is_cdan;
	u32 id;
	/* This specifies which cpu the user wants notifications to show up on
	 * (ie. to execute 'cb'). If notification-handling on that cpu is not
	 * available at the time of notification registration, the registration
	 * will fail.
	 */
	int desired_cpu;

	int dpio_id;
	u64 qman64;
	/* These fields are internal to the DPIO service once the context is
	 * registered. TBD: may require more internal state fields.
	 */
	struct list_head node;
	void *dpio_private;
};

int dpaa2_io_service_register(struct dpaa2_io *service,
			      struct dpaa2_io_notification_ctx *ctx);

int dpaa2_io_service_deregister(struct dpaa2_io *service,
				struct dpaa2_io_notification_ctx *ctx);

int dpaa2_io_service_rearm(struct dpaa2_io *service,
			   struct dpaa2_io_notification_ctx *ctx);

int dpaa2_io_from_registration(struct dpaa2_io_notification_ctx *ctx,
			       struct dpaa2_io **ret);

/* Pull dequeues */
int dpaa2_io_service_pull_fq(struct dpaa2_io *d, u32 fqid,
			     struct dpaa2_io_store *s);

int dpaa2_io_service_pull_channel(struct dpaa2_io *d, u32 channelid,
				  struct dpaa2_io_store *s);

/* Enqueues */
int dpaa2_io_service_enqueue_fq(struct dpaa2_io *d, u32 fqid,
				const struct dpaa2_fd *fd);

int dpaa2_io_service_enqueue_qd(struct dpaa2_io *d, u32 qdid, u8 prio,
				u16 qdbin, const struct dpaa2_fd *fd);

/* Buffer handling */
int dpaa2_io_service_release(struct dpaa2_io *d, u32 bpid,
			     const u64 *buffers, unsigned int num_buffers);

int dpaa2_io_service_acquire(struct dpaa2_io *d, u32 bpid,
			     u64 *buffers, unsigned int num_buffers);

/* DQ Structure */

/**
 * struct dpaa2_dq - the qman result structure
 * @dont_manipulate_directly: the 16 32bit data to represent the whole
 * possible qman dequeue result.
 *
 * When frames are dequeued, the FDs show up inside "dequeue" result structures
 * (if at all, not all dequeue results contain valid FDs). This structure type
 * is intentionally defined without internal detail, and the only reason it
 * isn't declared opaquely (without size) is to allow the user to provide
 * suitably-sized (and aligned) memory for these entries.
 */

struct dpaa2_dq {
	u32 dont_manipulate_directly[16];
};

/* Parsing frame dequeue results */
/* FQ empty */
#define DPAA2_DQ_STAT_FQEMPTY       0x80
/* FQ held active */
#define DPAA2_DQ_STAT_HELDACTIVE    0x40
/* FQ force eligible */
#define DPAA2_DQ_STAT_FORCEELIGIBLE 0x20
/* Valid frame */
#define DPAA2_DQ_STAT_VALIDFRAME    0x10
/* FQ ODP enable */
#define DPAA2_DQ_STAT_ODPVALID      0x04
/* Volatile dequeue */
#define DPAA2_DQ_STAT_VOLATILE      0x02
/* volatile dequeue command is expired */
#define DPAA2_DQ_STAT_EXPIRED       0x01

/**
 * qbman_result_DQ_flags() - Get the stat field of dequeue response
 * @dq: the dequeue result.
 */
//u32 qbman_result_DQ_flags(const struct dpaa2_dq *dq);

/**
 * dpaa2_dq_is_pull() - Check whether the dq response is from a pull
 * command.
 * @dq: the dequeue result.
 *
 * Return 1 for volatile(pull) dequeue, 0 for static dequeue.
 */
static inline int dpaa2_dq_is_pull(const struct dpaa2_dq *dq)
{
	return (int)(qbman_result_DQ_flags((const struct qbman_result *)dq) & DPAA2_DQ_STAT_VOLATILE);
}

/**
 * dpaa2_dq_is_pull_complete() - Check whether the pull command is completed.
 * @dq: the dequeue result.
 *
 * Return boolean.
 */
static inline int dpaa2_dq_is_pull_complete(
					const struct dpaa2_dq *dq)
{
	return (int)(qbman_result_DQ_flags((const struct qbman_result *)dq) & DPAA2_DQ_STAT_EXPIRED);
}

/**
 * dpaa2_dq_seqnum() - Get the seqnum field in dequeue response
 * seqnum is valid only if VALIDFRAME flag is TRUE
 * @dq: the dequeue result.
 *
 * Return seqnum.
 */
u16 dpaa2_dq_seqnum(const struct dpaa2_dq *dq);

/**
 * dpaa2_dq_odpid() - Get the seqnum field in dequeue response
 * odpid is valid only if ODPVAILD flag is TRUE.
 * @dq: the dequeue result.
 *
 * Return odpid.
 */
u16 dpaa2_dq_odpid(const struct dpaa2_dq *dq);

/**
 * dpaa2_dq_fqid() - Get the fqid in dequeue response
 * @dq: the dequeue result.
 *
 * Return fqid.
 */
u32 dpaa2_dq_fqid(const struct dpaa2_dq *dq);

/**
 * dpaa2_dq_byte_count() - Get the byte count in dequeue response
 * @dq: the dequeue result.
 *
 * Return the byte count remaining in the FQ.
 */
u32 dpaa2_dq_byte_count(const struct dpaa2_dq *dq);

/**
 * dpaa2_dq_frame_count() - Get the frame count in dequeue response
 * @dq: the dequeue result.
 *
 * Return the frame count remaining in the FQ.
 */
u32 dpaa2_dq_frame_count(const struct dpaa2_dq *dq);

/**
 * dpaa2_dq_fd_ctx() - Get the frame queue context in dequeue response
 * @dq: the dequeue result.
 *
 * Return the frame queue context.
 */
u64 dpaa2_dq_fqd_ctx(const struct dpaa2_dq *dq);

#define qb_cl(d) (&(d)->dont_manipulate_directly[0])

/**
 * dpaa2_dq_fd() - Get the frame descriptor in dequeue response
 * @dq: the dequeue result.
 *
 * Return the frame descriptor.
 */
static inline const struct dpaa2_fd *dpaa2_dq_fd(const struct dpaa2_dq *dq)
{
	const uint32_t *p = qb_cl(dq);

	return (const struct dpaa2_fd *)&p[8];
}


/* DPIO stores */

/* These are reusable memory blocks for retrieving dequeue results into, and to
 * assist with parsing those results once they show up. They also hide the
 * details of how to use "tokens" to make detection of DMA results possible (ie.
 * comparing memory before the DMA and after it) while minimising the needless
 * clearing/rewriting of those memory locations between uses.
 */

struct dpaa2_io_store *dpaa2_io_store_create(unsigned int max_frames,
					     struct device *dev);

void dpaa2_io_store_destroy(struct dpaa2_io_store *s);

struct dpaa2_dq *dpaa2_io_store_next(struct dpaa2_io_store *s, int *is_last);

/* Query functions to check queues and pools */
int dpaa2_io_query_fq_count(struct dpaa2_io *d, u32 fqid,
			    u32 *fcnt, u32 *bcnt);

int dpaa2_io_query_bp_count(struct dpaa2_io *d, u32 bpid,
			    u32 *num);

void *handle_dpio_interrupts(void *_dpio);

#endif /* __FSL_DPAA2_IO_H */
