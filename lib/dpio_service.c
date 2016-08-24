/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <linux/types.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <libgen.h>
#include <stdlib.h>
#include <sched.h>
#include <pthread.h>

#include "fsl_mc_cmd.h"
#include "fsl_dpio.h"
#include "fsl_dprc.h"
#include "fsl_mc_sys.h"
#include "fsl_dpmng.h"
#include "vfio_utils.h"
#include "allocator.h"

#include <fsl_qbman_debug.h>

#include "compat.h"

#include <sys/eventfd.h>
#include <sys/epoll.h>

#define PTR_ALIGN(p, a)            ((typeof(p))ALIGN((unsigned long)(p), (a)))

#define NR_CPUS 32

struct dpaa2_io_store {
	unsigned int max;
	dma_addr_t paddr;
	struct qbman_result *vaddr;
	void *alloced_addr;    /* unaligned value from kmalloc() */
	unsigned int idx;      /* position of the next-to-be-returned entry */
	struct qbman_swp *swp; /* portal used to issue VDQCR */
	struct device *dev;    /* device used for DMA mapping */
};

/* keep a per cpu array of DPIOs for fast access */
static struct dpaa2_io *dpio_by_cpu[NR_CPUS];

static LIST_HEAD(dpio_list);
static DEFINE_SPINLOCK(dpio_list_lock) ;

/* Interrupt process related data */
static pthread_t intr_thread;
static int ird_evend_fd;
extern int dpio_epoll_fd;

/**********************/
/* Internal functions */
/**********************/

void *handle_dpio_interrupts(void *_dpio)
{
	struct dpaa2_io *dpio = _dpio;
/*	int nfds;
	struct epoll_event events[10];
*/
	for(;;) {
#if 0
	        nfds = epoll_wait(dpio_epoll_fd, events, 1, -1);
		/* epoll_wait fail */
		if (nfds < 0) {
			if (errno == EINTR){
				/* System call interrupt, not an error */
				continue;
			}
	                pr_err("epoll_wait returns with fail %i\n", nfds);
			continue;
		}
		/* epoll_wait timeout, will never happens here */
		else if (nfds == 0) {
				pr_err("Timeout\n");
				continue;
		}
		/* epoll_wait has at least one fd ready to read */
#endif
		usleep(1);
		dpaa2_io_irq(dpio);
	}
	return NULL;
}

static inline struct dpaa2_io *service_select_by_cpu(struct dpaa2_io *d,
						     int cpu)
{
	if (d)
		return d;
	/* If cpu==-1, choose the current cpu, with no guarantees about
	 * potentially being migrated away.
	 */
	if (unlikely(cpu < 0)) {
		cpu = sched_getcpu();
	}

	/* If a specific cpu was requested, pick it up immediately */
	return dpio_by_cpu[cpu];
}

static inline struct dpaa2_io *service_select(struct dpaa2_io *d)
{
	if (d)
		return d;
	spin_lock(&dpio_list_lock);
	d = list_entry(dpio_list.next, struct dpaa2_io, node);
	list_del(&d->node);
	list_add_tail(&d->node, &dpio_list);
	spin_unlock(&dpio_list_lock);

	return d;
}

/**********************/
/* Exported functions */
/**********************/

/**
 * dpaa2_io_destroy() - destroy a dpaa2_io object.
 * Disable the interrupt and reclaim the resources of the dpaa2 io object.
 *
 * @dpio: the dpaa2_io object to destroy
 *
 * Return: No return value.
 */
void dpaa2_io_destroy(struct dpaa2_io *dpio)
{
	int32_t cpu = sched_getcpu();
	int err;

	spin_lock(&dpio_list_lock);
	list_del(&dpio->node);
	if (cpu != -1 && !dpio_by_cpu[cpu])
		dpio_by_cpu[cpu] = 0;
	spin_unlock(&dpio_list_lock);

	if (dpio->swp) {
		err = vfio_disable_dpio_interrupt(dpio->swp, dpio,
						&ird_evend_fd, &intr_thread);
		if (err)
			pr_err("vfio_disable_dpio_interrupt() failed in %s\n",
								__func__);
		qbman_swp_finish(dpio->swp);
	}
	if (dpio)
		kfree(dpio);
}
EXPORT_SYMBOL(dpaa2_io_destroy);

/**
 * dpaa2_io_create() - create a dpaa2_io object.
 *
 * Activates a "struct dpaa2_io" corresponding to the given dpio_id
 * and runs a dequeuing thread in the given cpu. -1 can be passed for
 * cpu if the caller does not wish to specify which cpu dequeues
 *
 * Return a valid dpaa2_io object for success, or NULL for failure.
 */
struct dpaa2_io *dpaa2_io_create(int dpio_id, int cpu)
{
	char dpio_id_str[20];
	struct fsl_mc_io *mc_io;
	struct dpio_attr dpio_attr;
	uint16_t dpio_token;
	struct dpaa2_io *dpio = NULL;
	int err;

	dpio = kmalloc(sizeof(*dpio), GFP_KERNEL);
	if (!dpio)
		goto err_dpio_alloc;

	mc_io = malloc(sizeof(struct fsl_mc_io));
	if (!mc_io)
		goto err_mc_io_alloc;

	err = mc_io_init(mc_io);
	if (err)
		goto err_mc_io_init;

	/* DPIO configuration */
	err = dpio_open(mc_io, 0, dpio_id, &dpio_token);
	if (err) {
		pr_err("error %d in %s in attempt to dpio_open()\n",
				err, __func__);
		goto err_dpio_open;
	}

	err = dpio_reset(mc_io, 0, dpio_token);
	if (err) {
		pr_err("error %d in %s in attempt to dpio_reset()\n",
				err, __func__);
		goto err_dpio_open;
	}

	vfio_force_rescan();
	err = dpio_get_attributes(mc_io, 0, dpio_token, &dpio_attr);
	if (err) {
		pr_err("error %d in %s in attempt to dpio_get_attributes()\n",
				err, __func__);
		goto err_dpio_open;
	}

	if (cpu == -1)
		/* -1 indicates the user does not care which core to run on */
		cpu = sched_getcpu();
	dpio->dpio_desc.cpu = cpu;

	vfio_force_rescan();
	err = dpio_set_stashing_destination(mc_io, 0, dpio_token,
						4+(cpu>>1));
	/* The stashing destination is based on the CPU cluster which is 4 + the
	 * cpu/2 since every two cores share a stashing destination
	 */
	if (err) {
		pr_err("error %d in %s in attempt to dpio_set_stashing_destination()\n",
				err, __func__);
		goto err_dpio_open;
	}

	vfio_force_rescan();
	err = dpio_enable(mc_io, 0, dpio_token);
	if (err) {
		pr_err("error %d in %s in attempt to dpio_enable()\n",
				err, __func__);
		goto err_dpio_open;
	}

	sprintf(dpio_id_str, "dpio.%i", dpio_id);
	dpio->swp_desc.cena_bar = vfio_map_portal_mem(dpio_id_str,
							PORTAL_MEM_CENA);
	if (!dpio->swp_desc.cena_bar) {
		pr_err("error %d in %s in attempt to vfio_map_portal_mem() cache enabled area\n",
				err, __func__);
		goto err_portal_cache_enabled_mem_setup;
	}

	dpio->swp_desc.cinh_bar = vfio_map_portal_mem(dpio_id_str,
							PORTAL_MEM_CINH);
	if (!dpio->swp_desc.cinh_bar) {
		pr_err("error %d in %s in attempt to vfio_map_portal_mem() cache inhibited area\n",
				err, __func__);
		goto err_portal_cache_inhibited_mem_setup;
	}
	atomic_set(&dpio->refs, 1);

	dpio->swp_desc.idx = dpio_id;
	dpio->swp_desc.eqcr_mode = qman_eqcr_vb_array;
	dpio->swp_desc.irq = 0;
	dpio->swp_desc.qman_version = dpio_attr.qbman_version;
	dpio->swp = qbman_swp_init(&dpio->swp_desc);
	if (!dpio->swp) {
		pr_err("qbman_swp_init() failed in %s\n", __func__);
		goto err_swp_init;
	}
	dpio->dpio_desc.dpio_id = dpio_id;

	INIT_LIST_HEAD(&dpio->node);
	spin_lock_init(&dpio->lock_mgmt_cmd);
	spin_lock_init(&dpio->lock_notifications);
	INIT_LIST_HEAD(&dpio->notifications);

	qbman_swp_interrupt_clear_status(dpio->swp, 0xffffffff);
	dpio->dpio_desc.receives_notifications = true;
	qbman_swp_push_set(dpio->swp, 0, 1);

	spin_lock(&dpio_list_lock);
	list_add_tail(&dpio->node, &dpio_list);
	if (cpu != -1 && !dpio_by_cpu[cpu])
		dpio_by_cpu[cpu] = dpio;
	spin_unlock(&dpio_list_lock);

	err = vfio_enable_dpio_interrupt(dpio->swp,
					dpio,
					&ird_evend_fd,
					&intr_thread,
					handle_dpio_interrupts);
	if (err) {
		pr_err("fail vfio_enable_dpio_interrupt\n");
		goto err_interrupt_enable;
	}

	return dpio;

err_interrupt_enable:
	qbman_swp_finish(dpio->swp);
err_swp_init:
	/* FIXME should cleanup portal mapped memory */
	/* vfio_unmap_portal_mem(dpio->swp_desc.cinh_bar) */

err_portal_cache_inhibited_mem_setup:
	/* FIXME should cleanup portal mapped memory */
	/* vfio_unmap_portal_mem(dpio->swp_desc.cena_bar) */
err_portal_cache_enabled_mem_setup:
	dpio_disable(mc_io, 0, dpio_token);
err_dpio_open:
	mc_io_cleanup(mc_io);
err_mc_io_init:
	free(mc_io);
err_mc_io_alloc:
	free(dpio);
err_dpio_alloc:
	return NULL;
}
EXPORT_SYMBOL(dpaa2_io_create);

/**
 * dpaa2_io_down() - release the dpaa2_io object.
 * @d: the dpaa2_io object to be released.
 *
 * The "struct dpaa2_io" type can represent an individual DPIO object (as
 * described by "struct dpaa2_io_desc") or an instance of a "DPIO service",
 * which can be used to group/encapsulate multiple DPIO objects. In all cases,
 * each handle obtained should be released using this function.
 */
void dpaa2_io_down(struct dpaa2_io *d)
{
	if (!atomic_dec_and_test(&d->refs))
		return;
	kfree(d);
}
EXPORT_SYMBOL(dpaa2_io_down);

/**
 * dpaa2_io_get_descriptor() - Get the DPIO descriptor of the given DPIO object.
 * @obj: the given DPIO object.
 * @desc: the returned DPIO descriptor.
 *
 * This function will return failure if the given dpaa2_io struct represents a
 * service rather than an individual DPIO object, otherwise it returns zero and
 * the given 'cfg' structure is filled in.
 *
 * Return 0 for success, or -EINVAL for failure.
 */
int dpaa2_io_get_descriptor(struct dpaa2_io *obj, struct dpaa2_io_desc *desc)
{
	*desc = obj->dpio_desc;
	return 0;
}
EXPORT_SYMBOL(dpaa2_io_get_descriptor);

#define DPAA_POLL_MAX 32

/**
 * dpaa2_io_irq() - Process any notifications and h/w-initiated events that are
 * irq-driven.
 * @obj: the given DPIO object.
 *
 * Obligatory for DPIO objects that have dpaa2_io_desc::has_irq non-zero.
 *
 * Return IRQ_HANDLED for success, or -EINVAL for failure.
 */
int dpaa2_io_irq(struct dpaa2_io *obj)
{
	const struct qbman_result *dq;
	int max = 0;
	struct qbman_swp *swp;
	u32 status;

	swp = obj->swp;
	status = qbman_swp_interrupt_read_status(swp);
	if (!status) {
		/*printf("Nothing to process\n");*/
		return 0;
	}

	swp = obj->swp;
	dq = qbman_swp_dqrr_next(swp);
	while (dq) {
		if (qbman_result_is_SCN(dq)) {
			struct dpaa2_io_notification_ctx *ctx;
			u64 q64;

			q64 = qbman_result_SCN_ctx(dq);
			ctx = (void *)q64;
			assert(ctx->cb);
			ctx->cb(ctx);
		} else {
			pr_crit("Unrecognised/ignored DQRR entry\n");
		}
		qbman_swp_dqrr_consume(swp, dq);
		++max;
		if (max > DPAA_POLL_MAX)
			break;
		dq = qbman_swp_dqrr_next(swp);
	}
	qbman_swp_interrupt_clear_status(swp, status);
	qbman_swp_interrupt_set_inhibit(swp, 0);
	return IRQ_HANDLED;
}
EXPORT_SYMBOL(dpaa2_io_irq);

/**
 * dpaa2_io_service_register() - Prepare for servicing of FQDAN or CDAN
 * notifications on the given DPIO service.
 * @service: the given DPIO service.
 * @ctx: the notification context.
 *
 * The MC command to attach the caller's DPNI/DPCON/DPAI device to a
 * DPIO object is performed after this function is called. In that way, (a) the
 * DPIO service is "ready" to handle a notification arrival (which might happen
 * before the "attach" command to MC has returned control of execution back to
 * the caller), and (b) the DPIO service can provide back to the caller the
 * 'dpio_id' and 'qman64' parameters that it should pass along in the MC command
 * in order for the DPNI/DPCON/DPAI resources to be configured to produce the
 * right notification fields to the DPIO service.
 *
 * Return 0 for success, or -ENODEV for failure.
 */
int dpaa2_io_service_register(struct dpaa2_io *d,
			      struct dpaa2_io_notification_ctx *ctx)
{
	d = service_select_by_cpu(d, ctx->desired_cpu);
	if (!d)
		return -ENODEV;
	ctx->dpio_id = d->dpio_desc.dpio_id;
	ctx->qman64 = (u64)ctx;
	ctx->dpio_private = d;
	pthread_mutex_lock(&d->lock_notifications);
	list_add(&ctx->node, &d->notifications);
	pthread_mutex_unlock(&d->lock_notifications);

	if (ctx->is_cdan)
		/* Enable the generation of CDAN notifications */
		qbman_swp_CDAN_set_context_enable(d->swp,
						  (u16)ctx->id,
						  ctx->qman64);
	return 0;
}
EXPORT_SYMBOL(dpaa2_io_service_register);

/**
 * dpaa2_io_service_deregister - The opposite of 'register'.
 * @service: the given DPIO service.
 * @ctx: the notification context.
 *
 * Note that 'register' should be called *before*
 * making the MC call to attach the notification-producing device to the
 * notification-handling DPIO service, the 'unregister' function should be
 * called *after* making the MC call to detach the notification-producing
 * device.
 *
 * Return 0 for success.
 */
int dpaa2_io_service_deregister(struct dpaa2_io *service,
				struct dpaa2_io_notification_ctx *ctx)
{
	struct dpaa2_io *d = ctx->dpio_private;

	(void)service; /* Silence compiler warning. Will be used in future */
	if (ctx->is_cdan)
		qbman_swp_CDAN_disable(d->swp, (u16)ctx->id);
	pthread_mutex_lock(&d->lock_notifications);
	list_del(&ctx->node);
	pthread_mutex_unlock(&d->lock_notifications);
	return 0;
}
EXPORT_SYMBOL(dpaa2_io_service_deregister);

/**
 * dpaa2_io_service_rearm() - Rearm the notification for the given DPIO service.
 * @service: the given DPIO service.
 * @ctx: the notification context.
 *
 * Once a FQDAN/CDAN has been produced, the corresponding FQ/channel is
 * considered "disarmed". Ie. the user can issue pull dequeue operations on that
 * traffic source for as long as it likes. Eventually it may wish to "rearm"
 * that source to allow it to produce another FQDAN/CDAN, that's what this
 * function achieves.
 *
 * Return 0 for success, or -ENODEV if no service available, -EBUSY/-EIO for not
 * being able to implement the rearm the notifiaton due to setting CDAN or
 * scheduling fq.
 */
int dpaa2_io_service_rearm(struct dpaa2_io *d,
			   struct dpaa2_io_notification_ctx *ctx)
{
	int err;

	d = service_select(d);
	if (!d)
		return -ENODEV;
	pthread_mutex_lock(&d->lock_mgmt_cmd);
	if (ctx->is_cdan)
		err = qbman_swp_CDAN_enable(d->swp, (u16)ctx->id);
	else
		err = qbman_swp_fq_schedule(d->swp, ctx->id);
	pthread_mutex_unlock(&d->lock_mgmt_cmd);
	return err;
}
EXPORT_SYMBOL(dpaa2_io_service_rearm);

/**
 * dpaa2_io_from_registration() - Get the DPIO object from the given
 * notification context.
 * @ctx: the given notifiation context.
 * @ret: the returned DPIO object.
 *
 * Like 'dpaa2_io_service_get_persistent()' (see below), except that the
 * returned handle is not selected based on a 'cpu' argument, but is the same
 * DPIO object that the given notification context is registered against. The
 * returned handle carries a reference count, so a corresponding dpaa2_io_down()
 * would be required when the reference is no longer needed.
 *
 * Return 0 for success, or -EINVAL for failure.
 */
int dpaa2_io_from_registration(struct dpaa2_io_notification_ctx *ctx,
			       struct dpaa2_io **io)
{
	struct dpaa2_io_notification_ctx *tmp;
	struct dpaa2_io *d = ctx->dpio_private;
	int ret = 0;

	/*
	 * Iterate the notifications associated with 'd' looking for a match. If
	 * not, we've been passed an unregistered ctx!
	 */
	pthread_mutex_lock(&d->lock_notifications);
	list_for_each_entry(tmp, &d->notifications, node)
		if (tmp == ctx)
			goto found;
	ret = -EINVAL;
found:
	pthread_mutex_unlock(&d->lock_notifications);
	if (!ret) {
		atomic_inc(&d->refs);
		*io = d;
	}
	return ret;
}
EXPORT_SYMBOL(dpaa2_io_from_registration);

/**
 * dpaa2_io_service_pull_fq() - pull dequeue functions from a fq.
 * @d: the given DPIO service.
 * @fqid: the given frame queue id.
 * @s: the dpaa2_io_store object for the result.
 *
 * To support DCA/order-preservation, it will be necessary to support an
 * alternative form, because they must ultimately dequeue to DQRR rather than a
 * user-supplied dpaa2_io_store. Furthermore, those dequeue results will
 * "complete" using a caller-provided callback (from DQRR processing) rather
 * than the caller explicitly looking at their dpaa2_io_store for results. Eg.
 * the alternative form will likely take a callback parameter rather than a
 * store parameter. Ignoring it for now to keep the picture clearer.
 *
 * Return 0 for success, or error code for failure.
 */
int dpaa2_io_service_pull_fq(struct dpaa2_io *d, u32 fqid,
			     struct dpaa2_io_store *s)
{
	struct qbman_pull_desc pd;
	int err=0;

	qbman_pull_desc_clear(&pd);
	qbman_pull_desc_set_storage(&pd, s->vaddr, s->paddr, 1);
	qbman_pull_desc_set_numframes(&pd, (u8)s->max);
	qbman_pull_desc_set_fq(&pd, fqid);
	d = service_select(d);
	if (!d)
		return -ENODEV;
	s->swp = d->swp;
	err = qbman_swp_pull(d->swp, &pd);
	if (err)
		s->swp = NULL;
	return err;
}
EXPORT_SYMBOL(dpaa2_io_service_pull_fq);

/**
 * dpaa2_io_service_pull_channel() - pull dequeue functions from a channel.
 * @d: the given DPIO service.
 * @channelid: the given channel id.
 * @s: the dpaa2_io_store object for the result.
 *
 * To support DCA/order-preservation, it will be necessary to support an
 * alternative form, because they must ultimately dequeue to DQRR rather than a
 * user-supplied dpaa2_io_store. Furthermore, those dequeue results will
 * "complete" using a caller-provided callback (from DQRR processing) rather
 * than the caller explicitly looking at their dpaa2_io_store for results. Eg.
 * the alternative form will likely take a callback parameter rather than a
 * store parameter. Ignoring it for now to keep the picture clearer.
 *
 * Return 0 for success, or error code for failure.
 */
int dpaa2_io_service_pull_channel(struct dpaa2_io *d, u32 channelid,
				  struct dpaa2_io_store *s)
{
	struct qbman_pull_desc pd;
	int err;

	qbman_pull_desc_clear(&pd);
	qbman_pull_desc_set_storage(&pd, s->vaddr, s->paddr, 1);
	qbman_pull_desc_set_numframes(&pd, (u8)s->max);
	qbman_pull_desc_set_channel(&pd, channelid, qbman_pull_type_prio);
	d = service_select(d);
	if (!d)
		return -ENODEV;
	s->swp = d->swp;
	err = qbman_swp_pull(d->swp, &pd);
	if (err)
		s->swp = NULL;
	return err;
}
EXPORT_SYMBOL(dpaa2_io_service_pull_channel);

/**
 * dpaa2_io_service_enqueue_fq() - Enqueue a frame to a frame queue.
 * @d: the given DPIO service.
 * @fqid: the given frame queue id.
 * @fd: the frame descriptor which is enqueued.
 *
 * This definition bypasses some features that are not expected to be priority-1
 * features, and may not be needed at all via current assumptions (QBMan's
 * feature set is wider than the MC object model is intendeding to support,
 * initially at least). Plus, keeping them out (for now) keeps the API view
 * simpler. Missing features are;
 *  - enqueue confirmation (results DMA'd back to the user)
 *  - ORP
 *  - DCA/order-preservation (see note in "pull dequeues")
 *  - enqueue consumption interrupts
 *
 * Return 0 for successful enqueue, or -EBUSY if the enqueue ring is not ready,
 * or -ENODEV if there is no dpio service.
 */
int dpaa2_io_service_enqueue_fq(struct dpaa2_io *d,
				u32 fqid,
				const struct dpaa2_fd *fd)
{
	int res;
	struct qbman_eq_desc ed;

	d = service_select(d);
	if (!d)
		return -ENODEV;
	qbman_eq_desc_clear(&ed);
	qbman_eq_desc_set_no_orp(&ed, 0);
	qbman_eq_desc_set_fq(&ed, fqid);
	res = qbman_swp_enqueue(d->swp, &ed, (const struct qbman_fd*)fd);
#ifdef debug
	if (dpaa2_fd_list == dpaa2_fd_get_format(fd))
		pr_info("DEBUG: This frame is a frame list. The final bit on the third frame is set to %s\n",
			dpaa2_sg_is_final(
				((void *)dpaa2_fd_get_addr(fd)) + 64) ?
							"true" : "false");
#endif
	return res;
}
EXPORT_SYMBOL(dpaa2_io_service_enqueue_fq);

/**
 * dpaa2_io_service_enqueue_qd() - Enqueue a frame to a QD.
 * @d: the given DPIO service.
 * @qdid: the given queuing destination id.
 * @prio: the given queuing priority.
 * @qdbin: the given queuing destination bin.
 * @fd: the frame descriptor which is enqueued.
 *
 * This definition bypasses some features that are not expected to be priority-1
 * features, and may not be needed at all via current assumptions (QBMan's
 * feature set is wider than the MC object model is intendeding to support,
 * initially at least). Plus, keeping them out (for now) keeps the API view
 * simpler. Missing features are;
 *  - enqueue confirmation (results DMA'd back to the user)
 *  - ORP
 *  - DCA/order-preservation (see note in "pull dequeues")
 *  - enqueue consumption interrupts
 *
 * Return 0 for successful enqueue, or -EBUSY if the enqueue ring is not ready,
 * or -ENODEV if there is no dpio service.
 */
int dpaa2_io_service_enqueue_qd(struct dpaa2_io *d,
				u32 qdid, u8 prio, u16 qdbin,
				const struct dpaa2_fd *fd)
{
	int res;
	struct qbman_eq_desc ed;

	d = service_select(d);
	if (!d)
		return -ENODEV;
	qbman_eq_desc_clear(&ed);
	qbman_eq_desc_set_no_orp(&ed, 0);
	qbman_eq_desc_set_qd(&ed, qdid, qdbin, prio);
	res = qbman_swp_enqueue(d->swp, &ed, (const struct qbman_fd*)fd);
	return res;
}
EXPORT_SYMBOL(dpaa2_io_service_enqueue_qd);

/**
 * dpaa2_io_service_release() - Release buffers to a buffer pool.
 * @d: the given DPIO object.
 * @bpid: the buffer pool id.
 * @buffers: the buffers to be released.
 * @num_buffers: the number of the buffers to be released.
 *
 * Return 0 for success, and negative error code for failure.
 */
int dpaa2_io_service_release(struct dpaa2_io *d,
			     u32 bpid,
			     const u64 *buffers,
			     unsigned int num_buffers)
{
	struct qbman_release_desc rd;

	d = service_select(d);
	if (!d)
		return -ENODEV;
	qbman_release_desc_clear(&rd);
	qbman_release_desc_set_bpid(&rd, bpid);
	return qbman_swp_release(d->swp, &rd, buffers, num_buffers);
}
EXPORT_SYMBOL(dpaa2_io_service_release);

/**
 * dpaa2_io_service_acquire() - Acquire buffers from a buffer pool.
 * @d: the given DPIO object.
 * @bpid: the buffer pool id.
 * @buffers: the buffer addresses for acquired buffers.
 * @num_buffers: the expected number of the buffers to acquire.
 *
 * Return a negative error code if the command failed, otherwise it returns
 * the number of buffers acquired, which may be less than the number requested.
 * Eg. if the buffer pool is empty, this will return zero.
 */
int dpaa2_io_service_acquire(struct dpaa2_io *d,
			     u32 bpid,
			     u64 *buffers,
			     unsigned int num_buffers)
{
	int err;

	d = service_select(d);
	if (!d)
		return -ENODEV;
	pthread_mutex_lock(&d->lock_mgmt_cmd);
	err = qbman_swp_acquire(d->swp, bpid, buffers, num_buffers);
	pthread_mutex_unlock(&d->lock_mgmt_cmd);
	return err;
}
EXPORT_SYMBOL(dpaa2_io_service_acquire);

/**
 * dpaa2_io_store_create() - Create the dma memory storage for dequeue
 * result.
 * @max_frames: the maximum number of dequeued result for frames, must be <= 16.
 * @dev: the device to allow mapping/unmapping the DMAable region.
 *
 * Constructor - max_frames must be <= 16. The user provides the
 * device struct to allow mapping/unmapping of the DMAable region. Area for
 * storage will be allocated during create. The size of this storage is
 * "max_frames*sizeof(struct dpaa2_dq)". The 'dpaa2_io_store' returned is a
 * wrapper structure allocated within the DPIO code, which owns and manages
 * allocated store.
 *
 * Return dpaa2_io_store struct for successfuly created storage memory, or NULL
 * if not getting the stroage for dequeue result in create API.
 */
struct dpaa2_io_store *dpaa2_io_store_create(unsigned int max_frames,
					     struct device *dev)
{
	struct dpaa2_io_store *ret;
	size_t size;

	ret = kmalloc(sizeof(*ret), GFP_KERNEL);
	if (!ret)
		return NULL;
	ret->max = max_frames;
	size = max_frames * sizeof(struct dpaa2_dq);

	ret->vaddr = vfio_setup_dma(size);
	ret->paddr = (u64)ret->vaddr;

	ret->idx = 0;
	ret->dev = dev;
	return ret;
}
EXPORT_SYMBOL(dpaa2_io_store_create);

/**
 * dpaa2_io_store_destroy() - Destroy the dma memory storage for dequeue
 * result.
 * @s: the storage memory to be destroyed.
 *
 * Frees to specified storage memory.
 */
void dpaa2_io_store_destroy(struct dpaa2_io_store *s)
{
	vfio_cleanup_dma(s->vaddr, s->max * sizeof(struct dpaa2_dq));
	s->vaddr = NULL;
	kfree(s->alloced_addr);
	kfree(s);
}
EXPORT_SYMBOL(dpaa2_io_store_destroy);

/**
 * dpaa2_io_store_next() - Determine when the next dequeue result is available.
 * @s: the dpaa2_io_store object.
 * @is_last: indicate whether this is the last frame in the pull command.
 *
 * Once dpaa2_io_store has been passed to a function that performs dequeues to
 * it, like dpaa2_ni_rx(), this function can be used to determine when the next
 * frame result is available. Once this function returns non-NULL, a subsequent
 * call to it will try to find the *next* dequeue result.
 *
 * Note that if a pull-dequeue has a null result because the target FQ/channel
 * was empty, then this function will return NULL rather than expect the caller
 * to always check for this on his own side. As such, "is_last" can be used to
 * differentiate between "end-of-empty-dequeue" and "still-waiting".
 *
 * Return dequeue result for a valid dequeue result, or NULL for empty dequeue.
 */
struct dpaa2_dq *dpaa2_io_store_next(struct dpaa2_io_store *s, int *is_last)
{
	int match;
	struct dpaa2_dq *ret = (struct dpaa2_dq *)&s->vaddr[s->idx];

	match = qbman_result_has_new_result(s->swp, (struct qbman_result *)ret);
	if (!match) {
		*is_last = 0;
		return NULL;
	}
	s->idx++;
	if (dpaa2_dq_is_pull_complete(ret)) {
		*is_last = 1;
		s->idx = 0;
		/*
		 * If we get an empty dequeue result to terminate a zero-results
		 * vdqcr, return NULL to the caller rather than expecting him to
		 * check non-NULL results every time.
		 */
		if (!(qbman_result_DQ_flags((struct qbman_result *)ret) & DPAA2_DQ_STAT_VALIDFRAME))
			ret = NULL;
	} else {
		*is_last = 0;
	}
	return ret;
}
EXPORT_SYMBOL(dpaa2_io_store_next);

int dpaa2_io_query_fq_count(struct dpaa2_io *d, u32 fqid, u32 *fcnt, u32 *bcnt)
{
	struct qbman_fq_query_np_rslt state;
	struct qbman_swp *swp;
	int ret;

	d = service_select(d);
	if (!d)
		return -ENODEV;

	swp = d->swp;
	pthread_mutex_lock(&d->lock_mgmt_cmd);
	ret = qbman_fq_query_state(swp, fqid, &state);
	pthread_mutex_unlock(&d->lock_mgmt_cmd);
	if (ret)
		return ret;
	*fcnt = qbman_fq_state_frame_count(&state);
	*bcnt = qbman_fq_state_byte_count(&state);

	return 0;
}
EXPORT_SYMBOL(dpaa2_io_query_fq_count);
/*
int dpaa2_io_query_bp_count(struct dpaa2_io *d, u32 bpid, u32 *num)
{
	struct qbman_attr state;
	struct qbman_swp *swp;
	int ret;

	d = service_select(d);
	if (!d)
		return -ENODEV;

	swp = d->swp;
	pthread_mutex_lock(&d->lock_mgmt_cmd);
	ret = qbman_bp_query(swp, bpid, &state);
	pthread_mutex_unlock(&d->lock_mgmt_cmd);
	if (ret)
		return ret;
	*num = qbman_bp_info_num_free_bufs(&state);

	return 0;
}
EXPORT_SYMBOL(dpaa2_io_query_bp_count);
*/
