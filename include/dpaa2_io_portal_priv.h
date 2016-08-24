/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 */

/**
 * @file		dpaa2_io_portal_priv.h
 * @description		Private functions & MACRO definitions for DPAA2 Data Path I/O portal
			type Device
 */

#ifndef _DPAA2_IO_PORTAL_PRIV_H_
#define _DPAA2_IO_PORTAL_PRIV_H_

/*Standard header files*/
#include <stddef.h>
#include <pthread.h>

/*DPAA2 header files*/
#include <std_types.h>
#include <dpaa2_common.h>
#include <dpaa2.h>
#include <dpaa2_vfio.h>
#include <dpaa2_dev.h>
#include <dpaa2_dev_priv.h>
#include <dpaa2_malloc.h>
#include <byteorder.h>
#include <dpaa2_lock.h>
#include <spinlock.h>
#include <atomic.h>
#include <dpaa2_dev_intr_priv.h>

/*MC header files*/
#include <fsl_dpio.h>
#include <fsl_dpio_cmd.h>
#include <fsl_mc_sys.h>
/*QBMAN header files*/
#include <fsl_qbman_portal.h>

#ifdef __cplusplus
extern "C" {
#endif
/* Macros to define feature enable/disable options */
#define LDPAA_IO_P_VENDOR_ID	6487
#define LDPAA_IO_P_MAJ_NUM	DPIO_VER_MAJOR
#define LDPAA_IO_P_MIN_NUM	DPIO_VER_MINOR
#define LDPAA_IO_P_NAME		"ldpaa-dpio"

/* Number of maximum frames storage in private dqrr storage */
#define NUM_MAX_RECV_FRAMES	16

/* Maximum number of channels*/
#define MAX_SCHED_GRPS		11

/* DPIO IRQ index for VFIO */
#define VFIO_DPIO_DATA_IRQ_INDEX 0
/* Invalid DPIO Channel index */
#define DPAA2_INVALID_CHANNEL_IDX	((uint8_t)(-1))

/*Stashing Macros*/
#define DPAA2_CORE_CLUSTER_BASE		0x04
#define DPAA2_CORE_CLUSTER_FIRST		(DPAA2_CORE_CLUSTER_BASE + 0)
#define DPAA2_CORE_CLUSTER_SECOND	(DPAA2_CORE_CLUSTER_BASE + 1)
#define DPAA2_CORE_CLUSTER_THIRD		(DPAA2_CORE_CLUSTER_BASE + 2)
#define DPAA2_CORE_CLUSTER_FOURTH	(DPAA2_CORE_CLUSTER_BASE + 3)

#define DPAA2_CORE_CLUSTER_GET(sdest, cpu_id) \
do { \
	if (cpu_id == 0 || cpu_id == 1) \
		sdest = DPAA2_CORE_CLUSTER_FIRST; \
	else if (cpu_id == 2 || cpu_id == 3) \
		sdest = DPAA2_CORE_CLUSTER_SECOND; \
	else if (cpu_id == 4 || cpu_id == 5) \
		sdest = DPAA2_CORE_CLUSTER_THIRD; \
	else \
		sdest = DPAA2_CORE_CLUSTER_FOURTH; \
} while (0)

/*
 * The DPAA2 DPIO device structure.
 */
struct dpaa2_dpio_dev {
	TAILQ_ENTRY(dpaa2_dpio_dev) next; /**< Pointer to Next device instance */
	struct qbman_result *hold_dqrr; /**< Last DQRR Entry which is on hold for this SW portal */
	dpaa2_mbuf_pt hold_buf; /**< Last buffer which is on hold  w.r.t hold_dqrr ptr */
	uint32_t index; /**< Index of a instance in the list */
//	odp_atomic_u16_t ref_count; /**< How many thread contexts are sharing this.*/
	struct fsl_mc_io *dpio; /** handle to DPIO portal object */
	uint16_t token;
	struct qbman_swp *sw_portal; /**< SW portal object */
	lock_t lock; /**< Mutex Lock required when Portal is shared */
	void *mc_portal; /**< MC Portal for configuring this device */
	uint64_t qbman_portal_ce_paddr; /**< Physical address of Cache Enabled Area */
	uint64_t ce_size; /**< Size of the CE region */
	uint64_t qbman_portal_ci_paddr; /**< Physical address of Cache Inhibit Area */
	uint64_t ci_size; /**< Size of the CI region */
	struct dpaa2_intr_handle *intr_handle;
	int32_t	vfio_fd; /**< File descriptor received via VFIO */
	int32_t hw_id; /**< An unique ID of this DPIO device instance */
	uint8_t ch_idx[MAX_SCHED_GRPS];	/**< channel indexes corresponding to DPCON
			  objects for static dequeue mapping */
	uint8_t ch_count;  /**< count of channels which are mapped for
			     static dequeue **/
};

/* DCA related helper Macros */
#define ANY_ATOMIC_CNTXT_TO_FREE(mbuf) \
	(mbuf->atomic_cntxt == thread_io_info.dpio_dev->hold_dqrr)
#define IS_HOLD_DQRR_VALID (thread_io_info.dpio_dev->hold_dqrr != NULL)
#define MARK_HOLD_DQRR_PTR_INVALID (thread_io_info.dpio_dev->hold_dqrr = NULL)
#define MARK_HOLD_BUF_CNTXT_INVALID \
	(thread_io_info.dpio_dev->hold_buf->atomic_cntxt = INVALID_CNTXT_PTR)
#define SAVE_HOLD_BUF_PTR(val) \
	(thread_io_info.dpio_dev->hold_buf = val)
#define SAVE_HOLD_DQRR_PTR(val) \
	(thread_io_info.dpio_dev->hold_dqrr = (struct qbman_result *)val)

#define GET_HOLD_DQRR_PTR (thread_io_info.dpio_dev->hold_dqrr)
#define GET_HOLD_DQRR_IDX \
	(qbman_get_dqrr_idx(thread_io_info.dpio_dev->hold_dqrr))

/*!
 * DPAA2 device list structure
 */
TAILQ_HEAD(dpaa2_dpio_device_list, dpaa2_dpio_dev); /*!< DPAA2 DPIO device List */
extern struct dpaa2_dpio_device_list *dpio_dev_list; /*!< Global list of DPAA2 devices. */

struct thread_io_info_t {
	struct dpaa2_dpio_dev *dpio_dev;
	struct qbman_result *dq_storage;
};
/*! Global per thread DPIO portal */
extern __thread struct thread_io_info_t thread_io_info;

/*! The globally stored DPIO for notifier */
extern struct dpaa2_dpio_dev *notif_dpio;
/* The epoll fd to be used for epolling on the notifier DPIO */
extern int notif_dpio_epollfd;

/* Helper Macro to acquire lock for IO Portal */
#define	SWP_LOCK(dpio_dev)	({					\
		if (odp_atomic_read_u16(&dpio_dev->ref_count) > 1)	\
					LOCK(dpio_dev->lock);		\
		})

/* Helper Macro to unlock IO Portal */
#define	SWP_UNLOCK(dpio_dev)	({					\
		if (odp_atomic_read_u16(&dpio_dev->ref_count) > 1)	\
					UNLOCK(dpio_dev->lock);		\
		})

int32_t dpaa2_io_portal_init(void);

int32_t dpaa2_io_portal_exit(void);

/*!
 * @details	DPIO driver probe function to initialize the device.
 *
 * @param[in]	dev - Pointer to DPAA2 device
 *
 * @param[in]	data - device specific configuration data
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_io_portal_probe(struct dpaa2_dev *dev,
			ODP_UNUSED const void *data);

/*!
 * @details	DPIO driver shutdown function to close the device.
 *
 * @param[in]	dev - Pointer to DPAA2 device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_io_portal_close(struct dpaa2_dev *dev);

/*!
 * @details	Register the DPIO interrupt with VFIO
 *
 * @param[in]	dpio_dev - Pointer to DPIO device
 *
 * @returns	index - interrupt index
 *
 */
int dpaa2_register_dpio_interrupt(struct dpaa2_dpio_dev *dpio_dev,
	uint32_t index);

void release_dpio(struct dpaa2_dpio_dev *dpio_dev);

#ifdef __cplusplus
}
#endif

#endif /* _DPAA2_IO_PORTAL_PRIV_H_ */
