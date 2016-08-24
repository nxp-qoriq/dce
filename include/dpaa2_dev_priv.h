/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2014-2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 */

/**
 * @file		dpaa2_dev_priv.h
 * @description		Private function & definitions for DPAA2 Device framework
 */

#ifndef _DPAA2_DEV_PRIV_H_
#define _DPAA2_DEV_PRIV_H_

#include <pthread.h>

#include <dpaa2.h>
#include <dpaa2_dev.h>
#include "dpaa2_vfio.h"
#include <fsl_mc_sys.h>

/*Macros to define QBMAN enqueue options */
/* Only Enqueue Error responses will be
 * pushed on FQID_ERR of Enqueue FQ */
#define DPAA2_EQ_RESP_ERR_FQ		0
/* All Enqueue responses will be pushed on address
 * set with qbman_eq_desc_set_response */
#define DPAA2_EQ_RESP_ALWAYS		1
/* Device is consumed at time of probing and does not needs
 * to be added into dpaa2_dev list */
#define DPAA2_DEV_CONSUMED		2

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Definitions of all functions exported by an Ethernet driver through the
 * the generic structure of type *dpaa2_dev_fops*
 */
typedef int32_t (*dpaa2_dev_probe_t)(struct dpaa2_dev *dev, const void *cfg);
	 /**< Driver Function pointer to initialize a device instance. */
typedef int32_t (*dpaa2_dev_shutdown_t)(struct dpaa2_dev *dev); /**< Driver
				Function pointer to close a device. */
typedef int32_t (*dpaa2_dev_cfg_t)(struct dpaa2_dev *dev); /**< Driver Function
			pointer for device default configuration. */
typedef int32_t (*dpaa2_dev_get_vqid_t)(void *vq); /**< Driver Function
					pointer to get the FQID/CHID */

/*
 * A structure that stores Common File operation & data for all drivers.
 */
struct dpaa2_driver {
	/**< Driver name. */
	const char	*name;
	uint32_t	vendor_id;
	uint32_t	major;
	uint32_t	minor;
	enum dpaa2_dev_type dev_type;
	/**< Device type of this Driver */
	dpaa2_dev_probe_t dev_probe;
	/**< Function pointer to probe a device. */
	dpaa2_dev_shutdown_t dev_shutdown;
	/**< Function pointer to close a device. */
};

/*
 * The DPAA2 device structure private data.
 */
struct dpaa2_dev_priv {
	void *mc_portal; /**< MC Portal for configuring this device */
	void *hw; /**< Hardware handle for this device.Used by DPAA2 framework */
	int32_t hw_id; /**< An unique ID of this device instance */
	int32_t qdid; /**< QDID for this device instance */
	int32_t	vfio_fd; /**< File descriptor received via VFIO */
	uint16_t token; /**< Token required by DPxxx objects */
	struct dpaa2_intr_handle *intr_handle;
	struct dpaa2_bp_list *bp_list; /**<Attached buffer pool list */

	/* Device operation function pointers */
	dpaa2_dev_cfg_t	fn_dev_cfg; /**< Driver Function pointer for device
				      default configuration. */
	dpaa2_dev_get_vqid_t fn_get_vqid; /**< Driver Function pointer to
					get the FQID/CHID */
	void	*drv_priv; /**< Private data of this device that is required
		by device driver. This shall contain device-specific Operations
		& Configuration parameters. */
	uint32_t flags;	/**< Flags passed by user to Enable features
			  like Shared Memory usage, interrupts/notifier. */

};


struct dpaa2_dma_mem {
	unsigned long *ptr;
	uint64_t phys_addr;
};

extern void dpaa2_register_driver(struct dpaa2_driver *drv);
extern void dpaa2_unregister_driver(struct dpaa2_driver *drv);

static inline int32_t  dpaa2_dummy_dev_fn(ODP_UNUSED struct dpaa2_dev *dev)
{
	/* DO nothing */
	DPAA2_INFO(FW, "Dummy function");
	return DPAA2_SUCCESS;
}

static inline int32_t  dpaa2_dummy_vq_fn(ODP_UNUSED void *vq)
{
	/* DO nothing */
	DPAA2_INFO(FW, "Dummy function");
	return DPAA2_SUCCESS;
}

extern int ndev_count;

/* The DPAA2 drivers list of registered drivers */
/* Drivers required for NIC, SEC, PME, DCE, AIOP_CI etc */
extern struct dpaa2_driver *dpaa2_driver_list[DPAA2_MAX_DEV];

void dpaa2_device_dump(void *stream);

#ifdef __cplusplus
}
#endif

#endif /* _DPAA2_DEV_PRIV_H_ */
