/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 */

/**
 * @file	dpaa2_dev_intr_priv.h
 *
 * @brief	Private header file for DPAA2 interrupt event module
 */

#ifndef _DPAA2_DEV_INTR_PRIV_H_
#define _DPAA2_DEV_INTR_PRIV_H_

/* DPAA2 header files */
//#include <odp/api/std_types.h>
#include <dpaa2_common.h>
#include <dpaa2.h>
#include <dpaa2_vfio.h>
#include <dpaa2_malloc.h>

#define DPAA2_INTR_REGISTERED BIT_POS(31)
#define DPAA2_INTR_ENABLED BIT_POS(30)

/*!
 * DPAA2 interrupt stucture. This is kept by each device to store the FD and
 * flags corresponding to an interrupt.
 */
struct dpaa2_intr_handle {
	int fd; /*!< eventfd corresponding to the device */
	int poll_fd; /*!< epollfd corresponding to the device */
	uint32_t flags; /*!< flags including maskable/
		* automasked/is_enabled information */
};

/*!
 * @details	Get the interrupt information of a particular device from VFIO.
 *		This API will also populate the same in the DPAA2 database.
 *
 * @param[in]	dev_vfio_fd - Device FD (the one which is provided by VFIO)
 *
 * @param[in]	device_info - Device info corresponding to the device FD
 *		(also the one provided by VFIO)
 *
 * @param[in, out]	intr_handle - Pointer to DPAA2 interrupt structure for
 *		the device. This will get allocated within this API based
 *		on the number of interrupts and will also get populated
 *		by the information received from VFIO. Default value of
 *		FD will be populated to '0'.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int dpaa2_get_interrupt_info(int dev_vfio_fd,
		struct vfio_device_info *device_info,
		struct dpaa2_intr_handle **intr_handle);


/*!
 * @details	Register the interrupt with VFIO. This API will create an
 *		eventfd corresponding to the interrupt and register it with
 *		the VFIO
 *
 * @param[in]	dev_vfio_fd - Device FD (the one which is provided by VFIO)
 *
 * @param[in]	intr_handle - Pointer to DPAA2 interrupt structure at a
 *		particular 'index' for the device.
 *
 * @param[in]	index - Index of the 'intr_handle'. This also index represents
 *		the index provided to VFIO.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int dpaa2_register_interrupt(int dev_vfio_fd,
		struct dpaa2_intr_handle *intr_handle,
		uint32_t index);


/*!
 * @details	Enable the interrupt in VFIO.
 *
 * @param[in]	dev_vfio_fd - Device FD (the one which is provided by VFIO)
 *
 * @param[in]	intr_handle - Pointer to DPAA2 interrupt structure at a
 *		particular 'index' for the device which needs to be enabled.
 *
 * @param[in]	index - Index of the 'intr_handle'. This also index represents
 *		the index provided to VFIO.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int dpaa2_enable_interrupt(int dev_vfio_fd,
		struct dpaa2_intr_handle *intr_handle,
		uint32_t index);


/*!
 * @details	Disable the interrupt in VFIO.
 *
 * @param[in]	dev_vfio_fd - Device FD (the one which is provided by VFIO)
 *
 * @param[in]	intr_handle - Pointer to DPAA2 interrupt structure at a
 *		particular 'index' for the device which needs to be disabled.
 *
 * @param[in]	index - Index of the 'intr_handle'. This also index represents
 *		the index provided to VFIO.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int dpaa2_disable_interrupt(int dev_vfio_fd,
		struct dpaa2_intr_handle *intr_handle,
		uint32_t index);

#endif	/* _DPAA2_DEV_INTR_PRIV_H_ */
