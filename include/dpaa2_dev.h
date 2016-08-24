/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2014-2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 */

/*!
 * @file	dpaa2_dev.h
 *
 * @brief	Device framework for DPAA2 based applications.
 *		- Centralized driver model.
 *		- Library to initialize, start, stop &
 *		  configure a device.
 *
 * @addtogroup	DPAA2_CORE
 * @ingroup	DPAA2_DEV
 * @{
 */

#ifndef _DPAA2_DEV_H_
#define _DPAA2_DEV_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <std_types.h>
#include <dpaa2_mbuf.h>
#include <dpaa2_queue.h>

/*! Default maximum size used in DPAA2 to store name of a DPAA2 DEVICE */
#define DEF_NAME_SZ	24
/* forward declaration of dpaa2_mbuf to avoid cyclic dependency.*/
struct dpaa2_mbuf;
/*!
 *  A set of values to identify Device Type.
 */

enum dpaa2_dev_type {
	DPAA2_NIC,	/*!< Network Interface */
	DPAA2_SEC,	/*!< SEC Accelerator Interface */
	DPAA2_PME,	/*!< PME Accelerator Interface */
	DPAA2_DCE,	/*!< DCE Accelerator Interface */
	DPAA2_AIOP_CI,	/*!< Advance IO Accelerator Command Interface */
	DPAA2_CONC,	/*!< Concentrator Device to group multiple VQ  */
	DPAA2_SW,	/*!< Switch Device */
	DPAA2_IO_CNTXT,	/*!< Input Outut context device object */
	DPAA2_MAX_DEV	/*!< Maximum Device types count */
};

/*! Maximum number of RX VQ's */
#define MAX_RX_VQS	64
/*! Maximum number of TX VQ's */
#define MAX_TX_VQS	64

/*! Maximum number of Error VQ's corresponding to each Tx */
#define MAX_ERR_VQS	 MAX_TX_VQS
/*! Maximum default number of Error VQ's corresponding to a device */
#define MAX_DEF_ERR_VQS        2

/*!
 *  Set of vq index used to receive tx-conf and errors.
 */
#define ERR_VQ_BASE    0

/*! Index of the default Error VQ for tx-conf/error handling */
#define DEF_TX_CONF_ERR_VQ_INDEX (ERR_VQ_BASE + MAX_ERR_VQS)

/*! Index of the default Error VQ of the device */
#define DEF_ERR_VQ_INDEX (DEF_TX_CONF_ERR_VQ_INDEX + 1)

/*!
 *  A set of values to identify State of a Device.
 */
enum dev_state {
	DEV_INACTIVE = 0, /*!< Network Interface is not operational */
	DEV_ACTIVE	/*!< Network Interface ia Operational */
};

/*!
 *  A set of values to identify type of frame queue.
 */
enum dpaa2_fq_type {
	DPAA2_FQ_TYPE_RX = 0,		/*!< RX frame queue */
	DPAA2_FQ_TYPE_RX_ERR,		/*!< RX error frame queue */
	DPAA2_FQ_TYPE_TX,		/*!< TX frame queue */
	DPAA2_FQ_TYPE_TX_CONF_ERR	/*!< TX Conf/Error frame queue */
};

/*! No VQ scheduling */
#define ODP_SCHED_SYNC_NONE     0
/*! VQ shall be configured as atomic - order shall be preserved*/
#define ODP_SCHED_SYNC_ATOMIC   1
/*! VQ shall be configured in order restoration mode  */
#define ODP_SCHED_SYNC_ORDERED  2

/*!
 * DPAA2 VQ attrubutes
 */
struct dpaa2_vq_param {
	struct dpaa2_dev *conc_dev;	/*!< Concentrator device if vq needs to
						be attached */
	uint8_t		sync;		/*!< Whether needs to be created atmoic
						or ordered */
	uint8_t		prio;		/*!< Priority associated with the vq */
};

/*!
 * DPAA2 device structure.
 */
struct dpaa2_dev {
	TAILQ_ENTRY(dpaa2_dev) next; /*!< Next in list. */

	uint16_t state; /**< device is ACTIVE or Not */
	enum dpaa2_dev_type dev_type; /*!< Ethernet NIC, Accelerators
				     * like SEC, PME, DCE, AIOP */
	char dev_string[DEF_NAME_SZ]; /*!< To identify the device during bus scan */

	void *priv; /*!< Private Data for this device */
	uint16_t num_rx_vqueues; /*!< Number of Rx queues in use. For DPAA2_CONC
				  * device, it shall awlays be 1 */
	uint16_t num_tx_vqueues; /*!< Number of Tx queues in use.
				  * 0 for Concentrator Device */
	struct dpaa2_dev *conc_dev; /*!< If any, Concentrator Device(AVQ)
				    * linked to this device */
	void *rx_vq[MAX_RX_VQS]; /*!< Set of RX virtual Queues
					  * for this device */
	void *tx_vq[MAX_TX_VQS]; /*!< Set of TX virtual Queues
				  * for this device */
	void *err_vq[MAX_ERR_VQS + MAX_DEF_ERR_VQS]; /*!< Set of Err virtual
						Queues for this device */
	uint64_t	pktio;
};

/*!
 * Typedef for the callback registered by the user. When this callback is
 * registered, on receive of any notification on the VQ this callback will
 * be called by the dispatcher. This will only provide the notifications
 * and will override the default evenfd based notification mechanism of DPAA2.
 */
typedef void (*dpaa2_notification_callback_t) (uint64_t user_cnxt);

/*!
 * DPAA2 device list structure
 */
TAILQ_HEAD(dpaa2_device_list, dpaa2_dev); /*!< DPAA2 devices in D-linked Q. */
extern struct dpaa2_device_list device_list; /*!< Global list of DPAA2 devices. */

/*!
 * @details	Initialize & configure a device with default settings.
 *		This function must be invoked first before any other function
 *		in the device specific API. This function can also be re-invoked
 *		when a device is in the stopped state.
 *
 * @param[in]   dev - Pointer to DPAA2 device structure
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
extern int32_t dpaa2_dev_init(struct dpaa2_dev *dev);

/*!
 * @details	Shutdown a given configured DPAA2 device.
 *
 * @param[in]	dev -  Pointer to DPAA2 device structure.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
extern int32_t dpaa2_dev_shutdown(struct dpaa2_dev *dev);

/*!
 * @details	Provide maximum number of receive (RX) virtual
 *		queues (VQ) supported for the given device.
 *
 * @param[in]	dev - Pointer to DPAA2 device structure.
 *
 * @returns	Number of RX VQ supported for the given device.
 *
 */
extern int32_t dpaa2_dev_get_max_rx_vq(struct dpaa2_dev *dev);

/*!
 * @details	Provide maximum number of transmit (TX) virtual
 *		queues (VQ) supported for the given device.
 *
 * @param[in]	dev - Pointer to DPAA2 device structure.
 *
 * @returns	Number of TX VQ supported for the given device.
 *
 */
extern int32_t dpaa2_dev_get_max_tx_vq(struct dpaa2_dev *dev);

/*!
 * @details	This function shall be used for dumping the device list
 *		information for debug purpose only.
 *
 * @param[out]	stream - pointer to stream.
 *
 * @returns   Nothing.
 *
 */
void dpaa2_device_list_dump(void *stream);

/*!
 * @details	Provide the hwid  for the given device.
 *
 * @param[in]	dev - Pointer to DPAA2 device structure.
 *
 * @returns	HW ID for the given device.
 *
 */
int32_t dpaa2_dev_hwid(struct dpaa2_dev *dev);

/*!
 * @details	Affine the concentator device list to thread
 *		specific IO conext.
 *
 * @param[in]	conc_dev - Concentrator device which is to be affined
 *
 * @returns	DPAA2_SUCCESS on success, Negative otherwise.
 *
 */
int32_t dpaa2_dev_affine_conc_list(struct dpaa2_dev *conc_dev);

/*!
 * @details	De-affine the concentator device list to thread
 *		specific IO conext.
 *
 * @param[in]	conc_dev - Concentrator device which is to be deaffined
 *
 * @returns	DPAA2_SUCCESS on success, Negative otherwise.
 *
 */
int32_t dpaa2_dev_deaffine_conc_list(struct dpaa2_dev *conc_dev);


/*!
 * @details	Return device pointer associated to given VQ.
 *
 * @param[in]	vq - Pointer to VQ
 *
 * @returns	dpaa2_dev pointer on success, NULL otherwise.
 *
 */
struct dpaa2_dev *dpaa2_dev_from_vq(void *vq);

/*!
 * @details     Set given uhandle to VQ.
 *
 * @param[in]   vq - Pointer to VQ
 *
 * @param[in]   uhandle - Handle value which needs to be set.
 *
 *
 * @returns     DPAA2_SUCCESS on success, DPAA2_FAILURE otherwise.
 *
 */
int dpaa2_dev_set_vq_handle(void *vq, uint64_t uhandle);

/*!
 * @details     Return handle associated to given VQ.
 *
 * @param[in]   vq - Pointer to VQ
 *
 * @returns     Handle of specified queue on success, DPAA2_FAILURE otherwise.
 *
 */
uint64_t dpaa2_dev_get_vq_handle(void *vq);

#ifdef __cplusplus
}
#endif

/*! @} */
#endif /* _DPAA2_DEV_H_ */
