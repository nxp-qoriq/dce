/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2014 Freescale Semiconductor, Inc.
 * All rights reserved.
 */

/*!
 * @file		dpaa2_cfg.h
 *
 * @brief		Common definitions and functions for DPAA2 framework.
 *
 * @addtogroup	DPAA2_CFG
 * @ingroup	DPAA2_COMMON
 * @{
 */

#ifndef _DPAA2_CFG_H_
#define _DPAA2_CFG_H_

#ifdef __cplusplus
extern "C" {
#endif


/*! Default namespace ID */
#define DPAA2_APP_DEF_NSID	0

/*!Maximum number of threads */
#define DPAA2_CONFIG_MAX_THREADS  128

/*!Maximum number of cores */
#define DPAA2_MAX_LCORE		8

/*!Maximum number of buffer pools */
#define DPAA2_MAX_BUF_POOLS	8

/*! Maximum number of memory pools allowed */
#define DPAA2_MAX_MEM_POOLS 128

/*! Maximum size of a log file */
#define DPAA2_MAX_LOG_FILES_SIZE 4000
/*! Default number of log files which will be created */
#define DPAA2_DEF_LOG_FILES 2
/*! Maximum number of log files which can be created */
#define DPAA2_MAX_LOG_FILES 8
/*! Default log file size */
#define DPAA2_DEF_LOG_FILE_SIZE 1000

#ifdef __cplusplus
}
#endif

/*! @} */
#endif /* _DPAA2_CFG_H_ */
