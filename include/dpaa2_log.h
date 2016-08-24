/*
 *   Derived from DPDK's rte_log.h
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *   Copyright 2014-2015 Freescale Semiconductor, Inc.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 */
#ifndef _DPAA2_LOG_H_
#define _DPAA2_LOG_H_

/*!
 * @file dpaa2_log.h
 *
 * @brief RTE Logs API
 * This file provides a log API to RTE applications.
 * @addtogroup DPAA2_LOG
 * @ingroup DPAA2_RTS
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>

/*! The dpaa2_log structure. */
struct dpaa2_logs {
	uint32_t type;  /*!< Bitfield with enabled logs. */
	uint32_t level; /*!< Log level. */
	uint32_t number_of_files;  /*!< number of log files. */
	uint16_t file_size;  /*!< log file size . */
	uint8_t file_logging;  /*!< file enabled logs. */
};

/*! Global log informations */
extern struct dpaa2_logs dpaa2_logs;

/*! SDK log type */
#define DPAA2_LOGTYPE_EAL     0x00000001 /*!< Log related to eal. */
#define DPAA2_LOGTYPE_MALLOC  0x00000002 /*!< Log related to malloc. */
#define DPAA2_LOGTYPE_RING    0x00000004 /*!< Log related to ring. */
#define DPAA2_LOGTYPE_MEMPOOL 0x00000008 /*!< Log related to mempool. */
#define DPAA2_LOGTYPE_TIMER   0x00000010 /*!< Log related to timers. */
#define DPAA2_LOGTYPE_PMD     0x00000020 /*!< Log related to poll mode driver. */
#define DPAA2_LOGTYPE_HASH    0x00000040 /*!< Log related to hash table. */
#define DPAA2_LOGTYPE_LPM     0x00000080 /*!< Log related to LPM. */
#define DPAA2_LOGTYPE_KNI     0x00000100 /*!< Log related to KNI. */
#define DPAA2_LOGTYPE_ACL     0x00000200 /*!< Log related to ACL. */
#define DPAA2_LOGTYPE_POWER   0x00000400 /*!< Log related to power. */
#define DPAA2_LOGTYPE_METER   0x00000800 /*!< Log related to QoS meter. */
#define DPAA2_LOGTYPE_SCHED   0x00001000 /*!< Log related to QoS port scheduler*/

#define DPAA2_LOGTYPE_FW	   DPAA2_LOGTYPE_EAL /*!< Log related to dpaa2 framework*/
#define DPAA2_LOGTYPE_FRAMEQ	0x0000002 /**< Log related to S/W frame Queue */
#define DPAA2_LOGTYPE_ETH   DPAA2_LOGTYPE_PMD /*!< Log related to ethernet */
#define DPAA2_LOGTYPE_BUF   0x0002000	/*!< Log related to Buffer */
#define DPAA2_LOGTYPE_SEC   0x0004000	/*!< Log related to Sec driver */
#define DPAA2_LOGTYPE_CMD   0x0008000	/*!< Log related to AIOP driver */
#define DPAA2_LOGTYPE_MEMZONE 0x0010000	/*!< Log related to memzone */
#define DPAA2_LOGTYPE_CONC	0x0020000	/*!< Log related to concentrator */
#define DPAA2_LOGTYPE_NOTIFIER	0x0040000 /**< Log related to notifier */

#define DPAA2_LOGTYPE_ALL  0x000fffff	/*!< Logs related to all type */

/*! these log types can be used in an application */
#define DPAA2_LOGTYPE_USER1   0x01000000 /*!< User-defined log type 1. */
#define DPAA2_LOGTYPE_USER2   0x02000000 /*!< User-defined log type 2. */
#define DPAA2_LOGTYPE_USER3   0x04000000 /*!< User-defined log type 3. */
#define DPAA2_LOGTYPE_USER4   0x08000000 /*!< User-defined log type 4. */
#define DPAA2_LOGTYPE_USER5   0x10000000 /*!< User-defined log type 5. */
#define DPAA2_LOGTYPE_USER6   0x20000000 /*!< User-defined log type 6. */
#define DPAA2_LOGTYPE_USER7   0x40000000 /*!< User-defined log type 7. */
#define DPAA2_LOGTYPE_USER8   0x80000000 /*!< User-defined log type 8. */

#define DPAA2_LOGTYPE_APP1 DPAA2_LOGTYPE_USER1
#define DPAA2_LOGTYPE_APP2 DPAA2_LOGTYPE_USER2

/*! Can't use 0, as it gives compiler warnings */
#define DPAA2_LOG_EMERG    1U  /*!< System is unusable.               */
#define DPAA2_LOG_ALERT    2U  /*!< Action must be taken immediately. */
#define DPAA2_LOG_CRIT     3U  /*!< Critical conditions.              */
#define DPAA2_LOG_ERR      4U  /*!< Error conditions.                 */
#define DPAA2_LOG_WARNING  5U  /*!< Warning conditions.               */
#define DPAA2_LOG_NOTICE   6U  /*!< Normal but significant condition. */
#define DPAA2_LOG_INFO     7U  /*!< Informational.                    */
#define DPAA2_LOG_DEBUG    8U  /*!< Debug-level messages.             */
#define DPAA2_LOG_LEVEL    9U  /*!< Maximum log level.		     */

/*!
 * Check if log level set in DPAA2 is greater than
 * or equal to the specified 'lvl'
 */
#define IF_LOG_LEVEL(lvl)  if (dpaa2_logs.level >= lvl)

/*!
 * Set the global log level.
 *
 * After this call, all logs that are lower or equal than level and
 * lower or equal than the DPAA2_LOG_LEVEL configuration option will be
 * displayed.
 *
 * @param level
 *   Log level. A value between DPAA2_LOG_EMERG (1) and DPAA2_LOG_DEBUG (8).
 */
void dpaa2_set_log_level(uint32_t level);

/*!
 * Get the global log level.
 */
uint32_t dpaa2_get_log_level(void);

/*!
 * Enable or disable the log type.
 *
 * @param type
 *   Log type, for example, DPAA2_LOGTYPE_EAL.
 * @param enable
 *   True for enable; false for disable.
 */
void dpaa2_set_log_type(uint32_t type, int enable);
/*!
 * Get the current loglevel for the message being processed.
 *
 * Before calling the user-defined stream for logging, the log
 * subsystem sets a per-lcore variable containing the loglevel and the
 * logtype of the message being processed. This information can be
 * accessed by the user-defined log output function through this
 * function.
 *
 * @return
 *   The loglevel of the message being processed.
 */
int dpaa2_log_cur_msg_loglevel(void);

/*!
 * Get the current logtype for the message being processed.
 *
 * Before calling the user-defined stream for logging, the log
 * subsystem sets a per-lcore variable containing the loglevel and the
 * logtype of the message being processed. This information can be
 * accessed by the user-defined log output function through this
 * function.
 *
 * @return
 *   The logtype of the message being processed.
 */
int dpaa2_log_cur_msg_logtype(void);

/*!
 * Enable or disable the history (enabled by default)
 *
 * @param enable
 *   true to enable, or 0 to disable history.
 */
void dpaa2_log_set_history(int enable);

/*!
 * Dump the log history to a file
 *
 * @param f
 *   A pointer to a file for output
 */
void dpaa2_log_dump_history(FILE *f);

/*!
 * Generates a log message.
 *
 * The message will be sent in the stream
 *
 * The level argument determines if the log should be displayed or
 * not, depending on the global dpaa2_logs variable.
 *
 * The preferred alternative is the DPAA2_LOG() function because debug logs may
 * be removed at compilation time if optimization is enabled. Moreover,
 * logs are automatically prefixed by type when using the macro.
 *
 * @param level
 *   Log level. A value between DPAA2_LOG_EMERG (1) and DPAA2_LOG_DEBUG (8).
 * @param logtype
 *   The log type, for example, DPAA2_LOGTYPE_EAL.
 * @param format
 *   The format string, as in printf(3), followed by the variable arguments
 *   required by the format.
 * @return
 *   - 0: Success.
 *   - Negative on error.
 */
int dpaa2_log(uint32_t level, uint32_t logtype, const char *format, ...)
#ifdef __GNUC__
#if (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 2))
	__attribute__((cold))
#endif
#endif
	__attribute__((format(printf, 3, 4)));

/*!
 * Generates a log message.
 *
 * The DPAA2_LOG() is equivalent to dpaa2_log() with two differences:

 * - DPAA2_LOG() can be used to remove debug logs at compilation time,
 *   depending on DPAA2_LOG_LEVEL configuration option, and compilation
 *   optimization level. If optimization is enabled, the tests
 *   involving constants only are pre-computed. If compilation is done
 *   with -O0, these tests will be done at run time.
 * - The log level and log type names are smaller, for example:
 *   DPAA2_LOG(INFO, EAL, "this is a %s", "log");
 *
 * @param l
 *   Log level. A value between EMERG (1) and DEBUG (8). The short name is
 *   expanded by the macro, so it cannot be an integer value.
 * @param t
 *   The log type, for example, EAL. The short name is expanded by the
 *   macro, so it cannot be an integer value.
 * @param fmt
 *   The fmt string, as in printf(3), followed by the variable arguments
 *   required by the format.
 * @param args
 *   The variable list of arguments according to the format string.
 * @return
 *   - 0: Success.
 *   - Negative on error.
 */

#ifdef DPAA2_LOGLIB_DISABLE
#define DPAA2_LOG(l, t, fmt, arg...) \
	fprintf(stderr, "\n%s %d-%s-" fmt, __func__, __LINE__, #l, ##arg)
#else
#define DPAA2_LOG(l, t, f, ...) \
	(void)(((DPAA2_LOG_ ## l <= DPAA2_LOG_LEVEL) &&		\
	(DPAA2_LOG_ ## l <= dpaa2_logs.level) &&			\
	(DPAA2_LOGTYPE_ ## t & dpaa2_logs.type)) ?		\
dpaa2_log(DPAA2_LOG_ ## l, DPAA2_LOGTYPE_ ## t, "\n%s %d-" # t "-" # l ":" f, \
	__func__, __LINE__, ##__VA_ARGS__) : 0)
#endif

/*! System is unusable. */
#define DPAA2_EMREG(app, fmt, ...) DPAA2_LOG(EMERG, app, fmt, ##__VA_ARGS__)

/*! Action must be taken immediately. */
#define DPAA2_ALERT(app, fmt, ...) DPAA2_LOG(ALERT, app,  fmt, ##__VA_ARGS__)

/*! Critical conditions. */
#define DPAA2_CRIT(app, fmt, ...) DPAA2_LOG(CRIT, app,  fmt, ##__VA_ARGS__)
/*! Functional Errors. */
#define DPAA2_ERR(app, fmt, ...)  DPAA2_LOG(ERR, app, fmt, ##__VA_ARGS__)
/*! Warning Conditions. */
#define DPAA2_WARN(app, fmt, ...) DPAA2_LOG(WARNING, app, fmt, ##__VA_ARGS__)
/*! Normal but significant conditions. */
#define DPAA2_NOTE(app, fmt, ...) DPAA2_LOG(NOTICE, app, fmt, ##__VA_ARGS__)

#ifdef DPAA2_DEBUG
/*! Functional Trace. */
#define DPAA2_TRACE(app) DPAA2_LOG(DEBUG, app, "trace")
/*! Informational. */
#define DPAA2_INFO(app, fmt, ...) DPAA2_LOG(INFO, app, fmt, ##__VA_ARGS__)
/*! Low Level Debug. */
#define DPAA2_DBG(app, fmt, ...) DPAA2_LOG(DEBUG, app, fmt, ##__VA_ARGS__)
#define DPAA2_DBG2(...)
#else
#define DPAA2_TRACE(...)
#define DPAA2_INFO(...)
#define DPAA2_DBG(...)
#define DPAA2_DBG2(...)
#endif

#ifdef __cplusplus
}
#endif

/*! @} */
#endif /* _DPAA2_LOG_H_ */
