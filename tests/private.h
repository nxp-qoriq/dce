/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#include "dce-test-data.h"

static int dbg_lvl;

#define GET_THREAD_NAME() \
({ \
	/* 16 bytes including \0 is specified max Linux thread name */ \
	static __thread char __thread_name[16]; \
	int __err; \
	__err = pthread_getname_np(pthread_self(), __thread_name, \
			sizeof(__thread_name)); \
	if (__err) \
		snprintf(__thread_name, sizeof(__thread_name), \
				"%s", strerror(__err)); \
	__thread_name; \
})

#ifndef debug
#define debug(level, fmt, args...) \
({ \
	/* use printf instead of pr_err and pr_info because they do not
	 * print from threads other than main */ \
	if (level <= dbg_lvl) { \
		printf("Worker %s: ", GET_THREAD_NAME()); \
		printf(fmt, ##args); \
	} \
})
#endif

#define SOFT_ASSERT
#ifdef SOFT_ASSERT
#define ASSERT(condition) \
do { \
	fflush(stdout); \
	fflush(stderr); \
	if (!(condition)) { \
		printf("SCREAM! %s,%s,%s,line=%d, %s\n", #condition, \
			__FILE__, __func__, __LINE__, \
			GET_THREAD_NAME()); \
	} \
	fflush(stderr); \
	fflush(stdout); \
} while(0)
#else /* SOFT_ASSERT */
#define ASSERT(condition) \
do { \
	fflush(stdout); \
	fflush(stderr); \
	assert(condition); \
} while(0)
#endif /* SOFT_ASSERT */

static inline uint64_t read_cntvct(void)
{
	uint64_t ret;
	uint64_t ret_new, timeout = 200;

	asm volatile ("mrs %0, cntvct_el0" : "=r" (ret));
	asm volatile ("mrs %0, cntvct_el0" : "=r" (ret_new));
	while (ret != ret_new && timeout--) {
		ret = ret_new;
		asm volatile ("mrs %0, cntvct_el0" : "=r" (ret_new));
	}
	assert(timeout || ret == ret_new);
	return ret;
}
