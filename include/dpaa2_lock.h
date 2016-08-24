/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2014 Freescale Semiconductor, Inc.
 * All rights reserved.
 */

/*!
 * @file	dpaa2_lock.h
 *
 * @brief	Standard Synchronization locks for user space programming.
 *		- mutex - recursive and non-recursive
 *		- read-write locks - recursive and non-recursive
 *		- barrier - recursive and non-recursive
 *
 * @addtogroup DPAA2_LOCK
 * @ingroup DPAA2_RTS
 * @{
 */

#ifndef _DPAA2_LOCK_H
#define _DPAA2_LOCK_H

#include <pthread.h>
#include <rwlock.h>
#include <barrier.h>
/*! Mutex lock type */
typedef pthread_mutex_t lock_t;
/*! Read-write lock type */
//typedef odp_rwlock_t rwlock_t;
/*! Barrier type */
//typedef odp_barrier_t barrier_t;

/*pthread_mutex_t Mutex;
pthread_mutexattr_t Attr;

pthread_mutexattr_init(&Attr);
pthread_mutexattr_settype(&Attr, PTHREAD_MUTEX_RECURSIVE);
pthread_mutex_init(&Mutex, &Attr);
*/

/*Mutexes are by default non-recursive, you need to set the attributes
to recursive*/

/*! Mutex Lock initalizer */
#define LOCK_INITIALIZER		PTHREAD_MUTEX_INITIALIZER
/*! Macro to initialize the Mutex lock */
#define LOCK_INIT(lock, flag)		pthread_mutex_init(&lock, flag)
/*! Macro to initalize the Mutex lock attributes */
#define LOCK_ATTR_INIT(attr)		pthread_mutexattr_init(attr)
/*! Macro to set the Mutex attribute to recursive */
#define LOCK_ATTR_SET_RECURSIVE(attr)	\
	pthread_mutexattr_settype(attr, PTHREAD_MUTEX_RECURSIVE)

#define LOCK_ATTR_SET_ADAPTIVE(attr) \
	pthread_mutexattr_settype(attr, PTHREAD_MUTEX_ADAPTIVE_NP)

/*! Macro to destroy the Mutex lock */
#define LOCK_DESTROY(lock)		pthread_mutex_destroy(&lock)
/*! Macro to acquire the Mutex lock */
#define LOCK(lock)			pthread_mutex_lock(&lock)
/*! Macro to acquire the Mutex lock */
#define LOCK_TAKE			LOCK
/*! Macro to release the Mutex lock */
#define UNLOCK(lock)			pthread_mutex_unlock(&lock)

/*Read write locks are by default non-re-entrant,
we need to have some special routine to implement the re-entrant rwlocks*/
/*! Macro to initialize the Read-Write lock */
#define RWLOCK_INIT(lock)		odp_rwlock_init(lock)
/*! Macro to acquire the Read lock */
#define RWLOCK_RLOCK(lock)		odp_rwlock_read_lock(&lock)
/*! Macro to release the Read lock */
#define RWLOCK_RUNLOCK(lock)		odp_rwlock_read_unlock(&lock)
/*! Macro to acquire the Write lock */
#define RWLOCK_WLOCK(lock)		odp_rwlock_write_lock(&lock)
/*! Macro to release the Write lock */
#define RWLOCK_WUNLOCK(lock)		odp_rwlock_write_unlock(&lock)


/*! Macro to initialize a barrier */
#define BARRIER_INIT(barrier, attr, count)	\
					odp_barrier_init(barrier, count)
/*! Macro to wait on a barrier */
#define BARRIER_WAIT(barrier)		odp_barrier_wait(barrier)

/*! @} */
#endif
