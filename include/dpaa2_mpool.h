/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2014 Freescale Semiconductor, Inc.
 * All rights reserved.
 */

/*!
 * @file	dpaa2_mpool.h
 *
 * @brief	Memory pools for data allocations management
 *
 * @addtogroup DPAA2_MEMPOOL
 * @ingroup DPAA2_RTS
 * @{
 */

#ifndef DPAA2_MPOOL_H
#define DPAA2_MPOOL_H
#ifdef __cplusplus
extern "C" {
#endif

#include <std_types.h>
#include <hints.h>


/*! Max limit on the length of the memory pool's name */
#define DPAA2_MAX_POOL_NAME_LEN 32

/*! Invalid memory pool ID */
#define DPAA2_POOL_INVALID (0xffffffff)


/*! Don't memset the pool block to 0 during block release. */
#define DPAA2_MPOOL_NO_MEMSET	BIT_POS(1)

/*! Don't memset the private part of pool block to 0 during block release. */
#define DPAA2_MPOOL_NO_PRIVATE_MEMSET	BIT_POS(2)

/*! Share the memory pool between the threads  */
#define DPAA2_MPOOL_SHARED	BIT_POS(3)

/*! Heap is not defined for this mpool. */
#define DPAA2_MPOOL_NO_HEAP	BIT_POS(4)

/*! mpool to be page aligned - only valid for memzone*/
#define DPAA2_MPOOL_PAGE_ALIGN	BIT_POS(5)

/*! NEED PREPARE flag - If the application has created the pool with prepare flag,
 * it can call the pool to prepare - It  will call the callback given by the
 * application for all the block nodes. The application will set the desired
 * initialization once for all the nodes.  It is recommended that the application
 * has these initialization specific parameters in private area - so that it does not
 * get memset during release block.
 * It is mandatory to pass DPAA2_MPOOL_NO_PRIVATE_MEMSET flag with this flag.
 */
#define DPAA2_MPOOL_NEED_PREPARE	BIT_POS(5)

/*!
 * An object constructor callback function for mempool.
 *
 * Arguments are the mempool, the opaque pointer given by the user in
 * dpaa2_mpool_create(), the pointer to the element and the index of
 * the element in the pool.
 */
typedef void (dpaa2_mpool_obj_ctor_t)(void *pool, void *obj_init_arg,
				void *addr, unsigned idx);


/*!	Global Data strucuture for memory pool statistics,
 *	Applications can use this structure to know the statistics
 *	min_threshold, max_threshold and release_cnt values are used
 *	only incase of Linux Kernel memory management
 */
struct dpaa2_mpool_stats {
	uint32_t free_cnt; /*!< free memblocks available */
	uint32_t alloc_cnt; /*!< allocated memblocks */
	uint32_t release_cnt; /*!< released memblocks */
	uint32_t alloc_fail_cnt; /*!< allocate fail memblocks */
	uint32_t release_fail_cnt;/*!< release fail memblocks */
	uint32_t heap_allockblocks; /*!< blocks allocated from heap */
	uint32_t heap_release_cnt; /*!< blocks released to heap */
	uint32_t heap_allocfail_cnt; /*!< heap alloc fail count */
	uint32_t blocks_cnt; /*!< total no.of blocks */
	uint32_t block_size; /*!< each block size */
	uint32_t min_threshold; /*!<threshold at which kernel thread wakes up*/
	uint32_t max_threshold; /*!<ensures that max no.of nodes available */
	uint32_t replenish_cnt; /*!<nodes to be replenished for each request */
	uint32_t static_alloc_cnt; /*!<total nodes allocated in static pool,
				will always be less or equal to blocks_cnt  */
};

/*!	Global Config strucuture for memory pool configuration,
 *	Applications can use this structure to know the config
 *	of the memory pools
 */
struct dpaa2_mpool_cfg {
	const char *name;	/*!< Name of memory pool. */
	uint32_t block_size;	/*!< Size of each block. */
	uint32_t  num_global_blocks;	/*!< Total number of global blocks  which all threads will use.
	In case thread support is off these are the total number of
	blocks which are allocated in the pool. */
	uint32_t num_max_blocks;
		/*!< Maximum number of blocks that can be allocated in this memory
		pool including from heap at a particular instance. */
	uint8_t flags;	/*!< flags for memset memory etc. */
	uint8_t num_threads;	/*!< Total number of threads. > 1 indicates thread support. */
	uint16_t replenish_cnt;	/*!<nodes to be replenished for each request */
	uint32_t min_threshold;	/*!<threshold at which blocks are replenished
					* from global pool*/
	uint32_t max_threshold; /*!<threshold at which blocks are replenished
					* to global pool */
	uint32_t num_per_thread_blocks;	/*!< Number of blocks in each thread. If thread support is off
						* this paramerer is not used. */
	uint32_t alignment;	/*!< memory block to be aligned at the specified value.
					* Zero value indicate no alignment*/
	unsigned priv_data_size;	/*!< private data */
};

/*!
 * @details	This API is used to return the size of given memory pool.
 *
 * @param[in]	mpool - pointer to memory pool
 *
 * @returns	Size of the given memory pool.
 *
 */
uint64_t dpaa2_mpool_size(void *mpool);


/*!
 * @details	Create the memory pool with the params given
 *
 * @param[in]	cfg - Memory pool configuration
 *
 * @param[in]	obj_init - A function pointer that is called for each object at
 *   initialization of the pool. The user can set some meta data in
 *   objects if needed. This parameter can be NULL if not needed.
 *   The obj_init() function takes the mpool pointer, the init_arg,
 *   the object pointer and the object number as parameters.
 *
 * @param[in]	obj_init_arg - An opaque pointer to data that can be used as an argument for
 *   each call to the object constructor function.
 *
 * @param[out]	obj_init_arg -pointer to handle of the pool created
 *
 * @returns	SUCCESS/FAILURE
 *
 */
void_t *dpaa2_mpool_create(struct dpaa2_mpool_cfg *cfg,
	dpaa2_mpool_obj_ctor_t *obj_init, void *obj_init_arg);

/*!
 * @details	This API is used to delete a memory pool and
 *		release the memory associated with it to the global memory pool.
 *
 * @param[in]	mpool - pointer to memory pool
 *
 * @returns	DPAA2_SUCCESS on SUCCESS; DPAA2_FAILURE on FAILURE.
 *
 */
int32_t dpaa2_mpool_delete(void_t *mpool);


/*!
 * @details This API is used to get a memory block from a memory pool. Applications
 *   should not call this API once the mpool is set for delete.
 *
 * @param[in]	mpool - pointer to memory pool
 *
 * @param[in,out]	heap - flag that indicates whether allocation from heap
 *			is wanted or not (true - wanted, false - unwanted) once
 *			mem pool is exhausted (in direction)
 *			flag that indicates whether allocation was done from heap as
 *			the mem pool is exhausted (out direction)
 *
 * @returns	address of the allocated mem block or NULL on failure
 *
 */
void_t *dpaa2_mpool_getblock(
	void_t *mpool,
	uint8_t *heap);


/*!
 * @details This API is used to release a memory block to a memory pool.
 *
 * @param[in]	mpool - pointer to memory pool
 *
 * @param[in]	p_block - address of the mem block to be released
 *
 * @returns	DPAA2_SUCCESS on SUCCESS; DPAA2_FAILURE on FAILURE.
 *
 */
int32_t dpaa2_mpool_relblock(
	void_t *mpool,
	void_t *p_block);


/*!
 * @details This API is used to get stats of a memory pool.
 *
 * @param[in]	mpool - pointer to memory pool
 *
 * @param[in,out]	pstats - pointer to structure to hold memory pool statistics (in direction)
 *			structure filled with statistics (out direction)
 *
 * @returns	DPAA2_SUCCESS on SUCCESS; DPAA2_FAILURE on FAILURE.
 *
 */
int32_t dpaa2_mpool_getstats(
	void_t *mpool,
	struct dpaa2_mpool_stats *pstats);


/*!
 * @details This API is used to get config of a memory pool.
 *
 * @param[in]	mpool - pointer to memory pool
 *
 * @returns	Pointer to structure dpaa2_mpool_cfg; NULL on FAILURE.
 *
 */
struct dpaa2_mpool_cfg *dpaa2_mpool_getcfg(void_t *mpool);


/*!
 * @details This API is used to set the threshold values of memory blocks
 *   in a memory pool.
 *
 * @param[in]	mpool - pointer to memory pool
 *
 * @param[in]	min_threshold - minimum number of blocks to be available in pool.
 *
 * @param[in]	max_threshold - maximum number of blocks to be available in pool
 *
 * @param[in]	replenish_cnt - number of blocks to replenish if the free list
 *		becomes empty
 *
 * @returns	DPAA2_SUCCESS on SUCCESS; DPAA2_FAILURE on FAILURE.
 *
 */
int32_t dpaa2_mpool_set_threshold_vals(void_t *mpool,
			uint32_t min_threshold,
			uint32_t max_threshold,
			uint32_t replenish_cnt);


/*!
 * @details Search a mpool from its name.
 *
 * @param[in]	name - The name of the mpool.
 *
 * @returns	The pointer to the mpool matching the name, or NULL if not found.
 *
 */
void_t *dpaa2_mpool_lookup(const char *name);


/*!
 * @details Return a pointer to the mpool owning this memory block.
 *
 * @param[in]	p_block - A memory block that is owned by a pool. If this is not the case,
 *				the behavior is undefined.
 *
 * @returns	A pointer to the mpool
 *
 */
void_t *dpaa2_mpool_from_blk(uint8_t *p_block);

/*!
 * @details Return the number of entries in the mpool.
 *
 * @param[in]	mpool - A pointer to the mpool structure.
 *
 * @returns	The number of entries in the mpool.
 *
 */
int dpaa2_mpool_count(const void_t *mpool);

/*!
 * @details Return the number of free entries in the mpool.
 *
 * @param[in]	mpool - A pointer to the mpool structure.
 *
 * @returns	The number of free entries in the mpool.
 *
 */
int dpaa2_mpool_free_count(const void_t *mpool);


/*!
 * @details Test if the mpool is full.
 *
 * @param[in]	mpool - A pointer to the mpool structure.
 *
 * @returns	1 if the mpool is full else return 0.
 *
 */
int dpaa2_mpool_is_full(const void_t *mpool);

/*!
 * @details Test if the mpool is empty.
 *
 * @param[in]	mpool - A pointer to the mpool structure.
 *
 * @returns	1 if the mpool is empty else return 0.
 *
 */
int dpaa2_mpool_is_empty(const void_t *mpool);

/*!
 * @details Return the physical address of block, which is an element of the pool mpool.
 *
 * @param[in]	p_virt - A pointer (virtual address) to the element of the pool.
 *
 * @returns	The physical address of the p_virt element.
 *
 */
phys_addr_t dpaa2_mem_virt2phy(const void *p_virt);

/*!
 * @details	Find physical address of a particular block in the pool
 *
 * @param[in]	mpool - ptr to the mpool structure
 *
 * @param[in]	blk - ptr to the block in the mpool
 *
 * @returns	Physical address of a particular block in the pool
 *
 */
phys_addr_t dpaa2_get_mpool_blk_phyaddr(
	const void_t *mpool,
	const void *blk);

/*!
 * @details	Find virtual address of a particular block in the pool
 *
 * @param[in]	mpool - ptr to the mpool structure
 *
 * @param[in]	blk - ptr to the physical addrss of the block in the mpool
 *
 * @returns	Virtual address of a particular block in the pool
 *
 */
void *dpaa2_get_mpool_blk_virtaddr(
	const void_t *mpool,
	const phys_addr_t blk);

/*!
 * @details	Find physical address of the pool start block
 *
 * @param[in]	mpool - ptr to the mpool structure
 *
 * @returns	physical address of pool start block
 *
 */
phys_addr_t dpaa2_get_mpool_phyaddr(const void_t *mpool);

/*!
 * @details	Get virtual address of the pool start block
 *
 * @param[in]	mpool - ptr to the mpool structure
 *
 * @returns	virtual address of pool start block
 *
 */
void *dpaa2_get_mpool_virtaddr(const void_t *mpool);

/*!
 * @details Dump the status of the mpool to the console.
 *
 * @param[in]	mpool - A pointer to the mpool structure.
 *
 * @returns	none
 *
 */
void dpaa2_mpool_dump(const void_t *mpool);

/*!
 * @details Dump the status of all mpools to the file or console.
 *		If the user passes file handle then list is printed
 *		in the specified file else it is printed on stdout.
 *
 * @param[in]	stream - stream can be file pointer, stderr or stdout device.
 *
 * @returns	none
 *
 */
void dpaa2_mpool_list_dump(void *stream);


#ifdef __cplusplus
}
#endif

/*! @} */
#endif /* DPAA2_MPOOL_H */
