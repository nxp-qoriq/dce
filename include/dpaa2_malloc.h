/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *   Copyright 2014 Freescale Semiconductor, Inc.
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
 */

/*!
 * @file	dpaa2_malloc.h
 *
 * @brief	This library provides methods for dynamically allocating
 *		memory from dpaa2 heap allocater
 *
 * @addtogroup DPAA2_MALLOC
 * @ingroup DPAA2_RTS
 * @{
 */
#ifndef DPAA2_MALLOC_H
#define DPAA2_MALLOC_H

#include <stddef.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif


#ifndef dpaa2_malloc
/*! Mapped to Kernel malloc */
#define	dpaa2_malloc(type, sz)	malloc((sz))
#endif

#ifndef dpaa2_calloc
/*! Mapped to Kernel calloc */
#define	dpaa2_calloc(type, cnt, sz, align)	calloc((cnt), (sz))
#endif

#ifndef dpaa2_realloc
/*! Mapped to Kernel realloc */
#define	dpaa2_realloc(old, sz)	realloc((old), (sz))
#endif

#ifndef dpaa2_zalloc
/*! Mapped to Kernel calloc for '1' memory count*/
#define	dpaa2_zalloc(type, sz, align)	calloc(1, (sz))
#endif

#ifndef dpaa2_free
/*! Mapped to Kernel free */
#define	dpaa2_free(p)		free(p)
#endif


/*!
 * Structure to hold heap statistics obtained from
 * dpaa2_malloc_get_stats function.
 */
struct dpaa2_data_malloc_stats {
	size_t heap_totalsz_bytes; /*!< Total bytes on heap */
	size_t heap_freesz_bytes;  /*!< Total free bytes on heap */
	size_t greatest_free_size; /*!< Size in bytes of largest free block */
	unsigned free_count;       /*!< Number of free elements on heap */
	unsigned alloc_count;      /*!< Number of allocated elements on heap */
	size_t heap_allocsz_bytes; /*!< Total allocated bytes on heap */
};

/*!
 * This function allocates memory from the huge-page area of memory. The memory
 * is not cleared.
 *
 * @param type
 *   A string identifying the type of allocated objects (useful for debug
 *   purposes, such as identifying the cause of a memory leak). Can be NULL.
 * @param size
 *   Size (in bytes) to be allocated.
 * @param align
 *   If 0, the return is a pointer that is suitably aligned for any kind of
 *   variable (in the same manner as malloc()).
 *   Otherwise, the return is a pointer that is a multiple of *align*. In
 *   this case, it must be a power of two. (Minimum alignment is the
 *   cacheline size, i.e. 64-bytes)
 * @return
 *   - NULL on error. Not enough memory, or invalid arguments (size is 0,
 *     align is not a power of two).
 *   - Otherwise, the pointer to the allocated object.
 */
void *
dpaa2_data_malloc(const char *type, size_t size, unsigned align);

/*!
 * Allocate zero'ed memory from the heap.
 *
 * Equivalent to dpaa2_malloc() except that the memory zone is
 * initialised with zeros.
 *
 * @param type
 *   A string identifying the type of allocated objects (useful for debug
 *   purposes, such as identifying the cause of a memory leak). Can be NULL.
 * @param size
 *   Size (in bytes) to be allocated.
 * @param align
 *   If 0, the return is a pointer that is suitably aligned for any kind of
 *   variable (in the same manner as malloc()).
 *   Otherwise, the return is a pointer that is a multiple of *align*. In
 *   this case, it must obviously be a power of two. (Minimum alignment is the
 *   cacheline size, i.e. 64-bytes)
 * @return
 *   - NULL on error. Not enough memory, or invalid arguments (size is 0,
 *     align is not a power of two).
 *   - Otherwise, the pointer to the allocated object.
 */
void *
dpaa2_data_zmalloc(const char *type, size_t size, unsigned align);

/*!
 * Replacement function for calloc(), using huge-page memory. Memory area is
 * initialised with zeros.
 *
 * @param type
 *   A string identifying the type of allocated objects (useful for debug
 *   purposes, such as identifying the cause of a memory leak). Can be NULL.
 * @param num
 *   Number of elements to be allocated.
 * @param size
 *   Size (in bytes) of a single element.
 * @param align
 *   If 0, the return is a pointer that is suitably aligned for any kind of
 *   variable (in the same manner as malloc()).
 *   Otherwise, the return is a pointer that is a multiple of *align*. In
 *   this case, it must obviously be a power of two. (Minimum alignment is the
 *   cacheline size, i.e. 64-bytes)
 * @return
 *   - NULL on error. Not enough memory, or invalid arguments (size is 0,
 *     align is not a power of two).
 *   - Otherwise, the pointer to the allocated object.
 */
void *
dpaa2_data_calloc(const char *type, size_t num, size_t size, unsigned align);

/*!
 * Replacement function for realloc(), using huge-page memory. Reserved area
 * memory is resized, preserving contents.
 *
 * @param ptr
 *   Pointer to already allocated memory
 * @param size
 *   Size (in bytes) of new area. If this is 0, memory is freed.
 * @param align
 *   If 0, the return is a pointer that is suitably aligned for any kind of
 *   variable (in the same manner as malloc()).
 *   Otherwise, the return is a pointer that is a multiple of *align*. In
 *   this case, it must obviously be a power of two. (Minimum alignment is the
 *   cacheline size, i.e. 64-bytes)
 * @return
 *   - NULL on error. Not enough memory, or invalid arguments (size is 0,
 *     align is not a power of two).
 *   - Otherwise, the pointer to the reallocated memory.
 */
void *
dpaa2_data_realloc(void *ptr, size_t size, unsigned align);

/*!
 * Frees the memory space pointed to by the provided pointer. This pointer
 * must have been returned by a previous call to dpaa2_data_malloc(),
 * dpaa2_data_zmalloc(), dpaa2_data_calloc() or dpaa2_data_realloc().
 * The behaviour of dpaa2_data_free() is undefined if the pointer does not
 * match this requirement. If the pointer is NULL, the function does nothing.
 *
 * @param ptr
 *   The pointer to memory to be freed.
 */
void
dpaa2_data_free(void *ptr);

/*!
 * If malloc debug is enabled, check a memory block for header
 * and trailer markers to indicate that all is well with the block.
 * If size is non-null, also return the size of the block.
 *
 * @param ptr
 *   pointer to the start of a data block, must have been returned
 *   by a previous call to dpaa2_malloc(), dpaa2_zmalloc(), dpaa2_calloc()
 *   or dpaa2_realloc()
 * @param size
 *   if non-null, and memory block pointer is valid, returns the size
 *   of the memory block
 * @return
 *   -1 on error, invalid pointer passed or header and trailer markers
 *   are missing or corrupted
 *   0 on success
 */
int
dpaa2_data_malloc_validate(const void *ptr, size_t *size);

/*!
 * Get heap statistics
 *
 * @param stats
 *   A structure which provides memory to store statistics
 * @return
 *   Null on error
 *   Pointer to structure storing statistics on success
 */
int
dpaa2_data_malloc_get_stats(struct dpaa2_data_malloc_stats *stats);

/*!
 * Dump statistics.
 *
 * Dump for the specified type to the console. If the type argument is
 * NULL, all memory types will be dumped.
 *
 * @param f
 *   A pointer to a file for output
 * @param type
 *   A string identifying the type of objects to dump, or NULL
 *   to dump all objects.
 */
void
dpaa2_data_malloc_dump_stats(FILE *f, const char *type);

/*!
 * Set the maximum amount of allocated memory for this type.
 *
 * This is not yet implemented
 *
 * @param type
 *   A string identifying the type of allocated objects.
 * @param max
 *   The maximum amount of allocated bytes for this type.
 * @return
 *   - 0: Success.
 *   - (-1): Error.
 */
int
dpaa2_data_malloc_set_limit(const char *type, size_t max);

/*!
 * Return the physical address of a virtual address obtained through
 * dpaa2_malloc
 *
 * @param addr
 *   Adress obtained from a previous dpaa2_malloc call
 * @return
 *   NULL on error
 *   otherwise return physical address of the buffer
 */
phys_addr_t
dpaa2_data_malloc_virt2phy(const void *addr);

#ifdef __cplusplus
}
#endif

/*! @} */
#endif /* _DPAA2_MALLOC_H_ */
