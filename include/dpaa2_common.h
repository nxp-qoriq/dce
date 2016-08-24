/*
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
 *
 * Derived from DPDK 1.6.1 rte_common.h
 */

/*!
 * @file		dpaa2_common.h
 *
 * @brief		Generic, commonly-used macro and inline function definitions
 *
 * @addtogroup	DPAA2_COMMON
 * @ingroup	DPAA2
 * @{
 */

#ifndef _DPAA2_COMMON_H_
#define _DPAA2_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <sched.h>

#ifndef typeof
#define typeof __typeof__
#endif

#ifndef asm
#define asm __asm__
#endif

#include <dpaa2_cfg.h>
#include <std_types.h>
#include <dpaa2_log.h>

#include <dpaa2_string_fns.h>
#include <dpaa2_debug.h>
#include <dpaa2_hexdump.h>
#include <dpaa2_random.h>


#ifdef __GNUC__
#if (defined __x86_64__) || (defined __ppc64__) || (defined  __aarch64__) || (defined __powerpc64__)
# define CONFIG_64BIT
#else
# define CONFIG_32BIT
#endif
#else
#if ((ULONG_MAX) == (UINT_MAX))
# define CONFIG_32BIT
#else
# define CONFIG_64BIT
#endif
#endif


/*! Round up variable x to a align (align should be power of 2) */
#define DPAA2_ALIGN_ROUNDUP(x, align)\
	((align) * (((x) + align - 1) / (align)))

/*! Round up pointer x to a align (align should be power of 2) */
#define DPAA2_ALIGN_ROUNDUP_PTR(x, align)\
	((void *)DPAA2_ALIGN_ROUNDUP((uintptr_t)(x), (uintptr_t)(align)))

/*! Round up a variable to the ODP_CACHE_LINE_SIZE */
#define CACHE_LINE_SIZE_ROUNDUP(x)\
	DPAA2_ALIGN_ROUNDUP(x, ODP_CACHE_LINE_SIZE)

/*! Round up a pointer to the ODP_CACHE_LINE_SIZE */
#define CACHE_LINE_SIZE_ROUNDUP_PTR(x)\
	((void *)CACHE_LINE_SIZE_ROUNDUP((uintptr_t)(x)))

/*! Round up the DPAA2_PAGE_SIZE */
#define DPAA2_PAGE_SIZE_ROUNDUP(x)\
	DPAA2_ALIGN_ROUNDUP(x, ODP_PAGE_SIZE)


/*! Round down variable x to a align (align should be power of 2) */
#define DPAA2_ALIGN_ROUNDDOWN_POWER_2(x, align)\
	((x) & (~((align) - 1)))

/*! Round down pointer x to a align (align should be power of 2) */
#define DPAA2_ALIGN_ROUNDDOWN_PTR_POWER_2(x, align)\
((void *)DPAA2_ALIGN_ROUNDDOWN_POWER_2((uintptr_t)(x), (uintptr_t)(align)))

/*! Round down a variable to the ODP_CACHE_LINE_SIZE */
#define CACHE_LINE_SIZE_ROUNDDOWN(x)\
	DPAA2_ALIGN_ROUNDDOWN_POWER_2(x, ODP_CACHE_LINE_SIZE)

/*! Round down a pointer to the ODP_CACHE_LINE_SIZE */
#define CACHE_LINE_SIZE_ROUNDDOWN_PTR(x)\
	((void *)CACHE_LINE_SIZE_ROUNDDOWN((uintptr_t)(x)))


/*! Indicates an incorrect physical address */
#define DPAA2_BAD_PHYS_ADDR ((phys_addr_t)-1)

/*!
 * Definition to mark a variable or function parameter as used so
 * as to avoid a compiler warning
 */
#define DPAA2_SET_USED(x) (void)(x)

/*********** Macros for pointer arithmetic ********/

/*!
 * add a byte-value offset from a pointer
 */
#define DPAA2_PTR_ADD(ptr, x) ((void *)((uintptr_t)(ptr) + (x)))

/*!
 * subtract a byte-value offset from a pointer
 */
#define DPAA2_PTR_SUB(ptr, x) ((void *)((uintptr_t)ptr - (x)))

/*!
 * get the difference between two pointer values, i.e. how far apart
 * in bytes are the locations they point two. It is assumed that
 * ptr1 is greater than ptr2.
 */
#define DPAA2_PTR_DIFF(ptr1, ptr2) ((uintptr_t)(ptr1) - (uintptr_t)(ptr2))

/*********** Macros/static functions for doing alignment ********/

/*!
 * @details	Function which rounds an unsigned int down to a given
 *		power-of-two value. Takes uintptr_t types as parameters,
 *		as this type of operation is most commonly done for pointer
 *		alignment. (See also DPAA2_ALIGN_FLOOR, DPAA2_ALIGN_CEIL,
 *		DPAA2_ALIGN, DPAA2_PTR_ALIGN_FLOOR, DPAA2_PTR_ALIGN_CEL,
 *		DPAA2_PTR_ALIGN macros)
 *
 * @param[in]	ptr - The value to be rounded down
 *
 * @param[in]	align - The power-of-two of which the result must be multiple.
 *
 * @returns	Function returns a properly aligned value where align is a
 *		power-of-two. If align is not a power-of-two, result will
 *		be incorrect.
 */
static inline uintptr_t
dpaa2_align_floor_int(uintptr_t ptr, uintptr_t align)
{
	return (ptr & ~(align - 1));
}

/*!
 * Macro to align a pointer to a given power-of-two. The resultant
 * pointer will be a pointer of the same type as the first parameter, and
 * point to an address no higher than the first parameter. Second parameter
 * must be a power-of-two value.
 */
#define DPAA2_PTR_ALIGN_FLOOR(ptr, align) \
	(typeof(ptr))dpaa2_align_floor_int((uintptr_t)ptr, align)

/*!
 * Macro to align a value to a given power-of-two. The resultant value
 * will be of the same type as the first parameter, and will be no
 * bigger than the first parameter. Second parameter must be a
 * power-of-two value.
 */
#define DPAA2_ALIGN_FLOOR(val, align) \
	(typeof(val))((val) & (~((typeof(val))((align) - 1))))

/*!
 * Macro to align a pointer to a given power-of-two. The resultant
 * pointer will be a pointer of the same type as the first parameter, and
 * point to an address no lower than the first parameter. Second parameter
 * must be a power-of-two value.
 */
#define DPAA2_PTR_ALIGN_CEIL(ptr, align) \
	DPAA2_PTR_ALIGN_FLOOR((typeof(ptr))DPAA2_PTR_ADD(ptr, (align) - 1), align)

/*!
 * Macro to align a value to a given power-of-two. The resultant value
 * will be of the same type as the first parameter, and will be no lower
 * than the first parameter. Second parameter must be a power-of-two
 * value.
 */
#define DPAA2_ALIGN_CEIL(val, align) \
	DPAA2_ALIGN_FLOOR(((val) + ((typeof(val)) (align) - 1)), align)

/*!
 * Macro to align a pointer to a given power-of-two. The resultant
 * pointer will be a pointer of the same type as the first parameter, and
 * point to an address no lower than the first parameter. Second parameter
 * must be a power-of-two value.
 * This function is the same as DPAA2_PTR_ALIGN_CEIL
 */
#define DPAA2_PTR_ALIGN(ptr, align) DPAA2_PTR_ALIGN_CEIL(ptr, align)

/*!
 * Macro to align a value to a given power-of-two. The resultant
 * value will be of the same type as the first parameter, and
 * will be no lower than the first parameter. Second parameter
 * must be a power-of-two value.
 * This function is the same as DPAA2_ALIGN_CEIL
 */
#define DPAA2_ALIGN(val, align) DPAA2_ALIGN_CEIL(val, align)

/*!
 * @details	Checks if a pointer is aligned to a given power-of-two value
 *
 * @param[in]	ptr -The pointer whose alignment is to be checked
 *
 * @param[in]	align -The power-of-two value to which the ptr should
 *		be aligned
 *
 * @returns	True(1) where the pointer is correctly aligned,
 *		false(0) otherwise
 */
static inline int
dpaa2_is_aligned(void *ptr, unsigned align)
{
	return DPAA2_PTR_ALIGN(ptr, align) == ptr;
}


/*********** Macros to work with powers of 2 ********/

/*!
 * @details	Returns true if n is a power of 2
 *
 * @param[in]	n - Number to check
 *
 * @returns	1 if true, 0 otherwise
 */
static inline int
dpaa2_is_power_of_2(uint32_t n)
{
	return ((n-1) & n) == 0;
}

/*!
 * @details	Aligns input parameter to the next power of 2
 *
 * @param[in]	x - The integer value to algin
 *
 * @returns	Input parameter aligned to the next power of 2
 */
static inline uint32_t
dpaa2_align32pow2(uint32_t x)
{
	x--;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;

	return x + 1;
}

/*!
 * @details	Aligns 64b input parameter to the next power of 2
 *
 * @param[in]	x - The 64b value to algin
 *
 * @returns	Input parameter aligned to the next power of 2
 */
static inline uint64_t
dpaa2_align64pow2(uint64_t v)
{
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v |= v >> 32;

	return v + 1;
}

/*********** Macros for calculating min and max **********/

/*!
 * Macro to return the minimum of two numbers
 */
#define DPAA2_MIN(a, b) ({ \
		typeof (a) _a = (a); \
		typeof (b) _b = (b); \
		_a < _b ? _a : _b; \
	})

/*!
 * Macro to return the maximum of two numbers
 */
#define DPAA2_MAX(a, b) ({ \
		typeof (a) _a = (a); \
		typeof (b) _b = (b); \
		_a > _b ? _a : _b; \
	})

/*********** Other general functions / macros ********/

/*! Take a macro value and get a string version of it */
#define _DPAA2_STR(x) #x
/*! Take a macro value and get a string version of it */
#define DPAA2_STR(x) _DPAA2_STR(x)

/*! Mask value of type <tp> for the first <ln> bit set. */
#define	DPAA2_LEN2MASK(ln, tp)	\
	((tp)((uint64_t)-1 >> (sizeof(uint64_t) * CHAR_BIT - (ln))))

/*! Number of elements in the array. */
#define	DPAA2_DIM(a)	(sizeof (a) / sizeof ((a)[0]))

/*!
 * @details	Converts a numeric string to the equivalent uint64_t value.
 *		As well as straight number conversion, also recognises the
 *		suffixes k, m and g for kilobytes, megabytes and gigabytes
 *		respectively.
 *
 *		If a negative number is passed in  i.e. a string with the
 *		first non-blank character being "-", zero is returned.
 *		Zero is also returned in the case of an error with 'errno' set.
 *
 * @param[in]	str - String containing number to convert.
 *
 * @returns	Corresponding uint64_t value.
 */
static inline uint64_t
dpaa2_str_to_size(const char *str)
{
	char *endptr;
	unsigned long long size;

	while (isspace((int)*str))
		str++;
	if (*str == '-')
		return 0;

	errno = 0;
	size = strtoull(str, &endptr, 0);
	if (errno)
		return 0;

	if (*endptr == ' ')
		endptr++; /* allow 1 space gap */

	switch (*endptr) {
	case 'G':
	case 'g':
		size *= 1024; /* fall-through */
	case 'M':
	case 'm':
		size *= 1024; /* fall-through */
	case 'K':
	case 'k':
		size *= 1024; /* fall-through */
	default:
		break;
	}
	return size;
}

/*!
 * @details	Function to terminate the application immediately,
 *		printing an error message and returning the exit_code
 *		back to the shell.
 *		This function never returns.
 *
 * @param[in]	exit_code - The exit code to be returned by the application
 *
 * @param[in]	format - The format string to be used for printing the message.
 *		This can include printf format characters which will be
 *		expanded using any further parameters to the function.
 */
void
dpaa2_exit(int exit_code, const char *format, ...)
	__attribute__((noreturn))
	__attribute__((format(printf, 2, 3)));

#ifdef __cplusplus
}
#endif

/*! @} */
#endif /* _DPAA2_COMMON_H_ */
