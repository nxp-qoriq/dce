/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * Standard C language types and definitions for ODP.
 */

#ifndef ODP_PLAT_STD_TYPES_H_
#define ODP_PLAT_STD_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>

/** @addtogroup odp_system ODP SYSTEM
 *  @{
 */
#if defined _GCC_STDINT_H || defined _STDINT_H
	/* TBD already defined */
#else
/*! Basic types upon which most other types are built.*/

/*! A type definition for 64bit integer */
typedef long long int64_t;
/*! A type definition for 32bit integer */
typedef int		int32_t;
/*! A type definition for 16bit integer */
typedef short int	int16_t;
/*! A type definition for 8bit integer */
typedef char		int8_t;
/*! A type definition for signed char */
typedef __signed char	char8_t;

/*! A type definition for 64bit unsigned integer*/
typedef unsigned long long	uint64_t;
/*! A type definition for 32bit unsigned integer*/
typedef unsigned int		uint32_t;
/*! A type definition for 16bit unsigned integer*/
typedef unsigned short int	uint16_t;
/*! A type definition for 8bit unsigned integer*/
typedef unsigned char		uint8_t;
/*! A type definition for unsigned char */
typedef unsigned char		uchar8_t;

/*! Standard type definitions */
typedef	double		__double_t;
typedef	double		__float_t;

#endif

/*! A type definition for unsigned pointer */
typedef uintptr_t uintptrx_t;
typedef uintptr_t dma_addr_t;
/*! A type definition for bool */
typedef unsigned char bool_t;
/*! A type definition for void */
typedef void void_t;
/*! A type definition for handle */
typedef void *handle_t;
/*!Physical address definition type. */
typedef uint64_t phys_addr_t;

/*! Represents a bad physical address */
#define DPAA2_BAD_PHYS_ADDR ((phys_addr_t)-1)

#define DPAA2_SUCCESS 0
#define DPAA2_FAILURE -1

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

typedef int odp_bool_t;

/**
 * Bit Macros to get/set Packet metadata header
 */

/** General Macro to define a particular bit position*/
#define BIT_POS(x)			((uint64_t)1 << ((x)))
/** Set a bit in the variable */
#define BIT_SET_AT_POS(var, pos)	(var |= pos)
/** Reset the bit in the variable */
#define BIT_RESET_AT_POS(var, pos)	(var &= ~(pos))
/** Check the bit is set in the variable */
#define BIT_ISSET_AT_POS(var, pos)	((var & pos) ? TRUE : FALSE)

/*! Macro to get lower 32 bits of a uint64_t variable */
#ifndef lower_32_bits
#define lower_32_bits(x) ((uint32_t)(x))
#endif
/*! Macro to get upper 32 bits of a uint64_t variable */
#ifndef upper_32_bits
#define upper_32_bits(x) (uint32_t)(((x) >> 32))
#endif

/**
 * @}
 */

#include <std_types.h>

#ifdef __cplusplus
}
#endif

#endif
