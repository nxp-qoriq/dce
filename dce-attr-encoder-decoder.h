/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#ifndef __DCE_ATTR_ENCODER_DECODER_H
#define __DCE_ATTR_ENCODER_DECODER_H

#include "dce-private.h"

/* ------------- */
/* dce_attr_code */
/* ------------- */

/* This struct locates a sub-field within a DCE attribute which
 * is either serving as a configuration command or a query result. The
 * representation is inherently little-endian, as the indexing of the words is
 * itself little-endian in nature and layerscape is little endian for anything
 * that crosses a word boundary too (64-bit fields are the obvious examples).
 */
struct dce_attr_code {
	unsigned int word; /* which u32[] array member encodes the field */
	unsigned int lsoffset; /* encoding offset from ls-bit */
	unsigned int width; /* encoding width. (bool must be 1.) */
};

/* Macros to define codes */
#define DCE_CODE(a, b, c) { a, b, c}
#define DCE_CODE_NULL \
	DCE_CODE((unsigned int)-1, (unsigned int)-1, (unsigned int)-1)

/* decode a field from a cacheline */
static inline u32 dce_attr_code_decode(const struct dce_attr_code *code,
				      const u32 *cacheline)
{
	return d32_u32(code->lsoffset, code->width, cacheline[code->word]);
}
static inline uint64_t dce_attr_code_decode_64(const struct dce_attr_code *code,
				      const uint64_t *cacheline)
{
	return cacheline[code->word / 2];
}

/* encode a field to a cacheline */
static inline void dce_attr_code_encode(const struct dce_attr_code *code,
				       u32 *cacheline, u32 val)
{
	cacheline[code->word] =
		r32_u32(code->lsoffset, code->width, cacheline[code->word])
		| e32_u32(code->lsoffset, code->width, val);
}
static inline void dce_attr_code_encode_64(const struct dce_attr_code *code,
				       uint64_t *cacheline, uint64_t val)
{
	cacheline[code->word / 2] = val;
}

/* Small-width signed values (two's-complement) will decode into medium-width
 * positives. (Eg. for an 8-bit signed field, which stores values from -128 to
 * +127, a setting of -7 would appear to decode to the 32-bit unsigned value
 * 249. Likewise -120 would decode as 136.) This function allows the caller to
 * "re-sign" such fields to 32-bit signed. (Eg. -7, which was 249 with an 8-bit
 * encoding, will become 0xfffffff9 if you cast the return value to u32).
 */
static inline int32_t dce_attr_code_makesigned(const struct dce_attr_code *code,
					  u32 val)
{
	BUG_ON(val >= (1u << code->width));
	/* If the high bit was set, it was encoding a negative */
	if (val >= (1u << (code->width - 1)))
		return (int32_t)0 - (int32_t)(((u32)1 << code->width) -
			val);
	/* Otherwise, it was encoding a positive */
	return (int32_t)val;
}

/* ---------------------- */
/* Descriptors/cachelines */
/* ---------------------- */

/* To avoid needless dynamic allocation, the driver API often gives the caller
 * a "descriptor" type that the caller can instantiate however they like.
 * Ultimately though, it is just a cacheline of binary storage (or something
 * smaller when it is known that the descriptor doesn't need all 64 bytes) for
 * holding pre-formatted pieces of hardware commands. The performance-critical
 * code can then copy these descriptors directly into hardware command
 * registers more efficiently than trying to construct/format commands
 * on-the-fly. The API user sees the descriptor as an array of 32-bit words in
 * order for the compiler to know its size, but the internal details are not
 * exposed. The following macro is used within the driver for converting *any*
 * descriptor pointer to a usable array pointer. The use of a macro (instead of
 * an inline) is necessary to work with different descriptor types and to work
 * correctly with const and non-const inputs (and similarly-qualified outputs).
 */
#define dce_cl(d) (&(d)->words[0])
#define dce_cl2(d) (&(d)->words[16])

#endif
