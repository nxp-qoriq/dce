/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#ifndef __DCE_PRIVATE_H
#define __DCE_PRIVATE_H

#include "dce-sys-decl.h"
#include <fsl_qbman_portal.h>

/* Perform extra checking */
#define DCE_CHECKING
#define MAKE_MASK32(width) (width == 32 ? 0xffffffff : \
				 (u32)((1 << width) - 1))

/* For CCSR or portal-CINH registers that contain fields at arbitrary offsets
 * and widths, these macro-generated encode/decode/isolate/remove inlines can
 * be used.
 *
 * Eg. to "d"ecode a 14-bit field out of a register (into a "uint16_t" type),
 * where the field is located 3 bits "up" from the least-significant bit of the
 * register (ie. the field location within the 32-bit register corresponds to a
 * mask of 0x0001fff8), you would do;
 *                uint16_t field = d32_uint16_t(3, 14, reg_value);
 *
 * Or to "e"ncode a 1-bit boolean value (input type is "int", zero is FALSE,
 * non-zero is TRUE, so must convert all non-zero inputs to 1, hence the "!!"
 * operator) into a register at bit location 0x00080000 (19 bits "in" from the
 * LS bit), do;
 *                reg_value |= e32_int(19, 1, !!field);
 *
 * If you wish to read-modify-write a register, such that you leave the 14-bit
 * field as-is but have all other fields set to zero, then "i"solate the 14-bit
 * value using;
 *                reg_value = i32_uint16_t(3, 14, reg_value);
 *
 * Alternatively, you could "r"emove the 1-bit boolean field (setting it to
 * zero) but leaving all other fields as-is;
 *                reg_val = r32_int(19, 1, reg_value);
 *
 */

#define DECLARE_CODEC32(t) \
static inline u32 e32_##t(u32 lsoffset, u32 width, t val) \
{ \
	BUG_ON(width > (sizeof(t) * 8)); \
	return ((u32)val & MAKE_MASK32(width)) << lsoffset; \
} \
static inline t d32_##t(u32 lsoffset, u32 width, u32 val) \
{ \
	BUG_ON(width > (sizeof(t) * 8)); \
	return (t)((val >> lsoffset) & MAKE_MASK32(width)); \
} \
static inline u32 i32_##t(u32 lsoffset, u32 width, \
				u32 val) \
{ \
	BUG_ON(width > (sizeof(t) * 8)); \
	return e32_##t(lsoffset, width, d32_##t(lsoffset, width, val)); \
} \
static inline u32 r32_##t(u32 lsoffset, u32 width, \
				u32 val) \
{ \
	BUG_ON(width > (sizeof(t) * 8)); \
	return ~(MAKE_MASK32(width) << lsoffset) & val; \
}
DECLARE_CODEC32(uint32_t)
DECLARE_CODEC32(u32)
DECLARE_CODEC32(uint16_t)
DECLARE_CODEC32(uint8_t)
DECLARE_CODEC32(int)

	/*********************/
	/* Debugging assists */
	/*********************/

static inline void __hexdump(unsigned long start, unsigned long end,
			unsigned long p, size_t sz, const unsigned char *c)
{
	while (start < end) {
		unsigned int pos = 0;
		char buf[64];
		int nl = 0;

		pos += sprintf(buf + pos, "%08lx: ", start);
		do {
			if ((start < p) || (start >= (p + sz)))
				pos += sprintf(buf + pos, "..");
			else
				pos += sprintf(buf + pos, "%02x", *(c++));
			if (!(++start & 15)) {
				buf[pos++] = '\n';
				nl = 1;
			} else {
				nl = 0;
				if (!(start & 1))
					buf[pos++] = ' ';
				if (!(start & 3))
					buf[pos++] = ' ';
			}
		} while (start & 15);
		if (!nl)
			buf[pos++] = '\n';
		buf[pos] = '\0';
		pr_info("%s", buf);
	}
}
static inline void hexdump(const void *ptr, size_t sz)
{
	unsigned long p = (unsigned long)ptr;
	unsigned long start = p & ~15;
	unsigned long end = (p + sz + 15) & ~15;
	const unsigned char *c = ptr;

	__hexdump(start, end, p, sz, c);
}

#endif /* DCE_PRIVATE_H */
