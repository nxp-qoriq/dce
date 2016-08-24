/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#include <compat.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/ioctl.h>

/* Similarly-named functions */
#define upper32(a) upper_32_bits(a)
#define lower32(a) lower_32_bits(a)

