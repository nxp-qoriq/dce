/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#include <stdint.h>
#include "qbman_portal.h"
#include "fsl_dpaa2_fd.h"

void loadTestFD(struct dpaa2_fd *frame)
{
	frame->simple.addr_lo = 0xbaba0000;
	frame->simple.addr_hi = 0x00000123;
	frame->simple.len = 0x1337;
	frame->simple.frc = 0xdeadbeef;
	frame->simple.flc_lo = 0x5a5a5a5a;
	frame->simple.flc_hi = 0x6b6b6b6b;
}
