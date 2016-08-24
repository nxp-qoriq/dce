/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2014 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#ifndef _FSL_MC_SYS_H
#define _FSL_MC_SYS_H

#include <stdint.h>

struct mc_command;


#define cpu_to_le64(x) __cpu_to_le64(x)
#define __iormb()       dmb()
#define __iowmb()       dmb()
#define __arch_getq(a)                  (*(volatile unsigned long *)(a))
#define __arch_putq(v, a)                (*(volatile unsigned long *)(a) = (v))
#define __arch_putq32(v, a)                (*(volatile unsigned int *)(a) = (v))
#define readq(c)        ({ uint64_t __v = __arch_getq(c); __iormb(); __v; })
#define writeq(v, c)     ({ uint64_t __v = v; __iowmb(); __arch_putq(__v, c); __v; })
#define writeq32(v, c) ({ uint32_t __v = v; __iowmb(); __arch_putq32(__v, c); __v; })
#define ioread64(_p)        readq(_p)
#define iowrite64(_v, _p)   writeq(_v, _p)
#define iowrite32(_v, _p)   writeq32(_v, _p)
#define __iomem

/**
 * struct fsl_mc_io - MC I/O object
 */
struct fsl_mc_io {
	int fd;
};

int mc_io_init(struct fsl_mc_io *mc_io);

void mc_io_cleanup(struct fsl_mc_io *mc_io);

int mc_send_command(struct fsl_mc_io *mc_io, struct mc_command *cmd);

#endif /* _FSL_MC_SYS_H */
