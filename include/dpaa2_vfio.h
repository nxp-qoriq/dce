/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2014 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#ifndef _DPAA2_VFIO_H_
#define _DPAA2_VFIO_H_

/*!
 * @file	dpaa2_vfio.h
 *
 * @brief	DPAA2 VFIO related definitions.
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/mman.h>
#include <linux/vfio.h>

#define VFIO_PATH_MAX		100
#define VFIO_MAX_GRP		1
#define VFIO_MAX_CONTAINERS	1

struct vfio_device {
	int fd; /* fsl_mc root container device ?? */
	int index; /*index of child device */
	struct vfio_device *child; /* Child device */
};

struct vfio_group {
	int fd; /* /dev/vfio/"groupid" */
	int groupid;
	struct vfio_container *container;
	int object_index;
	struct vfio_device *vfio_device; /* Pointer to device array*/
};

struct vfio_container {
	int fd; /* /dev/vfio/vfio */
	int used;
	int index; /* index in group list */
	struct vfio_group *group_list[VFIO_MAX_GRP];
};

int32_t setup_vfio_grp(char  *vfio_container);
void destroy_vfio_group(struct vfio_group *group);
int64_t vfio_map_mcp_obj(struct vfio_group *group, char *mcp_obj);
int32_t vfio_dmamap_mem_region(uint64_t vaddr,
		uint64_t iova,
		uint64_t size);

#endif /* _DPAA2_VFIO_H */
