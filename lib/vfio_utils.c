/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <stdlib.h>
#include <linux/vfio.h>
#include <sys/mman.h>

#include <pthread.h>
#include <sched.h>

#include <sys/eventfd.h>
#include <sys/epoll.h>

#include "vfio_utils.h"
#include "dpaa2_io_portal_priv.h"

#define VFIO_DMA_MAP_FLAG_MMIO (1 << 2)		/* non-cachable device region */

#define VFIO_DEVICE_FLAGS_FSL_MC (1 << 4)	/* vfio Freescale MC device */

#define IRQ_SET_BUF_LEN  (sizeof(struct vfio_irq_set) + sizeof(int))

int vfio_fd, vfio_group_fd;
static int vfio_group_id;
int dpio_epoll_fd;

void vfio_destroy(void)
{
	if (vfio_group_fd) {
		close(vfio_group_fd);
		vfio_group_fd = 0;
	}
	if (vfio_fd) {
		close(vfio_fd);
		vfio_fd = 0;
	}
}

int vfio_setup(const char *dprc)
{
	char dprc_path[100];
	char vfio_group_path[100];
	ssize_t linksize = 0;
	int dprc_fd;

	struct vfio_group_status group_status =	{
		.argsz = sizeof(group_status) };

	vfio_fd = open("/dev/vfio/vfio", O_RDWR);
	if (vfio_fd < 0) {
		perror("VFIO open failed");
		return -1;
	}

	sprintf(dprc_path, "/sys/bus/fsl-mc/devices/%s/iommu_group", dprc);
	linksize = readlink(dprc_path, vfio_group_path, 100-1);
	if (linksize < 0) {
		printf("Failed to readlink %s\n", dprc_path);
		return -1;
	}
	vfio_group_path[linksize] = 0;
	vfio_group_id = atoi(basename(vfio_group_path));
	sprintf(vfio_group_path, "/dev/vfio/%d", vfio_group_id);
	vfio_group_fd = open(vfio_group_path, O_RDWR);
	if (vfio_group_id < 0) {
		perror("VFIO group open failed");
		return -1;
	}

	ioctl(vfio_group_fd, VFIO_GROUP_GET_STATUS, &group_status);
	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		printf("Group status not viable\n");
		return -1;
	}


	/* Add the group to the container */
	if (ioctl(vfio_group_fd, VFIO_GROUP_SET_CONTAINER, &vfio_fd)) {
		perror("VFIO_GROUP_SET_CONTAINER failed");
		return -1;
	}

	/* Enable the IOMMU model we want */
	if (ioctl(vfio_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU)) {
		perror("VFIO_SET_IOMMU failed");
		return -1;
	}
	vfio_force_rescan();

	/* Set Device information */
	dprc_fd = ioctl(vfio_group_fd, VFIO_GROUP_GET_DEVICE_FD, dprc);
	if (dprc_fd < 0) {
		perror("vfio get device fd for dprc failed");
		return -1;
	}


	return 0;
}

void *vfio_setup_dma(uint64_t dma_size)
{
	struct vfio_iommu_type1_dma_map dma_map = { .argsz = sizeof(dma_map) };
	int ret;

	/* Allocate some space and setup a DMA mapping */
	dma_map.vaddr = (unsigned long) mmap(0, dma_size,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (!dma_map.vaddr) {
		perror("mmap failed ");
		return NULL;
	}
	dma_map.size = dma_size;
	dma_map.iova = dma_map.vaddr; /* 1MB starting at 0x0 from device view */
	dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;

	ret = ioctl(vfio_fd, VFIO_IOMMU_MAP_DMA, &dma_map);
	if (ret) {
		perror("DMA map ioctl failed");
		return NULL;
	}
	return (void*) dma_map.vaddr;
}

int vfio_cleanup_dma(void *vaddr, uint64_t dma_size)
{
	struct vfio_iommu_type1_dma_unmap dma_map = { .argsz = sizeof(dma_map) };
	int ret;

	/* Unmap mempry from software address space (mmu) */
	ret = munmap(vaddr, dma_size);
	if (ret) {
		perror("DMA munmap() failed");
		return errno;
	}

	dma_map.size = dma_size;
	dma_map.iova = (unsigned long)vaddr;
	dma_map.flags = 0;

	/* Remove corresponding hardware accelerator mapping (smmu) */
	ret = ioctl(vfio_fd, VFIO_IOMMU_UNMAP_DMA, &dma_map);
	if (ret) {
		perror("DMA unmap ioctl failed");
		return errno;
	}
	return 0;
}

void *vfio_map_portal(const char *deviceid, int mem_type)
{
	void *vaddr;
	int device;
	struct vfio_region_info reg = { .argsz = sizeof(reg) };

	device = ioctl(vfio_group_fd, VFIO_GROUP_GET_DEVICE_FD, deviceid);
	if (device < 0) {
		perror("VFIO_GROUP_GET_DEVICE_FD failed");
		return NULL;
	}
	reg.index = mem_type;
	if (ioctl(device, VFIO_DEVICE_GET_REGION_INFO, &reg) != 0) {
		perror("VFIO_DEVICE_GET_REGION_INFO failed");
		return NULL;
	}
	vaddr =  mmap(0, reg.size,
			PROT_READ | PROT_WRITE,
			MAP_SHARED,
			device, reg.offset);
	if (vaddr == (void*) -1) {
		perror("portal mmap failed");
		return NULL;
	}
	if (mem_type == PORTAL_MEM_CENA) {
		static bool once;
		// Stashing work around
		// TOOO: check version - not needed on rev 2
		if (!once)
			vfio_dma_map_area((uint64_t) vaddr, reg.offset, reg.size);
		once = true;
	}
	return vaddr;
}

int vfio_unmap_portal(void *vaddr, const char *deviceid, int mem_type)
{
	int device;
	struct vfio_region_info reg = { .argsz = sizeof(reg) };

	device = ioctl(vfio_group_fd, VFIO_GROUP_GET_DEVICE_FD, deviceid);
	if (device < 0) {
		perror("VFIO_GROUP_GET_DEVICE_FD failed");
		return -EINVAL;
	}
	reg.index = mem_type;
	if (ioctl(device, VFIO_DEVICE_GET_REGION_INFO, &reg) != 0) {
		perror("VFIO_DEVICE_GET_REGION_INFO failed");
		return -EINVAL;
	}

	assert(!(reg.size % getpagesize()));

	if (mem_type == PORTAL_MEM_CENA) {
		static bool once;
		// Stashing work around
		// TOOO: check version - not needed on rev 2
		if (!once)
			vfio_cleanup_dma(vaddr, reg.size);
		once = true;
	}

	return munmap(vaddr, reg.size);
}

int vfio_dma_map_area(uint64_t vaddr, uint64_t offset, ssize_t size)
{
	struct vfio_iommu_type1_dma_map dma_map = {
		.argsz = sizeof(dma_map),
		.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE
	};
	int ret;

	dma_map.vaddr = vaddr;
	dma_map.size = size;
	dma_map.iova = offset;
	dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
	ret = ioctl(vfio_fd, VFIO_IOMMU_MAP_DMA, &dma_map);
	if (ret) {
		perror("DMA map ioctl failed");
		return -1;
	}
	return ret;
}


void vfio_force_rescan(void)
{
	if (system("echo 1 > /sys/bus/fsl-mc/rescan")) {
		perror("Rescan failed");
	}
}

int vfio_bind_container(const char *dprc)
{
	char override_cmd[100];
	char bind_cmd[100];

	sprintf(override_cmd, "echo vfio-fsl-mc > /sys/bus/fsl-mc/devices/%s/driver_override", dprc);
	sprintf(bind_cmd, "echo %s > /sys/bus/fsl-mc/drivers/vfio-fsl-mc/bind", dprc);
	if (system(override_cmd))
		return -1;
	if (system(bind_cmd))
		return -1;
	return 0;
}

int vfio_unbind_container(const char *dprc)
{
	char override_cmd[100];
	char bind_cmd[100];

	sprintf(override_cmd, "echo vfio-fsl-mc > /sys/bus/fsl-mc/devices/%s/driver_override", dprc);
	sprintf(bind_cmd, "echo %s > /sys/bus/fsl-mc/drivers/vfio-fsl-mc/unbind", dprc);
	if (system(override_cmd))
		return -1;
	if (system(bind_cmd))
		return -1;
	return 0;
}

int vfio_destroy_container(const char *dprc)
{
	char override_cmd[100];
	char bind_cmd[100];

	sprintf(override_cmd, "echo vfio-fsl-mc > /sys/bus/fsl-mc/devices/%s/driver_override", dprc);
	sprintf(bind_cmd, "restool dpio destroy %s", dprc);
	if (system(override_cmd))
		return -1;
	if (system(bind_cmd))
		return -1;
	return 0;
}

struct vfio_iommu_type1_dma_map map = {
	.argsz = sizeof(map),
	.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE |
			VFIO_DMA_MAP_FLAG_MMIO,
	.vaddr = 0x6030000,
	.iova = 0x6030000,
	.size = 0x1000,
};

struct vfio_iommu_type1_dma_unmap unmap = {
	.argsz = sizeof(unmap),
	.flags = 0,
	.iova = 0x6030000,
	.size = 0x1000,
};
