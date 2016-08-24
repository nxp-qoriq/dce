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
		perror("VFIO open failed: ");
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
		perror("VFIO group open failed: ");
		return -1;
	}

	ioctl(vfio_group_fd, VFIO_GROUP_GET_STATUS, &group_status);
	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		printf("Group status not viable\n");
		return -1;
	}


	/* Add the group to the container */
	if (ioctl(vfio_group_fd, VFIO_GROUP_SET_CONTAINER, &vfio_fd)) {
		perror("VFIO_GROUP_SET_CONTAINER failed : ");
		return -1;
	}

	/* Enable the IOMMU model we want */
	if (ioctl(vfio_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU)) {
		perror("VFIO_SET_IOMMU failed : ");
		return -1;
	}
	vfio_force_rescan();

	/* Set Device information */
	dprc_fd = ioctl(vfio_group_fd, VFIO_GROUP_GET_DEVICE_FD, dprc);
	if (dprc_fd < 0) {
		perror("vfio get device fd for dprc failed: ");
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
		perror("mmap failed : ");
		return NULL;
	}
	dma_map.size = dma_size;
	dma_map.iova = dma_map.vaddr; /* 1MB starting at 0x0 from device view */
	dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;

	ret = ioctl(vfio_fd, VFIO_IOMMU_MAP_DMA, &dma_map);
	if (ret) {
		perror("DMA map ioctl failed: ");
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

#define PORTAL_SIZE  4096
void *vfio_map_portal_mem(const char *deviceid, int mem_type)
{
	void *vaddr;
	int device;
	struct vfio_region_info reg = { .argsz = sizeof(reg) };

	device = ioctl(vfio_group_fd, VFIO_GROUP_GET_DEVICE_FD, deviceid);
	if (device < 0) {
		perror("VFIO_GROUP_GET_DEVICE_FD failed: ");
		return NULL;
	}
	reg.index = mem_type;
	if (ioctl(device, VFIO_DEVICE_GET_REGION_INFO, &reg) != 0) {
		perror("VFIO_DEVICE_GET_REGION_INFO failed: ");
		return NULL;
	}
	vaddr =  mmap(0, reg.size,
			PROT_READ | PROT_WRITE,
			MAP_SHARED,
			device, reg.offset);
	if (vaddr == (void*) -1) {
		perror("portal mmap failed : ");
		return NULL;
	}
	if (mem_type == PORTAL_MEM_CENA) {
		// Stashing work around
		// TOOO: check version - not needed on rev 2
		vfio_dma_map_area((uint64_t) vaddr, reg.offset, reg.size);
	}
	return vaddr;
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
		perror("DMA map ioctl failed: ");
		return -1;
	}
	return ret;
}


void vfio_force_rescan(void)
{
	if (system("echo 1 > /sys/bus/fsl-mc/rescan")) {
		perror("Rescan failed: ");
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

int vfio_disable_regions(int device_fd, int *ird_evend_fd)
{
	struct vfio_device_info dev_info = { .argsz = sizeof(dev_info) };
	struct vfio_region_info reg_info = { .argsz = sizeof(reg_info) };
	struct vfio_irq_info irq_info = { .argsz = sizeof(irq_info) };
	struct vfio_irq_set *irq_set;
	char irq_set_buf[IRQ_SET_BUF_LEN];
	int ret;
	unsigned int i;
	int *fd_ptr;

	irq_info.index = 0;
	if (ioctl(device_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq_info))
		return -1;

	ret = munmap((void *)0x6030000, 0x1000);
	if (ret != 0)
		return -1;

	ret = ioctl(vfio_fd, VFIO_IOMMU_UNMAP_DMA, &unmap);
	if (ret != 0)
		return ret;

	for (i = 0; i < dev_info.num_regions; i++) {
		size_t size;

		reg_info.index = i;
		if (ioctl(device_fd, VFIO_DEVICE_GET_REGION_INFO, &reg_info))
			return -1;
		size = reg_info.size;
		if (reg_info.size < 0x1000)
			size = 0x1000;

		ret = munmap((void *)reg_info.offset, size);
		if (ret != 0)
			return -1;
	}

	/* Disable interrupt */
	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = sizeof(irq_set_buf);
	irq_set->count = 0;
	irq_set->flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_DPIO_DATA_IRQ_INDEX;
	irq_set->start = 0;
	fd_ptr = (int *)&irq_set->data;
	*fd_ptr = *ird_evend_fd;
	if (ioctl(device_fd, VFIO_DEVICE_SET_IRQS, irq_set) < 0)
		return -1;

	return 0;
}

int vfio_enable_regions(int device_fd, int *ird_evend_fd)
{
	struct vfio_device_info dev_info = { .argsz = sizeof(dev_info) };
	struct vfio_region_info reg_info = { .argsz = sizeof(reg_info) };
	struct vfio_irq_info irq_info = { .argsz = sizeof(irq_info) };
	struct vfio_irq_set *irq_set;
	char irq_set_buf[IRQ_SET_BUF_LEN];
	int ret;
	unsigned int i;
	int *fd_ptr;
	unsigned long *vaddr = NULL;

	vaddr = (unsigned long *) mmap(NULL, 0x1000, PROT_WRITE | PROT_READ,
					MAP_SHARED, device_fd,
					0x6030000);
	if (vaddr == MAP_FAILED) {
		perror("mmap failed");
		return -1;
	}

	map.vaddr = (unsigned long)vaddr;
	ret = ioctl(vfio_fd, VFIO_IOMMU_MAP_DMA, &map);

	/* retry */
	if (errno == EBUSY) {
		ret = ioctl(vfio_fd, VFIO_IOMMU_UNMAP_DMA, &unmap);
		if (ret)
			printf("Error in vfio_dma_unmap\n");

		ret = ioctl(vfio_fd, VFIO_IOMMU_MAP_DMA, &map);
	}
	if (ret != 0)
		return ret;

	if (errno)
		return errno;

	if (ioctl(device_fd, VFIO_DEVICE_GET_INFO, &dev_info))
		return -1;
	if (!(dev_info.flags & VFIO_DEVICE_FLAGS_FSL_MC))
		return -1;

	for (i = 0; i < dev_info.num_regions; i++) {
		unsigned long *map = NULL;
		size_t size;

		reg_info.index = i;
		if (ioctl(device_fd, VFIO_DEVICE_GET_REGION_INFO, &reg_info))
			return -1;
		size = reg_info.size;
		if (reg_info.size < 0x1000)
			size = 0x1000;

		map = (unsigned long *) mmap(NULL, size, PROT_WRITE | PROT_READ,
					MAP_SHARED, device_fd, reg_info.offset);
		if (map == MAP_FAILED)
			return -1;
	}

	/* Set irqs */
	irq_info.index = 0;
	if (ioctl(device_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq_info))
		return -1;

	/* Now set up IRQ : we know count is always one */
	*ird_evend_fd = eventfd(0, 0);
	if (*ird_evend_fd < 0) {
		printf("Error creating eventfd() %d\n", *ird_evend_fd);
		return -1;
	}

	/* Register interrupt */
	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = sizeof(irq_set_buf);
	irq_set->count = irq_info.count;
	irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD |
			VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_DPIO_DATA_IRQ_INDEX;
	irq_set->start = 0;
	fd_ptr = (int *)&irq_set->data;
	*fd_ptr = *ird_evend_fd;
	if (ioctl(device_fd, VFIO_DEVICE_SET_IRQS, irq_set) < 0)
		return -1;

	return 0;
}

int vfio_disable_dpio_interrupt(struct qbman_swp *swp,
				struct dpaa2_io *dpio,
				int *ird_evend_fd,
				pthread_t *intr_thread)
{
	struct vfio_group_status status = { .argsz = sizeof(status) };
	char deviceName[PATH_MAX];
	int device_fd;
	struct epoll_event epoll_ev;
	void *res;

	/* Status */
	if (vfio_group_fd < 0)
		return -1;
	if (ioctl(vfio_group_fd, VFIO_GROUP_GET_STATUS, &status))
		return -1;
	if (!(status.flags & VFIO_GROUP_FLAGS_VIABLE))
		return -1;
	if (!ioctl(vfio_fd, VFIO_GET_API_VERSION) == VFIO_API_VERSION)
		return -1;

	/* Set Device information */
	/* Get deviceName and groupid */
	snprintf(deviceName, sizeof(deviceName), "dpio.%i",
						dpio->dpio_desc.dpio_id);

	device_fd = ioctl(vfio_group_fd, VFIO_GROUP_GET_DEVICE_FD, deviceName);
	if (device_fd < 0)
		return -1;
	if (vfio_disable_regions(device_fd, ird_evend_fd))
		return -1;
	if (!ioctl(device_fd, VFIO_DEVICE_RESET))
		return -1;

	/* Delete epoll */
	epoll_ev.events = EPOLLIN | EPOLLPRI | EPOLLET;
	epoll_ev.data.fd = *ird_evend_fd;
	if (epoll_ctl(dpio_epoll_fd, EPOLL_CTL_DEL, *ird_evend_fd, &epoll_ev) < 0)
		return -1;

	/* Disable interrupts */
	qbman_swp_interrupt_set_inhibit(swp, QBMAN_SWP_INTERRUPT_DQRI);

	/* Cancel the interrupt thread */
	if (pthread_cancel(*intr_thread))
		return -1;

	if (pthread_join(*intr_thread, &res) != 0)
		return -1;

	if (res != PTHREAD_CANCELED) {
		printf("PTHREAD_CANCEL fail\n");
		return -1;
	}

	return 0;
}

int vfio_enable_dpio_interrupt(struct qbman_swp *swp,
				struct dpaa2_io *dpio,
				int *ird_evend_fd,
				pthread_t *intr_thread,
				void *(*handle_dpio_interrupts)(void *))
{
	struct vfio_group_status status = { .argsz = sizeof(status) };
	char pathIommu[PATH_MAX];
	char deviceName[PATH_MAX];
	char *groupName;
	int groupid, len, device_fd;
	char iommuGroupPath[PATH_MAX];
	struct epoll_event epoll_ev;
	pthread_attr_t intr_thread_attr;
	cpu_set_t cpu;
	int err;

	/* Get deviceName and groupid */
	snprintf(deviceName, sizeof(deviceName), "dpio.%i",
						dpio->dpio_desc.dpio_id);
	snprintf(pathIommu, sizeof(pathIommu),
			"/sys/bus/fsl-mc/devices/%s/iommu_group", deviceName);
	len = readlink(pathIommu, iommuGroupPath, PATH_MAX);
	if (len == -1)
		return -1;
	iommuGroupPath[len] = 0;
	groupName = basename(iommuGroupPath);
	if (sscanf(groupName, "%d", &groupid) != 1)
		return -1;
	if (groupid < 0)
		return -1;

	/* Status */
	if (vfio_group_fd < 0)
		return -1;
	if (ioctl(vfio_group_fd, VFIO_GROUP_GET_STATUS, &status))
		return -1;
	if (!(status.flags & VFIO_GROUP_FLAGS_VIABLE))
		return -1;
	if (!ioctl(vfio_fd, VFIO_GET_API_VERSION) == VFIO_API_VERSION)
		return -1;

	/* Set Device information */
	device_fd = ioctl(vfio_group_fd, VFIO_GROUP_GET_DEVICE_FD, deviceName);
	if (device_fd < 0)
		return -1;
	/*
	if (vfio_enable_regions(device_fd, ird_evend_fd))
		return -1;
		*/
	if (!ioctl(device_fd, VFIO_DEVICE_RESET))
		return -1;

	/* Setup epoll */
	dpio_epoll_fd = epoll_create(1);
	epoll_ev.events = EPOLLIN | EPOLLPRI | EPOLLET;
	epoll_ev.data.fd = *ird_evend_fd;
	err = epoll_ctl(dpio_epoll_fd, EPOLL_CTL_ADD, *ird_evend_fd, &epoll_ev);
	if (err < 0)
		return -1;

	/* Enable interrupts */
	qbman_swp_interrupt_set_trigger(swp, QBMAN_SWP_INTERRUPT_DQRI);
	qbman_swp_interrupt_clear_status(swp, 0xffffffff);
	qbman_swp_interrupt_set_inhibit(swp, 1);

	/* Set the interrupt handler to run on the core specified in dpio. This
	 * allows us to take advantage of portal stashing. A portal can only be
	 * stashed to one core  */
	err = pthread_attr_init(&intr_thread_attr);
	if (err)
		return err;
	CPU_ZERO(&cpu);
	CPU_SET(dpio->dpio_desc.cpu, &cpu);
	err = pthread_attr_setaffinity_np(&intr_thread_attr,
					   sizeof(cpu_set_t),
					   &cpu);
	if (err)
		return err;
	/* Create the interrupt thread */
	err = pthread_create(intr_thread, &intr_thread_attr,
				handle_dpio_interrupts, dpio);
	if (err)
		return -1;

	return 0;
}

