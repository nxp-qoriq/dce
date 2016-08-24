/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */

#ifndef _VFIO_UTILS_H_
#define _VFIO_UTILS_H_

#include <stdint.h>
#include <fsl_qbman_portal.h>
#include <fsl_dpaa2_io.h>

int vfio_setup(const char *drpc);

void *vfio_setup_dma(uint64_t dma_size);
int vfio_cleanup_dma(void *vaddr, uint64_t dma_size);

#define PORTAL_MEM_CENA 0
#define PORTAL_MEM_CINH 1
void *vfio_map_portal_mem(const char *device, int memtype);

int vfio_dma_map_area(uint64_t vaddr, uint64_t offset, ssize_t size);

void vfio_force_rescan(void);

int vfio_bind_container(const char *dprc);

int vfio_unbind_container(const char *dprc);

int vfio_destroy_container(const char *dprc);

int vfio_disable_regions(int device_fd, int *ird_evend_fd);

int vfio_enable_regions(int device_fd, int *ird_evend_fd);

int vfio_disable_dpio_interrupt(struct qbman_swp *swp,
				struct dpaa2_io *dpio,
				int *ird_evend_fd,
				pthread_t *intr_thread);

int vfio_enable_dpio_interrupt(struct qbman_swp *swp,
			       struct dpaa2_io *dpio,
			       int *ird_evend_fd,
			       pthread_t *intr_thread,
			       void *(*handle_dpio_interrupts)(void *dpio));

void vfio_destroy(void);

#endif
