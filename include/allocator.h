/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2010 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#ifndef __ALLOCATOR_H
#define __ALLOCATOR_H

#include <pthread.h>
#include <stdint.h>

struct dma_mem {
	void *addr;
	size_t sz;
	pthread_mutex_t alloc_lock;
};

/* Hooks for initialisation an allocator */
void dma_mem_allocator_init(struct dma_mem *mem);
void *dma_mem_memalign(struct dma_mem *map, size_t align, size_t size);
void dma_mem_free(struct dma_mem *map, void *ptr);
void dma_mem_print(struct dma_mem *map);
void dma_mem_print_lock(struct dma_mem *map);

#endif /* __ALLOCATOR_H */
