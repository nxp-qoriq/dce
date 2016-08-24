/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2018 NXP
 * All rights reserved.
 */
#ifndef __CIRC_FIFO_H
#define __CIRC_FIFO_H

struct circ_fifo {
	unsigned int allocer;
	unsigned int freer;
	unsigned int num_bufs;
	void *mem;
	size_t buf_size;
	pthread_mutex_t alloc_lock;
	pthread_mutex_t free_lock;
};

static void circ_fifo_setup(struct circ_fifo *fifo, void *mem,
		unsigned int object_size, size_t number_objects);
static void *circ_fifo_alloc(struct circ_fifo *fifo);
static void circ_fifo_free(struct circ_fifo *fifo);

static inline void circ_fifo_setup(struct circ_fifo *fifo, void *mem,
		unsigned int object_size, size_t number_objects)
{
	fifo->allocer = 0;
	fifo->freer = 0;
	fifo->num_bufs = number_objects;
	fifo->mem = mem;
	fifo->buf_size = object_size;
	pthread_mutex_init(&fifo->alloc_lock, NULL);
	pthread_mutex_init(&fifo->free_lock, NULL);
}

static inline bool circ_fifo_empty(struct circ_fifo *fifo)
{
	return fifo->allocer == fifo->freer;
}

static inline bool circ_fifo_full(struct circ_fifo *fifo)
{
	/* We allow the allocer and freer indexes to be 2 * the number of
	 * available buffers. This allows us to detect the difference between
	 * full and empty
	 */
	return (fifo->allocer % fifo->num_bufs == fifo->freer % fifo->num_bufs)
		&& (fifo->allocer != fifo->freer);
}

static inline void *circ_fifo_alloc(struct circ_fifo *fifo)
{
	unsigned int temp;

	if (circ_fifo_full(fifo))
		return NULL;
	temp = fifo->allocer % fifo->num_bufs;
	/* detect wrap condition. We go 2 * num_bufs to detect full vs empty
	 * since in both cases the allocer and the freer will be touching
	 */
	fifo->allocer = (fifo->allocer + 1) % (2 * fifo->num_bufs);
	return (uint8_t *)fifo->mem + (temp * fifo->buf_size);
}

static inline void circ_fifo_alloc_undo(struct circ_fifo *fifo)
{
	assert(!circ_fifo_empty(fifo));
	fifo->allocer = (fifo->allocer) ?
			fifo->allocer - 1 :
			(fifo->num_bufs * 2) - 1;
}

static inline void circ_fifo_free(struct circ_fifo *fifo)
{
	if (circ_fifo_empty(fifo)) {
		assert(false);
		return;
	}
	fifo->freer = (fifo->freer + 1) % (2 * fifo->num_bufs);
}

static inline void *circ_fifo_head(struct circ_fifo *fifo)
{
	return (uint8_t *)fifo->mem +
			(fifo->freer % fifo->num_bufs * fifo->buf_size);
}

static inline void *circ_fifo_head_seek(struct circ_fifo *fifo,
					unsigned int seek)
{
	return (uint8_t *)fifo->mem +
		fifo->buf_size * ((fifo->freer + seek) % fifo->num_bufs);
}

static inline unsigned int circ_fifo_num_alloc(struct circ_fifo *fifo)
{
	return fifo->allocer >= fifo->freer ? fifo->allocer - fifo->freer :
			fifo->allocer + (2 * fifo->num_bufs) - fifo->freer;
}

#endif /* __CIRC_FIFO_H */
