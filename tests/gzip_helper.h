/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2019 Freescale Semiconductor, Inc.
 * All rights reserved.
 */

#ifndef __GZIP_HELPER_H
#define __GZIP_HELPER_H

int gzip_data(struct qbman_swp *swp,
		struct dpdcei *comp_dpdcei,
		struct dma_mem *mem,
		void *dest,
		void *source,
		size_t *size)
{
	cpu_set_t cpu;
	size_t num_ops = 1; /* single op test */
	struct dpdcei_lane_params lane_params;
	struct dpdcei_lane *lane;
	size_t chunk_sz = *size;
	void *addr;
	struct dpaa2_fd input_fd = (struct dpaa2_fd){0};
	struct dpaa2_fd output_fd = (struct dpaa2_fd){0};
	struct dce_op_fd_pair_tx tx_op;
	struct dce_op_fd_pair_rx rx_op;
	int ret;
	int timeout = 1000;

	/* Necessary during enqueue, but is checked only in lane_create() */
	CPU_ZERO(&cpu);
	CPU_SET(0, &cpu);
	ret = pthread_setaffinity_np(pthread_self(),
			sizeof(cpu), &cpu);
	if (ret) {
		pr_err("Failed to affine my thread\n");
		goto fail_affine;
	}

	lane_params = (struct dpdcei_lane_params){
		.swp = swp,
		.dpdcei = comp_dpdcei,
		.paradigm = DCE_STATEFUL_RECYCLE,
		.compression_format = DCE_CF_GZIP,
		.compression_effort = DCE_CE_BEST_POSSIBLE,
		.dma_alloc = dma_allocator,
		.dma_free = dma_freer,
		.dma_opaque = mem,
		.max_in_flight = num_ops, /* we are sending a single op */
		/* use default gz_header */
		/* buffer_pool_id not used */
		/* buffer_pool_id2 not used */
		/* release_buffers not used */
		/* encode_base_64 not used */
	};

	debug(1, "Setting up dpdcei_lane\n");
	lane = dpdcei_lane_create(&lane_params);
	if (!lane) {
		pr_err("Failed to create dpdcei_lane\n");
		goto fail_lane_create;
	}

	debug(1, "Setting up input data\n");
	addr =  dma_mem_memalign(mem, 0 /* alignment */, chunk_sz);
	if (!addr){
		pr_err("Failed to allocate dma-able memory for input\n");
		goto fail_input_alloc;
	}
	memcpy(addr, source, chunk_sz);

	dpaa2_fd_set_addr(&input_fd, (dma_addr_t)addr);
	dpaa2_fd_set_len(&input_fd, chunk_sz);

	debug(1, "Setting up output buffer\n");

	addr = dma_mem_memalign(mem, 0, chunk_sz / 2 /* comp less space*/);
	if (!addr){
		pr_err("Failed to allocate dma-able memory for output\n");
		goto fail_output_alloc;
	}

	dpaa2_fd_set_addr(&output_fd, (dma_addr_t)addr);
	dpaa2_fd_set_len(&output_fd, (dma_addr_t)chunk_sz / 2);

	tx_op.input_fd = &input_fd;
	tx_op.output_fd = &output_fd;
	tx_op.flush = DCE_Z_FINISH;
	tx_op.user_context = (void *)0x900DF00D; /* One extra sanity check */

	debug(1, "Sending operation on compression dpdcei\n");
	ret = lane_enqueue_fd_pair(swp, lane, &tx_op);
	if (ret) {
		pr_err("Failed to enqueue op. Got status %d\n", ret);
		goto fail_enqueue;
	}

	debug(1, "Polling for result\n");
	while (!(ret = lane_dequeue_fd_pair(swp, lane, &rx_op, num_ops))) {
		usleep(1000);
		if (!timeout--) {
			pr_err("Failed to dequeue op\n");
			goto fail_dequeue;
		}
	}
	/* We sent a single op on lane, so impossible to receive more than 1 */
	assert(ret == 1);

	if (rx_op.status != STREAM_END) {
		pr_err("Compression returned unexpected status %s\n",
				dce_status_string(rx_op.status));
		goto fail_sanity;
	}

	debug(1, "Received response with status %s\n",
			dce_status_string(rx_op.status));

	if (rx_op.user_context != tx_op.user_context ||
			rx_op.user_context != (void*)0x900DF00D) {
		pr_err("User context was corrupted. Expected %p and got %p\n",
				(void *)0x900DF00D, rx_op.user_context);
		goto fail_sanity;
	}

	*size = dpaa2_fd_get_len(&rx_op.output_fd);
	memcpy(dest, (void *)dpaa2_fd_get_addr(&output_fd), *size);

	debug(1,"Success\n");

fail_sanity:
fail_enqueue:
fail_dequeue:
	dma_mem_free(mem, (void *)dpaa2_fd_get_addr(&output_fd));
fail_output_alloc:
	dma_mem_free(mem, (void *)dpaa2_fd_get_addr(&input_fd));
fail_input_alloc:
	ret = dpdcei_lane_destroy(lane);
	if (ret)
		pr_err("Failed to destroy dpdcei_lane\n");
fail_lane_create:
fail_affine:
	return ret;
}

#endif /* __GZIP_HELPER_H */
