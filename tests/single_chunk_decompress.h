/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2019 Freescale Semiconductor, Inc.
 * All rights reserved.
 */

#ifndef __SINGLE_CHUNK_DECOMP_H
#define __SINGLE_CHUNK_DECOMP_H

#include "gzip_helper.h"

void single_chunk_decompress(struct qbman_swp *swp,
				struct dpdcei *comp_dpdcei,
				struct dpdcei *decomp_dpdcei,
				struct dma_mem *mem)
{
	cpu_set_t cpu;
	size_t num_ops = 1; /* single op test */
	struct dpdcei_lane_params lane_params;
	struct dpdcei_lane *lane;
	void *compressed_dce_test_data = NULL;
	size_t chunk_sz = 4096;
	size_t out_sz = chunk_sz *2;
	size_t in_sz = chunk_sz;
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
		.dpdcei = decomp_dpdcei,
		.paradigm = DCE_STATEFUL_RECYCLE,
		.compression_format = DCE_CF_GZIP,
		/* compression effort is not relevant in decompression*/
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

	debug(0, "Setting up dpdcei_lane\n");
	lane = dpdcei_lane_create(&lane_params);
	if (!lane) {
		pr_err("Failed to create dpdcei_lane\n");
		goto fail_lane_create;
	}

	debug(0, "Compress data for decompression testing\n");
	compressed_dce_test_data = malloc(in_sz);
	if (!compressed_dce_test_data) {
		pr_err("Failed to allocate memory buffer to hold test data\n");
		goto fail_alloc_test_data_buff;
	}

	ret = gzip_data(swp, comp_dpdcei, mem, compressed_dce_test_data,
			dce_test_data, &in_sz);
	if (ret) {
		pr_err("Failed to compress data to prepare for decomp test\n");
		goto fail_gzip_test_data_setup;
	}

	debug(0, "Setting up input data\n");
	addr =  dma_mem_memalign(mem, 0 /* alignment */, in_sz);
	if (!addr){
		pr_err("Failed to allocate dma-able memory for input\n");
		goto fail_input_alloc;
	}
	memcpy(addr, compressed_dce_test_data, in_sz);
	dpaa2_fd_set_addr(&input_fd, (dma_addr_t)addr);
	dpaa2_fd_set_len(&input_fd, in_sz);

	debug(0, "Setting up output buffer\n");
	addr =  dma_mem_memalign(mem, 0 /* alignment */, out_sz);
	if (!addr){
		pr_err("Failed to allocate dma-able memory for output\n");
		goto fail_output_alloc;
	}
	dpaa2_fd_set_addr(&output_fd, (dma_addr_t)addr);
	dpaa2_fd_set_len(&output_fd, out_sz);

	tx_op.input_fd = &input_fd;
	tx_op.output_fd = &output_fd;
	tx_op.flush = DCE_Z_FINISH;
	tx_op.user_context = (void *)0x900DF00D; /* One extra sanity check */

	debug(0, "Sending operation on decompression dpdcei\n");
	ret = lane_enqueue_fd_pair(swp, lane, &tx_op);
	if (ret) {
		pr_err("Failed to enqueue op. Got status %d\n", ret);
		goto fail_enqueue;
	}

	debug(0, "Polling for result\n");
	while (!(ret = lane_dequeue_fd_pair(swp, lane, &rx_op, num_ops))) {
		usleep(1000);
		if (!timeout--) {
			pr_err("Failed to dequeue op\n");
			goto fail_dequeue;
		}
	}
	/* We sent a single op, so it is impossible to receive more than 1 */
	assert(ret == 1);

	if (rx_op.status != STREAM_END) {
		pr_err("Decompression returned unexpected status %s\n",
				dce_status_string(rx_op.status));
		goto fail_sanity;
	}

	debug(0, "Received response with status %s\n",
			dce_status_string(rx_op.status));

	if (rx_op.user_context != tx_op.user_context ||
			rx_op.user_context != (void*)0x900DF00D) {
		pr_err("User context was corrupted. Expected %p and got %p\n",
				(void *)0x900DF00D, rx_op.user_context);
		goto fail_sanity;
	}

	debug(0, "Checking if the decompressed data matches the original data\n");
	if (memcmp(
		(void *)dpaa2_fd_get_addr(&output_fd),
		dce_test_data,
		dpaa2_fd_get_len(&rx_op.output_fd))) {
		pr_err("Decompressed data did not match original input\n");
		goto fail_integrity;
	}

	debug(0,"Success\n");

fail_integrity:
fail_sanity:
fail_enqueue:
fail_dequeue:
	dma_mem_free(mem, (void *)dpaa2_fd_get_addr(&output_fd));
fail_output_alloc:
	dma_mem_free(mem, (void *)dpaa2_fd_get_addr(&input_fd));
fail_input_alloc:
fail_gzip_test_data_setup:
	free(compressed_dce_test_data);
fail_alloc_test_data_buff:
	ret = dpdcei_lane_destroy(lane);
	if (ret)
		pr_err("Failed to destroy dpdcei_lane\n");
fail_lane_create:
fail_affine:
	return;
}

#endif /* __SINGLE_CHUNK_DECOMP_H */
