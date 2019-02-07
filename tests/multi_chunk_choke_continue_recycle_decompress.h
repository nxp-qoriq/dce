/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2019 Freescale Semiconductor, Inc.
 * All rights reserved.
 */

#ifndef __MULTI_CHUNK_CHOKE_CONTINUE_RECYCLE_DECOMP_H
#define __MULTI_CHUNK_CHOKE_CONTINUE_RECYCLE_DECOMP_H

#include <time.h>

void multi_chunk_choke_continue_recycle_decompress(struct qbman_swp *swp,
				struct dpdcei *comp_dpdcei,
				struct dpdcei *decomp_dpdcei,
				struct dma_mem *mem)
{
	cpu_set_t cpu;
	size_t num_ops = 32; /* single op test */
	struct dpdcei_lane_params lane_params;
	struct dpdcei_lane *lane;
	uint8_t *compressed_dce_test_data;
	size_t compressed_dce_test_data_size;
	size_t chunk_sz = 1024;
	size_t out_sz = chunk_sz * 10;
	size_t in_sz = chunk_sz;
	void *addr;
	struct dpaa2_fd input_fd = (struct dpaa2_fd){0};
	struct dpaa2_fd output_fd = (struct dpaa2_fd){0};
	struct dce_op_fd_pair_tx tx_op;
	struct dce_op_fd_pair_rx rx_ops[num_ops];
	int ret;
	int timeout = 1000;
	uint8_t *decompressed_output;

	/* Initialize random number generator */
	srandom(time(NULL));

	/* Necessary during enqueue, but is checked only in lane_create() */
	CPU_ZERO(&cpu);
	CPU_SET(0, &cpu);
	ret = pthread_setaffinity_np(pthread_self(),
			sizeof(cpu), &cpu);
	if (ret) {
		pr_err("Failed to affine my thread\n");
		goto fail_affine;
	}

	decompressed_output = malloc(dce_test_data_size);
	if (!decompressed_output) {
		pr_err("Unable to allocate memory for integrity check\n");
		goto fail_alloc_integrity_mem;
	}

	lane_params = (struct dpdcei_lane_params){
		.swp = swp,
		.dpdcei = decomp_dpdcei,
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

	debug(0, "Setting up dpdcei_lane\n");
	lane = dpdcei_lane_create(&lane_params);
	if (!lane) {
		pr_err("Failed to create dpdcei_lane\n");
		goto fail_lane_create;
	}

	debug(0, "Compress data for decompression testing\n");
	compressed_dce_test_data = malloc(dce_test_data_size);
	if (!compressed_dce_test_data) {
		pr_err("Failed to allocate memory buffer to hold test data\n");
		goto fail_alloc_test_data_buff;
	}

	compressed_dce_test_data_size = dce_test_data_size;

	ret = gzip_data(swp, comp_dpdcei, mem, compressed_dce_test_data,
			dce_test_data, &compressed_dce_test_data_size);
	if (ret) {
		pr_err("Failed to compress data to prepare for decomp test\n");
		goto fail_gzip_test_data_setup;
	}

	unsigned int num_chunks;
	unsigned int i;
	assert(compressed_dce_test_data_size >= chunk_sz);
	/* Add chunk if data_len does not divide evenly into chunks */
	num_chunks = (compressed_dce_test_data_size / chunk_sz) +
		!!(compressed_dce_test_data_size % chunk_sz);

	for (i = 0; i < num_chunks; i++) {
		/* Make sure to allocate only needed for last chunk */
		in_sz = (i + 1 == num_chunks) ?
			compressed_dce_test_data_size - (i * chunk_sz) :
			chunk_sz;
		debug(0, "Setting up input data for op #%u\n", i);
		addr = dma_mem_memalign(&dce_mem, 0, in_sz);
		if (!addr) {
			pr_err("Failed to allocate dma-able memory for input\n");
			goto fail_input_alloc;
		}
		memcpy(addr, &compressed_dce_test_data[i * chunk_sz], in_sz);
		dpaa2_fd_set_addr(&input_fd, (dma_addr_t)addr);
		dpaa2_fd_set_len(&input_fd, in_sz);

		debug(0, "Setting up output buffer for op #%u\n", i);
		addr = dma_mem_memalign(&dce_mem, 0, out_sz);
		if (!addr) {
			pr_err("Failed to allocate dma-able memory for output\n");
			dma_mem_free(mem,
					(void *)dpaa2_fd_get_addr(&input_fd));
			goto fail_output_alloc;
		}
		dpaa2_fd_set_addr(&output_fd, (dma_addr_t)addr);
		if (random() % 2) {
			dpaa2_fd_set_len(&output_fd, out_sz);
		} else {
			/* Force an output blocked suspend, by setting the
			 * output buffer length indicator to be 1 tenth its
			 * actual size */
			dpaa2_fd_set_len(&output_fd, out_sz / 10);
			debug(0, "Setting the output buffer to %u bytes to force OUTPUT_BLOCKED_SUSPEND\n",
					dpaa2_fd_get_len(&output_fd));
		}

		tx_op.input_fd = &input_fd;
		tx_op.output_fd = &output_fd;
		tx_op.flush = i + 1 == num_chunks ? DCE_Z_FINISH :
					DCE_Z_NO_FLUSH;
		/* One extra sanity check */
		tx_op.user_context = (void *)(0x900DF00DULL | i << 4);

		debug(0, "Sending operation on compression dpdcei\n");
		ret = lane_enqueue_fd_pair(swp, lane, &tx_op);
		if (ret) {
			pr_err("Failed to enqueue op. Got status %d\n", ret);
			dma_mem_free(mem,
					(void *)dpaa2_fd_get_addr(&input_fd));
			dma_mem_free(mem,
					(void *)dpaa2_fd_get_addr(&output_fd));
			goto fail_enqueue;
		}
	}

	debug(0, "Polling for results\n");
	unsigned int ops_rcvd;
	size_t seeker = 0;
	for (ret = 0, ops_rcvd = 0; ops_rcvd < num_chunks;) {
		while (!(ret = lane_dequeue_fd_pair(swp, lane, rx_ops,
								num_ops))) {
			usleep(1000);
			if (!timeout--) {
				pr_err("Failed to dequeue op\n");
				goto fail_dequeue;
			}
		}
		timeout = 1000;
		assert(ret > 0);
		int j;
		for (j = 0; j < ret; j++) {
			int ret;
			struct dce_op_fd_pair_rx *op = &rx_ops[j];

			debug(0, "Processing op #%u\n", j + ops_rcvd);
			if (op->status != FULLY_PROCESSED &&
					op->status != STREAM_END &&
					op->status != OUTPUT_BLOCKED_SUSPEND &&
					op->status != SKIPPED) {
				pr_err("Got unexpected status %s\n",
						dce_status_string(op->status));
				goto fail_sanity;
			} else if (op->user_context !=
					(void *)(0x900DF00DULL |
						(j + ops_rcvd) << 4)) {
				pr_err("Got unexpected context %p\n",
							op->user_context);
				goto fail_sanity;
			}
			debug(0, "Received response with status %s\n",
					dce_status_string(op->status));

			switch (op->status) {
			case FULLY_PROCESSED:
			case STREAM_END:
			case OUTPUT_BLOCKED_SUSPEND:
				memcpy(&decompressed_output[seeker],
				(void *)dpaa2_fd_get_addr(&op->output_fd),
				dpaa2_fd_get_len(&op->output_fd));
				seeker += dpaa2_fd_get_len(&op->output_fd);
				break;
			default:
				/* No output is produced in SKIPPED frames */
				break;
			}

			if (op->status == OUTPUT_BLOCKED_SUSPEND) {
				debug(0, "This op was not fully processed because the output buffer length was too small to hold the output\n");
				debug(0, "%zu bytes of the input were processed and %u bytes of output were produced\n",
						op->input_consumed,
						dpaa2_fd_get_len(&output_fd));

				debug(0, "Acknowledge the OUTPUT_BLOCKED_SUSPEND was received and indicate the operation is to be resumed where it halted\n");
				lane_stream_continue(lane);

				debug(0, "Sending op #%u back in for processing\n",
						j + ops_rcvd);
				input_fd = op->input_fd;

				debug(0, "Update the input address to left over bytes that were not processed in the first pass\n");
				dpaa2_fd_set_addr(&input_fd,
					dpaa2_fd_get_addr(&input_fd) +
					op->input_consumed);

				debug(0, "Update the input length to left over bytes\n");
				dpaa2_fd_set_len(&input_fd,
						dpaa2_fd_get_len(&input_fd) -
						op->input_consumed);

				output_fd = op->output_fd;

				debug(0, "Update the output buffer address to point to empty room in buffer\n");
				debug(0, "NOTE: The buffer was marked smaller that it actually is to artificially force OUTPUT_BLOCKED_SUSPEND\n");
				dpaa2_fd_set_addr(&output_fd,
					dpaa2_fd_get_addr(&output_fd) +
					dpaa2_fd_get_len(&output_fd));
				dpaa2_fd_set_len(&output_fd, out_sz -
						dpaa2_fd_get_len(&output_fd));

				tx_op.flush = op->flush;
				/* One extra sanity check */
				tx_op.user_context = (void *)(0x900DF00DULL |
							num_chunks << 4);

				timeout = 1000;
				while ((ret = lane_recycle_fd_pair(swp, lane,
							&tx_op)))
					if (ret > 0 || !timeout--)
						break;

				assert(ret >= 0);
				debug(0, "Sent op #%u back to finish processing. Lane %s",
						j + ops_rcvd,
						ret == 0 ? "is still suspended, there must be more ops that were skipped because of the OUTPUT_BLOCKED_SUSPEND\n" :
						"has exited suspend\n");
				num_chunks++;
			} else if (op->status == SKIPPED) {
				debug(0, "This op was SKIPPED because a previous op caused the lane to be suspended\n");

				debug(0, "Sending op #%u back in for processing\n",
						j + ops_rcvd);

				input_fd = op->input_fd;
				output_fd = op->output_fd;
				tx_op.flush = op->flush;
				/* One extra sanity check */
				tx_op.user_context = (void *)(0x900DF00DULL |
							num_chunks << 4);

				timeout = 1000;
				while ((ret = lane_recycle_fd_pair(swp, lane,
							&tx_op)))
					if (ret > 0 || !timeout--)
						break;

				assert(ret >= 0);
				debug(0, "Sent op #%u back to finish processing. Lane %s",
						j + ops_rcvd,
						ret == 0 ? "is still suspended, there must be more ops that were skipped because of the OUTPUT_BLOCKED_SUSPEND\n" :
						"has exited suspend\n");
				num_chunks++;
			}
		}
		ops_rcvd += ret;
	}

	if (memcmp(decompressed_output, dce_test_data, dce_test_data_size)) {
		pr_err("Decompressed data did not match original input\n");
		goto fail_integrity;
	}

	debug(0,"Success\n");

fail_integrity:
fail_sanity:
fail_enqueue:
fail_dequeue:
fail_output_alloc:
fail_input_alloc:
fail_gzip_test_data_setup:
	free(compressed_dce_test_data);
fail_alloc_test_data_buff:
	ret = dpdcei_lane_destroy(lane);
	if (ret)
		pr_err("Failed to destroy dpdcei_lane\n");
fail_lane_create:
	free(decompressed_output);
fail_alloc_integrity_mem:
fail_affine:
	return;
}

#endif /* __MULTI_CHUNK_CHOKE_CONTINUE_RECYCLE_DECOMP_H */
