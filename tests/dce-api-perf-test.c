/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#include <compat.h>
#include <sys/sysinfo.h>
#include <semaphore.h>
#include <fsl_dprc.h>
#include <vfio_utils.h>
#include "../dce.h"
#include "dce-test-data.h"
#include <fsl_dpdcei.h>
#include <allocator.h>
#include "helper_swp.h"
#include "private.h"

struct chunk {
	dma_addr_t addr;
	dma_addr_t out_addr;
	size_t size;
	size_t out_size;
	struct list_head node;
};

enum suspend_policy {
	CONTINUE = 0,
	ABORT = 1,
};

enum skip_policy {
	RECYCLE = 0,
	DISCARD = 1,
};

struct work_context {
	struct qbman_swp *swp;
	pthread_t pid;
	struct dpdcei_lane *lane;
	struct dpdcei *dpdcei;
	struct list_head *chunk_list;
	const char *out_file;
	atomic_t eq;
	atomic_t dq;
	size_t total_in;
	size_t total_out;
	struct dma_mem *mem;
	enum lane_compression_format comp_format;
	enum dce_status status;
	bool stop;
	bool dequeue_stop;
	uint64_t end_time;
	bool synchronous;
	enum suspend_policy stream_suspend_policy;
	enum skip_policy skipped_frames_policy;
	unsigned int recycle_interval;
	bool suspend_sleep;
	sem_t sync_sem;
	sem_t recycle_finished;
	int engine;
	int idx;
	int ret;
};

struct dpdcei_context {
	struct dpdcei *dpdcei;
	int id;
	uint16_t token;
	/* Keep track of worker threads belonging to this dpdcei */
	struct list_head worker_list;
	int num_workers;
	struct list_head node;
};

struct swp_context {
	struct qbman_swp *swp;
	int id;
	uint16_t token;
	/* Keep track of dpdcei objects belonging to this dpio */
	struct list_head dpdcei_list;
	struct list_head node;
};

struct dprc_context {
	int id;
	/* Keep track of dpio objects belonging to this dprc */
	struct list_head swp_list;
	struct list_head node;
};

static int bad_parse;

static unsigned long get_ularg(const char *s, const char *pref)
{
	char *endptr;
	unsigned long ularg = strtoul(s, &endptr, 0 /* AUTO_DETECT_BASE */);

	bad_parse = 0;
	if ((endptr == s) || (*endptr != '\0')) {
		pr_err("Invalid %s%s\n", pref, s);
		bad_parse = 1;
	} else if (ularg == ULONG_MAX) {
		pr_err("Out of range %s%s\n", pref, s);
		bad_parse = 1;
	}
	return ularg;
}

static size_t chunk_size = 16 * 1024;
size_t max_decomp_ratio = 40; /* default maximum decompression ratio is 30, It
			       * can be changed using a parameter if the input
			       * data expands to more than 30 times the input
			       * size
			       */
size_t min_output_buf = 7;

static void sync_all(void);

#define wake_up(x) sem_post(x)

static void *worker_dq(void *__context)
{
	struct work_context *context = __context;
	FILE *out_stream = NULL;
	unsigned int num_ops, empty_count = 0, i;
	char thread_name[16];
	sem_t work_done_sem;

	snprintf(thread_name, sizeof(thread_name), "%d_dq", context->idx);
	pthread_setname_np(pthread_self(), thread_name);

	if (context->out_file) {
		char out_file[100];

		snprintf(out_file, 100, "%s_%d", context->out_file,
				context->idx);
		out_stream = fopen(out_file, "w");
		if (!out_stream)
			debug(0, "ERROR: Unable to open output file \"%s\" for writing\n",
					out_file);
	}

	sem_init(&work_done_sem,
			0 /* semaphore shared within process */,
			0 /* Semaphore start value */);
	debug(1, "Running on core %d\n", sched_getcpu());

	while (!context->dequeue_stop || (atomic_read(&context->eq) > atomic_read(&context->dq))) {
		const unsigned int max_num_fds = 32;
		struct dce_op_fd_pair_rx ops[max_num_fds];

		num_ops = lane_dequeue_fd_pair(context->swp, context->lane, ops,
								max_num_fds);
		if (!num_ops) {
			const unsigned int timeout = 15000;
			const unsigned int usec_in_sec = 1000000;
			const unsigned int backoff = 1000; /* microseconds */

			empty_count++;
			usleep(backoff);
			if (empty_count > (timeout * usec_in_sec / backoff)) {
				debug(0, "ERROR: Timed out while waiting for %d dequeues\n",
					atomic_read(&context->eq)
					- atomic_read(&context->dq));
				debug(0, "The number of frames on the Tx frame queue is %d and the Rx frame queue is %d\n",
				   dpdcei_todo_queue_count(context->swp,
					   context->dpdcei),
				   dpdcei_done_queue_count(context->swp,
					   context->dpdcei));
				debug(0, "PAUSED FOR DEBUG\n");
				getchar();
				context->stop = true;
				pthread_exit(NULL);
			} else {
				continue;
			}
		} else {
			empty_count = 0;
		}

		for (i = 0; i < num_ops; i++) {
			struct dce_op_fd_pair_rx *op = &ops[i];
			int ret;

			debug(5, "frame dq %u has status 0x%x, %s, input was %u bytes, of which %zu bytes were consumed, output buffer is %u\n",
					atomic_read(&context->dq), op->status,
					dce_status_string(op->status),
					dpaa2_fd_get_len(&op->input_fd),
					op->input_consumed,
					dpaa2_fd_get_len(&op->output_fd));
			/* The input_fd frc is not used by DCE, We get it here
			 * as a token and check it for sanity
			 */
			/*if (dpaa2_fd_get_frc(&op->input_fd) != atomic_read(&context->dq)) {
				debug(0, "Dequeueing frames out of order. Expected %u and read %u\n",
					atomic_read(&context->dq),
					dpaa2_fd_get_frc(&op->input_fd));
				assert(dpaa2_fd_get_frc(
						&op->input_fd) == atomic_read(&context->dq));
			}*/

			switch (op->status) {
				struct dce_op_fd_pair_tx recycle_op;
			case STREAM_END:
				/* We only write up to the end of the first file
				 * we process, then stop writing the file
				 */
				if (out_stream) {
					ret = fwrite((void *)dpaa2_fd_get_addr(
						&op->output_fd),
						1 /* Unit size is 1 byte */,
						dpaa2_fd_get_len(&op->output_fd),
						out_stream);
					if (ret != (int)dpaa2_fd_get_len(&op->output_fd)
						|| ferror(out_stream)) {
						debug(0, "ERROR: failed to write output to file because %s\n",
							strerror(errno));
						fclose(out_stream);
					}
					if (fclose(out_stream))
						debug(0, "ERROR on closing output file\n");
					out_stream = NULL;
				}
				context->total_in +=
					dpaa2_fd_get_len(&op->input_fd);
				context->total_out +=
					dpaa2_fd_get_len(&op->output_fd);
				if (context->synchronous)
					/* Signal enqueuer dequeue is done */
					sem_post(&context->sync_sem);
				break;
			case FULLY_PROCESSED:
				if (out_stream) {
					ret = fwrite((void *)dpaa2_fd_get_addr(
						&op->output_fd),
						1 /* Unit size is 1 byte */,
						dpaa2_fd_get_len(&op->output_fd),
						out_stream);
					if (ret != (int)dpaa2_fd_get_len(
						&op->output_fd)
						|| ferror(out_stream)) {
						debug(0, "ERROR: failed to write output to file because %s\n",
							strerror(errno));
						fclose(out_stream);
						out_stream = NULL;
					}
				}
				context->total_in +=
					dpaa2_fd_get_len(&op->input_fd);
				context->total_out +=
					dpaa2_fd_get_len(&op->output_fd);
				if (context->synchronous)
					/* Signal enqueuer that dequeue is done */
					sem_post(&context->sync_sem);
				break;
			case MEMBER_END_SUSPEND:
			case OUTPUT_BLOCKED_SUSPEND:
				debug(0, "Output choked on frame %u because the out buffer was too small. Enqueuer is blocked at %u\n",
						atomic_read(&context->dq), atomic_read(&context->eq));
				if (out_stream) {
					ret = fwrite((void *)dpaa2_fd_get_addr(&op->output_fd),
						1 /* Unit size is 1 byte */,
						dpaa2_fd_get_len(&op->output_fd),
						out_stream);
					if (ret != (int)dpaa2_fd_get_len(&op->output_fd)
						|| ferror(out_stream)) {
						debug(0, "ERROR: failed to write output to file\n");
						fclose(out_stream);
						out_stream = NULL;
					}
				}

				context->total_in += op->input_consumed;
				context->total_out +=
					dpaa2_fd_get_len(&op->output_fd);

				/* If we are doing compression only then we can
				 * use stream_abort() and then the recycle frame
				 * will be considered the start of a new stream.
				 * In decompression, the stream head cannot be
				 * arbitrarily chosen in the middle of a data
				 * stream, the DCE expects specially formatted
				 * headers and will return an error if we
				 * abandon a choke frame and pretend the next
				 * frame is a start of a new stream. Unless we
				 * are very lucky and it so happens that the
				 * processing of the data stopped right on the
				 * boundary between streams */
				if (context->stream_suspend_policy == CONTINUE)
					lane_stream_continue(context->lane);
				else
					lane_stream_abort(context->lane);

				if (context->skipped_frames_policy == DISCARD) {
					ret = lane_recycle_discard(context->lane);
					debug(5, "Discard frame %u. Will not attempt to reprocess\n",
						atomic_read(&context->dq));
					if (ret == 1)
						debug(0, "Exited suspend by discard at frame %u\n",
						     atomic_read(&context->eq));
					if (ret == 1 && context->suspend_sleep)
						/* lane is out of suspend */
						wake_up(
						   &context->recycle_finished);
					break;
				}

				recycle_op.input_fd = &op->input_fd;
				recycle_op.output_fd = &op->output_fd;
				recycle_op.flush = op->flush;
				recycle_op.user_context = context;

				/* Update the input address to the first
				 * unprocessed byte */
				dpaa2_fd_set_addr(recycle_op.input_fd,
					op->input_consumed
					+ dpaa2_fd_get_addr(&op->input_fd));

				/* Update the input length to reflect the bytes
				 * that have already processed */
				dpaa2_fd_set_len(recycle_op.input_fd,
					dpaa2_fd_get_len(&op->input_fd)
					- op->input_consumed);

				/* Update the output length to accommodate the
				 * extra data that did not fit. Note that
				 * This suspend was triggered intentionally by
				 * setting the buffer length shorter than what
				 * it actually is. The remedy here is to simply
				 * update the output buffer so it accommodates
				 * the extra output. A real life application
				 * will first have to copy out the produced data
				 * and then maybe allocate a larger buffer or
				 * reuses the same buffer with its size
				 * unchanged */
				dpaa2_fd_set_len(recycle_op.output_fd,
					(100 + dpaa2_fd_get_len(&op->output_fd))
					* 30 * max_decomp_ratio);
				assert(dpaa2_fd_get_len(recycle_op.output_fd));

				/* Ensure the context->eq is reread from mem */
				asm volatile("dmb st" : : : "memory");

				/* The input_fd frc is not used by DCE, We set
				 * it here as a token and read it on the other
				 * side to ensure order */
				dpaa2_fd_set_frc(recycle_op.input_fd,
						atomic_read(&context->eq));

				while ((ret = lane_recycle_fd_pair(context->swp,
					context->lane, &recycle_op))) {
					if (ret != -EBUSY)
						break;
				}
				atomic_inc(&context->eq);
				assert(ret >= 0);
				debug(5, "frame %u flush %s, input %u bytes, output %u bytes\n",
					atomic_read(&context->eq),
					recycle_op.flush == DCE_Z_FINISH ? "Z_FINISH" :
					recycle_op.flush == DCE_Z_NO_FLUSH ? "Z_NO_FLUSH" :
									"UNKNOWN",
					dpaa2_fd_get_len(recycle_op.input_fd),
					dpaa2_fd_get_len(recycle_op.output_fd));
				if (ret == 1)
					debug(0, "Exited suspend by recycle at frame %u\n",
						atomic_read(&context->eq));
				if (ret == 1 && context->suspend_sleep)
					/* The lane is out of suspend */
					wake_up(&context->recycle_finished);
				break;
			case SKIPPED:
				debug(1, "frame %u returned as is because the lane is suspended\n",
						atomic_read(&context->dq));

				if (context->skipped_frames_policy == DISCARD) {
					ret = lane_recycle_discard(context->lane);
					debug(5, "Discard frame %u. Will not attempt to reprocess\n",
						atomic_read(&context->dq));
					if (ret == 1)
						debug(0, "Exited suspend by discard at frame %u\n",
						     atomic_read(&context->eq));
					if (ret == 1 && context->suspend_sleep)
						/* lane is out of suspend */
						wake_up(
						   &context->recycle_finished);
					break;
				}

				recycle_op.input_fd = &op->input_fd;
				recycle_op.output_fd = &op->output_fd;
				recycle_op.flush = op->flush;
				recycle_op.user_context = context;

				/* Ensure the context->eq is reread from mem */
				asm volatile("dmb st" : : : "memory");

				/* The input_fd frc is not used by DCE, We set
				 * it here as a token and read it on the other
				 * side to ensure order */
				dpaa2_fd_set_frc(recycle_op.input_fd,
						atomic_read(&context->eq));

				while ((ret = lane_recycle_fd_pair(context->swp,
					context->lane, &recycle_op))) {
					if (ret != -EBUSY)
						break;
				}
				atomic_inc(&context->eq);
				assert(ret >= 0);
				debug(5, "frame %u flush %s, input %u bytes, output buffer %u bytes\n",
					atomic_read(&context->eq),
					recycle_op.flush == DCE_Z_FINISH ? "Z_FINISH" :
					recycle_op.flush == DCE_Z_NO_FLUSH ? "Z_NO_FLUSH" :
									"UNKNOWN",
					dpaa2_fd_get_len(recycle_op.input_fd),
					dpaa2_fd_get_len(recycle_op.output_fd));
				if (ret == 1)
					debug(0, "Exited recycle at frame %u\n",
						atomic_read(&context->eq));
				if (ret == 1 && context->suspend_sleep) {
					/* The lane is out of suspend */
					wake_up(&context->recycle_finished);
				}
				break;
			default:
				if (context->suspend_sleep)
					/* should not be here unless in async */
					sem_post(&context->recycle_finished);
				else if (context->synchronous)
					/* Signal enqueuer that dequeue done */
					sem_post(&context->sync_sem);
				if (!context->stop) {
					/* Thread stopped due to previous status */
					context->status = op->status;
					context->stop = true;
				}
			}
			atomic_inc(&context->dq);
		}
	}
	if (out_stream)
		/* Got stop signal before finishing the file */
		if (fclose(out_stream))
			debug(0, "ERROR on closing output file\n");
	return NULL; /* Thread exit */
}

#define wait_event(x, c) \
		do { \
			sem_wait(x); \
			assert(c); \
		} while (0)

static void *worker_func(void *__context)
{
	struct work_context *context = __context;
	pthread_t dequeuer;
	char thread_name[16];
	void *output;
	size_t output_sz;
	struct dpaa2_fd empty_fd = {.words = {0, 0, 0, 0, 0, 0, 0, 0} };
	struct dpaa2_fd input_fd = empty_fd, output_fd = empty_fd;
	struct dpaa2_fd too_small_output_fd = empty_fd;
	struct chunk *chunk;
	int ret;
	uint32_t frame_count = 0, tx_max = 0,
		 rx_max = 0, tx_min = UINT32_MAX, rx_min = UINT32_MAX, tx_avg = 0,
		 rx_avg = 0, reads = 0;

	snprintf(thread_name, sizeof(thread_name), "%d_eq", context->idx);
	pthread_setname_np(context->pid, thread_name);
	debug(3, "Worker %d at start line\n", context->idx);
	debug(1, "Running on core %d\n", sched_getcpu());

	context->mem = malloc(sizeof(*context->mem));
	assert(context->mem);
	context->mem->sz = (2 * chunk_size * max_decomp_ratio + 0x1000) &
								0xFFFFF000;
	context->mem->addr = vfio_setup_dma(context->mem->sz);
	if (!context->mem->addr) {
		ret = -ENOMEM;
		exit(EXIT_FAILURE);
	}
	dma_mem_allocator_init(context->mem);

	output_sz = chunk_size * max_decomp_ratio;
	output = dma_mem_memalign(context->mem, 0 /* Alignment */, output_sz);
	if (!output) {
		pr_err("Unable to allocate dma memory for DCE\n");
		exit(EXIT_FAILURE);
	}
	dpaa2_fd_set_addr(&output_fd, (dma_addr_t)output);
	dpaa2_fd_set_len(&output_fd, output_sz);

	/* We use this frame to trigger OUTPUT_BLOCKED_SUSPEND */
	too_small_output_fd = output_fd;
	dpaa2_fd_set_len(&too_small_output_fd,
			(chunk_size / max_decomp_ratio) > min_output_buf ?
			chunk_size / max_decomp_ratio : min_output_buf);
	assert(dpaa2_fd_get_len(&too_small_output_fd));
	if (context->recycle_interval)
		debug(0, "The choke output buffer length is %"PRIu32"\n",
			dpaa2_fd_get_len(&too_small_output_fd));

	context->total_in = 0;
	context->total_out = 0;

	if (context->synchronous)
		sem_init(&context->sync_sem,
			0 /* Semaphore shared within process */,
			1 /* Allow only one enqueueing user */);

	sem_init(&context->recycle_finished,
			0 /* Semaphore shared within process only */,
			0 /* Semaphore start value */);

	/* create dequeue worker */
	pthread_attr_t thread_attr;
	int i;
	cpu_set_t cpu;
	CPU_ZERO(&cpu);
	/*for (i = 0; i < get_nprocs(); i++)
		CPU_SET(i, &cpu);*/
	pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu);
	for (i = 0; i < get_nprocs(); i++) {
		if (CPU_ISSET(i, &cpu)) {
			CPU_ZERO(&cpu);
			if (i % 2)
				CPU_SET(i - 1, &cpu);
			else
				CPU_SET(i + 1, &cpu);
			break;
		}
	}
	assert(CPU_COUNT(&cpu) == 1); /* Should be affine to a single cpu */

	pthread_attr_init(&thread_attr);
	/* We inherit the enqueuer affinity by default in phtread_create() the
	 * work done below removes the affinity mask of the enqueuer thread to
	 * allow the enqueuer and consumer threads to work side by side  */
	pthread_attr_setaffinity_np(&thread_attr, sizeof(cpu_set_t), &cpu);
	pthread_create(&dequeuer, &thread_attr, worker_dq, context);

	sync_all(); /* Wait at the start line */

	chunk = list_entry(context->chunk_list->next, typeof(*chunk), node);
	while (1) {
		struct dce_op_fd_pair_tx op;
		bool last_chunk = chunk->node.next == context->chunk_list;

		dpaa2_fd_set_addr(&input_fd, chunk->addr);
		dpaa2_fd_set_len(&input_fd, chunk->size);
		op.input_fd = &input_fd;
		/* Recycle mode testing */
		if (context->recycle_interval) {
			op.output_fd = (atomic_read(&context->eq) + 1) % context->recycle_interval ?
						&output_fd : &too_small_output_fd;
			if (op.output_fd == &too_small_output_fd)
				debug(1, "Using %u output length to attempt to trigger OUTPUT_BLOCKED_SUSPEND\n",
						dpaa2_fd_get_len(op.output_fd));
		}
		else
			op.output_fd = &output_fd;
		dpaa2_fd_set_addr(&output_fd, chunk->out_addr);
		dpaa2_fd_set_len(&output_fd, chunk->out_size);
		op.flush  = last_chunk ? DCE_Z_FINISH : DCE_Z_NO_FLUSH;
		op.user_context = context;

		if (context->synchronous)
			/* Send one frame at a time in synchronous mode. the
			 * dequeuer frees it */
			sem_wait(&context->sync_sem);

		/* The input_fd frc is not used by DCE, We set it here as a
		 * token and read it on the other side to ensure order. This set
		 * is done HERE and not before the sem_wait because the lane
		 * may go into recycle. In which case the context->eq will be
		 * incremented by the dequeuer while recycling rejected frames.
		 * This race only occurs in synchronous mode, since in async
		 * mode the enqueuer goes to sleep waiting on the recycle
		 * semaphore and the loop logic rereads the context->eq */
		dpaa2_fd_set_frc(&input_fd, atomic_read(&context->eq));

		ret = lane_enqueue_fd_pair(context->swp, context->lane, &op);
		if (ret == -EBUSY) {
			printf("WE ARE GETTING EBUSY!!!\n");
			msleep(1); /* Give DCE a breather */
			continue;
		} else if (ret == -EACCES) {
			debug(1, "Enqueuer sees that lane is in suspend. Sleeping until the lane is recovered\n");
			/* -EACCES means that the lane has entered recycle
			 * state. This usually happens if the output buffer was
			 * insufficient to hold all output. We will wait for the
			 * dequeue loop to resolve the issue and signal us to
			 * continue work
			 */
			context->suspend_sleep = true;
			sem_wait(&context->recycle_finished);
			context->suspend_sleep = false;
			debug(1, "Enqueuer waking up because dequeuer signaled us that recycle is done\n");
			if (context->skipped_frames_policy == DISCARD &&
				context->engine == DPDCEI_ENGINE_DECOMPRESSION)
				/* Reset the chunk pointer to the first chunk of
				 * the file for decompression if the user picked
				 * discard mode. This is necessary in
				 * decompression, because decompression relies
				 * on previous context to continue decompression
				 * and it will almost always fail if a portion
				 * of a stream is discarded before continuing
				 * processing afterwards */
				chunk = list_entry(context->chunk_list->next,
					typeof(*chunk), node);
			continue;
		} else if (ret) {
			pr_err("Error on enqueue %d\n", ret);
			context->ret = ret;
			pthread_exit(NULL);
		}
		atomic_inc(&context->eq);

		debug(5, "frame %u has initial %s, flush %s, input %u bytes, output buffer %u bytes\n",
			atomic_read(&context->eq),
			chunk->node.prev == context->chunk_list ?
				"true" : "false",
			last_chunk ? "Z_FINISH" : "Z_NO_FLUSH",
			dpaa2_fd_get_len(&input_fd),
			dpaa2_fd_get_len(&output_fd));

		int flow_max = 1000;

		if (atomic_read(&context->eq) > atomic_read(&context->dq) + flow_max) {
			bool sampled = false;

			do  {
				if (!sampled) {
					sampled = true;
					frame_count = dpdcei_todo_queue_count(
							context->swp,
							context->dpdcei);

					if (tx_max < frame_count)
						tx_max = frame_count;
					if (tx_min > frame_count)
						tx_min = frame_count;
					tx_avg = ((reads * tx_avg)
							+ frame_count) /
							(reads + 1);
					frame_count = dpdcei_done_queue_count(
							context->swp,
							context->dpdcei);
					if (rx_max < frame_count)
						rx_max = frame_count;
					if (rx_min > frame_count)
						rx_min = frame_count;
					rx_avg = ((reads * rx_avg) + frame_count) / (reads + 1);
					reads++;
				}
				usleep(100);
				if (atomic_read(&context->dq) == atomic_read(&context->eq))
					debug(1, "DCE all caught up! Send work faster!\n");
			} while (atomic_read(&context->eq) > atomic_read(&context->dq) + 300);
		}

		if (context->stop) {

			context->dequeue_stop = true;
			debug(0, "Done work. Waiting for %d outstanding work requests before exit\n",
					atomic_read(&context->eq) - atomic_read(&context->dq));
			pthread_join(dequeuer, NULL /* no need retval */);
			assert(atomic_read(&context->eq) == atomic_read(&context->dq));
			context->end_time = read_cntvct();
			debug(0, "tx_max = %u rx_max = %u tx_min = %u rx_min = %u tx_avg = %u rx_avg = %u enqueuer got ahead %u times.\n",
					tx_max, rx_max, tx_min, rx_min, tx_avg,
					rx_avg, reads);
			if (context->status == OUTPUT_BLOCKED_DISCARD) {
				debug(0, "The output buffer supplied was too small\n");
			} else if (context->status == OUTPUT_BLOCKED_SUSPEND) {
				debug(0, "The output buffer supplied was too small\n");
			} else if (context->status == INPUT_STARVED) {
				debug(0, "Z_FINISH too early? Attempted to decompress a fraction of a DEFLATE stream\n");
			} else if (context->status != STREAM_END &&
					context->status != FULLY_PROCESSED) {
				debug(0, "Unexpected DCE status %s 0x%x\n",
				dce_status_string(context->status),
				context->status);
			}
			break;
		}

		chunk = list_entry(chunk->node.next, typeof(*chunk), node);
		if (last_chunk)
			chunk = list_entry(context->chunk_list->next,
					typeof(*chunk), node);
	}
	debug(0, "Bytes processed = %zu, Bytes produced = %zu\n",
			context->total_in, context->total_out);
	return NULL; /* Thread exit */
}

/* Barrier used by tests running across all threads */
static pthread_barrier_t barr;

static void sync_all(void)
{
	pthread_barrier_wait(&barr);
}

static void *dma_allocator(void *opaque, size_t align, size_t size)
{
	return dma_mem_memalign(opaque, align, size);
}

static void dma_freer(void *opaque, void *addr)
{
	dma_mem_free(opaque, addr);
}

static const char STR_help[] = "--help";
static const char STR_in[] = "--in=";
static const char STR_out[] = "--out=";
static const char STR_paradigm[] = "--paradigm=";
static const char STR_format[] = "--format=";
static const char STR_chunk_size[] = "--chunk-size=";
static const char STR_time[] = "--time=";
static const char STR_resources[] = "--resources";
static const char STR_decomp_ratio[] = "--decomp-ratio=";
static const char STR_recycle[] = "--recycle=";
static const char STR_sync[] = "--synchronous";
static const char STR_suspend_policy[] = "--suspend-policy=";
static const char STR_skip_policy[] = "--skip-policy=";
static const char STR_debug[] = "-d";

static const char STR_usage[] =
"dce-api-perf-test measures throughput of DCE under conditions supplied to test\n"
"\n"
"Usage:\n"
"    dce-api-perf-test [options]\n"
"Options:\n"
"    --in=<path>     Path to input file\n"
"    --out=<path>    Path to output file. Must be used with --synchronous. Impacts throughput \n"
"    --paradigm=<paradigm>   stateful-recycle, stateless \n"
"    --resources <dprc.id> <dpio.id> <dpdcei.id> <threads> <num> [dpdcei.id <threads> <num>] ... [dpio.id <dpdcei.id> ...] \n"
"    --format=<format>   raw, zlib, gzip \n"
"    --synchronous   Send only one operation per thread at a time. Impacts throughput\n"
"    --chunk-size=<size> Chunk size to send to DCE per operation\n"
"    --time=<time-in-sec> Run the test for given number of seconds\n"
"    --suspend-policy=<policy>   continue, abort\n"
"                                Continue or abort streams when suspended. Only valid if paradigm=stateful-recycle\n"
"                                `continue' logical stream i.e. file\n"
"                                `abort' discard stream history and treat next data as a new stream\n"
"                                NOTE: Stream history is needed for decompression in most cases\n"
"    --skip-policy=<policy>  recycle, discard\n"
"                            `recycle' or `discard' work that was previously skipped due to a suspend. Only valid if paradigm=stateful-recycle\n"
"                            NOTE: discard should be used when suspend-policy is abort and the test is doing decompression.\n"
"                            Otherwise application will attempt to start decompression in the middle of a file. Likely result in a header error\n"
"                            NOTE: Data integrity is maintained only when suspend-policy=continue and skip-policy=continue\n"
"    --decomp-ratio=<inflate-ratio> Output buffers will be <inflate-ratio> times the input buffer size\n"
"				    Use This option if `The output buffer supplied was too small' error report is observed\n"
"    -d [debug_level] debug prints based on level where -d 1 is the lowest\n"
"    --help          see this message\n";

static void usage(void)
{
	pr_info(STR_usage);
}

#define NEXT_ARG() (argv++, --argc)

int main(int argc, char *argv[])
{
	FILE *input_file = NULL;
	const char *out_file_name = NULL;
	unsigned int max_in_flight = 10000;
	bool synchronous_mode = false; /* asynchronous by default */
	enum suspend_policy suspend_policy = CONTINUE; /* Continue by default */
	enum skip_policy skip_policy = RECYCLE; /* recycle by default */
	unsigned int recycle_interval = 0; /* No recycle by default */
	size_t file_size;
	unsigned int num_chunks = 0;
	unsigned int num_threads = 0;
	LIST_HEAD(chunk_list);
	struct chunk *chunk, *t_chunk;
	uint64_t start, end, run_time, test_time_us, cpufreq = 1400000000;
	uint64_t total_total_in = 0, total_total_out = 0, Mbps = 0;
	struct work_context *contexts;
	char *endptr;
	struct dma_mem dce_mem;
	enum lane_paradigm paradigm = DCE_STATEFUL_RECYCLE;
	enum lane_compression_format format = DCE_CF_GZIP;
	unsigned int test_time = 2; /* 2 seconds by default */

	struct fsl_mc_io *mc_io;
	uint16_t dprc_token;
	int dprc_id;
	char dprc_id_str[50];
	LIST_HEAD(swp_list);
	struct swp_context *swp_context;
	int i, ret;

	/* process command line args */
	while (NEXT_ARG()) {
		if (!strncmp(*argv, STR_help, strlen(STR_help))) {
			usage();
			exit(EXIT_SUCCESS);
		} else if (!strncmp(*argv, STR_in, strlen(STR_in))) {
			input_file = fopen(&(*argv)[strlen(STR_in)], "r");
			if (!input_file) {
				pr_err("Unable to open input file %s\n",
						&(*argv)[strlen(STR_in)]);
				exit(EXIT_FAILURE);
			}
		} else if (!strncmp(*argv, STR_out, strlen(STR_out))) {
			out_file_name = (&(*argv)[strlen(STR_out)]);
			if (strlen(out_file_name) <= 0) {
				pr_err("Bad output file name\n");
				exit(EXIT_FAILURE);
			}
		} else if (!strncmp(*argv, STR_paradigm, strlen(STR_paradigm))) {
			if (!strncmp(&(*argv)[strlen(STR_paradigm)], "stateful-recycle",
						strlen("stateful-recycle")))
				paradigm = DCE_STATEFUL_RECYCLE;
			else if (!strncmp(&(*argv)[strlen(STR_paradigm)], "stateless",
						strlen("stateless")))
				paradigm = DCE_STATELESS;
			else {
				pr_err("Unexpected paradigm parameter\n");
				exit(EXIT_FAILURE);
			}
		} else if (!strncmp(*argv, STR_format, strlen(STR_format))) {
			if (!strncmp(&(*argv)[strlen(STR_format)], "raw",
						strlen("raw")))
				format = DCE_CF_DEFLATE;
			else if (!strncmp(&(*argv)[strlen(STR_format)], "zlib",
						strlen("zlib")))
				format = DCE_CF_ZLIB;
			else if (!strncmp(&(*argv)[strlen(STR_format)], "gzip",
						strlen("gzip")))
				format = DCE_CF_GZIP;
			else {
				pr_err("Unexpected format parameter\n");
				exit(EXIT_FAILURE);
			}
		} else if (!strncmp(*argv, STR_chunk_size,
					strlen(STR_chunk_size))) {
			chunk_size = get_ularg(&(*argv)[strlen(STR_chunk_size)],
						STR_chunk_size);
		} else if (!strncmp(*argv, STR_recycle,
					strlen(STR_recycle))) {
			recycle_interval = get_ularg(&(*argv)[strlen(STR_recycle)],
						STR_recycle);
			pr_info("********RECYCLE MODE ENABLED********\n"
				"Test will attempt to force recycle every %u frames by making the output buffer very small\n",
				recycle_interval);
		} else if (!strncmp(*argv, STR_time,
					strlen(STR_time))) {
			test_time = get_ularg(&(*argv)[strlen(STR_time)],
						STR_time);
		} else if (!strncmp(*argv, STR_decomp_ratio,
					strlen(STR_decomp_ratio))) {
			max_decomp_ratio = get_ularg(&(*argv)[strlen(STR_decomp_ratio)],
						STR_decomp_ratio);
		} else if (!strncmp(*argv, STR_resources,
						strlen(STR_resources))) {
			if (NEXT_ARG()) {
				if (!strncmp(*argv, "dprc.", strlen("dprc."))) {
					dprc_id = strtoul(&(*argv)[strlen("dprc.")],
							&endptr,
							10 /* base 10 */);
					while (NEXT_ARG()) {
						if (!strncmp(*argv, "dpio.", strlen("dpio."))) {
							swp_context = malloc(sizeof(*swp_context));
							assert(swp_context);
							memset(swp_context, 0, sizeof(*swp_context));
							swp_context->id = strtoul(&(*argv)[strlen("dpio.")],
									&endptr,
									10 /* base 10 */);
							INIT_LIST_HEAD(&swp_context->dpdcei_list);
							while (NEXT_ARG()) {
								if (!strncmp(*argv, "dpdcei.", strlen("dpdcei."))) {
									struct dpdcei_context *dpdcei_context = malloc(sizeof(*dpdcei_context));

									assert(dpdcei_context);
									memset(dpdcei_context, 0, sizeof(*dpdcei_context));
									dpdcei_context->id = strtoul(&(*argv)[strlen("dpdcei.")],
											&endptr,
											10 /* base 10 */);

									if (NEXT_ARG()) {
										if (!strncmp(*argv, "threads", strlen("threads"))) {
											if (NEXT_ARG()) {
												dpdcei_context->num_workers = strtoul(*argv,
													&endptr,
													10 /* base 10 */);
												if (dpdcei_context->num_workers == 0) {
													pr_err("Number of threads cannot be 0\n");
													exit(EXIT_FAILURE);
												}
												num_threads += dpdcei_context->num_workers;
												INIT_LIST_HEAD(&dpdcei_context->worker_list);
											} else {
												pr_err("Must specify the number of threads\n");
												exit(EXIT_FAILURE);
											}
										} else {
											pr_err("Must specify threads\n");
											exit(EXIT_FAILURE);
										}
									} else {
										pr_err("Must specify threads\n");
										exit(EXIT_FAILURE);
									}
									list_add_tail(&dpdcei_context->node, &swp_context->dpdcei_list);
								} else {
									argv--; argc++;
									break;
								}
							}
							if (list_empty(&swp_context->dpdcei_list)) {
								pr_err("Must specify dpdcei objects operating in this dpio\n");
								exit(EXIT_FAILURE);
							}
							list_add_tail(&swp_context->node, &swp_list);
							if (argc < 1) {
								argv--; argc++;
							}
						} else {
							argv--; argc++;
							break;
						}
					}
					if (list_empty(&swp_list)) {
						pr_err("Must specify dpio objects to use\n");
						exit(EXIT_FAILURE);
					}
					if (argc < 1) {
						argv--; argc++;
					}
				} else {
					pr_err("Must specify dprc\n");
					exit(EXIT_FAILURE);
				}
				if (argc < 1) {
					argv--; argc++;
				}
			} else {
				pr_err("No resources specified\n");
				exit(EXIT_FAILURE);
			}
			if (argc < 1) {
				argv--; argc++;
			}
		} else if (!strncmp(*argv, STR_debug, strlen(STR_debug))) {
			if (NEXT_ARG()) {
				dbg_lvl = strtoul(*argv, &endptr,
					0 /*AUTO_DETECT_BASE*/);
				if (dbg_lvl == 0 && endptr == *argv) {
					dbg_lvl = 1;
					argv--; argc++;
				}
			} else {
				/* add 1 to argc to prevent while loop from
				 * getting -1  if this was the last arg */
				argc++;
				dbg_lvl = 1;
			}
		} else if (!strncmp(*argv, STR_sync, strlen(STR_sync))) {
			synchronous_mode = true;
		} else if (!strncmp(*argv, STR_suspend_policy, strlen(STR_suspend_policy))) {
			if (!strncmp(&(*argv)[strlen(STR_suspend_policy)], "continue",
						strlen("continue"))) {
				suspend_policy = CONTINUE;
			} else if (!strncmp(&(*argv)[strlen(STR_suspend_policy)], "abort",
						strlen("abort"))) {
				suspend_policy = ABORT;
				pr_info("********ABORT MODE ENABLED********\n"
					"Test will abort mid stream if a suspend occurs. Data produced will not be decompressable\n"
					"Decompressed data will not correspond to the original input\n");
			} else {
				pr_err("Unexpected suspend policy parameter\n");
				exit(EXIT_FAILURE);
			}
		} else if (!strncmp(*argv, STR_skip_policy, strlen(STR_skip_policy))) {
			if (!strncmp(&(*argv)[strlen(STR_skip_policy)], "recycle",
						strlen("recycle"))) {
				skip_policy = RECYCLE;
			} else if (!strncmp(&(*argv)[strlen(STR_skip_policy)], "discard",
						strlen("discard"))) {
				pr_info("********DISCARD MODE ENABLED********\n"
					"ALL skipped frames will be discarded instead of resent back for processing\n");
				skip_policy = DISCARD;
			} else {
				pr_err("Unexpected skip policy parameter\n");
				exit(EXIT_FAILURE);
			}

		} else {
			pr_err("Unrecognised argument '%s'\n"
				"use --help to see usage \n", *argv);
			exit(EXIT_FAILURE);
		}

		if (bad_parse) {
			pr_err("Bad option argument. Use --help to see usage\n");
			exit(EXIT_FAILURE);
		}
	}

	if (list_empty(&swp_list)) {
		pr_err("Must provide dprc, dpio, and dpdcei resources for test\n");
		exit(EXIT_FAILURE);
	}

	/*if (out_file_name && !synchronous_mode) {
		pr_err("--out=<path> must be used with --synchronous\n");
		exit(EXIT_FAILURE);
	}*/
	if (suspend_policy == ABORT && paradigm == DCE_STATELESS) {
		pr_err("suspend-policy=abort must be used with --paradigm=stateful-recycle\n");
		exit(EXIT_FAILURE);
	}
	if (suspend_policy == ABORT && skip_policy == RECYCLE)
		pr_info("NOTE: suspend policy is set to abort and skip policy is set to recycle\n"
			"This combination will resend skipped frames to DCE *AFTER* destroying all previous context\n"
			"This will almost always fail in decompression, because decompression depends on previous output\n");

	/* Setup MC resources */
	mc_io = malloc(sizeof(struct fsl_mc_io));
	if (!mc_io) {
		pr_err("Unable to malloc memory for mc handle\n");
		exit(EXIT_FAILURE);
	}

	ret = mc_io_init(mc_io);
	if (ret) {
		free(mc_io);
		pr_err("mc_io_init() returns error %d\n", ret);
		exit(EXIT_FAILURE);
	}

	sprintf(dprc_id_str, "dprc.%i", dprc_id);

	ret = dprc_open(mc_io, 0, 1 /* ROOT DPRC ID */, &dprc_token);
	if (ret) {
		pr_err("%d from dprc_open() failed in %s\n", ret, __func__);
		exit(EXIT_FAILURE);
	}

	uint16_t root_token = dprc_token;

	ret = dprc_open(mc_io, 0, dprc_id, &dprc_token);
	if (ret) {
		pr_err("%d from dprc_open() failed in %s\n", ret, __func__);
		exit(EXIT_FAILURE);
	}

	ret = vfio_setup(dprc_id_str);
	if (ret){
		pr_err("vfio_setup() failed\n");
		exit(EXIT_FAILURE);
	}

	dprc_close(mc_io, 0, dprc_token);
	dprc_close(mc_io, 0, root_token);

	if (input_file) {
		fseek(input_file, 0L, SEEK_END);
		file_size = ftell(input_file);
		rewind(input_file);
	} else {
		file_size = 0xFFF000;
	}
	/* vfio_setup_dma() must be called after vfio_setup() is called */
	dce_mem.sz = (file_size + 0xFFFF000) & 0xFFFFFFFFFFFF000;
	dce_mem.addr = vfio_setup_dma(dce_mem.sz);
	if (!dce_mem.addr) {
		ret = -ENOMEM;
		exit(EXIT_FAILURE);
	}
	dma_mem_allocator_init(&dce_mem);

	/* Check cycle counter sanity */
	start = read_cntvct();
	usleep(50000);
	end = read_cntvct();
	cpufreq = (end - start) * 20;

	debug(1, "Number of testing threads %u\n", num_threads);
	debug(2, "Initialize barrier for sync_all()\n");
	/* num_threads + main thread all block on thread barrier */
	ret = pthread_barrier_init(&barr, NULL, num_threads + 1);
	if (ret != 0) {
		fprintf(stderr, "Failed to init barrier\n");
		goto fail_multi_thread;
	}

	debug(1, "Create the threads\n");
	contexts = malloc(num_threads * sizeof(struct work_context));
	if (!contexts) {
		ret = -1;
		pr_err("Failed to alloc memory for thread args\n");
		goto fail_contexts_alloc;
	}
	memset(contexts, 0, num_threads * sizeof(struct work_context));

	i = 0;
	int cpu_count = 0;
	list_for_each_entry(swp_context, &swp_list, node) {
		struct dpdcei_context *dpdcei_context;

		swp_context->swp = dce_helper_swp_init(swp_context->id);
		if (!swp_context->swp) {
			pr_err("dpio setup failed\n");
			exit(EXIT_FAILURE);
		}

		list_for_each_entry(dpdcei_context, &swp_context->dpdcei_list,
					node) {
			int j;
			struct dce_dpdcei_params dpdcei_params;
			struct dpdcei_lane_params lane_params;

			dpdcei_params = (struct dce_dpdcei_params) {
					.dpdcei_id = dpdcei_context->id,
					.mcp = mc_io,
					.dma_alloc = dma_allocator,
					.dma_free = dma_freer,
					.dma_opaque = &dce_mem,
					};

			dpdcei_context->dpdcei =
				dce_dpdcei_activate(&dpdcei_params);
			if (!dpdcei_context->dpdcei) {
				pr_err("dpdcei setup failed\n");
				exit(EXIT_FAILURE);
			}

			lane_params = (struct dpdcei_lane_params){
				.swp = swp_context->swp,
				.dpdcei = dpdcei_context->dpdcei,
				.paradigm = paradigm,
				.compression_format = format,
				.compression_effort =
					DCE_CE_BEST_POSSIBLE,
				.dma_alloc = dma_allocator,
				.dma_free = dma_freer,
				.dma_opaque = &dce_mem,
				.max_in_flight = max_in_flight,
				/* gz_header not used in ZLIB format mode */
				/* buffer_pool_id not used */
				/* buffer_pool_id2 not used */
				/* release_buffers not used */
				/* encode_base_64 not used */
			};

			for (j = 0; j < dpdcei_context->num_workers; j++, i++) {
				pthread_attr_t thread_attr;
				cpu_set_t cpu;
				struct work_context *context = &contexts[i];

				CPU_ZERO(&cpu);
				CPU_SET(0, &cpu);
				ret = pthread_setaffinity_np(pthread_self(),
					sizeof(cpu), &cpu);
				if (ret) {
					pr_err("Failed to affine main thread\n");
					exit(EXIT_FAILURE);
				}

				context->chunk_list = &chunk_list;
				context->out_file = out_file_name;
				context->idx = i;
				context->synchronous = synchronous_mode;
				context->stream_suspend_policy = suspend_policy;
				context->skipped_frames_policy = skip_policy;
				context->recycle_interval = i ? 0 : recycle_interval;
				context->lane =
					dpdcei_lane_create(&lane_params);
				context->dpdcei = dpdcei_context->dpdcei;
				context->engine = !dpdcei_is_compression(
					dpdcei_context->dpdcei);
				context->swp = swp_context->swp;
				if (!context->lane) {
					pr_err("dpdcei_lane_create() failed with %d\n",
							ret);
					exit(EXIT_FAILURE);
				}
				CPU_ZERO(&cpu);
				CPU_SET(cpu_count, &cpu);
				pthread_attr_init(&thread_attr);
				pthread_attr_setaffinity_np(&thread_attr,
						sizeof(cpu_set_t),
						&cpu);

				ret = pthread_create(&contexts[i].pid,&thread_attr,
						worker_func, &contexts[i]);
				if (ret) {
					pr_err("pthread_create failed with ret code %d\n",
							ret);
					goto fail_contexts_alloc;
				}
			}
		}
		/* Each cpu cluster share cache and so we increment two at a
		 * time to lower cache contention */
		cpu_count += 2 % get_nprocs();
	}

	/* Prepare input data list */
	if (input_file) {
		/* Get input data from sample data file */
		uint8_t buf[chunk_size];
		size_t bytes_in;
		bool alloc_for_decomp = false;

		for (i = 0; i < (signed)num_threads; i++) {
			if (contexts[i].engine != DPDCEI_ENGINE_COMPRESSION) {
				alloc_for_decomp = true;
				break;
			}
		}

		while ((bytes_in = fread(buf, 1, chunk_size, input_file)) > 0) {
			struct chunk *new_chunk = malloc(sizeof(struct chunk));
			const size_t out_size = alloc_for_decomp ?
				50 + max_decomp_ratio * chunk_size :
				1000 + chunk_size;

			new_chunk->addr =
			   (dma_addr_t) dma_mem_memalign(&dce_mem, 0, bytes_in);
			if (!new_chunk->addr) {
				pr_err("Unable to allocate dma memory for DCE\n");
				exit(EXIT_FAILURE);
			}
			new_chunk->out_addr =
				(dma_addr_t) dma_mem_memalign(&dce_mem, 0, out_size);
			if (!new_chunk->out_addr) {
				pr_err("Unable to allocate dma memory for DCE\n");
				exit(EXIT_FAILURE);
			}
			new_chunk->out_size = out_size;
			memcpy((void *)new_chunk->addr, buf, bytes_in);
			new_chunk->size = bytes_in;
			list_add_tail(&new_chunk->node, &chunk_list);
			num_chunks++;
		}
		fclose(input_file);
	} else { /* No input file provided, use stock data */
		for (i = 0; i < (signed)num_threads; i++) {
			if (contexts[i].engine != DPDCEI_ENGINE_COMPRESSION) {
				pr_err("Please provide compressed input file to run decompression test\n");
				exit(EXIT_FAILURE);
			}
		}

		if (dce_test_data_size < chunk_size) {
			pr_err("Chunk size passed is not supported with default data file. Please add an input file parameter large enough for the chunk size\n");
			exit(EXIT_FAILURE);
		}

		/* Add chunk if data_len does not divide evenly into chunks */
		num_chunks = (dce_test_data_size / chunk_size) +
			!!(dce_test_data_size % chunk_size);
		for (i = 0; i < (signed)num_chunks; i++) {
			struct chunk *new_chunk = malloc(sizeof(struct chunk));
			/* Make sure to allocate only needed for last chunk */
			new_chunk->size = (i + 1 == (signed)num_chunks) ?
				dce_test_data_size - (i * chunk_size) :
				chunk_size;
			new_chunk->addr = (dma_addr_t)
				dma_mem_memalign(&dce_mem, 0, new_chunk->size);
			if (!new_chunk->addr) {
				pr_err("Unable to allocate dma memory for DCE\n");
				exit(EXIT_FAILURE);
			}
			memcpy((void *)new_chunk->addr,
				&dce_test_data[i * chunk_size],
				new_chunk->size);
			list_add_tail(&new_chunk->node, &chunk_list);
		}
	}


	/* Wait for all threads to sleep on starting line */
	usleep(100000);
	/**********************************************************************/
	/************************** START LINE ********************************/
	debug(1, "Catch their exit\n");
	start = read_cntvct();
	sync_all();

	/* Sleep for required time */
	sleep(test_time);
	for (i = 0; i < (signed)num_threads; i++) {
		contexts[i].stop = true;
	}

	for (i = 0; i < (signed)num_threads; i++) {
		struct work_context *context = &contexts[i];
		unsigned long timeout = 0;

		ret = pthread_join(context->pid, NULL /* no need retval */);
		if (ret) {
			/* Leak, but warn */
			printf("Failed to join thread %d. %s\n", context->idx,
					strerror(ret));
		}
		/* calculate time based on last thread to finish line */
		if (end < context->end_time)
			end = context->end_time;
		if (timeout != 0)
			/* Leak, but warn */
			pr_err("Received signal while waiting for worker %d to finish\n",
					context->idx);
		if (context->ret)
			pr_err("Worker %d finished with error %d\n",
					context->idx, context->ret);
		/*dpdcei_lane_destroy(context->lane);*/
		total_total_in += context->total_in;
		total_total_out += context->total_out;
		if (context->engine == DPDCEI_ENGINE_COMPRESSION)
			Mbps += context->total_in;
		else
			Mbps += context->total_out;

	}
	/************************** FINISH LINE *******************************/
	/**********************************************************************/
	if (end <= start)
		pr_err("Time corruption detected. end = %lu start = %lu\n",
							end, start);
	else
		run_time = end - start;
	test_time_us = (uint64_t) 1000000 * run_time / cpufreq;
#ifdef NOP_TEST
	pr_info("********NOP test*********** No frame data was processed\n");
#endif
	pr_info("Took %lu us to process %zu bytes, and output %zu bytes. Cycles elapsed %lu. Counter frequency is %lu\n",
			test_time_us,
			total_total_in,
			total_total_out,
			run_time,
			cpufreq);

	list_for_each_entry(swp_context, &swp_list, node) {
		struct dpdcei_context *dpdcei_context;

		list_for_each_entry(dpdcei_context, &swp_context->dpdcei_list,
					node)
			dce_dpdcei_deactivate(dpdcei_context->dpdcei);
		dce_helper_swp_finish(swp_context->swp);
	}

	Mbps = Mbps * 8 /* bits per byte */ / test_time_us;

	pr_info("Throughput is %lu Mbps\n", Mbps);

	free(contexts);
fail_contexts_alloc:
	pthread_barrier_destroy(&barr);
fail_multi_thread:
	list_for_each_entry_safe(chunk, t_chunk, &chunk_list, node) {
		list_del(&chunk->node);
		free(chunk);
	}
	return ret;
}
