/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#include <compat.h>
#include <semaphore.h>
#include <fsl_dprc.h>
#include <vfio_utils.h>
#include "../dce.h"
#include "dce-test-data.h"
#include "private.h"

struct chunk {
	dma_addr_t addr;
	size_t size;
	struct list_head node;
};

struct work_context {
	pthread_t pid;
	struct dce_session *session;
	struct list_head *chunk_list;
	const char *out_file;
	unsigned int eq;
	unsigned int dq;
	size_t total_in;
	size_t total_out;
	struct dma_mem *mem;
	enum dce_compression_format comp_format;
	enum dce_status status;
	bool stop;
	bool dequeue_stop;
	uint64_t end_time;
	bool synchronous;
	unsigned int recycle_interval;
	bool recycle_sleep;
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

struct dpio_context {
	struct dpaa2_io *dpio;
	int id;
	uint16_t token;
	/* Keep track of dpdcei objects belonging to this dpio */
	struct list_head dpdcei_list;
	struct list_head node;
};

struct dprc_context {
	int id;
	/* Keep track of dpio objects belonging to this dprc */
	struct list_head dpio_list;
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
size_t max_decomp_ratio = 30; /* default maximum decompression ratio is 30, It
			       * can be changed using a parameter if the input
			       * data expands to more than 30 times the input
			       * size
			       */

static void sync_all(void);

#define wake_up(x) sem_post(x)

static void wake_cb(void *__context)
{
	sem_t *wake_up_handle = __context;

	debug(6, "Got callback successfully\n");
	wake_up(wake_up_handle);
}

static void *worker_dq(void *__context)
{
	struct work_context *context = __context;
	FILE *out_stream = NULL;
	int num_ops, empty_count = 0, i;
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

	while (!context->dequeue_stop || context->eq > context->dq) {
		struct timespec time;
		struct dce_op_fd_pair_rx ops[16];

		num_ops = dce_dequeue_fd_pair(context->session, ops, 16);
		if (!num_ops) {
			empty_count++;
			if (empty_count > 2) {
				dce_session_notification_arm(context->session,
						&work_done_sem);
				if (clock_gettime(CLOCK_REALTIME, &time) == -1)
					exit(EXIT_FAILURE);
				time.tv_sec += 1; /* Wait up to 1 second */
				debug(3, "Dequeuer going to sleep for 1 sec max waiting for frames\n");
				if (sem_timedwait(&work_done_sem, &time)) {
					assert(errno == ETIMEDOUT);
					if (context->eq - context->dq) {
						debug(0, "ERROR: Timed out while waiting for %d dequeues\n",
						     context->eq - context->dq);
						context->stop = true;
						pthread_exit(NULL);
					}
				}
				if (errno != ETIMEDOUT)
					debug(3, "Received signal that frames are available, will go check now\n");
				continue;
			}
		} else {
			empty_count = 0;
		}

		for (i = 0; i < num_ops; i++) {
			struct dce_op_fd_pair_rx *op = &ops[i];
			int ret;

			debug(5, "frame dq %u has status 0x%x, %s, input was %u bytes, of which %zu bytes were consumed, %u bytes of output\n",
					context->dq, op->status,
					dce_status_string(op->status),
					dpaa2_fd_get_len(&op->input_fd),
					op->input_consumed,
					dpaa2_fd_get_len(&op->output_fd));
#ifdef NOP_TEST
			context->total_out += 0;
#else
			context->total_out += dpaa2_fd_get_len(&op->output_fd);
#endif
			/* The input_fd frc is not used by DCE, We get it here
			 * as a token and check it for sanity
			 */
			if (dpaa2_fd_get_frc(&op->input_fd) != context->dq) {
				debug(0, "Dequeueing frames out of order. Expected %u and read %u\n",
					context->dq,
					dpaa2_fd_get_frc(&op->input_fd));
				assert(dpaa2_fd_get_frc(
						&op->input_fd) == context->dq);
			}

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
						debug(0, "ERROR: failed to write output to file\n");
						fclose(out_stream);
					}
					if (fclose(out_stream))
						debug(0, "ERROR on closing output file\n");
					out_stream = NULL;
				}
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
						debug(0, "ERROR: failed to write output to file\n");
						fclose(out_stream);
						out_stream = NULL;
					}
				}
				if (context->synchronous)
					/* Signal enqueuer that dequeue is done */
					sem_post(&context->sync_sem);
				break;
			case MEMBER_END_SUSPEND:
			case OUTPUT_BLOCKED_SUSPEND:

				debug(1, "Output choked on frame %u because the out buffer was too small\n",
						context->dq);
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
				/* We should use stream continue instead of
				 * stream abort, because this application
				 * supports compression and decompression. If we
				 * are doing compression only then we can use
				 * stream_abort() and then the recycle frame
				 * will be considered the start of a new stream.
				 * In decompression, the stream head cannot
				 * arbitrarily chosen in the middle of a data
				 * stream, the DCE expects specially formatted
				 * headers and will return an error if we
				 * abandon a choke frame and pretend the next
				 * frame is a start of a new stream. Unless we
				 * are very lucky and it so happens that the
				 * processing of the data stopped right on the
				 * boundary between streams */
				dce_stream_continue(context->session);

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
				assert(dpaa2_fd_get_len(&op->output_fd));

				/* Ensure the context->eq is reread from mem */
				asm volatile("dmb st" : : : "memory");

				/* The input_fd frc is not used by DCE, We set
				 * it here as a token and read it on the other
				 * side to ensure order */
				dpaa2_fd_set_frc(recycle_op.input_fd,
						context->eq);

				while ((ret = dce_recycle_fd_pair(
					context->session, &recycle_op))) {
					if (ret != -EBUSY)
						break;
				}
				assert(ret >= 0);
				debug(5, "frame %u flush %s, input %u bytes, output %u bytes\n",
					context->eq,
					recycle_op.flush == DCE_Z_FINISH ? "Z_FINISH" :
					recycle_op.flush == DCE_Z_NO_FLUSH ? "Z_NO_FLUSH" :
									"UNKNOWN",
					dpaa2_fd_get_len(recycle_op.input_fd),
					dpaa2_fd_get_len(recycle_op.output_fd));
				context->eq++;
				if (ret == 1 && context->recycle_sleep)
					/* The session is out of suspend */
					wake_up(&context->recycle_finished);
				break;
			case SKIPPED:
				debug(1, "frame %u returned as is because the session is suspended\n",
						context->dq);
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
						context->eq);

				while ((ret = dce_recycle_fd_pair(
					context->session, &recycle_op))) {
					if (ret != -EBUSY)
						break;
				}
				assert(ret >= 0);
				debug(5, "frame %u flush %s, input %u bytes, output %u bytes\n",
					context->eq,
					recycle_op.flush == DCE_Z_FINISH ? "Z_FINISH" :
					recycle_op.flush == DCE_Z_NO_FLUSH ? "Z_NO_FLUSH" :
									"UNKNOWN",
					dpaa2_fd_get_len(recycle_op.input_fd),
					dpaa2_fd_get_len(recycle_op.output_fd));
				context->eq++;
				if (ret == 1 && context->recycle_sleep)
					/* The session is out of suspend */
					wake_up(&context->recycle_finished);
				break;
			default:
				if (context->recycle_sleep)
					/* sho not be here unless in async */
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
			context->dq++;
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
	uint32_t frame_count = 0, byte_count = 0, tx_max = 0,
		 rx_max = 0, tx_min = UINT32_MAX, rx_min = UINT32_MAX, tx_avg = 0,
		 rx_avg = 0, reads = 0;

	snprintf(thread_name, sizeof(thread_name), "%d_eq", context->idx);
	pthread_setname_np(context->pid, thread_name);
	debug(3, "Worker %d at start line\n", context->idx);

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
	dpaa2_fd_set_len(&too_small_output_fd, chunk_size / max_decomp_ratio);
	assert(dpaa2_fd_get_len(&too_small_output_fd));

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
	pthread_create(&dequeuer, NULL, worker_dq, context);

	sync_all(); /* Wait at the start line */

	chunk = list_entry(context->chunk_list->next, typeof(*chunk), node);
	while (1) {
		struct dce_op_fd_pair_tx op;
		bool last_chunk = chunk->node.next == context->chunk_list;

		dpaa2_fd_set_addr(&input_fd, chunk->addr);
		dpaa2_fd_set_len(&input_fd, chunk->size);
		op.input_fd = &input_fd;
		/* Recycle mode testing */
		if (context->recycle_interval)
			op.output_fd = (context->eq + 1) % context->recycle_interval ?
						&output_fd : &too_small_output_fd;
		else
			op.output_fd = &output_fd;
		op.flush  = last_chunk ? DCE_Z_FINISH : DCE_Z_NO_FLUSH;
		op.user_context = context;

		if (context->synchronous)
			/* Send one frame at a time in synchronous mode. the
			 * dequeuer frees it
			 */
			sem_wait(&context->sync_sem);

		/* The input_fd frc is not used by DCE, We set it here as a
		 * token and read it on the other side to ensure order. This set
		 * is done HERE and not before the sem_wait because the session
		 * may go into recycle. In which case the context->eq will be
		 * incremented by the dequeuer while recycling rejected frames.
		 * This race only occurs in synchronous mode, since in async
		 * mode the enqueuer goes to sleep waiting on the recycle
		 * semaphore and the loop logic rereads the context->eq
		 */
		dpaa2_fd_set_frc(&input_fd, context->eq);

		ret = dce_enqueue_fd_pair(context->session, &op);
		if (ret == -EBUSY) {
			msleep(1); /* Give DCE a breather */
			continue;
		} else if (ret == -EACCES) {
			debug(1, "Enqueuer sees that session is in suspend. Sleeping until the session is recovered\n");
			/* -EACCES means that the session has entered recycle
			 * state. This usually happens if the output buffer was
			 * insufficient to hold all output. We will wait for the
			 * dequeue loop to resolve the issue and signal us to
			 * continue work
			 */
			context->recycle_sleep = true;
			sem_wait(&context->recycle_finished);
			context->recycle_sleep = false;
			debug(1, "Enqueuer waking up because dequeuer signaled us that recycle is done\n");
			continue;
		} else if (ret) {
			pr_err("Error on enqueue %d\n", ret);
			context->ret = ret;
			pthread_exit(NULL);
		}

		debug(5, "frame %u has initial %s, flush %s, input %u bytes, output %u bytes\n",
			context->eq,
			chunk->node.prev == context->chunk_list ?
				"true" : "false",
			last_chunk ? "Z_FINISH" : "Z_NO_FLUSH",
			dpaa2_fd_get_len(&input_fd),
			dpaa2_fd_get_len(&output_fd));
		context->eq++;
		context->total_in += chunk->size;

		if (context->eq > context->dq + 2000) {
			bool sampled = false;

			do  {
				if (!sampled) {
					sampled = true;
					dpaa2_io_query_fq_count(context->session->flow.dpdcei->dpio_p,
							context->session->flow.dpdcei->tx_fqid,
							&frame_count, &byte_count);
					if (tx_max < frame_count)
						tx_max = frame_count;
					if (tx_min > frame_count)
						tx_min = frame_count;
					tx_avg = ((reads * tx_avg) + frame_count) / (reads + 1);
					dpaa2_io_query_fq_count(context->session->flow.dpdcei->dpio_p,
							context->session->flow.dpdcei->rx_fqid,
							&frame_count, &byte_count);
					if (rx_max < frame_count)
						rx_max = frame_count;
					if (rx_min > frame_count)
						rx_min = frame_count;
					rx_avg = ((reads * rx_avg) + frame_count) / (reads + 1);
					reads++;
					usleep(3000);
				}
				usleep(100);
				if (context->dq == context->eq)
					pr_info("DCE all caught up! Send work faster!\n");
			} while (context->eq > context->dq + 300);
		}

		if (context->stop) {
			extern int interrupt_count;

			context->dequeue_stop = true;
			debug(0, "Received stop signal. Waiting for %d outstanding work requests\n",
					context->eq - context->dq);
			pthread_join(dequeuer, NULL /* no need retval */);
			assert(context->eq == context->dq);
			context->end_time = read_cntvct();
			debug(0, "tx_max = %u rx_max = %u tx_min = %u rx_min = %u tx_avg = %u rx_avg = %u enqueuer got ahead %u times. Interrupt count = %d\n",
					tx_max, rx_max, tx_min, rx_min, tx_avg,
					rx_avg, reads, interrupt_count);
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
	return NULL; /* Thread exit */
}

/* Barrier used by tests running across all threads */
static pthread_barrier_t barr;

static void sync_all(void)
{
	pthread_barrier_wait(&barr);
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
	bool synchronous_mode = false; /* asynchronous by default */
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
	enum dce_paradigm paradigm = DCE_STATEFUL_RECYCLE;
	enum dce_compression_format format = DCE_CF_GZIP;
	unsigned int test_time = 10; /* 10 seconds by default */

	struct fsl_mc_io *mc_io;
	uint16_t dprc_token;
	int dprc_id;
	char dprc_id_str[50];
	LIST_HEAD(dpio_list);
	struct dpio_context *dpio_context;
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
			pr_err("--recycle is not yet supported in this test\n");
			exit(EXIT_FAILURE);
			recycle_interval = get_ularg(&(*argv)[strlen(STR_recycle)],
						STR_recycle);
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
							dpio_context = malloc(sizeof(*dpio_context));
							assert(dpio_context);
							memset(dpio_context, 0, sizeof(*dpio_context));
							dpio_context->id = strtoul(&(*argv)[strlen("dpio.")],
									&endptr,
									10 /* base 10 */);
							INIT_LIST_HEAD(&dpio_context->dpdcei_list);
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
									list_add_tail(&dpdcei_context->node, &dpio_context->dpdcei_list);
								} else {
									argv--; argc++;
									break;
								}
							}
							if (list_empty(&dpio_context->dpdcei_list)) {
								pr_err("Must specify dpdcei objects operating in this dpio\n");
								exit(EXIT_FAILURE);
							}
							list_add_tail(&dpio_context->node, &dpio_list);
							if (argc < 1) {
								argv--; argc++;
							}
						} else {
							argv--; argc++;
							break;
						}
					}
					if (list_empty(&dpio_list)) {
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

	if (list_empty(&dpio_list)) {
		pr_err("Must provide dprc, dpio, and dpdcei resources for test\n");
		exit(EXIT_FAILURE);
	}

	if (out_file_name && !synchronous_mode) {
		pr_err("--out=<path> must be used with --synchronous\n");
		exit(EXIT_FAILURE);
	}

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

	ret = dprc_open(mc_io, 0, dprc_id, &dprc_token);
	if (ret) {
		pr_err("%d from dprc_open() failed in %s\n", ret, __func__);
		exit(EXIT_FAILURE);
	}

	list_for_each_entry(dpio_context, &dpio_list, node) {
		struct dpdcei_context *dpdcei_context;
		ret = dpio_open(mc_io, 0, dpio_context->id,
				&dpio_context->token);
		if (ret) {
			pr_err("%d from dpio_open() failed in %s\n",
					ret, __func__);
			exit(EXIT_FAILURE);
		}
		list_for_each_entry(dpdcei_context, &dpio_context->dpdcei_list,
				node) {
			ret = dpdcei_open(mc_io, 0, dpdcei_context->id,
					&dpdcei_context->token);
			if (ret) {
				pr_err("%d from dpdcei_open() failed in %s\n",
						ret, __func__);
				exit(EXIT_FAILURE);
			}
		}
	}

	ret = vfio_setup(dprc_id_str);
	if (ret){
		pr_err("vfio_setup() failed\n");
		exit(EXIT_FAILURE);
	}

	if (input_file) {
		fseek(input_file, 0L, SEEK_END);
		file_size = ftell(input_file);
		rewind(input_file);
	} else {
		file_size = 0xFFF000;
	}
	/* vfio_setup_dma() must be called after vfio_setup() is called */
	dce_mem.sz = (file_size + 0xFFF000) & 0xFFFFFFFFFFFF000;
	dce_mem.addr = vfio_setup_dma(dce_mem.sz);
	if (!dce_mem.addr) {
		ret = -ENOMEM;
		exit(EXIT_FAILURE);
	}
	dma_mem_allocator_init(&dce_mem);

	/* Prepare input data list */
	if (input_file) {
		/* Get input data from sample data file */
		uint8_t buf[chunk_size];
		size_t bytes_in;

		while ((bytes_in = fread(buf, 1, chunk_size, input_file)) > 0) {
			struct chunk *new_chunk = malloc(sizeof(struct chunk));

			new_chunk->addr =
			   (dma_addr_t) dma_mem_memalign(&dce_mem, 0, bytes_in);
			if (!new_chunk->addr) {
				pr_err("Unable to allocate dma memory for DCE\n");
				exit(EXIT_FAILURE);
			}
			memcpy((void *)new_chunk->addr, buf, bytes_in);
			new_chunk->size = bytes_in;
			list_add_tail(&new_chunk->node, &chunk_list);
			num_chunks++;
		}
		fclose(input_file);
	} else { /* No input file provided, use stock data */
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
	list_for_each_entry(dpio_context, &dpio_list, node) {
		struct dpdcei_context *dpdcei_context;

		dpio_context->dpio = dpaa2_io_create(dpio_context->id, -1);
		if (!dpio_context->dpio) {
			pr_err("dpio setup failed\n");
			exit(EXIT_FAILURE);
		}

		list_for_each_entry(dpdcei_context, &dpio_context->dpdcei_list,
					node) {
			int j;
			struct dce_session_params params;

			dpdcei_context->dpdcei =
				dpdcei_setup(dpio_context->dpio,
						dpdcei_context->id);
			if (!dpdcei_context->dpdcei) {
				pr_err("dpdcei setup failed\n");
				exit(EXIT_FAILURE);
			}

			params = (struct dce_session_params){
				.dpio = dpio_context->dpio,
				.dpdcei = dpdcei_context->dpdcei,
				.paradigm = paradigm,
				.compression_format = format,
				.compression_effort =
					DCE_CE_BEST_POSSIBLE,
				/* gz_header not used in ZLIB format mode */
				/* buffer_pool_id not used */
				/* buffer_pool_id2 not used */
				/* release_buffers not used */
				/* encode_base_64 not used */
				.work_done_callback = wake_cb,
			};

			for (j = 0; j < dpdcei_context->num_workers; j++, i++) {
				struct work_context *context = &contexts[i];

				context->chunk_list = &chunk_list;
				context->out_file = out_file_name;
				context->idx = i;
				context->synchronous = synchronous_mode;
				context->recycle_interval = recycle_interval;
				context->session =
					malloc(sizeof(*context->session));
				ret = dce_session_create(context->session,
						&params);
				context->engine =
					dpdcei_context->dpdcei->attr.engine;
				if (ret) {
					pr_err("dce_session_create() failed with %d\n",
							ret);
					exit(EXIT_FAILURE);
				}

				ret = pthread_create(&contexts[i].pid, NULL,
						worker_func, &contexts[i]);
				if (ret) {
					pr_err("pthread_create failed with ret code %d\n",
							ret);
					goto fail_contexts_alloc;
				}
			}
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
		dce_session_destroy(context->session);
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

	list_for_each_entry(dpio_context, &dpio_list, node) {
		struct dpdcei_context *dpdcei_context;

		list_for_each_entry(dpdcei_context, &dpio_context->dpdcei_list,
					node)
			dpdcei_cleanup(dpdcei_context->dpdcei);
		dpaa2_io_destroy(dpio_context->dpio);
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
