/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2019 Freescale Semiconductor, Inc.
 * All rights reserved.
 */

#include <compat.h>
#include "private.h"
#include "../dce.h"
#include <allocator.h>
#include <vfio_utils.h>
#include "helper_swp.h"
#include <sys/sysinfo.h>
#include <fsl_dprc.h>
#include <fsl_dpdcei.h>

#if 0
static void single_chunk_decompress(struct qbman_swp *swp,
				struct dpdcei *dpdcei,
				struct dma_mem *mem);

static void multi_chunk_compress(struct qbman_swp *swp,
			  struct dpdcei *dpdcei,
			  struct dma_mem *mem);

static void multi_chunk_decompress(struct qbman_swp *swp,
			  struct dpdcei *dpdcei,
			  struct dma_mem *mem);

static void multi_chunk_choke_continue_recycle_compress(struct qbman_swp *swp,
			  struct dpdcei *dpdcei,
			  struct dma_mem *mem);

static void multi_chunk_choke_continue_recycle_decompress(struct qbman_swp *swp,
			  struct dpdcei *dpdcei,
			  struct dma_mem *mem);

static void multi_chunk_choke_continue_dsicard_compress(struct qbman_swp *swp,
			  struct dpdcei *dpdcei,
			  struct dma_mem *mem);

static void multi_chunk_choke_continue_discard_decompress(struct qbman_swp *swp,
			  struct dpdcei *dpdcei,
			  struct dma_mem *mem);

static void multi_chunk_choke_abort_discard_compress(struct qbman_swp *swp,
			  struct dpdcei *dpdcei,
			  struct dma_mem *mem);

static void multi_chunk_choke_abort_discard_dompress(struct qbman_swp *swp,
			  struct dpdcei *dpdcei,
			  struct dma_mem *mem);

static void multi_chunk_choke_abort_recycle_compress(struct qbman_swp *swp,
			  struct dpdcei *dpdcei,
			  struct dma_mem *mem);

static void multi_chunk_choke_abort_recycle_decompress(struct qbman_swp *swp,
			  struct dpdcei *dpdcei,
			  struct dma_mem *mem);

static void multi_chunk_member_continue_decompress(struct qbman_swp *swp,
			  struct dpdcei *dpdcei,
			  struct dma_mem *mem);

static void multi_chunk_member_discontinue_decompress(struct qbman_swp *swp,
			  struct dpdcei *dpdcei,
			  struct dma_mem *mem);
#endif

static void process_input_args(int argc,
			char *argv[],
			int *dprc_id,
			int *dpio_id,
			int *comp_dpdcei_id,
			int *decomp_dpdcei_id);

static void *dma_allocator(void *opaque, size_t align, size_t size)
{
	return dma_mem_memalign(opaque, align, size);
}

static void dma_freer(void *opaque, void *addr)
{
	dma_mem_free(opaque, addr);
}


int main(int argc, char *argv[])
{
	struct qbman_swp *swp;
	int dpio_id;
	struct dce_dpdcei_params dpdcei_params;
	struct dpdcei *comp_dpdcei;
	int comp_dpdcei_id;
	struct dpdcei *decomp_dpdcei;
	int decomp_dpdcei_id;
	struct fsl_mc_io *mc_io;
	char dprc_id_str[50];
	int dprc_id;
	int ret = 0;
	struct dma_mem dce_mem;
	uint16_t dprc_token;
	uint16_t root_token;
	int test_count;

	process_input_args(argc,
			   argv,
			   &dprc_id,
			   &dpio_id,
			   &comp_dpdcei_id,
			   &decomp_dpdcei_id);

	pr_info("SETUP Data Path Objects ***************************************************************\n");

	debug(0, "Setup MC resources\n");
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

	debug(0, "Open root dprc\n");
	ret = dprc_open(mc_io, 0, 1 /* ROOT DPRC ID */, &dprc_token);
	if (ret) {
		pr_err("%d from dprc_open() failed in %s. Make sure to run application privileged (as root)\n", ret, __func__);
		exit(EXIT_FAILURE);
	}

	root_token = dprc_token;

	debug(0, "Open test dprc\n");
	ret = dprc_open(mc_io, 0, dprc_id, &dprc_token);
	if (ret) {
		pr_err("%d from dprc_open() failed in %s\n", ret, __func__);
		exit(EXIT_FAILURE);
	}

	debug(0, "Setup vfio to allow HW devices to access virtual addresses\n");
	ret = vfio_setup(dprc_id_str);
	if (ret){
		pr_err("vfio_setup() failed\n");
		exit(EXIT_FAILURE);
	}

	dprc_close(mc_io, 0, dprc_token);
	dprc_close(mc_io, 0, root_token);

	/* vfio_setup_dma() must be called after vfio_setup() is called */
	dce_mem.sz = (dce_test_data_size + 0xFFFF000) & 0xFFFFFFFFFFFF000;
	debug(0, "Allocate virtual memory and map it to test dprc using vfio\n");
	dce_mem.addr = vfio_setup_dma(dce_mem.sz);
	if (!dce_mem.addr) {
		ret = -ENOMEM;
		exit(EXIT_FAILURE);
	}
	dma_mem_allocator_init(&dce_mem);

	debug(0, "Setup QBman Software Portal\n");
	swp = dce_helper_swp_init(dpio_id);
	if (!swp) {
		pr_err("Software Portal init from dpio.%d failed\n", dpio_id);
		exit(EXIT_FAILURE);
	}

	dpdcei_params = (struct dce_dpdcei_params) {
		.dpdcei_id = comp_dpdcei_id,
			.mcp = mc_io,
			.dma_alloc = dma_allocator,
			.dma_free = dma_freer,
			.dma_opaque = &dce_mem,
	};

	debug(0, "Setup Decompression Compression Engine devices\n");
	comp_dpdcei = dce_dpdcei_activate(&dpdcei_params);
	if (!comp_dpdcei) {
		pr_err("dpdcei.%d activation failed\n", comp_dpdcei_id);
	}

	dpdcei_params.dpdcei_id = decomp_dpdcei_id;

	decomp_dpdcei = dce_dpdcei_activate(&dpdcei_params);
	if (!decomp_dpdcei) {
		pr_err("dpdcei.%d activation failed\n", decomp_dpdcei_id);
	}

	pr_info("\nTESTS *********************************************************************************\n");

	test_count = 0;

#include "single_chunk_compress.h"
	pr_info("_________________________________________________________________________\n");
	pr_info("Test # %d: single_chunk_compress\n", test_count++);
	single_chunk_compress(swp, comp_dpdcei, &dce_mem);
	pr_info("_________________________________________________________________________\n");

#include "single_chunk_decompress.h"
	pr_info("_________________________________________________________________________\n");
	pr_info("Test # %d: single_chunk_decompress\n", test_count++);
	single_chunk_decompress(swp, comp_dpdcei, decomp_dpdcei, &dce_mem);
	pr_info("_________________________________________________________________________\n");

#include "multi_chunk_compress.h"

	pr_info("_________________________________________________________________________\n");
	pr_info("Test # %d: multi_chunk_compress\n", test_count++);
	multi_chunk_compress(swp, comp_dpdcei, &dce_mem);
	pr_info("_________________________________________________________________________\n");

#include "multi_chunk_decompress.h"
	pr_info("_________________________________________________________________________\n");
	pr_info("Test # %d: multi_chunk_decompress\n", test_count++);
	multi_chunk_decompress(swp, comp_dpdcei, decomp_dpdcei, &dce_mem);
	pr_info("_________________________________________________________________________\n");

#include "multi_chunk_choke_continue_recycle_compress.h"
	pr_info("_________________________________________________________________________\n");
	pr_info("Test # %d: multi_chunk_choke_continue_recycle_compress\n",
								test_count++);
	multi_chunk_choke_continue_recycle_compress(swp, comp_dpdcei, &dce_mem);
	pr_info("_________________________________________________________________________\n");

#include "multi_chunk_choke_continue_recycle_decompress.h"
	pr_info("_________________________________________________________________________\n");
	pr_info("Test # %d: multi_chunk_choke_continue_recycle_decompress\n",
								test_count++);
	multi_chunk_choke_continue_recycle_decompress(swp, comp_dpdcei,
						decomp_dpdcei, &dce_mem);
	pr_info("_________________________________________________________________________\n");

	/* TODO
	pr_info("_________________________________________________________________________\n");
	multi_chunk_choke_continue_dsicard_compress();

	pr_info("_________________________________________________________________________\n");
	multi_chunk_choke_continue_discard_decompress();

	pr_info("_________________________________________________________________________\n");
	multi_chunk_choke_abort_discard_compress();

	pr_info("_________________________________________________________________________\n");
	multi_chunk_choke_abort_discard_dompress();

	pr_info("_________________________________________________________________________\n");
	multi_chunk_choke_abort_recycle_compress();

	pr_info("_________________________________________________________________________\n");
	multi_chunk_choke_abort_recycle_decompress();

	pr_info("_________________________________________________________________________\n");
	multi_chunk_member_continue_decompress();

	pr_info("_________________________________________________________________________\n");
	multi_chunk_member_discontinue_decompress();
	*/

	dce_dpdcei_deactivate(comp_dpdcei);
	dce_dpdcei_deactivate(decomp_dpdcei);
	dce_helper_swp_finish(swp);
	/* TODO: vfio_cleanup should be done after lane_destroy() is updated to
	 * send context invalidate frame */
	/*vfio_cleanup_dma(dce_mem.addr, dce_mem.sz);*/
	free(mc_io);

	return 0;

}

static void usage(void);

static void process_input_args(int argc,
			char *argv[],
			int *dprc_id,
			int *dpio_id,
			int *comp_dpdcei_id,
			int *decomp_dpdcei_id)
{
	char *endptr;

	/* skip application name */
	if (!++argv || !--argc) {
		usage();
		exit(EXIT_FAILURE);
	}

	if (!strncmp(*argv, "dprc.", strlen("dprc."))) {
		*dprc_id = strtoul(&(*argv)[strlen("dprc.")], &endptr,
							10 /* base 10 */);
	} else {
		usage();
		exit(EXIT_FAILURE);
	}

	/* on to the next arg */
	if (!++argv || !--argc) {
		usage();
		exit(EXIT_FAILURE);
	}

	if (!strncmp(*argv, "dpio.", strlen("dpio."))) {
		*dpio_id = strtoul(&(*argv)[strlen("dpio.")], &endptr,
							10 /* base 10 */);
	} else {
		usage();
		exit(EXIT_FAILURE);
	}

	if (!++argv || !--argc) {
		usage();
		exit(EXIT_FAILURE);
	}

	if (!strncmp(*argv, "dpdcei.", strlen("dpdcei."))) {
		*comp_dpdcei_id = strtoul(&(*argv)[strlen("dpdcei.")], &endptr,
							10 /* base 10 */);
	} else {
		exit(EXIT_FAILURE);
	}

	if (!++argv || !--argc) {
		usage();
		exit(EXIT_FAILURE);
	}

	if (!strncmp(*argv, "dpdcei.", strlen("dpdcei."))) {
		*decomp_dpdcei_id = strtoul(&(*argv)[strlen("dpdcei.")], &endptr,
							10 /* base 10 */);
	} else {
		exit(EXIT_FAILURE);
	}
}

static char *usage_STR =
	"dce-example <dprc> <dpio> <comp-dpdcei> <decomp-dpdcei>\n"
	"\nExample:\n"
	"dce-example dprc.2 dpio.8 dpdcei.0 dpdcei.1\n";

static void usage(void)
{
	pr_info("%s", usage_STR);
}
