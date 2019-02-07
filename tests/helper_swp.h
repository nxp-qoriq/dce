/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2019 NXP
 * All rights reserved.
 */

/* QBMan helper functions for applications of dce.h */

#ifndef __QMAN_HELPER_H
#define __QMAN_HELPER_H

#include <fsl_dpio.h>
#include <fsl_mc_sys.h>

/**
 * dce_helper_swp_init() - create a swp object.
 * @dpio_id:	Identifier of the dpio object to map as a Software Portal
 *
 * Activates a "struct qbman_swp" corresponding to the given dpio_id
 *
 * Return a valid swp object for success, or NULL for failure.
 */
static struct qbman_swp *dce_helper_swp_init(int dpio_id)
{
	char dpio_id_str[20];
	struct fsl_mc_io *mc_io;
	struct dpio_attr dpio_attr;
	uint16_t dpio_token;
	struct qbman_swp_desc swp_desc;
	struct qbman_swp *swp = NULL;
	int err;

	mc_io = malloc(sizeof(struct fsl_mc_io));
	if (!mc_io)
		goto err_mc_io_alloc;

	err = mc_io_init(mc_io);
	if (err)
		goto err_mc_io_init;

	/* DPIO configuration */
	err = dpio_open(mc_io, 0, dpio_id, &dpio_token);
	if (err) {
		pr_err("error %d in %s in attempt to dpio_open()\n",
				err, __func__);
		goto err_dpio_open;
	}

	err = dpio_reset(mc_io, 0, dpio_token);
	if (err) {
		pr_err("error %d in %s in attempt to dpio_reset()\n",
				err, __func__);
		goto err_dpio_open;
	}

	err = dpio_get_attributes(mc_io, 0, dpio_token, &dpio_attr);
	if (err) {
		pr_err("error %d in %s in attempt to dpio_get_attributes()\n",
				err, __func__);
		goto err_dpio_open;
	}

	err = dpio_enable(mc_io, 0, dpio_token);
	if (err) {
		pr_err("error %d in %s in attempt to dpio_enable()\n",
				err, __func__);
		goto err_dpio_open;
	}

	err = dpio_close(mc_io, 0, dpio_token);
	if (err) {
		pr_err("error %d in %s in attempt to dpio_close()\n",
				err, __func__);
		goto err_dpio_open;
	}

	/* Define the qman version temporarily here. To be removed once
	 * qbman_userspace library moves this define to fsl_qbman_portal.h */
#define QMAN_REV_5000   0x05000000
	sprintf(dpio_id_str, "dpio.%i", dpio_id);
	swp_desc.cena_bar = vfio_map_portal(dpio_id_str,
				    dpio_attr.qbman_version < QMAN_REV_5000 ?
				    PORTAL_MEM_CENA : PORTAL_MEM_MB_CENA);
	if (!swp_desc.cena_bar) {
		pr_err("error %d in %s in attempt to vfio_map_portal_mem() cache enabled area\n",
				err, __func__);
		goto err_portal_cache_enabled_mem_setup;
	}

	swp_desc.cinh_bar = vfio_map_portal(dpio_id_str,
							PORTAL_MEM_CINH);
	if (!swp_desc.cinh_bar) {
		pr_err("error %d in %s in attempt to vfio_map_portal_mem() cache inhibited area\n",
				err, __func__);
		goto err_portal_cache_inhibited_mem_setup;
	}

	swp_desc.idx = dpio_id;
	swp_desc.eqcr_mode = qman_eqcr_vb_array;
	swp_desc.irq = 0;
	swp_desc.qman_version = dpio_attr.qbman_version;
	swp = qbman_swp_init(&swp_desc);
	if (!swp) {
		pr_err("qbman_swp_init() failed in %s\n", __func__);
		goto err_swp_init;
	}

	qbman_swp_interrupt_clear_status(swp, 0xffffffff);
	qbman_swp_push_set(swp, 0, 1);

	return swp;

err_swp_init:
	/* FIXME should cleanup portal mapped memory */
	/* vfio_unmap_portal_mem(swp_desc.cinh_bar) */

err_portal_cache_inhibited_mem_setup:
	/* FIXME should cleanup portal mapped memory */
	/* vfio_unmap_portal_mem(swp_desc.cena_bar) */
err_portal_cache_enabled_mem_setup:
	dpio_disable(mc_io, 0, dpio_token);
err_dpio_open:
	mc_io_cleanup(mc_io);
err_mc_io_init:
	free(mc_io);
err_mc_io_alloc:
	return NULL;
}

/**
 * dce_helper_swp_finish() - Finish and free memroy associated a a particular swp
 * @swp:	Software portal to use for cleanup
 *
 * Return:	0 on success error code otherwise
 */
static int dce_helper_swp_finish(struct qbman_swp *swp)
{
	int dpio_id;
	char dpio_id_str[20];
	struct fsl_mc_io *mc_io;
	struct dpio_attr dpio_attr;
	uint16_t dpio_token;
	const struct qbman_swp_desc *swp_desc;
	int err;

	swp_desc = qbman_swp_get_desc(swp);
	if (!swp_desc)
		return -EINVAL;

	dpio_id = swp_desc->idx;

	mc_io = malloc(sizeof(struct fsl_mc_io));
	if (!mc_io)
		return -ENOMEM;

	err = mc_io_init(mc_io);
	if (err)
		goto err_mc_io_init;

	/* DPIO configuration */
	err = dpio_open(mc_io, 0, dpio_id, &dpio_token);
	if (err) {
		pr_err("error %d in %s in attempt to dpio_open()\n",
				err, __func__);
		goto err_dpio_open;
	}

	err = dpio_get_attributes(mc_io, 0, dpio_token, &dpio_attr);
	if (err) {
		pr_err("error %d in %s in attempt to dpio_get_attributes()\n",
				err, __func__);
		goto err_dpio_open;
	}

	sprintf(dpio_id_str, "dpio.%i", dpio_id);
	err = vfio_unmap_portal(swp_desc->cena_bar, dpio_id_str,
			dpio_attr.qbman_version < QMAN_REV_5000 ?
			PORTAL_MEM_CENA : PORTAL_MEM_MB_CENA);
	if (err) {
		pr_err("error %d in %s in attempt to vfio_unmap_portal() cena\n",
				err, __func__);
		goto err_dpio_open;
	}

	err = vfio_unmap_portal(swp_desc->cinh_bar, dpio_id_str,
							PORTAL_MEM_CINH);
	if (err) {
		pr_err("error %d in %s in attempt to vfio_unmap_portal() cinh\n",
				err, __func__);
		goto err_dpio_open;
	}

	err = dpio_disable(mc_io, 0, dpio_token);
	if (err) {
		pr_err("error %d in %s in attempt to dpio_enable()\n",
				err, __func__);
		goto err_dpio_open;
	}

	err = dpio_reset(mc_io, 0, dpio_token);
	if (err) {
		pr_err("error %d in %s in attempt to dpio_reset()\n",
				err, __func__);
		goto err_dpio_open;
	}
	err = dpio_close(mc_io, 0, dpio_token);
	if (err) {
		pr_err("error %d in %s in attempt to dpio_close()\n",
				err, __func__);
		goto err_dpio_open;
	}

	qbman_swp_finish(swp);

	return err;

err_dpio_open:
	mc_io_cleanup(mc_io);
err_mc_io_init:
	free(mc_io);
	return err;
}

#endif /* __QMAN_HELPER_H */
