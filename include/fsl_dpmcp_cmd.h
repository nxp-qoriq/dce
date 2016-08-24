/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2013 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#ifndef _FSL_DPMCP_CMD_H
#define _FSL_DPMCP_CMD_H

/* DPMCP Version */
#define DPMCP_VER_MAJOR				4
#define DPMCP_VER_MINOR				0

/* Command IDs */
#define DPMCP_CMDID_CLOSE                               0x8001
#define DPMCP_CMDID_OPEN                                0x80b1
#define DPMCP_CMDID_CREATE                              0x90b1
#define DPMCP_CMDID_DESTROY                             0x98b1
#define DPMCP_CMDID_GET_API_VERSION                     0xa0b1

#define DPMCP_CMDID_GET_ATTR                            0x0041
#define DPMCP_CMDID_RESET                               0x0051

#define DPMCP_CMDID_SET_IRQ_ENABLE                      0x0121
#define DPMCP_CMDID_GET_IRQ_ENABLE                      0x0131
#define DPMCP_CMDID_SET_IRQ_MASK                        0x0141
#define DPMCP_CMDID_GET_IRQ_MASK                        0x0151
#define DPMCP_CMDID_GET_IRQ_STATUS                      0x0161

/*                cmd, param, offset, width, type, arg_name */
#define DPMCP_CMD_OPEN(cmd, dpmcp_id) \
	MC_CMD_OP(cmd, 0, 0,  32, int,	    dpmcp_id)

/*                cmd, param, offset, width, type, arg_name */
#define DPMCP_CMD_CREATE(cmd, cfg) \
	MC_CMD_OP(cmd, 0, 0,  32, int,      cfg->portal_id)

/*                cmd, param, offset, width, type, arg_name */
#define DPMCP_CMD_SET_IRQ_ENABLE(cmd, irq_index, en) \
do { \
	MC_CMD_OP(cmd, 0, 0,  8,  uint8_t,  en); \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPMCP_CMD_GET_IRQ_ENABLE(cmd, irq_index) \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index)

/*                cmd, param, offset, width, type, arg_name */
#define DPMCP_RSP_GET_IRQ_ENABLE(cmd, en) \
	MC_RSP_OP(cmd, 0, 0,  8,  uint8_t,  en)

/*                cmd, param, offset, width, type, arg_name */
#define DPMCP_CMD_SET_IRQ_MASK(cmd, irq_index, mask) \
do { \
	MC_CMD_OP(cmd, 0, 0,  32, uint32_t, mask);\
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPMCP_CMD_GET_IRQ_MASK(cmd, irq_index) \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index)

/*                cmd, param, offset, width, type, arg_name */
#define DPMCP_RSP_GET_IRQ_MASK(cmd, mask) \
	MC_RSP_OP(cmd, 0, 0,  32, uint32_t, mask)

/*                cmd, param, offset, width, type, arg_name */
#define DPMCP_CMD_GET_IRQ_STATUS(cmd, irq_index, status) \
do { \
	MC_CMD_OP(cmd, 0, 0,  32, uint32_t, status);\
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPMCP_RSP_GET_IRQ_STATUS(cmd, status) \
	MC_RSP_OP(cmd, 0, 0,  32, uint32_t, status)

/*                cmd, param, offset, width, type,	arg_name */
#define DPMCP_RSP_GET_ATTRIBUTES(cmd, attr) \
	MC_RSP_OP(cmd, 0, 32, 32, int, (attr)->id)

/*                cmd, param, offset, width, type,      arg_name */
#define DPMCP_RSP_GET_API_VERSION(cmd, major, minor) \
do { \
	MC_RSP_OP(cmd, 0, 0,  16, uint16_t, major);\
	MC_RSP_OP(cmd, 0, 16, 16, uint16_t, minor);\
} while (0)

#endif /* _FSL_DPMCP_CMD_H */
