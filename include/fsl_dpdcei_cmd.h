/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2013 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#ifndef _FSL_DPDCEI_CMD_H
#define _FSL_DPDCEI_CMD_H

/* DPDCEI Version */
#define DPDCEI_VER_MAJOR				2
#define DPDCEI_VER_MINOR				2

/* Command IDs */
#define DPDCEI_CMDID_CLOSE                           0x8001
#define DPDCEI_CMDID_OPEN                            0x80d1
#define DPDCEI_CMDID_CREATE                          0x90d1
#define DPDCEI_CMDID_DESTROY                         0x98d1
#define DPDCEI_CMDID_GET_API_VERSION                 0xa0d1

#define DPDCEI_CMDID_ENABLE                          0x0021
#define DPDCEI_CMDID_DISABLE                         0x0031
#define DPDCEI_CMDID_GET_ATTR                        0x0041
#define DPDCEI_CMDID_RESET                           0x0051
#define DPDCEI_CMDID_IS_ENABLED                      0x0061

#define DPDCEI_CMDID_SET_IRQ_ENABLE                  0x0121
#define DPDCEI_CMDID_GET_IRQ_ENABLE                  0x0131
#define DPDCEI_CMDID_SET_IRQ_MASK                    0x0141
#define DPDCEI_CMDID_GET_IRQ_MASK                    0x0151
#define DPDCEI_CMDID_GET_IRQ_STATUS                  0x0161
#define DPDCEI_CMDID_CLEAR_IRQ_STATUS                0x0171

#define DPDCEI_CMDID_SET_RX_QUEUE                    0x1b01
#define DPDCEI_CMDID_GET_RX_QUEUE                    0x1b11
#define DPDCEI_CMDID_GET_TX_QUEUE                    0x1b21

/*                cmd, param, offset, width, type, arg_name */
#define DPDCEI_CMD_OPEN(cmd, dpdcei_id) \
	MC_CMD_OP(cmd, 0, 0,  32, int,      dpdcei_id)

/*                cmd, param, offset, width, type, arg_name */
#define DPDCEI_CMD_CREATE(cmd, cfg) \
do { \
	MC_CMD_OP(cmd, 0, 8,  8,  enum dpdcei_engine,  cfg->engine);\
	MC_CMD_OP(cmd, 0, 16, 8,  uint8_t,  cfg->priority);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPDCEI_RSP_IS_ENABLED(cmd, en) \
	MC_RSP_OP(cmd, 0, 0,  1,  int,	    en)

/*                cmd, param, offset, width, type, arg_name */
#define DPDCEI_CMD_SET_IRQ_ENABLE(cmd, irq_index, enable_state) \
do { \
	MC_CMD_OP(cmd, 0, 0,  8,  uint8_t,  enable_state); \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPDCEI_CMD_GET_IRQ_ENABLE(cmd, irq_index) \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index)

/*                cmd, param, offset, width, type, arg_name */
#define DPDCEI_RSP_GET_IRQ_ENABLE(cmd, enable_state) \
	MC_RSP_OP(cmd, 0, 0,  8,  uint8_t,  enable_state)

/*                cmd, param, offset, width, type, arg_name */
#define DPDCEI_CMD_SET_IRQ_MASK(cmd, irq_index, mask) \
do { \
	MC_CMD_OP(cmd, 0, 0,  32, uint32_t, mask); \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPDCEI_CMD_GET_IRQ_MASK(cmd, irq_index) \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index)

/*                cmd, param, offset, width, type, arg_name */
#define DPDCEI_RSP_GET_IRQ_MASK(cmd, mask) \
	MC_RSP_OP(cmd, 0, 0,  32, uint32_t, mask)

/*                cmd, param, offset, width, type, arg_name */
#define DPDCEI_CMD_GET_IRQ_STATUS(cmd, irq_index, status) \
do { \
	MC_CMD_OP(cmd, 0, 0,  32, uint32_t, status);\
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPDCEI_RSP_GET_IRQ_STATUS(cmd, status) \
	MC_RSP_OP(cmd, 0, 0,  32, uint32_t,  status)

/*                cmd, param, offset, width, type, arg_name */
#define DPDCEI_CMD_CLEAR_IRQ_STATUS(cmd, irq_index, status) \
do { \
	MC_CMD_OP(cmd, 0, 0,  32, uint32_t, status); \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPDCEI_RSP_GET_ATTRIBUTES(cmd, attr) \
do { \
	MC_RSP_OP(cmd, 0,  0, 32, int,                (attr)->id); \
	MC_RSP_OP(cmd, 0, 32,  8, enum dpdcei_engine, (attr)->engine); \
	MC_RSP_OP(cmd, 1, 0,  64, uint64_t, (attr)->dce_version); \
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPDCEI_CMD_SET_RX_QUEUE(cmd, cfg) \
do { \
	MC_CMD_OP(cmd, 0, 0,  32, int,      cfg->dest_cfg.dest_id); \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  cfg->dest_cfg.priority); \
	MC_CMD_OP(cmd, 0, 48, 4,  enum dpdcei_dest, cfg->dest_cfg.dest_type); \
	MC_CMD_OP(cmd, 1, 0,  64, uint64_t, cfg->user_ctx); \
	MC_CMD_OP(cmd, 2, 0,  32, uint32_t, cfg->options);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPDCEI_RSP_GET_RX_QUEUE(cmd, attr) \
do { \
	MC_RSP_OP(cmd, 0, 0,  32, int,      attr->dest_cfg.dest_id);\
	MC_RSP_OP(cmd, 0, 32, 8,  uint8_t,  attr->dest_cfg.priority);\
	MC_RSP_OP(cmd, 0, 48, 4,  enum dpdcei_dest, attr->dest_cfg.dest_type);\
	MC_RSP_OP(cmd, 1, 0,  64, uint64_t,  attr->user_ctx);\
	MC_RSP_OP(cmd, 2, 0,  32, uint32_t,  attr->fqid);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPDCEI_RSP_GET_TX_QUEUE(cmd, attr) \
	MC_RSP_OP(cmd, 0, 32, 32, uint32_t,  attr->fqid)

/*                cmd, param, offset, width, type,      arg_name */
#define DPDCEI_RSP_GET_API_VERSION(cmd, major, minor) \
do { \
	MC_RSP_OP(cmd, 0, 0,  16, uint16_t, major);\
	MC_RSP_OP(cmd, 0, 16, 16, uint16_t, minor);\
} while (0)

#endif /* _FSL_DPDCEI_CMD_H */
