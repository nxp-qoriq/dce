/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2014 Freescale Semiconductor, Inc.
 * All rights reserved.
 */

/*!
 * @file dpaa2_mbuf.h
 *
 * @brief This file contains Buffer management library services for DPAA2 based
 *	applications. DPAA2 buffer library provides the ability to allocate,
 *	free, copy and manipulate the dpaa2 buffers.
 *
 * @addtogroup DPAA2_MBUF
 * @ingroup DPAA2_RTS
 * @{
 */

#ifndef _DPAA2_MBUF_H_
#define _DPAA2_MBUF_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Standard header files */
#include <string.h>

/*DPAA2 header files */
#include <hints.h>
#include <align.h>
#include <dpaa2_common.h>
#include <dpaa2_cfg.h>
#include <std_types.h>
#include <dpaa2_malloc.h>
#include <dpaa2_dev.h>

#ifndef DPAA2_MBUF_MALLOC
#include <dpaa2_mpool.h>

extern void *dpaa2_mbuf_shell_mpool;
#endif

#define DPAA2_MBUF_OFFSET_INVALID (0xffff)

/*! Enable scatter gather support */
#define DPAA2_CFG_SG_SUPPORT		BIT_POS(1)

/* DPAA2 buffer flags */
/*! If DPAA2 MBUF is INLINE to the buffer */
#define DPAA2BUF_ALLOCATED_INLINE	BIT_POS(2)
/*! If DPAA2 MBUF is allocated using dpaa2_mbuf_alloc_shell */
#define DPAA2BUF_ALLOCATED_SHELL		BIT_POS(3)
/*! If memory is dma'ble */
#define DPAA2BUF_DMABLE			BIT_POS(4)
/*! If AIOP context is valid. To be used only used by DPAA2, not by the user */
#define DPAA2BUF_AIOP_CNTX_VALID		BIT_POS(5)
/*! If SEC context is valid. To be used only used by DPAA2, not by the user */
#define DPAA2BUF_SEC_CNTX_VALID		BIT_POS(6)

/*! Minimum buffer size to be configured in a buffer pool */
#define DPAA2_MBUF_MIN_SIZE		64
/*! Reserved area size in DPAA2 buffer that can be used by user applications
 *  for their purpose. */
#define	 DPAA2_MBUF_CNXT_DATA		16

/*! Invalid buffer pool ID */
#define INVALID_BPID			0xFFFF

/* Ethernet flags */
/*! Tx frame was longer than supported */
#define DPAA2BUF_ERROR_FRAME_TOO_LONG		BIT_POS(1)
/*! Tx frame was not from dma'ble memory */
#define DPAA2BUF_ERROR_SYSTEM_BUS_ERROR		BIT_POS(2)
/*! Ethernet packet error occured during Tx. */
#define DPAA2BUF_ERROR_TX			BIT_POS(3)
/*! Tx confirmation is required for the transmitted packet or not.
	Set DPAA2BUF_TX_CONF_REQUIRED if TX Confirmation is required
	alongwith the TX Error frames.*/
#define DPAA2BUF_TX_CONF_REQUIRED		BIT_POS(4)
/*! Tx confirmation/error is required on common queue or on FQ per virtual
	queue. If flag is set, send confirmation and error packets on common
	VQ otherwise on FQ per virtual queue.
	Allowed along with "DPAA2BUF_TX_CONF_REQUIRED" only.
	Use DEF_ERR_VQ_INDEX for default error vq index */
#define DPAA2BUF_TX_CONF_ERR_ON_COMMON_Q		BIT_POS(5)
/*! No Tx confirmation is required for the transmitted packet.
	Set DPAA2BUF_TX_NO_ACTION if TX Confirmation is not required
	alongwith the TX Error frames.*/
#define DPAA2BUF_TX_NO_ACTION			0

/*! Ethernet packet error occured during Tx.
	user needs to check this flag for any error occurenece.
	if this flag mask is set then user can check for the speceific
	errors given below:*/
#define DPAA2BUF_ERROR_TX_MASK  (DPAA2BUF_ERROR_FRAME_TOO_LONG |\
					DPAA2BUF_ERROR_SYSTEM_BUS_ERROR |\
					DPAA2BUF_ERROR_TX)

/*! It has an HASHVAL packet during Rx */
#define DPAA2BUF_HAS_HASHVAL		BIT_POS(6)

/*! Packet is Jumbo i.e. larger than ODPH_ETH_LEN_MAX */
#define DPAA2BUF_IS_JUMBO		BIT_POS(7)

/*! Packet has L3 set*/
#define DPAA2BUF_HAS_L3		BIT_POS(8)

/*! Packet has L4 set*/
#define DPAA2BUF_HAS_L4		BIT_POS(9)

/*! Packet is Segmeneted i.e. multiple buffers are present */
#define DPAA2BUF_IS_SEGMENTED		BIT_POS(10)

/*Buffer headroom*/
extern uint32_t dpaa2_mbuf_head_room;

/*!
 * Buffer pool configuration structure. User need to give DPAA2 the
 * 'num', and 'size'. Optionally user shall fill 'align' if buffer alignment is
 * required. User shall fill in 'addr' as memory pointer from where DPAA2
 * will carve out the buffers and 'addr' should be 'NULL' if user wants to
 * create buffers from the memory which user asked DPAA2
 * to reserve at 'dpaa2 init'. DPAA2 will fill in the 'bpid' corresponding to
 * every buffer pool configured.
 */
struct buf_pool_cfg {
	void *addr; /*!< The address from where DPAA2 will carve out the
			* buffers. 'addr' should be 'NULL' if user wants
			* to create buffers from the memory which user
			* asked DPAA2 to reserve during 'dpaa2 init' */
	phys_addr_t    phys_addr;  /*!< corresponding physical address
				* of the memory provided in addr */

	uint32_t num; /*!< number of buffers */
	uint32_t size; /*!< size of each buffer. 'size' should include
			* any headroom to be reserved and alignment */
	uint16_t align; /*!< Buffer alignment (in bytes) */
	uint16_t bpid; /*!< The buffer pool id. This will be filled
			*in by DPAA2 for each buffer pool */
	uint16_t meta_data_size; /* Size of inline buf area in buffer */
	uint16_t odp_user_area; /* Size of user private area in buffer */
};

/*!
 * Buffer pool list configuration structure. User need to give DPAA2 the
 * valid number of 'num_buf_pools'.
 */
struct dpaa2_bp_list_cfg {
	uint8_t num_buf_pools; /*!< Number of buffer pools in this
			* buffer pool list */
	struct buf_pool_cfg buf_pool[DPAA2_MAX_BUF_POOLS]; /*!< Configuration
			* of each buffer pool */
};

struct dpaa2_dev;

/*! Buffer structure to contain the packet information. */
struct dpaa2_mbuf {
	/* Cache line 1 */
	uint8_t *data; /*!< Pointer from where the actual data starts. */
	uint8_t *head; /*!< Pointer to head of buffer frame. */
	union {
		uint64_t phyaddr; /*!< Physical address of the start of
				* buffer (head). */
		struct {
			uint8_t notaddr[3]; /*!< Unused */
			uint8_t phaddr[5]; /*!< If address is 40 bits user
					* shall use phaddr. */
		} addr;
	};

	uint64_t hw_annot;/*!< Pointer to store address of hardware annotation
				area. This annotation area contains timestamp,
				parse results etc*/

	uint16_t end_off; /*!< Offset to end of buffer frame from 'head'
			for the current segment. */
	uint16_t priv_meta_off; /*!< Private DPAA2 metadata offset (before the
			* head pointer) - the actual start of frame */
	uint16_t bpid; /*!< Unique identifier representing the buffer pool ID
			* for allocated data of this segment. Should be 0xFFFF
			* (INVALID_BPID) if not from DPAA2 buffer pools. */
	uint16_t flags; /*!< DPAA2 buffer specific system flags */

	uint16_t usr_flags; /*!< DPAA2 buffer user defined flags */

	uint16_t frame_len; /*actual allocated length of the current segment of the packet - usable*/

	uint32_t eth_flags; /*!< Ethernet specific flags. */

	uint32_t tot_frame_len; /*!< Total no of allocated length of the all segments */

	uint32_t hash_val; /*!< Hash value calculated by DPNI for this flow */

	void	 *vq; /*!< VQ on which mbuf is received. It will be populated by
			driver when frame is received. Device can be derived
			from this VQ(valid only for first segment). */

	/* Cache line 2 */
	void *drv_priv_cnxt; /*!< Private context 1 for Driver usage */
	/* Cache line 3 */
	uint64_t buf_pool; /*!< odp buffer pool pointer - only for non packet */

	uint32_t drv_priv_resv[2]; /*!< Private context reserverd for Driver usage usage */
	uint64_t timestamp; /*!< Time stamp on which packet is received. */
	struct dpaa2_mbuf *next_sg; /*!< Pointer to hold list of Scatter/Gather
			* packets. */
	void *user_priv_area; /*!< Private data space location pointer for the user. */
	uint64_t user_cnxt_ptr; /* user context ptr */
	void *atomic_cntxt; /* The Atomic context hold by this buffer */

#ifdef ODP_IPSEC_DEBUG
	void *drv_priv_cnxt1; /*!< Private context 1 for Driver usage */
#endif
} __attribute__((__aligned__(ODP_CACHE_LINE_SIZE)));

typedef struct dpaa2_mbuf *dpaa2_mbuf_pt;

/*!
 * @details	Get the last segment of DPAA2 buffer.
 *
 * @param[in]	mbuf - dpaa2 buffer
 *
 * @returns	last segment of the input dpaa2 buffer.
 *
 */
static inline dpaa2_mbuf_pt dpaa2_mbuf_lastseg(
		dpaa2_mbuf_pt mbuf)
{
	dpaa2_mbuf_pt tmp = mbuf;

	DPAA2_TRACE(BUF);

	if (tmp) {
		while (tmp->next_sg != NULL)
			tmp = tmp->next_sg;
	}

	return tmp;
}

/*!
 * @details	Reset a DPAA2 buffer structure to default values
 *
 * @param[in]	mbuf - dpaa2 buffer
 *
 * @returns	none
 *
 */
static inline void dpaa2_mbuf_reset(
		dpaa2_mbuf_pt mbuf)
{
	struct dpaa2_mbuf *tmp = mbuf;
	DPAA2_TRACE(BUF);
	/* TODO optimize it */
	while (tmp != NULL) {
		/*
		 * Reset parser metadata.  Note that we clear via memset to make
		 * this routine indepenent of any additional adds to packet metadata.
		 */
		const size_t start_offset = ODP_OFFSETOF(struct dpaa2_mbuf, flags);
		const size_t len = ODP_OFFSETOF(struct dpaa2_mbuf, next_sg);
		uint8_t *start;

		start = (uint8_t *)tmp + start_offset;
		memset(start, 0, len - start_offset);

		/* Set metadata items that initialize to non-zero values */
		/* TODO headroom?*/
		tmp->data = tmp->head + dpaa2_mbuf_head_room;
		tmp->frame_len = tmp->end_off - (tmp->head - tmp->data);
		mbuf->tot_frame_len += tmp->frame_len;

		tmp = tmp->next_sg;
	}

	/* reset the the annotation data */
	if (mbuf->priv_meta_off)
		memset(mbuf->head - mbuf->priv_meta_off, 0, mbuf->priv_meta_off);
}

/*!
 * @details	Reset a DPAA2 buffer structure/shell to default values
 *
 * @param[in]	mbuf - dpaa2 buffer
 *
 * @returns	none
 *
 */
static inline void dpaa2_mbuf_shell_reset(
		dpaa2_mbuf_pt mbuf)
{
	DPAA2_TRACE(BUF);

	if (mbuf) {
		memset(mbuf, 0, sizeof(struct dpaa2_mbuf));
		/* Set bpid to a non-valid value */
		mbuf->bpid = INVALID_BPID;
	}
}
/**************************** Configuration API's ****************************/
/*!
 * @details	Configures the DPAA2 buffer library e.g. for SG allocation,
 *		inline dpaa2 buffer allocation etc. This API should be called
 *		once during initialization
 *
 * @param[in]	cfg_flags - Flags for DPAA2 buffer library configuration.
 *		User shall use 'DPAA2_CFG_SG_SUPPORT',
 *		'DPAA2_CFG_ALLOC_INLINE' for cfg_flags
 *
 * @returns	none
 *
 */
void dpaa2_mbuf_lib_config(
		uint32_t cfg_flags);

/*!
 * @details	Initialize a buffer pool list. This API must be
 *		called after an IO context is already affined to the thread
 *		via API dpaa2_thread_affine_io_context().
 *
 * @param[in,out]	bp_list_cfg -  Buffer pool list configuration.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise
 *
 */
void *dpaa2_mbuf_pool_list_init(
		struct dpaa2_bp_list_cfg *bp_list_cfg);


/*!
 * @details	De-initialize the buffer pool list. This will aquire all the
 *		buffers from QBMAN related to the buffer pool list,
 *		so that QBMAN will not have any buffers.
 *
 * @param[in]	bp_list - buffer pool list
 *
 * @returns	none
 *
 */
void dpaa2_mbuf_pool_list_deinit(void *bp_list);

/********************** API's to allocate/free buffers ***********************/
/*!
 * @details	Allocate a DPAA2 buffer of given size from given 'dev'.
 *		If the size is larger than the single available buffer,
 *		Scatter Gather frame will be allocated
 *		(provided support is enabled at 'dpaa2_mbuf_lib_config')
 *		This API must be called after an IO context is already
 *		affined to the thread via API dpaa2_thread_affine_io_context().
 *
 * @param[in]	dev - DPAA2 device. Buffer will be allcoated from the pool
 *		affined to this 'dev'
 *
 * @param[in]	size - the DPAA2 buffer size required.
 *
 * @returns	dpaa2 buffer on success; NULL of failure .
 *
 */
dpaa2_mbuf_pt dpaa2_mbuf_alloc(
		struct dpaa2_dev *dev,
		uint32_t size);

/*!
 * @details	Allocate DPAA2 buffer from given buffer pool.
 *
 * @param[in]	bpid - buffer pool id (which was filled in by DPAA2 at
 *		'dpaa2_mbuf_create_bp_list'
 *
 * @param[in]	length - if single buffer length is greater than the buffer size
 *		it may allocate SG list. length 0 means to allocate buffer
 *		of the size of buffer pool size.
 *
 * @returns	dpaa2 buffer on success; NULL on failure.
 *
 */
dpaa2_mbuf_pt dpaa2_mbuf_alloc_from_bpid(
		uint16_t bpid,
		int length);

/*!
 * @details	Allocate a DPAA2 buffer shell without the data frame.
 *		User may like to allocate dpaa2 buffer shell if he likes to
 *		use his own buffers.
 *
 * @returns	dpaa2 buffer pointer (this will not have the data frame).
 *
 */
static inline dpaa2_mbuf_pt dpaa2_mbuf_alloc_shell(void)
{
	dpaa2_mbuf_pt mbuf;

	DPAA2_TRACE(BUF);

#ifdef DPAA2_MBUF_MALLOC
	mbuf = dpaa2_calloc(NULL, 1, sizeof(struct dpaa2_mbuf), 0);
#else
	mbuf = (dpaa2_mbuf_pt)dpaa2_mpool_getblock(dpaa2_mbuf_shell_mpool, NULL);
#endif
	if (!mbuf) {
		DPAA2_ERR(BUF, "No memory available");
		return NULL;
	}
	mbuf->bpid = INVALID_BPID;
	mbuf->flags = DPAA2BUF_ALLOCATED_SHELL;

	return mbuf;
}

/*!
 * @details	Free a given DPAA2 buffer. This API must be
 *		called after an IO context is already affined to the thread
 *		via API dpaa2_thread_affine_io_context().
 *
 * @param[in]	mbuf - dpaa2 buffer to be freed
 *
 * @returns	none
 *
 */
void dpaa2_mbuf_free(
		dpaa2_mbuf_pt mbuf);

/*!
 * @details	Free a DPAA2 buffer shell without the data frame.
 *
 * @param[in]	mbuf - dpaa2 buffer shell pointer to be freed.
 *
 * @returns	none
 *
 */
void dpaa2_mbuf_free_shell(
		dpaa2_mbuf_pt mbuf);


/*!
 * @details	Free a list of DPAA2 buffers
 *
 * @param[in]	mbuf_list - dpaa2 buffer list to be freed.
 *
 * @param[in]	num - number of buffers in the list to be freed.
 *
 * @returns	none
 *
 */

static inline void
dpaa2_burst_free_bufs(dpaa2_mbuf_pt mbuf_list[], unsigned num)
{
	unsigned i;

	if (mbuf_list == NULL)
		return;

	for (i = 0; i < num; i++) {
		dpaa2_mbuf_free(mbuf_list[i]);
		mbuf_list[i] = NULL;
	}
}

/******************** API's related to headroom/tailroom *********************/
/*!
 * @details	Get the available headroom of that segment
 *
 * @param[in]	mbuf - dpaa2 buffer for which headroom is to be returned.
 *		This can be a SG segment as well.
 *
 * @returns	headroom present in the segment.
 *
 */
static inline int32_t dpaa2_mbuf_headroom(
		dpaa2_mbuf_pt mbuf)
{
	DPAA2_TRACE(BUF);

	return mbuf->data - mbuf->head;
}


/*!
 * @details	Get the available tailroom in the last segment.
 *
 * @param[in]	mbuf - dpaa2 buffer for which tailroom is to be returned.
 *
 * @returns	tailroom present in the segment.
 *
 */
static inline int32_t dpaa2_mbuf_tailroom(
		dpaa2_mbuf_pt mbuf)
{
	dpaa2_mbuf_pt tmp = dpaa2_mbuf_lastseg(mbuf);

	DPAA2_TRACE(BUF);
/*TODO SG support -  difference from current frame to last frame */
	return tmp->end_off - dpaa2_mbuf_headroom(tmp) - tmp->frame_len;
}

/*!
 * @details	Get the tail pointer in the last segment.
 *
 * @param[in]	mbuf - dpaa2 buffer for which tailroom is to be returned.
 *
 * @returns	dpaa2 buffer 'tail' pointer;
 *
 */
static inline uint8_t *dpaa2_mbuf_tail(
		dpaa2_mbuf_pt mbuf)
{
	dpaa2_mbuf_pt tmp = dpaa2_mbuf_lastseg(mbuf);

	DPAA2_TRACE(BUF);

	return tmp->data + tmp->frame_len;
}

/*!
 * @details	Reserve the headroom with offset provided by moving the
 *		data pointer
 *
 * @param[in]	mbuf - dpaa2 buffer on which headroom is to be reserved
 *
 * @param[in]	length - the length by which the headroom which be reserved
 *
 * @returns	none
 *
 */
static inline void dpaa2_mbuf_head_reserve(
		dpaa2_mbuf_pt mbuf,
		uint32_t length)
{
	DPAA2_TRACE(BUF);

	mbuf->data += length;
	mbuf->frame_len -= length;
	mbuf->tot_frame_len -= length;
	return;
}

/*!
 * @details	Get the available length in the segment. The available length
 *		is calculated from the 'data' to the 'end' of buffer.
 *
 * @param[in]	mbuf - dpaa2 buffer for which available length is returned.
 *
 * @returns	length availbale in the segment.
 *
 */
static inline int dpaa2_mbuf_avail_len(
		dpaa2_mbuf_pt mbuf)
{
	DPAA2_TRACE(BUF);

	return mbuf->end_off - dpaa2_mbuf_headroom(mbuf);
}



/***************** API's to pull, push, put, trim and merge ******************/
/*!
 * @details	This will move the 'data' pointer backwards by given offset.
 *		It will also update the packet length ('tot_frame_len' and 'length')
 *		and will return the updated data pointer (from dpaa2 buffer).
 *		User shall write his data at the returned pointer.
 *		This API shall be used if user requires to add data at the
 *		start of the buffer frame ('data' pointer in dpaa2 buffer).
 *		User will call our API providing the mbuf and the length
 *		(as 'offset') which he intends to write, and we will return the
 *		updated 'data' pointer to the user; also updating the 'tot_len'
 *		and 'length'
 *
 * @param[in]	mbuf - dpaa2 buffer
 *
 * @param[in]	length - The length which user intends to write or to shift the
 *		'data' pointer backwards
 *
 * @returns	updated dpaa2 buffer 'data' pointer;
 *		NULL if no headroom available.
 *
 */
static inline uint8_t *dpaa2_mbuf_push(
		dpaa2_mbuf_pt mbuf,
		int32_t length)
{
	DPAA2_TRACE(BUF);

	if (length > dpaa2_mbuf_headroom(mbuf)) {
		DPAA2_WARN(BUF, "Not enough headroom");
		return NULL;
	}

	mbuf->data -= length;
	mbuf->frame_len += length;
	mbuf->tot_frame_len += length;

	return mbuf->data;
}

/*!
 * @details	Forward the 'data' by given offset. This will also update
 *		the 'tot_len' and 'length' present in the dpaa2 buffer.
 *
 * @param[in]	mbuf - dpaa2 buffer
 *
 * @param[in]	length - length by which the user wants the data pointer
 *		to be shifted.
 *
 * @returns	updated dpaa2 buffer 'data' pointer
 *
 */
static inline uint8_t *dpaa2_mbuf_pull(
		dpaa2_mbuf_pt mbuf,
		uint32_t length)
{
	DPAA2_TRACE(BUF);

	mbuf->data += length;

	mbuf->frame_len -= length;
	mbuf->tot_frame_len -= length;
	return mbuf->data;
}

/*!
 * @details	Append the data length by given offset. The length will be
 *		appended in the last segment of the buffer. 'length' of the
 *		last SG entry will be updated as well as 'tot_len' will be
 *		updated. 'tail' pointer of the last dpaa2 buffer segment will be
 *		returned where user can write his data.
 *		(here 'tail' will be 'data' + original_length of last segment)
 *
 * @param[in]	mbuf - dpaa2 buffer
 *
 * @param[in]	length - length which needs to be added into the buffer.
 *
 * @param[in]	if alloc is set and current buffer do not have space,  alloc the new segment.
 *
 * @returns	'tail' pointer of the last dpaa2 buffer;
 *		NULL if no tailroom available
 *
 */
static inline uint8_t *dpaa2_mbuf_push_tail(
		dpaa2_mbuf_pt mbuf,
		uint32_t length,
		uint8_t alloc)
{
	dpaa2_mbuf_pt tmp;
	uint8_t *tail;

	DPAA2_TRACE(BUF);

	/* Get the last segment */
	tmp = dpaa2_mbuf_lastseg(mbuf);

	tail = tmp->data + tmp->frame_len;
	if (dpaa2_mbuf_tailroom(tmp) < (int32_t)length) {
		if (alloc) {
			DPAA2_WARN(BUF, "Alloc not supported - No tailroom");
			return NULL;
		} else {
			DPAA2_WARN(BUF, "Not enough tailroom");
			return NULL;
		}
	}

	tmp->frame_len += length;
	tmp->tot_frame_len += length;
	return tail;
}

/*!
 * @details	Trim the DPAA2 buffer by given size.
 *
 * @param[in]	mbuf - dpaa2 buffer
 *
 * @param[in]	length - length by which the buffer is to be trimmed
 *
 * @param[in]	free_extra - free the remaining segments if any
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise
 *
 */
int dpaa2_mbuf_pull_tail(
		dpaa2_mbuf_pt mbuf,
		uint32_t length,
		uint8_t free_extra);

/**
 * mbuf offset pointer
 *
 * Returns pointer to data in the packet offset. Optionally (in non-null inputs)
 * outputs handle to the segment and number of data bytes in the segment following the
 * pointer.
 *
 * @param      mbuf     Mbuf handle
 * @param      offset   Byte offset into the packet
 * @param[out] len      Number of data bytes remaining in the segment (output).
 *                      Ignored when NULL.
 * @param[out] seg      Handle to the segment containing the address (output).
 *                      Ignored when NULL.
 *
 * @return data Pointer to the offset
 * @retval NULL  Requested offset exceeds packet length
 */
uint8_t *dpaa2_mbuf_offset(dpaa2_mbuf_pt mbuf, uint32_t offset, uint32_t *len,
			dpaa2_mbuf_pt *seg);



/********************* API's related to dpaa2 buffer copy *********************/
/*!
 * @details	Make a complete copy of given DPAA2 buffer
 *
 * @param[out]	to_buf - DPAA2 buffer on which the 'from_buffer' is copied.
 *		'to_buf' should already have the buffer frames in it, and thus
 *		no new frame from any buffer pool will be allocated inside
 *		the function.
 *
 * @param[in]	from_buf - DPAA2 buffer which needs to be copied.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise
 *
 */
int dpaa2_mbuf_copy(
		dpaa2_mbuf_pt to_buf,
		dpaa2_mbuf_pt from_buf);

/*!
 * @details	Fill in the DPAA2 buffer with the data provided.
 *		This will also handle SG (in case SG is enabled).
 *		This API will overwrite any old data and will start
 *		writing from the data pointer
 *
 * @param[in]	mbuf - dpaa2 buffer on which the data is to be copied.
 *		This can also be a SG buffer
 *
 * @param[in]	data - data pointer from where copy has to be made
 *
 * @param[in]	offset - the offset of data to be copied
 *
 * @param[in]	length - the length of data to be copied
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise
 *
 */
int dpaa2_mbuf_data_copy_in(
		dpaa2_mbuf_pt mbuf,
		const uint8_t *data,
		uint32_t offset,
		uint32_t length);

/*!
 * @details	Copy the data from the DPAA2 buffer.
 *		This will also handle SG (in case SG is enabled).
 *
 * @param[in]	mbuf - dpaa2 buffer from where the data is to be copied.
 *		This can also be a SG buffer
 *
 * @param[in]	data - data pointer to which copy has to be made
 *
 * @param[in]	offset - the offset of data to be copied
 *
 * @param[in]	length - the length of data to be copied
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise
 *
 */
int dpaa2_mbuf_data_copy_out(
		dpaa2_mbuf_pt mbuf,
		uint8_t *data,
		uint32_t offset,
		uint32_t length);

/****************************** Other DPAA2 API's *****************************/
/*!
 * @details	Get the maximum number of buffer pools
 *
 * @returns	Maximum number of buffer pools available to the user
 *
 */
uint32_t dpaa2_mbuf_get_max_pools(void);


/*!
 * @details	Test if DPAA2 buffer is contiguous (i.e have only one segment).
 *
 * @param[in]	mbuf - dpaa2 buffer
 *
 * @returns	TRUE if dpaa2 buffer is contiguous;
 *		FALSE otherwise
 *
 */
static inline int dpaa2_mbuf_is_contiguous(
		const dpaa2_mbuf_pt mbuf)
{
	DPAA2_TRACE(BUF);

	return mbuf->next_sg ? FALSE : TRUE;
}


/*!
 * @details	Get the start of the frame (addr) of a segment
 *
 * @param[in]	mbuf - dpaa2 buffer
 *
 * @returns	Frame address (start of buffer)
 *
 */
static inline uintptr_t dpaa2_mbuf_frame_addr(
		const dpaa2_mbuf_pt mbuf)
{
	DPAA2_TRACE(BUF);

	return (uintptr_t)(mbuf->head - mbuf->priv_meta_off);
}


/**
 * @details	Tests if buffer is valid
 *
 * @param[in]	mbuf - DPAA2 buffer pointer
 *
 * @return	TRUE if valid, otherwise FALSE
 */
static inline int dpaa2_mbuf_is_valid(const dpaa2_mbuf_pt mbuf)
{
	/*todo - need more checks for buffer validity*/
	if (mbuf->data && mbuf->head)
		return TRUE;
	return FALSE;
}


/*!
 * @details	Dump DPAA2 buffer and its data
 *
 * @param[in]	stream - out device (file or stderr, stdout etc).
 *
 * @param[in]	mbuf - dpaa2 buffer
 *
 * @returns	none
 *
 */
void dpaa2_mbuf_dump_pkt(
		void *stream,
		dpaa2_mbuf_pt mbuf);


/*!
 * @details	Clean-up routine for DPAA2 buffer library. This API must be
 *		called after an IO context is already affined to the thread
 *		via API dpaa2_thread_affine_io_context().
 *
 * @returns	none
 *
 */
void dpaa2_mbuf_finish(void);


#ifdef __cplusplus
}
#endif

/*! @} */
#endif	/* _DPAA2_MBUF_H_ */
