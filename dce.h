/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#ifndef __DCE_H
#define __DCE_H

#include <fsl_qbman_base.h>
#include "dpdcei-drv.h"
#include "dce-fd.h"
#include "dce-fd-frc.h"
#include <semaphore.h>
#include <circ_fifo.h>

/**
 * DOC: The DCE API - A simplified interface to DCE
 *
 * DOC: Goal:
 *  This API was designed to simplify interaction with DCE as much as possible
 *  without loss of flexibility and acceleration offered by DCE hardware
 *
 * DOC: Theory of operation:
 *  A user creates a session object to process multiple pieces of similar data
 *  on DCE.  All subsequent interaction is done through this session. One
 *  session can be used concurrently, if order is not necessary. Multiple
 *  sessions can be used simultaneously
 */

/**
 * enum dce_engine - The engine to use for session operations
 * @DCE_COMPRESSION:	Compression engine
 * @DCE_DECOMPRESSION:	Decompression engine
 */
enum dce_engine {
	DCE_COMPRESSION,
	DCE_DECOMPRESSION
};

/**
  * enum dce_paradigm - The way to handle multi-frame requests
  * @DCE_STATELESS:	All operations will be self contained
  *			i.e. flush = FINISH for all
  * @DCE_STATEFUL_RECYCLE:	Operations maybe inter-related
  *				i.e. flush can be = NO_FLUSH
  */
enum dce_paradigm {
	DCE_STATELESS = 0,
	/* DCE_STATEFUL_TRUNCATION = 1, This mode is not longer supported*/
	DCE_STATEFUL_RECYCLE = 2
};

/**
 * enum dce_compression_format - The compression formats supported by DCE
 * @DCE_CF_DEFLATE:	Raw deflate, see RFC 1951
 * @DCE_CF_ZLIB:	zlib, see RFC 1950
 * @DCE_CF_GZIP:	gzip, see RFC 1952
 */
enum dce_compression_format {
	DCE_CF_DEFLATE = 0,
	DCE_CF_ZLIB = 1,
	DCE_CF_GZIP = 2
};

/**
 * enum dce_compression_effort - Level of compression to perform
 * @DCE_CE_NONE:	No compression, just add appropriate headers
 * @DCE_CE_STATIC_HUFF_STRMATCH:	Static Huffman & string matching
 * @DCE_CE_HUFF_ONLY:	Huffman only
 * @DCE_CE_BEST_POSSIBLE:	Best possible compression
 */
enum dce_compression_effort {
	DCE_CE_NONE = 0,
	DCE_CE_STATIC_HUFF_STRMATCH = 1,
	DCE_CE_HUFF_ONLY = 2,
	DCE_CE_BEST_POSSIBLE = 3,
};

/**
 * enum dce_flush_flag - Data flushing modes
 * @DCE_Z_NO_FLUSH:		equivalent to Z_NO_FLUSH
 * @DCE_Z_PARTIAL_FLUSH:	equivalent to Z_PARTIAL_FLUSH
 * @DCE_Z_SYNC_FLUSH:		equivalent to Z_SYNC_FLUSH
 * @DCE_Z_FULL_FLUSH:		equivalent to Z_FULL_FLUSH
 * @DCE_Z_FINISH:		equivalent to Z_FINISH
 * @DCE_Z_BLOCK:		equivalent to Z_BLOCK
 * @DCE_Z_TREES:		equivalent to Z_TREES
 *
 * These flush parameters are parallel to the zlib standard
 */
enum dce_flush_flag {
	DCE_Z_NO_FLUSH = 0x0,
	DCE_Z_PARTIAL_FLUSH = 0x1,
	DCE_Z_SYNC_FLUSH = 0x2,
	DCE_Z_FULL_FLUSH = 0x3,
	DCE_Z_FINISH = 0x4,
	DCE_Z_BLOCK = 0x5,
	DCE_Z_TREES = 0x6
};

/**
 * struct dce_gz_header - gzip header and state for gzip streams
 * @text:	True if compressed data is believed to be text
 * @time:	Modification time
 * @xflags:	Extra flags indicating compression level (not used when
 *		writing a gzip file)
 * @os:		operating system
 * @meta_data:	Contiguous memory for storing meta data like name and comment
 * @extra_len:	`extra' field length
 * @name_len:	`name' field length
 * @comment_len:	`comment' field length
 * @meta_max:	Space available at meta_data
 * @hcrc:	true if there was or will be a header crc
 * @done:	true when done reading gzip header
 *
 * The gzip compression format documented in RFC 1952 includes a header for each
 * gzip member.
 */
struct dce_gz_header {
	bool text; /* True if compressed data believed to be text */
	uint32_t mtime; /* Modification time in seconds since 1970 */
	uint8_t xflags; /* Extra flags indicating compression level (not used
			   when writing a gzip file) */
	uint32_t os; /* operating system */
	dma_addr_t meta_data; /* Compression: dma to `extra' field, followed by
				 `name' field, followed by `comment' field.
				 `name' and `comment' fields must be zero
				 terminated.  meta_data must be set to NULL if
				 none of the fields are present
				 Decompression: dma to `extra' field, `name'
				 field, and comment field. meta_data must be
				 set to NULL if fields are not needed. Fields
				 will be discarded */
	size_t extra_len; /* Compression: `extra' field length in meta_data
			     Decompression: Length of the `extra' field
			     (meta_data must != NULL) */
	size_t name_len; /* Compression: `name' field length in meta_data
			    Decompression: Length of the `name' field
			    (meta_data must != NULL) */
	size_t comment_len; /* Compression: `comment' field length in meta_daata
			       Decompression: Length of the `comment' field
			       (meta_data must != NULL) */
	size_t meta_max; /* Space at meta_data (when reading header) */
	bool hcrc; /* true if there was or will be a header crc */
	bool done; /* true when done reading gzip header (not used when writing
		      a gzip file) */
};

struct dce_session;

/**
 * \typedef dce_session_notification
 * \brief A one time call back to notify a session that work is finished
 * @session:	Pointer to session that owns the finished work
 *
 * Note:
 * This context should be treated as atomic. No work should be done in this
 * context. An application thread should call dce_receive_frames() or
 * dce_receive_data() to receive the finished work
 *
 * This notificication mechanism is optional. An application can poll
 * dce_receive_*() if minimizing latency is prioritized over efficiency
 *
 * there can be many finished work items available. This notification is
 * activated only once and does not trigger again until the user re-enables
 * the notification using dce_session_notification_arm()
 */
typedef void (*dce_session_notification)(void *context);

/**
 * struct dce_session_params - parameters used in initialisation of dce_session
 * @engine	: compression or decompression
 * @paradigm	: stateful_recycle, stateful_truncate, or stateless
 * @compression_format	: gzip, zlib, deflate
 * @compression_effort	: compression effort from none to best possible
 * @gz_header	: Pointer to gzip header. Valid in gzip mode only
 * @work_done_callback	: Optional. User defined work done notification. Should
 *			  be set to NULL if unused
 */

struct dce_session_params {
	/* Software portal to send data to DCE. Should be the same as the portal
	 * specified in the dpdcei object creation in most cases */
	struct dpaa2_io *dpio;

	/* dpdcei, a DCE FIFO queue. Many dpdcei can share a single dpio.
	 * Work can be sent to a single dpdcei from multiple dpio. The dpdcei
	 * object properties determines the type of DCE operation compression
	 * or decompression.
	 * The dpdcei object properties determine which dpio will be used to
	 * receive frames from this dpdcei */
	struct dpdcei *dpdcei;

	/* stateful_recycle, stateful_truncate, or stateless */
	enum dce_paradigm paradigm;

	/* gzip, zlib, deflate */
	enum dce_compression_format compression_format;

	/* compression effort */
	enum dce_compression_effort compression_effort;

	/* NOTE: Valid in gzip mode. Should be NULL in all other modes
	 *
	 * Compression:
	 * Pointer to gzip header with appropriate values to use for setting up
	 * gzip member headers
	 *
	 * Decompression:
	 * Pointer to gzip struct in which to place read headers NB: Header must
	 * persist until session_destroy() */
	struct dce_gz_header *gz_header;

	/* session will handle 64 bit encoded data */
	bool encode_base_64;

	/* User defined notification that work is available to be dequeued */
	dce_session_notification work_done_callback;
};

/* FIXME: these two structs were originally in the dce.c moved here because I
 * needed to declare the struct in my application that uses dce. Not sure if
 * there is a better way that allows the application to struct the objects */
struct dma_hw_mem {
	void *vaddr;
	size_t len;
	dma_addr_t paddr;
};

/* dce_session - struct used to keep track of session state. This struct is not
 * visible to the user */
struct dce_session {
	struct dpaa2_io *dpio;
	enum dce_paradigm paradigm;
	enum dce_compression_format compression_format;
	enum dce_compression_effort compression_effort;
	struct dce_gz_header gz_header;
	unsigned buffer_pool_id;
	unsigned buffer_pool_id2;
	bool release_buffers;
	bool encode_base_64;
	uint8_t state;
	bool recycle;
	bool recycler_allowed;
	struct dpdcei *dpdcei;
	struct dce_flow flow;
	struct circ_fifo fifo;
	struct dma_hw_mem pending_output;
	struct dma_hw_mem history;
	struct dma_hw_mem decomp_context;
	bool notify_arm;
	void *notification_context;
	dce_session_notification work_done_callback;
	unsigned int recycle_todo;
	pthread_mutex_t lock;
	sem_t enqueue_sem;
};

/**
 * dce_session_create() - Initialise a session for compression or decompression
 * @session:	Pointer to a session struct to be initialised
 * @params:	Pointer to a params struct to be used in configuring the session
 *
 * Contextual information is stored opaquely in the session object, such as the
 * buffer pool id to use for getting buffers, the gzip header pointer to info
 * such as the ID1 ID2 CM FLG MTIME XFL OS fields. A session is setup then used
 * to send many requests to DCE
 *
 * Return:	0 on success, error otherwise
 */
int dce_session_create(struct dce_session *session,
		       struct dce_session_params *params);

enum dce_status {
	FULLY_PROCESSED				= 0x00,
	STREAM_END				= 0x01,
	INPUT_STARVED				= 0x10,
	MEMBER_END_SUSPEND			= 0x11,
	Z_BLOCK_SUSPEND				= 0x12,
	OUTPUT_BLOCKED_SUSPEND			= 0x14,
	ACQUIRE_DATA_BUFFER_DENIED_SUSPEND	= 0x15,
	ACQUIRE_TABLE_BUFFER_DENIED_SUSPEND	= 0x16,
	OLL_REACHED_SUSPEND			= 0x17,
	OUTPUT_BLOCKED_DISCARD			= 0x24,
	ACQUIRE_DATA_BUFFER_DENIED_DISCARD	= 0x25,
	ACQUIRE_TABLE_BUFFER_DENIED_DISCARD	= 0x26,
	OLL_REACHED_DISCARD			= 0x27,
	HCL_REACHED_DISCARD			= 0x28,
	HCL_RELEASE_ABORTED			= 0x2F,
	SKIPPED					= 0x30,
	PREVIOUS_FLOW_TERMINATION		= 0x31,
	SUSPENDED_FLOW_TERMINATION		= 0x32,
	INVALID_FRAME_LIST			= 0x40,
	INVALID_FRC				= 0x41,
	UNSUPPORTED_FRAME			= 0x42,
	FRAME_TOO_SHORT				= 0x44,
	ZLIB_INCOMPLETE_HEADER			= 0x50,
	ZLIB_HEADER_ERROR			= 0x51,
	ZLIB_NEED_DICTIONARY_ERROR		= 0x52,
	GZIP_INCOMPLETE_HEADER			= 0x60,
	GZIP_HEADER_ERROR			= 0x61,
	DEFLATE_INVALID_BLOCK_TYPE		= 0x70,
	DEFLATE_INVALID_BLOCK_LENGTHS		= 0x71,
	DEFLATE_TOO_MANY_LEN_OR_DIST_SYM	= 0x80,
	DEFLATE_INVALID_CODE_LENGTHS_SET	= 0x81,
	DEFLATE_INVALID_BIT_LENGTH_REPEAT	= 0x82,
	DEFLATE_INVALID_LITERAL_LENGTHS_SET	= 0x83,
	DEFLATE_INVALID_DISTANCES_SET		= 0x84,
	DEFLATE_INVALID_LITERAL_LENGTH_CODE	= 0x85,
	DEFLATE_INVALID_DISTANCE_CODE		= 0x86,
	DEFLATE_INVALID_DISTANCE_TOO_FAR_BACK	= 0x87,
	DEFLATE_INCORRECT_DATA_CHECK		= 0x88,
	DEFLATE_INCORRECT_LENGTH_CHECK		= 0x89,
	DEFLATE_INVALID_CODE			= 0x8A,
	CXM_2BIT_ECC_ERROR			= 0xB0,
	CBM_2BIT_ECC_ERROR			= 0xB1,
	DHM_2BIT_ECC_ERROR			= 0xB2,
	INVALID_BASE64_CODE			= 0xC0,
	INVALID_BASE64_PADDING			= 0xC1,
	SCF_SYSTEM_MEM_READ_ERROR		= 0xD5,
	PENDING_OUTPUT_SYSTEM_MEM_READ_ERROR	= 0xD6,
	HISTORY_WINDOW_SYSTEM_MEM_READ_ERROR	= 0xD7,
	CTX_DATA_SYSTEM_MEM_READ_ERROR		= 0xD8,
	FRAME_DATA_SYSTEM_READ_ERROR		= 0xD9,
	INPUT_FRAME_TBL_SYSTEM_READ_ERROR	= 0xDA,
	OUTPUT_FRAME_TBL_SYSTEM_READ_ERROR	= 0xDB,
	SCF_SYSTEM_MEM_WRITE_ERROR		= 0xE5,
	PENDING_OUTPUT_SYSTEM_MEM_WRITE_ERROR	= 0xE6,
	HISTORY_WINDOW_SYSTEM_MEM_WRITE_ERROR	= 0xE7,
	CTX_DATA_SYSTEM_MEM_WRITE_ERROR		= 0xE8,
	FRAME_DATA_SYSTEM_MEM_WRITE_ERROR	= 0xE9,
	FRAME_TBL_SYSTEM_MEM_WRITE_ERROR	= 0xEA
};



/**
 * dce_session_destroy() - cleanup and release resources held by session
 * @session:	Pointer to a session to be retired
 *
 * This function checks for work units in flight and makes sure that there is no
 * attempt to cleanup a session while there is still work in flight
 *
 * Return:	0 on success, -EBUSY if there is still work in progress
 */
int dce_session_destroy(struct dce_session *session);

int dce_session_notification_arm(struct dce_session *session, void *context);

/**
 * dce_process_frame() - Compress or decompress a frame asynchronously
 * @session:	Pointer to session struct on which to send (de)compress requests

 * @flush:	Flush behaviour for the request using zlib semantics
 * @initial_frame:	(Re)initialise @session state. Discards previous state
 * @recycled_frame:	Frame was previously rejected by DCE. Now it is fixed
 * @context:	Pointer to a caller defined object that is returned in dequeue
 *
 * More on @flush
 * The @flush value is ignored for stateless @session. The @flush value in that
 * case is always assumed to be Z_FINISH by DCE. That is because in
 * DCE_STATELESS mode there is no state that is preserved from frame to
 * frame. All (de)compression to be done must be completed within a single
 * transaction in that mode. In stateful mode the flush value is used by DCE and
 * results in software zlib semantics
 *
 * More on @initial_frame
 * @initial_frame is ignored in stateless @session. The @initial_frame value in
 * that case is always assumed to be 'true' by DCE. Initialization of @session
 * is needed whenever it enters into a terminated state. The @session is in
 * terminated state initially. It also becomes terminated whenever a frame is
 * sent with a @flush value of 'Z_FINISH' and a STREAM_END status is sent back
 * as a response. SPECIAL NOTE: If @session is DCE_STATEFUL_RECYCLE and
 * an @initial_frame is rejected by DCE and goes into suspended state then the
 * frame can be corrected (e.g. add more output buffer room) and resent to DCE
 * for processing with @recycled_frame set to 'true'. In that case the
 * @initial_frame must be set to 'true' again, even though we do not want to
 * reinitialise @session state. The examples below clarify this parameter
 *
 * e.g. DCE_STATELESS @session
 * Every dce_process_frame call is a complete integral number of DEFLATE
 * stream(s). DCE assumes @initial_frame is true and @flush is Z_FINISH for all
 * frames
 *
 * e.g. DCE_STATEFUL_RECYCLE @session
 * We are trying to decompress two DEFLATE streams. Stream A and stream B. We
 * will split each stream into three chunks. A1, A2, A3, B1, B2, B3. Each chunk
 * will be sent to DCE for decompression
 *
 * case 1
 * A1: @initial_frame true. @flush Z_NO_FLUSH. Status returned FULLY_PROCESSED
 * A2: @initial_frame false. @flush Z_NO_FLUSH. Status returned FULLY_PROCESSED
 * A3: @initial_frame false. @flush Z_NO_FLUSH. Status returned FULLY_PROCESSED
 * B1: @initial_frame false. @flush Z_NO_FLUSH. Status returned FULLY_PROCESSED
 * B2: @initial_frame false. @flush Z_NO_FLUSH. Status returned FULLY_PROCESSED
 * B3: @initial_frame false. @flush Z_NO_FLUSH. Status returned FULLY_PROCESSED
 *
 * case 2
 * A1: @initial_frame true. @flush Z_NO_FLUSH. Status returned FULLY_PROCESSED
 * A2: @initial_frame false. @flush Z_NO_FLUSH. Status returned FULLY_PROCESSED
 * A3: @initial_frame false. @flush Z_FINISH. Status returned STREAM_END
 * B1: @initial_frame true. @flush Z_NO_FLUSH. Status returned FULLY_PROCESSED
 * B2: @initial_frame false. @flush Z_NO_FLUSH. Status returned FULLY_PROCESSED
 * B3: @initial_frame false. @flush Z_NO_FLUSH. Status returned FULLY_PROCESSED
 *
 * case 3
 * A1: @initial_frame true. @flush Z_NO_FLUSH. Status OUTPUT_BLOCKED_SUSPEND
 * OUTPUT_BLOCKED_SUSPEND informs us that DCE was able to produce some output,
 * but the output buffer supplied was insufficient to hold all output. We update
 * input pointer by adding @input_consumed returned in DCE callback. This
 * updates the address to point the input that is still to be processed in the
 * frame. We cannot reuse the same output buffer because DCE will overwrite the
 * output that was initially produced. We can either first store that output or
 * supply a new output buffer. Then we send the frame to DCE. NOTE: We set
 * the @initial_frame to 'true' even though this is not truly the first frame.
 * That is because an @initial_frame that causes a "*SUSPEND" state should be
 * recycled while keeping the @initial_frame 'true'
 * Updated A1: @initial_frame true. @recycled_frame true @flush Z_NO_FLUSH.
 *							Status FULLY_PROCESSED
 * A2: @initial_frame false. @flush Z_NO_FLUSH. Status FULLY_PROCESSED
 * A3..B3: same as case 1 or case 2
 *
 * case 4
 * A1: @initial_frame true. @flush Z_NO_FLUSH. Status returned FULLY_PROCESSED
 * A2: @initial_frame false. @flush Z_NO_FLUSH. Status returned FULLY_PROCESSED
 * In this case we did not know where A3 ends and B1 starts so we sent them in
 * one input frame
 * A3B1: @initial_frame false. @flush Z_NO_FLUSH. Status MEMBER_END_SUSPEND
 * MEMBER_END_SUSPEND informs us that a DEFLATE stream end was found in the
 * middle of the input buffer and DCE stopped processing there. This case is
 * handled similarly to case 3, OUTPUT_BLOCKED_SUSPEND. We update the input
 * address to point to the beginning of B1 and send the frame with
 * @recycled_frame true. All DCE "*SUSPEND" status codes are handled this way
 * B1: @initial_frame false. @recycled_frame true. @flush Z_NO_FLUSH.
 *							Status FULLY_PROCESSED
 * B2..B3: same as case 1 or case 2
 *
 * More on @recycled_frame
 * Setting the recycle parameter to true indicates to DCE that the information
 * that is in this frame was previously rejected by DCE for one reason or
 * another. The frame is resent to DCE for processing and the original reason
 * for rejection is fixed. This flag is only relevant when the @session is in
 * DCE_STATEFUL_RECYCLE mode
 *
 * e.g. OUTPUT_BLOCKED_SUSPEND
 * A frame is sent to DCE for processing, but the output buffer provided was
 * insufficient to hold all the output. In this case DCE will produce as much
 * output as it was able to and indicate in the callback function the status
 * OUTPUT_BLOCKED_SUSPEND. The application then must send the rest of the input
 * data that was not processed in the first attempt and provide more output room
 * for the data and it should set @recycled_frame to true
 *
 * More on @context
 * The caller can point context at a meaningful object to allow the user defined
 * callback to take some useful action. e.g. Wakeup a sleeping thread, pass on
 * some information about the destination for the data
 *
 * Return:	0 on success,
 *		-EBUSY if the device is busy and call must be reattempted
 *		-ENOSPC if the maximum number of inflight requests is exceeded
 *		-EACCES if a stateful session has entered recycle mode and must
 *			cleaned up using dce_recycle_*() function
 */
int dce_enqueue_frames(struct dce_session *session,
		      struct dpaa2_fd *input_fd,
		      struct dpaa2_fd *output_fd,
		      enum dce_flush_flag flush,
		      void *context);

struct dce_op_frame_list_tx {
	struct dpaa2_fd frame_list;
	void *user_context;
};

/**
 * struct dce_op_frame_tx - A DCE operation request in the dpaa2 frame
 *			    descriptor format
 *
 * @input_fd:	Pointer to a FD that contains the input data
 * @output_fd:	Pointer to a FD that has the output buffer. If FD format is
 *		dpaa2_fd_null then the buffer pool(s) associated with the
 *		@session are used to acquire buffers as necessary for output
 * @flush:	Flush behaviour for the request using zlib semantics
 * @user_context: Pointer returned as is once the operation is complete. This
 *		  can be used to `tag' each op for identification or it can
 *		  point to application context needed for later processing
 */
struct dce_op_fd_pair_tx {
	struct dpaa2_fd *input_fd;
	struct dpaa2_fd *output_fd;
	enum dce_flush_flag flush;
	void *user_context;
};


struct dce_op_fd_pair_rx {
	struct dpaa2_fd input_fd;
	struct dpaa2_fd output_fd;
	enum dce_flush_flag flush;
	enum dce_status status;
	size_t input_consumed;
	void *user_context;
};



/**
 * dce_process_data() - Compress or decompress arbitrary data asynchronously
 * @session:	Pointer to a session struct on which to send (de)compress
 *		requests
 *
 * Return:	0 on success,
 *		-EBUSY if the device is busy and call must be reattempted
 */
int dce_enqueue_fd_pair(struct dce_session *session,
			struct dce_op_fd_pair_tx *op);


/**
 * dce_status_string() - Translate DCE status into human readable string
 * @status:	status received from DCE
 *
 * Return:	String containing human readable DCE status
 */
char *dce_status_string(enum dce_status status);

/**
 * dce_dequeue_fd_pair() - Retrieve any finished work
 * @session:	Pointer the session on which to poll
 * @ops:	DCE operations. The input data, output buffer, and flags
 * @num_ops:	The number of available ops at dce_ops
 *
 * Return:	number of ops retrieved
 */
int dce_dequeue_fd_pair(struct dce_session *session,
			struct dce_op_fd_pair_rx *ops,
			unsigned int num_ops);

/*
 * dce_stream_abort() - Exit suspended state by abandoning stream state
 * @session:	Pointer to a session struct that is suspended in processing
 *
 * Return:	0 on success,
 *		-EINVAL if the session is not in suspended state
 */
int dce_stream_abort(struct dce_session *session);

/*
 * dce_stream_continue() - Exit suspended state by resuming current stream
 * @session:	Pointer to a session struct that is suspended in processing
 *
 * Return:	0 on success,
 *		-EINVAL if the session is not in suspended state
 */
int dce_stream_continue(struct dce_session *session);

/*
 * dce_recycle_discard() - Signal to a stateful session that an operation will
 *			   not be recycled
 *
 * @session:	Pointer to a session struct that has been suspended due to an
 *		operation returned with one of the following status codes:
 *
 *		OUTPUT_BLOCKED_SUSPEND
 *		ACQUIRE_DATA_BUFFER_DENIED_SUSPEND
 *		ACQUIRE_TABLE_BUFFER_DENIED_SUSPEND
 *		MEMBER_END_SUSPEND
 *		Z_BLOCK_SUSPEND
 *		OLL_REACHED_SUSPEND
 *
 *		All operations on this @session that follow an operation with
 *		one of the above status codes will be SKIPPED by DCE and
 *		returned as is
 *
 * Return:	0 if there are more operations to recycle/discard
 *		1 if there are no more ops to recycle/discard
 *		-EINVAL if the session is not in suspended state
 */
int dce_recycle_discard(struct dce_session *session);

/*
 * dce_recycle_fd_pair() - re-send a suspended or skipped operation
 * @session:	Pointer to a session struct that has been suspended due to an
 *		operation returned with one of the following status codes:
 *
 *		OUTPUT_BLOCKED_SUSPEND
 *		ACQUIRE_DATA_BUFFER_DENIED_SUSPEND
 *		ACQUIRE_TABLE_BUFFER_DENIED_SUSPEND
 *		MEMBER_END_SUSPEND
 *		Z_BLOCK_SUSPEND
 *		OLL_REACHED_SUSPEND
 *
 *		All operations on this @session that follow an operation with
 *		one of the above status codes will be SKIPPED by DCE and
 *		returned as is
 * @op:		Pointer to a tx op struct that substitutes a _SUSPEND or SKIPPED
 *
 * Return:	0 if there are more operations to recycle/discard
 *		1 if there are no more ops to recycle/discard
 *		-EINVAL if the session is not in suspended state
 */
int dce_recycle_fd_pair(struct dce_session *session,
			struct dce_op_fd_pair_tx *op);

/**
 * dce_gz_header_update() - Notify session of a gzip header update
 * @session: Pointer to a session struct that must be notified of the header
 *	     update
 *
 * This function is only valid for Compression sessions
 *
 * Return: 0 on success,
 *	   -EBUSY if the device is busy and call must be reattempted
 *	   -EINVAL if the session is not in gzip mode, is a decompression
 *	   session, or a stateless compression session. For stateless
 *	   compression sessions the gzip header will be updated automatically
 *	   with every call to dce_enqueue*()
 */
int dce_gz_header_update(struct dce_session *session);

#endif /* __DCE_H */
