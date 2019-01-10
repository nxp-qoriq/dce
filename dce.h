/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#ifndef __DCE_H
#define __DCE_H

#include <fsl_qbman_base.h>
#include "dce-fd.h"
#include "dce-fd-frc.h"
#include <semaphore.h>

/**
 * DOC: The DCE API - A simplified interface to Decompression Compression Engine
 *
 * DOC: Goal:
 *  This API was designed to simplify interaction with DCE as much as possible
 *  without loss of flexibility and acceleration offered by DCE hardware
 *
 * DOC: Theory of operation:
 *  A DPIO and a DPDCEI are made available to an application. Both are HW
 *  resources and are managed by the Management Complex (MC). Only privileged
 *  software is allowed to request such resources from the MC so usually this is
 *  done outside of the application at bootup time using dpl.dtb or after bootup
 *  using restool
 *
 *  The application uses the DPIO information to setup a software portal
 *  qbman_swp. Portals are very similar to the valve game portal. Anything can
 *  be passed through a portal. They allow the CPUs to TX and RX with HW
 *  accelerators including SEC for encryption, DCE for (de)compression
 *
 *  The application then sets up the DPDCEI using dpdcei_activate(). A DPDCEI
 *  represents a multi lane assembly line. All items placed on this assembly
 *  line will be either compressed or decompressed depending on the type of
 *  DPDCEI. The finished products are then sent back to a done queue. The CPU
 *  can then use the DPIO to pull in finished work from the DPDCEI finished
 *  queue
 *
 *  A dpdcei_lane represents a lane within a DPDCEI (assembly line). e.g. One
 *  lane can do GZIP compression the other can do ZLIB compression. All
 *  operations sent to a particular lane will be processed in order, but one
 *  lane can get ahead of the other. If an `issue' occurs in a particular lane
 *  only that lane is affected. All other lanes continue. Once the application
 *  resolves the `issue' the lane can continue work
 */

/**
  * enum lane_paradigm - The way to handle multi-frame requests
  * @DCE_STATELESS:	All operations will be self contained
  *			i.e. flush = FINISH for all
  * @DCE_STATEFUL_RECYCLE:	Operations maybe inter-related
  *				i.e. flush can be = NO_FLUSH
  */
enum lane_paradigm {
	DCE_STATELESS = 0,
	/* DCE_STATEFUL_TRUNCATION = 1, This mode is not longer supported*/
	DCE_STATEFUL_RECYCLE = 2
};

/**
 * enum lane_compression_format - The compression formats supported by DCE
 * @DCE_CF_DEFLATE:	Raw deflate, see RFC 1951
 * @DCE_CF_ZLIB:	zlib, see RFC 1950
 * @DCE_CF_GZIP:	gzip, see RFC 1952
 */
enum lane_compression_format {
	DCE_CF_DEFLATE = 0,
	DCE_CF_ZLIB = 1,
	DCE_CF_GZIP = 2
};

/**
 * enum lane_compression_effort - Level of compression to perform
 * @DCE_CE_NONE:	No compression, just add appropriate headers
 * @DCE_CE_STATIC_HUFF_STRMATCH:	Static Huffman & string matching
 * @DCE_CE_HUFF_ONLY:	Huffman only
 * @DCE_CE_BEST_POSSIBLE:	Best possible compression
 */
enum lane_compression_effort {
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
 * struct lane_gz_header - gzip header and state for gzip streams
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
struct lane_gz_header {
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

/* dpdcei_lane is kept private and should not be accessed by applications of the
 * dce.h header */
struct dpdcei_lane;

typedef void *(*dma_alloc)(void *opaque, size_t align, size_t size);
typedef void (*dma_free)(void *opaque, void *address);

/**
 * struct dce_dpdcei_params - parameters
 * @dpdcei_id:	id of the dpdcei object to activate
 * @mcp:	Management Complex portal to issue dpdcei commands
 * @dma_alloc:	Function allocates memory accessible by dpdcei & dpio devices
 * @dma_free:	Function frees memory that was dma_alloc()ed
 * @dma_opaque:	pointer passed as as to the dma_alloc() and dma_free() functions
 */
struct dce_dpdcei_params {
	int dpdcei_id;
	struct fsl_mc_io * mcp;
	dma_alloc dma_alloc;
	dma_free dma_free;
	void *dma_opaque;
};

/**
 * struct dpdcei_lane_params - parameters used in initialisation of dpdcei_lane
 * @swp:	The software portal to use during setup
 * @dma_alloc:	Function allocates memory accessible by dpdcei & dpio devices
 * @dma_free:	Function frees memory that was dma_alloc()ed
 * @dma_opaque:	Pointer passed as as to the dma_alloc() and dma_free() functions
 * @dpdcei:	The dpdcei device on which to transmit work
 * @max_in_flight:	The max number of in flight work allowed on this lane
 * @paradigm:	stateful_recycle, or stateless
 * @compression_format:	gzip, zlib, or DEFLATE without zlib or gzip headers
 * @compression_effort:	Compression effort from none to best possible
 * @member_continue:	whether to continue decompression at stream end
 * @gz_header:	Pointer to gzip header. Valid in gzip mode only
 * @encode_base_64: The input data is 64 bit encoded
 */
struct dpdcei_lane_params {
	/* Software portal to send data to DCE */
	struct qbman_swp *swp;

	/* Functions that allocate aligned dma accessible memory. In Linux user
	 * space this likely means using vfio or a similar structure to add
	 * memory pages to the vfio group to which the dpdcei and the dpio
	 * devices belong thus allowing both of these devices to access memory
	 * populated by the user to complete compression/decompression tasks */
	dma_alloc dma_alloc;
	dma_free dma_free;
	void *dma_opaque;

	/* dpdcei, a DCE FIFO queue. Many dpdcei can share a single dpio.
	 * Work can be sent to a single dpdcei from multiple dpio. The dpdcei
	 * object properties determines the type of DCE operation compression
	 * or decompression.
	 * The dpdcei object properties determine which dpio will be used to
	 * receive frames from this dpdcei */
	struct dpdcei *dpdcei;

	/* The maximum number of in flight work that is expected to be submitted
	 * to this lane. The number determines the amount of memory that will be
	 * allocated from the dma_alloc() function to maintain in flight state.
	 * The in flight count is incremented when work is enqueue()ed and
	 * decremented when work is dequeue()d */
	unsigned int max_in_flight;

	/* stateful_recycle, or stateless */
	enum lane_paradigm paradigm;

	/* gzip, zlib, deflate */
	enum lane_compression_format compression_format;

	/* Compression effort */
	enum lane_compression_effort compression_effort;

	/* Relevant in decompression only. Determines whether DCE will continue
	 * to decompress after the end of a stream encountered in the middle of
	 * input data. Set `false' the DCE will restur MEMBER_END_SUSPEND when
	 * it encounters the end of a stream mid-input. Set true and DCE will
	 * decompress data all the way to the end of input
	 *
	 * NOTE: The standard software zlib behaviour is to stop decompression
	 * once an end of stream is encountered regardless if extra data is
	 * available in input
	 *
	 * NOTE: if member_continue is set to `true' the decompresser will write
	 * all output data to the output buffer without delimiting the end of
	 * each stream
	 *
	 * NOTE: In stateless use. The behaviour of this option differs between
	 * LX2160 SOCs and earlier SOCs. Earlier SOCs will ignore this setting
	 * and always decompress the entire input */
	bool member_continue;

	/* NOTE: Valid in gzip mode. Should be NULL in all other modes
	 *
	 * Compression:
	 * Pointer to gzip header with appropriate values to use for setting up
	 * gzip member headers
	 *
	 * Decompression:
	 * Pointer to gzip struct in which to place read headers NB: Header must
	 * persist until lane_destroy() */
	struct lane_gz_header *gz_header;

	/* lane will handle 64 bit encoded data */
	bool encode_base_64;
};

/* struct dpdcei is opaque to the applications of dce.h. Defined in the
 * implementation in dce-internals.h */
struct dpdcei;

struct dpdcei *dce_dpdcei_activate(struct dce_dpdcei_params *params);

void dce_dpdcei_deactivate(struct dpdcei *dpdcei);

bool dpdcei_is_compression(struct dpdcei *dpdcei);

int dpdcei_todo_queue_count(struct qbman_swp *swp,
					 struct dpdcei *dpdcei);

int dpdcei_done_queue_count(struct qbman_swp *swp,
					 struct dpdcei *dpdcei);

/* struct dpdcei_lane is opaque to the applications of dce.h. Defined in the
 * implementation in dce-internals.h */
struct dpdcei_lane;

/**
 * dpdcei_lane_create() - Initialise a lane for compression or decompression
 * @lane:	Pointer to a lane struct to be initialised
 * @params:	Pointer to a params struct to be used in configuring the lane
 *
 * Contextual information is stored opaquely in the lane object, such as the
 * buffer pool id to use for getting buffers, the gzip header pointer to info
 * such as the ID1 ID2 CM FLG MTIME XFL OS fields. A lane is setup then used
 * to send many requests to DCE
 *
 * Return:	0 on success, error otherwise
 */
struct dpdcei_lane *dpdcei_lane_create(struct dpdcei_lane_params *params);



/**
 * dpdcei_lane_destroy() - cleanup and release resources held by lane
 * @lane:	Pointer to a lane to be retired
 *
 * This function checks for work units in flight and makes sure that there is no
 * attempt to cleanup a lane while there is still work in flight
 *
 * Return:	0 on success, -EBUSY if there is still work in progress
 */
int dpdcei_lane_destroy(struct dpdcei_lane *lane);

struct dce_op_frame_list_tx {
	struct dpaa2_fd frame_list;
	void *user_context;
};

/**
 * struct dce_op_fd_pair_tx - A DCE operation request in the dpaa2 frame
 *			    descriptor format
 *
 * @input_fd:	Pointer to a FD that contains the input data
 * @output_fd:	Pointer to a FD that has the output buffer. If FD format is
 *		dpaa2_fd_null then the buffer pool(s) associated with the
 *		@lane on which the op is enqueued are used to acquire buffers as
 *		necessary for output
 * @flush:	Flush behaviour for the request using zlib semantics
 * @user_context: Pointer returned as is once the operation is complete. This
 *		  can be used to `tag' each op for identification or it can
 *		  point to application context needed for later processing
 *
 *
 * More on @flush
 * The @flush value is ignored for stateless @lane. The @flush value in that
 * case is always assumed to be Z_FINISH by DCE. That is because in
 * DCE_STATELESS mode there is no state that is preserved from frame to
 * frame. All (de)compression to be done must be completed within a single
 * transaction in that mode. In stateful mode the flush value is used by DCE and
 * results in software zlib semantics
 *
 * More on @initial_frame
 * @initial_frame is ignored in stateless @lane. The @initial_frame value in
 * that case is always assumed to be 'true' by DCE. Initialization of @lane
 * is needed whenever it enters into a terminated state. The @lane is in
 * terminated state initially. It also becomes terminated whenever a frame is
 * sent with a @flush value of 'Z_FINISH' and a STREAM_END status is sent back
 * as a response. SPECIAL NOTE: If @lane is DCE_STATEFUL_RECYCLE and
 * an @initial_frame is rejected by DCE and goes into suspended state then the
 * frame can be corrected (e.g. add more output buffer room) and resent to DCE
 * for processing with @recycled_frame set to 'true'. In that case the
 * @initial_frame must be set to 'true' again, even though we do not want to
 * reinitialise @lane state. The examples below clarify this parameter
 *
 * e.g. DCE_STATELESS @lane
 * Every dce_process_frame call is a complete integral number of DEFLATE
 * stream(s). DCE assumes @initial_frame is true and @flush is Z_FINISH for all
 * frames
 *
 * e.g. DCE_STATEFUL_RECYCLE @lane
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
 * for rejection is fixed. This flag is only relevant when the @lane is in
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
 */
struct dce_op_fd_pair_tx {
	struct dpaa2_fd *input_fd;
	struct dpaa2_fd *output_fd;
	enum dce_flush_flag flush;
	void *user_context;
};

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
 * struct dce_op_fd_pair_rx - Container to receive DCE operation response
 *
 * @input_fd:	Copy out of input FD. Can be set to NULL if no copy needed
 * 		Note: the input data itself is not copied out, rather the, input
 * 		FD 32 bytes are copied which point to the input buffer
 * @output_fd:	Copy out of output FD. Must be valid pointer (i.e. not NULL)
 *		because the out length may not be the same as the length of the
 *		original supplied output buffer length
 * @flush:	Copy out of of the FLUSH flag as supplied during input
 * @user_context: Copy out of the context that was supplied in dce_op_fd_pair_tx
 * 		  This can be used to `tag' each op for identification or it can
 * 		  point to application context needed for later processing
 */
struct dce_op_fd_pair_rx {
	struct dpaa2_fd input_fd;
	struct dpaa2_fd output_fd;
	enum dce_flush_flag flush;
	enum dce_status status;
	size_t input_consumed;
	void *user_context;
};


int lane_enqueue_fd_pair(struct qbman_swp *swp,
			struct dpdcei_lane *lane,
			struct dce_op_fd_pair_tx *op);


/**
 * dce_status_string() - Translate DCE status into human readable string
 * @status:	status received from DCE
 *
 * Return:	String containing human readable DCE status
 */
char *dce_status_string(enum dce_status status);

/**
 * lane_dequeue_fd_pair() - Retrieve any finished work
 * @swp:	Software portal to use for issuing pull command
 * @lane:	Pointer the lane on which to check for frames
 * @ops:	DCE operations. The input data, output buffer, and flags
 * @num_ops:	The number of available ops at dce_ops
 *
 * Return:	number of ops retrieved
 */
int lane_dequeue_fd_pair(struct qbman_swp *swp,
			struct dpdcei_lane *lane,
			struct dce_op_fd_pair_rx *ops,
			unsigned int num_ops);

/*
 * lane_stream_abort() - Exit suspended state by abandoning stream state
 * @lane:	Pointer to a lane struct that is suspended in processing
 *
 * Return:	0 on success,
 *		-EINVAL if the lane is not in suspended state
 */
int lane_stream_abort(struct dpdcei_lane *lane);

/*
 * lane_stream_continue() - Exit suspended state by resuming current stream
 * @lane:	Pointer to a lane struct that is suspended in processing
 *
 * Return:	0 on success,
 *		-EINVAL if the lane is not in suspended state
 */
int lane_stream_continue(struct dpdcei_lane *lane);

/*
 * lane_recycle_discard() - Signal to a stateful lane that an operation will
 *			   not be recycled
 *
 * @lane:	Pointer to a lane struct that has been suspended due to an
 *		operation returned with one of the following status codes:
 *
 *		OUTPUT_BLOCKED_SUSPEND
 *		ACQUIRE_DATA_BUFFER_DENIED_SUSPEND
 *		ACQUIRE_TABLE_BUFFER_DENIED_SUSPEND
 *		MEMBER_END_SUSPEND
 *		Z_BLOCK_SUSPEND
 *		OLL_REACHED_SUSPEND
 *
 *		All operations on this @lane that follow an operation with
 *		one of the above status codes will be SKIPPED by DCE and
 *		returned as is
 *
 * Return:	0 if there are more operations to recycle/discard
 *		1 if there are no more ops to recycle/discard
 *		-EINVAL if the lane is not in suspended state
 */
int lane_recycle_discard(struct dpdcei_lane *lane);

/*
 * lane_recycle_fd_pair() - re-send a suspended or skipped operation
 * @swp:	Software portal to use for enqueuing the recycled fd
 * @lane:	Pointer to a lane struct that has been suspended due to an
 *		operation returned with one of the following status codes:
 *
 *		OUTPUT_BLOCKED_SUSPEND
 *		ACQUIRE_DATA_BUFFER_DENIED_SUSPEND
 *		ACQUIRE_TABLE_BUFFER_DENIED_SUSPEND
 *		MEMBER_END_SUSPEND
 *		Z_BLOCK_SUSPEND
 *		OLL_REACHED_SUSPEND
 *
 *		All operations on this @lane that follow an operation with
 *		one of the above status codes will be SKIPPED by DCE and
 *		returned as is
 * @op:		Pointer to a tx op struct that substitutes a _SUSPEND or SKIPPED
 *
 * Return:	0 if there are more operations to recycle/discard
 *		1 if there are no more ops to recycle/discard
 *		-EINVAL if the lane is not in suspended state
 */
int lane_recycle_fd_pair(struct qbman_swp *swp,
			 struct dpdcei_lane *lane,
			 struct dce_op_fd_pair_tx *op);

/**
 * lane_gz_header_update() - Notify lane of a gzip header update
 * @lane: Pointer to a lane struct that must be notified of the header
 *	     update
 *
 * This function is only valid for Compression lanes
 *
 * Return: 0 on success,
 *	   -EBUSY if the device is busy and call must be reattempted
 *	   -EINVAL if the lane is not in gzip mode, is a decompression
 *	   lane, or a stateless compression lane. For stateless
 *	   compression lanes the gzip header will be updated automatically
 *	   with every call to dce_enqueue*()
 */
int lane_gz_header_update(struct dpdcei_lane *lane);





#endif /* __DCE_H */
