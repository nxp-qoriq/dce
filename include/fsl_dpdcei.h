/*
 * SPDX-License-Identifier:     BSD-3-Clause
 * Copyright 2013 Freescale Semiconductor, Inc.
 * All rights reserved.
 */
#ifndef __FSL_DPDCEI_H
#define __FSL_DPDCEI_H

/* Data Path DCE Interface API
 * Contains initialization APIs and runtime control APIs for DPDCEI
 */

struct fsl_mc_io;

/** General DPDCEI macros */

/**
 * Indicates an invalid frame queue
 */
#define DPDCEI_FQID_NOT_VALID	(uint32_t)(-1)

/**
 * enum dpdcei_engine - DCE engine block
 * @DPDCEI_ENGINE_COMPRESSION: Engine compression
 * @DPDCEI_ENGINE_DECOMPRESSION: Engine decompression
 */
enum dpdcei_engine {
	DPDCEI_ENGINE_COMPRESSION,
	DPDCEI_ENGINE_DECOMPRESSION
};

/**
 * dpdcei_open() - Open a control session for the specified object
 * @mc_io: Pointer to MC portal's I/O object
 * @cmd_flags: Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDCEI object
 * @dpdcei_id: DPDCEI unique ID
 *
 * This function can be used to open a control session for an
 * already created object; an object may have been declared in
 * the DPL or by calling the dpdcei_create() function.
 * This function returns a unique authentication token,
 * associated with the specific object ID and the specific MC
 * portal; this token must be used in all subsequent commands for
 * this specific object.
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_open(struct fsl_mc_io	*mc_io,
		uint32_t		cmd_flags,
		int			dpdcei_id,
		uint16_t		*token);

/**
 * dpdcei_close() - Close the control session of the object
 * @mc_io: Pointer to MC portal's I/O object
 * @cmd_flags: Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDCEI object
 *
 * After this function is called, no further operations are
 * allowed on the object without opening a new control session.
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_close(struct fsl_mc_io	*mc_io,
		 uint32_t		cmd_flags,
		 uint16_t		token);

/**
 * struct dpdcei_cfg - Structure representing DPDCEI configuration
 * @engine: compression or decompression engine to be selected
 * @priority: Priority for the DCE hardware processing (valid values 1-8).
 *	This is the scheduling priority for traffic going into the accelerator.
 *	For scheduling priority on CPU side, coming back from accelerator, use
 *	dpdcei_set_rx_queue.
 */
struct dpdcei_cfg {
	enum dpdcei_engine	engine;
	uint8_t			priority;
};

/**
 * dpdcei_create() - Create the DPDCEI object
 * @mc_io: Pointer to MC portal's I/O object
 * @dprc_token:	Parent container token; '0' for default container
 * @cmd_flags: Command flags; one or more of 'MC_CMD_FLAG_'
 * @cfg: configuration parameters
 * @obj_id: returned object id
 *
 * Create the DPDCEI object, allocate required resources and
 * perform required initialization.
 *
 * The object can be created either by declaring it in the
 * DPL file, or by calling this function.
 *
 * The function accepts an authentication token of a parent
 * container that this object should be assigned to. The token
 * can be '0' so the object will be assigned to the default container.
 * The newly created object can be opened with the returned
 * object id and using the container's associated tokens and MC portals.
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_create(struct fsl_mc_io	*mc_io,
		  uint16_t		dprc_token,
		uint32_t		cmd_flags,
		const struct dpdcei_cfg	*cfg,
		uint32_t		*obj_id);

/**
 * dpdcei_destroy() - Destroy the DPDCEI object and release all its resources.
 * @mc_io: Pointer to MC portal's I/O object
 * @dprc_token: Parent container token; '0' for default container
 * @cmd_flags: Command flags; one or more of 'MC_CMD_FLAG_'
 * @object_id:	The object id; it must be a valid id within the container that
 * created this object;
 *
 * Return:	'0' on Success; error code otherwise.
 */
int dpdcei_destroy(struct fsl_mc_io	*mc_io,
		   uint16_t		dprc_token,
		   uint32_t		cmd_flags,
		   uint32_t		object_id);

/**
 * dpdcei_enable() - Enable the DPDCEI, allow sending and receiving frames.
 * @mc_io: Pointer to MC portal's I/O object
 * @cmd_flags: Command flags; one or more of 'MC_CMD_FLAG_'
 * @token: Token of DPDCEI object
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_enable(struct fsl_mc_io	*mc_io,
		  uint32_t		cmd_flags,
		  uint16_t		token);

/**
 * dpdcei_disable() - Disable the DPDCEI, stop sending and receiving frames.
 * @mc_io: Pointer to MC portal's I/O object
 * @cmd_flags: Command flags; one or more of 'MC_CMD_FLAG_'
 * @token: Token of DPDCEI object
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_disable(struct fsl_mc_io	*mc_io,
		   uint32_t		cmd_flags,
		   uint16_t		token);

/**
 * dpdcei_is_enabled() - Check if the DPDCEI is enabled.
 * @mc_io: Pointer to MC portal's I/O object
 * @cmd_flags: Command flags; one or more of 'MC_CMD_FLAG_'
 * @token: Token of DPDCEI object
 * @en:	Return '1' for object enabled/'0' otherwise
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_is_enabled(struct fsl_mc_io	*mc_io,
		      uint32_t		cmd_flags,
		      uint16_t		token,
		      int		*en);

/**
 * dpdcei_reset() - Reset the DPDCEI, returns the object to initial state.
 * @mc_io: Pointer to MC portal's I/O object
 * @cmd_flags: Command flags; one or more of 'MC_CMD_FLAG_'
 * @token: Token of DPDCEI object
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_reset(struct fsl_mc_io	*mc_io,
		 uint32_t		cmd_flags,
		 uint16_t		token);

/**
 * dpdcei_set_irq_enable() - Set overall interrupt state.
 * @mc_io: Pointer to MC portal's I/O object
 * @cmd_flags: Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:		Token of DPCI object
 * @irq_index:	The interrupt index to configure
 * @en:			Interrupt state - enable = 1, disable = 0
 *
 * Allows GPP software to control when interrupts are generated.
 * Each interrupt can have up to 32 causes.  The enable/disable control's the
 * overall interrupt state. if the interrupt is disabled no causes will cause
 * an interrupt
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_set_irq_enable(struct fsl_mc_io	*mc_io,
			  uint32_t		cmd_flags,
			  uint16_t		token,
			  uint8_t		irq_index,
			  uint8_t		en);

/**
 * dpdcei_get_irq_enable() - Get overall interrupt state
 * @mc_io: Pointer to MC portal's I/O object
 * @cmd_flags: Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:		Token of DPDCEI object
 * @irq_index:	The interrupt index to configure
 * @en:			Returned Interrupt state - enable = 1, disable = 0
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_get_irq_enable(struct fsl_mc_io	*mc_io,
			  uint32_t		cmd_flags,
			  uint16_t		token,
			  uint8_t		irq_index,
			  uint8_t		*en);

/**
 * dpdcei_set_irq_mask() - Set interrupt mask.
 * @mc_io: Pointer to MC portal's I/O object
 * @cmd_flags: Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:		Token of DPCI object
 * @irq_index:	The interrupt index to configure
 * @mask:		event mask to trigger interrupt;
 *				each bit:
 *					0 = ignore event
 *					1 = consider event for asserting IRQ
 *
 * Every interrupt can have up to 32 causes and the interrupt model supports
 * masking/unmasking each cause independently
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_set_irq_mask(struct fsl_mc_io	*mc_io,
			uint32_t		cmd_flags,
			uint16_t		token,
			uint8_t			irq_index,
			uint32_t		mask);

/**
 * dpdcei_get_irq_mask() - Get interrupt mask.
 * @mc_io: Pointer to MC portal's I/O object
 * @cmd_flags: Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:		Token of DPDCEI object
 * @irq_index:	The interrupt index to configure
 * @mask:		Returned event mask to trigger interrupt
 *
 * Every interrupt can have up to 32 causes and the interrupt model supports
 * masking/unmasking each cause independently
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_get_irq_mask(struct fsl_mc_io	*mc_io,
			uint32_t		cmd_flags,
			uint16_t		token,
			uint8_t			irq_index,
			uint32_t		*mask);

/**
 * dpdcei_get_irq_status() - Get the current status of any pending interrupts
 * @mc_io: Pointer to MC portal's I/O object
 * @cmd_flags: Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:		Token of DPDCEI object
 * @irq_index:	The interrupt index to configure
 * @status:		Returned interrupts status - one bit per cause:
 *					0 = no interrupt pending
 *					1 = interrupt pending
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_get_irq_status(struct fsl_mc_io	*mc_io,
			  uint32_t		cmd_flags,
			  uint16_t		token,
			  uint8_t		irq_index,
			  uint32_t		*status);

/**
 * dpdcei_clear_irq_status() - Clear a pending interrupt's status
 * @mc_io: Pointer to MC portal's I/O object
 * @cmd_flags: Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:		Token of DPDCEI object
 * @irq_index:	The interrupt index to configure
 * @status:		bits to clear (W1C) - one bit per cause:
 *					0 = don't change
 *					1 = clear status bit
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_clear_irq_status(struct fsl_mc_io	*mc_io,
			    uint32_t		cmd_flags,
			    uint16_t		token,
			    uint8_t		irq_index,
			    uint32_t		status);
/**
 * struct dpdcei_attr - Structure representing DPDCEI attributes
 * @id: DPDCEI object ID
 * @engine: DCE engine block
 */
struct dpdcei_attr {
	int id;
	enum dpdcei_engine engine;
	uint64_t dce_version;
};

/**
 * dpdcei_get_attributes() - Retrieve DPDCEI attributes.
 * @mc_io: Pointer to MC portal's I/O object
 * @cmd_flags: Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDCEI object
 * @attr: Returned  object's attributes
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_get_attributes(struct fsl_mc_io	*mc_io,
			  uint32_t		cmd_flags,
			  uint16_t		token,
			  struct dpdcei_attr	*attr);

/**
 * enum dpdcei_dest - DPDCEI destination types
 * @DPDCEI_DEST_NONE:  Unassigned destination; The queue is set in parked mode
 *			and does not generate FQDAN notifications;
 *			user is expected to dequeue from the queue based on
 *			polling or other user-defined method
 * @DPDCEI_DEST_DPIO: The queue is set in schedule mode and generates FQDAN
 *			notifications to the specified DPIO; user is expected to
 *			dequeue from the queue only after notification is
 *			received
 * @DPDCEI_DEST_DPCON: The queue is set in schedule mode and does not generate
 *			FQDAN notifications, but is connected to the specified
 *			DPCON object;
 *			user is expected to dequeue from the DPCON channel
 */
enum dpdcei_dest {
	DPDCEI_DEST_NONE = 0,
	DPDCEI_DEST_DPIO = 1,
	DPDCEI_DEST_DPCON = 2
};

/**
 * struct dpdcei_dest_cfg - Structure representing DPDCEI destination parameters
 * @dest_type: Destination type
 * @dest_id: Either DPIO ID or DPCON ID, depending on the destination type
 * @priority: Priority selection within the DPIO or DPCON channel; valid values
 *		are 0-1 or 0-7, depending on the number of priorities in that
 *		channel; not relevant for 'DPDCEI_DEST_NONE' option
 */
struct dpdcei_dest_cfg {
	enum dpdcei_dest	dest_type;
	int			dest_id;
	uint8_t			priority;
};

/** DPDCEI queue modification options */

/**
 * Select to modify the user's context associated with the queue
 */
#define DPDCEI_QUEUE_OPT_USER_CTX	0x00000001

/**
 * Select to modify the queue's destination
 */
#define DPDCEI_QUEUE_OPT_DEST		0x00000002

/**
 * struct dpdcei_rx_queue_cfg - RX queue configuration
 * @options: Flags representing the suggested modifications to the queue;
 *	Use any combination of 'DPDCEI_QUEUE_OPT_<X>' flags
 * @user_ctx: User context value provided in the frame descriptor of each
 *	dequeued frame;
 *	valid only if 'DPDCEI_QUEUE_OPT_USER_CTX' is contained in 'options'
 * @dest_cfg: Queue destination parameters;
 *	valid only if 'DPDCEI_QUEUE_OPT_DEST' is contained in 'options'
 */
struct dpdcei_rx_queue_cfg {
	uint32_t		options;
	uint64_t		user_ctx;
	struct dpdcei_dest_cfg	dest_cfg;
};

/**
 * dpdcei_set_rx_queue() - Set Rx queue configuration
 * @mc_io: Pointer to MC portal's I/O object
 * @cmd_flags: Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDCEI object
 * @cfg: Rx queue configuration
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_set_rx_queue(struct fsl_mc_io			*mc_io,
			uint32_t				cmd_flags,
			uint16_t				token,
			const struct dpdcei_rx_queue_cfg	*cfg);

/**
 * struct dpdcei_rx_queue_attr - Structure representing attributes of Rx queues
 * @user_ctx: User context value provided in the frame descriptor of each
 *		 dequeued frame
 * @dest_cfg: Queue destination configuration
 * @fqid: Virtual FQID value to be used for dequeue operations
 */
struct dpdcei_rx_queue_attr {
	uint64_t		user_ctx;
	struct dpdcei_dest_cfg	dest_cfg;
	uint32_t		fqid;
};

/**
 * dpdcei_get_rx_queue() - Retrieve Rx queue attributes.
 * @mc_io: Pointer to MC portal's I/O object
 * @cmd_flags: Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDCEI object
 * @attr:	Returned Rx queue attributes
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_get_rx_queue(struct fsl_mc_io		*mc_io,
			uint32_t			cmd_flags,
			uint16_t			token,
			struct dpdcei_rx_queue_attr	*attr);

/**
 * struct dpdcei_tx_queue_attr - Structure representing attributes of Tx queues
 * @fqid: Virtual FQID to be used for sending frames to DCE hardware
 */
struct dpdcei_tx_queue_attr {
	uint32_t fqid;
};

/**
 * dpdcei_get_tx_queue() - Retrieve Tx queue attributes.
 * @mc_io: Pointer to MC portal's I/O object
 * @cmd_flags: Command flags; one or more of 'MC_CMD_FLAG_'
 * @token: Token of DPDCEI object
 * @attr: Returned Tx queue attributes
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_get_tx_queue(struct fsl_mc_io		*mc_io,
			uint32_t			cmd_flags,
			uint16_t			token,
			struct dpdcei_tx_queue_attr	*attr);

/**
 * dpdcei_get_api_version() - Get Data Path DCE (decript/encrypt engine) API
 *				version
 * @mc_io:  Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @major_ver:	Major version of data path dce API
 * @minor_ver:	Minor version of data path dce API
 *
 * Return:  '0' on Success; Error code otherwise.
 */
int dpdcei_get_api_version(struct fsl_mc_io *mc_io,
			   uint32_t cmd_flags,
			   uint16_t *major_ver,
			   uint16_t *minor_ver);

#endif /* __FSL_DPDCEI_H */
