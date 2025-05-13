// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_OP_DEF_H
#define IOU_OP_DEF_H

/* 
 * Defines properties and handlers for an io_uring operation type.
 * Contains bit flags for operation capabilities and function pointers for execution.
 */
struct io_issue_def {
    /* needs req->file assigned */
    unsigned		needs_file : 1;
    /* should block plug */
    unsigned		plug : 1;
    /* supports ioprio */
    unsigned		ioprio : 1;
    /* supports iopoll */
    unsigned		iopoll : 1;
    /* op supports buffer selection */
    unsigned		buffer_select : 1;
    /* hash wq insertion if file is a regular file */
    unsigned		hash_reg_file : 1;
    /* unbound wq insertion if file is a non-regular file */
    unsigned		unbound_nonreg_file : 1;
    /* set if opcode supports polled "wait" */
    unsigned		pollin : 1;
    unsigned		pollout : 1;
    unsigned		poll_exclusive : 1;
    /* skip auditing */
    unsigned		audit_skip : 1;
    /* have to be put into the iopoll list */
    unsigned		iopoll_queue : 1;
    /* vectored opcode, set if 1) vectored, and 2) handler needs to know */
    unsigned		vectored : 1;

    /* size of async data needed, if any */
    unsigned short		async_size;

    int (*issue)(struct io_kiocb *, unsigned int);
    int (*prep)(struct io_kiocb *, const struct io_uring_sqe *);
};

/* 
 * Defines "cold path" data for io_uring operations.
 * Contains operation names and cleanup handlers that are rarely accessed.
 */
struct io_cold_def {
    const char		*name;

    void (*cleanup)(struct io_kiocb *);
    void (*fail)(struct io_kiocb *);
};

/* 
 * Global arrays defining characteristics of all supported io_uring operations.
 * Referenced by opcode value to access operation-specific behavior and metadata.
 */
extern const struct io_issue_def io_issue_defs[];
extern const struct io_cold_def io_cold_defs[];

/* 
 * Checks if an operation is supported in the current kernel.
 * Returns true if the operation has valid preparation handlers.
 */
bool io_uring_op_supported(u8 opcode);

/* 
 * Initializes operation tables at kernel boot time.
 * Validates that operation definitions are properly configured.
 */
void io_uring_optable_init(void);
#endif
