// SPDX-License-Identifier: GPL-2.0

/** 
 * io_tee_prep - Prepare a tee (pipe duplication) operation for io_uring
 * - This function:
 * - Validates the sqe parameters for a tee operation
 * - Initializes the request structure with tee operation details
 * - Sets up file descriptors and flags for the operation
 */
int io_tee_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * * io_tee - Execute a tee operation (duplicate pipe data without consuming)
 * This function:
 * - Calls vfs_tee() to perform the actual pipe duplication
 * - Handles short operations and retries if needed
 * - Manages completion of the request
 */
int io_tee(struct io_kiocb *req, unsigned int issue_flags);

/**
 * io_splice_cleanup - Clean up resources after a splice operation
 * This function:
 * - Releases any file references held by the request
 * - Frees allocated resources
 * - Handles both successful and failed/cancelled operations
 */
void io_splice_cleanup(struct io_kiocb *req);

/**
 * io_splice_prep - Prepare a splice operation for io_uring
 * This function:
 * - Validates the sqe parameters for a splice operation
 * - Initializes the request structure with file descriptors and flags
 * - Sets up the appropriate splice operation type (pipe to file, file to pipe, etc)
 */
int io_splice_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);


/**
 * io_splice - Execute a splice operation (move data between pipe and file)
 * This function:
 * - Calls vfs_splice() to perform the actual data movement
 * - Handles partial operations and retries if needed
 * - Manages completion of the request
 */
int io_splice(struct io_kiocb *req, unsigned int issue_flags);
