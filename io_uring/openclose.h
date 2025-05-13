// SPDX-License-Identifier: GPL-2.0

/* 
 * Removes a file from the fixed file table in the io_uring context.
 * Handles synchronization with appropriate locks for thread safety.
 */
int __io_close_fixed(struct io_ring_ctx *ctx, unsigned int issue_flags,
             unsigned int offset);

/* 
 * Prepares an openat request from submission queue entry.
 * Parses parameters and initializes the request structure for later execution.
 */
int io_openat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* 
 * Performs the actual file opening operation using openat semantics.
 * Handles file descriptor allocation and installation with proper error handling.
 */
int io_openat(struct io_kiocb *req, unsigned int issue_flags);

/* 
 * Releases resources allocated during open request preparation.
 * Frees the filename structure when request is being cleaned up.
 */
void io_open_cleanup(struct io_kiocb *req);

/* 
 * Prepares an openat2 request with extended options.
 * Similar to openat_prep but supports the more flexible open_how structure.
 */
int io_openat2_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* 
 * Performs file opening with extended options via openat2.
 * Supports additional flags and parameters beyond traditional openat.
 */
int io_openat2(struct io_kiocb *req, unsigned int issue_flags);

/* 
 * Prepares a file close request from submission queue entry.
 * Sets up either a normal file descriptor close or a fixed file table entry close.
 */
int io_close_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* 
 * Executes file descriptor close operation.
 * Handles both normal FDs and fixed file table entries with appropriate cleanup.
 */
int io_close(struct io_kiocb *req, unsigned int issue_flags);

/* 
 * Prepares installation of a file descriptor into the fixed file table.
 * Validates parameters for the fixed file table entry installation.
 */
int io_install_fixed_fd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* 
 * Installs a file into the fixed file table at specified index.
 * Receives a file descriptor from another file and places it in the table.
 */
int io_install_fixed_fd(struct io_kiocb *req, unsigned int issue_flags);
