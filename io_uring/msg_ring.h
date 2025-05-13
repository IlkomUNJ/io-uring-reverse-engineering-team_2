// SPDX-License-Identifier: GPL-2.0

/*
 Synchronous version of message ring for direct kernel use.
 Allows sending messages without going through the async request path.
*/
int io_uring_sync_msg_ring(struct io_uring_sqe *sqe);

/*
 Public interface for message ring request preparation.
 Converts io_kiocb to io_msg and calls core preparation function.
*/
int io_msg_ring_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 Main entry point for message ring operation execution.
 Dispatches to appropriate handler based on command type.
*/
int io_msg_ring(struct io_kiocb *req, unsigned int issue_flags);

/* Performs cleanup of message resources when request completes or is cancelled. */
void io_msg_ring_cleanup(struct io_kiocb *req);
