// SPDX-License-Identifier: GPL-2.0
#ifndef IORING_CANCEL_H
#define IORING_CANCEL_H

#include <linux/io_uring_types.h>

struct io_cancel_data {
	struct io_ring_ctx *ctx;
	union {
		u64 data;
		struct file *file;
	};
	u8 opcode;
	u32 flags;
	int seq;
};

/* Prepares a cancellation request by extracting parameters from the submission queue entry. Sets up which requests should be targeted for cancellation. */
int io_async_cancel_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Performs asynchronous cancellation of previously submitted requests. Uses the prepared parameters to find and cancel matching operations. */
int io_async_cancel(struct io_kiocb *req, unsigned int issue_flags);

/* Attempts to cancel a request but doesn't wait for completion. Returns immediately with success or failure status. */
int io_try_cancel(struct io_uring_task *tctx, struct io_cancel_data *cd,
		  unsigned int issue_flags);

/* Performs synchronous cancellation, getting parameters from user space. Waits until cancellation is complete before returning. */	  
int io_sync_cancel(struct io_ring_ctx *ctx, void __user *arg);

/* Checks if a request matches the cancellation criteria. Tests if the given request should be canceled based on the cancellation data. */
bool io_cancel_req_match(struct io_kiocb *req, struct io_cancel_data *cd);

/* Removes and cancels all matching requests from a list. Can either cancel all requests or only specific ones based on the provided callback. */
bool io_cancel_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			  struct hlist_head *list, bool cancel_all,
			  bool (*cancel)(struct io_kiocb *));

/* Removes and cancels requests matching specific criteria from a list. More targeted than remove_all, using the cancel data to select requests. */
int io_cancel_remove(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		     unsigned int issue_flags, struct hlist_head *list,
		     bool (*cancel)(struct io_kiocb *));

/* Checks if a request matches a specific sequence number. If not matched, updates the request with the new sequence number for future matching. */
static inline bool io_cancel_match_sequence(struct io_kiocb *req, int sequence)
{
	if (req->cancel_seq_set && sequence == req->work.cancel_seq)
		return true;

	req->cancel_seq_set = true;
	req->work.cancel_seq = sequence;
	return false;
}

#endif
