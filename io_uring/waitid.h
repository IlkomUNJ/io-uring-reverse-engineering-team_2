// SPDX-License-Identifier: GPL-2.0

#include "../kernel/exit.h"

struct io_waitid_async {
	struct io_kiocb *req;
	struct wait_opts wo;
};

/* Prepare an io_uring waitid request */
int io_waitid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Execute an asynchronous waitid operation. */
int io_waitid(struct io_kiocb *req, unsigned int issue_flags);

/* Cancel a pending waitid request. */
int io_waitid_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		     unsigned int issue_flags);

/* Remove and optionally cancel all waitid requests for a task. */
bool io_waitid_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			  bool cancel_all);
