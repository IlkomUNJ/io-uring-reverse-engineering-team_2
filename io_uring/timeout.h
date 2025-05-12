// SPDX-License-Identifier: GPL-2.0

struct io_timeout_data {
	struct io_kiocb			*req;
	struct hrtimer			timer;
	struct timespec64		ts;
	enum hrtimer_mode		mode;
	u32				flags;
};

/* Disarm a linked timeout request. */
struct io_kiocb *__io_disarm_linked_timeout(struct io_kiocb *req,
					    struct io_kiocb *link);

/* Inline helper to disarm linked timeout. */
static inline struct io_kiocb *io_disarm_linked_timeout(struct io_kiocb *req)
{
	struct io_kiocb *link = req->link;

	if (link && link->opcode == IORING_OP_LINK_TIMEOUT)
		return __io_disarm_linked_timeout(req, link);

	return NULL;
}

/* Flush all expired or killed timeouts. */
__cold void io_flush_timeouts(struct io_ring_ctx *ctx);
struct io_cancel_data;

/* Cancel a timeout request matching cancel data. */
int io_timeout_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd);

/* Cancel all matching timeouts for a task context. */
__cold bool io_kill_timeouts(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			     bool cancel_all);

/* Queue a linked timeout request */
void io_queue_linked_timeout(struct io_kiocb *req);

/* Disarm the next linked timeout in a chain. */
void io_disarm_next(struct io_kiocb *req);

/* Prepare a timeout request. */
int io_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Prepare a linked timeout request. */
int io_link_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Submit a timeout request. */
int io_timeout(struct io_kiocb *req, unsigned int issue_flags);

/* Prepare a timeout removal request. */
int io_timeout_remove_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Remove or update an existing timeout request. */
int io_timeout_remove(struct io_kiocb *req, unsigned int issue_flags);
