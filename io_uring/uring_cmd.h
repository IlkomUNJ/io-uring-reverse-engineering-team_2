// SPDX-License-Identifier: GPL-2.0

#include <linux/io_uring/cmd.h>
#include <linux/io_uring_types.h>

struct io_async_cmd {
	struct io_uring_cmd_data	data;
	struct iou_vec			vec;
	struct io_uring_sqe		sqes[2];
};

/* Execute an io_uring command */
int io_uring_cmd(struct io_kiocb *req, unsigned int issue_flags);

/* Prepare an io_uring command request */
int io_uring_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Cleanup resources after io_uring command completion. */
void io_uring_cmd_cleanup(struct io_kiocb *req);

/* Attempt to cancel io_uring commands. */
bool io_uring_try_cancel_uring_cmd(struct io_ring_ctx *ctx,
				   struct io_uring_task *tctx, bool cancel_all);

/* Free a cached io_async_cmd entry. */
void io_cmd_cache_free(const void *entry);

/* Import a fixed iovec for io_uring command. */
int io_uring_cmd_import_fixed_vec(struct io_uring_cmd *ioucmd,
				  const struct iovec __user *uvec,
				  size_t uvec_segs,
				  int ddir, struct iov_iter *iter,
				  unsigned issue_flags);
