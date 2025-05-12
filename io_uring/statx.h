// SPDX-License-Identifier: GPL-2.0

/* Prepare a statx io_uring request. */
int io_statx_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Execute a statx io_uring request. */
int io_statx(struct io_kiocb *req, unsigned int issue_flags);

/* Cleanup resources allocated during statx request. */
void io_statx_cleanup(struct io_kiocb *req);
