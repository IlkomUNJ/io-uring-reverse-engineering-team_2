// SPDX-License-Identifier: GPL-2.0

/* Prepare an ftruncate io_uring request. */
int io_ftruncate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Execute an ftruncate io_uring request. */
int io_ftruncate(struct io_kiocb *req, unsigned int issue_flags);
