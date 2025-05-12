// SPDX-License-Identifier: GPL-2.0

/* Prepare a sync_file_range io_uring request. */
int io_sfr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Execute a sync_file_range io_uring request. */
int io_sync_file_range(struct io_kiocb *req, unsigned int issue_flags);

/* Prepare an fsync io_uring request. */
int io_fsync_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Execute an fsync io_uring request. */
int io_fsync(struct io_kiocb *req, unsigned int issue_flags);

/* Execute a fallocate io_uring request. */
int io_fallocate(struct io_kiocb *req, unsigned int issue_flags);

/* Prepare a fallocate io_uring request. */
int io_fallocate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
