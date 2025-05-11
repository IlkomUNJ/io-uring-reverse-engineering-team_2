// SPDX-License-Identifier: GPL-2.0

/* Prepare a rename operation from io_uring submission queue entry */
int io_renameat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Perform the rename operation */
int io_renameat(struct io_kiocb *req, unsigned int issue_flags);

/* Cleanup resources allocated during rename preparation */
void io_renameat_cleanup(struct io_kiocb *req);

/* Prepare an unlink operation from io_uring submission queue entry */
int io_unlinkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Perform the unlink operation */
int io_unlinkat(struct io_kiocb *req, unsigned int issue_flags);

/* Cleanup resources allocated during unlink preparation */
void io_unlinkat_cleanup(struct io_kiocb *req);

/* Prepare a mkdir operation from io_uring submission queue entry */
int io_mkdirat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Perform the mkdir operation */
int io_mkdirat(struct io_kiocb *req, unsigned int issue_flags);

/* Cleanup resources allocated during mkdir preparation */
void io_mkdirat_cleanup(struct io_kiocb *req);

/* Prepare a symlink operation from io_uring submission queue entry */
int io_symlinkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Perform the symlink operation */
int io_symlinkat(struct io_kiocb *req, unsigned int issue_flags);

/* Prepare a link operation from io_uring submission queue entry */
int io_linkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Perform the link operation */
int io_linkat(struct io_kiocb *req, unsigned int issue_flags);

/* Cleanup resources allocated during link preparation */
void io_link_cleanup(struct io_kiocb *req);
