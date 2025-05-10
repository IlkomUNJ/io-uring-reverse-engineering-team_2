// SPDX-License-Identifier: GPL-2.0

/* Prepares a memory advise operation by extracting address, length, and advice type from a submission queue entry. Sets up the request structure with all parameters needed for later execution.*/
int io_madvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Executes a previously prepared memory advise operation by calling the kernel's do_madvise() function.*/
int io_madvise(struct io_kiocb *req, unsigned int issue_flags);

/* Prepares a file advise operation by extracting file offset, length, and advice type from a submission queue entry.*/
int io_fadvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Executes a previously prepared file advise operation by calling vfs_fadvise().*/
int io_fadvise(struct io_kiocb *req, unsigned int issue_flags);







