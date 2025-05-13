// SPDX-License-Identifier: GPL-2.0

/* Cleanup resources allocated for xattr requests. */
void io_xattr_cleanup(struct io_kiocb *req);

/* Prepare a file-based setxattr request. */
int io_fsetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Perform a file-based setxattr operation. */
int io_fsetxattr(struct io_kiocb *req, unsigned int issue_flags);

/* Prepare a path-based setxattr request. */
int io_setxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Perform a path-based setxattr operation */
int io_setxattr(struct io_kiocb *req, unsigned int issue_flags);

/* Prepare a file-based getxattr request. */
int io_fgetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Perform a file-based getxattr operation. */
int io_fgetxattr(struct io_kiocb *req, unsigned int issue_flags);

/* Prepare a path-based getxattr request. */
int io_getxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Perform a path-based getxattr operation. */
int io_getxattr(struct io_kiocb *req, unsigned int issue_flags);
