// SPDX-License-Identifier: GPL-2.0

#if defined(CONFIG_EPOLL)

/* Prepares an epoll control request. Sets up parameters to add, modify, or remove file descriptors from an epoll instance. */
int io_epoll_ctl_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Executes a prepared epoll control operation. Modifies the interest list of an epoll instance by adding, changing, or removing monitored file descriptors. */
int io_epoll_ctl(struct io_kiocb *req, unsigned int issue_flags);

/* Prepares an epoll wait request. Sets up parameters to wait for events on file descriptors registered with an epoll instance. */
int io_epoll_wait_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Waits for events on the monitored file descriptors. Blocks until events occur or timeout, then returns the ready file descriptors through io_uring completion queue. */
int io_epoll_wait(struct io_kiocb *req, unsigned int issue_flags);

#endif
