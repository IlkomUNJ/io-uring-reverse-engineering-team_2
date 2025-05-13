// SPDX-License-Identifier: GPL-2.0

#include "cancel.h"

/* Prepare a futex operation from io_uring submission queue entry */
int io_futex_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Prepare a futex vector wait operation from io_uring submission queue entry */
int io_futexv_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Perform a futex wait operation */
int io_futex_wait(struct io_kiocb *req, unsigned int issue_flags);

/* Perform a futex vector wait operation */
int io_futexv_wait(struct io_kiocb *req, unsigned int issue_flags);

/* Perform a futex wake operation */
int io_futex_wake(struct io_kiocb *req, unsigned int issue_flags);

#if defined(CONFIG_FUTEX)
/* Cancel a pending futex request in the io_uring context */
int io_futex_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		    unsigned int issue_flags);

/* Remove or cancel all futex requests associated with a given task */
bool io_futex_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			 bool cancel_all);

/* Initialize the futex cache for the io_uring context */
bool io_futex_cache_init(struct io_ring_ctx *ctx);

/* Free resources allocated for the futex cache */
void io_futex_cache_free(struct io_ring_ctx *ctx);
#else

/* Cancel a pending futex request in the io_uring context.
 * Returns 0 to indicate no cancellation performed. */
static inline int io_futex_cancel(struct io_ring_ctx *ctx,
				  struct io_cancel_data *cd,
				  unsigned int issue_flags)
{
	return 0;
}

/* Remove or cancel all futex requests associated with a given task.
 * Returns false to indicate no requests were removed or cancelled. */
static inline bool io_futex_remove_all(struct io_ring_ctx *ctx,
				       struct io_uring_task *tctx, bool cancel_all)
{
	return false;
}

/* Initialize the futex cache for the io_uring context.
 * Returns false to indicate initialization was not performed. */
static inline bool io_futex_cache_init(struct io_ring_ctx *ctx)
{
	return false;
}

/* Free resources allocated for the futex cache. */
static inline void io_futex_cache_free(struct io_ring_ctx *ctx)
{
}
#endif
