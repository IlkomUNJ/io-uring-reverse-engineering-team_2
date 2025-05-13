// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "../kernel/futex/futex.h"
#include "io_uring.h"
#include "alloc_cache.h"
#include "futex.h"

struct io_futex {
	struct file	*file;
	union {
		u32 __user			*uaddr;
		struct futex_waitv __user	*uwaitv;
	};
	unsigned long	futex_val;
	unsigned long	futex_mask;
	unsigned long	futexv_owned;
	u32		futex_flags;
	unsigned int	futex_nr;
	bool		futexv_unqueued;
};

struct io_futex_data {
	struct futex_q	q;
	struct io_kiocb	*req;
};

#define IO_FUTEX_ALLOC_CACHE_MAX	32

/*
Allocates and initializes a cache for futex data structures used by io_uring.
Returns true on successful initialization, false otherwise.
*/
bool io_futex_cache_init(struct io_ring_ctx *ctx)
{
	return io_alloc_cache_init(&ctx->futex_cache, IO_FUTEX_ALLOC_CACHE_MAX,
				sizeof(struct io_futex_data), 0);
}

/* Releases all resources allocated for the futex cache */
void io_futex_cache_free(struct io_ring_ctx *ctx)
{
	io_alloc_cache_free(&ctx->futex_cache, kfree);
}

/*
Clears async data, removes the request from hash list,
and marks the request as complete
*/
static void __io_futex_complete(struct io_kiocb *req, io_tw_token_t tw)
{
	req->async_data = NULL;
	hlist_del_init(&req->hash_node);
	io_req_task_complete(req, tw);
}

/*
Locks the task work context, frees the futex data from cache,
and completes the request
*/
static void io_futex_complete(struct io_kiocb *req, io_tw_token_t tw)
{
	struct io_ring_ctx *ctx = req->ctx;

	io_tw_lock(ctx, tw);
	io_cache_free(&ctx->futex_cache, req->async_data);
	__io_futex_complete(req, tw);
}

/*
Locks the task work context, optionally unqueues multiple futexes,
frees async data, clears async data flag, and completes the request
*/
static void io_futexv_complete(struct io_kiocb *req, io_tw_token_t tw)
{
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	struct futex_vector *futexv = req->async_data;

	io_tw_lock(req->ctx, tw);

	if (!iof->futexv_unqueued) {
		int res;

		res = futex_unqueue_multiple(futexv, iof->futex_nr);
		if (res != -1)
			io_req_set_res(req, res, 0);
	}

	kfree(req->async_data);
	req->flags &= ~REQ_F_ASYNC_DATA;
	__io_futex_complete(req, tw);
}

/*
Tests and sets the ownership bit atomically to claim the futex vector,
returns true if ownership was successfully claimed, false otherwise
*/
static bool io_futexv_claim(struct io_futex *iof)
{
	if (test_bit(0, &iof->futexv_owned) ||
	    test_and_set_bit_lock(0, &iof->futexv_owned))
		return false;
	return true;
}

/*
Attempts to unqueue the futex wait or claim futex vector ownership.
If successful, schedules completion with cancellation result.
Returns true if cancellation was initiated, false if already completed or in progress.
*/
static bool __io_futex_cancel(struct io_kiocb *req)
{
	/* futex wake already done or in progress */
	if (req->opcode == IORING_OP_FUTEX_WAIT) {
		struct io_futex_data *ifd = req->async_data;

		if (!futex_unqueue(&ifd->q))
			return false;
		req->io_task_work.func = io_futex_complete;
	} else {
		struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);

		if (!io_futexv_claim(iof))
			return false;
		req->io_task_work.func = io_futexv_complete;
	}

	hlist_del_init(&req->hash_node);
	io_req_set_res(req, -ECANCELED, 0);
	io_req_task_work_add(req);
	return true;
}

/*
Attempts to remove and cancel a futex request from the futex list.
Returns the result of the cancellation attempt.
*/
int io_futex_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		    unsigned int issue_flags)
{
	return io_cancel_remove(ctx, cd, issue_flags, &ctx->futex_list, __io_futex_cancel);
}

/* 
Removes or cancels all futex requests associated with the given task.
Returns true if any requests were removed or cancelled, false otherwise.
*/
bool io_futex_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			 bool cancel_all)
{
	return io_cancel_remove_all(ctx, tctx, &ctx->futex_list, cancel_all, __io_futex_cancel);
}

/* Validates the futex parameters, copies user-space addresses and flags,
and checks for invalid or unsupported flags.
Returns 0 on success or -EINVAL on invalid input. */
int io_futex_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	u32 flags;

	if (unlikely(sqe->len || sqe->futex_flags || sqe->buf_index ||
		     sqe->file_index))
		return -EINVAL;

	iof->uaddr = u64_to_user_ptr(READ_ONCE(sqe->addr));
	iof->futex_val = READ_ONCE(sqe->addr2);
	iof->futex_mask = READ_ONCE(sqe->addr3);
	flags = READ_ONCE(sqe->fd);

	if (flags & ~FUTEX2_VALID_MASK)
		return -EINVAL;

	iof->futex_flags = futex2_to_flags(flags);
	if (!futex_flags_valid(iof->futex_flags))
		return -EINVAL;

	if (!futex_validate_input(iof->futex_flags, iof->futex_val) ||
	    !futex_validate_input(iof->futex_flags, iof->futex_mask))
		return -EINVAL;

	return 0;
}

/* Attempts to claim ownership of the futex vector and mark it as woken.
If successful, sets the request result to 0 and schedules completion. */
static void io_futex_wakev_fn(struct wake_q_head *wake_q, struct futex_q *q)
{
	struct io_kiocb *req = q->wake_data;
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);

	if (!io_futexv_claim(iof))
		return;
	if (unlikely(!__futex_wake_mark(q)))
		return;

	io_req_set_res(req, 0, 0);
	req->io_task_work.func = io_futexv_complete;
	io_req_task_work_add(req);
}

/* Validates input parameters, allocates and initializes futex vector structures,
 * and sets up asynchronous data for the waitv operation.
 * Returns 0 on success, -EINVAL on invalid input, or -ENOMEM on allocation failure. */
int io_futexv_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	struct futex_vector *futexv;
	int ret;

	/* No flags or mask supported for waitv */
	if (unlikely(sqe->fd || sqe->buf_index || sqe->file_index ||
		     sqe->addr2 || sqe->futex_flags || sqe->addr3))
		return -EINVAL;

	iof->uaddr = u64_to_user_ptr(READ_ONCE(sqe->addr));
	iof->futex_nr = READ_ONCE(sqe->len);
	if (!iof->futex_nr || iof->futex_nr > FUTEX_WAITV_MAX)
		return -EINVAL;

	futexv = kcalloc(iof->futex_nr, sizeof(*futexv), GFP_KERNEL);
	if (!futexv)
		return -ENOMEM;

	ret = futex_parse_waitv(futexv, iof->uwaitv, iof->futex_nr,
				io_futex_wakev_fn, req);
	if (ret) {
		kfree(futexv);
		return ret;
	}

	iof->futexv_owned = 0;
	iof->futexv_unqueued = 0;
	req->flags |= REQ_F_ASYNC_DATA;
	req->async_data = futexv;
	return 0;
}

/* Marks the futex as woken, sets the request result to 0,
 * and schedules the request for completion. */
static void io_futex_wake_fn(struct wake_q_head *wake_q, struct futex_q *q)
{
	struct io_futex_data *ifd = container_of(q, struct io_futex_data, q);
	struct io_kiocb *req = ifd->req;

	if (unlikely(!__futex_wake_mark(q)))
		return;

	io_req_set_res(req, 0, 0);
	req->io_task_work.func = io_futex_complete;
	io_req_task_work_add(req);
}

/* Sets up waiting on multiple futexes, handling race conditions and wakeups.
 * Manages request state and futex list membership accordingly.
 * Returns IOU_ISSUE_SKIP_COMPLETE to indicate async completion handling. */
int io_futexv_wait(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	struct futex_vector *futexv = req->async_data;
	struct io_ring_ctx *ctx = req->ctx;
	int ret, woken = -1;

	io_ring_submit_lock(ctx, issue_flags);

	ret = futex_wait_multiple_setup(futexv, iof->futex_nr, &woken);

	/*
	 * Error case, ret is < 0. Mark the request as failed.
	 */
	if (unlikely(ret < 0)) {
		io_ring_submit_unlock(ctx, issue_flags);
		req_set_fail(req);
		io_req_set_res(req, ret, 0);
		kfree(futexv);
		req->async_data = NULL;
		req->flags &= ~REQ_F_ASYNC_DATA;
		return IOU_OK;
	}

	/*
	 * 0 return means that we successfully setup the waiters, and that
	 * nobody triggered a wakeup while we were doing so. If the wakeup
	 * happened post setup, the task_work will be run post this issue and
	 * under the submission lock. 1 means We got woken while setting up,
	 * let that side do the completion. Note that
	 * futex_wait_multiple_setup() will have unqueued all the futexes in
	 * this case. Mark us as having done that already, since this is
	 * different from normal wakeup.
	 */
	if (!ret) {
		/*
		 * If futex_wait_multiple_setup() returns 0 for a
		 * successful setup, then the task state will not be
		 * runnable. This is fine for the sync syscall, as
		 * it'll be blocking unless we already got one of the
		 * futexes woken, but it obviously won't work for an
		 * async invocation. Mark us runnable again.
		 */
		__set_current_state(TASK_RUNNING);
		hlist_add_head(&req->hash_node, &ctx->futex_list);
	} else {
		iof->futexv_unqueued = 1;
		if (woken != -1)
			io_req_set_res(req, woken, 0);
	}

	io_ring_submit_unlock(ctx, issue_flags);
	return IOU_ISSUE_SKIP_COMPLETE;
}

/* Allocates futex wait data, sets up the futex wait queue,
 * and enqueues the request for asynchronous completion.
 * Returns IOU_ISSUE_SKIP_COMPLETE if wait is successfully queued,
 * or IOU_OK with error set on failure. */
int io_futex_wait(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_futex_data *ifd = NULL;
	struct futex_hash_bucket *hb;
	int ret;

	if (!iof->futex_mask) {
		ret = -EINVAL;
		goto done;
	}

	io_ring_submit_lock(ctx, issue_flags);
	ifd = io_cache_alloc(&ctx->futex_cache, GFP_NOWAIT);
	if (!ifd) {
		ret = -ENOMEM;
		goto done_unlock;
	}

	req->async_data = ifd;
	ifd->q = futex_q_init;
	ifd->q.bitset = iof->futex_mask;
	ifd->q.wake = io_futex_wake_fn;
	ifd->req = req;

	ret = futex_wait_setup(iof->uaddr, iof->futex_val, iof->futex_flags,
			       &ifd->q, &hb);
	if (!ret) {
		hlist_add_head(&req->hash_node, &ctx->futex_list);
		io_ring_submit_unlock(ctx, issue_flags);

		futex_queue(&ifd->q, hb, NULL);
		return IOU_ISSUE_SKIP_COMPLETE;
	}

done_unlock:
	io_ring_submit_unlock(ctx, issue_flags);
done:
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	kfree(ifd);
	return IOU_OK;
}

/* Wakes up to futex_val waiters on the futex at the given address,
 * applying strict flags to ensure waking zero futexes returns zero.
 * Returns IOU_OK after setting the result or failure status on the request. */
int io_futex_wake(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	int ret;

	/*
	 * Strict flags - ensure that waking 0 futexes yields a 0 result.
	 * See commit 43adf8449510 ("futex: FLAGS_STRICT") for details.
	 */
	ret = futex_wake(iof->uaddr, FLAGS_STRICT | iof->futex_flags,
			 iof->futex_val, iof->futex_mask);
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}
