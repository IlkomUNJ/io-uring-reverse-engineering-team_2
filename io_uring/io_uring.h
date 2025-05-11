#ifndef IOU_CORE_H
#define IOU_CORE_H

#include <linux/errno.h>
#include <linux/lockdep.h>
#include <linux/resume_user_mode.h>
#include <linux/kasan.h>
#include <linux/poll.h>
#include <linux/io_uring_types.h>
#include <uapi/linux/eventpoll.h>
#include "alloc_cache.h"
#include "io-wq.h"
#include "slist.h"
#include "filetable.h"
#include "opdef.h"

#ifndef CREATE_TRACE_POINTS
#include <trace/events/io_uring.h>
#endif

enum {
	IOU_OK			= 0, /* deprecated, use IOU_COMPLETE */
	IOU_COMPLETE		= 0,

	IOU_ISSUE_SKIP_COMPLETE	= -EIOCBQUEUED,

	/*
	 * The request has more work to do and should be retried. io_uring will
	 * attempt to wait on the file for eligible opcodes, but otherwise
	 * it'll be handed to iowq for blocking execution. It works for normal
	 * requests as well as for the multi shot mode.
	 */
	IOU_RETRY		= -EAGAIN,

	/*
	 * Requeue the task_work to restart operations on this request. The
	 * actual value isn't important, should just be not an otherwise
	 * valid error code, yet less than -MAX_ERRNO and valid internally.
	 */
	IOU_REQUEUE		= -3072,
};

struct io_wait_queue {
	struct wait_queue_entry wq;
	struct io_ring_ctx *ctx;
	unsigned cq_tail;
	unsigned cq_min_tail;
	unsigned nr_timeouts;
	int hit_timeout;
	ktime_t min_timeout;
	ktime_t timeout;
	struct hrtimer t;

#ifdef CONFIG_NET_RX_BUSY_POLL
	ktime_t napi_busy_poll_dt;
	bool napi_prefer_busy_poll;
#endif
};

/* checks whether the completion queue (CQ) tail has advanced
 * enough to satisfy the wait condition or if a timeout has occurred since
 * the wait started. Specifically:
 * - It calculates the distance between the current CQ tail and the saved tail
 *   position at wait start.
 * - If the distance is non-negative (i.e., new completions have arrived), it returns true.
 * - If the number of CQ timeouts has changed since the wait started, indicating a timeout,
 *   it also returns true.
 * Returning true means the wait should be interrupted and the caller woken up,
 * either due to new events or timeout expiry */
static inline bool io_should_wake(struct io_wait_queue *iowq)
{
	struct io_ring_ctx *ctx = iowq->ctx;
	int dist = READ_ONCE(ctx->rings->cq.tail) - (int) iowq->cq_tail;

	/*
	 * Wake up if we have enough events, or if a timeout occurred since we
	 * started waiting. For timeouts, we always want to return to userspace,
	 * regardless of event count.
	 */
	return dist >= 0 || atomic_read(&ctx->cq_timeouts) != iowq->nr_timeouts;
}

#define IORING_MAX_ENTRIES	32768
#define IORING_MAX_CQ_ENTRIES	(2 * IORING_MAX_ENTRIES)

/* Returns the total size in bytes needed for the shared rings memory,
 * and outputs the offset of the SQ array. */
unsigned long rings_size(unsigned int flags, unsigned int sq_entries,
			 unsigned int cq_entries, size_t *sq_offset);

/* Initialize io_uring_params based on entries. */
int io_uring_fill_params(unsigned entries, struct io_uring_params *p);

/* Returns true if cache was successfully refilled. */
bool io_cqe_cache_refill(struct io_ring_ctx *ctx, bool overflow);

/* Run pending task work with signal handling. */
int io_run_task_work_sig(struct io_ring_ctx *ctx);

/* Mark a deferred request as failed. */
void io_req_defer_failed(struct io_kiocb *req, s32 res);

/* Returns true if the auxiliary CQE was successfully posted. */
bool io_post_aux_cqe(struct io_ring_ctx *ctx, u64 user_data, s32 res, u32 cflags);

/* Adds an auxiliary CQE internally without returning status. */
void io_add_aux_cqe(struct io_ring_ctx *ctx, u64 user_data, s32 res, u32 cflags);

/* Returns true if the completion event was successfully posted. */
bool io_req_post_cqe(struct io_kiocb *req, s32 res, u32 cflags);

/* Commit and flush the completion queue ring.. */
void __io_commit_cqring_flush(struct io_ring_ctx *ctx);

/* Get a file pointer for a normal (non-fixed) fd. */
struct file *io_file_get_normal(struct io_kiocb *req, int fd);

/* Get a file pointer for a fixed fd. */
struct file *io_file_get_fixed(struct io_kiocb *req, int fd,
			       unsigned issue_flags);

/* Add task work to the current request. */
void __io_req_task_work_add(struct io_kiocb *req, unsigned flags);

/* Add task work to a remote context. */
void io_req_task_work_add_remote(struct io_kiocb *req, unsigned flags);

/* Queue a request's task work for execution. */
void io_req_task_queue(struct io_kiocb *req);

/* Mark a request as complete via task work. */
void io_req_task_complete(struct io_kiocb *req, io_tw_token_t tw);

/* Queue a failed request for completion. */
void io_req_task_queue_fail(struct io_kiocb *req, int ret);

/* Submit a request's task work. */
void io_req_task_submit(struct io_kiocb *req, io_tw_token_t tw);

/* Process a list of task work nodes */
struct llist_node *io_handle_tw_list(struct llist_node *node, unsigned int *count, unsigned int max_entries);

/* Run task work for a specific io_uring task context. */
struct llist_node *tctx_task_work_run(struct io_uring_task *tctx, unsigned int max_entries, unsigned int *count);

/* Callback to execute task work for an io_uring task context. */
void tctx_task_work(struct callback_head *cb);

/* Cancel outstanding io_uring requests for current task. */
__cold void io_uring_cancel_generic(bool cancel_all, struct io_sq_data *sqd);

/* Allocate io_uring task context for a task. */
int io_uring_alloc_task_context(struct task_struct *task,
				struct io_ring_ctx *ctx);

/* Add a file to the registered files array in an io_uring task. */
int io_ring_add_registered_file(struct io_uring_task *tctx, struct file *file,
				     int start, int end);

/* Queue an io_kiocb request to the io_wq workqueue. */
void io_req_queue_iowq(struct io_kiocb *req);

/* Issue a poll operation for a request. */
int io_poll_issue(struct io_kiocb *req, io_tw_token_t tw);

/* Submit a number of SQEs to the io_uring context. */
int io_submit_sqes(struct io_ring_ctx *ctx, unsigned int nr);

/* Perform IO polling on the io_uring context. */
int io_do_iopoll(struct io_ring_ctx *ctx, bool force_nonspin);

/* Flush completion queue events to userspace. */
void __io_submit_flush_completions(struct io_ring_ctx *ctx);

/* Free an io_wq_work structure. */
struct io_wq_work *io_wq_free_work(struct io_wq_work *work);

/* Submit io_wq_work to the workqueue. */
void io_wq_submit_work(struct io_wq_work *work);

/* Free an io_kiocb request. */
void io_free_req(struct io_kiocb *req);

/* Queue the next request in sequence. */
void io_queue_next(struct io_kiocb *req);

/* Refill task reference counters. */
void io_task_refs_refill(struct io_uring_task *tctx);

/* Refill the request allocation cache. */
bool __io_alloc_req_refill(struct io_ring_ctx *ctx);

/* heck if a request matches a given task context safely. */
bool io_match_task_safe(struct io_kiocb *head, struct io_uring_task *tctx,
			bool cancel_all);

/* Activate the poll workqueue for an io_uring context. */
void io_activate_pollwq(struct io_ring_ctx *ctx);

/* uses lockdep assertions to verify that the appropriate locks
 * are held when manipulating the completion queue (CQ) of an io_uring instance.
 * The assertions vary depending on the io_uring setup flags:
 * - If DEFER_TASKRUN is set, the uring_lock must be held.
 * - If IOPOLL is enabled, uring_lock must be held.
 * - Otherwise, if task_complete is not set, completion_lock must be held.
 * - If submitter_task is set, the current task must be the submitter_task unless
 *   the context is dying.
 * These checks help catch locking violations during development and debugging. */
static inline void io_lockdep_assert_cq_locked(struct io_ring_ctx *ctx)
{
#if defined(CONFIG_PROVE_LOCKING)
	lockdep_assert(in_task());

	if (ctx->flags & IORING_SETUP_DEFER_TASKRUN)
		lockdep_assert_held(&ctx->uring_lock);

	if (ctx->flags & IORING_SETUP_IOPOLL) {
		lockdep_assert_held(&ctx->uring_lock);
	} else if (!ctx->task_complete) {
		lockdep_assert_held(&ctx->completion_lock);
	} else if (ctx->submitter_task) {
		/*
		 * ->submitter_task may be NULL and we can still post a CQE,
		 * if the ring has been setup with IORING_SETUP_R_DISABLED.
		 * Not from an SQE, as those cannot be submitted, but via
		 * updating tagged resources.
		 */
		if (!percpu_ref_is_dying(&ctx->refs))
			lockdep_assert(current == ctx->submitter_task);
	}
#endif
}

/* Returns true if CONFIG_COMPAT is enabled and the context is marked as compat. */
static inline bool io_is_compat(struct io_ring_ctx *ctx)
{
	return IS_ENABLED(CONFIG_COMPAT) && unlikely(ctx->compat);
}

/* Convenience inline wrapper to add task work with zero flags. */
static inline void io_req_task_work_add(struct io_kiocb *req)
{
	__io_req_task_work_add(req, 0);
}

/* checks if there are any pending completion requests
 * in the submit_state or if a completion queue flush is requested. If either
 * condition is true, it calls __io_submit_flush_completions() to make the
 * completion events visible to userspace.
 * This helps optimize flushing by avoiding unnecessary flush operations. */
static inline void io_submit_flush_completions(struct io_ring_ctx *ctx)
{
	if (!wq_list_empty(&ctx->submit_state.compl_reqs) ||
	    ctx->submit_state.cq_flush)
		__io_submit_flush_completions(ctx);
}

#define io_for_each_link(pos, head) \
	for (pos = (head); pos; pos = pos->link)

/* asserts the CQ lock is held, then attempts to get the next CQE
 * from the cached CQE pointer. If the cache is exhausted, it attempts to refill it.
 * It updates the cached CQ tail and CQE pointer accordingly.
 * If the IORING_SETUP_CQE32 flag is set, it accounts for 32-byte CQEs by advancing
 * the pointer an extra step.
 * Returns true if a CQE was successfully retrieved, false otherwise. */
static inline bool io_get_cqe_overflow(struct io_ring_ctx *ctx,
					struct io_uring_cqe **ret,
					bool overflow)
{
	io_lockdep_assert_cq_locked(ctx);

	if (unlikely(ctx->cqe_cached >= ctx->cqe_sentinel)) {
		if (unlikely(!io_cqe_cache_refill(ctx, overflow)))
			return false;
	}
	*ret = ctx->cqe_cached;
	ctx->cached_cq_tail++;
	ctx->cqe_cached++;
	if (ctx->flags & IORING_SETUP_CQE32)
		ctx->cqe_cached++;
	return true;
}

/*  Wrapper around io_get_cqe_overflow with overflow set to false.
 * Returns true if a CQE was successfully retrieved, false otherwise. */
static inline bool io_get_cqe(struct io_ring_ctx *ctx, struct io_uring_cqe **ret)
{
	return io_get_cqe_overflow(ctx, ret, false);
}

/* Marks that an extra CQE is pending and requests a CQ flush.
 * Then attempts to get a CQE for deferred completion.
 * Returns true if a CQE was successfully retrieved, false otherwise. */
static inline bool io_defer_get_uncommited_cqe(struct io_ring_ctx *ctx,
					       struct io_uring_cqe **cqe_ret)
{
	io_lockdep_assert_cq_locked(ctx);

	ctx->cq_extra++;
	ctx->submit_state.cq_flush = true;
	return io_get_cqe(ctx, cqe_ret);
}

/* Attempts to get a CQE from the ring and copies the request's CQE data into it.
 * If 32-byte CQEs are enabled, copies the extended CQE data and clears the request's big_cqe.
 * Optionally traces the completion event if tracing is enabled.
 * Returns true if a CQE was successfully filled, false if no CQE was available. */
static __always_inline bool io_fill_cqe_req(struct io_ring_ctx *ctx,
					    struct io_kiocb *req)
{
	struct io_uring_cqe *cqe;

	/*
	 * If we can't get a cq entry, userspace overflowed the
	 * submission (by quite a lot). Increment the overflow count in
	 * the ring.
	 */
	if (unlikely(!io_get_cqe(ctx, &cqe)))
		return false;


	memcpy(cqe, &req->cqe, sizeof(*cqe));
	if (ctx->flags & IORING_SETUP_CQE32) {
		memcpy(cqe->big_cqe, &req->big_cqe, sizeof(*cqe));
		memset(&req->big_cqe, 0, sizeof(req->big_cqe));
	}

	if (trace_io_uring_complete_enabled())
		trace_io_uring_complete(req->ctx, req, cqe);
	return true;
}

static inline void req_set_fail(struct io_kiocb *req)
{
	req->flags |= REQ_F_FAIL;
	if (req->flags & REQ_F_CQE_SKIP) {
		req->flags &= ~REQ_F_CQE_SKIP;
		req->flags |= REQ_F_SKIP_LINK_CQES;
	}
}

/* Sets the failure flag on the request. If the request was marked to skip CQE,
 * it clears that flag and sets the flag to skip linked CQEs instead. */
static inline void io_req_set_res(struct io_kiocb *req, s32 res, u32 cflags)
{
	req->cqe.res = res;
	req->cqe.flags = cflags;
}

/* Allocates memory for async data associated with the request. If a cache is
 * provided, allocation is done from the cache; otherwise, kmalloc is used with
 * the size defined by the opcode's async_size.
 * Sets the REQ_F_ASYNC_DATA flag if allocation succeeds.
 * Returns pointer to the allocated async data or NULL on failure */
static inline void *io_uring_alloc_async_data(struct io_alloc_cache *cache,
					      struct io_kiocb *req)
{
	if (cache) {
		req->async_data = io_cache_alloc(cache, GFP_KERNEL);
	} else {
		const struct io_issue_def *def = &io_issue_defs[req->opcode];

		WARN_ON_ONCE(!def->async_size);
		req->async_data = kmalloc(def->async_size, GFP_KERNEL);
	}
	if (req->async_data)
		req->flags |= REQ_F_ASYNC_DATA;
	return req->async_data;
}

/* Returns true if the request has async data allocated, false otherwise. */
static inline bool req_has_async_data(struct io_kiocb *req)
{
	return req->flags & REQ_F_ASYNC_DATA;
}

/* Releases the file reference if the request does not use a fixed file and
 * if a file pointer is present. */
static inline void io_put_file(struct io_kiocb *req)
{
	if (!(req->flags & REQ_F_FIXED_FILE) && req->file)
		fput(req->file);
}

/* Unlocks the uring_lock mutex if the IO_URING_F_UNLOCKED flag is set,
 * indicating the lock was not held prior to submission. */
static inline void io_ring_submit_unlock(struct io_ring_ctx *ctx,
					 unsigned issue_flags)
{
	lockdep_assert_held(&ctx->uring_lock);
	if (unlikely(issue_flags & IO_URING_F_UNLOCKED))
		mutex_unlock(&ctx->uring_lock);
}

/* Locks the uring_lock mutex if the IO_URING_F_UNLOCKED flag is set,
 * which occurs when requests are issued from an async worker thread
 * detached from the normal syscall context.
 * Asserts that the lock is held after this function. */
static inline void io_ring_submit_lock(struct io_ring_ctx *ctx,
				       unsigned issue_flags)
{
	/*
	 * "Normal" inline submissions always hold the uring_lock, since we
	 * grab it from the system call. Same is true for the SQPOLL offload.
	 * The only exception is when we've detached the request and issue it
	 * from an async worker thread, grab the lock for that case.
	 */
	if (unlikely(issue_flags & IO_URING_F_UNLOCKED))
		mutex_lock(&ctx->uring_lock);
	lockdep_assert_held(&ctx->uring_lock);
}

/* Uses smp_store_release to ensure that all CQE stores are visible before
 * updating the completion queue tail pointer, maintaining proper memory ordering. */
static inline void io_commit_cqring(struct io_ring_ctx *ctx)
{
	/* order cqe stores with ring update */
	smp_store_release(&ctx->rings->cq.tail, ctx->cached_cq_tail);
}

/* Checks if the poll workqueue has any waiting tasks and wakes them up
 * with the appropriate event mask for io_uring polling. */
static inline void io_poll_wq_wake(struct io_ring_ctx *ctx)
{
	if (wq_has_sleeper(&ctx->poll_wq))
		__wake_up(&ctx->poll_wq, TASK_NORMAL, 0,
				poll_to_key(EPOLL_URING_WAKE | EPOLLIN));
}

/* triggers the waitqueue handler for all tasks waiting on the CQ waitqueue.
 * It uses the event mask EPOLLIN | EPOLL_URING_WAKE to notify waiters. The EPOLL_URING_WAKE
 * flag helps detect recursion into poll waitqueue handlers and terminates multishot polls
 * appropriately. */
static inline void io_cqring_wake(struct io_ring_ctx *ctx)
{
	/*
	 * Trigger waitqueue handler on all waiters on our waitqueue. This
	 * won't necessarily wake up all the tasks, io_should_wake() will make
	 * that decision.
	 *
	 * Pass in EPOLLIN|EPOLL_URING_WAKE as the poll wakeup key. The latter
	 * set in the mask so that if we recurse back into our own poll
	 * waitqueue handlers, we know we have a dependency between eventfd or
	 * epoll and should terminate multishot poll at that point.
	 */
	if (wq_has_sleeper(&ctx->cq_wait))
		__wake_up(&ctx->cq_wait, TASK_NORMAL, 0,
				poll_to_key(EPOLL_URING_WAKE | EPOLLIN));
}

/* For SQPOLL mode, reads the actual sqring head to avoid races with the polling thread.
 * Returns true if the SQ ring is full (tail - head == sq_entries), false otherwise. */
static inline bool io_sqring_full(struct io_ring_ctx *ctx)
{
	struct io_rings *r = ctx->rings;

	/*
	 * SQPOLL must use the actual sqring head, as using the cached_sq_head
	 * is race prone if the SQPOLL thread has grabbed entries but not yet
	 * committed them to the ring. For !SQPOLL, this doesn't matter, but
	 * since this helper is just used for SQPOLL sqring waits (or POLLOUT),
	 * just read the actual sqring head unconditionally.
	 */
	return READ_ONCE(r->sq.tail) - READ_ONCE(r->sq.head) == ctx->sq_entries;
}

/* Calculates the number of SQ entries available by subtracting the cached SQ head
 * from the current SQ tail, using smp_load_acquire to ensure proper memory ordering.
 * Returns the minimum of this value and the maximum sq_entries. */
static inline unsigned int io_sqring_entries(struct io_ring_ctx *ctx)
{
	struct io_rings *rings = ctx->rings;
	unsigned int entries;

	/* make sure SQ entry isn't read before tail */
	entries = smp_load_acquire(&rings->sq.tail) - ctx->cached_sq_head;
	return min(entries, ctx->sq_entries);
}

/* processes any pending task work notifications for the current thread.
 * It handles clearing notification signals, running task work for IO worker threads,
 * and running any generic task work pending on the current task.
 * Returns true if any task work was executed, false otherwise */
static inline int io_run_task_work(void)
{
	bool ret = false;

	/*
	 * Always check-and-clear the task_work notification signal. With how
	 * signaling works for task_work, we can find it set with nothing to
	 * run. We need to clear it for that case, like get_signal() does.
	 */
	if (test_thread_flag(TIF_NOTIFY_SIGNAL))
		clear_notify_signal();
	/*
	 * PF_IO_WORKER never returns to userspace, so check here if we have
	 * notify work that needs processing.
	 */
	if (current->flags & PF_IO_WORKER) {
		if (test_thread_flag(TIF_NOTIFY_RESUME)) {
			__set_current_state(TASK_RUNNING);
			resume_user_mode_work(NULL);
		}
		if (current->io_uring) {
			unsigned int count = 0;

			__set_current_state(TASK_RUNNING);
			tctx_task_work_run(current->io_uring, UINT_MAX, &count);
			if (count)
				ret = true;
		}
	}
	if (task_work_pending(current)) {
		__set_current_state(TASK_RUNNING);
		task_work_run();
		ret = true;
	}

	return ret;
}

/* Returns true if there are any pending local work items or retry work. */
static inline bool io_local_work_pending(struct io_ring_ctx *ctx)
{
	return !llist_empty(&ctx->work_llist) || !llist_empty(&ctx->retry_llist);
}

/* Returns true if there is task work pending on the current task or local io_uring work. */
static inline bool io_task_work_pending(struct io_ring_ctx *ctx)
{
	return task_work_pending(current) || io_local_work_pending(ctx);
}

/* Uses lockdep to verify that the uring_lock mutex is held before proceeding. */
static inline void io_tw_lock(struct io_ring_ctx *ctx, io_tw_token_t tw)
{
	lockdep_assert_held(&ctx->uring_lock);
}

/*
 * Don't complete immediately but use deferred completion infrastructure.
 * Protected by ->uring_lock and can only be used either with
 * IO_URING_F_COMPLETE_DEFER or inside a tw handler holding the mutex.
 */
static inline void io_req_complete_defer(struct io_kiocb *req)
	__must_hold(&req->ctx->uring_lock)
{
	struct io_submit_state *state = &req->ctx->submit_state;

	lockdep_assert_held(&req->ctx->uring_lock);

	wq_list_add_tail(&req->comp_list, &state->compl_reqs);
}

/* Flushes the CQ ring if any of the following conditions are true:
 * - An offset timeout is used.
 * - Drain is active.
 * - An eventfd is present.
 * - Polling is activated.
 * This ensures that completion events are made visible to userspace in these cases. */
static inline void io_commit_cqring_flush(struct io_ring_ctx *ctx)
{
	if (unlikely(ctx->off_timeout_used || ctx->drain_active ||
		     ctx->has_evfd || ctx->poll_activated))
		__io_commit_cqring_flush(ctx);
}

/* Decrements the cached_refs counter of the current io_uring task context by @nr.
 * If the cached_refs drop below zero, it triggers a refill of task references. */
static inline void io_get_task_refs(int nr)
{
	struct io_uring_task *tctx = current->io_uring;

	tctx->cached_refs -= nr;
	if (unlikely(tctx->cached_refs < 0))
		io_task_refs_refill(tctx);
}

/* Returns true if the free_list has no next element, indicating the cache is empty. */
static inline bool io_req_cache_empty(struct io_ring_ctx *ctx)
{
	return !ctx->submit_state.free_list.next;
}

/* External declaration of the kmem_cache for io_kiocb requests */
extern struct kmem_cache *req_cachep;

/* Removes and returns the first io_kiocb request from the free_list. */
static inline struct io_kiocb *io_extract_req(struct io_ring_ctx *ctx)
{
	struct io_kiocb *req;

	req = container_of(ctx->submit_state.free_list.next, struct io_kiocb, comp_list);
	wq_stack_extract(&ctx->submit_state.free_list);
	return req;
}

/* Attempts to allocate a request from the cached free list. If the cache is empty,
 * it tries to refill it. Returns true if a request was successfully allocated,
 * false otherwise. */
static inline bool io_alloc_req(struct io_ring_ctx *ctx, struct io_kiocb **req)
{
	if (unlikely(io_req_cache_empty(ctx))) {
		if (!__io_alloc_req_refill(ctx))
			return false;
	}
	*req = io_extract_req(ctx);
	return true;
}

/* Returns true if the current task is the submitter task, indicating it is allowed
 * to run deferred task work. */
static inline bool io_allowed_defer_tw_run(struct io_ring_ctx *ctx)
{
	return likely(ctx->submitter_task == current);
}

/* Returns true if either DEFER_TASKRUN is not set, or if the current task is the submitter. */
static inline bool io_allowed_run_tw(struct io_ring_ctx *ctx)
{
	return likely(!(ctx->flags & IORING_SETUP_DEFER_TASKRUN) ||
		      ctx->submitter_task == current);
}

/*
 * Terminate the request if either of these conditions are true:
 *
 * 1) It's being executed by the original task, but that task is marked
 *    with PF_EXITING as it's exiting.
 * 2) PF_KTHREAD is set, in which case the invoker of the task_work is
 *    our fallback task_work.
 */
static inline bool io_should_terminate_tw(void)
{
	return current->flags & (PF_KTHREAD | PF_EXITING);
}

/* Sets the result and flags of the request's CQE, assigns the completion function,
 * and adds the request to the task work queue for asynchronous completion handling. */
static inline void io_req_queue_tw_complete(struct io_kiocb *req, s32 res)
{
	io_req_set_res(req, res, 0);
	req->io_task_work.func = io_req_task_complete;
	io_req_task_work_add(req);
}

/*
 * IORING_SETUP_SQE128 contexts allocate twice the normal SQE size for each
 * slot.
 */
static inline size_t uring_sqe_size(struct io_ring_ctx *ctx)
{
	if (ctx->flags & IORING_SETUP_SQE128)
		return 2 * sizeof(struct io_uring_sqe);
	return sizeof(struct io_uring_sqe);
}

/* Returns true if the request is marked as able to poll or if the associated file
 * supports polling. If the file supports polling, the request flag REQ_F_CAN_POLL
 * is set for future fast checks. */
static inline bool io_file_can_poll(struct io_kiocb *req)
{
	if (req->flags & REQ_F_CAN_POLL)
		return true;
	if (req->file && file_can_poll(req->file)) {
		req->flags |= REQ_F_CAN_POLL;
		return true;
	}
	return false;
}

/* Returns the current time as a ktime_t. If the context's clockid is CLOCK_MONOTONIC,
 * returns the monotonic time. Otherwise, returns the time with the stored clock offset. */
static inline ktime_t io_get_time(struct io_ring_ctx *ctx)
{
	if (ctx->clockid == CLOCK_MONOTONIC)
		return ktime_get();

	return ktime_get_with_offset(ctx->clock_offset);
}

enum {
	IO_CHECK_CQ_OVERFLOW_BIT,
	IO_CHECK_CQ_DROPPED_BIT,
};

/* Returns true if either the completion queue overflow check bit is set,
 * or if there is any local io_uring work pending. */
static inline bool io_has_work(struct io_ring_ctx *ctx)
{
	return test_bit(IO_CHECK_CQ_OVERFLOW_BIT, &ctx->check_cq) ||
	       io_local_work_pending(ctx);
}
#endif
