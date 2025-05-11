// SPDX-License-Identifier: GPL-2.0
/*
 * Shared application/kernel submission and completion ring pairs, for
 * supporting fast/efficient IO.
 *
 * A note on the read/write ordering memory barriers that are matched between
 * the application and kernel side.
 *
 * After the application reads the CQ ring tail, it must use an
 * appropriate smp_rmb() to pair with the smp_wmb() the kernel uses
 * before writing the tail (using smp_load_acquire to read the tail will
 * do). It also needs a smp_mb() before updating CQ head (ordering the
 * entry load(s) with the head store), pairing with an implicit barrier
 * through a control-dependency in io_get_cqe (smp_store_release to
 * store head will do). Failure to do so could lead to reading invalid
 * CQ entries.
 *
 * Likewise, the application must use an appropriate smp_wmb() before
 * writing the SQ tail (ordering SQ entry stores with the tail store),
 * which pairs with smp_load_acquire in io_get_sqring (smp_store_release
 * to store the tail will do). And it needs a barrier ordering the SQ
 * head load before writing new SQ entries (smp_load_acquire to read
 * head will do).
 *
 * When using the SQ poll thread (IORING_SETUP_SQPOLL), the application
 * needs to check the SQ flags for IORING_SQ_NEED_WAKEUP *after*
 * updating the SQ tail; a full memory barrier smp_mb() is needed
 * between.
 *
 * Also see the examples in the liburing library:
 *
 *	git://git.kernel.dk/liburing
 *
 * io_uring also uses READ/WRITE_ONCE() for _any_ store or load that happens
 * from data shared between the kernel and application. This is done both
 * for ordering purposes, but also to ensure that once a value is loaded from
 * data that the application could potentially modify, it remains stable.
 *
 * Copyright (C) 2018-2019 Jens Axboe
 * Copyright (c) 2018-2019 Christoph Hellwig
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/syscalls.h>
#include <net/compat.h>
#include <linux/refcount.h>
#include <linux/uio.h>
#include <linux/bits.h>

#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/bvec.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/anon_inodes.h>
#include <linux/sched/mm.h>
#include <linux/uaccess.h>
#include <linux/nospec.h>
#include <linux/fsnotify.h>
#include <linux/fadvise.h>
#include <linux/task_work.h>
#include <linux/io_uring.h>
#include <linux/io_uring/cmd.h>
#include <linux/audit.h>
#include <linux/security.h>
#include <linux/jump_label.h>
#include <asm/shmparam.h>

#define CREATE_TRACE_POINTS
#include <trace/events/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io-wq.h"

#include "io_uring.h"
#include "opdef.h"
#include "refs.h"
#include "tctx.h"
#include "register.h"
#include "sqpoll.h"
#include "fdinfo.h"
#include "kbuf.h"
#include "rsrc.h"
#include "cancel.h"
#include "net.h"
#include "notif.h"
#include "waitid.h"
#include "futex.h"
#include "napi.h"
#include "uring_cmd.h"
#include "msg_ring.h"
#include "memmap.h"
#include "zcrx.h"

#include "timeout.h"
#include "poll.h"
#include "rw.h"
#include "alloc_cache.h"
#include "eventfd.h"

#define SQE_COMMON_FLAGS (IOSQE_FIXED_FILE | IOSQE_IO_LINK | \
			  IOSQE_IO_HARDLINK | IOSQE_ASYNC)

#define SQE_VALID_FLAGS	(SQE_COMMON_FLAGS | IOSQE_BUFFER_SELECT | \
			IOSQE_IO_DRAIN | IOSQE_CQE_SKIP_SUCCESS)

#define IO_REQ_LINK_FLAGS (REQ_F_LINK | REQ_F_HARDLINK)

#define IO_REQ_CLEAN_FLAGS (REQ_F_BUFFER_SELECTED | REQ_F_NEED_CLEANUP | \
				REQ_F_POLLED | REQ_F_INFLIGHT | REQ_F_CREDS | \
				REQ_F_ASYNC_DATA)

#define IO_REQ_CLEAN_SLOW_FLAGS (REQ_F_REFCOUNT | IO_REQ_LINK_FLAGS | \
				 REQ_F_REISSUE | IO_REQ_CLEAN_FLAGS)

#define IO_TCTX_REFS_CACHE_NR	(1U << 10)

#define IO_COMPL_BATCH			32
#define IO_REQ_ALLOC_BATCH		8
#define IO_LOCAL_TW_DEFAULT_MAX		20

struct io_defer_entry {
	struct list_head	list;
	struct io_kiocb		*req;
	u32			seq;
};

/* requests with any of those set should undergo io_disarm_next() */
#define IO_DISARM_MASK (REQ_F_ARM_LTIMEOUT | REQ_F_LINK_TIMEOUT | REQ_F_FAIL)

/*
 * No waiters. It's larger than any valid value of the tw counter
 * so that tests against ->cq_wait_nr would fail and skip wake_up().
 */
#define IO_CQ_WAKE_INIT		(-1U)
/* Forced wake up if there is a waiter regardless of ->cq_wait_nr */
#define IO_CQ_WAKE_FORCE	(IO_CQ_WAKE_INIT >> 1)

/* Attempt to cancel io_uring requests for a task. */
static bool io_uring_try_cancel_requests(struct io_ring_ctx *ctx,
					 struct io_uring_task *tctx,
					 bool cancel_all,
					 bool is_sqpoll_thread);

/* Queue an io_uring submission queue entry for processing. */					 
static void io_queue_sqe(struct io_kiocb *req);

static __read_mostly DEFINE_STATIC_KEY_FALSE(io_key_has_sqarray);

struct kmem_cache *req_cachep;
static struct workqueue_struct *iou_wq __ro_after_init;

static int __read_mostly sysctl_io_uring_disabled;
static int __read_mostly sysctl_io_uring_group = -1;

#ifdef CONFIG_SYSCTL
static const struct ctl_table kernel_io_uring_disabled_table[] = {
	{
		.procname	= "io_uring_disabled",
		.data		= &sysctl_io_uring_disabled,
		.maxlen		= sizeof(sysctl_io_uring_disabled),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_TWO,
	},
	{
		.procname	= "io_uring_group",
		.data		= &sysctl_io_uring_group,
		.maxlen		= sizeof(gid_t),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
};
#endif

/* Calculates how many completion queue entries are available by subtracting
 * the current head from the cached tail. */
static inline unsigned int __io_cqring_events(struct io_ring_ctx *ctx)
{
	return ctx->cached_cq_tail - READ_ONCE(ctx->rings->cq.head);
}

/* Returns the number of completion queue entries that the user can consume,
 * calculated as the difference between the ring's tail and head pointers. */
static inline unsigned int __io_cqring_events_user(struct io_ring_ctx *ctx)
{
	return READ_ONCE(ctx->rings->cq.tail) - READ_ONCE(ctx->rings->cq.head);
}

/* Iterates over all linked io_kiocb requests starting from @head and checks
 * if any of them have the REQ_F_INFLIGHT flag set, indicating they are currently
 * being processed.
 * Returns true if any linked request is inflight, false otherwise. */
static bool io_match_linked(struct io_kiocb *head)
{
	struct io_kiocb *req;

	io_for_each_link(req, head) {
		if (req->flags & REQ_F_INFLIGHT)
			return true;
	}
	return false;
}

/* Checks whether the request chain belongs to the specified task context (@tctx).
 * If @cancel_all is true, all requests match unconditionally.
 * For requests with linked timeouts, locking is used to protect against races
 * when checking linked requests. Returns true if the request chain matches 
 * the task context or cancellation criteria, false otherwise. */
/*
 * As io_match_task() but protected against racing with linked timeouts.
 * User must not hold timeout_lock.
 */
bool io_match_task_safe(struct io_kiocb *head, struct io_uring_task *tctx,
			bool cancel_all)
{
	bool matched;

	if (tctx && head->tctx != tctx)
		return false;
	if (cancel_all)
		return true;

	if (head->flags & REQ_F_LINK_TIMEOUT) {
		struct io_ring_ctx *ctx = head->ctx;

		/* protect against races with linked timeouts */
		raw_spin_lock_irq(&ctx->timeout_lock);
		matched = io_match_linked(head);
		raw_spin_unlock_irq(&ctx->timeout_lock);
	} else {
		matched = io_match_linked(head);
	}
	return matched;
}

/* Sets the request's failure flag and records the failure result,
 * indicating that this linked request node has failed. */
static inline void req_fail_link_node(struct io_kiocb *req, int res)
{
	req_set_fail(req);
	io_req_set_res(req, res, 0);
}

/* Adds the request's completion list node to the context's free list,
 * enabling efficient reuse of request structures without reallocating. */
static inline void io_req_add_to_cache(struct io_kiocb *req, struct io_ring_ctx *ctx)
{
	wq_stack_add_head(&req->comp_list, &ctx->submit_state.free_list);
}

/* Called when all references to the io_uring context have been dropped.
 * Signals completion to notify that the io_ring_ctx can be safely freed. */
static __cold void io_ring_ctx_ref_free(struct percpu_ref *ref)
{
	struct io_ring_ctx *ctx = container_of(ref, struct io_ring_ctx, refs);

	complete(&ctx->ref_comp);
}

/* This function is scheduled when fallback requests are pending in the io_uring context.
 * It safely retrieves all fallback requests from the lockless list, increments the context
 * reference count to prevent premature freeing, and processes each request by invoking
 * its associated io_task_work function. After processing, it flushes completions,
 * releases the context lock, and decrements the reference count. */
static __cold void io_fallback_req_func(struct work_struct *work)
{
	struct io_ring_ctx *ctx = container_of(work, struct io_ring_ctx,
						fallback_work.work);
	struct llist_node *node = llist_del_all(&ctx->fallback_llist);
	struct io_kiocb *req, *tmp;
	struct io_tw_state ts = {};

	percpu_ref_get(&ctx->refs);
	mutex_lock(&ctx->uring_lock);
	llist_for_each_entry_safe(req, tmp, node, io_task_work.node)
		req->io_task_work.func(req, ts);
	io_submit_flush_completions(ctx);
	mutex_unlock(&ctx->uring_lock);
	percpu_ref_put(&ctx->refs);
}

/* Attempts to allocate a hash table with 2^bits buckets. If allocation fails,
 * it progressively reduces the number of bits (and thus the size) until allocation
 * succeeds or the minimum size (2 buckets) is reached.
 * On success, initializes each bucket's list head and stores the actual number of bits used.
 * Returns 0 on success, or -ENOMEM if allocation fails even at the smallest size. */
static int io_alloc_hash_table(struct io_hash_table *table, unsigned bits)
{
	unsigned int hash_buckets;
	int i;

	do {
		hash_buckets = 1U << bits;
		table->hbs = kvmalloc_array(hash_buckets, sizeof(table->hbs[0]),
						GFP_KERNEL_ACCOUNT);
		if (table->hbs)
			break;
		if (bits == 1)
			return -ENOMEM;
		bits--;
	} while (1);

	table->hash_bits = bits;
	for (i = 0; i < hash_buckets; i++)
		INIT_HLIST_HEAD(&table->hbs[i].list);
	return 0;
}

/* Releases memory and resources held by various allocation caches used within the context,
 * including caches for asynchronous polling, network messages, read/write operations,
 * command structures, messages, futexes, and other resource caches. */
static void io_free_alloc_caches(struct io_ring_ctx *ctx)
{
	io_alloc_cache_free(&ctx->apoll_cache, kfree);
	io_alloc_cache_free(&ctx->netmsg_cache, io_netmsg_cache_free);
	io_alloc_cache_free(&ctx->rw_cache, io_rw_cache_free);
	io_alloc_cache_free(&ctx->cmd_cache, io_cmd_cache_free);
	io_alloc_cache_free(&ctx->msg_cache, kfree);
	io_futex_cache_free(ctx);
	io_rsrc_cache_free(ctx);
}

/* Allocates memory for a new io_ring_ctx structure and initializes its fields,
 * including hash tables, reference counters, caches, locks, wait queues,
 * and various lists used internally by the io_uring subsystem.
 * The hash table size is chosen based on the completion queue entries, balancing
 * memory usage and performance. Multiple allocation caches are initialized for
 * different async request types. Synchronization primitives like mutexes, spinlocks,
 * and wait queues are set up to protect shared data structures.
 * Returns a pointer to the initialized io_ring_ctx on success, or NULL on failure. */
static __cold struct io_ring_ctx *io_ring_ctx_alloc(struct io_uring_params *p)
{
	struct io_ring_ctx *ctx;
	int hash_bits;
	bool ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	xa_init(&ctx->io_bl_xa);

	/*
	 * Use 5 bits less than the max cq entries, that should give us around
	 * 32 entries per hash list if totally full and uniformly spread, but
	 * don't keep too many buckets to not overconsume memory.
	 */
	hash_bits = ilog2(p->cq_entries) - 5;
	hash_bits = clamp(hash_bits, 1, 8);
	if (io_alloc_hash_table(&ctx->cancel_table, hash_bits))
		goto err;
	if (percpu_ref_init(&ctx->refs, io_ring_ctx_ref_free,
			    0, GFP_KERNEL))
		goto err;

	ctx->flags = p->flags;
	ctx->hybrid_poll_time = LLONG_MAX;
	atomic_set(&ctx->cq_wait_nr, IO_CQ_WAKE_INIT);
	init_waitqueue_head(&ctx->sqo_sq_wait);
	INIT_LIST_HEAD(&ctx->sqd_list);
	INIT_LIST_HEAD(&ctx->cq_overflow_list);
	ret = io_alloc_cache_init(&ctx->apoll_cache, IO_POLL_ALLOC_CACHE_MAX,
			    sizeof(struct async_poll), 0);
	ret |= io_alloc_cache_init(&ctx->netmsg_cache, IO_ALLOC_CACHE_MAX,
			    sizeof(struct io_async_msghdr),
			    offsetof(struct io_async_msghdr, clear));
	ret |= io_alloc_cache_init(&ctx->rw_cache, IO_ALLOC_CACHE_MAX,
			    sizeof(struct io_async_rw),
			    offsetof(struct io_async_rw, clear));
	ret |= io_alloc_cache_init(&ctx->cmd_cache, IO_ALLOC_CACHE_MAX,
			    sizeof(struct io_async_cmd),
			    sizeof(struct io_async_cmd));
	spin_lock_init(&ctx->msg_lock);
	ret |= io_alloc_cache_init(&ctx->msg_cache, IO_ALLOC_CACHE_MAX,
			    sizeof(struct io_kiocb), 0);
	ret |= io_futex_cache_init(ctx);
	ret |= io_rsrc_cache_init(ctx);
	if (ret)
		goto free_ref;
	init_completion(&ctx->ref_comp);
	xa_init_flags(&ctx->personalities, XA_FLAGS_ALLOC1);
	mutex_init(&ctx->uring_lock);
	init_waitqueue_head(&ctx->cq_wait);
	init_waitqueue_head(&ctx->poll_wq);
	spin_lock_init(&ctx->completion_lock);
	raw_spin_lock_init(&ctx->timeout_lock);
	INIT_WQ_LIST(&ctx->iopoll_list);
	INIT_LIST_HEAD(&ctx->defer_list);
	INIT_LIST_HEAD(&ctx->timeout_list);
	INIT_LIST_HEAD(&ctx->ltimeout_list);
	init_llist_head(&ctx->work_llist);
	INIT_LIST_HEAD(&ctx->tctx_list);
	ctx->submit_state.free_list.next = NULL;
	INIT_HLIST_HEAD(&ctx->waitid_list);
#ifdef CONFIG_FUTEX
	INIT_HLIST_HEAD(&ctx->futex_list);
#endif
	INIT_DELAYED_WORK(&ctx->fallback_work, io_fallback_req_func);
	INIT_WQ_LIST(&ctx->submit_state.compl_reqs);
	INIT_HLIST_HEAD(&ctx->cancelable_uring_cmd);
	io_napi_init(ctx);
	mutex_init(&ctx->mmap_lock);

	return ctx;

free_ref:
	percpu_ref_exit(&ctx->refs);
err:
	io_free_alloc_caches(ctx);
	kvfree(ctx->cancel_table.hbs);
	xa_destroy(&ctx->io_bl_xa);
	kfree(ctx);
	return NULL;
}

/* Increments the overflow counter in the completion queue ring and
 * decrements the extra completion count tracked in the context */
static void io_account_cq_overflow(struct io_ring_ctx *ctx)
{
	struct io_rings *r = ctx->rings;

	WRITE_ONCE(r->cq_overflow, READ_ONCE(r->cq_overflow) + 1);
	ctx->cq_extra--;
}

static bool req_need_defer(struct io_kiocb *req, u32 seq)
{
	if (unlikely(req->flags & REQ_F_IO_DRAIN)) {
		struct io_ring_ctx *ctx = req->ctx;

		return seq + READ_ONCE(ctx->cq_extra) != ctx->cached_cq_tail;
	}

	return false;
}

/* Frees or releases any resources allocated or referenced by the request,
 * including legacy buffers, custom cleanup handlers, polling data, inflight
 * tracking, credentials, and asynchronous data. Finally, clears the cleanup-related flags. */
static void io_clean_op(struct io_kiocb *req)
{
	if (unlikely(req->flags & REQ_F_BUFFER_SELECTED))
		io_kbuf_drop_legacy(req);

	if (req->flags & REQ_F_NEED_CLEANUP) {
		const struct io_cold_def *def = &io_cold_defs[req->opcode];

		if (def->cleanup)
			def->cleanup(req);
	}
	if ((req->flags & REQ_F_POLLED) && req->apoll) {
		kfree(req->apoll->double_poll);
		kfree(req->apoll);
		req->apoll = NULL;
	}
	if (req->flags & REQ_F_INFLIGHT)
		atomic_dec(&req->tctx->inflight_tracked);
	if (req->flags & REQ_F_CREDS)
		put_cred(req->creds);
	if (req->flags & REQ_F_ASYNC_DATA) {
		kfree(req->async_data);
		req->async_data = NULL;
	}
	req->flags &= ~IO_REQ_CLEAN_FLAGS;
}

/* If the request is not already marked as inflight, sets the inflight flag
 * and increments the inflight request counter in the associated task context. */
static inline void io_req_track_inflight(struct io_kiocb *req)
{
	if (!(req->flags & REQ_F_INFLIGHT)) {
		req->flags |= REQ_F_INFLIGHT;
		atomic_inc(&req->tctx->inflight_tracked);
	}
}

/* Validates that the request has a linked request, clears the ARM_LTIMEOUT flag,
 * sets the LINK_TIMEOUT flag to indicate a linked timeout, and sets reference counts
 * appropriately for both the request and its linked counterpart.
 * Returns the linked request pointer on success, or NULL if the link is missing. */
static struct io_kiocb *__io_prep_linked_timeout(struct io_kiocb *req)
{
	if (WARN_ON_ONCE(!req->link))
		return NULL;

	req->flags &= ~REQ_F_ARM_LTIMEOUT;
	req->flags |= REQ_F_LINK_TIMEOUT;

	/* linked timeouts should have two refs once prep'ed */
	io_req_set_refcount(req);
	__io_req_set_refcount(req->link, 2);
	return req->link;
}

/* Checks if the request has the ARM_LTIMEOUT flag set, indicating it needs
 * preparation for a linked timeout. If so, calls __io_prep_linked_timeout to
 * perform the preparation; otherwise, returns NULL.
 * Returns the linked request pointer if prepared, or NULL if no preparation was needed. */
static inline struct io_kiocb *io_prep_linked_timeout(struct io_kiocb *req)
{
	if (likely(!(req->flags & REQ_F_ARM_LTIMEOUT)))
		return NULL;
	return __io_prep_linked_timeout(req);
}

/* Prepares the linked timeout for the request and queues it for timeout handling.
 * This function ensures the linked timeout is properly set up before being queued. */
static noinline void __io_arm_ltimeout(struct io_kiocb *req)
{
	io_queue_linked_timeout(__io_prep_linked_timeout(req));
}

/* If the request has the ARM_LTIMEOUT flag set, calls __io_arm_ltimeout to
 * prepare and queue the linked timeout. */
static inline void io_arm_ltimeout(struct io_kiocb *req)
{
	if (unlikely(req->flags & REQ_F_ARM_LTIMEOUT))
		__io_arm_ltimeout(req);
}

/* Ensures the request has the proper credentials, initializes work flags,
 * and sets concurrency or unbound execution flags based on request properties.
 * For regular files, it may hash the work item by inode to optimize serialization,
 * avoiding unnecessary serialization for certain direct I/O cases or when IOPOLL is enabled. */
static void io_prep_async_work(struct io_kiocb *req)
{
	const struct io_issue_def *def = &io_issue_defs[req->opcode];
	struct io_ring_ctx *ctx = req->ctx;

	if (!(req->flags & REQ_F_CREDS)) {
		req->flags |= REQ_F_CREDS;
		req->creds = get_current_cred();
	}

	req->work.list.next = NULL;
	atomic_set(&req->work.flags, 0);
	if (req->flags & REQ_F_FORCE_ASYNC)
		atomic_or(IO_WQ_WORK_CONCURRENT, &req->work.flags);

	if (req->file && !(req->flags & REQ_F_FIXED_FILE))
		req->flags |= io_file_get_flags(req->file);

	if (req->file && (req->flags & REQ_F_ISREG)) {
		bool should_hash = def->hash_reg_file;

		/* don't serialize this request if the fs doesn't need it */
		if (should_hash && (req->file->f_flags & O_DIRECT) &&
		    (req->file->f_op->fop_flags & FOP_DIO_PARALLEL_WRITE))
			should_hash = false;
		if (should_hash || (ctx->flags & IORING_SETUP_IOPOLL))
			io_wq_hash_work(&req->work, file_inode(req->file));
	} else if (!req->file || !S_ISBLK(file_inode(req->file)->i_mode)) {
		if (def->unbound_nonreg_file)
			atomic_or(IO_WQ_WORK_UNBOUND, &req->work.flags);
	}
}

/* If the request has the LINK_TIMEOUT flag set, locks the timeout_lock to protect
 * against concurrent modifications while preparing each linked request for async work.
 * Otherwise, prepares each linked request without locking. */
static void io_prep_async_link(struct io_kiocb *req)
{
	struct io_kiocb *cur;

	if (req->flags & REQ_F_LINK_TIMEOUT) {
		struct io_ring_ctx *ctx = req->ctx;

		raw_spin_lock_irq(&ctx->timeout_lock);
		io_for_each_link(cur, req)
			io_prep_async_work(cur);
		raw_spin_unlock_irq(&ctx->timeout_lock);
	} else {
		io_for_each_link(cur, req)
			io_prep_async_work(cur);
	}
}

/* prepares the request and its linked chain for asynchronous execution,
 * verifies that the current context is suitable for queuing (not a kernel thread and
 * has a valid io_wq), and then enqueues the work. If the request belongs to a different
 * thread group, it marks the work as canceled to avoid execution issues.
 * If the request has a linked timeout, it queues that timeout as well. */
static void io_queue_iowq(struct io_kiocb *req)
{
	struct io_kiocb *link = io_prep_linked_timeout(req);
	struct io_uring_task *tctx = req->tctx;

	BUG_ON(!tctx);

	if ((current->flags & PF_KTHREAD) || !tctx->io_wq) {
		io_req_task_queue_fail(req, -ECANCELED);
		return;
	}

	/* init ->work of the whole link before punting */
	io_prep_async_link(req);

	/*
	 * Not expected to happen, but if we do have a bug where this _can_
	 * happen, catch it here and ensure the request is marked as
	 * canceled. That will make io-wq go through the usual work cancel
	 * procedure rather than attempt to run this request (or create a new
	 * worker for it).
	 */
	if (WARN_ON_ONCE(!same_thread_group(tctx->task, current)))
		atomic_or(IO_WQ_WORK_CANCEL, &req->work.flags);

	trace_io_uring_queue_async_work(req, io_wq_is_hashed(&req->work));
	io_wq_enqueue(tctx->io_wq, &req->work);
	if (link)
		io_queue_linked_timeout(link);
}

/* Wrapper to queue the request onto the io-wq workqueue. */
static void io_req_queue_iowq_tw(struct io_kiocb *req, io_tw_token_t tw)
{
	io_queue_iowq(req);
}

/* Sets the request's io_task_work function to io_req_queue_iowq_tw and schedules
 * the request to be processed via task work, ensuring safe context for queuing. */
void io_req_queue_iowq(struct io_kiocb *req)
{
	req->io_task_work.func = io_req_queue_iowq_tw;
	io_req_task_work_add(req);
}

/* Acquires the completion lock and iterates over the deferred request list.
 * For each deferred entry, checks if it still needs to be deferred using req_need_defer().
 * If not, removes it from the deferred list, queues it for execution, and frees the deferred entry.
 * Stops processing when a request still needs to be deferred. */
static __cold noinline void io_queue_deferred(struct io_ring_ctx *ctx)
{
	spin_lock(&ctx->completion_lock);
	while (!list_empty(&ctx->defer_list)) {
		struct io_defer_entry *de = list_first_entry(&ctx->defer_list,
						struct io_defer_entry, list);

		if (req_need_defer(de->req, de->seq))
			break;
		list_del_init(&de->list);
		io_req_task_queue(de->req);
		kfree(de);
	}
	spin_unlock(&ctx->completion_lock);
}

/* Wakes poll waitqueue if polling is activated, flushes any offloaded timeouts,
 * queues deferred requests if draining is active, and flushes eventfd signals
 * if the context has eventfd support enabled. */
void __io_commit_cqring_flush(struct io_ring_ctx *ctx)
{
	if (ctx->poll_activated)
		io_poll_wq_wake(ctx);
	if (ctx->off_timeout_used)
		io_flush_timeouts(ctx);
	if (ctx->drain_active)
		io_queue_deferred(ctx);
	if (ctx->has_evfd)
		io_eventfd_flush_signal(ctx);
}

/* Acquires the completion_lock spinlock unless the context is configured
 * for lockless completion queue operation. */
static inline void __io_cq_lock(struct io_ring_ctx *ctx)
{
	if (!ctx->lockless_cq)
		spin_lock(&ctx->completion_lock);
}

/* Always acquires the completion_lock spinlock.
 * Annotated with __acquires to inform static analysis tools that the lock is acquired. */
static inline void io_cq_lock(struct io_ring_ctx *ctx)
	__acquires(ctx->completion_lock)
{
	spin_lock(&ctx->completion_lock);
}

/* Commits the completion queue ring changes, then conditionally releases the
 * completion_lock if lockless_cq is not enabled and the task is not complete.
 * If not using syscall IOPOLL, wakes up waiters on the completion queue ring.
 * Finally, flushes any pending completion queue ring updates. */
static inline void __io_cq_unlock_post(struct io_ring_ctx *ctx)
{
	io_commit_cqring(ctx);
	if (!ctx->task_complete) {
		if (!ctx->lockless_cq)
			spin_unlock(&ctx->completion_lock);
		/* IOPOLL rings only need to wake up if it's also SQPOLL */
		if (!ctx->syscall_iopoll)
			io_cqring_wake(ctx);
	}
	io_commit_cqring_flush(ctx);
}

/* Commits the completion queue ring changes, releases the completion_lock unconditionally,
 * wakes up waiters on the completion queue ring, and flushes any pending completion queue ring updates.
 * Annotated with __releases to inform static analysis tools that the lock is released. */
static void io_cq_unlock_post(struct io_ring_ctx *ctx)
	__releases(ctx->completion_lock)
{
	io_commit_cqring(ctx);
	spin_unlock(&ctx->completion_lock);
	io_cqring_wake(ctx);
	io_commit_cqring_flush(ctx);
}

/* Transfers overflowed completion queue events from the overflow list back into
 * the main completion queue ring if space is available, freeing the overflow entries.
 * If the context is not dying and the completion queue is full, the flush is aborted.
 * Handles large overflow cases by yielding the CPU and reacquiring locks to avoid
 * long lock holds. Clears overflow flags once all overflow entries are flushed.
 * Requires the uring_lock to be held on entry */
static void __io_cqring_overflow_flush(struct io_ring_ctx *ctx, bool dying)
{
	size_t cqe_size = sizeof(struct io_uring_cqe);

	lockdep_assert_held(&ctx->uring_lock);

	/* don't abort if we're dying, entries must get freed */
	if (!dying && __io_cqring_events(ctx) == ctx->cq_entries)
		return;

	if (ctx->flags & IORING_SETUP_CQE32)
		cqe_size <<= 1;

	io_cq_lock(ctx);
	while (!list_empty(&ctx->cq_overflow_list)) {
		struct io_uring_cqe *cqe;
		struct io_overflow_cqe *ocqe;

		ocqe = list_first_entry(&ctx->cq_overflow_list,
					struct io_overflow_cqe, list);

		if (!dying) {
			if (!io_get_cqe_overflow(ctx, &cqe, true))
				break;
			memcpy(cqe, &ocqe->cqe, cqe_size);
		}
		list_del(&ocqe->list);
		kfree(ocqe);

		/*
		 * For silly syzbot cases that deliberately overflow by huge
		 * amounts, check if we need to resched and drop and
		 * reacquire the locks if so. Nothing real would ever hit this.
		 * Ideally we'd have a non-posting unlock for this, but hard
		 * to care for a non-real case.
		 */
		if (need_resched()) {
			io_cq_unlock_post(ctx);
			mutex_unlock(&ctx->uring_lock);
			cond_resched();
			mutex_lock(&ctx->uring_lock);
			io_cq_lock(ctx);
		}
	}

	if (list_empty(&ctx->cq_overflow_list)) {
		clear_bit(IO_CHECK_CQ_OVERFLOW_BIT, &ctx->check_cq);
		atomic_andnot(IORING_SQ_CQ_OVERFLOW, &ctx->rings->sq_flags);
	}
	io_cq_unlock_post(ctx);
}

/* Calls __io_cqring_overflow_flush with the dying flag set to true to ensure
 * all overflow completion queue events are flushed and freed during context teardown */
static void io_cqring_overflow_kill(struct io_ring_ctx *ctx)
{
	if (ctx->rings)
		__io_cqring_overflow_flush(ctx, true);
}

/* Acquires the uring_lock mutex, flushes overflow completion queue events,
 * and releases the lock. This is the normal path for flushing overflow CQEs. */
static void io_cqring_do_overflow_flush(struct io_ring_ctx *ctx)
{
	mutex_lock(&ctx->uring_lock);
	__io_cqring_overflow_flush(ctx, false);
	mutex_unlock(&ctx->uring_lock);
}

/*If the task context's cached task matches the current task, increment the cached_refs
 * counter for fast-path reference management. Otherwise, decrement the inflight counter,
 * wake any waiters if the task is in cancellation, and release the task_struct reference. */
/* must to be called somewhat shortly after putting a request */
static inline void io_put_task(struct io_kiocb *req)
{
	struct io_uring_task *tctx = req->tctx;

	if (likely(tctx->task == current)) {
		tctx->cached_refs++;
	} else {
		percpu_counter_sub(&tctx->inflight, 1);
		if (unlikely(atomic_read(&tctx->in_cancel)))
			wake_up(&tctx->wait);
		put_task_struct(tctx->task);
	}
}

/* Calculates the number of references needed to refill the cache to IO_TCTX_REFS_CACHE_NR,
 * adds the difference to the inflight counter and the current task's usage count,
 * and updates the cached_refs counter accordingly */
void io_task_refs_refill(struct io_uring_task *tctx)
{
	unsigned int refill = -tctx->cached_refs + IO_TCTX_REFS_CACHE_NR;

	percpu_counter_add(&tctx->inflight, refill);
	refcount_add(refill, &current->usage);
	tctx->cached_refs += refill;
}

/* If the task's io_uring_task context has cached references, this function clears the cache,
 * decrements the inflight counter by the cached amount, and releases the corresponding
 * number of references to the task_struct.
 * Marked __cold since it's expected to be called infrequently. */
static __cold void io_uring_drop_tctx_refs(struct task_struct *task)
{
	struct io_uring_task *tctx = task->io_uring;
	unsigned int refs = tctx->cached_refs;

	if (refs) {
		tctx->cached_refs = 0;
		percpu_counter_sub(&tctx->inflight, refs);
		put_task_struct_many(task, refs);
	}
}

/* Allocates an overflow CQE structure to store completion events when the main CQ ring is full.
 * If allocation fails, accounts for the overflow event and marks that a CQE was dropped.
 * If successful, initializes the overflow CQE with the provided data and adds it to the overflow list.
 * Also sets appropriate flags indicating overflow condition. Requires the completion_lock to be held.
 * Returns true if the overflow event was successfully queued, false otherwise. */
static bool io_cqring_event_overflow(struct io_ring_ctx *ctx, u64 user_data,
				     s32 res, u32 cflags, u64 extra1, u64 extra2)
{
	struct io_overflow_cqe *ocqe;
	size_t ocq_size = sizeof(struct io_overflow_cqe);
	bool is_cqe32 = (ctx->flags & IORING_SETUP_CQE32);

	lockdep_assert_held(&ctx->completion_lock);

	if (is_cqe32)
		ocq_size += sizeof(struct io_uring_cqe);

	ocqe = kmalloc(ocq_size, GFP_ATOMIC | __GFP_ACCOUNT);
	trace_io_uring_cqe_overflow(ctx, user_data, res, cflags, ocqe);
	if (!ocqe) {
		/*
		 * If we're in ring overflow flush mode, or in task cancel mode,
		 * or cannot allocate an overflow entry, then we need to drop it
		 * on the floor.
		 */
		io_account_cq_overflow(ctx);
		set_bit(IO_CHECK_CQ_DROPPED_BIT, &ctx->check_cq);
		return false;
	}
	if (list_empty(&ctx->cq_overflow_list)) {
		set_bit(IO_CHECK_CQ_OVERFLOW_BIT, &ctx->check_cq);
		atomic_or(IORING_SQ_CQ_OVERFLOW, &ctx->rings->sq_flags);

	}
	ocqe->cqe.user_data = user_data;
	ocqe->cqe.res = res;
	ocqe->cqe.flags = cflags;
	if (is_cqe32) {
		ocqe->cqe.big_cqe[0] = extra1;
		ocqe->cqe.big_cqe[1] = extra2;
	}
	list_add_tail(&ocqe->list, &ctx->cq_overflow_list);
	return true;
}

/* Adds the request's completion event to the context's overflow list using
 * io_cqring_event_overflow(), then clears the big_cqe data in the request */
static void io_req_cqe_overflow(struct io_kiocb *req)
{
	io_cqring_event_overflow(req->ctx, req->cqe.user_data,
				req->cqe.res, req->cqe.flags,
				req->big_cqe.extra1, req->big_cqe.extra2);
	memset(&req->big_cqe, 0, sizeof(req->big_cqe));
}

/* Attempts to update the cached CQE pointer and sentinel to a contiguous free range
 * in the completion queue ring buffer. If there are pending overflow CQEs and this
 * is not an overflow-triggered refill, returns false to force overflow handling.
 * Ensures safe bounds even if userspace has manipulated the tail pointer.
 * Returns true if the cache was successfully refilled with a contiguous range,
 * false otherwise. */
/*
 * writes to the cq entry need to come after reading head; the
 * control dependency is enough as we're using WRITE_ONCE to
 * fill the cq entry
 */
bool io_cqe_cache_refill(struct io_ring_ctx *ctx, bool overflow)
{
	struct io_rings *rings = ctx->rings;
	unsigned int off = ctx->cached_cq_tail & (ctx->cq_entries - 1);
	unsigned int free, queued, len;

	/*
	 * Posting into the CQ when there are pending overflowed CQEs may break
	 * ordering guarantees, which will affect links, F_MORE users and more.
	 * Force overflow the completion.
	 */
	if (!overflow && (ctx->check_cq & BIT(IO_CHECK_CQ_OVERFLOW_BIT)))
		return false;

	/* userspace may cheat modifying the tail, be safe and do min */
	queued = min(__io_cqring_events(ctx), ctx->cq_entries);
	free = ctx->cq_entries - queued;
	/* we need a contiguous range, limit based on the current array offset */
	len = min(free, ctx->cq_entries - off);
	if (!len)
		return false;

	if (ctx->flags & IORING_SETUP_CQE32) {
		off <<= 1;
		len <<= 1;
	}

	ctx->cqe_cached = &rings->cqes[off];
	ctx->cqe_sentinel = ctx->cqe_cached + len;
	return true;
}

/* Increments the cq_extra counter to track extra completions.
 * Tries to get a free CQE slot; if successful, writes the provided data
 * into the CQE and clears the big_cqe fields if in CQE32 mode.
 * Traces the completion event and returns true.
 * If no CQE is available, returns false indicating overflow. */
static bool io_fill_cqe_aux(struct io_ring_ctx *ctx, u64 user_data, s32 res,
			      u32 cflags)
{
	struct io_uring_cqe *cqe;

	ctx->cq_extra++;

	/*
	 * If we can't get a cq entry, userspace overflowed the
	 * submission (by quite a lot). Increment the overflow count in
	 * the ring.
	 */
	if (likely(io_get_cqe(ctx, &cqe))) {
		WRITE_ONCE(cqe->user_data, user_data);
		WRITE_ONCE(cqe->res, res);
		WRITE_ONCE(cqe->flags, cflags);

		if (ctx->flags & IORING_SETUP_CQE32) {
			WRITE_ONCE(cqe->big_cqe[0], 0);
			WRITE_ONCE(cqe->big_cqe[1], 0);
		}

		trace_io_uring_complete(ctx, NULL, cqe);
		return true;
	}
	return false;
}

/* Attempts to fill a CQE in the completion queue ring. If the ring is full,
 * falls back to storing the event in the overflow list. The completion queue
 * lock is held during the operation to ensure consistency.
 * Returns true if the CQE was successfully posted (either in the ring or overflow),
 * false otherwise. */
bool io_post_aux_cqe(struct io_ring_ctx *ctx, u64 user_data, s32 res, u32 cflags)
{
	bool filled;

	io_cq_lock(ctx);
	filled = io_fill_cqe_aux(ctx, user_data, res, cflags);
	if (!filled)
		filled = io_cqring_event_overflow(ctx, user_data, res, cflags, 0, 0);
	io_cq_unlock_post(ctx);
	return filled;
}

/* Attempts to fill a CQE directly in the completion queue ring. If no CQE is available,
 * locks the completion_lock and adds the event to the overflow list. Marks the submission
 * state to indicate that a CQ flush is required. */
/*
 * Must be called from inline task_work so we now a flush will happen later,
 * and obviously with ctx->uring_lock held (tw always has that).
 */
void io_add_aux_cqe(struct io_ring_ctx *ctx, u64 user_data, s32 res, u32 cflags)
{
	if (!io_fill_cqe_aux(ctx, user_data, res, cflags)) {
		spin_lock(&ctx->completion_lock);
		io_cqring_event_overflow(ctx, user_data, res, cflags, 0, 0);
		spin_unlock(&ctx->completion_lock);
	}
	ctx->submit_state.cq_flush = true;
}

/* Helper function for multishot requests to post additional CQEs.
 * Must be called from task_work context with IO_URING_F_MULTISHOT flag set.
 * Requires the uring_lock to be held.
 * Returns true if the CQE was successfully posted, false otherwise. */
bool io_req_post_cqe(struct io_kiocb *req, s32 res, u32 cflags)
{
	struct io_ring_ctx *ctx = req->ctx;
	bool posted;

	lockdep_assert(!io_wq_current_is_worker());
	lockdep_assert_held(&ctx->uring_lock);

	__io_cq_lock(ctx);
	posted = io_fill_cqe_aux(ctx, req->cqe.user_data, res, cflags);
	ctx->submit_state.cq_flush = true;
	__io_cq_unlock_post(ctx);
	return posted;
}

/* handles completion of requests issued via io-wq (IO_URING_F_IOWQ).
 * If the request is marked for deferred completion (lockless CQ or REQ_F_REISSUE),
 * it schedules completion via task_work. Otherwise, it attempts to fill the CQE
 * directly. If filling the CQE fails, it defers completion similarly.
 * The request reference is released at the end, assuming io-wq holds a reference.
 * WARNs if called for requests not issued via io-wq. */
static void io_req_complete_post(struct io_kiocb *req, unsigned issue_flags)
{
	struct io_ring_ctx *ctx = req->ctx;
	bool completed = true;

	/*
	 * All execution paths but io-wq use the deferred completions by
	 * passing IO_URING_F_COMPLETE_DEFER and thus should not end up here.
	 */
	if (WARN_ON_ONCE(!(issue_flags & IO_URING_F_IOWQ)))
		return;

	/*
	 * Handle special CQ sync cases via task_work. DEFER_TASKRUN requires
	 * the submitter task context, IOPOLL protects with uring_lock.
	 */
	if (ctx->lockless_cq || (req->flags & REQ_F_REISSUE)) {
defer_complete:
		req->io_task_work.func = io_req_task_complete;
		io_req_task_work_add(req);
		return;
	}

	io_cq_lock(ctx);
	if (!(req->flags & REQ_F_CQE_SKIP))
		completed = io_fill_cqe_req(ctx, req);
	io_cq_unlock_post(ctx);

	if (!completed)
		goto defer_complete;

	/*
	 * We don't free the request here because we know it's called from
	 * io-wq only, which holds a reference, so it cannot be the last put.
	 */
	req_ref_put(req);
}

/* This function must be called with the io_uring context's uring_lock held.
 * It marks the request as failed, sets the result with proper cleanup,
 * calls the opcode-specific failure handler if present, and completes the request
 * via deferred completion. */
void io_req_defer_failed(struct io_kiocb *req, s32 res)
	__must_hold(&ctx->uring_lock)
{
	const struct io_cold_def *def = &io_cold_defs[req->opcode];

	lockdep_assert_held(&req->ctx->uring_lock);

	req_set_fail(req);
	io_req_set_res(req, res, io_put_kbuf(req, res, IO_URING_F_UNLOCKED));
	if (def->fail)
		def->fail(req);
	io_req_complete_defer(req);
}

/* Initializes fields that do not need to be reset on every allocation,
 * keeping them valid across request reuse. Clears pointers to buffer and file nodes,
 * linked request, and async data. Zeroes out the completion queue event structures
 * for safety, although not strictly necessary. */
static void io_preinit_req(struct io_kiocb *req, struct io_ring_ctx *ctx)
{
	req->ctx = ctx;
	req->buf_node = NULL;
	req->file_node = NULL;
	req->link = NULL;
	req->async_data = NULL;
	/* not necessary, but safer to zero */
	memset(&req->cqe, 0, sizeof(req->cqe));
	memset(&req->big_cqe, 0, sizeof(req->big_cqe));
}

/* Allocates a batch of io_kiocb requests from the slab cache and adds them to the
 * request cache for reuse. This function must be called with the uring_lock held
 * to avoid races with request retirement and reuse.
 * Bulk allocation is attempted first for efficiency; if it fails, a single allocation
 * is tried as a fallback. The context's reference count is incremented by the number
 * of successfully allocated requests.
 * Returns true if at least one request was allocated and cached, false otherwise. */
__cold bool __io_alloc_req_refill(struct io_ring_ctx *ctx)
	__must_hold(&ctx->uring_lock)
{
	gfp_t gfp = GFP_KERNEL | __GFP_NOWARN;
	void *reqs[IO_REQ_ALLOC_BATCH];
	int ret;

	ret = kmem_cache_alloc_bulk(req_cachep, gfp, ARRAY_SIZE(reqs), reqs);

	/*
	 * Bulk alloc is all-or-nothing. If we fail to get a batch,
	 * retry single alloc to be on the safe side.
	 */
	if (unlikely(ret <= 0)) {
		reqs[0] = kmem_cache_alloc(req_cachep, gfp);
		if (!reqs[0])
			return false;
		ret = 1;
	}

	percpu_ref_get_many(&ctx->refs, ret);
	while (ret--) {
		struct io_kiocb *req = reqs[ret];

		io_preinit_req(req, ctx);
		io_req_add_to_cache(req, ctx);
	}
	return true;
}

/* Clears the reference counting flag to restore refs for task completion,
 * sets the flag to skip CQE posting, assigns the completion function to
 * io_req_task_complete, and adds the request to task work for deferred freeing.
 * Marked __cold as freeing is an infrequent operation. */
__cold void io_free_req(struct io_kiocb *req)
{
	/* refs were already put, restore them for io_req_task_complete() */
	req->flags &= ~REQ_F_REFCOUNT;
	/* we only want to free it, don't post CQEs */
	req->flags |= REQ_F_CQE_SKIP;
	req->io_task_work.func = io_req_task_complete;
	io_req_task_work_add(req);
}

/* Acquires the completion_lock to safely disarm the next linked request,
 * preventing races with completion processing. */
static void __io_req_find_next_prep(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;

	spin_lock(&ctx->completion_lock);
	io_disarm_next(req);
	spin_unlock(&ctx->completion_lock);
}

/* If the current request has the LINK flag set (indicating dependent requests),
 * it disarms the next request safely by calling __io_req_find_next_prep().
 * Then, it extracts the next linked request from the current request's link pointer,
 * clears the link to avoid double processing, and returns the next request.
 * Returns a pointer to the next io_kiocb request in the chain, or NULL if none. */
static inline struct io_kiocb *io_req_find_next(struct io_kiocb *req)
{
	struct io_kiocb *nxt;

	/*
	 * If LINK is set, we have dependent requests in this chain. If we
	 * didn't fail this request, queue the first one up, moving any other
	 * dependencies to the next request. In case of failure, fail the rest
	 * of the chain.
	 */
	if (unlikely(req->flags & IO_DISARM_MASK))
		__io_req_find_next_prep(req);
	nxt = req->link;
	req->link = NULL;
	return nxt;
}

/* If the context pointer is NULL, returns immediately.
 * If the context has the TASKRUN flag set, clears the TASKRUN flag from the submission queue flags.
 * Flushes any pending completions, unlocks the uring_lock mutex, and decrements the context's reference count. */
static void ctx_flush_and_put(struct io_ring_ctx *ctx, io_tw_token_t tw)
{
	if (!ctx)
		return;
	if (ctx->flags & IORING_SETUP_TASKRUN_FLAG)
		atomic_andnot(IORING_SQ_TASKRUN, &ctx->rings->sq_flags);

	io_submit_flush_completions(ctx);
	mutex_unlock(&ctx->uring_lock);
	percpu_ref_put(&ctx->refs);
}

/*
 * Run queued task_work, returning the number of entries processed in *count.
 * If more entries than max_entries are available, stop processing once this
 * is reached and return the rest of the list.
 */
struct llist_node *io_handle_tw_list(struct llist_node *node,
				     unsigned int *count,
				     unsigned int max_entries)
{
	struct io_ring_ctx *ctx = NULL;
	struct io_tw_state ts = { };

	do {
		struct llist_node *next = node->next;
		struct io_kiocb *req = container_of(node, struct io_kiocb,
						    io_task_work.node);

		if (req->ctx != ctx) {
			ctx_flush_and_put(ctx, ts);
			ctx = req->ctx;
			mutex_lock(&ctx->uring_lock);
			percpu_ref_get(&ctx->refs);
		}
		INDIRECT_CALL_2(req->io_task_work.func,
				io_poll_task_func, io_req_rw_complete,
				req, ts);
		node = next;
		(*count)++;
		if (unlikely(need_resched())) {
			ctx_flush_and_put(ctx, ts);
			ctx = NULL;
			cond_resched();
		}
	} while (node && *count < max_entries);

	ctx_flush_and_put(ctx, ts);
	return node;
}

/* Iterates over the list of io_kiocb requests extracted from the task work nodes.
 * For each request, if synchronous mode is enabled and the context changes,
 * flushes the previous context's fallback work and releases its reference.
 * Adds each request's task work node to the context's fallback lockless list,
 * scheduling the fallback delayed work if needed.
 * At the end, if synchronous mode is enabled, flushes and releases the last context.
 * Marked __cold as this is an infrequent fallback path. */
static __cold void __io_fallback_tw(struct llist_node *node, bool sync)
{
	struct io_ring_ctx *last_ctx = NULL;
	struct io_kiocb *req;

	while (node) {
		req = container_of(node, struct io_kiocb, io_task_work.node);
		node = node->next;
		if (sync && last_ctx != req->ctx) {
			if (last_ctx) {
				flush_delayed_work(&last_ctx->fallback_work);
				percpu_ref_put(&last_ctx->refs);
			}
			last_ctx = req->ctx;
			percpu_ref_get(&last_ctx->refs);
		}
		if (llist_add(&req->io_task_work.node,
			      &req->ctx->fallback_llist))
			schedule_delayed_work(&req->ctx->fallback_work, 1);
	}

	if (last_ctx) {
		flush_delayed_work(&last_ctx->fallback_work);
		percpu_ref_put(&last_ctx->refs);
	}
}

/* Removes all task work nodes from the task_list and processes them using
 * the __io_fallback_tw helper. */
static void io_fallback_tw(struct io_uring_task *tctx, bool sync)
{
	struct llist_node *node = llist_del_all(&tctx->task_list);

	__io_fallback_tw(node, sync);
}

/* Returns a pointer to the remaining task work nodes that were not processed,
 * or NULL if none remain.
 * If the current task is exiting, immediately processes all fallback task work synchronously.
 * Otherwise, removes all task work nodes, reverses their order, and processes up to max_entries.
 * If the task context is in cancellation, drops cached task references.
 * Traces the number of task work entries run. */
struct llist_node *tctx_task_work_run(struct io_uring_task *tctx,
				      unsigned int max_entries,
				      unsigned int *count)
{
	struct llist_node *node;

	if (unlikely(current->flags & PF_EXITING)) {
		io_fallback_tw(tctx, true);
		return NULL;
	}

	node = llist_del_all(&tctx->task_list);
	if (node) {
		node = llist_reverse_order(node);
		node = io_handle_tw_list(node, count, max_entries);
	}

	/* relaxed read is enough as only the task itself sets ->in_cancel */
	if (unlikely(atomic_read(&tctx->in_cancel)))
		io_uring_drop_tctx_refs(current);

	trace_io_uring_task_work_run(tctx, *count);
	return node;
}

/* Retrieves the io_uring_task from the callback_head pointer and runs all
 * pending task work entries by calling tctx_task_work_run with UINT_MAX to
 * process all entries. Warns if any task work remains unprocessed, which
 * should never happen. */
void tctx_task_work(struct callback_head *cb)
{
	struct io_uring_task *tctx;
	struct llist_node *ret;
	unsigned int count = 0;

	tctx = container_of(cb, struct io_uring_task, task_work);
	ret = tctx_task_work_run(tctx, UINT_MAX, &count);
	/* can't happen */
	WARN_ON_ONCE(ret);
}

/* This function atomically adds the request's task work node to the context's
 * lockless work list and manages a counter tracking queued works. It wakes
 * the submitter task if the number of queued works meets or exceeds the number
 * of waiters. If the work list was previously empty, it sets flags and signals
 * eventfd if configured. Proper synchronization ensures visibility and avoids
 * unnecessary wake-ups. */
static void io_req_local_work_add(struct io_kiocb *req, unsigned flags)
{
	struct io_ring_ctx *ctx = req->ctx;
	unsigned nr_wait, nr_tw, nr_tw_prev;
	struct llist_node *head;

	/* See comment above IO_CQ_WAKE_INIT */
	BUILD_BUG_ON(IO_CQ_WAKE_FORCE <= IORING_MAX_CQ_ENTRIES);

	/*
	 * We don't know how many reuqests is there in the link and whether
	 * they can even be queued lazily, fall back to non-lazy.
	 */
	if (req->flags & IO_REQ_LINK_FLAGS)
		flags &= ~IOU_F_TWQ_LAZY_WAKE;

	guard(rcu)();

	head = READ_ONCE(ctx->work_llist.first);
	do {
		nr_tw_prev = 0;
		if (head) {
			struct io_kiocb *first_req = container_of(head,
							struct io_kiocb,
							io_task_work.node);
			/*
			 * Might be executed at any moment, rely on
			 * SLAB_TYPESAFE_BY_RCU to keep it alive.
			 */
			nr_tw_prev = READ_ONCE(first_req->nr_tw);
		}

		/*
		 * Theoretically, it can overflow, but that's fine as one of
		 * previous adds should've tried to wake the task.
		 */
		nr_tw = nr_tw_prev + 1;
		if (!(flags & IOU_F_TWQ_LAZY_WAKE))
			nr_tw = IO_CQ_WAKE_FORCE;

		req->nr_tw = nr_tw;
		req->io_task_work.node.next = head;
	} while (!try_cmpxchg(&ctx->work_llist.first, &head,
			      &req->io_task_work.node));

	/*
	 * cmpxchg implies a full barrier, which pairs with the barrier
	 * in set_current_state() on the io_cqring_wait() side. It's used
	 * to ensure that either we see updated ->cq_wait_nr, or waiters
	 * going to sleep will observe the work added to the list, which
	 * is similar to the wait/wawke task state sync.
	 */

	if (!head) {
		if (ctx->flags & IORING_SETUP_TASKRUN_FLAG)
			atomic_or(IORING_SQ_TASKRUN, &ctx->rings->sq_flags);
		if (ctx->has_evfd)
			io_eventfd_signal(ctx);
	}

	nr_wait = atomic_read(&ctx->cq_wait_nr);
	/* not enough or no one is waiting */
	if (nr_tw < nr_wait)
		return;
	/* the previous add has already woken it up */
	if (nr_tw_prev >= nr_wait)
		return;
	wake_up_state(ctx->submitter_task, TASK_INTERRUPTIBLE);
}

/* Attempts to add the request's task work node to the io_uring_task's task_list.
 * If the node is already pending, the function returns early.
 * If this is the first pending task work, it sets the TASKRUN flag if configured.
 * For SQPOLL mode, it signals the poll thread directly without adding task work.
 * Otherwise, it tries to add task work to the task_struct. If that fails (e.g., due to
 * memory constraints), it falls back to processing the task work via the fallback path. */
static void io_req_normal_work_add(struct io_kiocb *req)
{
	struct io_uring_task *tctx = req->tctx;
	struct io_ring_ctx *ctx = req->ctx;

	/* task_work already pending, we're done */
	if (!llist_add(&req->io_task_work.node, &tctx->task_list))
		return;

	if (ctx->flags & IORING_SETUP_TASKRUN_FLAG)
		atomic_or(IORING_SQ_TASKRUN, &ctx->rings->sq_flags);

	/* SQPOLL doesn't need the task_work added, it'll run it itself */
	if (ctx->flags & IORING_SETUP_SQPOLL) {
		__set_notify_signal(tctx->task);
		return;
	}

	if (likely(!task_work_add(tctx->task, &tctx->task_work, ctx->notify_method)))
		return;

	io_fallback_tw(tctx, false);
}

/* Chooses between local deferred task work or normal task work addition depending
 * on whether the IORING_SETUP_DEFER_TASKRUN flag is set in the context */
void __io_req_task_work_add(struct io_kiocb *req, unsigned flags)
{
	if (req->ctx->flags & IORING_SETUP_DEFER_TASKRUN)
		io_req_local_work_add(req, flags);
	else
		io_req_normal_work_add(req);
}

/* This function should only be called if the context has the IORING_SETUP_DEFER_TASKRUN
 * flag set. It warns if called otherwise and delegates to __io_req_task_work_add. */
void io_req_task_work_add_remote(struct io_kiocb *req, unsigned flags)
{
	if (WARN_ON_ONCE(!(req->ctx->flags & IORING_SETUP_DEFER_TASKRUN)))
		return;
	__io_req_task_work_add(req, flags);
}

/* Removes all task work nodes from both the local work list and retry list,
 * then processes them via the fallback task work handler.
 * Marked __cold as this is an infrequent fallback path */
static void __cold io_move_task_work_from_local(struct io_ring_ctx *ctx)
{
	struct llist_node *node = llist_del_all(&ctx->work_llist);

	__io_fallback_tw(node, false);
	node = llist_del_all(&ctx->retry_llist);
	__io_fallback_tw(node, false);
}

/* Returns true if there is local work pending and the number of events processed
 * is less than the minimum required, indicating that local work should continue.
 * If the TASKRUN flag is set in the context, sets the SQ_TASKRUN flag to notify
 * the submission queue thread.
 * Returns false if no local work is pending or if the minimum events threshold is met. */
static bool io_run_local_work_continue(struct io_ring_ctx *ctx, int events,
				       int min_events)
{
	if (!io_local_work_pending(ctx))
		return false;
	if (events < min_events)
		return true;
	if (ctx->flags & IORING_SETUP_TASKRUN_FLAG)
		atomic_or(IORING_SQ_TASKRUN, &ctx->rings->sq_flags);
	return false;
}

/* Iterates over the linked list of task work nodes, invoking the function pointer
 * stored in each io_kiocb's io_task_work.func with the request and token as arguments.
 * Stops processing when either the list is exhausted or the maximum number of events
 * has been processed.
 * Returns the number of processed task work entries. */
static int __io_run_local_work_loop(struct llist_node **node,
				    io_tw_token_t tw,
				    int events)
{
	int ret = 0;

	while (*node) {
		struct llist_node *next = (*node)->next;
		struct io_kiocb *req = container_of(*node, struct io_kiocb,
						    io_task_work.node);
		INDIRECT_CALL_2(req->io_task_work.func,
				io_poll_task_func, io_req_rw_complete,
				req, tw);
		*node = next;
		if (++ret >= events)
			break;
	}

	return ret;
}

/* This function processes deferred local task work for the io_uring context,
 * including retry and main work lists. It ensures the current task is the submitter,
 * clears the TASKRUN flag if set, and processes task work in loops until the minimum
 * event count is reached or no work remains. The main work list is reversed to
 * maintain FIFO order before processing. Completions are flushed after processing.
 * Returns the total number of task work events processed. */
static int __io_run_local_work(struct io_ring_ctx *ctx, io_tw_token_t tw,
			       int min_events, int max_events)
{
	struct llist_node *node;
	unsigned int loops = 0;
	int ret = 0;

	if (WARN_ON_ONCE(ctx->submitter_task != current))
		return -EEXIST;
	if (ctx->flags & IORING_SETUP_TASKRUN_FLAG)
		atomic_andnot(IORING_SQ_TASKRUN, &ctx->rings->sq_flags);
again:
	min_events -= ret;
	ret = __io_run_local_work_loop(&ctx->retry_llist.first, tw, max_events);
	if (ctx->retry_llist.first)
		goto retry_done;

	/*
	 * llists are in reverse order, flip it back the right way before
	 * running the pending items.
	 */
	node = llist_reverse_order(llist_del_all(&ctx->work_llist));
	ret += __io_run_local_work_loop(&node, tw, max_events - ret);
	ctx->retry_llist.first = node;
	loops++;

	if (io_run_local_work_continue(ctx, ret, min_events))
		goto again;
retry_done:
	io_submit_flush_completions(ctx);
	if (io_run_local_work_continue(ctx, ret, min_events))
		goto again;

	trace_io_uring_local_work_run(ctx, ret, loops);
	return ret;
}

/* Runs local task work if any is pending, using a default maximum event count
 * or the specified minimum, whichever is larger. Assumes the caller already
 * holds the uring_lock. Returns the number of processed events. */
static inline int io_run_local_work_locked(struct io_ring_ctx *ctx,
					   int min_events)
{
	struct io_tw_state ts = {};

	if (!io_local_work_pending(ctx))
		return 0;
	return __io_run_local_work(ctx, ts, min_events,
					max(IO_LOCAL_TW_DEFAULT_MAX, min_events));
}

/* Acquires the uring_lock mutex, runs local task work with the specified
 * min and max event limits, then releases the lock.
 * Returns the number of processed events. */
static int io_run_local_work(struct io_ring_ctx *ctx, int min_events,
			     int max_events)
{
	struct io_tw_state ts = {};
	int ret;

	mutex_lock(&ctx->uring_lock);
	ret = __io_run_local_work(ctx, ts, min_events, max_events);
	mutex_unlock(&ctx->uring_lock);
	return ret;
}

/* Acquires the task work lock for the context and defers the request failure
 * with the result code stored in the request's completion entry. */
static void io_req_task_cancel(struct io_kiocb *req, io_tw_token_t tw)
{
	io_tw_lock(req->ctx, tw);
	io_req_defer_failed(req, req->cqe.res);
}

/* Acquires the task work lock for the context and decides the submission path:
 * - If task work should terminate, defers failure with -EFAULT.
 * - If the request is forced asynchronous, queues it on the io-wq.
 * - Otherwise, queues it directly on the submission queue. */
void io_req_task_submit(struct io_kiocb *req, io_tw_token_t tw)
{
	io_tw_lock(req->ctx, tw);
	if (unlikely(io_should_terminate_tw()))
		io_req_defer_failed(req, -EFAULT);
	else if (req->flags & REQ_F_FORCE_ASYNC)
		io_queue_iowq(req);
	else
		io_queue_sqe(req);
}

/* Sets the result of the request to the failure code and schedules the
 * request for cancellation by assigning io_req_task_cancel as the task work
 * function and adding it to the task work queue. */
void io_req_task_queue_fail(struct io_kiocb *req, int ret)
{
	io_req_set_res(req, ret, 0);
	req->io_task_work.func = io_req_task_cancel;
	io_req_task_work_add(req);
}

/* Assigns io_req_task_submit as the task work function and adds the request
 * to the task work queue for processing. */
void io_req_task_queue(struct io_kiocb *req)
{
	req->io_task_work.func = io_req_task_submit;
	io_req_task_work_add(req);
}

/* Finds the next request in the linked chain and queues it for submission. */
void io_queue_next(struct io_kiocb *req)
{
	struct io_kiocb *nxt = io_req_find_next(req);

	if (nxt)
		io_req_task_queue(nxt);
}

/* This function must be called with the uring_lock held.
 * Iterates over a batch of completed io_kiocb requests and performs cleanup:
 * - Handles special cases such as reissuing requests, managing reference counts,
 *   freeing async poll resources, queuing linked requests, and other cleanup.
 * - Releases associated file and task references.
 * - Returns requests to the cache for reuse. */
static void io_free_batch_list(struct io_ring_ctx *ctx,
			       struct io_wq_work_node *node)
	__must_hold(&ctx->uring_lock)
{
	do {
		struct io_kiocb *req = container_of(node, struct io_kiocb,
						    comp_list);

		if (unlikely(req->flags & IO_REQ_CLEAN_SLOW_FLAGS)) {
			if (req->flags & REQ_F_REISSUE) {
				node = req->comp_list.next;
				req->flags &= ~REQ_F_REISSUE;
				io_queue_iowq(req);
				continue;
			}
			if (req->flags & REQ_F_REFCOUNT) {
				node = req->comp_list.next;
				if (!req_ref_put_and_test(req))
					continue;
			}
			if ((req->flags & REQ_F_POLLED) && req->apoll) {
				struct async_poll *apoll = req->apoll;

				if (apoll->double_poll)
					kfree(apoll->double_poll);
				io_cache_free(&ctx->apoll_cache, apoll);
				req->flags &= ~REQ_F_POLLED;
			}
			if (req->flags & IO_REQ_LINK_FLAGS)
				io_queue_next(req);
			if (unlikely(req->flags & IO_REQ_CLEAN_FLAGS))
				io_clean_op(req);
		}
		io_put_file(req);
		io_req_put_rsrc_nodes(req);
		io_put_task(req);

		node = req->comp_list.next;
		io_req_add_to_cache(req, ctx);
	} while (node);
}

/* Iterates over the list of completed requests and attempts to post completion
 * queue entries (CQEs) for each. Requests marked for requeue or skipping CQEs
 * are excluded. If CQE posting fails (e.g., due to overflow), handles overflow
 * with appropriate locking based on whether the completion queue is lockless.
 * After processing, frees the batch of completed requests and resets the completion
 * list. Clears the cq_flush flag in the submit state. */
void __io_submit_flush_completions(struct io_ring_ctx *ctx)
	__must_hold(&ctx->uring_lock)
{
	struct io_submit_state *state = &ctx->submit_state;
	struct io_wq_work_node *node;

	__io_cq_lock(ctx);
	__wq_list_for_each(node, &state->compl_reqs) {
		struct io_kiocb *req = container_of(node, struct io_kiocb,
					    comp_list);

		/*
		 * Requests marked with REQUEUE should not post a CQE, they
		 * will go through the io-wq retry machinery and post one
		 * later.
		 */
		if (!(req->flags & (REQ_F_CQE_SKIP | REQ_F_REISSUE)) &&
		    unlikely(!io_fill_cqe_req(ctx, req))) {
			if (ctx->lockless_cq) {
				spin_lock(&ctx->completion_lock);
				io_req_cqe_overflow(req);
				spin_unlock(&ctx->completion_lock);
			} else {
				io_req_cqe_overflow(req);
			}
		}
	}
	__io_cq_unlock_post(ctx);

	if (!wq_list_empty(&state->compl_reqs)) {
		io_free_batch_list(ctx, state->compl_reqs.first);
		INIT_WQ_LIST(&state->compl_reqs);
	}
	ctx->submit_state.cq_flush = false;
}

/* performs a read memory barrier to ensure ordering of memory accesses before
 * reading the number of completion events from the completion queue ring.
 * Returns the number of completion events currently available.*/
static unsigned io_cqring_events(struct io_ring_ctx *ctx)
{
	/* See comment at the top of this file */
	smp_rmb();
	return __io_cqring_events(ctx);
}

/* This function actively polls and completes I/O events when IOPOLL mode is enabled.
 * It locks the context, repeatedly tries to reap events from the poll list, and
 * yields the CPU if needed to allow other tasks to run. This ensures efficient
 * processing of polled events while maintaining system responsiveness. */
static __cold void io_iopoll_try_reap_events(struct io_ring_ctx *ctx)
{
	if (!(ctx->flags & IORING_SETUP_IOPOLL))
		return;

	mutex_lock(&ctx->uring_lock);
	while (!wq_list_empty(&ctx->iopoll_list)) {
		/* let it sleep and repeat later if can't complete a request */
		if (io_do_iopoll(ctx, true) == 0)
			break;
		/*
		 * Ensure we allow local-to-the-cpu processing to take place,
		 * in this case we need to ensure that we reap all events.
		 * Also let task_work, etc. to progress by releasing the mutex
		 */
		if (need_resched()) {
			mutex_unlock(&ctx->uring_lock);
			cond_resched();
			mutex_lock(&ctx->uring_lock);
		}
	}
	mutex_unlock(&ctx->uring_lock);
}

/* actively polls for I/O completion events in io_uring's IOPOLL mode
 * while holding the context lock. It handles completion queue overflow and dropped events,
 * avoids unnecessary polling if events are already available, and repeatedly processes
 * local and task work. The function polls until the minimum requested events are collected,
 * or an error, signal, or reschedule request occurs, ensuring efficient and responsive
 * I/O event handling.
 * Returns 0 on success, or a negative error code on failure or interruption. */
static int io_iopoll_check(struct io_ring_ctx *ctx, unsigned int min_events)
{
	unsigned int nr_events = 0;
	unsigned long check_cq;

	min_events = min(min_events, ctx->cq_entries);

	lockdep_assert_held(&ctx->uring_lock);

	if (!io_allowed_run_tw(ctx))
		return -EEXIST;

	check_cq = READ_ONCE(ctx->check_cq);
	if (unlikely(check_cq)) {
		if (check_cq & BIT(IO_CHECK_CQ_OVERFLOW_BIT))
			__io_cqring_overflow_flush(ctx, false);
		/*
		 * Similarly do not spin if we have not informed the user of any
		 * dropped CQE.
		 */
		if (check_cq & BIT(IO_CHECK_CQ_DROPPED_BIT))
			return -EBADR;
	}
	/*
	 * Don't enter poll loop if we already have events pending.
	 * If we do, we can potentially be spinning for commands that
	 * already triggered a CQE (eg in error).
	 */
	if (io_cqring_events(ctx))
		return 0;

	do {
		int ret = 0;

		/*
		 * If a submit got punted to a workqueue, we can have the
		 * application entering polling for a command before it gets
		 * issued. That app will hold the uring_lock for the duration
		 * of the poll right here, so we need to take a breather every
		 * now and then to ensure that the issue has a chance to add
		 * the poll to the issued list. Otherwise we can spin here
		 * forever, while the workqueue is stuck trying to acquire the
		 * very same mutex.
		 */
		if (wq_list_empty(&ctx->iopoll_list) ||
		    io_task_work_pending(ctx)) {
			u32 tail = ctx->cached_cq_tail;

			(void) io_run_local_work_locked(ctx, min_events);

			if (task_work_pending(current) ||
			    wq_list_empty(&ctx->iopoll_list)) {
				mutex_unlock(&ctx->uring_lock);
				io_run_task_work();
				mutex_lock(&ctx->uring_lock);
			}
			/* some requests don't go through iopoll_list */
			if (tail != ctx->cached_cq_tail ||
			    wq_list_empty(&ctx->iopoll_list))
				break;
		}
		ret = io_do_iopoll(ctx, !min_events);
		if (unlikely(ret < 0))
			return ret;

		if (task_sigpending(current))
			return -EINTR;
		if (need_resched())
			break;

		nr_events += ret;
	} while (nr_events < min_events);

	return 0;
}

/* Defers the completion of the request to be handled later, typically by
 * scheduling it for completion processing outside the immediate context. */
void io_req_task_complete(struct io_kiocb *req, io_tw_token_t tw)
{
	io_req_complete_defer(req);
}

/*
 * After the iocb has been issued, it's safe to be found on the poll list.
 * Adding the kiocb to the list AFTER submission ensures that we don't
 * find it from a io_do_iopoll() thread before the issuer is done
 * accessing the kiocb cookie.
 */
static void io_iopoll_req_issued(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ring_ctx *ctx = req->ctx;
	const bool needs_lock = issue_flags & IO_URING_F_UNLOCKED;

	/* workqueue context doesn't hold uring_lock, grab it now */
	if (unlikely(needs_lock))
		mutex_lock(&ctx->uring_lock);

	/*
	 * Track whether we have multiple files in our lists. This will impact
	 * how we do polling eventually, not spinning if we're on potentially
	 * different devices.
	 */
	if (wq_list_empty(&ctx->iopoll_list)) {
		ctx->poll_multi_queue = false;
	} else if (!ctx->poll_multi_queue) {
		struct io_kiocb *list_req;

		list_req = container_of(ctx->iopoll_list.first, struct io_kiocb,
					comp_list);
		if (list_req->file != req->file)
			ctx->poll_multi_queue = true;
	}

	/*
	 * For fast devices, IO may have already completed. If it has, add
	 * it to the front so we find it first.
	 */
	if (READ_ONCE(req->iopoll_completed))
		wq_list_add_head(&req->comp_list, &ctx->iopoll_list);
	else
		wq_list_add_tail(&req->comp_list, &ctx->iopoll_list);

	if (unlikely(needs_lock)) {
		/*
		 * If IORING_SETUP_SQPOLL is enabled, sqes are either handle
		 * in sq thread task context or in io worker task context. If
		 * current task context is sq thread, we don't need to check
		 * whether should wake up sq thread.
		 */
		if ((ctx->flags & IORING_SETUP_SQPOLL) &&
		    wq_has_sleeper(&ctx->sq_data->wait))
			wake_up(&ctx->sq_data->wait);

		mutex_unlock(&ctx->uring_lock);
	}
}

/* determines and returns flags for an I/O request based on
 * the file's type and mode:
 * - Sets REQ_F_ISREG if the file is a regular file.
 * - Sets REQ_F_SUPPORT_NOWAIT if the file is opened with non-blocking or no-wait mode.
 * A compile-time check ensures that REQ_F_ISREG_BIT is exactly one greater than
 * REQ_F_SUPPORT_NOWAIT_BIT, maintaining flag bit ordering assumptions.
 * Returns the combined io_req_flags_t flags. */
io_req_flags_t io_file_get_flags(struct file *file)
{
	io_req_flags_t res = 0;

	BUILD_BUG_ON(REQ_F_ISREG_BIT != REQ_F_SUPPORT_NOWAIT_BIT + 1);

	if (S_ISREG(file_inode(file)->i_mode))
		res |= REQ_F_ISREG;
	if ((file->f_flags & O_NONBLOCK) || (file->f_mode & FMODE_NOWAIT))
		res |= REQ_F_SUPPORT_NOWAIT;
	return res;
}

/* calculates the original submission queue head sequence number
 * corresponding to the given request. Since the cached_sq_head in the context
 * is incremented for each submitted request, it decrements the sequence number
 * for each linked request preceding the current one to find the original sequence.
 * Returns the sequence number as a 32-bit unsigned integer. */
static u32 io_get_sequence(struct io_kiocb *req)
{
	u32 seq = req->ctx->cached_sq_head;
	struct io_kiocb *cur;

	/* need original cached_sq_head, but it was increased for each req */
	io_for_each_link(cur, req)
		seq--;
	return seq;
}

/* manages whether a request should be processed immediately or deferred.
 * It checks sequence ordering and the defer list state. If no deferral is needed,
 * it queues the request for task work. Otherwise, it prepares the request for asynchronous
 * handling, allocates a defer entry, and adds it to the defer list for later processing.
 * If memory allocation fails, the request is marked as failed.
 * Access to the defer list is protected by the completion_lock spinlock. */
static __cold void io_drain_req(struct io_kiocb *req)
	__must_hold(&ctx->uring_lock)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_defer_entry *de;
	int ret;
	u32 seq = io_get_sequence(req);

	/* Still need defer if there is pending req in defer list. */
	spin_lock(&ctx->completion_lock);
	if (!req_need_defer(req, seq) && list_empty_careful(&ctx->defer_list)) {
		spin_unlock(&ctx->completion_lock);
queue:
		ctx->drain_active = false;
		io_req_task_queue(req);
		return;
	}
	spin_unlock(&ctx->completion_lock);

	io_prep_async_link(req);
	de = kmalloc(sizeof(*de), GFP_KERNEL);
	if (!de) {
		ret = -ENOMEM;
		io_req_defer_failed(req, ret);
		return;
	}

	spin_lock(&ctx->completion_lock);
	if (!req_need_defer(req, seq) && list_empty(&ctx->defer_list)) {
		spin_unlock(&ctx->completion_lock);
		kfree(de);
		goto queue;
	}

	trace_io_uring_defer(req);
	de->req = req;
	de->seq = seq;
	list_add_tail(&de->list, &ctx->defer_list);
	spin_unlock(&ctx->completion_lock);
}

/* If the request already has a file assigned or the operation does not require
 * a file, returns true immediately.
 * Otherwise, assigns the file based on whether the request uses a fixed file
 * descriptor or a normal one:
 * - For fixed files, retrieves the file using io_file_get_fixed with the given flags.
 * - For normal files, retrieves the file using io_file_get_normal.
 * Returns true if a valid file pointer was assigned, false otherwise. */
static bool io_assign_file(struct io_kiocb *req, const struct io_issue_def *def,
			   unsigned int issue_flags)
{
	if (req->file || !def->needs_file)
		return true;

	if (req->flags & REQ_F_FIXED_FILE)
		req->file = io_file_get_fixed(req, req->cqe.fd, issue_flags);
	else
		req->file = io_file_get_normal(req, req->cqe.fd);

	return !!req->file;
}

/* This function handles credential overrides if the request specifies different
 * credentials than the current task, performs auditing before and after issuing
 * the request, and calls the operation-specific issue function.
 * Returns the result of the issue operation. */
static inline int __io_issue_sqe(struct io_kiocb *req,
				 unsigned int issue_flags,
				 const struct io_issue_def *def)
{
	const struct cred *creds = NULL;
	int ret;

	if (unlikely((req->flags & REQ_F_CREDS) && req->creds != current_cred()))
		creds = override_creds(req->creds);

	if (!def->audit_skip)
		audit_uring_entry(req->opcode);

	ret = def->issue(req, issue_flags);

	if (!def->audit_skip)
		audit_uring_exit(!ret, ret);

	if (creds)
		revert_creds(creds);

	return ret;
}

/* Retrieves the operation definition for the request opcode and attempts to
 * assign the associated file if required. If file assignment fails, returns -EBADF.
 * Calls __io_issue_sqe to perform the actual issue operation.
 * On successful issue (IOU_OK), completes the request either by deferring or posting
 * completion immediately based on issue flags.
 * If the issue returns IOU_ISSUE_SKIP_COMPLETE, it arms a timeout and, if in IOPOLL mode
 * and the operation supports it, marks the request as issued for polling.
 * Returns 0 on success or an appropriate error code. */
static int io_issue_sqe(struct io_kiocb *req, unsigned int issue_flags)
{
	const struct io_issue_def *def = &io_issue_defs[req->opcode];
	int ret;

	if (unlikely(!io_assign_file(req, def, issue_flags)))
		return -EBADF;

	ret = __io_issue_sqe(req, issue_flags, def);

	if (ret == IOU_OK) {
		if (issue_flags & IO_URING_F_COMPLETE_DEFER)
			io_req_complete_defer(req);
		else
			io_req_complete_post(req, issue_flags);

		return 0;
	}

	if (ret == IOU_ISSUE_SKIP_COMPLETE) {
		ret = 0;
		io_arm_ltimeout(req);

		/* If the op doesn't have a file, we're not polling for it */
		if ((req->ctx->flags & IORING_SETUP_IOPOLL) && def->iopoll_queue)
			io_iopoll_req_issued(req, issue_flags);
	}
	return ret;
}

/* issues the request with flags indicating non-blocking,
 * multishot, and deferred completion behavior. It locks the task work context,
 * verifies that the request has an associated file and that IOPOLL mode is not
 * enabled (which is incompatible with this function).
 * It then calls __io_issue_sqe to perform the actual issue operation.
 * The function warns if the issue returns IOU_ISSUE_SKIP_COMPLETE, which should
 * not happen in this context. Returns the result of the issue operation. */
int io_poll_issue(struct io_kiocb *req, io_tw_token_t tw)
{
	const unsigned int issue_flags = IO_URING_F_NONBLOCK |
					 IO_URING_F_MULTISHOT |
					 IO_URING_F_COMPLETE_DEFER;
	int ret;

	io_tw_lock(req->ctx, tw);

	WARN_ON_ONCE(!req->file);
	if (WARN_ON_ONCE(req->ctx->flags & IORING_SETUP_IOPOLL))
		return -EFAULT;

	ret = __io_issue_sqe(req, issue_flags, &io_issue_defs[req->opcode]);

	WARN_ON_ONCE(ret == IOU_ISSUE_SKIP_COMPLETE);
	return ret;
}

/* obtains the io_kiocb request from the work pointer and decrements
 * its reference count atomically. If the reference count reaches zero, it frees
 * the request. If the request is part of a linked chain, it returns the next linked
 * request's work pointer for further processing.
 * Returns a pointer to the next io_wq_work if there is a linked request to process,
 * or NULL otherwise. */
struct io_wq_work *io_wq_free_work(struct io_wq_work *work)
{
	struct io_kiocb *req = container_of(work, struct io_kiocb, work);
	struct io_kiocb *nxt = NULL;

	if (req_ref_put_and_test_atomic(req)) {
		if (req->flags & IO_REQ_LINK_FLAGS)
			nxt = io_req_find_next(req);
		io_free_req(req);
	}
	return nxt ? &nxt->work : NULL;
}

/* submits an I/O request to the io-wq workqueue for asynchronous execution.
 * It manages reference counting, assigns the file, and handles special cases like multishot
 * requests and forced asynchronous operations. It attempts to issue the request, retrying
 * with polling if necessary and allowed. If the request cannot be issued or is canceled,
 * it queues the request for failure completion, ensuring clean error handling outside
 * of the workqueue context. */
void io_wq_submit_work(struct io_wq_work *work)
{
	struct io_kiocb *req = container_of(work, struct io_kiocb, work);
	const struct io_issue_def *def = &io_issue_defs[req->opcode];
	unsigned int issue_flags = IO_URING_F_UNLOCKED | IO_URING_F_IOWQ;
	bool needs_poll = false;
	int ret = 0, err = -ECANCELED;

	/* one will be dropped by ->io_wq_free_work() after returning to io-wq */
	if (!(req->flags & REQ_F_REFCOUNT))
		__io_req_set_refcount(req, 2);
	else
		req_ref_get(req);

	io_arm_ltimeout(req);

	/* either cancelled or io-wq is dying, so don't touch tctx->iowq */
	if (atomic_read(&work->flags) & IO_WQ_WORK_CANCEL) {
fail:
		io_req_task_queue_fail(req, err);
		return;
	}
	if (!io_assign_file(req, def, issue_flags)) {
		err = -EBADF;
		atomic_or(IO_WQ_WORK_CANCEL, &work->flags);
		goto fail;
	}

	/*
	 * If DEFER_TASKRUN is set, it's only allowed to post CQEs from the
	 * submitter task context. Final request completions are handed to the
	 * right context, however this is not the case of auxiliary CQEs,
	 * which is the main mean of operation for multishot requests.
	 * Don't allow any multishot execution from io-wq. It's more restrictive
	 * than necessary and also cleaner.
	 */
	if (req->flags & (REQ_F_MULTISHOT|REQ_F_APOLL_MULTISHOT)) {
		err = -EBADFD;
		if (!io_file_can_poll(req))
			goto fail;
		if (req->file->f_flags & O_NONBLOCK ||
		    req->file->f_mode & FMODE_NOWAIT) {
			err = -ECANCELED;
			if (io_arm_poll_handler(req, issue_flags) != IO_APOLL_OK)
				goto fail;
			return;
		} else {
			req->flags &= ~(REQ_F_APOLL_MULTISHOT|REQ_F_MULTISHOT);
		}
	}

	if (req->flags & REQ_F_FORCE_ASYNC) {
		bool opcode_poll = def->pollin || def->pollout;

		if (opcode_poll && io_file_can_poll(req)) {
			needs_poll = true;
			issue_flags |= IO_URING_F_NONBLOCK;
		}
	}

	do {
		ret = io_issue_sqe(req, issue_flags);
		if (ret != -EAGAIN)
			break;

		/*
		 * If REQ_F_NOWAIT is set, then don't wait or retry with
		 * poll. -EAGAIN is final for that case.
		 */
		if (req->flags & REQ_F_NOWAIT)
			break;

		/*
		 * We can get EAGAIN for iopolled IO even though we're
		 * forcing a sync submission from here, since we can't
		 * wait for request slots on the block side.
		 */
		if (!needs_poll) {
			if (!(req->ctx->flags & IORING_SETUP_IOPOLL))
				break;
			if (io_wq_worker_stopped())
				break;
			cond_resched();
			continue;
		}

		if (io_arm_poll_handler(req, issue_flags) == IO_APOLL_OK)
			return;
		/* aborted or ready, in either case retry blocking */
		needs_poll = false;
		issue_flags &= ~IO_URING_F_NONBLOCK;
	} while (1);

	/* avoid locking problems by failing it from a clean context */
	if (ret)
		io_req_task_queue_fail(req, ret);
}

/* looks up the fixed file descriptor in the io_uring context's
 * file table under the submission lock. If found, it assigns the resource node
 * to the request, updates request flags based on the node, and returns the file pointer.
 * Returns the file pointer if found, or NULL otherwise. */
inline struct file *io_file_get_fixed(struct io_kiocb *req, int fd,
				      unsigned int issue_flags)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_rsrc_node *node;
	struct file *file = NULL;

	io_ring_submit_lock(ctx, issue_flags);
	node = io_rsrc_node_lookup(&ctx->file_table.data, fd);
	if (node) {
		io_req_assign_rsrc_node(&req->file_node, node);
		req->flags |= io_slot_flags(node);
		file = io_slot_file(node);
	}
	io_ring_submit_unlock(ctx, issue_flags);
	return file;
}

/* obtains the file pointer using fget(), traces the file retrieval,
 * and if the file is associated with an io_uring fixed file (which is not allowed here),
 * it tracks the request as inflight.
 * Returns the file pointer, or NULL if the descriptor is invalid. */
struct file *io_file_get_normal(struct io_kiocb *req, int fd)
{
	struct file *file = fget(fd);

	trace_io_uring_file_get(req, fd);

	/* we don't allow fixed io_uring files */
	if (file && io_is_uring_fops(file))
		io_req_track_inflight(req);
	return file;
}

/* handles queuing an asynchronous I/O request based on the result of a previous attempt.
 * If the result is not -EAGAIN or the request has the NOWAIT flag, it defers failure immediately.
 * Otherwise, it prepares any linked timeout and arms the poll handler. Based on the poll handler's status,
 * it either queues the request for immediate task work, sends it to the io-wq workqueue, or waits.
 * Linked timeouts are also queued if present.
 * Must be called with the uring_lock held. */
static void io_queue_async(struct io_kiocb *req, int ret)
	__must_hold(&req->ctx->uring_lock)
{
	struct io_kiocb *linked_timeout;

	if (ret != -EAGAIN || (req->flags & REQ_F_NOWAIT)) {
		io_req_defer_failed(req, ret);
		return;
	}

	linked_timeout = io_prep_linked_timeout(req);

	switch (io_arm_poll_handler(req, 0)) {
	case IO_APOLL_READY:
		io_kbuf_recycle(req, 0);
		io_req_task_queue(req);
		break;
	case IO_APOLL_ABORTED:
		io_kbuf_recycle(req, 0);
		io_queue_iowq(req);
		break;
	case IO_APOLL_OK:
		break;
	}

	if (linked_timeout)
		io_queue_linked_timeout(linked_timeout);
}

/* Must be called with the uring_lock held.
 * attempts to issue the SQE with non-blocking and deferred completion flags.
 * If the issue returns an error (e.g., EAGAIN), it defers the request asynchronously
 * by calling io_queue_async to handle retries or failure. */
static inline void io_queue_sqe(struct io_kiocb *req)
	__must_hold(&req->ctx->uring_lock)
{
	int ret;

	ret = io_issue_sqe(req, IO_URING_F_NONBLOCK|IO_URING_F_COMPLETE_DEFER);

	/*
	 * We async punt it if the file wasn't marked NOWAIT, or if the file
	 * doesn't support non-blocking read/write attempts
	 */
	if (unlikely(ret))
		io_queue_async(req, ret);
}

/* Must be called with the uring_lock held.
 * If the request has the FAIL flag set, it converts any hard links to normal links
 * and defers the request as failed with the stored result code.
 * Otherwise, if the context is currently draining, it calls io_drain_req to handle
 * the request; if not, it queues the request to the io-wq workqueue. */
static void io_queue_sqe_fallback(struct io_kiocb *req)
	__must_hold(&req->ctx->uring_lock)
{
	if (unlikely(req->flags & REQ_F_FAIL)) {
		/*
		 * We don't submit, fail them all, for that replace hardlinks
		 * with normal links. Extra REQ_F_LINK is tolerated.
		 */
		req->flags &= ~REQ_F_HARDLINK;
		req->flags |= REQ_F_LINK;
		io_req_defer_failed(req, req->cqe.res);
	} else {
		if (unlikely(req->ctx->drain_active))
			io_drain_req(req);
		else
			io_queue_iowq(req);
	}
}

/*
 * Check SQE restrictions (opcode and flags).
 *
 * Returns 'true' if SQE is allowed, 'false' otherwise.
 */
static inline bool io_check_restriction(struct io_ring_ctx *ctx,
					struct io_kiocb *req,
					unsigned int sqe_flags)
{
	if (!test_bit(req->opcode, ctx->restrictions.sqe_op))
		return false;

	if ((sqe_flags & ctx->restrictions.sqe_flags_required) !=
	    ctx->restrictions.sqe_flags_required)
		return false;

	if (sqe_flags & ~(ctx->restrictions.sqe_flags_allowed |
			  ctx->restrictions.sqe_flags_required))
		return false;

	return true;
}

/* Sets the drain_active flag to true to indicate draining is in progress.
 * If there is a head request in the current submission link, marks it with
 * REQ_F_IO_DRAIN and REQ_F_FORCE_ASYNC flags to ensure it is drained asynchronously.
 * Also sets drain_next to true to indicate subsequent requests should be drained. */
static void io_init_drain(struct io_ring_ctx *ctx)
{
	struct io_kiocb *head = ctx->submit_state.link.head;

	ctx->drain_active = true;
	if (head) {
		/*
		 * If we need to drain a request in the middle of a link, drain
		 * the head request and the next request/link after the current
		 * link. Considering sequential execution of links,
		 * REQ_F_IO_DRAIN will be maintained for every request of our
		 * link.
		 */
		head->flags |= REQ_F_IO_DRAIN | REQ_F_FORCE_ASYNC;
		ctx->drain_next = true;
	}
}

/* Clears per-opcode command data to ensure no stale data remains if the request
 * fails before preparation. Returns the provided error code. */
static __cold int io_init_fail_req(struct io_kiocb *req, int err)
{
	/* ensure per-opcode data is cleared if we fail before prep */
	memset(&req->cmd.data, 0, sizeof(req->cmd.data));
	return err;
}

/* Must be called with the uring_lock held.
 * This function initializes the request fields from the SQE, validates the opcode
 * and flags, handles special flags such as buffer selection, I/O drain, and restricted
 * contexts. It also manages plugging for block I/O, sets up credentials if specified,
 * and finally calls the per-opcode preparation function.
 * Returns 0 on success or a negative error code on failure */
static int io_init_req(struct io_ring_ctx *ctx, struct io_kiocb *req,
		       const struct io_uring_sqe *sqe)
	__must_hold(&ctx->uring_lock)
{
	const struct io_issue_def *def;
	unsigned int sqe_flags;
	int personality;
	u8 opcode;

	/* req is partially pre-initialised, see io_preinit_req() */
	req->opcode = opcode = READ_ONCE(sqe->opcode);
	/* same numerical values with corresponding REQ_F_*, safe to copy */
	sqe_flags = READ_ONCE(sqe->flags);
	req->flags = (__force io_req_flags_t) sqe_flags;
	req->cqe.user_data = READ_ONCE(sqe->user_data);
	req->file = NULL;
	req->tctx = current->io_uring;
	req->cancel_seq_set = false;

	if (unlikely(opcode >= IORING_OP_LAST)) {
		req->opcode = 0;
		return io_init_fail_req(req, -EINVAL);
	}
	opcode = array_index_nospec(opcode, IORING_OP_LAST);

	def = &io_issue_defs[opcode];
	if (unlikely(sqe_flags & ~SQE_COMMON_FLAGS)) {
		/* enforce forwards compatibility on users */
		if (sqe_flags & ~SQE_VALID_FLAGS)
			return io_init_fail_req(req, -EINVAL);
		if (sqe_flags & IOSQE_BUFFER_SELECT) {
			if (!def->buffer_select)
				return io_init_fail_req(req, -EOPNOTSUPP);
			req->buf_index = READ_ONCE(sqe->buf_group);
		}
		if (sqe_flags & IOSQE_CQE_SKIP_SUCCESS)
			ctx->drain_disabled = true;
		if (sqe_flags & IOSQE_IO_DRAIN) {
			if (ctx->drain_disabled)
				return io_init_fail_req(req, -EOPNOTSUPP);
			io_init_drain(ctx);
		}
	}
	if (unlikely(ctx->restricted || ctx->drain_active || ctx->drain_next)) {
		if (ctx->restricted && !io_check_restriction(ctx, req, sqe_flags))
			return io_init_fail_req(req, -EACCES);
		/* knock it to the slow queue path, will be drained there */
		if (ctx->drain_active)
			req->flags |= REQ_F_FORCE_ASYNC;
		/* if there is no link, we're at "next" request and need to drain */
		if (unlikely(ctx->drain_next) && !ctx->submit_state.link.head) {
			ctx->drain_next = false;
			ctx->drain_active = true;
			req->flags |= REQ_F_IO_DRAIN | REQ_F_FORCE_ASYNC;
		}
	}

	if (!def->ioprio && sqe->ioprio)
		return io_init_fail_req(req, -EINVAL);
	if (!def->iopoll && (ctx->flags & IORING_SETUP_IOPOLL))
		return io_init_fail_req(req, -EINVAL);

	if (def->needs_file) {
		struct io_submit_state *state = &ctx->submit_state;

		req->cqe.fd = READ_ONCE(sqe->fd);

		/*
		 * Plug now if we have more than 2 IO left after this, and the
		 * target is potentially a read/write to block based storage.
		 */
		if (state->need_plug && def->plug) {
			state->plug_started = true;
			state->need_plug = false;
			blk_start_plug_nr_ios(&state->plug, state->submit_nr);
		}
	}

	personality = READ_ONCE(sqe->personality);
	if (personality) {
		int ret;

		req->creds = xa_load(&ctx->personalities, personality);
		if (!req->creds)
			return io_init_fail_req(req, -EINVAL);
		get_cred(req->creds);
		ret = security_uring_override_creds(req->creds);
		if (ret) {
			put_cred(req->creds);
			return io_init_fail_req(req, ret);
		}
		req->flags |= REQ_F_CREDS;
	}

	return def->prep(req, sqe);
}

/* This function traces the failure, marks the request and its link head as failed
 * to avoid breaking links mid-way (which would disrupt SQPOLL links). If the request
 * is not part of a linked chain, it queues the request for fallback handling immediately.
 * If it is linked, it appends the request to the current link chain for deferred handling.
 * Returns 0 if the request is linked (deferred handling), or the original error code
 * if handled immediately. */
static __cold int io_submit_fail_init(const struct io_uring_sqe *sqe,
				      struct io_kiocb *req, int ret)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_submit_link *link = &ctx->submit_state.link;
	struct io_kiocb *head = link->head;

	trace_io_uring_req_failed(sqe, req, ret);

	/*
	 * Avoid breaking links in the middle as it renders links with SQPOLL
	 * unusable. Instead of failing eagerly, continue assembling the link if
	 * applicable and mark the head with REQ_F_FAIL. The link flushing code
	 * should find the flag and handle the rest.
	 */
	req_fail_link_node(req, ret);
	if (head && !(head->flags & REQ_F_FAIL))
		req_fail_link_node(head, -ECANCELED);

	if (!(req->flags & IO_REQ_LINK_FLAGS)) {
		if (head) {
			link->last->link = req;
			link->head = NULL;
			req = head;
		}
		io_queue_sqe_fallback(req);
		return ret;
	}

	if (head)
		link->last->link = req;
	else
		link->head = req;
	link->last = req;
	return 0;
}

/* Must be called with the uring_lock held.
 * This function initializes the request from the SQE. On failure, it handles the
 * failure via io_submit_fail_init. If successful, it traces the submission and
 * manages linked requests:
 * - If there is an existing link head, queues the request as part of the link.
 *   If the request ends the link, flushes the entire link unless forced async or failed.
 * - If no link head exists but the request has link or async flags, starts a new link
 *   or falls back to fallback queueing.
 * - Otherwise, queues the request immediately.
 * Returns 0 on success or an error code on failure. */
static inline int io_submit_sqe(struct io_ring_ctx *ctx, struct io_kiocb *req,
			 const struct io_uring_sqe *sqe)
	__must_hold(&ctx->uring_lock)
{
	struct io_submit_link *link = &ctx->submit_state.link;
	int ret;

	ret = io_init_req(ctx, req, sqe);
	if (unlikely(ret))
		return io_submit_fail_init(sqe, req, ret);

	trace_io_uring_submit_req(req);

	/*
	 * If we already have a head request, queue this one for async
	 * submittal once the head completes. If we don't have a head but
	 * IOSQE_IO_LINK is set in the sqe, start a new head. This one will be
	 * submitted sync once the chain is complete. If none of those
	 * conditions are true (normal request), then just queue it.
	 */
	if (unlikely(link->head)) {
		trace_io_uring_link(req, link->last);
		link->last->link = req;
		link->last = req;

		if (req->flags & IO_REQ_LINK_FLAGS)
			return 0;
		/* last request of the link, flush it */
		req = link->head;
		link->head = NULL;
		if (req->flags & (REQ_F_FORCE_ASYNC | REQ_F_FAIL))
			goto fallback;

	} else if (unlikely(req->flags & (IO_REQ_LINK_FLAGS |
					  REQ_F_FORCE_ASYNC | REQ_F_FAIL))) {
		if (req->flags & IO_REQ_LINK_FLAGS) {
			link->head = req;
			link->last = req;
		} else {
fallback:
			io_queue_sqe_fallback(req);
		}
		return 0;
	}

	io_queue_sqe(req);
	return 0;
}

/*
 * Batched submission is done, ensure local IO is flushed out.
 */
static void io_submit_state_end(struct io_ring_ctx *ctx)
{
	struct io_submit_state *state = &ctx->submit_state;

	if (unlikely(state->link.head))
		io_queue_sqe_fallback(state->link.head);
	/* flush only after queuing links as they can generate completions */
	io_submit_flush_completions(ctx);
	if (state->plug_started)
		blk_finish_plug(&state->plug);
}

/*
 * Start submission side cache.
 */
static void io_submit_state_start(struct io_submit_state *state,
				  unsigned int max_ios)
{
	state->plug_started = false;
	state->need_plug = max_ios > 2;
	state->submit_nr = max_ios;
	/* set only head, no need to init link_last in advance */
	state->link.head = NULL;
}

/* Ensures that all loads from the submission queue entries (SQEs) are completed
 * before updating the SQ ring head pointer. This prevents race conditions where
 * the application might overwrite SQEs after the head is updated.
 * Uses smp_store_release to enforce memory ordering, guaranteeing that all prior
 * reads are visible before publishing the new head value. */
static void io_commit_sqring(struct io_ring_ctx *ctx)
{
	struct io_rings *rings = ctx->rings;

	/*
	 * Ensure any loads from the SQEs are done at this point,
	 * since once we write the new head, the application could
	 * write new data to them.
	 */
	smp_store_release(&rings->sq.head, ctx->cached_sq_head);
}

/*
 * Fetch an sqe, if one is available. Note this returns a pointer to memory
 * that is mapped by userspace. This means that care needs to be taken to
 * ensure that reads are stable, as we cannot rely on userspace always
 * being a good citizen. If members of the sqe are validated and then later
 * used, it's important that those reads are done through READ_ONCE() to
 * prevent a re-load down the line.
 */
static bool io_get_sqe(struct io_ring_ctx *ctx, const struct io_uring_sqe **sqe)
{
	unsigned mask = ctx->sq_entries - 1;
	unsigned head = ctx->cached_sq_head++ & mask;

	if (static_branch_unlikely(&io_key_has_sqarray) &&
	    (!(ctx->flags & IORING_SETUP_NO_SQARRAY))) {
		head = READ_ONCE(ctx->sq_array[head]);
		if (unlikely(head >= ctx->sq_entries)) {
			/* drop invalid entries */
			spin_lock(&ctx->completion_lock);
			ctx->cq_extra--;
			spin_unlock(&ctx->completion_lock);
			WRITE_ONCE(ctx->rings->sq_dropped,
				   READ_ONCE(ctx->rings->sq_dropped) + 1);
			return false;
		}
		head = array_index_nospec(head, ctx->sq_entries);
	}

	/*
	 * The cached sq head (or cq tail) serves two purposes:
	 *
	 * 1) allows us to batch the cost of updating the user visible
	 *    head updates.
	 * 2) allows the kernel side to track the head on its own, even
	 *    though the application is the one updating it.
	 */

	/* double index for 128-byte SQEs, twice as long */
	if (ctx->flags & IORING_SETUP_SQE128)
		head <<= 1;
	*sqe = &ctx->sq_sqes[head];
	return true;
}

/* Must be called with the uring_lock held.
 * This function submits up to @nr SQEs or the number of available entries in the SQ ring,
 * whichever is smaller. It increments task references accordingly and initializes submission
 * state. For each SQE, it allocates a request, retrieves the SQE, and attempts to submit it.
 * If submission fails and the context is not configured with IORING_SETUP_SUBMIT_ALL,
 * it stops early. If no requests could be submitted and no cached requests are available,
 * it returns -EAGAIN to indicate retry.
 * After submission, it finalizes the submission state and commits the SQ ring head to
 * notify the kernel of consumed SQEs.
 * Returns the number of SQEs successfully submitted or a negative error code. */
int io_submit_sqes(struct io_ring_ctx *ctx, unsigned int nr)
	__must_hold(&ctx->uring_lock)
{
	unsigned int entries = io_sqring_entries(ctx);
	unsigned int left;
	int ret;

	if (unlikely(!entries))
		return 0;
	/* make sure SQ entry isn't read before tail */
	ret = left = min(nr, entries);
	io_get_task_refs(left);
	io_submit_state_start(&ctx->submit_state, left);

	do {
		const struct io_uring_sqe *sqe;
		struct io_kiocb *req;

		if (unlikely(!io_alloc_req(ctx, &req)))
			break;
		if (unlikely(!io_get_sqe(ctx, &sqe))) {
			io_req_add_to_cache(req, ctx);
			break;
		}

		/*
		 * Continue submitting even for sqe failure if the
		 * ring was setup with IORING_SETUP_SUBMIT_ALL
		 */
		if (unlikely(io_submit_sqe(ctx, req, sqe)) &&
		    !(ctx->flags & IORING_SETUP_SUBMIT_ALL)) {
			left--;
			break;
		}
	} while (--left);

	if (unlikely(left)) {
		ret -= left;
		/* try again if it submitted nothing and can't allocate a req */
		if (!ret && io_req_cache_empty(ctx))
			ret = -EAGAIN;
		current->io_uring->cached_refs += left;
	}

	io_submit_state_end(ctx);
	 /* Commit SQ ring head once we've consumed and submitted all SQEs */
	io_commit_sqring(ctx);
	return ret;
}

/* checks if the io_uring wait queue should wake the waiting task,
 * either because the queue is ready or there is work pending in the context.
 * If so, it calls autoremove_wake_function to wake and remove the wait queue entry.
 * Otherwise, it returns -1 to indicate no wake-up.
 * Note: Overflowed completion queue events (CQEs) cannot be safely flushed here,
 * so the wake-up is deferred to the next invocation.
 * Returns:
 * - 1 if the wait queue entry was woken and removed.
 * - -1 if no wake-up occurred. */
static int io_wake_function(struct wait_queue_entry *curr, unsigned int mode,
			    int wake_flags, void *key)
{
	struct io_wait_queue *iowq = container_of(curr, struct io_wait_queue, wq);

	/*
	 * Cannot safely flush overflowed CQEs from here, ensure we wake up
	 * the task, and the next invocation will do it.
	 */
	if (io_should_wake(iowq) || io_has_work(iowq->ctx))
		return autoremove_wake_function(curr, mode, wake_flags, key);
	return -1;
}

/* checks if there is local io_uring work pending for the current context.
 * If so, it sets the current task state to TASK_RUNNING and attempts to run local work
 * with a maximum budget. If any work was executed, it returns 0.
 * It then attempts to run generic task work. If any work was executed, it returns 0.
 * Finally, it checks if the current task has any pending signals. If so, it returns -EINTR
 * to indicate interruption.
 * Returns 0 if no interruption occurred, or -EINTR if a signal is pending. */
int io_run_task_work_sig(struct io_ring_ctx *ctx)
{
	if (io_local_work_pending(ctx)) {
		__set_current_state(TASK_RUNNING);
		if (io_run_local_work(ctx, INT_MAX, IO_LOCAL_TW_DEFAULT_MAX) > 0)
			return 0;
	}
	if (io_run_task_work() > 0)
		return 0;
	if (task_sigpending(current))
		return -EINTR;
	return 0;
}

/* Returns true if the current task has an io_uring context and has inflight I/O
 * operations (indicated by a positive inflight counter), false otherwise. */
static bool current_pending_io(void)
{
	struct io_uring_task *tctx = current->io_uring;

	if (!tctx)
		return false;
	return percpu_counter_read_positive(&tctx->inflight);
}

/* This function is called when the timer expires. It sets the hit_timeout flag
 * to indicate the timeout was reached, resets the minimum timeout, and wakes up
 * the associated wait queue's task to handle any pending completions or work.
 * Returns HRTIMER_NORESTART to indicate the timer should not be restarted. */
static enum hrtimer_restart io_cqring_timer_wakeup(struct hrtimer *timer)
{
	struct io_wait_queue *iowq = container_of(timer, struct io_wait_queue, t);

	WRITE_ONCE(iowq->hit_timeout, 1);
	iowq->min_timeout = 0;
	wake_up_process(iowq->wq.private);
	return HRTIMER_NORESTART;
}

/*
 * Doing min_timeout portion. If we saw any timeouts, events, or have work,
 * wake up. If not, and we have a normal timeout, switch to that and keep
 * sleeping.
 */
static enum hrtimer_restart io_cqring_min_timer_wakeup(struct hrtimer *timer)
{
	struct io_wait_queue *iowq = container_of(timer, struct io_wait_queue, t);
	struct io_ring_ctx *ctx = iowq->ctx;

	/* no general timeout, or shorter (or equal), we are done */
	if (iowq->timeout == KTIME_MAX ||
	    ktime_compare(iowq->min_timeout, iowq->timeout) >= 0)
		goto out_wake;
	/* work we may need to run, wake function will see if we need to wake */
	if (io_has_work(ctx))
		goto out_wake;
	/* got events since we started waiting, min timeout is done */
	if (iowq->cq_min_tail != READ_ONCE(ctx->rings->cq.tail))
		goto out_wake;
	/* if we have any events and min timeout expired, we're done */
	if (io_cqring_events(ctx))
		goto out_wake;

	/*
	 * If using deferred task_work running and application is waiting on
	 * more than one request, ensure we reset it now where we are switching
	 * to normal sleeps. Any request completion post min_wait should wake
	 * the task and return.
	 */
	if (ctx->flags & IORING_SETUP_DEFER_TASKRUN) {
		atomic_set(&ctx->cq_wait_nr, 1);
		smp_mb();
		if (!llist_empty(&ctx->work_llist))
			goto out_wake;
	}

	hrtimer_update_function(&iowq->t, io_cqring_timer_wakeup);
	hrtimer_set_expires(timer, iowq->timeout);
	return HRTIMER_RESTART;
out_wake:
	return io_cqring_timer_wakeup(timer);
}

/* This function sets up and starts a high-resolution timer on the stack, using either
 * a minimum timeout or a standard timeout. It then puts the current task to sleep
 * until the timer expires or the wait queue is woken up.
 * After waking, it cancels and destroys the timer, sets the current task state back
 * to TASK_RUNNING, and returns -ETIME if the timeout was hit, or 0 otherwise. */
static int io_cqring_schedule_timeout(struct io_wait_queue *iowq,
				      clockid_t clock_id, ktime_t start_time)
{
	ktime_t timeout;

	if (iowq->min_timeout) {
		timeout = ktime_add_ns(iowq->min_timeout, start_time);
		hrtimer_setup_on_stack(&iowq->t, io_cqring_min_timer_wakeup, clock_id,
				       HRTIMER_MODE_ABS);
	} else {
		timeout = iowq->timeout;
		hrtimer_setup_on_stack(&iowq->t, io_cqring_timer_wakeup, clock_id,
				       HRTIMER_MODE_ABS);
	}

	hrtimer_set_expires_range_ns(&iowq->t, timeout, 0);
	hrtimer_start_expires(&iowq->t, HRTIMER_MODE_ABS);

	if (!READ_ONCE(iowq->hit_timeout))
		schedule();

	hrtimer_cancel(&iowq->t);
	destroy_hrtimer_on_stack(&iowq->t);
	__set_current_state(TASK_RUNNING);

	return READ_ONCE(iowq->hit_timeout) ? -ETIME : 0;
}

struct ext_arg {
	size_t argsz;
	struct timespec64 ts;
	const sigset_t __user *sig;
	ktime_t min_time;
	bool ts_set;
	bool iowait;
};

/* marks the current task as in I/O wait if there are pending I/O requests
 * and the iowait flag is set, which helps CPU frequency scaling decisions for low queue-depth I/O.
 * If a timeout or minimum timeout is set on the wait queue, it calls io_cqring_schedule_timeout
 * to sleep with a high-resolution timer. Otherwise, it simply calls schedule() to sleep indefinitely.
 * After waking, it clears the in_iowait flag and returns the result of the timeout scheduling,
 * which is 0 if woken normally or -ETIME if the timeout expired. */
static int __io_cqring_wait_schedule(struct io_ring_ctx *ctx,
				     struct io_wait_queue *iowq,
				     struct ext_arg *ext_arg,
				     ktime_t start_time)
{
	int ret = 0;

	/*
	 * Mark us as being in io_wait if we have pending requests, so cpufreq
	 * can take into account that the task is waiting for IO - turns out
	 * to be important for low QD IO.
	 */
	if (ext_arg->iowait && current_pending_io())
		current->in_iowait = 1;
	if (iowq->timeout != KTIME_MAX || iowq->min_timeout)
		ret = io_cqring_schedule_timeout(iowq, ctx->clockid, start_time);
	else
		schedule();
	current->in_iowait = 0;
	return ret;
}

/* If this returns > 0, the caller should retry */
static inline int io_cqring_wait_schedule(struct io_ring_ctx *ctx,
					  struct io_wait_queue *iowq,
					  struct ext_arg *ext_arg,
					  ktime_t start_time)
{
	if (unlikely(READ_ONCE(ctx->check_cq)))
		return 1;
	if (unlikely(io_local_work_pending(ctx)))
		return 1;
	if (unlikely(task_work_pending(current)))
		return 1;
	if (unlikely(task_sigpending(current)))
		return -EINTR;
	if (unlikely(io_should_wake(iowq)))
		return 0;

	return __io_cqring_wait_schedule(ctx, iowq, ext_arg, start_time);
}

/* waits for at least @min_events completion events to be available
 * in the shared completion queue (CQ) ring. The application is responsible for
 * reaping the events from the CQ ring.
 * It first runs any pending local and generic task work, flushes overflowed CQEs,
 * and checks if enough events are already available. If so, it returns immediately.
 * Otherwise, it sets up a wait queue entry and calculates timeouts based on @ext_arg.
 * It handles signal masks if provided, then enters a loop:
 * - Prepares to wait on the CQ wait queue.
 * - Schedules waiting with timeout if set.
 * - Runs local and generic task work after waking.
 * - Checks for CQ overflow or dropped events, handling errors accordingly.
 * - Checks if the wait queue should wake.
 * - Reschedules if none of the above conditions are met.
 * On exit, it cleans up the wait queue and restores the signal mask.
 * Returns 0 if events are available or on successful wake, -EBADR if CQ events were dropped,
 * or other negative error codes on failure or interruption. */
static int io_cqring_wait(struct io_ring_ctx *ctx, int min_events, u32 flags,
			  struct ext_arg *ext_arg)
{
	struct io_wait_queue iowq;
	struct io_rings *rings = ctx->rings;
	ktime_t start_time;
	int ret;

	min_events = min_t(int, min_events, ctx->cq_entries);

	if (!io_allowed_run_tw(ctx))
		return -EEXIST;
	if (io_local_work_pending(ctx))
		io_run_local_work(ctx, min_events,
				  max(IO_LOCAL_TW_DEFAULT_MAX, min_events));
	io_run_task_work();

	if (unlikely(test_bit(IO_CHECK_CQ_OVERFLOW_BIT, &ctx->check_cq)))
		io_cqring_do_overflow_flush(ctx);
	if (__io_cqring_events_user(ctx) >= min_events)
		return 0;

	init_waitqueue_func_entry(&iowq.wq, io_wake_function);
	iowq.wq.private = current;
	INIT_LIST_HEAD(&iowq.wq.entry);
	iowq.ctx = ctx;
	iowq.cq_tail = READ_ONCE(ctx->rings->cq.head) + min_events;
	iowq.cq_min_tail = READ_ONCE(ctx->rings->cq.tail);
	iowq.nr_timeouts = atomic_read(&ctx->cq_timeouts);
	iowq.hit_timeout = 0;
	iowq.min_timeout = ext_arg->min_time;
	iowq.timeout = KTIME_MAX;
	start_time = io_get_time(ctx);

	if (ext_arg->ts_set) {
		iowq.timeout = timespec64_to_ktime(ext_arg->ts);
		if (!(flags & IORING_ENTER_ABS_TIMER))
			iowq.timeout = ktime_add(iowq.timeout, start_time);
	}

	if (ext_arg->sig) {
#ifdef CONFIG_COMPAT
		if (in_compat_syscall())
			ret = set_compat_user_sigmask((const compat_sigset_t __user *)ext_arg->sig,
						      ext_arg->argsz);
		else
#endif
			ret = set_user_sigmask(ext_arg->sig, ext_arg->argsz);

		if (ret)
			return ret;
	}

	io_napi_busy_loop(ctx, &iowq);

	trace_io_uring_cqring_wait(ctx, min_events);
	do {
		unsigned long check_cq;
		int nr_wait;

		/* if min timeout has been hit, don't reset wait count */
		if (!iowq.hit_timeout)
			nr_wait = (int) iowq.cq_tail -
					READ_ONCE(ctx->rings->cq.tail);
		else
			nr_wait = 1;

		if (ctx->flags & IORING_SETUP_DEFER_TASKRUN) {
			atomic_set(&ctx->cq_wait_nr, nr_wait);
			set_current_state(TASK_INTERRUPTIBLE);
		} else {
			prepare_to_wait_exclusive(&ctx->cq_wait, &iowq.wq,
							TASK_INTERRUPTIBLE);
		}

		ret = io_cqring_wait_schedule(ctx, &iowq, ext_arg, start_time);
		__set_current_state(TASK_RUNNING);
		atomic_set(&ctx->cq_wait_nr, IO_CQ_WAKE_INIT);

		/*
		 * Run task_work after scheduling and before io_should_wake().
		 * If we got woken because of task_work being processed, run it
		 * now rather than let the caller do another wait loop.
		 */
		if (io_local_work_pending(ctx))
			io_run_local_work(ctx, nr_wait, nr_wait);
		io_run_task_work();

		/*
		 * Non-local task_work will be run on exit to userspace, but
		 * if we're using DEFER_TASKRUN, then we could have waited
		 * with a timeout for a number of requests. If the timeout
		 * hits, we could have some requests ready to process. Ensure
		 * this break is _after_ we have run task_work, to avoid
		 * deferring running potentially pending requests until the
		 * next time we wait for events.
		 */
		if (ret < 0)
			break;

		check_cq = READ_ONCE(ctx->check_cq);
		if (unlikely(check_cq)) {
			/* let the caller flush overflows, retry */
			if (check_cq & BIT(IO_CHECK_CQ_OVERFLOW_BIT))
				io_cqring_do_overflow_flush(ctx);
			if (check_cq & BIT(IO_CHECK_CQ_DROPPED_BIT)) {
				ret = -EBADR;
				break;
			}
		}

		if (io_should_wake(&iowq)) {
			ret = 0;
			break;
		}
		cond_resched();
	} while (1);

	if (!(ctx->flags & IORING_SETUP_DEFER_TASKRUN))
		finish_wait(&ctx->cq_wait, &iowq.wq);
	restore_saved_sigmask_unless(ret == -EINTR);

	return READ_ONCE(rings->cq.head) == READ_ONCE(rings->cq.tail) ? ret : 0;
}

/* This function releases the submission queue (SQ) and ring buffer memory regions
 * allocated for the io_uring instance. It then clears the pointers in the context
 * to prevent dangling references. */
static void io_rings_free(struct io_ring_ctx *ctx)
{
	io_free_region(ctx, &ctx->sq_region);
	io_free_region(ctx, &ctx->ring_region);
	ctx->rings = NULL;
	ctx->sq_sqes = NULL;
}

/* computes the size of the memory region required to hold the io_uring rings,
 * including the completion queue events (CQEs) and optionally the submission queue array.
 * It accounts for alignment and flag-based layout differences.
 * Returns the total size in bytes required for the rings, or SIZE_MAX on overflow or error. */
unsigned long rings_size(unsigned int flags, unsigned int sq_entries,
			 unsigned int cq_entries, size_t *sq_offset)
{
	struct io_rings *rings;
	size_t off, sq_array_size;

	off = struct_size(rings, cqes, cq_entries);
	if (off == SIZE_MAX)
		return SIZE_MAX;
	if (flags & IORING_SETUP_CQE32) {
		if (check_shl_overflow(off, 1, &off))
			return SIZE_MAX;
	}

#ifdef CONFIG_SMP
	off = ALIGN(off, SMP_CACHE_BYTES);
	if (off == 0)
		return SIZE_MAX;
#endif

	if (flags & IORING_SETUP_NO_SQARRAY) {
		*sq_offset = SIZE_MAX;
		return off;
	}

	*sq_offset = off;

	sq_array_size = array_size(sizeof(u32), sq_entries);
	if (sq_array_size == SIZE_MAX)
		return SIZE_MAX;

	if (check_add_overflow(off, sq_array_size, &off))
		return SIZE_MAX;

	return off;
}

/* acquires the uring_lock mutex and repeatedly extracts requests
 * from the request cache, freeing each one back to the slab cache. It keeps
 * track of the number of freed requests and updates the context's reference
 * count accordingly. Finally, it releases the mutex. */
static void io_req_caches_free(struct io_ring_ctx *ctx)
{
	struct io_kiocb *req;
	int nr = 0;

	mutex_lock(&ctx->uring_lock);

	while (!io_req_cache_empty(ctx)) {
		req = io_extract_req(ctx);
		kmem_cache_free(req_cachep, req);
		nr++;
	}
	if (nr)
		percpu_ref_put_many(&ctx->refs, nr);
	mutex_unlock(&ctx->uring_lock);
}

/* performs a thorough cleanup of the io_uring context by:
 * - Stopping submission queue threads.
 * - Unregistering buffers, files, and event notifications.
 * - Freeing caches, buffers, and memory regions.
 * - Releasing credentials and task references.
 * - Checking and warning if any timeouts remain.
 * - Freeing ring buffers and adjusting static keys.
 * - Cleaning up internal data structures like hash maps and cancel tables.
 * - Finally, freeing the context structure itself.
 * Ensures all resources are properly released when the io_uring instance is no longer needed. */
static __cold void io_ring_ctx_free(struct io_ring_ctx *ctx)
{
	io_sq_thread_finish(ctx);

	mutex_lock(&ctx->uring_lock);
	io_sqe_buffers_unregister(ctx);
	io_sqe_files_unregister(ctx);
	io_unregister_zcrx_ifqs(ctx);
	io_cqring_overflow_kill(ctx);
	io_eventfd_unregister(ctx);
	io_free_alloc_caches(ctx);
	io_destroy_buffers(ctx);
	io_free_region(ctx, &ctx->param_region);
	mutex_unlock(&ctx->uring_lock);
	if (ctx->sq_creds)
		put_cred(ctx->sq_creds);
	if (ctx->submitter_task)
		put_task_struct(ctx->submitter_task);

	WARN_ON_ONCE(!list_empty(&ctx->ltimeout_list));

	if (ctx->mm_account) {
		mmdrop(ctx->mm_account);
		ctx->mm_account = NULL;
	}
	io_rings_free(ctx);

	if (!(ctx->flags & IORING_SETUP_NO_SQARRAY))
		static_branch_dec(&io_key_has_sqarray);

	percpu_ref_exit(&ctx->refs);
	free_uid(ctx->user);
	io_req_caches_free(ctx);
	if (ctx->hash_map)
		io_wq_put_hash(ctx->hash_map);
	io_napi_free(ctx);
	kvfree(ctx->cancel_table.hbs);
	xa_destroy(&ctx->io_bl_xa);
	kfree(ctx);
}

/* This function is called to activate polling on the io_uring context's poll wait queue.
 * It sets the poll_activated flag under the uring_lock mutex to ensure thread safety,
 * then wakes up all tasks waiting on the poll wait queue to handle any missed wake-ups
 * that occurred before activation. Finally, it releases a reference on the context's
 * percpu_ref to balance the reference count. */
static __cold void io_activate_pollwq_cb(struct callback_head *cb)
{
	struct io_ring_ctx *ctx = container_of(cb, struct io_ring_ctx,
					       poll_wq_task_work);

	mutex_lock(&ctx->uring_lock);
	ctx->poll_activated = true;
	mutex_unlock(&ctx->uring_lock);

	/*
	 * Wake ups for some events between start of polling and activation
	 * might've been lost due to loose synchronisation.
	 */
	wake_up_all(&ctx->poll_wq);
	percpu_ref_put(&ctx->refs);
}

/* ensures that polling on the completion queue wait queue is activated.
 * It acquires the completion_lock spinlock and checks if polling is already activated
 * or in progress. If not, and the submitter task and completion task are valid, it
 * initializes a task work item to activate polling via `io_activate_pollwq_cb`.
 * It increments the context's reference count before adding the task work to the
 * submitter task, ensuring proper synchronization. If adding the task work fails,
 * it releases the reference immediately. Finally, it releases the completion_lock spinlock.*/
__cold void io_activate_pollwq(struct io_ring_ctx *ctx)
{
	spin_lock(&ctx->completion_lock);
	/* already activated or in progress */
	if (ctx->poll_activated || ctx->poll_wq_task_work.func)
		goto out;
	if (WARN_ON_ONCE(!ctx->task_complete))
		goto out;
	if (!ctx->submitter_task)
		goto out;
	/*
	 * with ->submitter_task only the submitter task completes requests, we
	 * only need to sync with it, which is done by injecting a tw
	 */
	init_task_work(&ctx->poll_wq_task_work, io_activate_pollwq_cb);
	percpu_ref_get(&ctx->refs);
	if (task_work_add(ctx->submitter_task, &ctx->poll_wq_task_work, TWA_SIGNAL))
		percpu_ref_put(&ctx->refs);
out:
	spin_unlock(&ctx->completion_lock);
}

/* implements the poll operation for the io_uring file descriptor.
 * It activates polling if not already active, registers the wait queue for polling,
 * and sets the appropriate poll event mask flags based on the state of the submission
 * and completion queues.
 * - If the submission queue is not full, it signals readiness for writing (EPOLLOUT, EPOLLWRNORM).
 * - If there are completion events available or pending work, it signals readiness for reading (EPOLLIN, EPOLLRDNORM).
 * Note: It deliberately avoids flushing the completion queue overflow list here to prevent potential deadlocks,
 * encouraging users to handle flushes upon receiving EPOLLIN but seeing no events.
 * Returns a mask of poll events indicating readiness. */
static __poll_t io_uring_poll(struct file *file, poll_table *wait)
{
	struct io_ring_ctx *ctx = file->private_data;
	__poll_t mask = 0;

	if (unlikely(!ctx->poll_activated))
		io_activate_pollwq(ctx);
	/*
	 * provides mb() which pairs with barrier from wq_has_sleeper
	 * call in io_commit_cqring
	 */
	poll_wait(file, &ctx->poll_wq, wait);

	if (!io_sqring_full(ctx))
		mask |= EPOLLOUT | EPOLLWRNORM;

	/*
	 * Don't flush cqring overflow list here, just do a simple check.
	 * Otherwise there could possible be ABBA deadlock:
	 *      CPU0                    CPU1
	 *      ----                    ----
	 * lock(&ctx->uring_lock);
	 *                              lock(&ep->mtx);
	 *                              lock(&ctx->uring_lock);
	 * lock(&ep->mtx);
	 *
	 * Users may get EPOLLIN meanwhile seeing nothing in cqring, this
	 * pushes them to do the flush.
	 */

	if (__io_cqring_events_user(ctx) || io_has_work(ctx))
		mask |= EPOLLIN | EPOLLRDNORM;

	return mask;
}

struct io_tctx_exit {
	struct callback_head		task_work;
	struct completion		completion;
	struct io_ring_ctx		*ctx;
};

/* This function is called when a task with an io_uring context is exiting.
 * It retrieves the current io_uring task context and the exit work structure.
 * If the task is not currently in cancellation (to avoid races) and the context
 * is valid, it removes the task context node from internal tracking.
 * Finally, it signals completion of the exit work.
 * Note: The task context pointer can be NULL if the task_work queuing raced
 * with cancellation during exec. */
static __cold void io_tctx_exit_cb(struct callback_head *cb)
{
	struct io_uring_task *tctx = current->io_uring;
	struct io_tctx_exit *work;

	work = container_of(cb, struct io_tctx_exit, task_work);
	/*
	 * When @in_cancel, we're in cancellation and it's racy to remove the
	 * node. It'll be removed by the end of cancellation, just ignore it.
	 * tctx can be NULL if the queueing of this task_work raced with
	 * work cancelation off the exec path.
	 */
	if (tctx && !atomic_read(&tctx->in_cancel))
		io_uring_del_tctx_node((unsigned long)work->ctx);
	complete(&work->completion);
}

/* identify if the given work item belongs to the specified
 * io_uring context by comparing the work's associated request's context pointer.
 * Returns true if the work's context matches the given context, false otherwise. */
static __cold bool io_cancel_ctx_cb(struct io_wq_work *work, void *data)
{
	struct io_kiocb *req = container_of(work, struct io_kiocb, work);

	return req->ctx == data;
}

/* This function performs a thorough cleanup of the io_uring context before freeing it.
 * It handles:
 * - Reaping asynchronous completions.
 * - Shutting down zero-copy RX interfaces.
 * - Canceling outstanding requests and related workqueue callbacks.
 * - Freeing cached requests.
 * - Waiting interruptibly for all references to drop, with a timeout and backoff.
 * - Signaling task contexts to exit and waiting for their completion callbacks.
 * - Synchronizing RCU if deferred task runs are enabled.
 * - Finally freeing the io_uring context itself.
 * This ensures all resources and pending work are fully cleaned up before destruction. */
static __cold void io_ring_exit_work(struct work_struct *work)
{
	struct io_ring_ctx *ctx = container_of(work, struct io_ring_ctx, exit_work);
	unsigned long timeout = jiffies + HZ * 60 * 5;
	unsigned long interval = HZ / 20;
	struct io_tctx_exit exit;
	struct io_tctx_node *node;
	int ret;

	/*
	 * If we're doing polled IO and end up having requests being
	 * submitted async (out-of-line), then completions can come in while
	 * we're waiting for refs to drop. We need to reap these manually,
	 * as nobody else will be looking for them.
	 */
	do {
		if (test_bit(IO_CHECK_CQ_OVERFLOW_BIT, &ctx->check_cq)) {
			mutex_lock(&ctx->uring_lock);
			io_cqring_overflow_kill(ctx);
			mutex_unlock(&ctx->uring_lock);
		}
		if (ctx->ifq) {
			mutex_lock(&ctx->uring_lock);
			io_shutdown_zcrx_ifqs(ctx);
			mutex_unlock(&ctx->uring_lock);
		}

		if (ctx->flags & IORING_SETUP_DEFER_TASKRUN)
			io_move_task_work_from_local(ctx);

		/* The SQPOLL thread never reaches this path */
		while (io_uring_try_cancel_requests(ctx, NULL, true, false))
			cond_resched();

		if (ctx->sq_data) {
			struct io_sq_data *sqd = ctx->sq_data;
			struct task_struct *tsk;

			io_sq_thread_park(sqd);
			tsk = sqd->thread;
			if (tsk && tsk->io_uring && tsk->io_uring->io_wq)
				io_wq_cancel_cb(tsk->io_uring->io_wq,
						io_cancel_ctx_cb, ctx, true);
			io_sq_thread_unpark(sqd);
		}

		io_req_caches_free(ctx);

		if (WARN_ON_ONCE(time_after(jiffies, timeout))) {
			/* there is little hope left, don't run it too often */
			interval = HZ * 60;
		}
		/*
		 * This is really an uninterruptible wait, as it has to be
		 * complete. But it's also run from a kworker, which doesn't
		 * take signals, so it's fine to make it interruptible. This
		 * avoids scenarios where we knowingly can wait much longer
		 * on completions, for example if someone does a SIGSTOP on
		 * a task that needs to finish task_work to make this loop
		 * complete. That's a synthetic situation that should not
		 * cause a stuck task backtrace, and hence a potential panic
		 * on stuck tasks if that is enabled.
		 */
	} while (!wait_for_completion_interruptible_timeout(&ctx->ref_comp, interval));

	init_completion(&exit.completion);
	init_task_work(&exit.task_work, io_tctx_exit_cb);
	exit.ctx = ctx;

	mutex_lock(&ctx->uring_lock);
	while (!list_empty(&ctx->tctx_list)) {
		WARN_ON_ONCE(time_after(jiffies, timeout));

		node = list_first_entry(&ctx->tctx_list, struct io_tctx_node,
					ctx_node);
		/* don't spin on a single task if cancellation failed */
		list_rotate_left(&ctx->tctx_list);
		ret = task_work_add(node->task, &exit.task_work, TWA_SIGNAL);
		if (WARN_ON_ONCE(ret))
			continue;

		mutex_unlock(&ctx->uring_lock);
		/*
		 * See comment above for
		 * wait_for_completion_interruptible_timeout() on why this
		 * wait is marked as interruptible.
		 */
		wait_for_completion_interruptible(&exit.completion);
		mutex_lock(&ctx->uring_lock);
	}
	mutex_unlock(&ctx->uring_lock);
	spin_lock(&ctx->completion_lock);
	spin_unlock(&ctx->completion_lock);

	/* pairs with RCU read section in io_req_local_work_add() */
	if (ctx->flags & IORING_SETUP_DEFER_TASKRUN)
		synchronize_rcu();

	io_ring_ctx_free(ctx);
}

/* performs the initial steps to safely shut down an io_uring context:
 * - Locks the uring_lock mutex.
 * - Marks the context's reference counter as killed to prevent new references.
 * - Unregisters all personalities associated with the context.
 * - Unlocks the mutex.
 * - Flushes any pending fallback work.
 * - Initializes and queues the exit work on a dedicated workqueue to perform full cleanup asynchronously.
 * Using a dedicated workqueue avoids spawning excessive event kworkers during mass shutdowns. */
static __cold void io_ring_ctx_wait_and_kill(struct io_ring_ctx *ctx)
{
	unsigned long index;
	struct creds *creds;

	mutex_lock(&ctx->uring_lock);
	percpu_ref_kill(&ctx->refs);
	xa_for_each(&ctx->personalities, index, creds)
		io_unregister_personality(ctx, index);
	mutex_unlock(&ctx->uring_lock);

	flush_delayed_work(&ctx->fallback_work);

	INIT_WORK(&ctx->exit_work, io_ring_exit_work);
	/*
	 * Use system_unbound_wq to avoid spawning tons of event kworkers
	 * if we're exiting a ton of rings at the same time. It just adds
	 * noise and overhead, there's no discernable change in runtime
	 * over using system_wq.
	 */
	queue_work(iou_wq, &ctx->exit_work);
}

/* This function is called when the io_uring file descriptor is closed.
 * It clears the private_data pointer and initiates the shutdown and cleanup
 * of the associated io_uring context.
 * Returns 0 on success. */
static int io_uring_release(struct inode *inode, struct file *file)
{
	struct io_ring_ctx *ctx = file->private_data;

	file->private_data = NULL;
	io_ring_ctx_wait_and_kill(ctx);
	return 0;
}

struct io_task_cancel {
	struct io_uring_task *tctx;
	bool all;
};

/* determines if the given work item matches the specified task context,
 * optionally considering all requests if cancel_all is true.
 * Returns true if the work matches the task context, false otherwise */
static bool io_cancel_task_cb(struct io_wq_work *work, void *data)
{
	struct io_kiocb *req = container_of(work, struct io_kiocb, work);
	struct io_task_cancel *cancel = data;

	return io_match_task_safe(req, cancel->tctx, cancel->all);
}

/* scans the deferred request list in reverse order under the completion_lock,
 * looking for requests that match the given task context. Once found, it cuts the list
 * at that position, extracting all matching deferred requests into a local list.
 * It then iterates over the extracted list, failing each request with -ECANCELED and freeing
 * their memory. Returns true if any deferred requests were canceled, false otherwise. */
static __cold bool io_cancel_defer_files(struct io_ring_ctx *ctx,
					 struct io_uring_task *tctx,
					 bool cancel_all)
{
	struct io_defer_entry *de;
	LIST_HEAD(list);

	spin_lock(&ctx->completion_lock);
	list_for_each_entry_reverse(de, &ctx->defer_list, list) {
		if (io_match_task_safe(de->req, tctx, cancel_all)) {
			list_cut_position(&list, &ctx->defer_list, &de->list);
			break;
		}
	}
	spin_unlock(&ctx->completion_lock);
	if (list_empty(&list))
		return false;

	while (!list_empty(&list)) {
		de = list_first_entry(&list, struct io_defer_entry, list);
		list_del_init(&de->list);
		io_req_task_queue_fail(de->req, -ECANCELED);
		kfree(de);
	}
	return true;
}

/* iterates over all task contexts associated with the io_uring context,
 * attempting to cancel any pending io_wq work items that belong to the context.
 * It holds the uring_lock mutex during iteration to ensure safe access.
 * Returns true if any cancellations were performed, false otherwise. */
static __cold bool io_uring_try_cancel_iowq(struct io_ring_ctx *ctx)
{
	struct io_tctx_node *node;
	enum io_wq_cancel cret;
	bool ret = false;

	mutex_lock(&ctx->uring_lock);
	list_for_each_entry(node, &ctx->tctx_list, ctx_node) {
		struct io_uring_task *tctx = node->task->io_uring;

		/*
		 * io_wq will stay alive while we hold uring_lock, because it's
		 * killed after ctx nodes, which requires to take the lock.
		 */
		if (!tctx || !tctx->io_wq)
			continue;
		cret = io_wq_cancel_cb(tctx->io_wq, io_cancel_ctx_cb, ctx, true);
		ret |= (cret != IO_WQ_CANCEL_NOTFOUND);
	}
	mutex_unlock(&ctx->uring_lock);

	return ret;
}

/* tries to cancel all outstanding requests associated with the given
 * io_uring context and optionally a specific task context. It handles:
 * - Waking up deferred task runs if enabled.
 * - Canceling workqueue requests via io_wq_cancel_cb.
 * - Reaping iopoll events if applicable.
 * - Running local deferred work if allowed.
 * - Canceling deferred file requests.
 * - Removing poll, waitid, futex, and uring_cmd requests under the uring_lock.
 * - Killing timeouts.
 * - Running task work or flushing fallback work.
 * Returns true if any cancellations or work were performed, false otherwise. */
static __cold bool io_uring_try_cancel_requests(struct io_ring_ctx *ctx,
						struct io_uring_task *tctx,
						bool cancel_all,
						bool is_sqpoll_thread)
{
	struct io_task_cancel cancel = { .tctx = tctx, .all = cancel_all, };
	enum io_wq_cancel cret;
	bool ret = false;

	/* set it so io_req_local_work_add() would wake us up */
	if (ctx->flags & IORING_SETUP_DEFER_TASKRUN) {
		atomic_set(&ctx->cq_wait_nr, 1);
		smp_mb();
	}

	/* failed during ring init, it couldn't have issued any requests */
	if (!ctx->rings)
		return false;

	if (!tctx) {
		ret |= io_uring_try_cancel_iowq(ctx);
	} else if (tctx->io_wq) {
		/*
		 * Cancels requests of all rings, not only @ctx, but
		 * it's fine as the task is in exit/exec.
		 */
		cret = io_wq_cancel_cb(tctx->io_wq, io_cancel_task_cb,
				       &cancel, true);
		ret |= (cret != IO_WQ_CANCEL_NOTFOUND);
	}

	/* SQPOLL thread does its own polling */
	if ((!(ctx->flags & IORING_SETUP_SQPOLL) && cancel_all) ||
	    is_sqpoll_thread) {
		while (!wq_list_empty(&ctx->iopoll_list)) {
			io_iopoll_try_reap_events(ctx);
			ret = true;
			cond_resched();
		}
	}

	if ((ctx->flags & IORING_SETUP_DEFER_TASKRUN) &&
	    io_allowed_defer_tw_run(ctx))
		ret |= io_run_local_work(ctx, INT_MAX, INT_MAX) > 0;
	ret |= io_cancel_defer_files(ctx, tctx, cancel_all);
	mutex_lock(&ctx->uring_lock);
	ret |= io_poll_remove_all(ctx, tctx, cancel_all);
	ret |= io_waitid_remove_all(ctx, tctx, cancel_all);
	ret |= io_futex_remove_all(ctx, tctx, cancel_all);
	ret |= io_uring_try_cancel_uring_cmd(ctx, tctx, cancel_all);
	mutex_unlock(&ctx->uring_lock);
	ret |= io_kill_timeouts(ctx, tctx, cancel_all);
	if (tctx)
		ret |= io_run_task_work() > 0;
	else
		ret |= flush_delayed_work(&ctx->fallback_work);
	return ret;
}

/* Returns the number of inflight requests for the task context, using either
 * the tracked atomic counter or the percpu counter sum. */
static s64 tctx_inflight(struct io_uring_task *tctx, bool tracked)
{
	if (tracked)
		return atomic_read(&tctx->inflight_tracked);
	return percpu_counter_sum(&tctx->inflight);
}

/*
 * Find any io_uring ctx that this task has registered or done IO on, and cancel
 * requests. @sqd should be not-null IFF it's an SQPOLL thread cancellation.
 */
/* attempts to cancel all or tracked outstanding io_uring requests
 * associated with the current task. It manages cancellation state, iterates over
 * all io_uring contexts related to the task, and repeatedly tries to cancel requests
 * until none remain. It also handles waiting interruptibly for completions and task
 * work to finish, avoiding races with incoming completions.
 * If @cancel_all is true, it performs a full cancellation and frees the task context. */
__cold void io_uring_cancel_generic(bool cancel_all, struct io_sq_data *sqd)
{
	struct io_uring_task *tctx = current->io_uring;
	struct io_ring_ctx *ctx;
	struct io_tctx_node *node;
	unsigned long index;
	s64 inflight;
	DEFINE_WAIT(wait);

	WARN_ON_ONCE(sqd && sqd->thread != current);

	if (!current->io_uring)
		return;
	if (tctx->io_wq)
		io_wq_exit_start(tctx->io_wq);

	atomic_inc(&tctx->in_cancel);
	do {
		bool loop = false;

		io_uring_drop_tctx_refs(current);
		if (!tctx_inflight(tctx, !cancel_all))
			break;

		/* read completions before cancelations */
		inflight = tctx_inflight(tctx, false);
		if (!inflight)
			break;

		if (!sqd) {
			xa_for_each(&tctx->xa, index, node) {
				/* sqpoll task will cancel all its requests */
				if (node->ctx->sq_data)
					continue;
				loop |= io_uring_try_cancel_requests(node->ctx,
							current->io_uring,
							cancel_all,
							false);
			}
		} else {
			list_for_each_entry(ctx, &sqd->ctx_list, sqd_list)
				loop |= io_uring_try_cancel_requests(ctx,
								     current->io_uring,
								     cancel_all,
								     true);
		}

		if (loop) {
			cond_resched();
			continue;
		}

		prepare_to_wait(&tctx->wait, &wait, TASK_INTERRUPTIBLE);
		io_run_task_work();
		io_uring_drop_tctx_refs(current);
		xa_for_each(&tctx->xa, index, node) {
			if (io_local_work_pending(node->ctx)) {
				WARN_ON_ONCE(node->ctx->submitter_task &&
					     node->ctx->submitter_task != current);
				goto end_wait;
			}
		}
		/*
		 * If we've seen completions, retry without waiting. This
		 * avoids a race where a completion comes in before we did
		 * prepare_to_wait().
		 */
		if (inflight == tctx_inflight(tctx, !cancel_all))
			schedule();
end_wait:
		finish_wait(&tctx->wait, &wait);
	} while (1);

	io_uring_clean_tctx(tctx);
	if (cancel_all) {
		/*
		 * We shouldn't run task_works after cancel, so just leave
		 * ->in_cancel set for normal exit.
		 */
		atomic_dec(&tctx->in_cancel);
		/* for exec all current's requests should be gone, kill tctx */
		__io_uring_free(current);
	}
}

/* unregisters the ring file descriptor and then calls
 * io_uring_cancel_generic to cancel outstanding requests for the current task. */
void __io_uring_cancel(bool cancel_all)
{
	io_uring_unreg_ringfd();
	io_uring_cancel_generic(cancel_all, NULL);
}

/* validates and translates a user-space pointer offset into a kernel
 * pointer within the context's completion queue wait argument buffer. It ensures:
 * - The offset is aligned to sizeof(long).
 * - The offset plus the size of io_uring_reg_wait does not overflow and fits within the buffer.
 * - Prevents speculative execution attacks using array_index_nospec.
 * Returns a pointer to the io_uring_reg_wait structure within the buffer on success,
 * or ERR_PTR(-EFAULT) on validation failure. */
static struct io_uring_reg_wait *io_get_ext_arg_reg(struct io_ring_ctx *ctx,
			const struct io_uring_getevents_arg __user *uarg)
{
	unsigned long size = sizeof(struct io_uring_reg_wait);
	unsigned long offset = (uintptr_t)uarg;
	unsigned long end;

	if (unlikely(offset % sizeof(long)))
		return ERR_PTR(-EFAULT);

	/* also protects from NULL ->cq_wait_arg as the size would be 0 */
	if (unlikely(check_add_overflow(offset, size, &end) ||
		     end > ctx->cq_wait_size))
		return ERR_PTR(-EFAULT);

	offset = array_index_nospec(offset, ctx->cq_wait_size - size);
	return ctx->cq_wait_arg + offset;
}

/* checks if the extended argument flags and size are valid.
 * It rejects unsupported flags and invalid sizes, and copies the argument
 * from user-space for further validation if needed.
 * Returns 0 on success, -EINVAL or -EFAULT on failure. */
static int io_validate_ext_arg(struct io_ring_ctx *ctx, unsigned flags,
			       const void __user *argp, size_t argsz)
{
	struct io_uring_getevents_arg arg;

	if (!(flags & IORING_ENTER_EXT_ARG))
		return 0;
	if (flags & IORING_ENTER_EXT_ARG_REG)
		return -EINVAL;
	if (argsz != sizeof(arg))
		return -EINVAL;
	if (copy_from_user(&arg, argp, sizeof(arg)))
		return -EFAULT;
	return 0;
}

/* interprets the extended argument passed to io_uring enter,
 * handling different formats based on flags:
 * - If EXT_ARG is not set, argp points directly to a sigset_t.
 * - If EXT_ARG_REG is set, argp points to a registered wait structure.
 * - Otherwise, argp points to an io_uring_getevents_arg structure.
 * It validates sizes and flags, copies data from user space safely,
 * and populates ext_arg fields accordingly, including minimum wait time,
 * signal mask, and optional timespec.
 * Returns 0 on success or a negative error code on failure. */
static int io_get_ext_arg(struct io_ring_ctx *ctx, unsigned flags,
			  const void __user *argp, struct ext_arg *ext_arg)
{
	const struct io_uring_getevents_arg __user *uarg = argp;
	struct io_uring_getevents_arg arg;

	ext_arg->iowait = !(flags & IORING_ENTER_NO_IOWAIT);

	/*
	 * If EXT_ARG isn't set, then we have no timespec and the argp pointer
	 * is just a pointer to the sigset_t.
	 */
	if (!(flags & IORING_ENTER_EXT_ARG)) {
		ext_arg->sig = (const sigset_t __user *) argp;
		return 0;
	}

	if (flags & IORING_ENTER_EXT_ARG_REG) {
		struct io_uring_reg_wait *w;

		if (ext_arg->argsz != sizeof(struct io_uring_reg_wait))
			return -EINVAL;
		w = io_get_ext_arg_reg(ctx, argp);
		if (IS_ERR(w))
			return PTR_ERR(w);

		if (w->flags & ~IORING_REG_WAIT_TS)
			return -EINVAL;
		ext_arg->min_time = READ_ONCE(w->min_wait_usec) * NSEC_PER_USEC;
		ext_arg->sig = u64_to_user_ptr(READ_ONCE(w->sigmask));
		ext_arg->argsz = READ_ONCE(w->sigmask_sz);
		if (w->flags & IORING_REG_WAIT_TS) {
			ext_arg->ts.tv_sec = READ_ONCE(w->ts.tv_sec);
			ext_arg->ts.tv_nsec = READ_ONCE(w->ts.tv_nsec);
			ext_arg->ts_set = true;
		}
		return 0;
	}

	/*
	 * EXT_ARG is set - ensure we agree on the size of it and copy in our
	 * timespec and sigset_t pointers if good.
	 */
	if (ext_arg->argsz != sizeof(arg))
		return -EINVAL;
#ifdef CONFIG_64BIT
	if (!user_access_begin(uarg, sizeof(*uarg)))
		return -EFAULT;
	unsafe_get_user(arg.sigmask, &uarg->sigmask, uaccess_end);
	unsafe_get_user(arg.sigmask_sz, &uarg->sigmask_sz, uaccess_end);
	unsafe_get_user(arg.min_wait_usec, &uarg->min_wait_usec, uaccess_end);
	unsafe_get_user(arg.ts, &uarg->ts, uaccess_end);
	user_access_end();
#else
	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;
#endif
	ext_arg->min_time = arg.min_wait_usec * NSEC_PER_USEC;
	ext_arg->sig = u64_to_user_ptr(arg.sigmask);
	ext_arg->argsz = arg.sigmask_sz;
	if (arg.ts) {
		if (get_timespec64(&ext_arg->ts, u64_to_user_ptr(arg.ts)))
			return -EFAULT;
		ext_arg->ts_set = true;
	}
	return 0;
#ifdef CONFIG_64BIT
uaccess_end:
	user_access_end();
	return -EFAULT;
#endif
}

/* submits IO requests and optionally waits for completions on an io_uring instance.
 * It supports various flags to control submission, waiting, and extended arguments.
 * The function performs:
 * - Validation of flags and file descriptor.
 * - Lookup of the io_uring context from the fd or registered rings.
 * - Handling of SQPOLL mode where a kernel thread handles submissions/completions.
 * - Submission of SQEs under the uring_lock mutex.
 * - Optional running of deferred task work.
 * - Waiting for completions using either polling or eventfd mechanisms.
 * - Proper locking and unlocking of resources.
 * - Cleanup of file references.
 * Returns the number of submitted SQEs or completion events, or a negative error code. */
SYSCALL_DEFINE6(io_uring_enter, unsigned int, fd, u32, to_submit,
		u32, min_complete, u32, flags, const void __user *, argp,
		size_t, argsz)
{
	struct io_ring_ctx *ctx;
	struct file *file;
	long ret;

	if (unlikely(flags & ~(IORING_ENTER_GETEVENTS | IORING_ENTER_SQ_WAKEUP |
			       IORING_ENTER_SQ_WAIT | IORING_ENTER_EXT_ARG |
			       IORING_ENTER_REGISTERED_RING |
			       IORING_ENTER_ABS_TIMER |
			       IORING_ENTER_EXT_ARG_REG |
			       IORING_ENTER_NO_IOWAIT)))
		return -EINVAL;

	/*
	 * Ring fd has been registered via IORING_REGISTER_RING_FDS, we
	 * need only dereference our task private array to find it.
	 */
	if (flags & IORING_ENTER_REGISTERED_RING) {
		struct io_uring_task *tctx = current->io_uring;

		if (unlikely(!tctx || fd >= IO_RINGFD_REG_MAX))
			return -EINVAL;
		fd = array_index_nospec(fd, IO_RINGFD_REG_MAX);
		file = tctx->registered_rings[fd];
		if (unlikely(!file))
			return -EBADF;
	} else {
		file = fget(fd);
		if (unlikely(!file))
			return -EBADF;
		ret = -EOPNOTSUPP;
		if (unlikely(!io_is_uring_fops(file)))
			goto out;
	}

	ctx = file->private_data;
	ret = -EBADFD;
	if (unlikely(ctx->flags & IORING_SETUP_R_DISABLED))
		goto out;

	/*
	 * For SQ polling, the thread will do all submissions and completions.
	 * Just return the requested submit count, and wake the thread if
	 * we were asked to.
	 */
	ret = 0;
	if (ctx->flags & IORING_SETUP_SQPOLL) {
		if (unlikely(ctx->sq_data->thread == NULL)) {
			ret = -EOWNERDEAD;
			goto out;
		}
		if (flags & IORING_ENTER_SQ_WAKEUP)
			wake_up(&ctx->sq_data->wait);
		if (flags & IORING_ENTER_SQ_WAIT)
			io_sqpoll_wait_sq(ctx);

		ret = to_submit;
	} else if (to_submit) {
		ret = io_uring_add_tctx_node(ctx);
		if (unlikely(ret))
			goto out;

		mutex_lock(&ctx->uring_lock);
		ret = io_submit_sqes(ctx, to_submit);
		if (ret != to_submit) {
			mutex_unlock(&ctx->uring_lock);
			goto out;
		}
		if (flags & IORING_ENTER_GETEVENTS) {
			if (ctx->syscall_iopoll)
				goto iopoll_locked;
			/*
			 * Ignore errors, we'll soon call io_cqring_wait() and
			 * it should handle ownership problems if any.
			 */
			if (ctx->flags & IORING_SETUP_DEFER_TASKRUN)
				(void)io_run_local_work_locked(ctx, min_complete);
		}
		mutex_unlock(&ctx->uring_lock);
	}

	if (flags & IORING_ENTER_GETEVENTS) {
		int ret2;

		if (ctx->syscall_iopoll) {
			/*
			 * We disallow the app entering submit/complete with
			 * polling, but we still need to lock the ring to
			 * prevent racing with polled issue that got punted to
			 * a workqueue.
			 */
			mutex_lock(&ctx->uring_lock);
iopoll_locked:
			ret2 = io_validate_ext_arg(ctx, flags, argp, argsz);
			if (likely(!ret2))
				ret2 = io_iopoll_check(ctx, min_complete);
			mutex_unlock(&ctx->uring_lock);
		} else {
			struct ext_arg ext_arg = { .argsz = argsz };

			ret2 = io_get_ext_arg(ctx, flags, argp, &ext_arg);
			if (likely(!ret2))
				ret2 = io_cqring_wait(ctx, min_complete, flags,
						      &ext_arg);
		}

		if (!ret) {
			ret = ret2;

			/*
			 * EBADR indicates that one or more CQE were dropped.
			 * Once the user has been informed we can clear the bit
			 * as they are obviously ok with those drops.
			 */
			if (unlikely(ret2 == -EBADR))
				clear_bit(IO_CHECK_CQ_DROPPED_BIT,
					  &ctx->check_cq);
		}
	}
out:
	if (!(flags & IORING_ENTER_REGISTERED_RING))
		fput(file);
	return ret;
}

static const struct file_operations io_uring_fops = {
	.release	= io_uring_release,
	.mmap		= io_uring_mmap,
	.get_unmapped_area = io_uring_get_unmapped_area,
#ifndef CONFIG_MMU
	.mmap_capabilities = io_uring_nommu_mmap_capabilities,
#endif
	.poll		= io_uring_poll,
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= io_uring_show_fdinfo,
#endif
};

/* Returns true if the file's f_op pointer matches io_uring_fops, false otherwise. */
bool io_is_uring_fops(struct file *file)
{
	return file->f_op == &io_uring_fops;
}

/* allocates memory regions for the io_uring shared rings (SQ and CQ),
 * validates parameters, and sets up pointers and ring metadata. It handles:
 * - Calculating the total size of the rings and submission queue array.
 * - Creating memory regions for the rings and SQEs.
 * - Setting up ring masks and entries.
 * - Supporting 128-byte SQEs if requested.
 * - Handling user-provided memory regions if NO_MMAP is set.
 * Returns 0 on success or a negative error code on failure. */
static __cold int io_allocate_scq_urings(struct io_ring_ctx *ctx,
					 struct io_uring_params *p)
{
	struct io_uring_region_desc rd;
	struct io_rings *rings;
	size_t size, sq_array_offset;
	int ret;

	/* make sure these are sane, as we already accounted them */
	ctx->sq_entries = p->sq_entries;
	ctx->cq_entries = p->cq_entries;

	size = rings_size(ctx->flags, p->sq_entries, p->cq_entries,
			  &sq_array_offset);
	if (size == SIZE_MAX)
		return -EOVERFLOW;

	memset(&rd, 0, sizeof(rd));
	rd.size = PAGE_ALIGN(size);
	if (ctx->flags & IORING_SETUP_NO_MMAP) {
		rd.user_addr = p->cq_off.user_addr;
		rd.flags |= IORING_MEM_REGION_TYPE_USER;
	}
	ret = io_create_region(ctx, &ctx->ring_region, &rd, IORING_OFF_CQ_RING);
	if (ret)
		return ret;
	ctx->rings = rings = io_region_get_ptr(&ctx->ring_region);

	if (!(ctx->flags & IORING_SETUP_NO_SQARRAY))
		ctx->sq_array = (u32 *)((char *)rings + sq_array_offset);
	rings->sq_ring_mask = p->sq_entries - 1;
	rings->cq_ring_mask = p->cq_entries - 1;
	rings->sq_ring_entries = p->sq_entries;
	rings->cq_ring_entries = p->cq_entries;

	if (p->flags & IORING_SETUP_SQE128)
		size = array_size(2 * sizeof(struct io_uring_sqe), p->sq_entries);
	else
		size = array_size(sizeof(struct io_uring_sqe), p->sq_entries);
	if (size == SIZE_MAX) {
		io_rings_free(ctx);
		return -EOVERFLOW;
	}

	memset(&rd, 0, sizeof(rd));
	rd.size = PAGE_ALIGN(size);
	if (ctx->flags & IORING_SETUP_NO_MMAP) {
		rd.user_addr = p->sq_off.user_addr;
		rd.flags |= IORING_MEM_REGION_TYPE_USER;
	}
	ret = io_create_region(ctx, &ctx->sq_region, &rd, IORING_OFF_SQES);
	if (ret) {
		io_rings_free(ctx);
		return ret;
	}
	ctx->sq_sqes = io_region_get_ptr(&ctx->sq_region);
	return 0;
}

/* allocates an unused file descriptor with O_RDWR and O_CLOEXEC flags,
 * installs the given file pointer into the descriptor table, and returns the fd.
 * Returns the allocated file descriptor on success or a negative error code on failure. */
static int io_uring_install_fd(struct file *file)
{
	int fd;

	fd = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return fd;
	fd_install(fd, file);
	return fd;
}

/*
 * Allocate an anonymous fd, this is what constitutes the application
 * visible backing of an io_uring instance. The application mmaps this
 * fd to gain access to the SQ/CQ ring details.
 */
static struct file *io_uring_get_file(struct io_ring_ctx *ctx)
{
	/* Create a new inode so that the LSM can block the creation.  */
	return anon_inode_create_getfile("[io_uring]", &io_uring_fops, ctx,
					 O_RDWR | O_CLOEXEC, NULL);
}

/* hecks the consistency and validity of the flags provided during
 * io_uring setup. It enforces constraints such as:
 * - Disallowing mmap rings without a real fd if REGISTERED_FD_ONLY is set.
 * - Rejecting IPI-related flags when SQPOLL mode is enabled.
 * - Ensuring TASKRUN_FLAG is only set alongside COOP_TASKRUN or DEFER_TASKRUN.
 * - Validating that HYBRID_IOPOLL is only set if IOPOLL is also set.
 * - Requiring SINGLE_ISSUER flag when DEFER_TASKRUN is enabled.
 * Returns 0 if parameters are valid, or -EINVAL if any checks fail. */
static int io_uring_sanitise_params(struct io_uring_params *p)
{
	unsigned flags = p->flags;

	/* There is no way to mmap rings without a real fd */
	if ((flags & IORING_SETUP_REGISTERED_FD_ONLY) &&
	    !(flags & IORING_SETUP_NO_MMAP))
		return -EINVAL;

	if (flags & IORING_SETUP_SQPOLL) {
		/* IPI related flags don't make sense with SQPOLL */
		if (flags & (IORING_SETUP_COOP_TASKRUN |
			     IORING_SETUP_TASKRUN_FLAG |
			     IORING_SETUP_DEFER_TASKRUN))
			return -EINVAL;
	}

	if (flags & IORING_SETUP_TASKRUN_FLAG) {
		if (!(flags & (IORING_SETUP_COOP_TASKRUN |
			       IORING_SETUP_DEFER_TASKRUN)))
			return -EINVAL;
	}

	/* HYBRID_IOPOLL only valid with IOPOLL */
	if ((flags & IORING_SETUP_HYBRID_IOPOLL) && !(flags & IORING_SETUP_IOPOLL))
		return -EINVAL;

	/*
	 * For DEFER_TASKRUN we require the completion task to be the same as
	 * the submission task. This implies that there is only one submitter.
	 */
	if ((flags & IORING_SETUP_DEFER_TASKRUN) &&
	    !(flags & IORING_SETUP_SINGLE_ISSUER))
		return -EINVAL;

	return 0;
}

/* validates and adjusts the number of SQ and CQ entries for the io_uring
 * instance. It ensures:
 * - Entries are non-zero and within maximum limits (with optional clamping).
 * - SQ entries are rounded up to the next power of two.
 * - CQ entries are either specified by the user (rounded up and validated) or set to twice the SQ entries.
 * - Offsets within the io_rings structure for SQ and CQ rings are set for mmap.
 * - User addresses for mmap offsets are zeroed if mmap is enabled.
 * Returns 0 on success or -EINVAL on invalid parameters. */
int io_uring_fill_params(unsigned entries, struct io_uring_params *p)
{
	if (!entries)
		return -EINVAL;
	if (entries > IORING_MAX_ENTRIES) {
		if (!(p->flags & IORING_SETUP_CLAMP))
			return -EINVAL;
		entries = IORING_MAX_ENTRIES;
	}

	/*
	 * Use twice as many entries for the CQ ring. It's possible for the
	 * application to drive a higher depth than the size of the SQ ring,
	 * since the sqes are only used at submission time. This allows for
	 * some flexibility in overcommitting a bit. If the application has
	 * set IORING_SETUP_CQSIZE, it will have passed in the desired number
	 * of CQ ring entries manually.
	 */
	p->sq_entries = roundup_pow_of_two(entries);
	if (p->flags & IORING_SETUP_CQSIZE) {
		/*
		 * If IORING_SETUP_CQSIZE is set, we do the same roundup
		 * to a power-of-two, if it isn't already. We do NOT impose
		 * any cq vs sq ring sizing.
		 */
		if (!p->cq_entries)
			return -EINVAL;
		if (p->cq_entries > IORING_MAX_CQ_ENTRIES) {
			if (!(p->flags & IORING_SETUP_CLAMP))
				return -EINVAL;
			p->cq_entries = IORING_MAX_CQ_ENTRIES;
		}
		p->cq_entries = roundup_pow_of_two(p->cq_entries);
		if (p->cq_entries < p->sq_entries)
			return -EINVAL;
	} else {
		p->cq_entries = 2 * p->sq_entries;
	}

	p->sq_off.head = offsetof(struct io_rings, sq.head);
	p->sq_off.tail = offsetof(struct io_rings, sq.tail);
	p->sq_off.ring_mask = offsetof(struct io_rings, sq_ring_mask);
	p->sq_off.ring_entries = offsetof(struct io_rings, sq_ring_entries);
	p->sq_off.flags = offsetof(struct io_rings, sq_flags);
	p->sq_off.dropped = offsetof(struct io_rings, sq_dropped);
	p->sq_off.resv1 = 0;
	if (!(p->flags & IORING_SETUP_NO_MMAP))
		p->sq_off.user_addr = 0;

	p->cq_off.head = offsetof(struct io_rings, cq.head);
	p->cq_off.tail = offsetof(struct io_rings, cq.tail);
	p->cq_off.ring_mask = offsetof(struct io_rings, cq_ring_mask);
	p->cq_off.ring_entries = offsetof(struct io_rings, cq_ring_entries);
	p->cq_off.overflow = offsetof(struct io_rings, cq_overflow);
	p->cq_off.cqes = offsetof(struct io_rings, cqes);
	p->cq_off.flags = offsetof(struct io_rings, cq_flags);
	p->cq_off.resv1 = 0;
	if (!(p->flags & IORING_SETUP_NO_MMAP))
		p->cq_off.user_addr = 0;

	return 0;
}

/* performs the full setup of an io_uring instance, including:
 * - Validating and sanitizing parameters.
 * - Allocating and initializing the io_uring context.
 * - Setting up rings, submission queue arrays, and offload threads if requested.
 * - Configuring flags and features supported by the instance.
 * - Copying finalized parameters back to user space.
 * - Installing the io_uring file descriptor for user access.
 * Returns the new file descriptor on success or a negative error code on failure. */
static __cold int io_uring_create(unsigned entries, struct io_uring_params *p,
				  struct io_uring_params __user *params)
{
	struct io_ring_ctx *ctx;
	struct io_uring_task *tctx;
	struct file *file;
	int ret;

	ret = io_uring_sanitise_params(p);
	if (ret)
		return ret;

	ret = io_uring_fill_params(entries, p);
	if (unlikely(ret))
		return ret;

	ctx = io_ring_ctx_alloc(p);
	if (!ctx)
		return -ENOMEM;

	ctx->clockid = CLOCK_MONOTONIC;
	ctx->clock_offset = 0;

	if (!(ctx->flags & IORING_SETUP_NO_SQARRAY))
		static_branch_inc(&io_key_has_sqarray);

	if ((ctx->flags & IORING_SETUP_DEFER_TASKRUN) &&
	    !(ctx->flags & IORING_SETUP_IOPOLL) &&
	    !(ctx->flags & IORING_SETUP_SQPOLL))
		ctx->task_complete = true;

	if (ctx->task_complete || (ctx->flags & IORING_SETUP_IOPOLL))
		ctx->lockless_cq = true;

	/*
	 * lazy poll_wq activation relies on ->task_complete for synchronisation
	 * purposes, see io_activate_pollwq()
	 */
	if (!ctx->task_complete)
		ctx->poll_activated = true;

	/*
	 * When SETUP_IOPOLL and SETUP_SQPOLL are both enabled, user
	 * space applications don't need to do io completion events
	 * polling again, they can rely on io_sq_thread to do polling
	 * work, which can reduce cpu usage and uring_lock contention.
	 */
	if (ctx->flags & IORING_SETUP_IOPOLL &&
	    !(ctx->flags & IORING_SETUP_SQPOLL))
		ctx->syscall_iopoll = 1;

	ctx->compat = in_compat_syscall();
	if (!ns_capable_noaudit(&init_user_ns, CAP_IPC_LOCK))
		ctx->user = get_uid(current_user());

	/*
	 * For SQPOLL, we just need a wakeup, always. For !SQPOLL, if
	 * COOP_TASKRUN is set, then IPIs are never needed by the app.
	 */
	if (ctx->flags & (IORING_SETUP_SQPOLL|IORING_SETUP_COOP_TASKRUN))
		ctx->notify_method = TWA_SIGNAL_NO_IPI;
	else
		ctx->notify_method = TWA_SIGNAL;

	/*
	 * This is just grabbed for accounting purposes. When a process exits,
	 * the mm is exited and dropped before the files, hence we need to hang
	 * on to this mm purely for the purposes of being able to unaccount
	 * memory (locked/pinned vm). It's not used for anything else.
	 */
	mmgrab(current->mm);
	ctx->mm_account = current->mm;

	ret = io_allocate_scq_urings(ctx, p);
	if (ret)
		goto err;

	if (!(p->flags & IORING_SETUP_NO_SQARRAY))
		p->sq_off.array = (char *)ctx->sq_array - (char *)ctx->rings;

	ret = io_sq_offload_create(ctx, p);
	if (ret)
		goto err;

	p->features = IORING_FEAT_SINGLE_MMAP | IORING_FEAT_NODROP |
			IORING_FEAT_SUBMIT_STABLE | IORING_FEAT_RW_CUR_POS |
			IORING_FEAT_CUR_PERSONALITY | IORING_FEAT_FAST_POLL |
			IORING_FEAT_POLL_32BITS | IORING_FEAT_SQPOLL_NONFIXED |
			IORING_FEAT_EXT_ARG | IORING_FEAT_NATIVE_WORKERS |
			IORING_FEAT_RSRC_TAGS | IORING_FEAT_CQE_SKIP |
			IORING_FEAT_LINKED_FILE | IORING_FEAT_REG_REG_RING |
			IORING_FEAT_RECVSEND_BUNDLE | IORING_FEAT_MIN_TIMEOUT |
			IORING_FEAT_RW_ATTR | IORING_FEAT_NO_IOWAIT;

	if (copy_to_user(params, p, sizeof(*p))) {
		ret = -EFAULT;
		goto err;
	}

	if (ctx->flags & IORING_SETUP_SINGLE_ISSUER
	    && !(ctx->flags & IORING_SETUP_R_DISABLED))
		WRITE_ONCE(ctx->submitter_task, get_task_struct(current));

	file = io_uring_get_file(ctx);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto err;
	}

	ret = __io_uring_add_tctx_node(ctx);
	if (ret)
		goto err_fput;
	tctx = current->io_uring;

	/*
	 * Install ring fd as the very last thing, so we don't risk someone
	 * having closed it before we finish setup
	 */
	if (p->flags & IORING_SETUP_REGISTERED_FD_ONLY)
		ret = io_ring_add_registered_file(tctx, file, 0, IO_RINGFD_REG_MAX);
	else
		ret = io_uring_install_fd(file);
	if (ret < 0)
		goto err_fput;

	trace_io_uring_create(ret, ctx, p->sq_entries, p->cq_entries, p->flags);
	return ret;
err:
	io_ring_ctx_wait_and_kill(ctx);
	return ret;
err_fput:
	fput(file);
	return ret;
}

/*
 * Sets up an aio uring context, and returns the fd. Applications asks for a
 * ring size, we return the actual sq/cq ring sizes (among other things) in the
 * params structure passed in.
 */
static long io_uring_setup(u32 entries, struct io_uring_params __user *params)
{
	struct io_uring_params p;
	int i;

	if (copy_from_user(&p, params, sizeof(p)))
		return -EFAULT;
	for (i = 0; i < ARRAY_SIZE(p.resv); i++) {
		if (p.resv[i])
			return -EINVAL;
	}

	if (p.flags & ~(IORING_SETUP_IOPOLL | IORING_SETUP_SQPOLL |
			IORING_SETUP_SQ_AFF | IORING_SETUP_CQSIZE |
			IORING_SETUP_CLAMP | IORING_SETUP_ATTACH_WQ |
			IORING_SETUP_R_DISABLED | IORING_SETUP_SUBMIT_ALL |
			IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG |
			IORING_SETUP_SQE128 | IORING_SETUP_CQE32 |
			IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN |
			IORING_SETUP_NO_MMAP | IORING_SETUP_REGISTERED_FD_ONLY |
			IORING_SETUP_NO_SQARRAY | IORING_SETUP_HYBRID_IOPOLL))
		return -EINVAL;

	return io_uring_create(entries, &p, params);
}

/* enforces system-wide io_uring usage policies based on sysctl settings,
 * capability checks, and group membership. The rules are:
 * - If io_uring is disabled globally (sysctl_io_uring_disabled == 2), deny access.
 * - If io_uring is enabled (0) or the caller has CAP_SYS_ADMIN, allow access.
 * - Otherwise, check if the caller belongs to the configured io_uring group.
 * - Finally, defer to the Linux Security Module (LSM) hook for additional checks.
 * Returns 0 if allowed, or -EPERM if denied. */
static inline int io_uring_allowed(void)
{
	int disabled = READ_ONCE(sysctl_io_uring_disabled);
	kgid_t io_uring_group;

	if (disabled == 2)
		return -EPERM;

	if (disabled == 0 || capable(CAP_SYS_ADMIN))
		goto allowed_lsm;

	io_uring_group = make_kgid(&init_user_ns, sysctl_io_uring_group);
	if (!gid_valid(io_uring_group))
		return -EPERM;

	if (!in_group_p(io_uring_group))
		return -EPERM;

allowed_lsm:
	return security_uring_allowed();
}

/* checks if the current task is allowed to use io_uring,
 * then delegates to the internal io_uring_setup function to perform setup.
 * Returns a file descriptor on success or a negative error code on failure. */
SYSCALL_DEFINE2(io_uring_setup, u32, entries,
		struct io_uring_params __user *, params)
{
	int ret;

	ret = io_uring_allowed();
	if (ret)
		return ret;

	return io_uring_setup(entries, params);
}

/* performs compile-time sanity checks on io_uring data structures
 * using BUILD_BUG_ON to ensure offsets and sizes are as expected.
 * It initializes the kmem cache for io_kiocb structures with proper annotations
 * for hardened usercopy.
 * It creates the unbound workqueue used for io_uring exit work.
 * It registers sysctl entries for io_uring configuration if enabled.
 * Returns 0 on success. */
static int __init io_uring_init(void)
{
	struct kmem_cache_args kmem_args = {
		.useroffset = offsetof(struct io_kiocb, cmd.data),
		.usersize = sizeof_field(struct io_kiocb, cmd.data),
		.freeptr_offset = offsetof(struct io_kiocb, work),
		.use_freeptr_offset = true,
	};

#define __BUILD_BUG_VERIFY_OFFSET_SIZE(stype, eoffset, esize, ename) do { \
	BUILD_BUG_ON(offsetof(stype, ename) != eoffset); \
	BUILD_BUG_ON(sizeof_field(stype, ename) != esize); \
} while (0)

#define BUILD_BUG_SQE_ELEM(eoffset, etype, ename) \
	__BUILD_BUG_VERIFY_OFFSET_SIZE(struct io_uring_sqe, eoffset, sizeof(etype), ename)
#define BUILD_BUG_SQE_ELEM_SIZE(eoffset, esize, ename) \
	__BUILD_BUG_VERIFY_OFFSET_SIZE(struct io_uring_sqe, eoffset, esize, ename)
	BUILD_BUG_ON(sizeof(struct io_uring_sqe) != 64);
	BUILD_BUG_SQE_ELEM(0,  __u8,   opcode);
	BUILD_BUG_SQE_ELEM(1,  __u8,   flags);
	BUILD_BUG_SQE_ELEM(2,  __u16,  ioprio);
	BUILD_BUG_SQE_ELEM(4,  __s32,  fd);
	BUILD_BUG_SQE_ELEM(8,  __u64,  off);
	BUILD_BUG_SQE_ELEM(8,  __u64,  addr2);
	BUILD_BUG_SQE_ELEM(8,  __u32,  cmd_op);
	BUILD_BUG_SQE_ELEM(12, __u32, __pad1);
	BUILD_BUG_SQE_ELEM(16, __u64,  addr);
	BUILD_BUG_SQE_ELEM(16, __u64,  splice_off_in);
	BUILD_BUG_SQE_ELEM(24, __u32,  len);
	BUILD_BUG_SQE_ELEM(28,     __kernel_rwf_t, rw_flags);
	BUILD_BUG_SQE_ELEM(28, /* compat */   int, rw_flags);
	BUILD_BUG_SQE_ELEM(28, /* compat */ __u32, rw_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  fsync_flags);
	BUILD_BUG_SQE_ELEM(28, /* compat */ __u16,  poll_events);
	BUILD_BUG_SQE_ELEM(28, __u32,  poll32_events);
	BUILD_BUG_SQE_ELEM(28, __u32,  sync_range_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  msg_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  timeout_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  accept_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  cancel_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  open_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  statx_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  fadvise_advice);
	BUILD_BUG_SQE_ELEM(28, __u32,  splice_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  rename_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  unlink_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  hardlink_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  xattr_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  msg_ring_flags);
	BUILD_BUG_SQE_ELEM(32, __u64,  user_data);
	BUILD_BUG_SQE_ELEM(40, __u16,  buf_index);
	BUILD_BUG_SQE_ELEM(40, __u16,  buf_group);
	BUILD_BUG_SQE_ELEM(42, __u16,  personality);
	BUILD_BUG_SQE_ELEM(44, __s32,  splice_fd_in);
	BUILD_BUG_SQE_ELEM(44, __u32,  file_index);
	BUILD_BUG_SQE_ELEM(44, __u16,  addr_len);
	BUILD_BUG_SQE_ELEM(46, __u16,  __pad3[0]);
	BUILD_BUG_SQE_ELEM(48, __u64,  addr3);
	BUILD_BUG_SQE_ELEM_SIZE(48, 0, cmd);
	BUILD_BUG_SQE_ELEM(48, __u64, attr_ptr);
	BUILD_BUG_SQE_ELEM(56, __u64, attr_type_mask);
	BUILD_BUG_SQE_ELEM(56, __u64,  __pad2);

	BUILD_BUG_ON(sizeof(struct io_uring_files_update) !=
		     sizeof(struct io_uring_rsrc_update));
	BUILD_BUG_ON(sizeof(struct io_uring_rsrc_update) >
		     sizeof(struct io_uring_rsrc_update2));

	/* ->buf_index is u16 */
	BUILD_BUG_ON(offsetof(struct io_uring_buf_ring, bufs) != 0);
	BUILD_BUG_ON(offsetof(struct io_uring_buf, resv) !=
		     offsetof(struct io_uring_buf_ring, tail));

	/* should fit into one byte */
	BUILD_BUG_ON(SQE_VALID_FLAGS >= (1 << 8));
	BUILD_BUG_ON(SQE_COMMON_FLAGS >= (1 << 8));
	BUILD_BUG_ON((SQE_VALID_FLAGS | SQE_COMMON_FLAGS) != SQE_VALID_FLAGS);

	BUILD_BUG_ON(__REQ_F_LAST_BIT > 8 * sizeof_field(struct io_kiocb, flags));

	BUILD_BUG_ON(sizeof(atomic_t) != sizeof(u32));

	/* top 8bits are for internal use */
	BUILD_BUG_ON((IORING_URING_CMD_MASK & 0xff000000) != 0);

	io_uring_optable_init();

	/* imu->dir is u8 */
	BUILD_BUG_ON((IO_IMU_DEST | IO_IMU_SOURCE) > U8_MAX);

	/*
	 * Allow user copy in the per-command field, which starts after the
	 * file in io_kiocb and until the opcode field. The openat2 handling
	 * requires copying in user memory into the io_kiocb object in that
	 * range, and HARDENED_USERCOPY will complain if we haven't
	 * correctly annotated this range.
	 */
	req_cachep = kmem_cache_create("io_kiocb", sizeof(struct io_kiocb), &kmem_args,
				SLAB_HWCACHE_ALIGN | SLAB_PANIC | SLAB_ACCOUNT |
				SLAB_TYPESAFE_BY_RCU);

	iou_wq = alloc_workqueue("iou_exit", WQ_UNBOUND, 64);
	BUG_ON(!iou_wq);

#ifdef CONFIG_SYSCTL
	register_sysctl_init("kernel", kernel_io_uring_disabled_table);
#endif

	return 0;
};
__initcall(io_uring_init);
