// SPDX-License-Identifier: GPL-2.0

#include <linux/io_uring_types.h>

#define IO_POLL_ALLOC_CACHE_MAX 32

enum {
    IO_APOLL_OK,
    IO_APOLL_ABORTED,
    IO_APOLL_READY
};

struct io_poll {
    struct file			*file;
    struct wait_queue_head		*head;
    __poll_t			events;
    int				retries;
    struct wait_queue_entry		wait;
};

struct async_poll {
    struct io_poll		poll;
    struct io_poll		*double_poll;
};

/*
 * Must only be called inside issue_flags & IO_URING_F_MULTISHOT, or
 * potentially other cases where we already "own" this poll request.
 */
/* 
 * Increments the poll reference counter for multishot poll requests.
 * Uses atomic increment to safely track active references in concurrent environments.
 */
static inline void io_poll_multishot_retry(struct io_kiocb *req)
{
    atomic_inc(&req->poll_refs);
}

/* 
 * Prepares a poll add operation from submission queue entry.
 * Parses SQE parameters and initializes the request structure for polling.
 */
int io_poll_add_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* 
 * Implements the poll add operation for monitoring file events.
 * Sets up waitqueue entries and handles immediate completion if events are already available.
 */
int io_poll_add(struct io_kiocb *req, unsigned int issue_flags);

/* 
 * Prepares a poll remove or update operation.
 * Validates SQE parameters and sets up the request for removing or updating an existing poll.
 */
int io_poll_remove_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* 
 * Implements poll remove or update functionality.
 * Locates and modifies or removes an existing poll request based on provided parameters.
 */
int io_poll_remove(struct io_kiocb *req, unsigned int issue_flags);

/* 
 * Cancels an active poll request.
 * Finds the target request in the cancellation hash table and triggers its removal.
 */
struct io_cancel_data;
int io_poll_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
           unsigned issue_flags);

/* 
 * Sets up polling for asynchronous operations.
 * Configures poll events based on the operation type and installs handler.
 */
int io_arm_poll_handler(struct io_kiocb *req, unsigned issue_flags);

/* 
 * Removes all poll requests associated with a task.
 * Scans the poll hash table to find and optionally cancel all matching requests.
 */
bool io_poll_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
            bool cancel_all);

/* 
 * Task work handler for completing poll operations.
 * Processes poll results and determines next actions for the request.
 */
void io_poll_task_func(struct io_kiocb *req, io_tw_token_t tw);
