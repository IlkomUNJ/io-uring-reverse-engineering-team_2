// SPDX-License-Identifier: GPL-2.0

struct io_tctx_node {
	struct list_head	ctx_node;
	struct task_struct	*task;
	struct io_ring_ctx	*ctx;
};

/* Allocate and initialize io_uring task context */
int io_uring_alloc_task_context(struct task_struct *task,
				struct io_ring_ctx *ctx);

/* Remove an io_uring_file -> task mapping. */
void io_uring_del_tctx_node(unsigned long index);

/* Add a task context node for current task and io_uring context. */
int __io_uring_add_tctx_node(struct io_ring_ctx *ctx);

/* Add task context node during submission. */
int __io_uring_add_tctx_node_from_submit(struct io_ring_ctx *ctx);

/* Clean all task context nodes and release io_wq. */
void io_uring_clean_tctx(struct io_uring_task *tctx);

/* Unregister all registered ring file descriptors. */
void io_uring_unreg_ringfd(void);

/* Register ring file descriptors for io_uring.*/
int io_ringfd_register(struct io_ring_ctx *ctx, void __user *__arg,
		       unsigned nr_args);

/* Unregister ring file descriptors for io_uring. */
int io_ringfd_unregister(struct io_ring_ctx *ctx, void __user *__arg,
			 unsigned nr_args);

/*
 * Note that this task has used io_uring. We use it for cancelation purposes.
 * Add task context node if not already present.
 */
static inline int io_uring_add_tctx_node(struct io_ring_ctx *ctx)
{
	struct io_uring_task *tctx = current->io_uring;

	if (likely(tctx && tctx->last == ctx))
		return 0;

	return __io_uring_add_tctx_node_from_submit(ctx);
}
