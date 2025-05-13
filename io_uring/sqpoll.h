// SPDX-License-Identifier: GPL-2.0

struct io_sq_data {
	refcount_t		refs;
	atomic_t		park_pending;
	struct mutex		lock;

	/* ctx's that are using this sqd */
	struct list_head	ctx_list;

	struct task_struct	*thread;
	struct wait_queue_head	wait;

	unsigned		sq_thread_idle;
	int			sq_cpu;
	pid_t			task_pid;
	pid_t			task_tgid;

	u64			work_time;
	unsigned long		state;
	struct completion	exited;
};

/* Create or attach to SQPOLL offload thread. */
int io_sq_offload_create(struct io_ring_ctx *ctx, struct io_uring_params *p);

/* Finish and cleanup SQPOLL thread for a context. */
void io_sq_thread_finish(struct io_ring_ctx *ctx);

/* Stop the SQPOLL thread. */
void io_sq_thread_stop(struct io_sq_data *sqd);

/* Park the SQPOLL thread. */
void io_sq_thread_park(struct io_sq_data *sqd);

/* Unpark the SQPOLL thread. */
void io_sq_thread_unpark(struct io_sq_data *sqd);

/* Release a reference to io_sq_data. */
void io_put_sq_data(struct io_sq_data *sqd);

/* Wait until the submission queue has space. */
void io_sqpoll_wait_sq(struct io_ring_ctx *ctx);

/* Set CPU affinity of the SQPOLL thread. */
int io_sqpoll_wq_cpu_affinity(struct io_ring_ctx *ctx, cpumask_var_t mask);
