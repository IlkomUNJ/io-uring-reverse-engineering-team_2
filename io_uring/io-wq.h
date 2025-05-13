#ifndef INTERNAL_IO_WQ_H
#define INTERNAL_IO_WQ_H

#include <linux/refcount.h>
#include <linux/io_uring_types.h>

struct io_wq;

enum {
	IO_WQ_WORK_CANCEL	= 1,
	IO_WQ_WORK_HASHED	= 2,
	IO_WQ_WORK_UNBOUND	= 4,
	IO_WQ_WORK_CONCURRENT	= 16,

	IO_WQ_HASH_SHIFT	= 24,	/* upper 8 bits are used for hash key */
};

enum io_wq_cancel {
	IO_WQ_CANCEL_OK,	/* cancelled before started */
	IO_WQ_CANCEL_RUNNING,	/* found, running, and attempted cancelled */
	IO_WQ_CANCEL_NOTFOUND,	/* work not found */
};

typedef struct io_wq_work *(free_work_fn)(struct io_wq_work *);
typedef void (io_wq_work_fn)(struct io_wq_work *);

struct io_wq_hash {
	refcount_t refs;
	unsigned long map;
	struct wait_queue_head wait;
};

/* Decreases reference count for a hash table and frees it when count reaches zero. */
static inline void io_wq_put_hash(struct io_wq_hash *hash)
{
	if (refcount_dec_and_test(&hash->refs))
		kfree(hash);
}

struct io_wq_data {
	struct io_wq_hash *hash;
	struct task_struct *task;
	io_wq_work_fn *do_work;
	free_work_fn *free_work;
};

struct io_wq *io_wq_create(unsigned bounded, struct io_wq_data *data);

/* Marks a worker queue for shutdown, preventing new work from being accepted. */
void io_wq_exit_start(struct io_wq *wq);

/* Completes worker queue shutdown by stopping all workers, cancelling remaining work, and freeing resources.*/
void io_wq_put_and_exit(struct io_wq *wq);

/* Marks work as serialized based on a pointer value, preventing parallel execution of related operations. 
Calculates a hash from the pointer and embeds it in the work flags.*/
void io_wq_enqueue(struct io_wq *wq, struct io_wq_work *work);

/* Marks work as serialized based on a pointer value, preventing parallel execution of related operations. Calculates a hash from the pointer and embeds it in the work flags.*/
void io_wq_hash_work(struct io_wq_work *work, void *val);

/* Sets which CPUs workers are allowed to run on.  */
int io_wq_cpu_affinity(struct io_uring_task *tctx, cpumask_var_t mask);

/* Sets or gets the maximum number of workers that can exist simultaneously. */
int io_wq_max_workers(struct io_wq *wq, int *new_count);

/* Checks if current worker thread should stop processing work. */
bool io_wq_worker_stopped(void);

/* Helper function that checks if work is marked for serialized execution by examining flag bits. */
static inline bool __io_wq_is_hashed(unsigned int work_flags)
{
	return work_flags & IO_WQ_WORK_HASHED;
}

/* Checks if a work item needs serialized execution by safely examining its flags. */
static inline bool io_wq_is_hashed(struct io_wq_work *work)
{
	return __io_wq_is_hashed(atomic_read(&work->flags));
}

typedef bool (work_cancel_fn)(struct io_wq_work *, void *);

/* Cancels matching work items using a callback function. Reports whether work was pending, running, or not found. */
enum io_wq_cancel io_wq_cancel_cb(struct io_wq *wq, work_cancel_fn *cancel,
					void *data, bool cancel_all);

#if defined(CONFIG_IO_WQ)

/* Notifies system when a worker goes to sleep. Updates accounting and may trigger creation of new workers. */
extern void io_wq_worker_sleeping(struct task_struct *);

/* Notifies system when a worker starts running. Updates accounting to track active worker count. */
extern void io_wq_worker_running(struct task_struct *);
#else

static inline void io_wq_worker_sleeping(struct task_struct *tsk)
{
}
static inline void io_wq_worker_running(struct task_struct *tsk)
{
}
#endif

/* Checks if the current thread is an io_uring worker by examining task flags. Used for context verification. */
static inline bool io_wq_current_is_worker(void)
{
	return in_task() && (current->flags & PF_IO_WORKER) &&
		current->worker_private;
}
#endif
