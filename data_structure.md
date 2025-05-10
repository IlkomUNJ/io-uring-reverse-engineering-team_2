# Task 3: Data Structure Investigation
The objective of this task is to document all internal data structures defined in io_uring. 

Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_ev_fd       | io_uring/eventfd.c | eventfd_ctx, uint, uint, refcount_t, atomic_t, rcu_head | io_eventfd_free | io_uring/eventfd.c | local variable
| | | | io_eventfd_put | io_uring/eventfd.c | function parameter
| | | | io_eventfd_do_signal | io_uring/eventfd.c | local variable, function parameter
| | | | __io_eventfd_signal | io_uring/eventfd.c | function parameter
| | | | io_eventfd_grab | io_uring/eventfd.c | return value, local variable
| | | | io_eventfd_signal | io_uring/eventfd.c | local variable 
| | | | io_eventfd_flush_signal | io_uring/eventfd.c | local variable
| | | | io_eventfd_register | io_uring/eventfd.c | local variable
| | | | io_eventfd_unregister | io_uring/eventfd.c | function parameter
io_rename | io_uring/fs.c | struct file			*file, int				old_dfd, int				new_dfd, struct filename			*oldpath, struct filename			*newpath, int				flags |  io_renameat_prep | io_uring/fs.c | declaration
| | | | io_renameat | io_uring/fs.c | declaration
| | | | io_renameat_cleanup | io_uring/fs.c | declaration
io_unlink | io_uring/fs.c | struct file			*file, int				dfd, int				flags, struct filename			*filename | io_unlinkat_prep | io_uring/fs.c | declaration
| | | | io_unlinkat | io_uring/fs.c | declaration
| | | | io_unlinkat_cleanup | io_uring/fs.c | declaration
io_mkdir | io_uring/fs.c | struct file			*file, int				dfd, umode_t				mode, struct filename			*filename | io_mkdirat_prep | io_uring/fs.c | declaration
| | | | io_mkdirat | io_uring/fs.c | declaration
| | | | io_mkdirat_cleanup | io_uring/fs.c | declaration
io_link | io_uring/fs.c | struct file			*file, int				old_dfd, int				new_dfd, struct filename			*oldpath, struct filename			*newpath, int				flags | io_symlinkat_prep | io_uring/fs.c | declaration
| | | | io_symlinkat | io_uring/fs.c | declaration
| | | | io_linkat_prep | io_uring/fs.c | declaration
| | | | io_linkat | io_uring/fs.c | declaration
| | | | io_link_cleanup | io_uring/fs.c | declaration
io_futex | io_uring/futex.c | struct file	*file, union { 		u32 __user			*uaddr, struct futex_waitv __user	*uwaitv | io_futexv_complete | io_uring/futex.c | declaration
| | | | io_futexv_claim | io_uring/futex.c | declaration
| | | | __io_futex_cancel | io_uring/futex.c | declaration
| | | | io_futex_prep | io_uring/futex.c | declaration
| | | | io_futex_wakev_fn | io_uring/futex.c | declaration
| | | | io_futexv_prep | io_uring/futex.c | declaration
| | | | io_futexv_wait | io_uring/futex.c | declaration
| | | | io_futex_wait | io_uring/futex.c | declaration
| | | | io_futex_wake | io_uring/futex.c | declaration
io_futex_data | io_uring/futex.c | struct futex_q	q, struct io_kiocb	*req |io_futex_cache_init | io_uring/futex.c | declaration
| | | | __io_futex_cancel | io_uring/futex.c | declaration
| | | | io_futex_wake_fn | io_uring/futex.c | declaration
| | | | io_futex_wait | io_uring/futex.c | declaration
io_defer_entry | io_uring/io_uring.c | struct list_head	list, struct io_kiocb		*req, u32			seq | io_queue_deferred | io_uring/io_uring.c | declaration
| | | | io_queue_deferred | io_uring/io_uring.c | declaration
| | | | io_drain_req | io_uring/io_uring.c | declaration
| | | | io_match_task_safe | io_uring/io_uring.c | declaration
| | | | io_match_task_safe | io_uring/io_uring.c | declaration
ext_arg | io_uring/io_uring.c | size_t argsz, struct timespec64 ts, const sigset_t __user *sig, ktime_t min_time, bool ts_set, bool iowait | READ_ONCE | io_uring/io_uring.c | declaration
| | | | READ_ONCE | io_uring/io_uring.c | declaration
| | | | READ_ONCE | io_uring/io_uring.c | function parameter or call
| | | | READ_ONCE | io_uring/io_uring.c | declaration
| | | | __io_cqring_wait_schedule | io_uring/io_uring.c | function parameter or call
| | | | __io_cqring_wait_schedule | io_uring/io_uring.c | declaration
| | | | __io_cqring_wait_schedule | io_uring/io_uring.c | assignment or return
| | | | __io_cqring_wait_schedule | io_uring/io_uring.c | function parameter or call
| | | | __io_cqring_wait_schedule | io_uring/io_uring.c | function parameter or call
| | | | __io_cqring_wait_schedule | io_uring/io_uring.c | function parameter or call
| | | | __io_cqring_wait_schedule | io_uring/io_uring.c | function parameter or call
| | | | __io_cqring_wait_schedule | io_uring/io_uring.c | reference
| | | | __io_cqring_wait_schedule | io_uring/io_uring.c | function parameter or call
| | | | __io_cqring_wait_schedule | io_uring/io_uring.c | function parameter or call
| | | | ERR_PTR | io_uring/io_uring.c | declaration
| | | | ERR_PTR | io_uring/io_uring.c | function parameter or call
| | | | ERR_PTR | io_uring/io_uring.c | function parameter or call
| | | | ERR_PTR | io_uring/io_uring.c | declaration
| | | | PTR_ERR | io_uring/io_uring.c | function parameter or call
| | | | PTR_ERR | io_uring/io_uring.c | function parameter or call
| | | | PTR_ERR | io_uring/io_uring.c | function parameter or call
| | | | PTR_ERR | io_uring/io_uring.c | function parameter or call
| | | | PTR_ERR | io_uring/io_uring.c | function parameter or call
| | | | PTR_ERR | io_uring/io_uring.c | assignment or return
| | | | PTR_ERR | io_uring/io_uring.c | function parameter or call
| | | | PTR_ERR | io_uring/io_uring.c | assignment or return
| | | | PTR_ERR | io_uring/io_uring.c | function parameter or call
| | | | PTR_ERR | io_uring/io_uring.c | assignment or return
| | | | PTR_ERR | io_uring/io_uring.c | function parameter or call
| | | | PTR_ERR | io_uring/io_uring.c | assignment or return
| | | | PTR_ERR | io_uring/io_uring.c | declaration
| | | | PTR_ERR | io_uring/io_uring.c | function parameter or call
| | | | PTR_ERR | io_uring/io_uring.c | reference
io_tctx_exit | io_uring/io_uring.c | struct callback_head		task_work, struct completion		completion, struct io_ring_ctx		*ctx | io_uring_poll | io_uring/io_uring.c | declaration
| | | | io_tctx_exit_cb | io_uring/io_uring.c | declaration
| | | | io_tctx_exit_cb | io_uring/io_uring.c | declaration
| | | | io_ring_exit_work | io_uring/io_uring.c | declaration
io_task_cancel | io_uring/io_uring.c | struct io_uring_task *tctx, bool all | io_uring_release | io_uring/io_uring.c | declaration
| | | | io_cancel_task_cb | io_uring/io_uring.c | declaration
| | | | io_uring_try_cancel_iowq | io_uring/io_uring.c | declaration
io_wait_queue | io_uring/io_uring.h | struct wait_queue_entry wq, struct io_ring_ctx *ctx, unsigned cq_tail, unsigned cq_min_tail, unsigned nr_timeouts, int hit_timeout, ktime_t min_timeout, ktime_t timeout, struct hrtimer t, #ifdef CONFIG_NET_RX_BUSY_POLL 	ktime_t napi_busy_poll_dt, bool napi_prefer_busy_poll, #endif | io_submit_sqes | io_uring/io_uring.c | declaration
| | | | io_cqring_timer_wakeup | io_uring/io_uring.c | declaration
| | | | io_cqring_min_timer_wakeup | io_uring/io_uring.c | declaration
| | | | io_cqring_timer_wakeup | io_uring/io_uring.c | declaration
| | | | READ_ONCE | io_uring/io_uring.c | declaration
| | | | READ_ONCE | io_uring/io_uring.c | declaration
| | | | __io_cqring_wait_schedule | io_uring/io_uring.c | declaration
| | | |  | io_uring/io_uring.h | declaration
| | | | io_should_wake | io_uring/io_uring.h | declaration
| | | | ktime_after | io_uring/napi.c | declaration
| | | | dynamic_tracking_do_busy_loop | io_uring/napi.c | declaration
| | | | __io_napi_busy_loop | io_uring/napi.c | declaration
| | | | __io_napi_busy_loop | io_uring/napi.h | declaration
| | | | io_napi | io_uring/napi.h | declaration
| | | | io_napi_add | io_uring/napi.h | declaration
io_worker | io_uring/io-wq.c | refcount_t ref, unsigned long flags, struct hlist_nulls_node nulls_node, struct list_head all_list, struct task_struct *task, struct io_wq *wq, struct io_wq_acct *acct, struct io_wq_work *cur_work, raw_spinlock_t lock, struct completion ref_done, unsigned long create_state, struct callback_head create_work, int init_retries, union { 		struct rcu_head rcu, struct delayed_work work | io_wq_dec_running | io_uring/io-wq.c | declaration
| | | | io_worker_get | io_uring/io-wq.c | declaration
| | | | io_worker_release | io_uring/io-wq.c | declaration
| | | | io_get_acct | io_uring/io-wq.c | declaration
| | | | io_wq_worker_stopped | io_uring/io-wq.c | declaration
| | | | io_worker_cancel_cb | io_uring/io-wq.c | declaration
| | | | io_task_worker_match | io_uring/io-wq.c | declaration
| | | | io_task_worker_match | io_uring/io-wq.c | declaration
| | | | io_worker_exit | io_uring/io-wq.c | declaration
| | | | io_acct_activate_free_worker | io_uring/io-wq.c | declaration
| | | | io_wq_inc_running | io_uring/io-wq.c | declaration
| | | | create_worker_cb | io_uring/io-wq.c | declaration
| | | | create_worker_cb | io_uring/io-wq.c | declaration
| | | | create_worker_cb | io_uring/io-wq.c | declaration
| | | | io_wq_dec_running | io_uring/io-wq.c | declaration
| | | | __io_worker_busy | io_uring/io-wq.c | declaration
| | | | __io_worker_idle | io_uring/io-wq.c | declaration
| | | | io_wait_on_hash | io_uring/io-wq.c | declaration
| | | | io_wait_on_hash | io_uring/io-wq.c | declaration
| | | | io_wq_worker | io_uring/io-wq.c | declaration
| | | | io_wq_worker_running | io_uring/io-wq.c | declaration
| | | | io_wq_worker_sleeping | io_uring/io-wq.c | declaration
| | | | io_wq_worker_sleeping | io_uring/io-wq.c | declaration
| | | | io_should_retry_thread | io_uring/io-wq.c | declaration
| | | | queue_create_worker_retry | io_uring/io-wq.c | declaration
| | | | create_worker_cont | io_uring/io-wq.c | declaration
| | | | create_worker_cont | io_uring/io-wq.c | declaration
| | | | io_workqueue_create | io_uring/io-wq.c | declaration
| | | | create_io_worker | io_uring/io-wq.c | declaration
| | | | create_io_worker | io_uring/io-wq.c | declaration
| | | | create_io_worker | io_uring/io-wq.c | declaration
| | | | create_io_worker | io_uring/io-wq.c | declaration
| | | | io_wq_worker_wake | io_uring/io-wq.c | declaration
| | | | io_wq_hash_work | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_task_work_match | io_uring/io-wq.c | declaration
| | | | io_task_work_match | io_uring/io-wq.c | declaration
| | | | io_wq_cancel_tw_create | io_uring/io-wq.c | declaration
| | | | io_wq_cancel_tw_create | io_uring/io-wq.c | declaration
| | | | io_wq_worker_affinity | io_uring/io-wq.c | declaration
io_wq_acct | io_uring/io-wq.c | /** 	 * Protects access to the worker lists. 	 */ 	raw_spinlock_t workers_lock, unsigned nr_workers, unsigned max_workers, atomic_t nr_running, /** 	 * The list of free workers.  Protected by #workers_lock 	 * (write) and RCU (read). 	 */ 	struct hlist_nulls_head free_list, /** 	 * The list of all workers.  Protected by #workers_lock 	 * (write) and RCU (read). 	 */ 	struct list_head all_list, raw_spinlock_t lock, struct io_wq_work_list work_list, unsigned long flags | create_io_worker | io_uring/io-wq.c | declaration
| | | | io_wq_dec_running | io_uring/io-wq.c | declaration
| | | | io_worker_release | io_uring/io-wq.c | declaration
| | | | io_worker_release | io_uring/io-wq.c | declaration
| | | | io_get_acct | io_uring/io-wq.c | declaration
| | | | io_worker_cancel_cb | io_uring/io-wq.c | declaration
| | | | io_worker_exit | io_uring/io-wq.c | declaration
| | | | __io_acct_run_queue | io_uring/io-wq.c | declaration
| | | | io_acct_run_queue | io_uring/io-wq.c | declaration
| | | | io_acct_activate_free_worker | io_uring/io-wq.c | declaration
| | | | io_wq_create_worker | io_uring/io-wq.c | declaration
| | | | io_wq_inc_running | io_uring/io-wq.c | declaration
| | | | create_worker_cb | io_uring/io-wq.c | declaration
| | | | create_worker_cb | io_uring/io-wq.c | declaration
| | | | io_wq_dec_running | io_uring/io-wq.c | declaration
| | | | __io_worker_busy | io_uring/io-wq.c | declaration
| | | | __io_worker_idle | io_uring/io-wq.c | declaration
| | | | io_wait_on_hash | io_uring/io-wq.c | declaration
| | | | io_wait_on_hash | io_uring/io-wq.c | declaration
| | | | io_wq_worker | io_uring/io-wq.c | declaration
| | | | io_wq_worker_sleeping | io_uring/io-wq.c | declaration
| | | | create_worker_cont | io_uring/io-wq.c | declaration
| | | | io_workqueue_create | io_uring/io-wq.c | declaration
| | | | create_io_worker | io_uring/io-wq.c | declaration
| | | | create_io_worker | io_uring/io-wq.c | declaration
| | | | io_run_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_enqueue | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | ERR_PTR | io_uring/io-wq.c | declaration
| | | | io_wq_max_workers | io_uring/io-wq.c | declaration
io_wq | io_uring/io-wq.c | unsigned long state, free_work_fn *free_work, io_wq_work_fn *do_work, struct io_wq_hash *hash, atomic_t worker_refs, struct completion worker_done, struct hlist_node cpuhp_node, struct task_struct *task, struct io_wq_acct acct[IO_WQ_ACCT_NR], struct wait_queue_entry wait, struct io_wq_work *hash_tail[IO_WQ_NR_HASH_BUCKETS], cpumask_var_t cpu_mask |create_io_worker | io_uring/io-wq.c | declaration
| | | | io_wq_dec_running | io_uring/io-wq.c | declaration
| | | | io_wq_cancel_tw_create | io_uring/io-wq.c | declaration
| | | | io_worker_release | io_uring/io-wq.c | declaration
| | | | io_worker_release | io_uring/io-wq.c | declaration
| | | | io_worker_ref_put | io_uring/io-wq.c | declaration
| | | | io_worker_cancel_cb | io_uring/io-wq.c | declaration
| | | | io_worker_exit | io_uring/io-wq.c | declaration
| | | | io_wq_create_worker | io_uring/io-wq.c | declaration
| | | | io_wq_create_worker | io_uring/io-wq.c | reference
| | | | create_worker_cb | io_uring/io-wq.c | declaration
| | | | create_worker_cb | io_uring/io-wq.c | declaration
| | | | io_wq_dec_running | io_uring/io-wq.c | declaration
| | | | io_wait_on_hash | io_uring/io-wq.c | declaration
| | | | io_wait_on_hash | io_uring/io-wq.c | declaration
| | | | io_wait_on_hash | io_uring/io-wq.c | declaration
| | | | io_wq_worker | io_uring/io-wq.c | declaration
| | | | io_wq_worker_sleeping | io_uring/io-wq.c | declaration
| | | | create_worker_cont | io_uring/io-wq.c | declaration
| | | | create_io_worker | io_uring/io-wq.c | declaration
| | | | create_io_worker | io_uring/io-wq.c | declaration
| | | | io_run_cancel | io_uring/io-wq.c | declaration
| | | | io_run_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_enqueue | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | ERR_PTR | io_uring/io-wq.c | declaration
| | | | io_wq_exit_start | io_uring/io-wq.c | declaration
| | | | io_wq_cancel_tw_create | io_uring/io-wq.c | declaration
| | | | io_wq_exit_workers | io_uring/io-wq.c | declaration
| | | | io_wq_destroy | io_uring/io-wq.c | declaration
| | | | io_wq_put_and_exit | io_uring/io-wq.c | declaration
| | | | __io_wq_cpu_online | io_uring/io-wq.c | declaration
| | | | io_wq_cpu_online | io_uring/io-wq.c | declaration
| | | | io_wq_cpu_offline | io_uring/io-wq.c | declaration
| | | | io_wq_cpu_affinity | io_uring/io-wq.c | function parameter or call
| | | | io_wq_cpu_affinity | io_uring/io-wq.c | function parameter or call
| | | | io_wq_cpu_affinity | io_uring/io-wq.c | function parameter or call
| | | | io_wq_cpu_affinity | io_uring/io-wq.c | function parameter or call
| | | | io_wq_max_workers | io_uring/io-wq.c | declaration
| | | |  | io_uring/io-wq.h | declaration
| | | | io_wq_put_hash | io_uring/io-wq.h | declaration
| | | | io_wq_exit_start | io_uring/io-wq.h | declaration
| | | | io_wq_put_and_exit | io_uring/io-wq.h | declaration
| | | | io_wq_enqueue | io_uring/io-wq.h | declaration
| | | | io_wq_max_workers | io_uring/io-wq.h | declaration
| | | | bool | io_uring/io-wq.h | declaration
| | | | io_queue_iowq | io_uring/io_uring.c | function parameter or call
| | | | io_queue_iowq | io_uring/io_uring.c | function parameter or call
| | | | io_ring_exit_work | io_uring/io_uring.c | function parameter or call
| | | | io_ring_exit_work | io_uring/io_uring.c | function parameter or call
| | | | io_uring_try_cancel_iowq | io_uring/io_uring.c | reference
| | | | io_uring_try_cancel_iowq | io_uring/io_uring.c | function parameter or call
| | | | io_uring_try_cancel_iowq | io_uring/io_uring.c | function parameter or call
| | | | io_uring_try_cancel_iowq | io_uring/io_uring.c | function parameter or call
| | | | io_uring_try_cancel_iowq | io_uring/io_uring.c | function parameter or call
| | | | io_uring_cancel_generic | io_uring/io_uring.c | function parameter or call
| | | | io_uring_cancel_generic | io_uring/io_uring.c | function parameter or call
| | | | __io_register_iowq_aff | io_uring/register.c | function parameter or call
| | | | __io_register_iowq_aff | io_uring/register.c | function parameter or call
| | | | __io_register_iowq_aff | io_uring/register.c | function parameter or call
| | | | __io_register_iowq_aff | io_uring/register.c | function parameter or call
| | | | __io_uring_free | io_uring/tctx.c | function parameter or call
| | | | __io_uring_free | io_uring/tctx.c | function parameter or call
| | | | __io_uring_free | io_uring/tctx.c | function parameter or call
| | | | __io_uring_free | io_uring/tctx.c | function parameter or call
| | | | __io_uring_add_tctx_node | io_uring/tctx.c | function parameter or call
| | | | io_uring_clean_tctx | io_uring/tctx.c | declaration
| | | | io_uring_clean_tctx | io_uring/tctx.c | assignment or return
| | | | io_cancel_req_match | io_uring/cancel.c | function parameter or call
| | | | io_cancel_req_match | io_uring/cancel.c | function parameter or call
io_cb_cancel_data | io_uring/io-wq.c | work_cancel_fn *fn, void *data, int nr_running, int nr_pending, bool cancel_all |io_wq_dec_running | io_uring/io-wq.c | declaration
| | | | create_worker_cont | io_uring/io-wq.c | declaration
| | | | io_wq_enqueue | io_uring/io-wq.c | declaration
| | | | io_wq_hash_work | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_destroy | io_uring/io-wq.c | declaration
online_data | io_uring/io-wq.c | unsigned int cpu, bool online | io_wq_put_and_exit | io_uring/io-wq.c | declaration
| | | | io_wq_worker_affinity | io_uring/io-wq.c | declaration
| | | | __io_wq_cpu_online | io_uring/io-wq.c | declaration
io_wq_hash | io_uring/io-wq.h | refcount_t refs, unsigned long map, struct wait_queue_head wait |void | io_uring/io-wq.h | declaration
| | | | io_wq_put_hash | io_uring/io-wq.h | declaration
| | | | io_wq_put_hash | io_uring/io-wq.h | declaration
io_wq_data | io_uring/io-wq.h | struct io_wq_hash *hash, struct task_struct *task, io_wq_work_fn *do_work, free_work_fn *free_work | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_put_hash | io_uring/io-wq.h | declaration
| | | | io_wq_put_hash | io_uring/io-wq.h | declaration
io_buffer_list | io_uring/kbuf.h | /* 	 * If ->buf_nr_pages is set, then buf_pages/buf_ring are used. If not, 	 * then these are classic provided buffers and ->buf_list is used. 	 */ 	union { 		struct list_head buf_list, struct io_uring_buf_ring *buf_ring | io_kbuf_inc_commit | io_uring/kbuf.c | declaration
| | | | io_kbuf_inc_commit | io_uring/kbuf.c | declaration
| | | | io_kbuf_inc_commit | io_uring/kbuf.c | declaration
| | | | xa_load | io_uring/kbuf.c | declaration
| | | | io_kbuf_recycle_legacy | io_uring/kbuf.c | declaration
| | | | io_kbuf_recycle_legacy | io_uring/kbuf.c | declaration
| | | | u64_to_user_ptr | io_uring/kbuf.c | declaration
| | | | u64_to_user_ptr | io_uring/kbuf.c | declaration
| | | | u64_to_user_ptr | io_uring/kbuf.c | declaration
| | | | u64_to_user_ptr | io_uring/kbuf.c | declaration
| | | | u64_to_user_ptr | io_uring/kbuf.c | declaration
| | | | io_buffers_peek | io_uring/kbuf.c | declaration
| | | | __io_put_kbuf_ring | io_uring/kbuf.c | declaration
| | | | __io_put_kbufs | io_uring/kbuf.c | declaration
| | | | io_put_bl | io_uring/kbuf.c | declaration
| | | | io_destroy_buffers | io_uring/kbuf.c | declaration
| | | | io_destroy_bl | io_uring/kbuf.c | declaration
| | | | io_remove_buffers | io_uring/kbuf.c | declaration
| | | | io_provide_buffers_prep | io_uring/kbuf.c | declaration
| | | | io_provide_buffers | io_uring/kbuf.c | declaration
| | | | io_register_pbuf_ring | io_uring/kbuf.c | declaration
| | | | io_unregister_pbuf_ring | io_uring/kbuf.c | declaration
| | | | io_register_pbuf_status | io_uring/kbuf.c | declaration
| | | | io_register_pbuf_status | io_uring/kbuf.c | declaration
| | | | __io_put_kbufs | io_uring/kbuf.h | declaration
io_buffer | io_uring/kbuf.h | struct list_head list, __u64 addr, __u32 len, __u16 bid, __u16 bgid | io_kbuf_recycle_legacy | io_uring/kbuf.c | declaration
| | | | io_kbuf_recycle_legacy | io_uring/kbuf.c | declaration
| | | | io_kbuf_recycle_legacy | io_uring/kbuf.c | declaration
| | | | __io_put_kbufs | io_uring/kbuf.c | declaration
| | | | __io_put_kbufs | io_uring/kbuf.c | declaration
| | | | io_provide_buffers_prep | io_uring/kbuf.c | declaration
buf_sel_arg | io_uring/kbuf.h | struct iovec *iovs, size_t out_len, size_t max_len, unsigned short nr_iovs, unsigned short mode | u64_to_user_ptr | io_uring/kbuf.c | declaration
| | | | u64_to_user_ptr | io_uring/kbuf.c | declaration
| | | | io_buffers_peek | io_uring/kbuf.c | declaration
| | | | io_buffers_peek | io_uring/kbuf.h | declaration

If the following row value in a column is missing, assume the value is the same with the previous row in the same column. 
Continue until all data structures documented properly.
