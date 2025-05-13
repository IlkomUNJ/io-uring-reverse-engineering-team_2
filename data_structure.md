# Task 3: Data Structure Investigation
The objective of this task is to document all internal data structures defined in io_uring. 

Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_fadvise | io_uring/advise.c | struct file			*file, u64				offset, u64				len, u32				advice | io_fadvise | io_uring/advise.c | function call
 |  |  |  | io_fadvise_force_async | io_uring/advise.c | variable declaration
 |  |  |  | io_fadvise_prep | io_uring/advise.c | variable declaration
 |  |  |  | io_fadvise | io_uring/advise.h | function call
 |  |  |  | io_eopnotsupp_prep | io_uring/opdef.c | assignment or return
io_madvise | io_uring/advise.c | struct file			*file, u64				addr, u64				len, u32				advice | io_madvise | io_uring/advise.c | function call
 |  |  |  | io_madvise_prep | io_uring/advise.c | variable declaration
 |  |  |  | io_madvise | io_uring/advise.h | function call
 |  |  |  | io_eopnotsupp_prep | io_uring/opdef.c | assignment or return
io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | io_async_cancel | io_uring/cancel.c | variable declaration
 |  |  |  | io_async_cancel_prep | io_uring/cancel.c | variable declaration
io_cancel_data | io_uring/cancel.h | struct io_ring_ctx *ctx, union { 		u64 data, struct file *file | __io_sync_cancel | io_uring/cancel.c | variable declaration
 |  |  |  | io_async_cancel | io_uring/cancel.c | declaration
 |  |  |  | io_async_cancel_one | io_uring/cancel.c | variable declaration
 |  |  |  | io_async_cancel_prep | io_uring/cancel.c | variable declaration
 |  |  |  | io_cancel_cb | io_uring/cancel.c | variable declaration
 |  |  |  | io_cancel_remove_all | io_uring/cancel.c | variable declaration
 |  |  |  | io_cancel_req_match | io_uring/cancel.c | variable declaration
 |  |  |  | io_sync_cancel | io_uring/cancel.c | declaration
 |  |  |  | io_async_cancel | io_uring/cancel.h | variable declaration
 |  |  |  | io_cancel_remove_all | io_uring/cancel.h | variable declaration
 |  |  |  | io_cancel_req_match | io_uring/cancel.h | variable declaration
 |  |  |  | __io_futex_cancel | io_uring/futex.c | variable declaration
 |  |  |  | io_futex_cache_free | io_uring/futex.h | variable declaration
 |  |  |  | io_futex_wake | io_uring/futex.h | variable declaration
 |  |  |  | __io_poll_cancel | io_uring/poll.c | variable declaration
 |  |  |  | io_poll_remove | io_uring/poll.c | declaration
 |  |  |  | io_poll_remove_all | io_uring/poll.c | variable declaration
 |  |  |  | io_poll_remove | io_uring/poll.h | reference
 |  |  |  | io_req_task_link_timeout | io_uring/timeout.c | declaration
 |  |  |  | io_timeout_cancel | io_uring/timeout.c | variable declaration
 |  |  |  | io_timeout_fn | io_uring/timeout.c | variable declaration
 |  |  |  | io_timeout_remove | io_uring/timeout.c | declaration
 |  |  |  | io_timeout_update | io_uring/timeout.c | declaration
 |  |  |  | io_flush_timeouts | io_uring/timeout.h | reference
 |  |  |  | io_timeout_cancel | io_uring/timeout.h | variable declaration
 |  |  |  | __io_waitid_cancel | io_uring/waitid.c | variable declaration
 |  |  |  | io_waitid | io_uring/waitid.h | variable declaration
io_epoll | io_uring/epoll.c | struct file			*file, int				epfd, int				op, int				fd, struct epoll_event		event | io_epoll_ctl | io_uring/epoll.c | variable declaration
 |  |  |  | io_epoll_ctl_prep | io_uring/epoll.c | variable declaration
io_epoll_wait | io_uring/epoll.c | struct file			*file, int				maxevents, struct epoll_event __user	*events | io_epoll_wait | io_uring/epoll.c | function call
 |  |  |  | io_epoll_wait_prep | io_uring/epoll.c | variable declaration
 |  |  |  | io_epoll_wait | io_uring/epoll.h | function call
 |  |  |  | io_eopnotsupp_prep | io_uring/opdef.c | assignment or return
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
ext_arg | io_uring/io_uring.c | size_t argsz, struct timespec64 ts, const sigset_t __user *sig, ktime_t min_time, bool ts_set, bool iowait | READ_ONCE | io_uring/io_uring.c | declaration
| | | | READ_ONCE | io_uring/io_uring.c | declaration
| | | | READ_ONCE | io_uring/io_uring.c | function parameter or call
| | | | __io_cqring_wait_schedule | io_uring/io_uring.c | function parameter or call
| | | | __io_cqring_wait_schedule | io_uring/io_uring.c | declaration
| | | | __io_cqring_wait_schedule | io_uring/io_uring.c | assignment or return
| | | | __io_cqring_wait_schedule | io_uring/io_uring.c | reference
| | | | ERR_PTR | io_uring/io_uring.c | declaration
| | | | ERR_PTR | io_uring/io_uring.c | function parameter or call
| | | | PTR_ERR | io_uring/io_uring.c | assignment or return
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
| | | | __io_cqring_wait_schedule | io_uring/io_uring.c | declaration
| | | |  | io_uring/io_uring.h | declaration
| | | | io_should_wake | io_uring/io_uring.h | declaration
| | | | ktime_after | io_uring/napi.c | declaration
| | | | dynamic_tracking_do_busy_loop | io_uring/napi.c | declaration
| | | | __io_napi_busy_loop | io_uring/napi.c | declaration
| | | | io_napi | io_uring/napi.h | declaration
| | | | io_napi_add | io_uring/napi.h | declaration
io_worker | io_uring/io-wq.c | refcount_t ref, unsigned long flags, struct hlist_nulls_node nulls_node, struct list_head all_list, struct task_struct *task, struct io_wq *wq, struct io_wq_acct *acct, struct io_wq_work *cur_work, raw_spinlock_t lock, struct completion ref_done, unsigned long create_state, struct callback_head create_work, int init_retries, union { 		struct rcu_head rcu, struct delayed_work work | io_wq_dec_running | io_uring/io-wq.c | declaration
| | | | io_worker_get | io_uring/io-wq.c | declaration
| | | | io_worker_release | io_uring/io-wq.c | declaration
| | | | io_get_acct | io_uring/io-wq.c | declaration
| | | | io_wq_worker_stopped | io_uring/io-wq.c | declaration
| | | | io_worker_cancel_cb | io_uring/io-wq.c | declaration
| | | | io_task_worker_match | io_uring/io-wq.c | declaration
| | | | io_worker_exit | io_uring/io-wq.c | declaration
| | | | io_acct_activate_free_worker | io_uring/io-wq.c | declaration
| | | | io_wq_inc_running | io_uring/io-wq.c | declaration
| | | | create_worker_cb | io_uring/io-wq.c | declaration
| | | | io_wq_dec_running | io_uring/io-wq.c | declaration
| | | | __io_worker_busy | io_uring/io-wq.c | declaration
| | | | __io_worker_idle | io_uring/io-wq.c | declaration
| | | | io_wait_on_hash | io_uring/io-wq.c | declaration
| | | | io_wq_worker | io_uring/io-wq.c | declaration
| | | | io_wq_worker_running | io_uring/io-wq.c | declaration
| | | | io_wq_worker_sleeping | io_uring/io-wq.c | declaration
| | | | io_should_retry_thread | io_uring/io-wq.c | declaration
| | | | queue_create_worker_retry | io_uring/io-wq.c | declaration
| | | | create_worker_cont | io_uring/io-wq.c | declaration
| | | | io_workqueue_create | io_uring/io-wq.c | declaration
| | | | create_io_worker | io_uring/io-wq.c | declaration
| | | | io_wq_worker_wake | io_uring/io-wq.c | declaration
| | | | io_wq_hash_work | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_task_work_match | io_uring/io-wq.c | declaration
| | | | io_wq_cancel_tw_create | io_uring/io-wq.c | declaration
| | | | io_wq_worker_affinity | io_uring/io-wq.c | declaration
io_wq_acct | io_uring/io-wq.c | struct list_head all_list, raw_spinlock_t lock, struct io_wq_work_list work_list, unsigned long flags | create_io_worker | io_uring/io-wq.c | declaration
| | | | io_wq_dec_running | io_uring/io-wq.c | declaration
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
| | | | __io_worker_busy | io_uring/io-wq.c | declaration
| | | | __io_worker_idle | io_uring/io-wq.c | declaration
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
| | | | ERR_PTR | io_uring/io-wq.c | declaration
| | | | io_wq_max_workers | io_uring/io-wq.c | declaration
io_wq | io_uring/io-wq.c | unsigned long state, free_work_fn *free_work, io_wq_work_fn *do_work, struct io_wq_hash *hash, atomic_t worker_refs, struct completion worker_done, struct hlist_node cpuhp_node, struct task_struct *task, struct io_wq_acct acct[IO_WQ_ACCT_NR], struct wait_queue_entry wait, struct io_wq_work *hash_tail[IO_WQ_NR_HASH_BUCKETS], cpumask_var_t cpu_mask |create_io_worker | io_uring/io-wq.c | declaration
| | | | io_wq_dec_running | io_uring/io-wq.c | declaration
| | | | io_wq_cancel_tw_create | io_uring/io-wq.c | declaration
| | | | io_worker_release | io_uring/io-wq.c | declaration
| | | | io_worker_ref_put | io_uring/io-wq.c | declaration
| | | | io_worker_cancel_cb | io_uring/io-wq.c | declaration
| | | | io_worker_exit | io_uring/io-wq.c | declaration
| | | | io_wq_create_worker | io_uring/io-wq.c | declaration
| | | | io_wq_create_worker | io_uring/io-wq.c | reference
| | | | create_worker_cb | io_uring/io-wq.c | declaration
| | | | io_wq_dec_running | io_uring/io-wq.c | declaration
| | | | io_wait_on_hash | io_uring/io-wq.c | declaration
| | | | io_wq_worker | io_uring/io-wq.c | declaration
| | | | io_wq_worker_sleeping | io_uring/io-wq.c | declaration
| | | | create_worker_cont | io_uring/io-wq.c | declaration
| | | | create_io_worker | io_uring/io-wq.c | declaration
| | | | io_run_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_enqueue | io_uring/io-wq.c | declaration
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
| | | | io_wq_max_workers | io_uring/io-wq.c | declaration
| | | |  | io_uring/io-wq.h | declaration
| | | | io_wq_put_hash | io_uring/io-wq.h | declaration
| | | | io_wq_exit_start | io_uring/io-wq.h | declaration
| | | | io_wq_put_and_exit | io_uring/io-wq.h | declaration
| | | | io_wq_enqueue | io_uring/io-wq.h | declaration
| | | | io_wq_max_workers | io_uring/io-wq.h | declaration
| | | | bool | io_uring/io-wq.h | declaration
| | | | io_queue_iowq | io_uring/io_uring.c | function parameter or call
| | | | io_ring_exit_work | io_uring/io_uring.c | function parameter or call
| | | | io_uring_try_cancel_iowq | io_uring/io_uring.c | reference
| | | | io_uring_cancel_generic | io_uring/io_uring.c | function parameter or call
| | | | __io_register_iowq_aff | io_uring/register.c | function parameter or call
| | | | __io_uring_free | io_uring/tctx.c | function parameter or call
| | | | __io_uring_add_tctx_node | io_uring/tctx.c | function parameter or call
| | | | io_uring_clean_tctx | io_uring/tctx.c | declaration
| | | | io_uring_clean_tctx | io_uring/tctx.c | assignment or return
| | | | io_cancel_req_match | io_uring/cancel.c | function parameter or call
io_cb_cancel_data | io_uring/io-wq.c | work_cancel_fn *fn, void *data, int nr_running, int nr_pending, bool cancel_all |io_wq_dec_running | io_uring/io-wq.c | declaration
| | | | create_worker_cont | io_uring/io-wq.c | declaration
| | | | io_wq_enqueue | io_uring/io-wq.c | declaration
| | | | io_wq_hash_work | io_uring/io-wq.c | declaration
| | | | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_destroy | io_uring/io-wq.c | declaration
online_data | io_uring/io-wq.c | unsigned int cpu, bool online | io_wq_put_and_exit | io_uring/io-wq.c | declaration
| | | | io_wq_worker_affinity | io_uring/io-wq.c | declaration
| | | | __io_wq_cpu_online | io_uring/io-wq.c | declaration
io_wq_hash | io_uring/io-wq.h | refcount_t refs, unsigned long map, struct wait_queue_head wait |void | io_uring/io-wq.h | declaration
| | | | io_wq_put_hash | io_uring/io-wq.h | declaration
io_wq_data | io_uring/io-wq.h | struct io_wq_hash *hash, struct task_struct *task, io_wq_work_fn *do_work, free_work_fn *free_work | io_wq_worker_cancel | io_uring/io-wq.c | declaration
| | | | io_wq_put_hash | io_uring/io-wq.h | declaration
io_buffer_list | io_uring/kbuf.h | 	union { 		struct list_head buf_list, struct io_uring_buf_ring *buf_ring | io_kbuf_inc_commit | io_uring/kbuf.c | declaration
| | | | io_kbuf_inc_commit | io_uring/kbuf.c | declaration
| | | | xa_load | io_uring/kbuf.c | declaration
| | | | io_kbuf_recycle_legacy | io_uring/kbuf.c | declaration
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
| | | | __io_put_kbufs | io_uring/kbuf.h | declaration
io_buffer | io_uring/kbuf.h | struct list_head list, __u64 addr, __u32 len, __u16 bid, __u16 bgid | io_kbuf_recycle_legacy | io_uring/kbuf.c | declaration
| | | | io_kbuf_recycle_legacy | io_uring/kbuf.c | declaration
| | | | __io_put_kbufs | io_uring/kbuf.c | declaration
| | | | __io_put_kbufs | io_uring/kbuf.c | declaration
| | | | io_provide_buffers_prep | io_uring/kbuf.c | declaration
buf_sel_arg | io_uring/kbuf.h | struct iovec *iovs, size_t out_len, size_t max_len, unsigned short nr_iovs, unsigned short mode | u64_to_user_ptr | io_uring/kbuf.c | declaration
| | | | u64_to_user_ptr | io_uring/kbuf.c | declaration
| | | | io_buffers_peek | io_uring/kbuf.c | declaration
| | | | io_buffers_peek | io_uring/kbuf.h | declaration
io_msg | io_uring/msg_ring.c | struct file			*file, struct file			*src_file, struct callback_head		tw, u64 user_data, u32 len, u32 cmd, u32 src_fd, union { 		u32 dst_fd, u32 cqe_flags |io_msg_ring_cleanup | io_uring/msg_ring.c | declaration
| | | | kmem_cache_alloc | io_uring/msg_ring.c | declaration
| | | | io_msg_ring_data | io_uring/msg_ring.c | declaration
| | | | io_msg_grab_file | io_uring/msg_ring.c | declaration
| | | | io_msg_install_complete | io_uring/msg_ring.c | declaration
| | | | io_msg_tw_fd_complete | io_uring/msg_ring.c | declaration
| | | | io_msg_fd_remote | io_uring/msg_ring.c | declaration
| | | | io_msg_send_fd | io_uring/msg_ring.c | declaration
| | | | __io_msg_ring_prep | io_uring/msg_ring.c | declaration
| | | | io_msg_ring | io_uring/msg_ring.c | declaration
| | | | io_uring_sync_msg_ring | io_uring/msg_ring.c | declaration
| | | | io_uring_sync_msg_ring | io_uring/msg_ring.c | function parameter or call
| | | | __io_msg_ring_data | io_uring/msg_ring.c | reference
io_napi_entry | io_uring/napi.c | unsigned int		napi_id, struct list_head	list, unsigned long		timeout, struct hlist_node	node, struct rcu_head		rcu | __io_napi_add_id | io_uring/napi.c | declaration
| | | | __io_napi_del_id | io_uring/napi.c | declaration
| | | | __io_napi_remove_stale | io_uring/napi.c | declaration
| | | | ktime_after | io_uring/napi.c | declaration
| | | | io_napi_free | io_uring/napi.c | declaration
io_shutdown | io_uring/net.c | struct file			*file, int				how | io_shutdown_prep | io_uring/net.c | declaration
| | | | io_shutdown | io_uring/net.c | declaration
| | | | io_shutdown | io_uring/net.h | declaration
| | | | io_no_issue | io_uring/opdef.c | assignment or return
io_accept | io_uring/net.c | struct file			*file, struct sockaddr __user		*addr, int __user			*addr_len, int				flags, int				iou_flags, u32				file_slot, unsigned long			nofile |  io_accept_prep | io_uring/net.c | declaration
| | | | io_accept | io_uring/net.c | declaration
| | | | io_accept | io_uring/net.h | declaration
| | | | io_no_issue | io_uring/opdef.c | assignment or return
io_socket | io_uring/net.c | struct file			*file, int				domain, int				type, int				protocol, int				flags, u32				file_slot, unsigned long			nofile |  io_socket_prep | io_uring/net.c | declaration
| | | | io_socket | io_uring/net.c | declaration
| | | | io_socket | io_uring/net.h | declaration
| | | | io_no_issue | io_uring/opdef.c | assignment or return
io_connect | io_uring/net.c | struct file			*file, struct sockaddr __user		*addr, int				addr_len, bool				in_progress, bool				seen_econnaborted | io_connect_prep | io_uring/net.c | declaration
| | | | io_connect | io_uring/net.c | declaration
| | | | io_connect | io_uring/net.h | declaration
| | | | io_no_issue | io_uring/opdef.c | assignment or return
io_bind | io_uring/net.c | struct file			*file, int				addr_len |  io_bind_prep | io_uring/net.c | declaration
| | | | io_bind | io_uring/net.c | declaration
| | | | io_bind | io_uring/net.h | declaration
| | | | io_no_issue | io_uring/opdef.c | assignment or return
io_listen | io_uring/net.c | struct file			*file, int				backlog | io_listen_prep | io_uring/net.c | declaration
| | | | io_listen | io_uring/net.c | declaration
| | | | io_listen | io_uring/net.h | declaration
| | | | io_no_issue | io_uring/opdef.c | assignment or return
io_sr_msg | io_uring/net.c | struct file			*file, union { 		struct compat_msghdr __user	*umsg_compat, struct user_msghdr __user	*umsg, void __user			*buf |   io_netmsg_recycle | io_uring/net.c | declaration
| | | | io_send_setup | io_uring/net.c | declaration
| | | | io_sendmsg_setup | io_uring/net.c | declaration
| | | | io_sendmsg_prep | io_uring/net.c | declaration
| | | | iter_iov | io_uring/net.c | declaration
| | | | io_sendmsg | io_uring/net.c | declaration
| | | | io_send | io_uring/net.c | declaration
| | | | io_recvmsg_prep_setup | io_uring/net.c | declaration
| | | | io_recvmsg_prep | io_uring/net.c | declaration
| | | | io_recvmsg | io_uring/net.c | declaration
| | | | io_recv | io_uring/net.c | declaration
| | | | io_send_zc_cleanup | io_uring/net.c | declaration
| | | | io_send_zc_prep | io_uring/net.c | declaration
| | | | io_send_zc_import | io_uring/net.c | declaration
| | | | io_send_zc | io_uring/net.c | declaration
| | | | io_sendmsg_zc | io_uring/net.c | declaration
| | | | io_sendrecv_fail | io_uring/net.c | declaration
io_recvzc | io_uring/net.c | struct file			*file, unsigned			msg_flags, u16				flags, u32				len, struct io_zcrx_ifq		*ifq | io_recvzc_prep | io_uring/net.c | declaration
| | | | io_recvzc | io_uring/net.c | declaration
| | | | io_no_issue | io_uring/opdef.c | assignment or return
| | | | io_recvzc | io_uring/zcrx.h | declaration
io_recvmsg_multishot_hdr | io_uring/net.c | struct io_uring_recvmsg_out msg, struct sockaddr_storage addr | io_recvmsg_prep_setup | io_uring/net.c | declaration
io_async_msghdr | io_uring/net.h |	struct iou_vec				vec, struct_group(clear, 		int				namelen, struct iovec			fast_iov, __kernel_size_t			controllen, __kernel_size_t			payloadlen, struct sockaddr __user		*uaddr, struct msghdr			msg, struct sockaddr_storage		addr, ) | io_free_alloc_caches | io_uring/io_uring.c | declaration
| | | | io_free_alloc_caches | io_uring/io_uring.c | declaration
| | | | io_netmsg_iovec_free | io_uring/net.c | declaration
| | | | io_netmsg_recycle | io_uring/net.c | declaration
| | | | io_sendmsg_recvmsg_cleanup | io_uring/net.c | declaration
| | | | io_send_setup | io_uring/net.c | declaration
| | | | io_sendmsg_setup | io_uring/net.c | declaration
| | | | io_bundle_nbufs | io_uring/net.c | declaration
| | | | iter_iov | io_uring/net.c | declaration
| | | | io_sendmsg | io_uring/net.c | declaration
| | | | io_send | io_uring/net.c | declaration
| | | | io_recvmsg_prep_setup | io_uring/net.c | declaration
| | | | io_recvmsg | io_uring/net.c | declaration
| | | | io_recv | io_uring/net.c | declaration
| | | | io_send_zc_cleanup | io_uring/net.c | declaration
| | | | io_send_zc_prep | io_uring/net.c | declaration
| | | | io_send_zc_import | io_uring/net.c | declaration
| | | | io_send_zc | io_uring/net.c | declaration
| | | | io_sendmsg_zc | io_uring/net.c | declaration
| | | | io_connect_prep | io_uring/net.c | declaration
| | | | io_connect | io_uring/net.c | declaration
| | | | io_bind_prep | io_uring/net.c | declaration
| | | | io_bind | io_uring/net.c | declaration
| | | | io_netmsg_cache_free | io_uring/net.c | declaration
| | | | io_no_issue | io_uring/opdef.c | declaration
io_nop | io_uring/nop.c | 	struct file     *file, int             result, int		fd, unsigned int	flags | io_nop_prep | io_uring/nop.c | declaration
| | | | io_nop | io_uring/nop.c | declaration
| | | | io_nop | io_uring/nop.h | declaration
| | | | io_no_issue | io_uring/opdef.c | assignment or return
io_notif_data | io_uring/notif.h | struct file		*file, struct ubuf_info	uarg, struct io_notif_data	*next, struct io_notif_data	*head, unsigned		account_pages, bool			zc_report, bool			zc_used, bool			zc_copied | io_send_zc_prep | io_uring/net.c | declaration
| | | | io_notif_tw_complete | io_uring/notif.c | declaration
| | | | io_link_skb | io_uring/notif.c | declaration
| | | | io_kiocb_to_cmd | io_uring/notif.h | declaration
| | | | io_notif_flush | io_uring/notif.h | declaration
| | | | io_notif_account_mem | io_uring/notif.h | declaration
io_issue_def | io_uring/opdef.h | 	unsigned short		async_size, int (*issue)(struct io_kiocb *, unsigned int), int (*prep)(struct io_kiocb *, const struct io_uring_sqe *) | io_prep_async_work | io_uring/io_uring.c | declaration
| | | | io_drain_req | io_uring/io_uring.c | declaration
| | | | io_issue_sqe | io_uring/io_uring.c | declaration
| | | | io_wq_submit_work | io_uring/io_uring.c | declaration
| | | | io_init_fail_req | io_uring/io_uring.c | declaration
| | | | io_req_set_res | io_uring/io_uring.h | declaration
| | | | io_no_issue | io_uring/opdef.c | declaration
| | | | io_arm_poll_handler | io_uring/poll.c | declaration
| | | | io_iov_compat_buffer_select_prep | io_uring/rw.c | declaration
io_cold_def | io_uring/opdef.h | const char		*name, void (*cleanup)(struct io_kiocb *), void (*fail)(struct io_kiocb *) | io_clean_op | io_uring/io_uring.c | declaration
| | | | io_req_defer_failed | io_uring/io_uring.c | declaration
io_open | io_uring/openclose.c | struct file			*file, int				dfd, u32				file_slot, struct filename			*filename, struct open_how			how, unsigned long			nofile | io_openat_force_async | io_uring/openclose.c | declaration
| | | | __io_openat_prep | io_uring/openclose.c | declaration
| | | | io_openat_prep | io_uring/openclose.c | declaration
| | | | io_openat2_prep | io_uring/openclose.c | declaration
| | | | io_openat2 | io_uring/openclose.c | declaration
| | | | io_open_cleanup | io_uring/openclose.c | declaration
io_close | io_uring/openclose.c | struct file			*file, int				fd, u32				file_slot | io_no_issue | io_uring/opdef.c | assignment or return
| | | | io_close_fixed | io_uring/openclose.c | declaration
| | | | io_close_prep | io_uring/openclose.c | declaration
| | | | io_close | io_uring/openclose.c | declaration
| | | | io_close | io_uring/openclose.h | declaration
io_fixed_install | io_uring/openclose.c | struct file			*file, unsigned int			o_flags | io_install_fixed_fd_prep | io_uring/openclose.c | declaration
| | | | io_install_fixed_fd | io_uring/openclose.c | declaration
io_poll_update | io_uring/poll.c | struct file			*file, u64				old_user_data, u64				new_user_data, __poll_t			events, bool				update_events, bool				update_user_data | io_poll_remove_prep | io_uring/poll.c | declaration
| | | | io_poll_remove | io_uring/poll.c | declaration
io_poll_table | io_uring/poll.c | struct poll_table_struct pt, struct io_kiocb output value	__poll_t result_mask |  io_poll_double_prepare | io_uring/poll.c | declaration
| | | | io_poll_add_hash | io_uring/poll.c | declaration
| | | | io_arm_poll_handler | io_uring/poll.c | declaration
| | | | io_poll_add | io_uring/poll.c | declaration
io_poll | io_uring/poll.h | struct file			*file, struct wait_queue_head		*head, __poll_t			events, int				retries, struct wait_queue_entry		wait | io_poll_mark_cancelled | io_uring/poll.c | declaration
| | | | io_poll_mark_cancelled | io_uring/poll.c | declaration
| | | | io_kiocb_to_cmd | io_uring/poll.c | declaration
| | | | io_init_poll_iocb | io_uring/poll.c | declaration
| | | | io_poll_remove_entry | io_uring/poll.c | declaration
| | | | io_poll_task_func | io_uring/poll.c | declaration
| | | | io_pollfree_wake | io_uring/poll.c | declaration
| | | | io_poll_double_prepare | io_uring/poll.c | function parameter or call
| | | | io_poll_double_prepare | io_uring/poll.c | declaration
| | | | io_poll_add_hash | io_uring/poll.c | declaration
| | | | io_poll_add_prep | io_uring/poll.c | declaration
| | | | io_poll_add | io_uring/poll.c | declaration
| | | | io_poll_remove | io_uring/poll.c | declaration
async_poll | io_uring/poll.h | struct io_poll		poll, struct io_poll		*double_poll | io_free_alloc_caches | io_uring/io_uring.c | declaration
| | | | io_queue_next | io_uring/io_uring.c | declaration
| | | | io_poll_add_hash | io_uring/poll.c | declaration
| | | | io_arm_poll_handler | io_uring/poll.c | declaration
io_ring_ctx_rings | io_uring/register.c | struct io_rings *rings, struct io_uring_sqe *sq_sqes, struct io_mapped_region sq_region, struct io_mapped_region ring_region | __io_register_iowq_aff | io_uring/register.c | declaration
| | | | __io_register_iowq_aff | io_uring/register.c | declaration
| | | | io_register_resize_rings | io_uring/register.c | declaration
io_rsrc_update | io_uring/rsrc.c | struct file			*file, u64				arg, u32				nr_args, u32				offset |   io_files_update_prep | io_uring/rsrc.c | declaration
| | | | io_files_update_prep | io_uring/rsrc.c | declaration
| | | | io_files_update | io_uring/rsrc.c | declaration
io_rsrc_node | io_uring/rsrc.h | unsigned char			type, int				refs, u64 tag, union { 		unsigned long file_ptr, struct io_mapped_ubuf *buf | io_free_file_tables | io_uring/filetable.c | declaration
| | | | io_fixed_fd_remove | io_uring/filetable.c | declaration
| | | | io_slot_flags | io_uring/filetable.h | declaration
| | | | io_wq_submit_work | io_uring/io_uring.c | declaration
| | | | io_msg_grab_file | io_uring/msg_ring.c | declaration
| | | | io_buffer_unmap | io_uring/rsrc.c | declaration
| | | | io_rsrc_cache_init | io_uring/rsrc.c | declaration
| | | | io_rsrc_data_alloc | io_uring/rsrc.c | declaration
| | | | io_free_rsrc_node | io_uring/rsrc.c | declaration
| | | | io_sqe_files_unregister | io_uring/rsrc.c | declaration
| | | | io_sqe_buffers_unregister | io_uring/rsrc.c | declaration
| | | | ERR_PTR | io_uring/rsrc.c | declaration
| | | | io_vec_realloc | io_uring/rsrc.c | declaration
| | | | io_rsrc_cache_free | io_uring/rsrc.h | declaration
| | | | io_free_rsrc_node | io_uring/rsrc.h | declaration
| | | | io_rsrc_data_alloc | io_uring/rsrc.h | declaration
| | | | io_buffer_validate | io_uring/rsrc.h | declaration
| | | | io_put_rsrc_node | io_uring/rsrc.h | declaration
| | | | io_req_put_rsrc_nodes | io_uring/rsrc.h | declaration
| | | | io_splice_cleanup | io_uring/splice.c | declaration
| | | | io_async_cancel | io_uring/cancel.c | declaration
io_mapped_ubuf | io_uring/rsrc.h | u64		ubuf, unsigned int	len, unsigned int	nr_bvecs, unsigned int    folio_shift, refcount_t	refs, unsigned long	acct_pages, void		(*release)(void *), void		*priv, bool		is_kbuf, u8		dir, struct bio_vec	bvec[] __counted_by(nr_bvecs) | io_uring_show_fdinfo | io_uring/fdinfo.c | declaration
| | | | io_release_ubuf | io_uring/rsrc.c | declaration
| | | | kvmalloc | io_uring/rsrc.c | declaration
| | | | io_free_imu | io_uring/rsrc.c | declaration
| | | | io_buffer_unmap | io_uring/rsrc.c | declaration
| | | | io_rsrc_cache_init | io_uring/rsrc.c | declaration
| | | | io_sqe_buffers_unregister | io_uring/rsrc.c | declaration
| | | | ERR_PTR | io_uring/rsrc.c | declaration
| | | | io_vec_realloc | io_uring/rsrc.c | declaration
io_imu_folio_data | io_uring/rsrc.h | 	unsigned int	nr_pages_mid, unsigned int	folio_shift, unsigned int	nr_folios | io_region_init_ptr | io_uring/memmap.c | declaration
| | | | io_sqe_buffers_unregister | io_uring/rsrc.c | declaration
| | | | io_buffer_validate | io_uring/rsrc.h | declaration
io_rw | io_uring/rw.c |  	struct kiocb			kiocb, u64				addr, u32				len, rwf_t				flags | io_complete_rw_iopoll | io_uring/rw.c | declaration
| | | | io_iov_compat_buffer_select_prep | io_uring/rw.c | declaration
| | | | io_iov_buffer_select_prep | io_uring/rw.c | declaration
| | | | io_iov_compat_buffer_select_prep | io_uring/rw.c | declaration
| | | | io_meta_restore | io_uring/rw.c | declaration
| | | | io_prep_rwv | io_uring/rw.c | declaration
| | | | __io_prep_rw | io_uring/rw.c | declaration
| | | | io_rw_prep_reg_vec | io_uring/rw.c | declaration
| | | | io_read_mshot_prep | io_uring/rw.c | declaration
| | | | io_readv_writev_cleanup | io_uring/rw.c | declaration
| | | | io_rw_should_reissue | io_uring/rw.c | declaration
| | | | io_req_end_write | io_uring/rw.c | declaration
| | | | io_req_io_end | io_uring/rw.c | declaration
| | | | io_req_rw_complete | io_uring/rw.c | declaration
| | | | io_complete_rw | io_uring/rw.c | declaration
| | | | io_complete_rw_iopoll | io_uring/rw.c | declaration
| | | | io_rw_done | io_uring/rw.c | declaration
| | | | loop_rw_iter | io_uring/rw.c | declaration
| | | | io_rw_should_retry | io_uring/rw.c | declaration
| | | | io_iter_do_read | io_uring/rw.c | declaration
| | | | io_rw_init_file | io_uring/rw.c | declaration
| | | | __io_read | io_uring/rw.c | declaration
| | | | io_read_mshot | io_uring/rw.c | declaration
| | | | io_write | io_uring/rw.c | declaration
| | | | io_rw_fail | io_uring/rw.c | declaration
io_meta_state | io_uring/rw.h | u32			seed, struct iov_iter_state	iter_meta | - | -| -
io_async_rw | io_uring/rw.h | struct iou_vec			vec, size_t				bytes_done, struct_group(clear, 		struct iov_iter			iter, struct iov_iter_state		iter_state, struct iovec			fast_iov, 		union { 			struct wait_page_queue		wpq, struct { 				struct uio_meta			meta, struct io_meta_state		meta_state | io_free_alloc_caches | io_uring/io_uring.c | declaration
| | | | io_no_issue | io_uring/opdef.c | declaration
| | | | io_iov_compat_buffer_select_prep | io_uring/rw.c | declaration
| | | | io_iov_compat_buffer_select_prep | io_uring/rw.c | declaration
| | | | import_ubuf | io_uring/rw.c | declaration
| | | | io_rw_recycle | io_uring/rw.c | declaration
| | | | io_rw_alloc_async | io_uring/rw.c | declaration
| | | | io_meta_save_state | io_uring/rw.c | declaration
| | | | io_meta_restore | io_uring/rw.c | declaration
| | | | io_prep_rwv | io_uring/rw.c | declaration
| | | | __io_prep_rw | io_uring/rw.c | declaration
| | | | io_rw_prep_reg_vec | io_uring/rw.c | declaration
| | | | io_rw_should_reissue | io_uring/rw.c | declaration
| | | | io_fixup_rw_res | io_uring/rw.c | declaration
| | | | io_rw_should_retry | io_uring/rw.c | declaration
| | | | io_rw_init_file | io_uring/rw.c | declaration
| | | | io_rw_init_file | io_uring/rw.c | reference
| | | | __io_read | io_uring/rw.c | declaration
| | | | io_write | io_uring/rw.c | declaration
| | | | io_rw_cache_free | io_uring/rw.c | declaration
| `io_wq_work_node | `linux/io_uring_types.h | `struct io_wq_work_node *next         | `wq_list_add_after     | `io_uring/io_slist.h | parameter               |
|                   |                          |                                        | `wq_list_add_tail      | `io_uring/io_slist.h | parameter               |
|                   |                          |                                        | `wq_list_add_head      | `io_uring/io_slist.h | parameter               |
|                   |                          |                                        | `wq_list_cut           | `io_uring/io_slist.h | parameter, local var    |
|                   |                          |                                        | `wq_stack_add_head     | `io_uring/io_slist.h | parameter               |
|                   |                          |                                        | `wq_list_del          | `io_uring/io_slist.h | parameter               |
|                   |                          |                                        | `wq_stack_extract      | `io_uring/io_slist.h | return value            |
| `io_wq_work_list | `linux/io_uring_types.h | `struct io_wq_work_node *first, *last | `wq_list_add_tail      | `io_uring/io_slist.h | parameter, local var    |
|                   |                          |                                        | `wq_list_add_head      | `io_uring/io_slist.h | parameter               |
|                   |                          |                                        | `wq_list_add_after     | `io_uring/io_slist.h | parameter               |
|                   |                          |                                        | `wq_list_cut           | `io_uring/io_slist.h | parameter               |
|                   |                          |                                        | `__wq_list_splice      | `io_uring/io_slist.h | parameter               |
|                   |                          |                                        | `wq_list_splice        | `io_uring/io_slist.h | parameter               |
|                   |                          |                                        | `wq_list_del           | `io_uring/io_slist.h | parameter               |
| `io_wq_work      | `linux/io_uring_types.h | `struct io_wq_work_node list          | `wq_next_work          | `io_uring/io_slist.h | parameter, return value |
| `io_splice    | io_uring/splice.c | struct file *file_out, loff_t off_out, loff_t off_in, u64 len, int splice_fd_in, unsigned int flags, struct io_rsrc_node *rsrc_node | `__io_splice_prep      | `io_uring/splice.c | Local variable via `io_kiocb_to_cmd() |
|                |                     |                                                                                                                                                   | `io_tee_prep           | `io_uring/splice.c | Local variable via `io_kiocb_to_cmd() |
|                |                     |                                                                                                                                                   | `io_splice_prep        | `io_uring/splice.c | Local variable via `io_kiocb_to_cmd() |
|                |                     |                                                                                                                                                   | `io_tee                | `io_uring/splice.c | Local variable via `io_kiocb_to_cmd() |
|                |                     |                                                                                                                                                   | `io_splice            | `io_uring/splice.c | Local variable via `io_kiocb_to_cmd() |
|                |                     |                                                                                                                                                   | `io_splice_cleanup     | `io_uring/splice.c | Local variable via `io_kiocb_to_cmd() |
|                |                     |                                                                                                                                                   | io_splice_get_file    | io_uring/splice.c | Local variable via io_kiocb_to_cmd() |
io_tee         | io_uring/splice.h | struct io_kiocb *req, const struct io_uring_sqe *sqe | io_tee_prep           | io_uring/splice.c   | function definition
|               |                |                                                | io_tee                | io_uring/splice.c   | function definition
io_splice      | io_uring/splice.h | struct io_kiocb *req, const struct io_uring_sqe *sqe | io_splice_prep        | io_uring/splice.c   | function definition
|               |                |                                                | io_splice             | io_uring/splice.c   | function definition
|               |                |                                                | io_splice_cleanup     | io_uring/splice.c   | function definition
io_sq_data       | io_uring/sqpoll.c | task_struct, refcount_t, atomic_t, mutex, wait_queue_head_t, completion, list_head, unsigned long, int, pid_t | io_sq_thread_unpark | io_uring/sqpoll.c | function parameter
| | | | io_sq_thread_park | io_uring/sqpoll.c | function parameter
| | | | io_sq_thread_stop | io_uring/sqpoll.c | function parameter
| | | | io_put_sq_data | io_uring/sqpoll.c | function parameter
| | | | io_sqd_update_thread_idle | io_uring/sqpoll.c | local variable
| | | | io_sq_thread_finish | io_uring/sqpoll.c | local variable
| | | | io_attach_sq_data | io_uring/sqpoll.c | return value, local variable
| | | | io_get_sq_data | io_uring/sqpoll.c | return value, local variable
| | | | io_sqd_events_pending | io_uring/sqpoll.c | function parameter
| | | | io_sqd_handle_event | io_uring/sqpoll.c | function parameter
| | | | io_sq_thread | io_uring/sqpoll.c | function parameter
| | | | io_sq_offload_create | io_uring/sqpoll.c | local variable
| | | | io_sqpoll_wq_cpu_affinity | io_uring/sqpoll.c | local variable
io_sq_data       | io_uring/sqpoll.h | refcount_t, atomic_t, mutex, list_head, task_struct, wait_queue_head_t, unsigned, int, pid_t, u64, unsigned long, completion | io_sq_offload_create | io_uring/sqpoll.c | local variable (via function declaration)
| | | | io_sq_thread_finish | io_uring/sqpoll.c | local variable (via function declaration)
| | | | io_sq_thread_stop | io_uring/sqpoll.h | function parameter
| | | | io_sq_thread_park | io_uring/sqpoll.h | function parameter
| | | | io_sq_thread_unpark | io_uring/sqpoll.h | function parameter
| | | | io_put_sq_data | io_uring/sqpoll.h | function parameter
| | | | io_sqpoll_wait_sq | io_uring/sqpoll.c | local variable (via function declaration)
| | | | io_sqpoll_wq_cpu_affinity | io_uring/sqpoll.c | local variable (via function declaration)
io_statx         | io_uring/statx.c | file, int, unsigned int, unsigned int, filename, statx __user* | io_statx_prep | io_uring/statx.c | local variable
| | | | io_statx | io_uring/statx.c | local variable
| | | | io_statx_cleanup | io_uring/statx.c | local variable
io_statx         | io_uring/statx.h | (declaration only) | io_statx_prep | io_uring/statx.c | local variable (via function declaration)
| | | | io_statx | io_uring/statx.c | local variable (via function declaration)
| | | | io_statx_cleanup | io_uring/statx.c | local variable (via function declaration)
io_sync          | io_uring/sync.c | file, loff_t, loff_t, int, int | io_sfr_prep | io_uring/sync.c | local variable
| | | | io_sync_file_range | io_uring/sync.c | local variable
| | | | io_fsync_prep | io_uring/sync.c | local variable
| | | | io_fsync | io_uring/sync.c | local variable
| | | | io_fallocate_prep | io_uring/sync.c | local variable
| | | | io_fallocate | io_uring/sync.c | local variable
io_sync          | io_uring/sync.h | (declaration only) | io_sfr_prep | io_uring/sync.c | local variable (via function declaration)
| | | | io_sync_file_range | io_uring/sync.c | local variable (via function declaration)
| | | | io_fsync_prep | io_uring/sync.c | local variable (via function declaration)
| | | | io_fsync | io_uring/sync.c | local variable (via function declaration)
| | | | io_fallocate_prep | io_uring/sync.c | local variable (via function declaration)
| | | | io_fallocate | io_uring/sync.c | local variable (via function declaration)
io_uring_task    | io_uring/tctx.c | io_wq, xarray, wait_queue_head_t, atomic_t, llist_head, task_struct, percpu_counter, struct file*[], io_ring_ctx* | __io_uring_free | io_uring/tctx.c | local variable
| | | | io_uring_alloc_task_context | io_uring/tctx.c | local variable
| | | | __io_uring_add_tctx_node | io_uring/tctx.c | local variable
| | | | __io_uring_add_tctx_node_from_submit | io_uring/tctx.c | local variable
| | | | io_uring_del_tctx_node | io_uring/tctx.c | local variable
| | | | io_uring_clean_tctx | io_uring/tctx.c | function parameter
| | | | io_uring_unreg_ringfd | io_uring/tctx.c | local variable
| | | | io_ring_add_registered_file | io_uring/tctx.c | function parameter
| | | | io_ring_add_registered_fd | io_uring/tctx.c | local variable
| | | | io_ringfd_register | io_uring/tctx.c | local variable
| | | | io_ringfd_unregister | io_uring/tctx.c | local variable
io_tctx_node     | io_uring/tctx.c | io_ring_ctx, task_struct, list_head | __io_uring_add_tctx_node | io_uring/tctx.c | local variable
| | | | io_uring_del_tctx_node | io_uring/tctx.c | local variable
| | | | io_uring_clean_tctx | io_uring/tctx.c | local variable
io_wq_data       | io_uring/tctx.c | io_wq_hash, task_struct, work functions | io_init_wq_offload | io_uring/tctx.c | local variable
io_tctx_node     | io_uring/tctx.h | list_head, task_struct, io_ring_ctx | io_uring_add_tctx_node | io_uring/tctx.c | local variable (via function declarations)
| | | | io_uring_del_tctx_node | io_uring/tctx.h | local variable (via function declaration)
| | | | __io_uring_add_tctx_node | io_uring/tctx.h | local variable (via function declaration)
| | | | __io_uring_add_tctx_node_from_submit | io_uring/tctx.h | local variable (via function declaration)
| | | | io_uring_clean_tctx | io_uring/tctx.h | local variable (via function declaration)
io_uring_task    | io_uring/tctx.h | (declaration only) | io_uring_alloc_task_context | io_uring/tctx.c | local variable (via function declaration)
| | | | io_uring_clean_tctx | io_uring/tctx.h | function parameter
| | | | io_uring_add_tctx_node | io_uring/tctx.h | local variable
| | | | io_ringfd_register | io_uring/tctx.h | local variable (via function declaration)
| | | | io_ringfd_unregister | io_uring/tctx.h | local variable (via function declaration)
io_timeout | io_uring/timeout.c |  file			*file, u32				off, u32				target_seq, u32				repeats,  list_head		list, /* head of the link, used by linked timeouts only */ 	 io_kiocb			*head, /* for linked completions */ 	 io_kiocb			*prev | io_eopnotsupp_prep | io_uring/opdef.c | assignment or return
 |  |  |  | ERR_PTR | io_uring/timeout.c | function call
 |  |  |  | __io_timeout_prep | io_uring/timeout.c | variable declaration
 |  |  |  | io_disarm_next | io_uring/timeout.c | variable declaration
 |  |  |  | io_flush_killed_timeouts | io_uring/timeout.c | variable declaration
 |  |  |  | io_flush_timeouts | io_uring/timeout.c | variable declaration
 |  |  |  | io_is_timeout_noseq | io_uring/timeout.c | variable declaration
 |  |  |  | io_kill_timeout | io_uring/timeout.c | variable declaration
 |  |  |  | io_kill_timeouts | io_uring/timeout.c | variable declaration
 |  |  |  | io_link_timeout_fn | io_uring/timeout.c | variable declaration
 |  |  |  | io_linked_timeout_update | io_uring/timeout.c | variable declaration
 |  |  |  | io_put_req | io_uring/timeout.c | variable declaration
 |  |  |  | io_queue_linked_timeout | io_uring/timeout.c | variable declaration
 |  |  |  | io_req_task_link_timeout | io_uring/timeout.c | variable declaration
 |  |  |  | io_timeout | io_uring/timeout.c | function call
 |  |  |  | io_timeout_complete | io_uring/timeout.c | variable declaration
 |  |  |  | io_timeout_fn | io_uring/timeout.c | variable declaration
 |  |  |  | io_timeout_update | io_uring/timeout.c | variable declaration
 |  |  |  | io_timeout | io_uring/timeout.h | function call
io_timeout_rem | io_uring/timeout.c |  file			*file, u64				addr, /* timeout update */ 	 timespec64		ts, u32				flags, bool				ltimeout | io_timeout_remove | io_uring/timeout.c | variable declaration
 |  |  |  | io_timeout_remove_prep | io_uring/timeout.c | variable declaration
io_timeout_data | io_uring/timeout.h |  io_kiocb			*req,  hrtimer			timer,  timespec64		ts, enum hrtimer_mode		mode, u32				flags | io_eopnotsupp_prep | io_uring/opdef.c | function call
 |  |  |  | __io_timeout_prep | io_uring/timeout.c | variable declaration
 |  |  |  | io_disarm_next | io_uring/timeout.c | variable declaration
 |  |  |  | io_is_timeout_noseq | io_uring/timeout.c | variable declaration
 |  |  |  | io_kill_timeout | io_uring/timeout.c | variable declaration
 |  |  |  | io_link_timeout_fn | io_uring/timeout.c | variable declaration
 |  |  |  | io_linked_timeout_update | io_uring/timeout.c | variable declaration
 |  |  |  | io_queue_linked_timeout | io_uring/timeout.c | variable declaration
 |  |  |  | io_timeout | io_uring/timeout.c | variable declaration
 |  |  |  | io_timeout_complete | io_uring/timeout.c | variable declaration
 |  |  |  | io_timeout_finish | io_uring/timeout.c | variable declaration
 |  |  |  | io_timeout_fn | io_uring/timeout.c | variable declaration
 |  |  |  | io_timeout_get_clock | io_uring/timeout.c | variable declaration
 |  |  |  | io_timeout_update | io_uring/timeout.c | variable declaration
io_ftrunc | io_uring/truncate.c |  file			*file, loff_t				len | io_ftruncate | io_uring/truncate.c | variable declaration
 |  |  |  | io_ftruncate_prep | io_uring/truncate.c | variable declaration
io_async_cmd | io_uring/uring_cmd.h |  io_uring_cmd_data	data,  iou_vec			vec,  io_uring_sqe		sqes[2] | io_free_alloc_caches | io_uring/io_uring.c | function call
 |  |  |  | io_eopnotsupp_prep | io_uring/opdef.c | function call
 |  |  |  | io_cmd_cache_free | io_uring/uring_cmd.c | variable declaration
 |  |  |  | io_req_uring_cleanup | io_uring/uring_cmd.c | variable declaration
 |  |  |  | io_uring_cmd_import_fixed_vec | io_uring/uring_cmd.c | variable declaration
 |  |  |  | io_uring_cmd_prep_setup | io_uring/uring_cmd.c | variable declaration
io_waitid | io_uring/waitid.c |  file *file, int which, pid_t upid, int options, atomic_t refs,  wait_queue_head *head,  siginfo __user *infop,  waitid_info info | io_eopnotsupp_prep | io_uring/opdef.c | assignment or return
 |  |  |  | __io_waitid_cancel | io_uring/waitid.c | variable declaration
 |  |  |  | io_waitid | io_uring/waitid.c | function call
 |  |  |  | io_waitid_cb | io_uring/waitid.c | declaration
 |  |  |  | io_waitid_compat_copy_si | io_uring/waitid.c | variable declaration
 |  |  |  | io_waitid_complete | io_uring/waitid.c | variable declaration
 |  |  |  | io_waitid_copy_si | io_uring/waitid.c | variable declaration
 |  |  |  | io_waitid_drop_issue_ref | io_uring/waitid.c | variable declaration
 |  |  |  | io_waitid_prep | io_uring/waitid.c | variable declaration
 |  |  |  | io_waitid_wait | io_uring/waitid.c | variable declaration
 |  |  |  | io_waitid | io_uring/waitid.h | function call
io_waitid_async | io_uring/waitid.h |  io_kiocb *req,  wait_opts wo | io_eopnotsupp_prep | io_uring/opdef.c | function call
 |  |  |  | __io_waitid_cancel | io_uring/waitid.c | variable declaration
 |  |  |  | io_waitid | io_uring/waitid.c | variable declaration
 |  |  |  | io_waitid_cb | io_uring/waitid.c | variable declaration
 |  |  |  | io_waitid_drop_issue_ref | io_uring/waitid.c | variable declaration
 |  |  |  | io_waitid_free | io_uring/waitid.c | variable declaration
 |  |  |  | io_waitid_prep | io_uring/waitid.c | variable declaration
 |  |  |  | io_waitid_wait | io_uring/waitid.c | variable declaration
io_xattr | io_uring/xattr.c |  file			*file,  kernel_xattr_ctx		ctx,  filename			*filename | __io_getxattr_prep | io_uring/xattr.c | variable declaration
 |  |  |  | __io_setxattr_prep | io_uring/xattr.c | variable declaration
 |  |  |  | io_fgetxattr | io_uring/xattr.c | variable declaration
 |  |  |  | io_fsetxattr | io_uring/xattr.c | variable declaration
 |  |  |  | io_getxattr | io_uring/xattr.c | variable declaration
 |  |  |  | io_getxattr_prep | io_uring/xattr.c | variable declaration
 |  |  |  | io_setxattr | io_uring/xattr.c | variable declaration
 |  |  |  | io_setxattr_prep | io_uring/xattr.c | variable declaration
 |  |  |  | io_xattr_cleanup | io_uring/xattr.c | variable declaration
io_zcrx_args | io_uring/zcrx.c |  io_kiocb		*req,  io_zcrx_ifq	*ifq,  socket		*sock, unsigned		nr_skbs | io_zcrx_copy_frag | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_sync_for_device | io_uring/zcrx.c | declaration
 |  |  |  | io_zcrx_tcp_recvmsg | io_uring/zcrx.c | declaration
io_zcrx_area | io_uring/zcrx.h |  net_iov_area	nia,  io_zcrx_ifq	*ifq, atomic_t		*user_refs, bool			is_mapped, u16			area_id,  page		**pages, /* freelist */ 	spinlock_t		freelist_lock ____cacheline_aligned_in_smp, u32			free_count, u32			*freelist | __io_zcrx_unmap_area | io_uring/zcrx.c | variable declaration
 |  |  |  | container_of | io_uring/zcrx.c | function call
 |  |  |  | io_pp_zc_destroy | io_uring/zcrx.c | variable declaration
 |  |  |  | io_unregister_zcrx_ifqs | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_copy_chunk | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_create_area | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_free_area | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_get_niov_uref | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_map_area | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_queue_cqe | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_refill_slow | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_return_niov_freelist | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_ring_refill | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_scrub | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_sync_for_device | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_unmap_area | io_uring/zcrx.c | variable declaration
io_zcrx_ifq | io_uring/zcrx.h |  io_ring_ctx		*ctx,  io_zcrx_area		*area,  io_uring			*rq_ring,  io_uring_zcrx_rqe	*rqes, u32				rq_entries, u32				cached_rq_head, spinlock_t			rq_lock, u32				if_rxq,  device			*dev,  net_device		*netdev, netdevice_tracker		netdev_tracker, spinlock_t			lock | io_close_queue | io_uring/zcrx.c | variable declaration
 |  |  |  | io_free_rbuf_ring | io_uring/zcrx.c | variable declaration
 |  |  |  | io_pp_uninstall | io_uring/zcrx.c | variable declaration
 |  |  |  | io_pp_zc_alloc_netmems | io_uring/zcrx.c | variable declaration
 |  |  |  | io_pp_zc_destroy | io_uring/zcrx.c | variable declaration
 |  |  |  | io_pp_zc_init | io_uring/zcrx.c | variable declaration
 |  |  |  | io_register_zcrx_ifq | io_uring/zcrx.c | variable declaration
 |  |  |  | io_unregister_zcrx_ifqs | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_copy_chunk | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_copy_frag | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_create_area | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_drop_netdev | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_free_area | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_get_niov_uref | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_ifq_free | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_map_area | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_queue_cqe | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_refill_slow | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_ring_refill | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_rqring_entries | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_scrub | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_sync_for_device | io_uring/zcrx.c | variable declaration
 |  |  |  | io_zcrx_unmap_area | io_uring/zcrx.c | variable declaration
 |  |  |  | min | io_uring/zcrx.c | variable declaration
 |  |  |  | io_shutdown_zcrx_ifqs | io_uring/zcrx.h | variable declaration

 
If the following row value in a column is missing, assume the value is the same with the previous row in the same column. 
Continue until all data structures documented properly.
