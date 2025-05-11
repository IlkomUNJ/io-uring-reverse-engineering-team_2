
struct io_ring_ctx;
/* Connects a user's eventfd to an io_uring for completion notifications. 
Takes the io_uring context, a pointer to the eventfd, and a flag controlling async behavior. */
int io_eventfd_register(struct io_ring_ctx *ctx, void __user *arg,
			unsigned int eventfd_async);

/* Removes a previously registered eventfd from an io_uring context. 
Cleans up resources and breaks the connection between them. */
int io_eventfd_unregister(struct io_ring_ctx *ctx);

/* Notifies through eventfd only if new completions have occurred. 
Prevents unnecessary wakeups by checking if completion queue has changed. */
void io_eventfd_flush_signal(struct io_ring_ctx *ctx);

/* A function that make sure to always notifies through eventfd regardless of completion state. Used when applications should be woken up immediately. */
void io_eventfd_signal(struct io_ring_ctx *ctx);
