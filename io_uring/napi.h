/* SPDX-License-Identifier: GPL-2.0 */

#ifndef IOU_NAPI_H
#define IOU_NAPI_H

#include <linux/kernel.h>
#include <linux/io_uring.h>
#include <net/busy_poll.h>

#ifdef CONFIG_NET_RX_BUSY_POLL

/* Initialize NAPI support in an io_uring context */
void io_napi_init(struct io_ring_ctx *ctx);

/* Free all NAPI resources in an io_uring context */
void io_napi_free(struct io_ring_ctx *ctx);

/* Handle registration of NAPI settings from user space */
int io_register_napi(struct io_ring_ctx *ctx, void __user *arg);

/* Disable NAPI tracking and return current settings to user space */
int io_unregister_napi(struct io_ring_ctx *ctx, void __user *arg);

/* Add a NAPI ID to the tracking list */
int __io_napi_add_id(struct io_ring_ctx *ctx, unsigned int napi_id);

/* Execute busy polling loop for network sockets */
void __io_napi_busy_loop(struct io_ring_ctx *ctx, struct io_wait_queue *iowq);

/* Execute busy polling for submission queue poller mode */
int io_napi_sqpoll_busy_poll(struct io_ring_ctx *ctx);

/* Check if NAPI tracking is active */
static inline bool io_napi(struct io_ring_ctx *ctx)
{
	return !list_empty(&ctx->napi_list);
}

/* Conditionally execute busy polling if NAPI tracking is active. */
static inline void io_napi_busy_loop(struct io_ring_ctx *ctx,
				     struct io_wait_queue *iowq)
{
	if (!io_napi(ctx))
		return;
	__io_napi_busy_loop(ctx, iowq);
}

/*
 * io_napi_add() - Add napi id to the busy poll list
 * @req: pointer to io_kiocb request
 *
 * Add the napi id of the socket to the napi busy poll list and hash table.
 */
static inline void io_napi_add(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct socket *sock;

	if (READ_ONCE(ctx->napi_track_mode) != IO_URING_NAPI_TRACKING_DYNAMIC)
		return;

	sock = sock_from_file(req->file);
	if (sock && sock->sk)
		__io_napi_add_id(ctx, READ_ONCE(sock->sk->sk_napi_id));
}

#else

/* 
 No-op stubs for when NAPI support is disabled.
 Empty initialization function for compatibility when NAPI is disabled .
*/
static inline void io_napi_init(struct io_ring_ctx *ctx)
{
}

/* Empty cleanup function for compatibility when NAPI is disabled. */
static inline void io_napi_free(struct io_ring_ctx *ctx)
{
}

/* Returns "operation not supported" when attempting to register NAPI with NAPI support disabled. */
static inline int io_register_napi(struct io_ring_ctx *ctx, void __user *arg)
{
	return -EOPNOTSUPP;
}

/* Returns "operation not supported" when attempting to unregister NAPI with NAPI support disabled. */
static inline int io_unregister_napi(struct io_ring_ctx *ctx, void __user *arg)
{
	return -EOPNOTSUPP;
}

/* Always returns false since NAPI tracking cannot be active when disabled. */
static inline bool io_napi(struct io_ring_ctx *ctx)
{
	return false;
}

/* No-op function since NAPI tracking cannot be added when disabled. */
static inline void io_napi_add(struct io_kiocb *req)
{
}

/* No-op busy loop function when NAPI support is disabled. */
static inline void io_napi_busy_loop(struct io_ring_ctx *ctx,
				     struct io_wait_queue *iowq)
{
}

/* No-op busy poll function for sqpoll mode when NAPI support is disabled. */
static inline int io_napi_sqpoll_busy_poll(struct io_ring_ctx *ctx)
{
	return 0;
}
#endif /* CONFIG_NET_RX_BUSY_POLL */

#endif
