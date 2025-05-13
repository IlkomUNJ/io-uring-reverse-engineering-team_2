// SPDX-License-Identifier: GPL-2.0

#include <linux/net.h>
#include <linux/uio.h>
#include <net/sock.h>
#include <linux/nospec.h>

#include "rsrc.h"

#define IO_NOTIF_UBUF_FLAGS	(SKBFL_ZEROCOPY_FRAG | SKBFL_DONT_ORPHAN)
#define IO_NOTIF_SPLICE_BATCH	32

struct io_notif_data {
    struct file		*file;
    struct ubuf_info	uarg;

    struct io_notif_data	*next;
    struct io_notif_data	*head;

    unsigned		account_pages;
    bool			zc_report;
    bool			zc_used;
    bool			zc_copied;
};

/* 
 * Allocates and initializes a new notification request for io_uring operations.
 * Sets up needed structures for handling zero-copy notifications.
 */
struct io_kiocb *io_alloc_notif(struct io_ring_ctx *ctx);

/* 
 * Callback for when a zero-copy buffer completes operation.
 * Updates notification flags and schedules completion based on operation status.
 */
void io_tx_ubuf_complete(struct sk_buff *skb, struct ubuf_info *uarg,
             bool success);

/* 
 * Converts a generic io_kiocb request to its specialized notification data.
 * Provides access to notification-specific fields and state.
 */
static inline struct io_notif_data *io_notif_to_data(struct io_kiocb *notif)
{
    return io_kiocb_to_cmd(notif, struct io_notif_data);
}

/* 
 * Forces completion of a pending notification.
 * Ensures notification resources are properly released even without network activity.
 */
static inline void io_notif_flush(struct io_kiocb *notif)
    __must_hold(&notif->ctx->uring_lock)
{
    struct io_notif_data *nd = io_notif_to_data(notif);

    io_tx_ubuf_complete(NULL, &nd->uarg, true);
}

/* 
 * Accounts for memory used by notification buffers.
 * Tracks memory usage per user and updates accounting information.
 */
static inline int io_notif_account_mem(struct io_kiocb *notif, unsigned len)
{
    struct io_ring_ctx *ctx = notif->ctx;
    struct io_notif_data *nd = io_notif_to_data(notif);
    unsigned nr_pages = (len >> PAGE_SHIFT) + 2;
    int ret;

    if (ctx->user) {
        ret = __io_account_mem(ctx->user, nr_pages);
        if (ret)
            return ret;
        nd->account_pages += nr_pages;
    }
    return 0;
}
