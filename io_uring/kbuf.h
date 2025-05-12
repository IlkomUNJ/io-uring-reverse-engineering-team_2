// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_KBUF_H
#define IOU_KBUF_H

#include <uapi/linux/io_uring.h>
#include <linux/io_uring_types.h>

enum {
	/* ring mapped provided buffers */
	IOBL_BUF_RING	= 1,
	/* buffers are consumed incrementally rather than always fully */
	IOBL_INC	= 2,
};

struct io_buffer_list {
	/*
	 * If ->buf_nr_pages is set, then buf_pages/buf_ring are used. If not,
	 * then these are classic provided buffers and ->buf_list is used.
	 */
	union {
		struct list_head buf_list;
		struct io_uring_buf_ring *buf_ring;
	};
	__u16 bgid;

	/* below is for ring provided buffers */
	__u16 buf_nr_pages;
	__u16 nr_entries;
	__u16 head;
	__u16 mask;

	__u16 flags;

	struct io_mapped_region region;
};

struct io_buffer {
	struct list_head list;
	__u64 addr;
	__u32 len;
	__u16 bid;
	__u16 bgid;
};

enum {
	/* can alloc a bigger vec */
	KBUF_MODE_EXPAND	= 1,
	/* if bigger vec allocated, free old one */
	KBUF_MODE_FREE		= 2,
};

struct buf_sel_arg {
	struct iovec *iovs;
	size_t out_len;
	size_t max_len;
	unsigned short nr_iovs;
	unsigned short mode;
};

/* Selects an appropriate buffer for a request based on buffer index, with proper locking. */
void __user *io_buffer_select(struct io_kiocb *req, size_t *len,
			      unsigned int issue_flags);

/* Selects multiple buffers for a request using the provided arguments, handles both buffer types. */
int io_buffers_select(struct io_kiocb *req, struct buf_sel_arg *arg,
		      unsigned int issue_flags);

/* Examines available buffers without consuming them, returning count or error code. */
int io_buffers_peek(struct io_kiocb *req, struct buf_sel_arg *arg);

/* Releases all buffer resources associated with a context during cleanup or shutdown. */
void io_destroy_buffers(struct io_ring_ctx *ctx);

/* Prepares a request for removing buffers by validating and parsing SQE parameters. */
int io_remove_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Executes buffer removal from a buffer group based on the prepared request. */
int io_remove_buffers(struct io_kiocb *req, unsigned int issue_flags);

/* Prepares a request for providing buffers by validating and parsing SQE parameters. */
int io_provide_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Adds user provided buffers to a buffer group based on the prepared request. */
int io_provide_buffers(struct io_kiocb *req, unsigned int issue_flags);

/* Registers a persistent buffer ring for a buffer group with memory mapping support. */
int io_register_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg);

/* Unregisters a persistent buffer ring and cleans up associated resources. */
int io_unregister_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg);

/* Retrieves current status information for a buffer group ring and reports to userspace. */
int io_register_pbuf_status(struct io_ring_ctx *ctx, void __user *arg);

/* Returns a legacy buffer to its buffer list for future reuse with proper locking. */
bool io_kbuf_recycle_legacy(struct io_kiocb *req, unsigned issue_flags);

/* Releases a legacy buffer's resources and updates the request state. */
void io_kbuf_drop_legacy(struct io_kiocb *req);

/* Returns buffers to their pools and prepares completion notification flags for userspace. */
unsigned int __io_put_kbufs(struct io_kiocb *req, int len, int nbufs);

/* Finalizes buffer usage by updating tracking information based on buffer type. */
bool io_kbuf_commit(struct io_kiocb *req,
		    struct io_buffer_list *bl, int len, int nr);

/* Retrieves the memory mapped region associated with a buffer group for mmap operations. */
struct io_mapped_region *io_pbuf_get_region(struct io_ring_ctx *ctx,
					    unsigned int bgid);

/* Handles recycling of ring buffers by updating flags and maintaining buffer state without advancing head. */
static inline bool io_kbuf_recycle_ring(struct io_kiocb *req)
{
	/*
	 * We don't need to recycle for REQ_F_BUFFER_RING, we can just clear
	 * the flag and hence ensure that bl->head doesn't get incremented.
	 * If the tail has already been incremented, hang on to it.
	 * The exception is partial io, that case we should increment bl->head
	 * to monopolize the buffer.
	 */
	if (req->buf_list) {
		req->buf_index = req->buf_list->bgid;
		req->flags &= ~(REQ_F_BUFFER_RING|REQ_F_BUFFERS_COMMIT);
		return true;
	}
	return false;
}

/* Determines if buffer selection is needed based on request flags, avoiding redundant selection. */
static inline bool io_do_buffer_select(struct io_kiocb *req)
{
	if (!(req->flags & REQ_F_BUFFER_SELECT))
		return false;
	return !(req->flags & (REQ_F_BUFFER_SELECTED|REQ_F_BUFFER_RING));
}

/* Routes buffer recycling to the appropriate handler based on buffer type and flags. */
static inline bool io_kbuf_recycle(struct io_kiocb *req, unsigned issue_flags)
{
	if (req->flags & REQ_F_BL_NO_RECYCLE)
		return false;
	if (req->flags & REQ_F_BUFFER_SELECTED)
		return io_kbuf_recycle_legacy(req, issue_flags);
	if (req->flags & REQ_F_BUFFER_RING)
		return io_kbuf_recycle_ring(req);
	return false;
}

/* Releases a single buffer and updates completion flags for userspace notification. */
static inline unsigned int io_put_kbuf(struct io_kiocb *req, int len,
				       unsigned issue_flags)
{
	if (!(req->flags & (REQ_F_BUFFER_RING | REQ_F_BUFFER_SELECTED)))
		return 0;
	return __io_put_kbufs(req, len, 1);
}

/* Releases multiple buffers and updates completion flags for userspace notification. */
static inline unsigned int io_put_kbufs(struct io_kiocb *req, int len,
					int nbufs, unsigned issue_flags)
{
	if (!(req->flags & (REQ_F_BUFFER_RING | REQ_F_BUFFER_SELECTED)))
		return 0;
	return __io_put_kbufs(req, len, nbufs);
}
#endif
