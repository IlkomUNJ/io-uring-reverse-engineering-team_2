// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_RSRC_H
#define IOU_RSRC_H

#include <linux/io_uring_types.h>
#include <linux/lockdep.h>

#define IO_VEC_CACHE_SOFT_CAP		256

// Resource types used in io_uring
enum {
	IORING_RSRC_FILE		= 0,	// Registered file descriptor
	IORING_RSRC_BUFFER		= 1,	// Registered buffer
};

// Node structure representing a single resource (file or buffer)
struct io_rsrc_node {
	unsigned char type;		// Type of the resource (file or buffer)
	int refs;				// Reference count

	u64 tag;					// Optional tag for identifying the resource
	union {
		unsigned long file_ptr;				// Pointer to a file (if type is file)
		struct io_mapped_ubuf *buf;		// Pointer to a mapped user buffer (if type is buffer)
	};
};

// Flags used for IO_IMU (I/O mapped user buffer) direction
enum {
	IO_IMU_DEST	= 1 << ITER_DEST,	// Destination direction (e.g., read)
	IO_IMU_SOURCE = 1 << ITER_SOURCE, // Source direction (e.g., write)
};

// Structure representing a registered user buffer
struct io_mapped_ubuf {
	u64 ubuf;						// User buffer address
	unsigned int len;				// Total length of buffer
	unsigned int nr_bvecs;			// Number of bio_vec entries
	unsigned int folio_shift;		// Page shift for folio granularity
	refcount_t refs;				// Reference count
	unsigned long acct_pages;		// Number of accounted memory pages
	void (*release)(void *);		// Custom release function
	void *priv;						// Private data pointer
	bool is_kbuf;					// Indicates if this is a kernel buffer
	u8 dir;							// Direction (source/destination)
	struct bio_vec bvec[] __counted_by(nr_bvecs);	// Array of bio_vec structs
};

// Metadata for folio layout of a mapped user buffer
struct io_imu_folio_data {
	unsigned int nr_pages_head;		// Pages partially included at start
	unsigned int nr_pages_mid;		// Fully included middle pages
	unsigned int folio_shift;		// Page shift size
	unsigned int nr_folios;			// Total number of folios
};

// Initializes the resource cache for the given io_uring context
bool io_rsrc_cache_init(struct io_ring_ctx *ctx);

// Frees the resource cache for the given io_uring context
void io_rsrc_cache_free(struct io_ring_ctx *ctx);

// Allocates a new resource node of given type
struct io_rsrc_node *io_rsrc_node_alloc(struct io_ring_ctx *ctx, int type);

// Frees a resource node
void io_free_rsrc_node(struct io_ring_ctx *ctx, struct io_rsrc_node *node);

// Frees the resource data structure
void io_rsrc_data_free(struct io_ring_ctx *ctx, struct io_rsrc_data *data);

// Allocates memory for managing 'nr' resource nodes
int io_rsrc_data_alloc(struct io_rsrc_data *data, unsigned nr);

// Finds the buffer resource node associated with a request
struct io_rsrc_node *io_find_buf_node(struct io_kiocb *req, unsigned issue_flags);

// Imports a registered buffer into an iov_iter for I/O
int io_import_reg_buf(struct io_kiocb *req, struct iov_iter *iter,
			u64 buf_addr, size_t len, int ddir,
			unsigned issue_flags);

// Imports a vector of registered I/O buffers into an iov_iter
int io_import_reg_vec(int ddir, struct iov_iter *iter,
			struct io_kiocb *req, struct iou_vec *vec,
			unsigned nr_iovs, unsigned issue_flags);

// Prepares iovec array from user-provided vector
int io_prep_reg_iovec(struct io_kiocb *req, struct iou_vec *iv,
			const struct iovec __user *uvec, size_t uvec_segs);

// Registers a new set of user buffers by cloning existing ones
int io_register_clone_buffers(struct io_ring_ctx *ctx, void __user *arg);

// Unregisters previously registered user buffers
int io_sqe_buffers_unregister(struct io_ring_ctx *ctx);

// Registers new user buffers for use in io_uring
int io_sqe_buffers_register(struct io_ring_ctx *ctx, void __user *arg,
			    unsigned int nr_args, u64 __user *tags);

// Unregisters previously registered file descriptors
int io_sqe_files_unregister(struct io_ring_ctx *ctx);

// Registers file descriptors for fast access
int io_sqe_files_register(struct io_ring_ctx *ctx, void __user *arg,
			  unsigned nr_args, u64 __user *tags);

// Updates existing registered file descriptors
int io_register_files_update(struct io_ring_ctx *ctx, void __user *arg,
			     unsigned nr_args);

// Updates resources like buffers or files based on type
int io_register_rsrc_update(struct io_ring_ctx *ctx, void __user *arg,
			    unsigned size, unsigned type);

// Registers resources (buffers or files)
int io_register_rsrc(struct io_ring_ctx *ctx, void __user *arg,
			unsigned int size, unsigned int type);

// Validates the integrity of the given buffer iovec
int io_buffer_validate(struct iovec *iov);

// Determines if buffer pages can be coalesced into folios
bool io_check_coalesce_buffer(struct page **page_array, int nr_pages,
			      struct io_imu_folio_data *data);

// Looks up a resource node by index in resource data
static inline struct io_rsrc_node *io_rsrc_node_lookup(struct io_rsrc_data *data,
						       int index)
{
	if (index < data->nr)
		return data->nodes[array_index_nospec(index, data->nr)];
	return NULL;
}

// Decrements a resource node’s ref count and frees it if needed
static inline void io_put_rsrc_node(struct io_ring_ctx *ctx, struct io_rsrc_node *node)
{
	lockdep_assert_held(&ctx->uring_lock);
	if (!--node->refs)
		io_free_rsrc_node(ctx, node);
}

// Resets a resource node in the data structure
static inline bool io_reset_rsrc_node(struct io_ring_ctx *ctx,
				      struct io_rsrc_data *data, int index)
{
	struct io_rsrc_node *node = data->nodes[index];

	if (!node)
		return false;
	io_put_rsrc_node(ctx, node);
	data->nodes[index] = NULL;
	return true;
}

// Releases all resource nodes tied to a request
static inline void io_req_put_rsrc_nodes(struct io_kiocb *req)
{
	if (req->file_node) {
		io_put_rsrc_node(req->ctx, req->file_node);
		req->file_node = NULL;
	}
	if (req->flags & REQ_F_BUF_NODE) {
		io_put_rsrc_node(req->ctx, req->buf_node);
		req->buf_node = NULL;
	}
}

// Assigns a resource node to a request and increments its ref count
static inline void io_req_assign_rsrc_node(struct io_rsrc_node **dst_node,
					   struct io_rsrc_node *node)
{
	node->refs++;
	*dst_node = node;
}

// Assigns a buffer resource node to a request
static inline void io_req_assign_buf_node(struct io_kiocb *req,
					  struct io_rsrc_node *node)
{
	io_req_assign_rsrc_node(&req->buf_node, node);
	req->flags |= REQ_F_BUF_NODE;
}

// Handles the update of registered files for a specific request
int io_files_update(struct io_kiocb *req, unsigned int issue_flags);

// Prepares the file update operation
int io_files_update_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Accounts for memory used by a user
int __io_account_mem(struct user_struct *user, unsigned long nr_pages);

// Unaccounts memory from the user (used during release)
static inline void __io_unaccount_mem(struct user_struct *user,
				      unsigned long nr_pages)
{
	atomic_long_sub(nr_pages, &user->locked_vm);
}

// Frees memory for the given iovec vector
void io_vec_free(struct iou_vec *iv);

// Reallocates memory for the iovec vector
int io_vec_realloc(struct iou_vec *iv, unsigned nr_entries);

// Resets iovec vector with a new array and count
static inline void io_vec_reset_iovec(struct iou_vec *iv,
				      struct iovec *iovec, unsigned nr)
{
	io_vec_free(iv);
	iv->iovec = iovec;
	iv->nr = nr;
}

// Clears and frees vector if KASAN is enabled
static inline void io_alloc_cache_vec_kasan(struct iou_vec *iv)
{
	if (IS_ENABLED(CONFIG_KASAN))
		io_vec_free(iv);
}

#endif
