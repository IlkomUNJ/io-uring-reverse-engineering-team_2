// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_FILE_TABLE_H
#define IOU_FILE_TABLE_H

#include <linux/file.h>
#include <linux/io_uring_types.h>
#include "rsrc.h"

/* Creates a new file table with space for the specified number of files. Returns true if successful, false if memory allocation fails. */
bool io_alloc_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table, unsigned nr_files);

/* Releases all memory used by a file table, including all file references and tracking structures. */
void io_free_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table);

/* Installs a file descriptor in the fixed file table with proper locking. Returns the slot number on success or an error code. */
int io_fixed_fd_install(struct io_kiocb *req, unsigned int issue_flags,
			struct file *file, unsigned int file_slot);

/* Internal helper that installs a file in the fixed file table without locking. Used by the main install function after locks are acquired. */
int __io_fixed_fd_install(struct io_ring_ctx *ctx, struct file *file,
				unsigned int file_slot);

/* Removes a file from the fixed file table at the specified offset.*/
int io_fixed_fd_remove(struct io_ring_ctx *ctx, unsigned int offset);

/* Sets the range of slots that can be used for automatic file allocation. Returns 0 on success or an error code. */
int io_register_file_alloc_range(struct io_ring_ctx *ctx,
				 struct io_uring_file_index_range __user *arg);

io_req_flags_t io_file_get_flags(struct file *file);

/* Marks a slot in the file bitmap as unused and updates the allocation hint. */
static inline void io_file_bitmap_clear(struct io_file_table *table, int bit)
{
	WARN_ON_ONCE(!test_bit(bit, table->bitmap));
	__clear_bit(bit, table->bitmap);
	table->alloc_hint = bit;
}

/* Marks a slot in the file bitmap as in-use and updates the allocation hint to the next position. */
static inline void io_file_bitmap_set(struct io_file_table *table, int bit)
{
	WARN_ON_ONCE(test_bit(bit, table->bitmap));
	__set_bit(bit, table->bitmap);
	table->alloc_hint = bit + 1;
}

#define FFS_NOWAIT		0x1UL
#define FFS_ISREG		0x2UL
#define FFS_MASK		~(FFS_NOWAIT|FFS_ISREG)

/* Extracts operation flags from a resource node that were packed with the file pointer. */
static inline unsigned int io_slot_flags(struct io_rsrc_node *node)
{

	return (node->file_ptr & ~FFS_MASK) << REQ_F_SUPPORT_NOWAIT_BIT;
}

/* Extracts the actual file pointer from a resource node by stripping off the flag bits. */
static inline struct file *io_slot_file(struct io_rsrc_node *node)
{
	return (struct file *)(node->file_ptr & FFS_MASK);
}

/* Stores a file pointer in a resource node along with its operation flags for compact storage. */
static inline void io_fixed_file_set(struct io_rsrc_node *node,
				     struct file *file)
{
	node->file_ptr = (unsigned long)file |
		(io_file_get_flags(file) >> REQ_F_SUPPORT_NOWAIT_BIT);
}

/* Configures which range of slots in the file table can be used for automatic allocation. */
static inline void io_file_table_set_alloc_range(struct io_ring_ctx *ctx,
						 unsigned off, unsigned len)
{
	ctx->file_alloc_start = off;
	ctx->file_alloc_end = off + len;
	ctx->file_table.alloc_hint = ctx->file_alloc_start;
}

#endif
