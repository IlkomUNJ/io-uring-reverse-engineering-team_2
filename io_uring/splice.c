// SPDX-License-Identifier: GPL-2.0
/*
 * io_uring splice/tee operations implementation
 *
 * Provides support for splice and tee operations through io_uring,
 * enabling efficient data movement between pipes and files without
 * multiple copies between kernel and userspace.
 */

 #include <linux/kernel.h>
 #include <linux/errno.h>
 #include <linux/fs.h>
 #include <linux/file.h>
 #include <linux/mm.h>
 #include <linux/slab.h>
 #include <linux/namei.h>
 #include <linux/io_uring.h>
 #include <linux/splice.h>
 
 #include <uapi/linux/io_uring.h>
 
 #include "io_uring.h"
 #include "splice.h"
 
 /*
  * struct io_splice - Holds state for splice/tee operations
  * @file_out:    Output file descriptor
  * @off_out:     Offset for output file
  * @off_in:      Offset for input file
  * @len:         Number of bytes to splice/tee
  * @splice_fd_in: Input file descriptor number
  * @flags:       Splice flags (SPLICE_F_*)
  * @rsrc_node:   Resource node for fixed files
  */
 struct io_splice {
	 struct file			*file_out;
	 loff_t				off_out;
	 loff_t				off_in;
	 u64				len;
	 int				splice_fd_in;
	 unsigned int			flags;
	 struct io_rsrc_node		*rsrc_node;
 };
 
 /*
  * __io_splice_prep - Common preparation for both splice and tee operations
  * Validates flags and extracts common parameters from SQE.
  */
 static int __io_splice_prep(struct io_kiocb *req,
				 const struct io_uring_sqe *sqe)
 {
	 struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	 /* Only these flags are valid for splice/tee */
	 unsigned int valid_flags = SPLICE_F_FD_IN_FIXED | SPLICE_F_ALL;
 
	 sp->len = READ_ONCE(sqe->len);
	 sp->flags = READ_ONCE(sqe->splice_flags);
	 
	 /* Validate that only permitted flags are set */
	 if (unlikely(sp->flags & ~valid_flags))
		 return -EINVAL;
	 
	 sp->splice_fd_in = READ_ONCE(sqe->splice_fd_in);
	 sp->rsrc_node = NULL;
	 
	 /* Force async execution for safety */
	 req->flags |= REQ_F_FORCE_ASYNC;
	 return 0;
 }
 
 /*
  * io_tee_prep - Prepare a tee operation (duplicate pipe data)
  * Validates that no offsets are provided (invalid for tee) and
  * performs common splice/tee preparation.
  */
 int io_tee_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
 {
	 /* Tee doesn't support offsets */
	 if (READ_ONCE(sqe->splice_off_in) || READ_ONCE(sqe->off))
		 return -EINVAL;
	 return __io_splice_prep(req, sqe);
 }
 
 /*
  * io_splice_cleanup - Clean up resources after splice/tee operations
  * Releases any fixed file resources that were acquired during the operation.
  */
 void io_splice_cleanup(struct io_kiocb *req)
 {
	 struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
 
	 if (sp->rsrc_node)
		 io_put_rsrc_node(req->ctx, sp->rsrc_node);
 }
 
 /*
  * io_splice_get_file - Get the input file descriptor for the operation
  * Handles both normal and fixed file descriptors.
  */
 static struct file *io_splice_get_file(struct io_kiocb *req,
						unsigned int issue_flags)
 {
	 struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	 struct io_ring_ctx *ctx = req->ctx;
	 struct io_rsrc_node *node;
	 struct file *file = NULL;
 
	 /* Handle normal (non-fixed) file descriptors */
	 if (!(sp->flags & SPLICE_F_FD_IN_FIXED))
		 return io_file_get_normal(req, sp->splice_fd_in);
 
	 /* Handle fixed file descriptors - requires context lock */
	 io_ring_submit_lock(ctx, issue_flags);
	 node = io_rsrc_node_lookup(&ctx->file_table.data, sp->splice_fd_in);
	 if (node) {
		 node->refs++;
		 sp->rsrc_node = node;
		 file = io_slot_file(node);
		 /* Mark that we need cleanup for this resource */
		 req->flags |= REQ_F_NEED_CLEANUP;
	 }
	 io_ring_submit_unlock(ctx, issue_flags);
	 return file;
 }
 
 /*
  * io_tee - Execute a tee operation (duplicate pipe data)
  * Performs the actual tee operation using do_tee().
  */
 int io_tee(struct io_kiocb *req, unsigned int issue_flags)
 {
	 struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	 struct file *out = sp->file_out;
	 unsigned int flags = sp->flags & ~SPLICE_F_FD_IN_FIXED;
	 struct file *in;
	 ssize_t ret = 0;
 
	 /* Tee operations cannot be non-blocking */
	 WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);
 
	 in = io_splice_get_file(req, issue_flags);
	 if (!in) {
		 ret = -EBADF;
		 goto done;
	 }
 
	 /* Perform the actual tee operation if length is non-zero */
	 if (sp->len)
		 ret = do_tee(in, out, sp->len, flags);
 
	 /* Clean up if we used a normal file descriptor */
	 if (!(sp->flags & SPLICE_F_FD_IN_FIXED))
		 fput(in);
 done:
	 /* Mark request as failed if we didn't transfer full length */
	 if (ret != sp->len)
		 req_set_fail(req);
	 /* Set result for completion */
	 io_req_set_res(req, ret, 0);
	 return IOU_OK;
 }
 
 /*
  * io_splice_prep - Prepare a splice operation
  * Extracts offsets and performs common splice preparation.
  */
 int io_splice_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
 {
	 struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
 
	 /* Read offsets from SQE (-1 means use current file position) */
	 sp->off_in = READ_ONCE(sqe->splice_off_in);
	 sp->off_out = READ_ONCE(sqe->off);
	 return __io_splice_prep(req, sqe);
 }
 
 /*
  * io_splice - Execute a splice operation (move data between file and pipe)
  * Performs the actual splice operation using do_splice().
  * Returns IOU_OK on completion.
  */
 int io_splice(struct io_kiocb *req, unsigned int issue_flags)
 {
	 struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	 struct file *out = sp->file_out;
	 unsigned int flags = sp->flags & ~SPLICE_F_FD_IN_FIXED;
	 loff_t *poff_in, *poff_out;
	 struct file *in;
	 ssize_t ret = 0;
 
	 /* Splice operations cannot be non-blocking */
	 WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);
 
	 in = io_splice_get_file(req, issue_flags);
	 if (!in) {
		 ret = -EBADF;
		 goto done;
	 }
 
	 /* Set up offset pointers (NULL means use current file position) */
	 poff_in = (sp->off_in == -1) ? NULL : &sp->off_in;
	 poff_out = (sp->off_out == -1) ? NULL : &sp->off_out;
 
	 /* Perform the actual splice operation if length is non-zero */
	 if (sp->len)
		 ret = do_splice(in, poff_in, out, poff_out, sp->len, flags);
 
	 /* Clean up if we used a normal file descriptor */
	 if (!(sp->flags & SPLICE_F_FD_IN_FIXED))
		 fput(in);
 done:
	 /* Mark request as failed if we didn't transfer full length */
	 if (ret != sp->len)
		 req_set_fail(req);
	 /* Set result for completion */
	 io_req_set_res(req, ret, 0);
	 return IOU_OK;
 }