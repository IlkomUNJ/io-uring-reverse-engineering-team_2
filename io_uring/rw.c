// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/blk-mq.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/fsnotify.h>
#include <linux/poll.h>
#include <linux/nospec.h>
#include <linux/compat.h>
#include <linux/io_uring/cmd.h>
#include <linux/indirect_call_wrapper.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "opdef.h"
#include "kbuf.h"
#include "alloc_cache.h"
#include "rsrc.h"
#include "poll.h"
#include "rw.h"

/* Completion handler for normal (non-iopoll) read/write operations */
static void io_complete_rw(struct kiocb *kiocb, long res);

/* Completion handler for iopoll read/write operations */
static void io_complete_rw_iopoll(struct kiocb *kiocb, long res);

/* Structure holding read/write operation data */
struct io_rw {
	/* NOTE: kiocb has the file as the first member, so don't do it here */
	struct kiocb			kiocb;  /* Kernel I/O control block */
	u64				addr;   /* User buffer address */
	u32				len;    /* Length of data to transfer */
	rwf_t				flags;  /* Read/write flags */
};

/* Check if file supports non-blocking operations */
static bool io_file_supports_nowait(struct io_kiocb *req, __poll_t mask)
{
	/* If FMODE_NOWAIT is set for a file, we're golden */
	if (req->flags & REQ_F_SUPPORT_NOWAIT)
		return true;
	/* No FMODE_NOWAIT, if we can poll, check the status */
	if (io_file_can_poll(req)) {
		struct poll_table_struct pt = { ._key = mask };

		return vfs_poll(req->file, &pt) & mask;
	}
	/* No FMODE_NOWAIT support, and file isn't pollable. Tough luck. */
	return false;
}

/* Handle compat iovec buffer selection for 32-bit userspace */
static int io_iov_compat_buffer_select_prep(struct io_rw *rw)
{
	struct compat_iovec __user *uiov = u64_to_user_ptr(rw->addr);
	struct compat_iovec iov;

	if (copy_from_user(&iov, uiov, sizeof(iov)))
		return -EFAULT;
	rw->len = iov.iov_len;
	return 0;
}

/* Prepare buffer selection for readv/writev operations */
static int io_iov_buffer_select_prep(struct io_kiocb *req)
{
	struct iovec __user *uiov;
	struct iovec iov;
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);

	if (rw->len != 1)
		return -EINVAL;

	if (io_is_compat(req->ctx))
		return io_iov_compat_buffer_select_prep(rw);

	uiov = u64_to_user_ptr(rw->addr);
	if (copy_from_user(&iov, uiov, sizeof(*uiov)))
		return -EFAULT;
	rw->len = iov.iov_len;
	return 0;
}

/* Import iovec from userspace for vectored I/O */
static int io_import_vec(int ddir, struct io_kiocb *req,
			 struct io_async_rw *io,
			 const struct iovec __user *uvec,
			 size_t uvec_segs)
{
	int ret, nr_segs;
	struct iovec *iov;

	if (io->vec.iovec) {
		nr_segs = io->vec.nr;
		iov = io->vec.iovec;
	} else {
		nr_segs = 1;
		iov = &io->fast_iov;
	}

	ret = __import_iovec(ddir, uvec, uvec_segs, nr_segs, &iov, &io->iter,
			     io_is_compat(req->ctx));
	if (unlikely(ret < 0))
		return ret;
	if (iov) {
		req->flags |= REQ_F_NEED_CLEANUP;
		io_vec_reset_iovec(&io->vec, iov, io->iter.nr_segs);
	}
	return 0;
}

/* Import read/write buffer from userspace */
static int __io_import_rw_buffer(int ddir, struct io_kiocb *req,
			     struct io_async_rw *io,
			     unsigned int issue_flags)
{
	const struct io_issue_def *def = &io_issue_defs[req->opcode];
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
	void __user *buf = u64_to_user_ptr(rw->addr);
	size_t sqe_len = rw->len;

	if (def->vectored && !(req->flags & REQ_F_BUFFER_SELECT))
		return io_import_vec(ddir, req, io, buf, sqe_len);

	if (io_do_buffer_select(req)) {
		buf = io_buffer_select(req, &sqe_len, issue_flags);
		if (!buf)
			return -ENOBUFS;
		rw->addr = (unsigned long) buf;
		rw->len = sqe_len;
	}
	return import_ubuf(ddir, buf, sqe_len, &io->iter);
}

/* Wrapper for buffer import with state saving */
static inline int io_import_rw_buffer(int rw, struct io_kiocb *req,
				      struct io_async_rw *io,
				      unsigned int issue_flags)
{
	int ret;

	ret = __io_import_rw_buffer(rw, req, io, issue_flags);
	if (unlikely(ret < 0))
		return ret;

	iov_iter_save_state(&io->iter, &io->iter_state);
	return 0;
}

/* Recycle async read/write resources */
static void io_rw_recycle(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_async_rw *rw = req->async_data;

	if (unlikely(issue_flags & IO_URING_F_UNLOCKED))
		return;

	io_alloc_cache_vec_kasan(&rw->vec);
	if (rw->vec.nr > IO_VEC_CACHE_SOFT_CAP)
		io_vec_free(&rw->vec);

	if (io_alloc_cache_put(&req->ctx->rw_cache, rw)) {
		req->async_data = NULL;
		req->flags &= ~REQ_F_ASYNC_DATA;
	}
}

/* Cleanup read/write request resources */
static void io_req_rw_cleanup(struct io_kiocb *req, unsigned int issue_flags)
{
	/*
	 * Disable quick recycling for anything that's gone through io-wq.
	 * See detailed comment in code about potential UAF issues.
	 */
	if (!(req->flags & (REQ_F_REISSUE | REQ_F_REFCOUNT))) {
		req->flags &= ~REQ_F_NEED_CLEANUP;
		io_rw_recycle(req, issue_flags);
	}
}

/* Allocate async read/write data structure */
static int io_rw_alloc_async(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_async_rw *rw;

	rw = io_uring_alloc_async_data(&ctx->rw_cache, req);
	if (!rw)
		return -ENOMEM;
	if (rw->vec.iovec)
		req->flags |= REQ_F_NEED_CLEANUP;
	rw->bytes_done = 0;
	return 0;
}

/* Save metadata state for restoration */
static inline void io_meta_save_state(struct io_async_rw *io)
{
	io->meta_state.seed = io->meta.seed;
	iov_iter_save_state(&io->meta.iter, &io->meta_state.iter_meta);
}

/* Restore metadata state */
static inline void io_meta_restore(struct io_async_rw *io, struct kiocb *kiocb)
{
	if (kiocb->ki_flags & IOCB_HAS_METADATA) {
		io->meta.seed = io->meta_state.seed;
		iov_iter_restore(&io->meta.iter, &io->meta_state.iter_meta);
	}
}

/* Prepare request with protection information (PI) */
static int io_prep_rw_pi(struct io_kiocb *req, struct io_rw *rw, int ddir,
			 u64 attr_ptr, u64 attr_type_mask)
{
	struct io_uring_attr_pi pi_attr;
	struct io_async_rw *io;
	int ret;

	if (copy_from_user(&pi_attr, u64_to_user_ptr(attr_ptr),
	    sizeof(pi_attr)))
		return -EFAULT;

	if (pi_attr.rsvd)
		return -EINVAL;

	io = req->async_data;
	io->meta.flags = pi_attr.flags;
	io->meta.app_tag = pi_attr.app_tag;
	io->meta.seed = pi_attr.seed;
	ret = import_ubuf(ddir, u64_to_user_ptr(pi_attr.addr),
			  pi_attr.len, &io->meta.iter);
	if (unlikely(ret < 0))
		return ret;
	req->flags |= REQ_F_HAS_METADATA;
	io_meta_save_state(io);
	return ret;
}

/* Common preparation for read/write operations */
static int __io_prep_rw(struct io_kiocb *req, const struct io_uring_sqe *sqe,
			int ddir)
{
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
	unsigned ioprio;
	u64 attr_type_mask;
	int ret;

	if (io_rw_alloc_async(req))
		return -ENOMEM;

	rw->kiocb.ki_pos = READ_ONCE(sqe->off);
	req->buf_index = READ_ONCE(sqe->buf_index);

	ioprio = READ_ONCE(sqe->ioprio);
	if (ioprio) {
		ret = ioprio_check_cap(ioprio);
		if (ret)
			return ret;

		rw->kiocb.ki_ioprio = ioprio;
	} else {
		rw->kiocb.ki_ioprio = get_current_ioprio();
	}
	rw->kiocb.dio_complete = NULL;
	rw->kiocb.ki_flags = 0;

	if (req->ctx->flags & IORING_SETUP_IOPOLL)
		rw->kiocb.ki_complete = io_complete_rw_iopoll;
	else
		rw->kiocb.ki_complete = io_complete_rw;

	rw->addr = READ_ONCE(sqe->addr);
	rw->len = READ_ONCE(sqe->len);
	rw->flags = READ_ONCE(sqe->rw_flags);

	attr_type_mask = READ_ONCE(sqe->attr_type_mask);
	if (attr_type_mask) {
		u64 attr_ptr;

		/* only PI attribute is supported currently */
		if (attr_type_mask != IORING_RW_ATTR_FLAG_PI)
			return -EINVAL;

		attr_ptr = READ_ONCE(sqe->attr_ptr);
		return io_prep_rw_pi(req, rw, ddir, attr_ptr, attr_type_mask);
	}
	return 0;
}

/* Import buffers for read/write operations */
static int io_rw_do_import(struct io_kiocb *req, int ddir)
{
	if (io_do_buffer_select(req))
		return 0;

	return io_import_rw_buffer(ddir, req, req->async_data, 0);
}

/* Prepare read/write operation */
static int io_prep_rw(struct io_kiocb *req, const struct io_uring_sqe *sqe,
		      int ddir)
{
	int ret;

	ret = __io_prep_rw(req, sqe, ddir);
	if (unlikely(ret))
		return ret;

	return io_rw_do_import(req, ddir);
}

/* Prepare read operation */
int io_prep_read(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	return io_prep_rw(req, sqe, ITER_DEST);
}

/* Prepare write operation */
int io_prep_write(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	return io_prep_rw(req, sqe, ITER_SOURCE);
}

/* Prepare vectored read/write operation */
static int io_prep_rwv(struct io_kiocb *req, const struct io_uring_sqe *sqe,
		       int ddir)
{
	int ret;

	ret = io_prep_rw(req, sqe, ddir);
	if (unlikely(ret))
		return ret;
	if (!(req->flags & REQ_F_BUFFER_SELECT))
		return 0;

	/*
	 * Additional validation for buffer selection case since rw->len
	 * might have changed due to buffer selection
	 */
	return io_iov_buffer_select_prep(req);
}

/* Prepare vectored read operation */
int io_prep_readv(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	return io_prep_rwv(req, sqe, ITER_DEST);
}

/* Prepare vectored write operation */
int io_prep_writev(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	return io_prep_rwv(req, sqe, ITER_SOURCE);
}

/* Initialize fixed read/write operation */
static int io_init_rw_fixed(struct io_kiocb *req, unsigned int issue_flags,
			    int ddir)
{
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
	struct io_async_rw *io = req->async_data;
	int ret;

	if (io->bytes_done)
		return 0;

	ret = io_import_reg_buf(req, &io->iter, rw->addr, rw->len, ddir,
				issue_flags);
	iov_iter_save_state(&io->iter, &io->iter_state);
	return ret;
}

/* Prepare fixed read operation */
int io_prep_read_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	return __io_prep_rw(req, sqe, ITER_DEST);
}

/* Prepare fixed write operation */
int io_prep_write_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	return __io_prep_rw(req, sqe, ITER_SOURCE);
}

/* Import registered buffer vector for read/write */
static int io_rw_import_reg_vec(struct io_kiocb *req,
				struct io_async_rw *io,
				int ddir, unsigned int issue_flags)
{
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
	unsigned uvec_segs = rw->len;
	int ret;

	ret = io_import_reg_vec(ddir, &io->iter, req, &io->vec,
				uvec_segs, issue_flags);
	if (unlikely(ret))
		return ret;
	iov_iter_save_state(&io->iter, &io->iter_state);
	req->flags &= ~REQ_F_IMPORT_BUFFER;
	return 0;
}

/* Prepare registered vector for read/write */
static int io_rw_prep_reg_vec(struct io_kiocb *req)
{
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
	struct io_async_rw *io = req->async_data;
	const struct iovec __user *uvec;

	uvec = u64_to_user_ptr(rw->addr);
	return io_prep_reg_iovec(req, &io->vec, uvec, rw->len);
}

/* Prepare fixed vectored read operation */
int io_prep_readv_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	int ret;

	ret = __io_prep_rw(req, sqe, ITER_DEST);
	if (unlikely(ret))
		return ret;
	return io_rw_prep_reg_vec(req);
}

/* Prepare fixed vectored write operation */
int io_prep_writev_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	int ret;

	ret = __io_prep_rw(req, sqe, ITER_SOURCE);
	if (unlikely(ret))
		return ret;
	return io_rw_prep_reg_vec(req);
}

/*
 * Prepare multishot read operation
 * Must be used with provided buffers and has special requirements
 */
int io_read_mshot_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
	int ret;

	/* must be used with provided buffers */
	if (!(req->flags & REQ_F_BUFFER_SELECT))
		return -EINVAL;

	ret = __io_prep_rw(req, sqe, ITER_DEST);
	if (unlikely(ret))
		return ret;

	if (rw->addr || rw->len)
		return -EINVAL;

	req->flags |= REQ_F_APOLL_MULTISHOT;
	return 0;
}

/* Cleanup function for readv/writev operations */
void io_readv_writev_cleanup(struct io_kiocb *req)
{
	lockdep_assert_held(&req->ctx->uring_lock);
	io_rw_recycle(req, 0);
}

/* Update position for read/write operations */
static inline loff_t *io_kiocb_update_pos(struct io_kiocb *req)
{
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);

	if (rw->kiocb.ki_pos != -1)
		return &rw->kiocb.ki_pos;

	if (!(req->file->f_mode & FMODE_STREAM)) {
		req->flags |= REQ_F_CUR_POS;
		rw->kiocb.ki_pos = req->file->f_pos;
		return &rw->kiocb.ki_pos;
	}

	rw->kiocb.ki_pos = 0;
	return NULL;
}
/* 
 * Determine if a read/write operation should be reissued after getting -EAGAIN.
 * Only applicable for block devices and regular files.
 */
static bool io_rw_should_reissue(struct io_kiocb *req)
{
#ifdef CONFIG_BLOCK
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
	umode_t mode = file_inode(req->file)->i_mode;
	struct io_async_rw *io = req->async_data;
	struct io_ring_ctx *ctx = req->ctx;

	/* Only for block devices and regular files */
	if (!S_ISBLK(mode) && !S_ISREG(mode))
		return false;
	/* Don't reissue if this is NOWAIT or from io-wq without IOPOLL */
	if ((req->flags & REQ_F_NOWAIT) || (io_wq_current_is_worker() &&
	    !(ctx->flags & IORING_SETUP_IOPOLL)))
		return false;
	/*
	 * If ref is dying, we might be running poll reap from the exit work.
	 * Don't attempt to reissue from that path.
	 */
	if (percpu_ref_is_dying(&ctx->refs))
		return false;

	/* Restore metadata and iterator state before retry */
	io_meta_restore(io, &rw->kiocb);
	iov_iter_restore(&io->iter, &io->iter_state);
	return true;
#else
	return false;
#endif
}

/* Complete write accounting for regular files */
static void io_req_end_write(struct io_kiocb *req)
{
	if (req->flags & REQ_F_ISREG) {
		struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
		kiocb_end_write(&rw->kiocb);
	}
}

/*
 * Trigger notifications after IO completion and finish write accounting
 */
static void io_req_io_end(struct io_kiocb *req)
{
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);

	if (rw->kiocb.ki_flags & IOCB_WRITE) {
		io_req_end_write(req);
		fsnotify_modify(req->file);  // File modification notification
	} else {
		fsnotify_access(req->file);  // File access notification
	}
}

/* Common completion handling for read/write operations */
static void __io_complete_rw_common(struct io_kiocb *req, long res)
{
	if (res == req->cqe.res)
		return;
	if (res == -EAGAIN && io_rw_should_reissue(req)) {
		/* Mark for reissue and prevent buffer recycling */
		req->flags |= REQ_F_REISSUE | REQ_F_BL_NO_RECYCLE;
	} else {
		req_set_fail(req);
		req->cqe.res = res;
	}
}

/* Fix up the result by adding previously done IO for partial operations */
static inline int io_fixup_rw_res(struct io_kiocb *req, long res)
{
	struct io_async_rw *io = req->async_data;

	/* Add previously done IO, if any */
	if (req_has_async_data(req) && io->bytes_done > 0) {
		if (res < 0)
			res = io->bytes_done;
		else
			res += io->bytes_done;
	}
	return res;
}

/* Complete read/write request */
void io_req_rw_complete(struct io_kiocb *req, io_tw_token_t tw)
{
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
	struct kiocb *kiocb = &rw->kiocb;

	/* Handle DIO caller completion if needed */
	if ((kiocb->ki_flags & IOCB_DIO_CALLER_COMP) && kiocb->dio_complete) {
		long res = kiocb->dio_complete(rw->kiocb.private);
		io_req_set_res(req, io_fixup_rw_res(req, res), 0);
	}

	io_req_io_end(req);

	/* Return buffer if one was selected */
	if (req->flags & (REQ_F_BUFFER_SELECTED|REQ_F_BUFFER_RING))
		req->cqe.flags |= io_put_kbuf(req, req->cqe.res, 0);

	io_req_rw_cleanup(req, 0);
	io_req_task_complete(req, tw);
}

/* Normal (non-iopoll) completion handler */
static void io_complete_rw(struct kiocb *kiocb, long res)
{
	struct io_rw *rw = container_of(kiocb, struct io_rw, kiocb);
	struct io_kiocb *req = cmd_to_io_kiocb(rw);

	if (!kiocb->dio_complete || !(kiocb->ki_flags & IOCB_DIO_CALLER_COMP)) {
		__io_complete_rw_common(req, res);
		io_req_set_res(req, io_fixup_rw_res(req, res), 0);
	}
	/* Schedule completion via task work */
	req->io_task_work.func = io_req_rw_complete;
	__io_req_task_work_add(req, IOU_F_TWQ_LAZY_WAKE);
}

/* IOPOLL completion handler */
static void io_complete_rw_iopoll(struct kiocb *kiocb, long res)
{
	struct io_rw *rw = container_of(kiocb, struct io_rw, kiocb);
	struct io_kiocb *req = cmd_to_io_kiocb(rw);

	if (kiocb->ki_flags & IOCB_WRITE)
		io_req_end_write(req);
	if (unlikely(res != req->cqe.res)) {
		if (res == -EAGAIN && io_rw_should_reissue(req))
			req->flags |= REQ_F_REISSUE | REQ_F_BL_NO_RECYCLE;
		else
			req->cqe.res = res;
	}

	/* Mark completion for iopoll */
	smp_store_release(&req->iopoll_completed, 1);
}

/* Finalize read/write operation result */
static inline void io_rw_done(struct io_kiocb *req, ssize_t ret)
{
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);

	/* IO was queued async, completion will happen later */
	if (ret == -EIOCBQUEUED)
		return;

	/* Transform internal restart error codes to EINTR */
	if (unlikely(ret < 0)) {
		switch (ret) {
		case -ERESTARTSYS:
		case -ERESTARTNOINTR:
		case -ERESTARTNOHAND:
		case -ERESTART_RESTARTBLOCK:
			ret = -EINTR;
			break;
		}
	}

	/* Call appropriate completion handler */
	if (req->ctx->flags & IORING_SETUP_IOPOLL)
		io_complete_rw_iopoll(&rw->kiocb, ret);
	else
		io_complete_rw(&rw->kiocb, ret);
}

/* Handle completion of kiocb operation */
static int kiocb_done(struct io_kiocb *req, ssize_t ret,
		       unsigned int issue_flags)
{
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
	unsigned final_ret = io_fixup_rw_res(req, ret);

	/* Update file position if needed */
	if (ret >= 0 && req->flags & REQ_F_CUR_POS)
		req->file->f_pos = rw->kiocb.ki_pos;
	
	/* Handle non-iopoll case inline */
	if (ret >= 0 && !(req->ctx->flags & IORING_SETUP_IOPOLL)) {
		__io_complete_rw_common(req, ret);
		io_req_io_end(req);
		io_req_set_res(req, final_ret, io_put_kbuf(req, ret, issue_flags));
		io_req_rw_cleanup(req, issue_flags);
		return IOU_OK;
	} else {
		io_rw_done(req, ret);
	}

	return IOU_ISSUE_SKIP_COMPLETE;
}

/* Get position pointer for kiocb, handling stream files */
static inline loff_t *io_kiocb_ppos(struct kiocb *kiocb)
{
	return (kiocb->ki_filp->f_mode & FMODE_STREAM) ? NULL : &kiocb->ki_pos;
}

/*
 * Fallback for files without ->read_iter()/->write_iter() by looping over
 * ->read()/->write() manually.
 */
static ssize_t loop_rw_iter(int ddir, struct io_rw *rw, struct iov_iter *iter)
{
	struct io_kiocb *req = cmd_to_io_kiocb(rw);
	struct kiocb *kiocb = &rw->kiocb;
	struct file *file = kiocb->ki_filp;
	ssize_t ret = 0;
	loff_t *ppos;

	/* Don't support polled or non-blocking IO through this path */
	if (kiocb->ki_flags & IOCB_HIPRI)
		return -EOPNOTSUPP;
	if ((kiocb->ki_flags & IOCB_NOWAIT) &&
	    !(kiocb->ki_filp->f_flags & O_NONBLOCK))
		return -EAGAIN;
	if ((req->flags & REQ_F_BUF_NODE) && req->buf_node->buf->is_kbuf)
		return -EFAULT;

	ppos = io_kiocb_ppos(kiocb);

	/* Manual loop for each segment */
	while (iov_iter_count(iter)) {
		void __user *addr;
		size_t len;
		ssize_t nr;

		/* Get address and length for current segment */
		if (iter_is_ubuf(iter)) {
			addr = iter->ubuf + iter->iov_offset;
			len = iov_iter_count(iter);
		} else if (!iov_iter_is_bvec(iter)) {
			addr = iter_iov_addr(iter);
			len = iter_iov_len(iter);
		} else {
			addr = u64_to_user_ptr(rw->addr);
			len = rw->len;
		}

		/* Perform the actual read/write */
		if (ddir == READ)
			nr = file->f_op->read(file, addr, len, ppos);
		else
			nr = file->f_op->write(file, addr, len, ppos);

		if (nr < 0) {
			if (!ret)
				ret = nr;
			break;
		}
		ret += nr;
		
		/* Advance the iterator */
		if (!iov_iter_is_bvec(iter)) {
			iov_iter_advance(iter, nr);
		} else {
			rw->addr += nr;
			rw->len -= nr;
			if (!rw->len)
				break;
		}
		if (nr != len)
			break;
	}

	return ret;
}

/*
 * Async buffer waitqueue callback handler - called when page is unlocked
 * after IO completion. This queues a task_work based retry of the operation.
 */
static int io_async_buf_func(struct wait_queue_entry *wait, unsigned mode,
			     int sync, void *arg)
{
	struct wait_page_queue *wpq;
	struct io_kiocb *req = wait->private;
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
	struct wait_page_key *key = arg;

	wpq = container_of(wait, struct wait_page_queue, wait);

	if (!wake_page_match(wpq, key))
		return 0;

	/* Clear WAITQ flag and remove from wait queue */
	rw->kiocb.ki_flags &= ~IOCB_WAITQ;
	list_del_init(&wait->entry);
	io_req_task_queue(req);
	return 1;
}

/* Determine if a read operation should use async page retry mechanism */
static bool io_rw_should_retry(struct io_kiocb *req)
{
	struct io_async_rw *io = req->async_data;
	struct wait_page_queue *wait = &io->wpq;
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
	struct kiocb *kiocb = &rw->kiocb;

	/* Never retry for NOWAIT or metadata requests */
	if (req->flags & (REQ_F_NOWAIT | REQ_F_HAS_METADATA))
		return false;

	/* Only for buffered IO */
	if (kiocb->ki_flags & (IOCB_DIRECT | IOCB_HIPRI))
		return false;

	/* Don't attempt if we can poll or fs doesn't support async unlocks */
	if (io_file_can_poll(req) ||
	    !(req->file->f_op->fop_flags & FOP_BUFFER_RASYNC))
		return false;

	/* Setup waitqueue entry for async retry */
	wait->wait.func = io_async_buf_func;
	wait->wait.private = req;
	wait->wait.flags = 0;
	INIT_LIST_HEAD(&wait->wait.entry);
	kiocb->ki_flags |= IOCB_WAITQ;
	kiocb->ki_flags &= ~IOCB_NOWAIT;
	kiocb->ki_waitq = wait;
	return true;
}

/* Perform read operation using appropriate file operations */
static inline int io_iter_do_read(struct io_rw *rw, struct iov_iter *iter)
{
	struct file *file = rw->kiocb.ki_filp;

	if (likely(file->f_op->read_iter))
		return file->f_op->read_iter(&rw->kiocb, iter);
	else if (file->f_op->read)
		return loop_rw_iter(READ, rw, iter);
	else
		return -EINVAL;
}

/* Check if operation needs complete_io handling (regular files/block devices) */
static bool need_complete_io(struct io_kiocb *req)
{
	return req->flags & REQ_F_ISREG ||
		S_ISBLK(file_inode(req->file)->i_mode);
}

/* Initialize file for read/write operation */
static int io_rw_init_file(struct io_kiocb *req, fmode_t mode, int rw_type)
{
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
	struct kiocb *kiocb = &rw->kiocb;
	struct io_ring_ctx *ctx = req->ctx;
	struct file *file = req->file;
	int ret;

	/* Check file mode */
	if (unlikely(!(file->f_mode & mode)))
		return -EBADF;

	/* Get file flags if not fixed file */
	if (!(req->flags & REQ_F_FIXED_FILE))
		req->flags |= io_file_get_flags(file);

	kiocb->ki_flags = file->f_iocb_flags;
	ret = kiocb_set_rw_flags(kiocb, rw->flags, rw_type);
	if (unlikely(ret))
		return ret;
	kiocb->ki_flags |= IOCB_ALLOC_CACHE;

	/*
	 * Handle NOWAIT cases:
	 * - If IOCB_NOWAIT is set
	 * - Or file is O_NONBLOCK but doesn't support NOWAIT
	 */
	if (kiocb->ki_flags & IOCB_NOWAIT ||
	    ((file->f_flags & O_NONBLOCK && !(req->flags & REQ_F_SUPPORT_NOWAIT))))
		req->flags |= REQ_F_NOWAIT;

	/* IOPOLL setup */
	if (ctx->flags & IORING_SETUP_IOPOLL) {
		if (!(kiocb->ki_flags & IOCB_DIRECT) || !file->f_op->iopoll)
			return -EOPNOTSUPP;
		kiocb->private = NULL;
		kiocb->ki_flags |= IOCB_HIPRI;
		req->iopoll_completed = 0;
		if (ctx->flags & IORING_SETUP_HYBRID_IOPOLL) {
			req->flags &= ~REQ_F_IOPOLL_STATE;
			req->iopoll_start = ktime_get_ns();
		}
	} else {
		if (kiocb->ki_flags & IOCB_HIPRI)
			return -EINVAL;
	}

	/* Metadata handling */
	if (req->flags & REQ_F_HAS_METADATA) {
		struct io_async_rw *io = req->async_data;

		/* Metadata only supported for O_DIRECT */
		if (!(req->file->f_flags & O_DIRECT))
			return -EOPNOTSUPP;
		kiocb->ki_flags |= IOCB_HAS_METADATA;
		kiocb->private = &io->meta;
	}

	return 0;
}

/* Main read operation handler */
static int __io_read(struct io_kiocb *req, unsigned int issue_flags)
{
	bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
	struct io_async_rw *io = req->async_data;
	struct kiocb *kiocb = &rw->kiocb;
	ssize_t ret;
	loff_t *ppos;

	/* Import buffers */
	if (req->flags & REQ_F_IMPORT_BUFFER) {
		ret = io_rw_import_reg_vec(req, io, ITER_DEST, issue_flags);
		if (unlikely(ret))
			return ret;
	} else if (io_do_buffer_select(req)) {
		ret = io_import_rw_buffer(ITER_DEST, req, io, issue_flags);
		if (unlikely(ret < 0))
			return ret;
	}
	
	/* Initialize file for reading */
	ret = io_rw_init_file(req, FMODE_READ, READ);
	if (unlikely(ret))
		return ret;
	req->cqe.res = iov_iter_count(&io->iter);

	/* Handle non-blocking case */
	if (force_nonblock) {
		if (unlikely(!io_file_supports_nowait(req, EPOLLIN)))
			return -EAGAIN;
		kiocb->ki_flags |= IOCB_NOWAIT;
	} else {
		kiocb->ki_flags &= ~IOCB_NOWAIT;
	}

	ppos = io_kiocb_update_pos(req);

	/* Verify read area */
	ret = rw_verify_area(READ, req->file, ppos, req->cqe.res);
	if (unlikely(ret))
		return ret;

	/* Perform the actual read */
	ret = io_iter_do_read(rw, &io->iter);

	/* Transform -EOPNOTSUPP to -EAGAIN for non-blocking case */
	if (ret == -EOPNOTSUPP && force_nonblock)
		ret = -EAGAIN;

	if (ret == -EAGAIN) {
		/* If we can poll, just do that */
		if (io_file_can_poll(req))
			return -EAGAIN;
		/* IOPOLL retry should happen for io-wq threads */
		if (!force_nonblock && !(req->ctx->flags & IORING_SETUP_IOPOLL))
			goto done;
		/* No retry on NONBLOCK nor RWF_NOWAIT */
		if (req->flags & REQ_F_NOWAIT)
			goto done;
		ret = 0;
	} else if (ret == -EIOCBQUEUED) {
		return IOU_ISSUE_SKIP_COMPLETE;
	} else if (ret == req->cqe.res || ret <= 0 || !force_nonblock ||
		   (req->flags & REQ_F_NOWAIT) || !need_complete_io(req) ||
		   (issue_flags & IO_URING_F_MULTISHOT)) {
		goto done;
	}

	/*
	 * Partial read handling - restore iterator state and retry
	 */
	iov_iter_restore(&io->iter, &io->iter_state);
	io_meta_restore(io, kiocb);

	/* Retry loop for partial reads */
	do {
		/* Advance iterator by bytes consumed */
		iov_iter_advance(&io->iter, ret);
		if (!iov_iter_count(&io->iter))
			break;
		io->bytes_done += ret;
		iov_iter_save_state(&io->iter, &io->iter_state);

		/* Check if we should retry with async mechanism */
		if (!io_rw_should_retry(req)) {
			kiocb->ki_flags &= ~IOCB_WAITQ;
			return -EAGAIN;
		}

		req->cqe.res = iov_iter_count(&io->iter);
		/* Retry read with IOCB_WAITQ set */
		ret = io_iter_do_read(rw, &io->iter);
		if (ret == -EIOCBQUEUED)
			return IOU_ISSUE_SKIP_COMPLETE;
		kiocb->ki_flags &= ~IOCB_WAITQ;
		iov_iter_restore(&io->iter, &io->iter_state);
	} while (ret > 0);
done:
	return ret;
}

int io_read(struct io_kiocb *req, unsigned int issue_flags)
{
	int ret;

	ret = __io_read(req, issue_flags);
	if (ret >= 0)
		return kiocb_done(req, ret, issue_flags);

	return ret;
}

int io_read_mshot(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
	unsigned int cflags = 0;
	int ret;

	/*
	 * Multishot MUST be used on a pollable file
	 */
	if (!io_file_can_poll(req))
		return -EBADFD;

	/* make it sync, multishot doesn't support async execution */
	rw->kiocb.ki_complete = NULL;
	ret = __io_read(req, issue_flags);

	/*
	 * If we get -EAGAIN, recycle our buffer and just let normal poll
	 * handling arm it.
	 */
	if (ret == -EAGAIN) {
		/*
		 * Reset rw->len to 0 again to avoid clamping future mshot
		 * reads, in case the buffer size varies.
		 */
		if (io_kbuf_recycle(req, issue_flags))
			rw->len = 0;
		return IOU_RETRY;
	} else if (ret <= 0) {
		io_kbuf_recycle(req, issue_flags);
		if (ret < 0)
			req_set_fail(req);
	} else if (!(req->flags & REQ_F_APOLL_MULTISHOT)) {
		cflags = io_put_kbuf(req, ret, issue_flags);
	} else {
		/*
		 * Any successful return value will keep the multishot read
		 * armed, if it's still set. Put our buffer and post a CQE. If
		 * we fail to post a CQE, or multishot is no longer set, then
		 * jump to the termination path. This request is then done.
		 */
		cflags = io_put_kbuf(req, ret, issue_flags);
		rw->len = 0; /* similarly to above, reset len to 0 */

		if (io_req_post_cqe(req, ret, cflags | IORING_CQE_F_MORE)) {
			if (issue_flags & IO_URING_F_MULTISHOT)
				/*
				 * Force retry, as we might have more data to
				 * be read and otherwise it won't get retried
				 * until (if ever) another poll is triggered.
				 */
				io_poll_multishot_retry(req);

			return IOU_RETRY;
		}
	}

	/*
	 * Either an error, or we've hit overflow posting the CQE. For any
	 * multishot request, hitting overflow will terminate it.
	 */
	io_req_set_res(req, ret, cflags);
	io_req_rw_cleanup(req, issue_flags);
	return IOU_COMPLETE;
}

static bool io_kiocb_start_write(struct io_kiocb *req, struct kiocb *kiocb)
{
	struct inode *inode;
	bool ret;

	if (!(req->flags & REQ_F_ISREG))
		return true;
	if (!(kiocb->ki_flags & IOCB_NOWAIT)) {
		kiocb_start_write(kiocb);
		return true;
	}

	inode = file_inode(kiocb->ki_filp);
	ret = sb_start_write_trylock(inode->i_sb);
	if (ret)
		__sb_writers_release(inode->i_sb, SB_FREEZE_WRITE);
	return ret;
}

int io_write(struct io_kiocb *req, unsigned int issue_flags)
{
	bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;
	struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);
	struct io_async_rw *io = req->async_data;
	struct kiocb *kiocb = &rw->kiocb;
	ssize_t ret, ret2;
	loff_t *ppos;

	if (req->flags & REQ_F_IMPORT_BUFFER) {
		ret = io_rw_import_reg_vec(req, io, ITER_SOURCE, issue_flags);
		if (unlikely(ret))
			return ret;
	}

	ret = io_rw_init_file(req, FMODE_WRITE, WRITE);
	if (unlikely(ret))
		return ret;
	req->cqe.res = iov_iter_count(&io->iter);

	if (force_nonblock) {
		/* If the file doesn't support async, just async punt */
		if (unlikely(!io_file_supports_nowait(req, EPOLLOUT)))
			goto ret_eagain;

		/* Check if we can support NOWAIT. */
		if (!(kiocb->ki_flags & IOCB_DIRECT) &&
		    !(req->file->f_op->fop_flags & FOP_BUFFER_WASYNC) &&
		    (req->flags & REQ_F_ISREG))
			goto ret_eagain;

		kiocb->ki_flags |= IOCB_NOWAIT;
	} else {
		/* Ensure we clear previously set non-block flag */
		kiocb->ki_flags &= ~IOCB_NOWAIT;
	}

	ppos = io_kiocb_update_pos(req);

	ret = rw_verify_area(WRITE, req->file, ppos, req->cqe.res);
	if (unlikely(ret))
		return ret;

	if (unlikely(!io_kiocb_start_write(req, kiocb)))
		return -EAGAIN;
	kiocb->ki_flags |= IOCB_WRITE;

	if (likely(req->file->f_op->write_iter))
		ret2 = req->file->f_op->write_iter(kiocb, &io->iter);
	else if (req->file->f_op->write)
		ret2 = loop_rw_iter(WRITE, rw, &io->iter);
	else
		ret2 = -EINVAL;

	/*
	 * Raw bdev writes will return -EOPNOTSUPP for IOCB_NOWAIT. Just
	 * retry them without IOCB_NOWAIT.
	 */
	if (ret2 == -EOPNOTSUPP && (kiocb->ki_flags & IOCB_NOWAIT))
		ret2 = -EAGAIN;
	/* no retry on NONBLOCK nor RWF_NOWAIT */
	if (ret2 == -EAGAIN && (req->flags & REQ_F_NOWAIT))
		goto done;
	if (!force_nonblock || ret2 != -EAGAIN) {
		/* IOPOLL retry should happen for io-wq threads */
		if (ret2 == -EAGAIN && (req->ctx->flags & IORING_SETUP_IOPOLL))
			goto ret_eagain;

		if (ret2 != req->cqe.res && ret2 >= 0 && need_complete_io(req)) {
			trace_io_uring_short_write(req->ctx, kiocb->ki_pos - ret2,
						req->cqe.res, ret2);

			/* This is a partial write. The file pos has already been
			 * updated, setup the async struct to complete the request
			 * in the worker. Also update bytes_done to account for
			 * the bytes already written.
			 */
			iov_iter_save_state(&io->iter, &io->iter_state);
			io->bytes_done += ret2;

			if (kiocb->ki_flags & IOCB_WRITE)
				io_req_end_write(req);
			return -EAGAIN;
		}
done:
		return kiocb_done(req, ret2, issue_flags);
	} else {
ret_eagain:
		iov_iter_restore(&io->iter, &io->iter_state);
		io_meta_restore(io, kiocb);
		if (kiocb->ki_flags & IOCB_WRITE)
			io_req_end_write(req);
		return -EAGAIN;
	}
}

int io_read_fixed(struct io_kiocb *req, unsigned int issue_flags)
{
	int ret;

	ret = io_init_rw_fixed(req, issue_flags, ITER_DEST);
	if (unlikely(ret))
		return ret;

	return io_read(req, issue_flags);
}

int io_write_fixed(struct io_kiocb *req, unsigned int issue_flags)
{
	int ret;

	ret = io_init_rw_fixed(req, issue_flags, ITER_SOURCE);
	if (unlikely(ret))
		return ret;

	return io_write(req, issue_flags);
}

void io_rw_fail(struct io_kiocb *req)
{
	int res;

	res = io_fixup_rw_res(req, req->cqe.res);
	io_req_set_res(req, res, req->cqe.flags);
}

static int io_uring_classic_poll(struct io_kiocb *req, struct io_comp_batch *iob,
				unsigned int poll_flags)
{
	struct file *file = req->file;

	if (req->opcode == IORING_OP_URING_CMD) {
		struct io_uring_cmd *ioucmd;

		ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
		return file->f_op->uring_cmd_iopoll(ioucmd, iob, poll_flags);
	} else {
		struct io_rw *rw = io_kiocb_to_cmd(req, struct io_rw);

		return file->f_op->iopoll(&rw->kiocb, iob, poll_flags);
	}
}

static u64 io_hybrid_iopoll_delay(struct io_ring_ctx *ctx, struct io_kiocb *req)
{
	struct hrtimer_sleeper timer;
	enum hrtimer_mode mode;
	ktime_t kt;
	u64 sleep_time;

	if (req->flags & REQ_F_IOPOLL_STATE)
		return 0;

	if (ctx->hybrid_poll_time == LLONG_MAX)
		return 0;

	/* Using half the running time to do schedule */
	sleep_time = ctx->hybrid_poll_time / 2;

	kt = ktime_set(0, sleep_time);
	req->flags |= REQ_F_IOPOLL_STATE;

	mode = HRTIMER_MODE_REL;
	hrtimer_setup_sleeper_on_stack(&timer, CLOCK_MONOTONIC, mode);
	hrtimer_set_expires(&timer.timer, kt);
	set_current_state(TASK_INTERRUPTIBLE);
	hrtimer_sleeper_start_expires(&timer, mode);

	if (timer.task)
		io_schedule();

	hrtimer_cancel(&timer.timer);
	__set_current_state(TASK_RUNNING);
	destroy_hrtimer_on_stack(&timer.timer);
	return sleep_time;
}

static int io_uring_hybrid_poll(struct io_kiocb *req,
				struct io_comp_batch *iob, unsigned int poll_flags)
{
	struct io_ring_ctx *ctx = req->ctx;
	u64 runtime, sleep_time;
	int ret;

	sleep_time = io_hybrid_iopoll_delay(ctx, req);
	ret = io_uring_classic_poll(req, iob, poll_flags);
	runtime = ktime_get_ns() - req->iopoll_start - sleep_time;

	/*
	 * Use minimum sleep time if we're polling devices with different
	 * latencies. We could get more completions from the faster ones.
	 */
	if (ctx->hybrid_poll_time > runtime)
		ctx->hybrid_poll_time = runtime;

	return ret;
}

int io_do_iopoll(struct io_ring_ctx *ctx, bool force_nonspin)
{
	struct io_wq_work_node *pos, *start, *prev;
	unsigned int poll_flags = 0;
	DEFINE_IO_COMP_BATCH(iob);
	int nr_events = 0;

	/*
	 * Only spin for completions if we don't have multiple devices hanging
	 * off our complete list.
	 */
	if (ctx->poll_multi_queue || force_nonspin)
		poll_flags |= BLK_POLL_ONESHOT;

	wq_list_for_each(pos, start, &ctx->iopoll_list) {
		struct io_kiocb *req = container_of(pos, struct io_kiocb, comp_list);
		int ret;

		/*
		 * Move completed and retryable entries to our local lists.
		 * If we find a request that requires polling, break out
		 * and complete those lists first, if we have entries there.
		 */
		if (READ_ONCE(req->iopoll_completed))
			break;

		if (ctx->flags & IORING_SETUP_HYBRID_IOPOLL)
			ret = io_uring_hybrid_poll(req, &iob, poll_flags);
		else
			ret = io_uring_classic_poll(req, &iob, poll_flags);

		if (unlikely(ret < 0))
			return ret;
		else if (ret)
			poll_flags |= BLK_POLL_ONESHOT;

		/* iopoll may have completed current req */
		if (!rq_list_empty(&iob.req_list) ||
		    READ_ONCE(req->iopoll_completed))
			break;
	}

	if (!rq_list_empty(&iob.req_list))
		iob.complete(&iob);
	else if (!pos)
		return 0;

	prev = start;
	wq_list_for_each_resume(pos, prev) {
		struct io_kiocb *req = container_of(pos, struct io_kiocb, comp_list);

		/* order with io_complete_rw_iopoll(), e.g. ->result updates */
		if (!smp_load_acquire(&req->iopoll_completed))
			break;
		nr_events++;
		req->cqe.flags = io_put_kbuf(req, req->cqe.res, 0);
		if (req->opcode != IORING_OP_URING_CMD)
			io_req_rw_cleanup(req, 0);
	}
	if (unlikely(!nr_events))
		return 0;

	pos = start ? start->next : ctx->iopoll_list.first;
	wq_list_cut(&ctx->iopoll_list, prev, start);

	if (WARN_ON_ONCE(!wq_list_empty(&ctx->submit_state.compl_reqs)))
		return 0;
	ctx->submit_state.compl_reqs.first = pos;
	__io_submit_flush_completions(ctx);
	return nr_events;
}

void io_rw_cache_free(const void *entry)
{
	struct io_async_rw *rw = (struct io_async_rw *) entry;

	io_vec_free(&rw->vec);
	kfree(rw);
}
