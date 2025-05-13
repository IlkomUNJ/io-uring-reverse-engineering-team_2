#ifndef IOU_REQ_REF_H
#define IOU_REQ_REF_H

#include <linux/atomic.h>
#include <linux/io_uring_types.h>

/*
 * Shamelessly stolen from the mm implementation of page reference checking,
 * see commit f958d7b528b1 for details.
 */
#define req_ref_zero_or_close_to_overflow(req)	\
    ((unsigned int) atomic_read(&(req->refs)) + 127u <= 127u)

/* 
 * Atomically increments the reference counter if not zero.
 * Ensures requests with active references stay alive during concurrent operations.
 */
static inline bool req_ref_inc_not_zero(struct io_kiocb *req)
{
    WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));
    return atomic_inc_not_zero(&req->refs);
}

/* 
 * Decrements reference counter and checks if it reached zero in an atomic operation.
 * Handles potential race conditions with data_race flag check for requests being accessed concurrently.
 */
static inline bool req_ref_put_and_test_atomic(struct io_kiocb *req)
{
    WARN_ON_ONCE(!(data_race(req->flags) & REQ_F_REFCOUNT));
    WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
    return atomic_dec_and_test(&req->refs);
}

/* 
 * Decreases request reference count and tests if it reached zero.
 * Handles both refcounted and non-refcounted requests with appropriate behavior for each.
 */
static inline bool req_ref_put_and_test(struct io_kiocb *req)
{
    if (likely(!(req->flags & REQ_F_REFCOUNT)))
        return true;

    WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
    return atomic_dec_and_test(&req->refs);
}

/* 
 * Increases the reference count of a request.
 * Prevents request deallocation while operations are being performed on it.
 */
static inline void req_ref_get(struct io_kiocb *req)
{
    WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));
    WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
    atomic_inc(&req->refs);
}

/* 
 * Decreases the reference count of a request.
 * Helps track when a request can be safely deallocated when no references remain.
 */
static inline void req_ref_put(struct io_kiocb *req)
{
    WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));
    WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
    atomic_dec(&req->refs);
}

/* 
 * Initializes reference counting for a request with specified count.
 * Sets the refcount flag and initial reference count if not already set.
 */
static inline void __io_req_set_refcount(struct io_kiocb *req, int nr)
{
    if (!(req->flags & REQ_F_REFCOUNT)) {
        req->flags |= REQ_F_REFCOUNT;
        atomic_set(&req->refs, nr);
    }
}

/* 
 * Enables reference counting for a request with initial count of 1.
 * Convenient wrapper around __io_req_set_refcount for the common case.
 */
static inline void io_req_set_refcount(struct io_kiocb *req)
{
    __io_req_set_refcount(req, 1);
}
#endif
