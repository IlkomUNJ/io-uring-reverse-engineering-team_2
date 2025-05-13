// SPDX-License-Identifier: GPL-2.0
#ifndef IORING_REGISTER_H
#define IORING_REGISTER_H

/* 
 * Unregisters previously registered eventfd from an io_uring context.
 * Removes the association between eventfd and ring, stopping completion notifications.
 */
int io_eventfd_unregister(struct io_ring_ctx *ctx);

/* 
 * Unregisters a personality (credential set) from an io_uring context.
 * Removes credential mapping associated with the given personality ID and frees resources.
 */
int io_unregister_personality(struct io_ring_ctx *ctx, unsigned id);

/* 
 * Retrieves file structure for a file descriptor with registration awareness.
 * Handles both regular file descriptors and those registered with io_uring, based on the registered flag.
 */
struct file *io_uring_register_get_file(unsigned int fd, bool registered);

#endif
