// SPDX-License-Identifier: GPL-2.0

#include <linux/net.h>
#include <linux/uio.h>
#include <linux/io_uring_types.h>

struct io_async_msghdr {
#if defined(CONFIG_NET)
	struct iou_vec				vec;

	struct_group(clear,
		int				namelen;
		struct iovec			fast_iov;
		__kernel_size_t			controllen;
		__kernel_size_t			payloadlen;
		struct sockaddr __user		*uaddr;
		struct msghdr			msg;
		struct sockaddr_storage		addr;
	);
#else
	struct_group(clear);
#endif
};

#if defined(CONFIG_NET)

/* 
 Prepares for a socket shutdown operation.
 Sets up the necessary data structures for handling a socket shutdown request.
*/
int io_shutdown_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* 
 Executes a socket shutdown operation.
 Performs the actual socket shutdown based on the previously prepared parameters.
*/
int io_shutdown(struct io_kiocb *req, unsigned int issue_flags);

/* 
 Cleans up resources used by sendmsg and recvmsg operations.
 Frees memory allocated for async message handlers and associated data structures.
*/
void io_sendmsg_recvmsg_cleanup(struct io_kiocb *req);

/* 
 Prepares a sendmsg request.
 Sets up the necessary data structures for handling a socket send message request.
*/
int io_sendmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* 
 Executes a sendmsg operation.
 Performs the actual socket send message based on the previously prepared parameters.
*/
int io_sendmsg(struct io_kiocb *req, unsigned int issue_flags);

/* 
 Executes a send operation.
 Performs a simpler socket send operation with fewer parameters than sendmsg.
*/
int io_send(struct io_kiocb *req, unsigned int issue_flags);

/* 
 Prepares a recvmsg request.
 Sets up the necessary data structures for handling a socket receive message request.
*/
int io_recvmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* 
 Executes a recvmsg operation.
 Performs the actual socket receive message based on the previously prepared parameters.
*/
int io_recvmsg(struct io_kiocb *req, unsigned int issue_flags);

/* 
 Executes a recv operation.
 Performs a simpler socket receive operation with fewer parameters than recvmsg.
*/
int io_recv(struct io_kiocb *req, unsigned int issue_flags);

/* 
 Handles failures in send/receive operations.
 Updates completion queue entries with appropriate error codes when operations fail.
*/
void io_sendrecv_fail(struct io_kiocb *req);

/* 
 Prepares an accept request.
 Sets up the necessary data structures for handling a socket accept request.
*/
int io_accept_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* 
 Executes an accept operation.
 Performs the actual socket accept based on the previously prepared parameters.
*/
int io_accept(struct io_kiocb *req, unsigned int issue_flags);

/* 
 Prepares a socket creation request.
 Sets up the necessary data structures for creating a new socket.
*/
int io_socket_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* 
 Executes a socket creation operation.
 Creates a new socket based on the previously prepared parameters.
*/
int io_socket(struct io_kiocb *req, unsigned int issue_flags);

/* 
 Prepares a connect request.
 Sets up the necessary data structures for connecting to a remote endpoint.
*/
int io_connect_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* 
 Executes a connect operation.
 Establishes a connection to a remote endpoint based on the previously prepared parameters.
*/
int io_connect(struct io_kiocb *req, unsigned int issue_flags);

/* 
 Executes a zero-copy send operation.
 Performs a socket send with reduced copying of data buffers for better performance.
*/
int io_send_zc(struct io_kiocb *req, unsigned int issue_flags);

/* 
 Executes a zero-copy sendmsg operation.
 Performs a socket sendmsg with reduced copying of data buffers for better performance.
*/
int io_sendmsg_zc(struct io_kiocb *req, unsigned int issue_flags);

/* 
 Prepares a zero-copy send operation.
 Sets up the necessary data structures for zero-copy socket sends.
*/
int io_send_zc_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* 
 Cleans up resources from a zero-copy send operation.
 Frees memory and releases references used in zero-copy sends.
*/
void io_send_zc_cleanup(struct io_kiocb *req);

/* 
 Prepares a bind request.
 Sets up the necessary data structures for binding a socket to a local address.
*/
int io_bind_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* 
 Executes a bind operation.
 Binds a socket to a local address based on the previously prepared parameters.
*/
int io_bind(struct io_kiocb *req, unsigned int issue_flags);

/* 
 Prepares a listen request.
 Sets up the necessary data structures for putting a socket in listening state.
*/
int io_listen_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* 
 Executes a listen operation.
 Makes a socket listen for incoming connections based on the previously prepared parameters.
*/
int io_listen(struct io_kiocb *req, unsigned int issue_flags);

/* 
 Frees cached network message structures.
 Releases resources allocated for network message caching to prevent memory leaks.
*/
void io_netmsg_cache_free(const void *entry);
#else
static inline void io_netmsg_cache_free(const void *entry)
{
}
#endif
