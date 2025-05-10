# Task 1: Information about io_uring source
List in this section source and headers of io_uring. For each of the C source/header, you must put description what's the prime responsibily of the source. Take notes, description of the source should be slightly technical like the example given. 

## Source
### advice.c
Store io_madvice & io_fadvice structures, both have the same exact attributes. Which make them basically the same thing. Except function body treat them as separate. Codes which make use of io_madvice are guarded by compilation macro, which make its relevant functions only active if the build flag is set. But functions that make use of io_fadvice are active all the time. The exact difference between io_madvice & io_fadvice will only known after exploring do_madvise function for io_madvice & vfs_fadvise function for io_fadvice. 

### alloc_cache.c
Implements memory allocation caching for io_uring operations. Provides efficient memory management for request structures and reuses allocated memory to reduce overhead of repeated allocations. It contains all the functions needed to allocate, free, and manage these memory chunks efficiently.

### cancel.c
Handles cancellation of pending io_uring operations. Implements mechanisms that allows users to cancel submitted but not yet completed requests in the submission queue. Includes logic for selective cancellation by request type, file descriptor, or user data associated with requests.

### epoll.c
Implements epoll integration with io_uring for event notification. Allows io_uring to monitor file descriptors for events using the epoll interface. Provides functionality to register, modify, and deregister epoll interest on file descriptors through the io_uring interface.

### eventfd.c
Handles eventfd integration with io_uring. Manages the creation and signaling of eventfd descriptors for notification of io_uring events. Allows applications to efficiently wait for io_uring completion events using the eventfd mechanism.

### fdinfo.c
Provides file descriptor information management for io_uring. Handles tracking and management of file descriptors used in io_uring operations. Maintains reference counts and state information for file descriptors registered with io_uring instances.

### filetable.c
Implements fixed file table functionality for io_uring. Manages pre-registered file descriptors that can be referenced by index rather than descriptor number. Increasig file access efficiency by avoiding repeated file lookups and permission checks.

### fs.c
Handles filesystem-related io_uring operations. Implements common functionality used by various filesystem operations (read, write, sync, etc.). Provides abstractions over VFS operations for the io_uring interface.

### futex.c
Implements futex (fast userspace mutex) operations for io_uring. Allows applications to perform futex wait and wake operations asynchronously through the io_uring interface. Provides synchronization primitives for userspace applications.

### io_uring.c
The core of the io_uring subsystem. Implements the main io_uring functionality, including setup and teardown of io_uring instances, request handling, and completion processing. Acts as the central coordination point for all io_uring operations.

### io-wq.c
Implements the io_uring workqueue system. Manages worker threads that process io_uring requests asynchronously. Handles thread creation, scheduling, and load balancing of workers for optimal performance.

### kbuf.c
Manages kernel buffers used by io_uring operations. Provides functions for allocation, mapping, and access control of kernel memory buffers. Implements zero-copy optimizations for data transfers between kernel and userspace.

### memmap.c
Handles memory mapping operations for io_uring. Implements mmap and munmap functionality through the io_uring interface. Manages virtual memory areas and memory protection for io_uring operations.

### msg_ring.c
Implements the message ring functionality for io_uring. Allows io_uring instances to communicate with each other by sending messages through rings. Provides inter-ring communication mechanisms for complex I/O patterns.

### napi.c
Implements Network API integration with io_uring. Provides networking-specific optimizations by integrating with the NAPI (New API) polling mechanism used in Linux networking. Optimizes packet processing performance.

### net.c
Handles networking-specific io_uring operations. Implements send, receive, and other socket operations for the io_uring interface. Provides asynchronous networking I/O functionality for sockets.

### nop.c
Implements the NOP (no-operation) command for io_uring. Provides a lightweight operation that goes through the io_uring processing pipeline but performs no actual work. Useful for testing and benchmarking.

### notif.c
Manages notifications for io_uring operations. Implements various notification mechanisms for completion events. Coordinates signaling between kernel and userspace when operations complete.


## Headers
### advice.h
Just declare the function specification. 