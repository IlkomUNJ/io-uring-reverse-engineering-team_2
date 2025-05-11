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

### opdef.c
Defines all the supported io_uring operations and their handlers. Think of it like a registry where all the operation types and corresponding functions are listed.

### openclose.c
Handles async file open and close operations. This includes the whole lifecycle from opening to closing a file via io_uring.

### poll.c
Implements polling operations for file descriptors through io_uring. It works in a similar way to epoll or poll system calls but fully async.

### register.c
Takes care of registering various resources (like buffers or file descriptors) so they can be reused more efficiently during I/O operations.

### rsrc.c
General resource manager for io_uring. It helps allocate, track, and clean up resources. It’s like a layer of abstraction to keep resource usage clean and efficient.

### rw.c
Implements the main read and write operations. This is where actual file I/O happens. It includes various optimizations for speed and low latency.

### splice.c
Implements zero-copy data movement between file descriptors using splice. So data can move directly between two FDs (like a pipe and a file) without bouncing through userspace.

### sqpoll.c
Handles submission queue polling using a kernel thread that continuously checks for new submissions. This helps reduce latency since it avoids user-to-kernel context switches.

### statx.c
Implements statx, which gives detailed file metadata. It's like an advanced version of stat, done asynchronously through io_uring.

### sync.c
Takes care of sync-related operations like fsync and fdatasync. It ensures that data actually gets written to disk.

### tctx.c
Manages task contexts, meaning it keeps track of each thread or process using io_uring, and their associated state.

### timeout.c
Implements timeouts for requests. This includes setting up timers and canceling operations if they take too long.

### truncate.c
Allows file truncation like changing a file's size to happen asynchronously through io_uring.

### uring_cmd.c
Implements a way to send custom device commands through io_uring. This lets apps talk directly to devices using custom formats.

### waitid.c
Handles asynchronous waiting on process state changes, like when a child process exits. It ties process monitoring into io_uring’s async model.

### xattr.c
Implements async operations for extended file attributes — basically file metadata beyond the standard stuff. You can get, set, or list these attributes.

### zcrx.c
Optimizes data reception in networking by doing zero-copy. This speeds up receiving data by skipping unnecessary memory operations.


## Headers
## advice.h
Declares function prototypes and structures for io_madvice and io_fadvice operations. Contains definitions for memory and file advice parameters that control caching behavior. Exposes the interface for advice-related operations without implementation details.

## alloc_cache.h
Defines structures and interfaces for the io_uring memory allocation cache system. Contains declarations for cache creation, management, and memory pool functions. Provides the API for optimized memory allocation used by io_uring operations.

## cancel.h
Declares function prototypes and data structures for cancellation operations in io_uring. Defines cancellation flags and parameters used to identify and terminate pending operations. Provides the public interface for the cancellation subsystem.

## epoll.h
Contains definitions and function declarations for epoll integration with io_uring. Defines structures that map epoll operations to the io_uring interface. Declares conversion functions between epoll events and io_uring completion formats.

## eventfd.h
Declares interfaces for eventfd notification mechanisms in io_uring. Defines constants and structures for eventfd operations and callbacks. Provides the API for creating and managing eventfd notifications through io_uring.

## fdinfo.h
Defines structures and functions for tracking file descriptor information. Contains declarations for file descriptor state tracking and reference counting. Provides interfaces for mapping file descriptors to internal io_uring representations.

## filetable.h
Declares structures and functions for the fixed file table feature. Defines constants for file table limitations and access modes. Contains interfaces for registering, looking up, and managing pre-registered file descriptors.

## fs.h
Defines common filesystem operation interfaces for io_uring. Contains declarations for directory and file path handling functions. Provides abstractions over filesystem operations used across multiple io_uring commands.

## futex.h
Declares structures and constants for futex operations through io_uring. Defines parameters and flags for wait and wake operations. Contains interfaces for asynchronous futex operations that integrate with the io_uring subsystem.

## io_uring.h
Core header that defines the main io_uring data structures and APIs. Contains definitions for submission and completion queue entries, operation codes, and feature flags. Declares the core functions for ring setup, submission, and completion processing.

## io-wq.h
Declares interfaces for the io_uring workqueue system. Defines structures for worker threads and work items. Contains declarations for workqueue creation, management, and work distribution APIs.

## kbuf.h
Defines structures and functions for kernel buffer management. Contains declarations for buffer allocation, registration, and mapping between userspace and kernel. Provides interfaces for zero-copy optimizations through pre-registered buffers.

## memmap.h
Declares structures and constants for memory mapping operations. Defines flags and parameters for mmap-related io_uring commands. Contains interfaces for memory management operations through the io_uring subsystem.

## msg_ring.h
Defines data structures and constants for message passing between io_uring instances. Contains declarations for message formats and ring-to-ring communication protocols. Provides interfaces for inter-ring message delivery and reception.

## napi.h
Declares interfaces for Network API integration with io_uring. Contains structures for integrating with the Linux networking stack's polling mechanisms. Defines functions for optimized packet processing through io_uring.

## net.h
Defines structures and constants for networking operations in io_uring. Contains declarations for socket operations and network buffer handling. Provides interfaces for asynchronous network I/O through io_uring.

## nop.h
Declares minimal interfaces for the no-operation command. Contains constants and structures for NOP operation parameters. Provides declarations for the simplest possible io_uring operation used for testing and benchmarking. 
