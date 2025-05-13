#ifndef IO_URING_MEMMAP_H
#define IO_URING_MEMMAP_H

#define IORING_MAP_OFF_PARAM_REGION		0x20000000ULL
#define IORING_MAP_OFF_ZCRX_REGION		0x30000000ULL

/*
 Pins user pages to memory so they won't be swapped out.
 Used to ensure io_uring operations have access to user memory during processing.
*/
struct page **io_pin_pages(unsigned long ubuf, unsigned long len, int *npages);

#ifndef CONFIG_MMU
/*
 Returns mmap capabilities for non-MMU systems.
 Indicates support for direct, read, and write mappings.
*/
unsigned int io_uring_nommu_mmap_capabilities(struct file *file);
#endif

/*
 Finds appropriate unmapped memory area for io_uring regions.
 Helps select good virtual address ranges for mapping io_uring memory.
*/
unsigned long io_uring_get_unmapped_area(struct file *file, unsigned long addr,
					 unsigned long len, unsigned long pgoff,
					 unsigned long flags);

/*
 Handles mmap system calls for io_uring file descriptors.
 Entry point for userspace mmap operations on io_uring.
*/
int io_uring_mmap(struct file *file, struct vm_area_struct *vma);

/*
 Frees memory region resources including unmapping memory, releasing pages, and accounting.
 Cleans up resources allocated for io_uring memory regions.
*/
void io_free_region(struct io_ring_ctx *ctx, struct io_mapped_region *mr);

/*
 Creates a new memory region based on provided parameters.
 Handles both user-provided and kernel-allocated memory regions.
*/
int io_create_region(struct io_ring_ctx *ctx, struct io_mapped_region *mr,
		     struct io_uring_region_desc *reg,
		     unsigned long mmap_offset);

/*
 Thread-safe wrapper for creating memory regions.
 Protects against race conditions during region creation and publication.
*/
int io_create_region_mmap_safe(struct io_ring_ctx *ctx,
				struct io_mapped_region *mr,
				struct io_uring_region_desc *reg,
				unsigned long mmap_offset);

/*
 Retrieves the kernel virtual address pointer for a memory region.
 Provides access to the region's memory from kernel context.
*/
static inline void *io_region_get_ptr(struct io_mapped_region *mr)
{
	return mr->ptr;
}

/*
 Checks if a memory region has been initialized.
 Returns true if the region has pages allocated to it.
*/
static inline bool io_region_is_set(struct io_mapped_region *mr)
{
	return !!mr->nr_pages;
}

#endif
