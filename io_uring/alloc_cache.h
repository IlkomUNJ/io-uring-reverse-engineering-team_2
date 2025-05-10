#ifndef IOU_ALLOC_CACHE_H
#define IOU_ALLOC_CACHE_H

#include <linux/io_uring_types.h>

/*
 * Don't allow the cache to grow beyond this size.
 */
#define IO_ALLOC_CACHE_MAX	128

/* Cleans up the entire memory cache. Releases all cached objects using the provided free function. */
void io_alloc_cache_free(struct io_alloc_cache *cache,
			 void (*free)(const void *));

/* Sets up a new memory cache with specified maximum size and object sizes. Returns true if successful. */
bool io_alloc_cache_init(struct io_alloc_cache *cache,
			 unsigned max_nr, unsigned int size,
			 unsigned int init_bytes);


/* Creates a new object when the cache is empty. Allocates new memory with requested size and flags. */
void *io_cache_alloc_new(struct io_alloc_cache *cache, gfp_t gfp);

/* Returns an object to the cache for reuse. Returns true if successfully cached, false if cache is full. */
static inline bool io_alloc_cache_put(struct io_alloc_cache *cache,
				      void *entry)
{
	if (cache->nr_cached < cache->max_cached) {
		if (!kasan_mempool_poison_object(entry))
			return false;
		cache->entries[cache->nr_cached++] = entry;
		return true;
	}
	return false;
}

/* Gets a pre-allocated object from the cache. Prepares it for reuse by removing poison markers if KASAN is enabled. */
static inline void *io_alloc_cache_get(struct io_alloc_cache *cache)
{
	if (cache->nr_cached) {
		void *entry = cache->entries[--cache->nr_cached];

		/*
		 * If KASAN is enabled, always clear the initial bytes that
		 * must be zeroed post alloc, in case any of them overlap
		 * with KASAN storage.
		 */
#if defined(CONFIG_KASAN)
		kasan_mempool_unpoison_object(entry, cache->elem_size);
		if (cache->init_clear)
			memset(entry, 0, cache->init_clear);
#endif
		return entry;
	}

	return NULL;
}

/* Allocation function that first tries the cache, then allocates new memory if cache is empty. */
static inline void *io_cache_alloc(struct io_alloc_cache *cache, gfp_t gfp)
{
	void *obj;

	obj = io_alloc_cache_get(cache);
	if (obj)
		return obj;
	return io_cache_alloc_new(cache, gfp);
}

/* A free function that tries to put the object in cache first, only truly frees if cache is full. */
static inline void io_cache_free(struct io_alloc_cache *cache, void *obj)
{
	if (!io_alloc_cache_put(cache, obj))
		kfree(obj);
}

#endif
