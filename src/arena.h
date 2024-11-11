#ifndef CTEST_ARENA_H
#define CTEST_ARENA_H

#include <stdint.h>
#include <unistd.h>
#include <sys/user.h>

struct ctest_result;

/**
 * @brief Stores an allocation in the arena
 *
 * @note Once deallocated, memory allocations will stay in the arena to detect double free
 */
struct ctest_mem_allocation
{
	/**
	 * @brief The allocator
	 */
	uintptr_t allocator;
	/**
	 * @brief The pointer returned by malloc/realloc or mmap
	 */
	uintptr_t ptr;
	/**
	 * @brief The requested size of the pointer
	 */
	size_t size;
	/**
	 * @brief The register state when the allocation request was issued
	 */
	struct user_regs_struct regs;
	/**
	 * @brief RIP when the instruction was freed, 0 if not freed
	 */
	uintptr_t freed_rip;
};

// TODO: Store secondary table of deallocated memory to check for use after free and double free
/**
 * @brief The memory allocation arena
 */
struct ctest_mem_arena
{
	/**
	 * @brief Storage for the allocation blocks
	 */
	struct ctest_mem_allocation* data;
	/**
	 * @brief The number of allocations
	 */
	size_t size;
	/**
	 * @brief Capacity of the @ref data, before needing to grow
	 */
	size_t capacity;
};

/**
 * @brief Creates a new empty arena
 *
 * @returns An empty arena
 */
struct ctest_mem_arena
__ctest_mem_arena_new();
/**
 * @brief Deletes an arena
 *
 * @param arena The arena to delete
 */
void
__ctest_mem_arena_free(struct ctest_mem_arena* arena);

/**
 * @brief Adds a new allocation/deallocation to the arena
 *
 * The allocation is retrieved from @ref ctest_mem_msg_out and @ref ctest_mem_msg_in
 */
void
__ctest_mem_arena_add(struct ctest_result* result);

/**
 * @brief Deletes an allocation from the arena
 *
 * @param ptr Pointer to the allocated memory
 *
 * @returns 1 If deallocation succesfully finished
 * 0 if no memory was allocated for that pointer
 */
/*
int
__ctest_mem_arena_delete(struct ctest_mem_arena* arena,
                   uintptr_t deallocator,
                   uintptr_t ptr,
                   struct user_regs_struct regs);
*/

/**
 * @brief Finds an allocated memory buffer from the arena
 *
 * @param result The result structure
 * @param ptr The pointer to find
 *
 * @returns The memory data associated with ptr, NULL if not found
 */
struct ctest_mem_allocation*
__ctest_mem_arena_find(struct ctest_result* result, uintptr_t ptr);

/**
 * @brief Finds a contiguous memory buffer that spans over a range
 *
 * @param result The result structure
 * @param alloc The output of this function, see the returned values for more information
 * @param start The start address
 * @param end The end address
 *
 * @returns 0 On success, on failures this function returns the following error codes:
 *  - 1 [alloc is not set]: No memory allocation was found for the start or end pointer of the range, e.g:
 * 		`| 0x0 malloc(64) | HOLE | 0x80 malloc(16) |`, searching for range [80, 90]
 *  - 2 [alloc is set to start allocation]: Start allocation was found but it did not contain the end address, e.g:
 *  	`| 0x0 malloc(64) |`, searching for range [60, 70], this is most likely a buffer overflow
 *  - 3 [alloc is set to end allocation]: Emd allocation was found but it did not contain the start address, e.g:
 *  	`HOLE | 0x40 malloc(64) |`, searching for range [60, 70], this is most likely a buffer underflow
 *
 * # Example
 *
 * Consider this memory layout
 * `| 0x0 malloc(64) || 0x40 malloc(16) |`
 *  - If the search the range is [14, 16], then it will return the data allocated by the first malloc call()
 *  - However, if you search the range [60, 70], because it spans over two allocations, it will return NULL
 */
int
__ctest_mem_arena_find_range(struct ctest_result* result, struct ctest_mem_allocation** alloc, uintptr_t start, uintptr_t end);

/**
 * @brief Prints the arena state to a file descriptor
 *
 * @param result The result structure
 * @param fd File descriptor to print to
 */
void
__ctest_mem_arena_print(struct ctest_result* result, int fd);

#endif // CTEST_ARENA_H
