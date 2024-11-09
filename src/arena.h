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
	 * @brief Flag to indicate if the allocation has been freed
	 */
	int freed;
};

// TODO: Store secondary table of deallocated memory to check for use after free and double free
// FIXME: Split into memory/arena
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
 * @brief Prints the arena state to a file descriptor
 *
 * @param result The result structure
 * @param fd File descriptor to print to
 */
void
__ctest_mem_arena_print(struct ctest_result* result, int fd);

#endif // CTEST_ARENA_H
