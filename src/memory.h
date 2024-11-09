#ifndef CTEST_MEMORY_H
#define CTEST_MEMORY_H

#include <stdint.h>
#include <sys/user.h>
#include <unistd.h>

struct ctest_result;

struct ctest_mem_data
{
	uintptr_t allocator;
	uintptr_t ptr;
	size_t size;
	struct user_regs_struct regs;
	int freed;
	// void *backtrace[16];
};

/**
 * @brief Message sent via result to child to get information about current call
 *
 * @see ctest_result.message_out
 */
union ctest_mem_msg_out
{
	struct
	{
		uintptr_t allocator;
		struct
		{
			struct user_regs_struct regs;
		} malloc, realloc, free;
	};
};

/**
 * @brief Message received via result from child to get results about call
 *
 * @see ctest_result.message_in
 */
union ctest_mem_msg_in
{
	struct
	{
		uintptr_t ptr;
	} malloc, realloc, free;
};

// TODO...
union ctest_mem_allocator_settings
{
	///< Settings for malloc/realloc
	struct
	{
		/**
		 * @param Number of malloc() calls that should return NULL per million calls
		 *
		 * @note If calling the real malloc does fail while the tester did not want it to fail,
		 * the program will crash
		 */
		size_t failures_per_million;
		/**
		 * @param malloc() will fail when the requested size is zero
		 */
		int fail_on_zero;
	} malloc;
};

// TODO: Store secondary table of deallocated memory to check for use after free and double free
// FIXME: Split into memory/arena
struct ctest_mem_arena
{
	struct ctest_mem_data* data;
	size_t size;
	size_t capacity;
	/**
	 * Flag set to 1 when a memory hook is running.
	 * So as to avoid recursive infinite loop.
	 */
	int in_hook;
	/**
	 * @param Settings for malloc
	 */
	union ctest_mem_allocator_settings malloc_settings;
};

struct ctest_mem_arena
__ctest_mem_arena_new();
void
__ctest_mem_arena_free(struct ctest_mem_arena* arena);

/**
 * @brief Adds a new allocation/deallocation to the arena
 */
void
__ctest_mem_add(struct ctest_result* result);

/**
 * @brief Deletes an allocation from the arena
 *
 * @param ptr Pointer to the allocated memory
 *
 * @returns 1 If deallocation succesfully finished
 * 0 if no memory was allocated for that pointer
 */
int
__ctest_mem_delete(struct ctest_mem_arena* arena,
                   uintptr_t deallocator,
                   uintptr_t ptr,
                   struct user_regs_struct regs);

/**
 * @brief Finds an allocated memory buffer from the arena
 *
 * @param result The result structure
 * @param ptr The pointer to find
 *
 * @returns The memory data associated with ptr, NULL if not found
 */
struct ctest_mem_data*
__ctest_mem_find(struct ctest_result* result, uintptr_t ptr);

/**
 * @brief Prints the memory state to a file descriptor
 *
 * @param result The result structure
 * @param fd File descriptor to print to
 */
void
__ctest_mem_print(struct ctest_result* result, int fd);

/**
 * @brief Hooks called when a memory access is made
 *
 * @returns 1 If message_in needs to be processed for the next steps
 */
int
__ctest_mem_mem_hook(struct ctest_result* result, int access, struct user_regs_struct* regs);

/**
 * @brief Hooks called when a memory management function is called
 *
 * Currently this is called for malloc/realloc and free
 *
 * @returns 1 If message_in needs to be processed for the next steps
 */
int
__ctest_mem_memman_hook(struct ctest_result* result, struct user_regs_struct* regs);

#endif // CTEST_MEMORY_H
