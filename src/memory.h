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
	// void *backtrace[16];
};

/**
 * @brief Message sent via result to child to get information about current call
 *
 * @see ctest_result.message
 */
union ctest_mem_msg
{
	struct
	{
		// RDI
		size_t size;
	} malloc;

	struct
	{
		// RDI
		uintptr_t ptr;
		// RSI
		size_t size;
	} realloc;

	struct
	{
		// RDI
		uintptr_t ptr;
	} free;
};

struct ctest_mem_allocator_settings
{
	union
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
struct ctest_mem_arena
{
	struct ctest_mem_data* data;
	size_t size;
	size_t capacity;
	/**
	 * Flag set to 1 when a memory hook is running.
	 * So as to avoid recursive infinite loop.
	 */
	int in_memory_hook;
	/**
	 * @param Settings for malloc
	 */
	struct ctest_mem_allocator_settings malloc_settings;
};

struct ctest_mem_arena
__ctest_mem_arena_new();
void
__ctest_mem_arena_free(struct ctest_mem_arena* arena);

/**
 * @brief Adds a new allocation to the arena
 */
void
__ctest_mem_add(struct ctest_mem_arena* arena,
                uintptr_t allocator,
                uintptr_t ptr,
                struct user_regs_struct regs);

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
 * @brief Hooks called when a memory management function is called
 *
 * Currently this is called for malloc/realloc and free
 */
void
__ctest_mem_hook(struct ctest_result* result, struct user_regs_struct* regs);

#endif // CTEST_MEMORY_H
