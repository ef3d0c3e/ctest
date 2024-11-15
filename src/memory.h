#ifndef CTEST_MEMORY_H
#define CTEST_MEMORY_H

#include "arena.h"
#include "mem_maps.h"

struct ctest_result;

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
		union
		{
			struct {
			struct user_regs_struct regs;
			} malloc, realloc, free;
		};
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
	} malloc;

	struct
	{
		uintptr_t ptr;
		uintptr_t original_ptr;
		size_t original_usable_size;
	} realloc;

	struct
	{
		uintptr_t ptr;
	} free;
};

// TODO...
/**
 * @brief Experimental settings for allocators
 *
 * @note This is a work in progress, it does nothing currently
 */
union ctest_mem_allocator_settings
{
	///< Settings for malloc/realloc
	struct
	{
		/**
		 * @brief Number of malloc() calls that should return NULL per million calls
		 *
		 * @note If calling the real malloc does fail while the tester did not want it to fail,
		 * the program will crash
		 */
		size_t failures_per_million;
		/**
		 * @brief malloc() will fail when the requested size is zero
		 */
		int fail_on_zero;
	} malloc;
};

/**
 * @brief The memory structure
 */
struct ctest_mem
{
	/**
	 * @brief The child's memory maps
	 *
	 * @note This entry cannot be populated in @ref __ctest_mem_new() because we don't yet know the child's pid
	 */
	struct ctest_maps maps;
	/**
	 * @brief The allocation arena
	 */
	struct ctest_mem_arena allocation_arena;
	/**
	 * @brief The deallocation arena
	 */
	struct ctest_mem_arena deallocation_arena;
	/**
	 * @param Settings for malloc
	 */
	union ctest_mem_allocator_settings malloc_settings;
};

/**
 * @brief Creates a new memory structure
 *
 * @note The @ref mem_maps won't be populated here, a later call to @ref __ctest_mem_maps_parse() is required
 */
struct ctest_mem __ctest_mem_new();

/**
 * @brief Deletes a memory structure
 */
void __ctest_mem_free(struct ctest_mem* mem);

#endif // CTEST_MEMORY_H
