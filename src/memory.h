#ifndef CTEST_MEMORY_H
#define CTEST_MEMORY_H

#include <stdint.h>
#include <unistd.h>
#include <sys/user.h>

struct ctest_result;

struct ctest_mem_data
{
	uintptr_t allocator;
	uintptr_t ptr;
	size_t size;
	struct user_regs_struct regs;
	//void *backtrace[16];
};

// TODO: Store secondary table of deallocated memory to check for use after free and double free
struct ctest_mem_arena
{
	struct ctest_mem_data* data;
	size_t size;
	size_t capacity;
};

struct ctest_mem_arena __ctest_mem_arena_new();
void __ctest_mem_arena_free(struct ctest_mem_arena* arena);

/**
 * @brief Adds a new allocation to the arena
 */
void __ctest_mem_add(struct ctest_mem_arena *arena, uintptr_t allocator, uintptr_t ptr, struct user_regs_struct regs);

/**
 * @brief Deletes an allocation from the arena
 *
 * @param ptr Pointer to the allocated memory
 *
 * @returns 1 If deallocation succesfully finished
 * 0 if no memory was allocated for that pointer
 */
int __ctest_mem_delete(struct ctest_mem_arena *arena, uintptr_t deallocator, uintptr_t ptr, struct user_regs_struct regs);

/**
 * @brief Hooks called when a memory management function is called
 *
 * Currently this is called for malloc/realloc and free
 */
void __ctest_mem_hook(struct ctest_result *result, struct user_regs_struct regs);

#endif // CTEST_MEMORY_H
