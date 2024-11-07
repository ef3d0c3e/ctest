#ifndef CTEST_MEMORY_H
#define CTEST_MEMORY_H

#include <stdint.h>
#include <unistd.h>
#include <sys/user.h>

struct ctest_mem_data
{
	uintptr_t allocator;
	uintptr_t ptr;
	size_t size;
	struct user_regs_struct regs;
	//void *backtrace[16];
};

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
 */
int __ctest_mem_delete(struct ctest_mem_arena *arena, uintptr_t ptr);

#endif // CTEST_MEMORY_H
