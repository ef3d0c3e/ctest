#include "memory.h"
#include "tester.h"
#include <execinfo.h>
#include <stdlib.h>
#include <stdio.h>

static void grow(struct ctest_mem_arena *arena)
{
	if (!arena->data)
	{
		arena->data = malloc(sizeof(struct ctest_mem_data));
		return;
	}
	else
	{
		arena->capacity *= 2;
		arena->data = realloc(arena->data, arena->capacity);
	}
}

struct ctest_mem_arena __ctest_mem_arena_new()
{
	return (struct ctest_mem_arena) {
		.data = NULL,
		.size = 0,
		.capacity = 0,
	};
}
void __ctest_mem_arena_free(struct ctest_mem_arena* arena)
{
	if (!arena->data)
		free(arena->data);
}

/**
 * @brief Adds a new allocation to the arena
 */
void __ctest_mem_add(struct ctest_mem_arena *arena, uintptr_t allocator, uintptr_t ptr, struct user_regs_struct regs)
{
	if (arena->size >= arena->capacity)
		grow(arena);
	size_t size;
	if (allocator == (uintptr_t)malloc)
		size = regs.rdi;
	else if (allocator == (uintptr_t)realloc)
		size = regs.rsi;
	else
	{
		fprintf(stderr, "Unknown allocator: 0x%p\n", (void*)allocator);
		exit(1);
	}

	struct ctest_mem_data data = {
		.allocator = allocator,
		.ptr = ptr,
		.size = size,
		.regs = regs,
	};
	arena->data[size++] = data;
}
/**
 * @brief Deletes an allocation from the arena
 *
 * @param ptr Pointer to the allocated memory
 */
int __ctest_mem_delete(struct ctest_mem_arena *arena, uintptr_t ptr);
