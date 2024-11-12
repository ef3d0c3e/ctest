#include "arena.h"
#include "result.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>

static void
grow(struct ctest_mem_arena* arena)
{
	if (!arena->data) {
		arena->data = malloc(sizeof(struct ctest_mem_allocation));
		arena->capacity = 1;
	} else {
		arena->capacity *= 2;
		arena->data = realloc(arena->data, arena->capacity * sizeof(struct ctest_mem_allocation));
	}
}

void __ctest_mem_allocation_free(struct ctest_mem_allocation* allocation)
{
	free(allocation->initialized_memory);
}

struct ctest_mem_arena
__ctest_mem_arena_new()
{
	return (struct ctest_mem_arena){
		.data = NULL,
		.size = 0,
		.capacity = 0,
	};
}
void
__ctest_mem_arena_free(struct ctest_mem_arena* arena)
{
	for (size_t i = 0; i < arena->size; ++i)
		__ctest_mem_allocation_free(&arena->data[i]);
	free(arena->data);
}

int
__ctest_mem_arena_delete(struct ctest_mem_arena* arena, uintptr_t ptr)
{
	for (size_t i = 0; i < arena->size; ++i) {
		if (arena->data[i].ptr != ptr)
			continue;

		__ctest_mem_allocation_free(&arena->data[i]);
		for (size_t j = i + 1; j < arena->size; ++j)
			arena->data[j - 1] = arena->data[j];
		--arena->size;
		return 1;
	}
	return 0;
}

void
__ctest_mem_arena_add(struct ctest_mem_arena* arena, struct ctest_mem_allocation allocation)
{
	if (arena->size >= arena->capacity)
		grow(arena);
	arena->data[arena->size++] = allocation;
}

struct ctest_mem_allocation*
__ctest_mem_arena_find(struct ctest_result* result, uintptr_t ptr)
{
	/* Search for allocated memory */
	for (size_t i = 0; i < result->mem.allocation_arena.size; ++i) {
		if (result->mem.allocation_arena.data[i].ptr == ptr)
			return &result->mem.allocation_arena.data[i];
	}
	/* Search for deallocated memory */
	for (size_t i = 0; i < result->mem.deallocation_arena.size; ++i) {
		if (result->mem.deallocation_arena.data[i].ptr == ptr)
			return &result->mem.deallocation_arena.data[i];
	}
	return NULL;
}

int
__ctest_mem_arena_find_range(struct ctest_result* result,
                             struct ctest_mem_allocation** alloc,
                             uintptr_t start,
                             uintptr_t end)
{
	/* Search for allocated memory */
	for (size_t i = 0; i < result->mem.allocation_arena.size; ++i) {
		struct ctest_mem_allocation* allocation = &result->mem.allocation_arena.data[i];
		// Contains start
		if (allocation->ptr <= start && allocation->ptr + allocation->size > start) {
			*alloc = allocation;
			// Does not contain end : Buffer overflow
			if (allocation->ptr + allocation->size < end)
				return 2;
			return 0;
		}
		// Contains end only
		else if (allocation->ptr < end && allocation->ptr + allocation->size > end) {
			*alloc = allocation;
			return 3;
		}
	}
	/* Search for deallocated memory */
	for (size_t i = 0; i < result->mem.deallocation_arena.size; ++i) {
		struct ctest_mem_allocation* allocation = &result->mem.deallocation_arena.data[i];
		// Contains start
		if (allocation->ptr <= start && allocation->ptr + allocation->size > start) {
			*alloc = allocation;
			// Does not contain end : Buffer overflow
			if (allocation->ptr + allocation->size < end)
				return 2;
			return 0;
		}
		// Contains end only
		else if (allocation->ptr < end && allocation->ptr + allocation->size > end) {
			*alloc = allocation;
			return 3;
		}
	}
	/* Nothing found */
	return 1;
}

void
__ctest_mem_set_initialized(struct ctest_mem_allocation* allocation,
                            uintptr_t address,
                            uint8_t write_width)
{
	for (uint8_t i = 0; i < write_width; ++i) {
		uint8_t* word = &allocation->initialized_memory[(address - allocation->ptr + i) / 8];
		*word |= (1 << ((address - allocation->ptr + i) % 8));
	}
}

uint8_t
__ctest_mem_is_initialized(struct ctest_mem_allocation* allocation,
                           uintptr_t address,
                           uint8_t read_width)
{
	uint8_t initialized = 0;
	for (uint8_t i = 0; i < read_width; ++i) {
		const uint8_t word = allocation->initialized_memory[(address - allocation->ptr + i) / 8];
		if (word & (1 << ((address - allocation->ptr + i) % 8)))
			initialized += 1;
	}

	return initialized;
}

void
__ctest_mem_arena_print(struct ctest_result* result, int fd)
{
	dprintf(fd, " * Unfreed blocks:\n");
	for (size_t i = 0; i < result->mem.allocation_arena.size; ++i) {
		dprintf(fd,
		        " -- Heap block [%p] --\n size: %zu\n freed: %lx\n",
		        (void*)result->mem.allocation_arena.data[i].ptr,
		        result->mem.allocation_arena.data[i].size,
		        result->mem.allocation_arena.data[i].freed_rip);
	}
	dprintf(fd, " * Freed blocks:\n");
	for (size_t i = 0; i < result->mem.deallocation_arena.size; ++i) {
		dprintf(fd,
		        " -- Heap block [%p] --\n size: %zu\n freed: %lx\n",
		        (void*)result->mem.deallocation_arena.data[i].ptr,
		        result->mem.deallocation_arena.data[i].size,
		        result->mem.deallocation_arena.data[i].freed_rip);
	}
}
