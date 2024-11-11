#include "arena.h"
#include "result.h"
#include <stdio.h>
#include <stdlib.h>

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
	if (!arena->data)
		free(arena->data);
}

void
__ctest_mem_arena_add(struct ctest_result* result)
{
	if (result->mem.arena.size >= result->mem.arena.capacity)
		grow(&result->mem.arena);

	struct ctest_mem_allocation data;
	data.allocator = result->message_out.mem.allocator;
	data.regs = result->message_out.mem.malloc.regs;
	/* malloc */
	if (data.allocator == (uintptr_t)malloc) {
		data.ptr = result->message_in.mem.malloc.ptr;
		data.size = result->message_out.mem.malloc.regs.rdi;
		data.freed_rip = 0;
		data.alloc_rip = result->rip_before_call;
	}
	/* realloc */
	else if (data.allocator == (uintptr_t)realloc) {
		data.ptr = result->message_in.mem.realloc.ptr;
		data.size = result->message_out.mem.realloc.regs.rsi;
		data.freed_rip = 0;
		data.alloc_rip = result->rip_before_call;
	}
	/* free */
	else if (data.allocator == (uintptr_t)free) {
		// Nothing to do
		if (result->message_in.mem.free.ptr == 0)
			return;
		struct ctest_mem_allocation* data =
		  __ctest_mem_arena_find(result, result->message_in.mem.free.ptr);
		data->freed_rip = result->rip_before_call;

	} else {
		fprintf(stderr, "%s: Unknown allocator: 0x%p\n", __FUNCTION__, (void*)data.allocator);
		exit(1);
	}

	result->mem.arena.data[result->mem.arena.size++] = data;
}

int
__ctest_mem_delete(struct ctest_mem_arena* arena,
                   uintptr_t deallocator,
                   uintptr_t ptr,
                   struct user_regs_struct regs)
{
	for (size_t i = 0; i < arena->size; ++i) {
		if (arena->data[i].ptr != ptr)
			continue;

		for (size_t j = i + 1; j < arena->size; ++j)
			arena->data[j - 1] = arena->data[j];
		--arena->size;
		return 1;
	}
	return 0;
}

struct ctest_mem_allocation*
__ctest_mem_arena_find(struct ctest_result* result, uintptr_t ptr)
{
	for (size_t i = 0; i < result->mem.arena.size; ++i) {
		if (result->mem.arena.data[i].ptr == ptr)
			return &result->mem.arena.data[i];
	}
	return NULL;
}

int
__ctest_mem_arena_find_range(struct ctest_result* result,
                             struct ctest_mem_allocation** alloc,
                             uintptr_t start,
                             uintptr_t end)
{
	for (size_t i = 0; i < result->mem.arena.size; ++i) {
		struct ctest_mem_allocation* allocation = &result->mem.arena.data[i];
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
	return 1;
}

void
__ctest_mem_arena_print(struct ctest_result* result, int fd)
{
	for (size_t i = 0; i < result->mem.arena.size; ++i) {
		dprintf(fd,
		        " -- Heap block [%p] --\n size: %zu\n freed: %lx\n",
		        (void*)result->mem.arena.data[i].ptr,
		        result->mem.arena.data[i].size,
		        result->mem.arena.data[i].freed_rip);
	}
}
