#include "memory.h"
#include "tester.h"
#include <dlfcn.h>
#include <execinfo.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>

static void
grow(struct ctest_mem_arena* arena)
{
	if (!arena->data) {
		arena->data = malloc(sizeof(struct ctest_mem_data));
		return;
	} else {
		arena->capacity *= 2;
		arena->data = realloc(arena->data, arena->capacity);
	}
}

struct ctest_mem_arena
__ctest_mem_arena_new()
{
	return (struct ctest_mem_arena){ .data = NULL,
		                             .size = 0,
		                             .capacity = 0,
		                             .in_memory_hook = 0,
		                             .malloc_settings = (struct ctest_mem_allocator_settings){
		                               .malloc = {
		                                 .failures_per_million = 0,
		                                 .fail_on_zero = 1,
		                               } } };
}
void
__ctest_mem_arena_free(struct ctest_mem_arena* arena)
{
	if (!arena->data)
		free(arena->data);
}

void
__ctest_mem_add(struct ctest_mem_arena* arena,
                uintptr_t allocator,
                uintptr_t ptr,
                struct user_regs_struct regs)
{
	if (arena->size >= arena->capacity)
		grow(arena);
	size_t size;
	if (allocator == (uintptr_t)malloc)
		size = regs.rdi;
	else if (allocator == (uintptr_t)realloc)
		size = regs.rsi;
	else if (allocator == (uintptr_t)mmap)
		size = regs.rsi;
	else {
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

/* Malloc hook called by the child */
void*
malloc_hook(struct ctest_result* result)
{
	result->arena.in_memory_hook = 1;
	void* ptr = malloc(result->message.mem.malloc.size);
	result->arena.in_memory_hook = 0;

	return ptr;
}

void
__ctest_mem_hook(struct ctest_result* result, struct user_regs_struct* regs)
{
	if (result->arena.in_memory_hook)
		return;
	if (regs->rip == (uintptr_t)malloc) {
		result->message.mem.malloc.size = regs->rdi;
		regs->rip = (uintptr_t)malloc_hook;
		regs->rdi = (uintptr_t)result->child_result;
	}
}
