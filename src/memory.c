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
		arena->capacity = 1;
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
		                             .malloc_settings = (union ctest_mem_allocator_settings){
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
__ctest_mem_add(struct ctest_result* result)
{
	if (result->arena.size >= result->arena.capacity)
		grow(&result->arena);
	struct ctest_mem_data data;
	data.allocator = result->message_out.mem.allocator;
	data.regs = result->message_out.mem.malloc.regs;
	if (data.allocator == (uintptr_t)malloc) {
		data.ptr = result->message_in.mem.malloc.ptr;
		data.size = result->message_out.mem.malloc.regs.rdi;
		data.freed = 0;
	} else if (data.allocator == (uintptr_t)realloc) {
		data.ptr = result->message_in.mem.realloc.ptr;
		data.size = result->message_out.mem.realloc.regs.rsi;
		data.freed = 0;
	} else if (data.allocator == (uintptr_t)free) {
		// Nothing to do
		if (result->message_in.mem.free.ptr == 0)
			return;
		struct ctest_mem_data *data = __ctest_mem_find(result, result->message_in.mem.free.ptr);
		// TODO: Raise error api + print backtrace/registers
		if (!data)
		{
			fprintf(stderr, "%s: free(%p): Pointer was not found in heap\n", __FUNCTION__, (void*)result->message_in.mem.free.ptr);
			exit(1);
		} else if (data->allocator != (uintptr_t)malloc)
		{
			fprintf(stderr, "%s: free(%p): Pointer was not allocated with malloc()\n", __FUNCTION__, (void*)result->message_in.mem.free.ptr);
			exit(1);
		}
		else if (data->freed)
		{
			fprintf(stderr, "%s: free(%p): Pointer was already deallocated\n", __FUNCTION__, (void*)result->message_in.mem.free.ptr);
			exit(1);
		}
		data->freed = 1;

	} else {
		fprintf(stderr, "%s: Unknown allocator: 0x%p\n", __FUNCTION__, (void*)data.allocator);
		exit(1);
	}

	result->arena.data[result->arena.size++] = data;
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

struct ctest_mem_data*
__ctest_mem_find(struct ctest_result* result,
                   uintptr_t ptr)
{
	for (size_t i = 0; i < result->arena.size; ++i)
	{
		printf("WANT=%p FIND=%p\n", (void*)ptr, (void*)result->arena.data[i].ptr);
		if (result->arena.data[i].ptr == ptr)
			return &result->arena.data[i];
	}
	return NULL;
}

void
__ctest_mem_print(struct ctest_result* result,
                   int fd)
{
	for (size_t i = 0; i < result->arena.size; ++i)
	{
		dprintf(fd, " -- Heap block [%p] --\n size: %zu\n freed: %d\n",
				(void*)result->arena.data[i].ptr,
				result->arena.data[i].size,
				result->arena.data[i].freed
			);
	}
}

/* Malloc hook called by the child */
void*
malloc_hook(struct ctest_result* result)
{
	// TODO: Apply malloc settings
	const size_t size = result->message_out.mem.malloc.regs.rdi;
	if (!size && result->arena.malloc_settings.malloc.fail_on_zero)
	{
		// TODO: Emit warning
		result->message_in.mem.malloc.ptr = (uintptr_t)0;
		result->arena.in_memory_hook = 0;
		return NULL;
	}
	void* ptr = malloc(size);
	if (!ptr) {
		write(result->messages, "malloc() failed unexpectedly\n", 29);
		exit(1);
	}

	// Fill with random data
	for (size_t i = 0; i < size; ++i)
		((unsigned char*)ptr)[i] = rand() % 255;
	result->message_in.mem.malloc.ptr = (uintptr_t)ptr;
	result->arena.in_memory_hook = 0;

	return ptr;
}

void
free_hook(struct ctest_result* result)
{
	free((void*)result->message_out.mem.free.regs.rdi);
	result->message_in.mem.free.ptr = (uintptr_t)result->message_out.mem.free.regs.rdi;
	result->arena.in_memory_hook = 0;
}

int
__ctest_mem_hook(struct ctest_result* result, struct user_regs_struct* regs)
{
	if (result->arena.in_memory_hook)
		return 0;

	result->arena.in_memory_hook = 1;
	if (regs->rip == (uintptr_t)malloc) {
		result->message_out.mem.allocator = (uintptr_t)malloc;
		result->message_out.mem.malloc.regs = *regs;
		regs->rip = (uintptr_t)malloc_hook;
		regs->rdi = (uintptr_t)result->child_result;
	} else if (regs->rip == (uintptr_t)free) {
		result->message_out.mem.allocator = (uintptr_t)free;
		result->message_out.mem.free.regs = *regs;
		regs->rip = (uintptr_t)free_hook;
		regs->rdi = (uintptr_t)result->child_result;
	}
	return 1;
}
