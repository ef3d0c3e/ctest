#include "tester.h"
#include "error.h"
#include <dlfcn.h>
#include <execinfo.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/shm.h>
#include <malloc.h>
#include <unistd.h>

struct ctest_mem
__ctest_mem_new()
{
	return (struct ctest_mem){
		.allocation_arena = __ctest_mem_arena_new(),
		.deallocation_arena = __ctest_mem_arena_new(),
		.in_hook = 0,
		                       .malloc_settings = (union ctest_mem_allocator_settings){
		                         .malloc = {
		                           .failures_per_million = 0,
		                           .fail_on_zero = 1,
		                         } } };
}

void
__ctest_mem_free(struct ctest_mem* mem)
{
	__ctest_mem_maps_free(&mem->maps);
	__ctest_mem_arena_free(&mem->allocation_arena);
	__ctest_mem_arena_free(&mem->deallocation_arena);
}

/* Malloc hook called by the child */
static void*
malloc_hook(struct ctest_result* result)
{
	// TODO: When malloc calls to mmap and s/brk, keep track of the new memory page as if it were heap, for direct mmap calls more checking needs to be done
	// A dumbproof method is to reparse the pages after malloc() and mark the new pages as `heap`

	// TODO: Apply malloc settings
	const size_t size = result->message_out.mem.malloc.regs.rdi;
	if (!size && result->mem.malloc_settings.malloc.fail_on_zero) {
		// TODO: Emit warning
		result->message_in.mem.malloc.ptr = (uintptr_t)0;
		result->mem.in_hook = 0;
		return NULL;
	}

	void* ptr = malloc(size);
	if (!ptr) {
		write(result->messages, "malloc() failed unexpectedly\n", 29);
		exit(1);
	}

	result->message_in.mem.malloc.ptr = (uintptr_t)ptr;
	result->mem.in_hook = 0;

	return ptr;
}

/* Realloc hook called by the child */
static void*
realloc_hook(struct ctest_result* result)
{
	// TODO: When malloc calls to mmap and s/brk, keep track of the new memory page as if it were heap, for direct mmap calls more checking needs to be done
	// A dumbproof method is to reparse the pages after malloc() and mark the new pages as `heap`
	// TODO: Apply malloc settings
	const size_t original_ptr = result->message_out.mem.malloc.regs.rdi;
	const size_t size = result->message_out.mem.malloc.regs.rsi;

	result->message_in.mem.realloc.original_ptr = original_ptr;
	if (!size && result->mem.malloc_settings.malloc.fail_on_zero) {
		// TODO: Emit warning
		result->message_in.mem.realloc.ptr = (uintptr_t)0;
		result->mem.in_hook = 0;
		return NULL;
	}

	result->message_in.mem.realloc.original_usable_size = malloc_usable_size((void*)original_ptr);
	void* ptr = realloc((void*)original_ptr, size);
	if (!ptr) {
		write(result->messages, "realloc() failed unexpectedly\n", 29);
		exit(1);
	}

	result->message_in.mem.realloc.ptr = (uintptr_t)ptr;
	result->mem.in_hook = 0;

	return ptr;
}

/* Free hook called by the child */
static void
free_hook(struct ctest_result* result)
{
	free((void*)result->message_out.mem.free.regs.rdi);
	result->message_in.mem.free.ptr = (uintptr_t)result->message_out.mem.free.regs.rdi;
	result->mem.in_hook = 0;
}

static void*
print_stacktrace_exit(struct ctest_result* result)
{
	// TODO: Use libunwind instead
	void* bt[64];
	const int size = backtrace(bt, 64);
	char** lines = backtrace_symbols(bt, size);

	fprintf(stderr, " * Stacktrace:\n");
	for (int i = 0; i < size; ++i) {
		fprintf(stderr, " #%d: %s\n", i, lines[i]);
	}
	free(lines);

	longjmp(result->jmp_end, 1);
}

#include <elfutils/libdwfl.h>
#include <gelf.h>
#include <fcntl.h>

int
__ctest_mem_memman_hook(struct ctest_result* result, struct user_regs_struct* regs)
{
	if (result->mem.in_hook)
		return 0;

	result->mem.in_hook = 1;
	// TODO: realloc
	if (regs->rip == (uintptr_t)malloc) {
		result->message_out.mem.allocator = (uintptr_t)malloc;
		result->message_out.mem.malloc.regs = *regs;
		regs->rip = (uintptr_t)malloc_hook;
		regs->rdi = (uintptr_t)result->child_result;
	} else if (regs->rip == (uintptr_t)realloc) {
		result->message_out.mem.allocator = (uintptr_t)realloc;
		result->message_out.mem.realloc.regs = *regs;
		regs->rip = (uintptr_t)realloc_hook;
		regs->rdi = (uintptr_t)result->child_result;
	} else if (regs->rip == (uintptr_t)free) {
		result->message_out.mem.allocator = (uintptr_t)free;
		result->message_out.mem.free.regs = *regs;
		uintptr_t ptr = regs->rdi;
		struct ctest_mem_allocation* data = __ctest_mem_arena_find(result, ptr);
		if (!data) {
			__ctest_raise_parent_error(
			  result, regs, "Free on unallocated memory: %p\n", (void*)ptr);
			regs->rip = (uintptr_t)print_stacktrace_exit;
			regs->rdi = (uintptr_t)result->child_result;
		} else if (data->allocator != (uintptr_t)malloc) {
			__ctest_raise_parent_error(
			  result, regs, "Free on pointer not allocated by malloc(): %p\n", (void*)ptr);
			regs->rip = (uintptr_t)print_stacktrace_exit;
			regs->rdi = (uintptr_t)result->child_result;
		} else if (data->freed_rip) {
			__ctest_raise_parent_error(
			  result, regs, "Double free detected in program: %p\n", (void*)ptr);
			regs->rip = (uintptr_t)print_stacktrace_exit;
			regs->rdi = (uintptr_t)result->child_result;
		} else {
			regs->rip = (uintptr_t)free_hook;
			regs->rdi = (uintptr_t)result->child_result;
		}
	}
	else {
		fprintf(stderr, "%s: Unsupported allocator\n", __FUNCTION__);
		exit(1);
	}
	return 1;
}
