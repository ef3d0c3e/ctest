#include "memory_management.h"
#include "result.h"
#include "error.h"
#include "tracer.h"
#include <malloc.h>

void
__ctest_mem_process_allocation(struct ctest_result* result)
{

	struct ctest_mem_allocation data;
	data.allocator = result->message_out.mem.allocator;
	data.regs = result->message_out.mem.malloc.regs;
	/* malloc */
	if (data.allocator == (uintptr_t)malloc) {
		data.ptr = result->message_in.mem.malloc.ptr;
		data.size = result->message_out.mem.malloc.regs.rdi;
		data.initialized_memory = calloc(data.size / 8 + (data.size % 8 != 0), 1);
		data.freed_rip = 0;
		data.alloc_rip = result->rip_before_call;

		__ctest_mem_arena_add(&result->mem.allocation_arena, data);
	}
	/* realloc */
	else if (data.allocator == (uintptr_t)realloc) {

		data.ptr = result->message_in.mem.realloc.ptr;
		data.size = result->message_out.mem.realloc.regs.rsi;

		/* Mark the original allocation as freed & carry over initialized memory */
		struct ctest_mem_allocation* original = __ctest_mem_arena_find(result, data.ptr);
		// TODO... find the original allocation, if not found, use malloc_usable_size to consider
		// all these bytes initialized
		// data.initialized_memory = calloc(data.size / 8 + (data.size % 8 != 0), 1);
		if (original) {
			original->freed_rip = result->rip_before_call;

		} else {
			// data.initialized_memory = calloc(data.size / 8 + (data.size % 8 != 0), 1);
		}

		data.alloc_rip = result->rip_before_call;

		__ctest_mem_arena_add(&result->mem.allocation_arena, data);
	}
	/* free */
	else if (data.allocator == (uintptr_t)free) {
		// Nothing to do
		if (result->message_in.mem.free.ptr == 0)
			return;
		struct ctest_mem_allocation* data =
		  __ctest_mem_arena_find(result, result->message_in.mem.free.ptr);
		/* If found, move to the deallocation arena */
		if (data) {
			data->freed_rip = result->rip_before_call;
			__ctest_mem_arena_add(&result->mem.deallocation_arena, *data);
			__ctest_mem_arena_delete(&result->mem.allocation_arena, data->ptr);
		}

	} else {
		fprintf(stderr, "%s: Unknown allocator: 0x%p\n", __FUNCTION__, (void*)data.allocator);
		exit(1);
	}
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
		/* Free on unknown memory */
		if (!data) {
			__ctest_raise_parent_error(
			  result, regs, "Free on unallocated memory: %p\n", (void*)ptr);
			__ctest_print_alloc_info(result, data);
			regs->rip = (uintptr_t)__ctest_tracer_shutdown;
			regs->rdi = (uintptr_t)result->child_result;
		} 
		/* Free on wrong memory */
		else if (data->allocator != (uintptr_t)malloc) {
			__ctest_raise_parent_error(
			  result, regs, "Free on pointer not allocated by malloc(): %p\n", (void*)ptr);
			__ctest_print_alloc_info(result, data);
			regs->rip = (uintptr_t)__ctest_tracer_shutdown;
			regs->rdi = (uintptr_t)result->child_result;
		}
		/* Double free */
		else if (data->freed_rip) {
			__ctest_raise_parent_error(
			  result, regs, "Double free detected in program: %p\n", (void*)ptr);
			__ctest_print_alloc_info(result, data);

			regs->rip = (uintptr_t)__ctest_tracer_shutdown;
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
