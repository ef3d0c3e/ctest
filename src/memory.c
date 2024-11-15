#include "tester.h"
#include "error.h"

struct ctest_mem
__ctest_mem_new()
{
	return (struct ctest_mem){
		.allocation_arena = __ctest_mem_arena_new(),
		.deallocation_arena = __ctest_mem_arena_new(),
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
