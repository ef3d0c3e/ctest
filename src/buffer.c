#include "buffer.h"
#include "result.h"
#include "error.h"
#include "messages.h"
#include <string.h>


int
__ctest_buffer_at_least(struct ctest_result* result, struct user_regs_struct* regs, uintptr_t addr, size_t size, const char* action)
{
	struct ctest_map_entry* map = __ctest_mem_maps_get(&result->mem.maps, addr);
	/* Unmapped memory */
	if (!map) {
		__ctest_raise_parent_error(
				result,
				regs,
				"Attempt to %s %zu bytes in unmapped memory: %s[0x%llx, 0x%llx]%s\n",
				action,
				size,
				__ctest_color(CTEST_COLOR_BLUE),
				addr,
				addr + size,
				__ctest_color(CTEST_COLOR_RESET));
		__ctest_print_source_line(result, STDERR_FILENO, regs->rsp);
		return 0;
	}
	// TODO: consider all maps not linked to a fd as heap too
	if (strcmp(map->pathname, "[heap]") == 0) {
		struct ctest_mem_allocation* alloc;
		const int err = __ctest_mem_arena_find_range(result, &alloc, addr, addr + size);
		/* Unknown heap memory */
		if (err == 1) {
			// TODO: Find closests blocks
			__ctest_raise_parent_error(
					result,
					regs,
					"Attempt to %s %zu bytes in unallocated heap memory: %s[0x%llx, 0x%llx]%s\n",
					action,
					size,
					__ctest_color(CTEST_COLOR_BLUE),
					addr,
					addr + size,
					__ctest_color(CTEST_COLOR_RESET));
			return 0;
		}
		/* Buffer overflow */
		else if (err == 2) {
			__ctest_raise_parent_error(
					result,
					regs,
					"Heap-Buffer overflow of %zu bytes in %s: %s[0x%llx, 0x%llx]%s\n",
					addr + size - alloc->ptr - alloc->size,
					action,
					__ctest_color(CTEST_COLOR_BLUE),
					addr,
					addr + size,
					__ctest_color(CTEST_COLOR_RESET));
			__ctest_print_alloc_info(result, alloc);
			return 0;
		}
		/* Buffer underflow */
		else if (err == 3) {
			__ctest_raise_parent_error(
					result,
					regs,
					"Heap-Buffer underflow of %zu bytes in %s: %s[0x%llx, 0x%llx]%s\n",
					alloc->ptr - addr,
					action,
					__ctest_color(CTEST_COLOR_BLUE),
					addr,
					(addr + size),
					__ctest_color(CTEST_COLOR_RESET));
			__ctest_print_alloc_info(result, alloc);
			return 0;
		}
		/* Use after free */
		else if (alloc->freed_rip) {
			__ctest_raise_parent_error(
					result,
					regs,
					"Use after free of %zu bytes in %s: %s[0x%llx, 0x%llx]%s\n",
					size,
					action,
					__ctest_color(CTEST_COLOR_BLUE),
					addr,
					addr + size,
					__ctest_color(CTEST_COLOR_RESET));
			__ctest_print_alloc_info(result, alloc);
			return 0;
		}
	}
	// TODO: [stack]
	return 1;
}
