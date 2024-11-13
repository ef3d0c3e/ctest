#include "mem_access.h"
#include "arena.h"
#include "error.h"
#include "mem_maps.h"
#include "messages.h"
#include "result.h"
#include "util.h"
#include <capstone/x86.h>
#include <string.h>

/* Calculates the effective address of a X86_OP_MEM */
static uintptr_t
calculate_effective_address(cs_x86_op* op, struct user_regs_struct* regs)
{
	// Get base register if available
	uintptr_t base = 0;
	if (op->mem.base != X86_REG_INVALID) {
		base = __ctest_util_get_register_value(op->mem.base, regs);
	}

	uintptr_t index = 0;
	// Get index register and apply scale if available
	if (op->mem.index != X86_REG_INVALID) {
		index = __ctest_util_get_register_value(op->mem.index, regs) * op->mem.scale;
	}

	// Add displacement
	uintptr_t displacement = op->mem.disp;

	// Handle segment base if segment register is used
	uintptr_t segment = 0;
	if (op->mem.segment == X86_REG_FS) {
		segment = regs->fs_base;
	} else if (op->mem.segment == X86_REG_GS) {
		segment = regs->gs_base;
	}

	return base + index + displacement + segment;
}

static const char* access_name[] = { "", "Read", "Write", "Read AND Write" };

/* Process a heap memory access */
static int
heap_access(struct ctest_result* result,
            struct user_regs_struct* regs,
            struct ctest_map_entry* map,
            cs_x86_op* op,
            uintptr_t address,
            const int is_read,
            const int is_write)
{
	struct ctest_mem_allocation* alloc;
	const int err = __ctest_mem_arena_find_range(result, &alloc, address, address + op->size);
	/* Unknown heap memory */
	if (err == 1) {
		// TODO: Find closests blocks
		__ctest_raise_parent_error(
		  result,
		  regs,
		  "Attempt to %s %d bytes in unallocated heap memory: %s[0x%llx, 0x%llx]%s\n",
		  access_name[is_read | (is_write << 1)],
		  op->size,
		  __ctest_color(CTEST_COLOR_BLUE),
		  (void*)address,
		  (void*)(address + op->size),
		  __ctest_color(CTEST_COLOR_RESET));
		return 0;
	}
	/* Buffer overflow */
	else if (err == 2) {
		__ctest_raise_parent_error(
		  result,
		  regs,
		  "Heap-Buffer overflow of %d bytes in %s instruction: %s[0x%llx, 0x%llx]%s\n",
		  address + op->size - alloc->ptr - alloc->size,
		  access_name[is_read | (is_write << 1)],
		  __ctest_color(CTEST_COLOR_BLUE),
		  (void*)address,
		  (void*)(address + op->size),
		  __ctest_color(CTEST_COLOR_RESET));
		__ctest_print_alloc_info(result, alloc);
		return 0;
	}
	/* Buffer underflow */
	else if (err == 3) {
		__ctest_raise_parent_error(
		  result,
		  regs,
		  "Heap-Buffer underflow of %d bytes in %s instruction: %s[0x%llx, 0x%llx]%s\n",
		  alloc->ptr - address,
		  access_name[is_read | (is_write << 1)],
		  __ctest_color(CTEST_COLOR_BLUE),
		  (void*)address,
		  (void*)(address + op->size),
		  __ctest_color(CTEST_COLOR_RESET));
		__ctest_print_alloc_info(result, alloc);
		return 0;
	}
	/* Use after free */
	else if (alloc->freed_rip) {
		__ctest_raise_parent_error(
		  result,
		  regs,
		  "Use after free of %d bytes in %s instruction: %s[0x%llx, 0x%llx]%s\n",
		  op->size,
		  access_name[is_read | (is_write << 1)],
		  __ctest_color(CTEST_COLOR_BLUE),
		  (void*)address,
		  (void*)(address + op->size),
		  __ctest_color(CTEST_COLOR_RESET));
		__ctest_print_alloc_info(result, alloc);
		return 0;
	}
	
	/* Check for reads to uninitialized memory */
	if (is_read)
	{
		// TODO...
		uint8_t initialized = __ctest_mem_is_initialized(alloc, address, op->size);
		if (initialized != op->size)
		{
			__ctest_raise_parent_error(
					result,
					regs,
					"Read of %d uninitialized bytes in %s instruction: %s[0x%llx, 0x%llx]%s\n",
					op->size,
					access_name[is_read | (is_write << 1)],
					__ctest_color(CTEST_COLOR_BLUE),
					(void*)address,
					(void*)(address + op->size),
					__ctest_color(CTEST_COLOR_RESET));
			__ctest_print_alloc_info(result, alloc);
			return 0;
		}
	}
	else if (is_write)
	{
		__ctest_mem_set_initialized(alloc, address, op->size);
	}
	return 1;
}

int
__ctest_mem_access_insn_hook(struct ctest_result* result,
                             struct user_regs_struct* regs,
                             cs_insn* insn)
{
	// For stuff like nop dword ptr [rax, rax]
	if (insn[0].id == X86_INS_NOP)
		return 1;
	// Capstone treats LEA as reads
	else if (insn[0].id == X86_INS_LEA)
		return 1;
	for (uint8_t i = 0; i < insn[0].detail->x86.op_count; ++i)
	{
		cs_x86_op* op = &(insn[0].detail->x86.operands[i]);
		if (op->type != X86_OP_MEM)
			continue;
		const int is_read = (op->access & CS_AC_READ) != 0;
		const int is_write = (op->access & CS_AC_WRITE) != 0;

		uintptr_t address = calculate_effective_address(op, regs);
		struct ctest_map_entry* map = __ctest_mem_maps_get(&result->mem.maps, address);
		//for (size_t i = 0; i < result->mem.maps.size; ++i) {
		//	printf("%llx-%llx %s\n", result->mem.maps.data[i].start,
		//	result->mem.maps.data[i].end, result->mem.maps.data[i].pathname);
		//}
		/* Unmapped memory */
		if (!map) {
			__ctest_raise_parent_error(
					result,
					regs,
					"Attempt to %s %d bytes in unmapped memory: %s[0x%llx, 0x%llx]%s\n",
					access_name[is_read | (is_write << 1)],
					op->size,
					__ctest_color(CTEST_COLOR_BLUE),
					(void*)address,
					(void*)(address + op->size),
					__ctest_color(CTEST_COLOR_RESET));
			__ctest_print_source_line(result, STDERR_FILENO, regs->rsp);
			return 0;
		}
		// TODO: [stack], consider all maps not linked to a fd as heap
		if (strcmp(map->pathname, "[heap]") == 0) {
			if (!heap_access(result, regs, map, op, address, is_read, is_write))
				return 0;
		}
		printf("Accessed memory: %p [%s]\n", (void*)address, map->pathname);

	}
	return 1;
}
