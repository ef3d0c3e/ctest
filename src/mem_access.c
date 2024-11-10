#include "mem_access.h"
#include "arena.h"
#include "error.h"
#include "mem_maps.h"
#include "messages.h"
#include "result.h"
#include <asm/prctl.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

/* Get value in registor, from @ref x86_reg enum */
static uintptr_t
get_register_value(x86_reg reg, struct user_regs_struct* regs)
{
	switch (reg) {
		case X86_REG_RAX:
			return regs->rax;
		case X86_REG_RBX:
			return regs->rbx;
		case X86_REG_RCX:
			return regs->rcx;
		case X86_REG_RDX:
			return regs->rdx;
		case X86_REG_RSI:
			return regs->rsi;
		case X86_REG_RDI:
			return regs->rdi;
		case X86_REG_RBP:
			return regs->rbp;
		case X86_REG_RSP:
			return regs->rsp;
		case X86_REG_R8:
			return regs->r8;
		case X86_REG_R9:
			return regs->r9;
		case X86_REG_R10:
			return regs->r10;
		case X86_REG_R11:
			return regs->r11;
		case X86_REG_R12:
			return regs->r12;
		case X86_REG_R13:
			return regs->r13;
		case X86_REG_R14:
			return regs->r14;
		case X86_REG_R15:
			return regs->r15;
		case X86_REG_RIP:
			return regs->rip;
		default:
			fprintf(stderr, "Unhandled register: %d\n", reg);
			return 0;
	}
}

/* Gets the value of the segment base register */
static uintptr_t
get_segment_base(x86_reg segment, pid_t pid)
{
	uint64_t base = 0;
	if (segment == X86_REG_FS) {
		ptrace(PTRACE_ARCH_PRCTL, pid, ARCH_GET_FS, &base);
	} else if (segment == X86_REG_GS) {
		ptrace(PTRACE_ARCH_PRCTL, pid, ARCH_GET_GS, &base);
	}
	return base;
}

/* Calculates the effective address of a X86_OP_MEM */
static uintptr_t
calculate_effective_address(pid_t pid, cs_x86_op* op, struct user_regs_struct* regs)
{

	// Get base register if available
	uintptr_t base = 0;
	if (op->mem.base != X86_REG_INVALID) {
		base = get_register_value(op->mem.base, regs);
	}

	uintptr_t index = 0;
	// Get index register and apply scale if available
	if (op->mem.index != X86_REG_INVALID) {
		index = get_register_value(op->mem.index, regs) * op->mem.scale;
	}

	// Add displacement
	uintptr_t displacement = op->mem.disp;

	// Handle segment base if segment register is used
	uintptr_t segment = 0;
	if (op->mem.segment != X86_REG_INVALID) {
		segment = get_segment_base(op->mem.segment, pid);
	}

	return base + index + displacement + segment;
}

int
__ctest_mem_access_insn_hook(struct ctest_result* result,
                             struct user_regs_struct* regs,
                             cs_insn* insn)
{
	static const char* access_name[] = { "", "Read", "Write", "Read AND Write" };

	cs_x86_op* op = &(insn[0].detail->x86.operands[0]);
	if (op->type == X86_OP_MEM) {
		const int is_read = (op->access & CS_AC_READ) != 0;
		const int is_write = (op->access & CS_AC_WRITE) != 0;

		uintptr_t address = calculate_effective_address(result->child, op, regs);
		struct ctest_map_entry* map = __ctest_mem_maps_get(&result->mem.maps, address);
		for (size_t i = 0; i < result->mem.maps.size; ++i) {
			// printf("%llx-%llx %s\n", result->mem.maps.data[i].start,
			// result->mem.maps.data[i].end, result->mem.maps.data[i].pathname);
		}
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
		if (strcmp(map->pathname, "[heap]") == 0) {
			struct ctest_mem_allocation* alloc;
			const int err =
			  __ctest_mem_arena_find_range(result, &alloc, address, address + op->size);
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
			} else if (err == 2) {
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
			} else if (err == 3) {
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
		}
		printf("Accessed memory: %p [%s]\n", (void*)address, map->pathname);
	}
	return 1;
	// printf("0x%" PRIx64 ": %s %s\n", insn[0].address,
	//		insn[0].mnemonic, insn[0].op_str);
}
