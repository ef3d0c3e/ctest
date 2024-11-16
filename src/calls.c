#include "calls.h"
#include "error.h"
#include "mem_maps.h"
#include "result.h"
#include "util.h"
#include <capstone/x86.h>
#include <errno.h>
#include <string.h>
#include <sys/user.h>
#include <elfutils/libdwfl.h>
#include <elfutils/libdwelf.h>
#include <elfutils/known-dwarf.h>
#include <elfutils/elf-knowledge.h>
#include <elfutils/libdw.h>
#include <dwarf.h>

/* Get the call address of a call insn */
static uintptr_t
get_call_target_address(const cs_x86_op* op, struct user_regs_struct* regs)
{
	// Check for direct CALL (Immediate operand)
	if (op->type == CS_OP_IMM) {
		printf("-- Direct Call %p --\n", op->imm);
		return op->imm;
	}

	// Check for indirect CALL via register
	else if (op->type == CS_OP_REG) {
		printf("-- Reg Call --\n");
		return __ctest_util_get_register_value(op->reg, regs);
	}

	// Check for indirect CALL via memory
	else if (op->type == CS_OP_MEM) {
		uintptr_t base_val = 0;
		uintptr_t index_val = 0;
		uintptr_t segment_base = 0;

		// Handle the base register if available
		if (op->mem.base != X86_REG_INVALID) {
			base_val = __ctest_util_get_register_value(op->mem.base, regs);
		}

		// Handle the index register if available
		if (op->mem.index != X86_REG_INVALID) {
			index_val = __ctest_util_get_register_value(op->mem.index, regs) * op->mem.scale;
		}

		// Handle the segment register if it's FS or GS
		if (op->mem.segment == X86_REG_FS) {
			segment_base = regs->fs_base;
		} else if (op->mem.segment == X86_REG_GS) {
			segment_base = regs->gs_base;
		}

		// Calculate the effective address for indirect CALL
		return segment_base + base_val + index_val + op->mem.disp;
	}

	fprintf(stderr, "CALL instruction has an unsupported operand type\n");
	exit(1);
}

/*
void inspect_stack_variables(Dwfl_Module *module, Dwarf_Addr func_addr) {
	Dwarf_Die *func_die = NULL;
	if (dwfl_module_addrsym(module, func_addr, &func_die, NULL) != NULL) {
		Dwarf_Die child;
		if (dwarf_child(func_die, &child) == 0) {
			do {
				// Check for local variables and parameters
				if (dwarf_tag(&child) == DW_TAG_variable || dwarf_tag(&child) == DW_TAG_formal_parameter) {
					Dwarf_Attribute loc_attr, size_attr;
					// Get location
					if (dwarf_attr(&child, DW_AT_location, &loc_attr)) {
						Dwarf_Op *expr;
						size_t exprlen;
						if (dwarf_getlocation(&loc_attr, &expr, &exprlen) == 0) {
							// Assuming single DW_OP_fbreg operation for stack variables
							if (expr->atom == DW_OP_fbreg) {
								int64_t offset = expr->number; // Stack offset
								printf("Variable at offset: %ld\n", offset);
							}
						}
					}
					// Get size
					if (dwarf_attr(&child, DW_AT_byte_size, &size_attr)) {
						uint64_t size;
						if (dwarf_formudata(&size_attr, &size) == 0) {
							printf("Variable size: %llu bytes\n", size);
						}
					}
				}
			} while (dwarf_siblingof(&child, &child) == 0);
		}
	}
}
*/

int
__ctest_calls_insn_hook(struct ctest_result* result, struct user_regs_struct* regs, cs_insn* insn)
{

	for (int i = 0; i < insn[0].detail->groups_count; ++i) {
		if (insn[0].detail->groups[i] != CS_GRP_CALL)
			continue;
		result->rip_before_call = regs->rip;
		break;
	}
	return 1;
}
