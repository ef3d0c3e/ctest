#include "calls.h"
#include "error.h"
#include "mem_maps.h"
#include "result.h"
#include "util.h"
#include <capstone/x86.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <elfutils/libdwfl.h>
#include <elfutils/libdwelf.h>
#include <elfutils/known-dwarf.h>
#include <elfutils/elf-knowledge.h>
#include <elfutils/libdw.h>
#include <dwarf.h>

/* Get the call address of a call insn */
static uintptr_t
get_call_target_address(struct ctest_result* result, const cs_x86_op* op, struct user_regs_struct* regs)
{
	uintptr_t addr;

	// Check for direct CALL (Immediate operand)
	if (op->type == CS_OP_IMM) {
		printf("-- Direct Call %p --\n", op->imm);
		addr = op->imm;
	}

	// Check for indirect CALL via register
	else if (op->type == CS_OP_REG) {
		printf("-- Reg Call --\n");
		addr = __ctest_util_get_register_value(op->reg, regs);
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
		addr = segment_base + base_val + index_val + op->mem.disp;
        printf("-- Indirect Call via Memory --\n");
	}
	else
	{
		fprintf(stderr, "CALL instruction has an unsupported operand type\n");
		exit(1);
	}

	// Init dwfl
	Dwfl* dwfl;
	Dwfl_Callbacks callbacks = {
		.find_elf = dwfl_linux_proc_find_elf,
		.find_debuginfo = dwfl_standard_find_debuginfo,
	};
	dwfl = dwfl_begin(&callbacks);

	if (dwfl_linux_proc_report(dwfl, result->child) != 0) {
		fprintf(stderr, "dwfl_linux_proc_report failed: %s\n", strerror(errno));
		exit(1);
	}

	if (dwfl_report_end(dwfl, NULL, NULL) != 0) {
		fprintf(stderr, "dwfl_report_end failed: %s\n", strerror(errno));
		exit(1);
	}

	Dwfl_Module* module = dwfl_addrmodule(dwfl, addr);
	if (!module)
	{
		fprintf(stderr, "dwfl_addrmodule(/* dwfl */, %p) failed: %s\n", (void*)addr, strerror(errno));
		exit(1);
	}

	// Attempt to relocate the address
	Dwarf_Addr relocated_addr = addr;
	if (dwfl_module_relocate_address(module, &relocated_addr) < 0) {
		fprintf(stderr, "Failed to relocate address %p\n", (void *)addr);
		return addr;
	}

	Dwarf_Addr base_addr = 0;
	dwfl_module_info(module, NULL, &base_addr, NULL, NULL, NULL, NULL, NULL);
	if (base_addr == 0)
	{
		fprintf(stderr, "Failed to get module base address %p\n", (void *)addr);
		return addr;
	}
	printf("-- Module base address: %p --\n", (void *)base_addr);

	// Adjust the GOT entry address
	uintptr_t got_entry = base_addr + relocated_addr + 0x8; // Offset depends on architecture
	printf("-- Calculated GOT entry address: %p --\n", (void *)got_entry);

	// Validate GOT entry address and read its value
	uintptr_t resolved_addr = ptrace(PTRACE_PEEKDATA, result->child, got_entry, NULL);
	if (resolved_addr == (uintptr_t)-1) {
		perror("Failed to resolve GOT entry");
		return addr; // Fallback to original address
	}

	printf("-- Resolved address from GOT: %p --\n", (void *)resolved_addr);
	return resolved_addr;
}

void inspect_stack_variables(struct ctest_result* result, Dwarf_Addr func_addr) {
	// Init dwfl
	Dwfl* dwfl;
	Dwfl_Callbacks callbacks = {
		.find_elf = dwfl_linux_proc_find_elf,
		.find_debuginfo = dwfl_standard_find_debuginfo,
	};
	dwfl = dwfl_begin(&callbacks);

	if (dwfl_linux_proc_report(dwfl, result->child) != 0) {
		fprintf(stderr, "dwfl_linux_proc_report failed: %s\n", strerror(errno));
		exit(1);
	}

	if (dwfl_report_end(dwfl, NULL, NULL) != 0) {
		fprintf(stderr, "dwfl_report_end failed: %s\n", strerror(errno));
		exit(1);
	}

	Dwfl_Module* module = dwfl_addrmodule(dwfl, func_addr);
	GElf_Sym sym;
	const char *symbol_name = dwfl_module_addrsym(module, func_addr, &sym, NULL);
	if (!symbol_name) {
		fprintf(stderr, "Failed to find symbol for address: %lx\n", func_addr);
		//exit(1);
	}
	printf("Found symbol: %s\n", symbol_name);
/*
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
	*/
	dwfl_end(dwfl);
}

int
__ctest_calls_insn_hook(struct ctest_result* result, struct user_regs_struct* regs, cs_insn* insn)
{

	for (int i = 0; i < insn[0].detail->groups_count; ++i) {
		if (insn[0].detail->groups[i] != CS_GRP_CALL)
			continue;
		result->rip_before_call = regs->rip;
		inspect_stack_variables(result, get_call_target_address(result, &insn[0].detail->x86.operands[i], regs));
		break;
	}
	return 1;
}
