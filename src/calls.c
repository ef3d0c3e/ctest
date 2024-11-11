#include "calls.h"
#include "result.h"
#include "util.h"
#include <sys/user.h>

/* Get the call address of a call insn */
static uintptr_t
get_call_target_address(const cs_insn* insn, struct user_regs_struct* regs)
{
	cs_x86_op op = insn->detail->x86.operands[0];

	// Check for direct CALL (Immediate operand)
	if (op.type == CS_OP_IMM) {
		return op.imm;
	}

	// Check for indirect CALL via register
	else if (op.type == CS_OP_REG) {
		return __ctest_util_get_register_value(op.reg, regs);
	}

	// Check for indirect CALL via memory
	else if (op.type == CS_OP_MEM) {
		uintptr_t base_val = 0;
		uintptr_t index_val = 0;
		uintptr_t segment_base = 0;

		// Handle the base register if available
		if (op.mem.base != X86_REG_INVALID) {
			base_val = __ctest_util_get_register_value(op.mem.base, regs);
		}

		// Handle the index register if available
		if (op.mem.index != X86_REG_INVALID) {
			index_val = __ctest_util_get_register_value(op.mem.index, regs) * op.mem.scale;
		}

		// Handle the segment register if it's FS or GS
		if (op.mem.segment == X86_REG_FS || op.mem.segment == X86_REG_GS) {
			// segment_base = __ctest_util_get_register_value(op.mem.segment, regs);
		}

		// Calculate the effective address for indirect CALL
		return segment_base + base_val + index_val + op.mem.disp;
	}

	fprintf(stderr, "CALL instruction has an unsupported operand type\n");
	exit(1);
}

int
__ctest_calls_insn_hook(struct ctest_result* result, struct user_regs_struct* regs, cs_insn* insn)
{
	result->rip_before_call = regs->rip;
	return 1;
}
