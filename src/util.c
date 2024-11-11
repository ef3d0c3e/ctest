#include "util.h"

uintptr_t
__ctest_util_get_register_value(x86_reg reg, struct user_regs_struct* regs)
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
