#include "error.h"
#include "result.h"
#include <stdarg.h>
#include <stdio.h>
#include <sys/user.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdint.h>

static void
print_registers(int fd, struct user_regs_struct* regs)
{
	dprintf(fd,
			"RAX=%p%sR8 =%p\n"
			"RBX=%p%sR9 =%p\n"
			"RCX=%p%sR10=%p\n"
			"RDX=%p%sR11=%p\n"
			"RSI=%p%sR12=%p\n"
			"RDI=%p%sR13=%p\n"
			"RBP=%p%sR14=%p\n"
			"RSP=%p%sR15=%p\n"
			"RIP=%p%sEFLAGS=%p\n",
			(void*)regs->rax, "\t", (void*)regs->r8,
			(void*)regs->rbx, "\t", (void*)regs->r9,
			(void*)regs->rcx, "\t", (void*)regs->r10,
			(void*)regs->rdx, "\t", (void*)regs->r11,
			(void*)regs->rsi, "\t", (void*)regs->r12,
			(void*)regs->rdi, "\t", (void*)regs->r13,
			(void*)regs->rbp, "\t", (void*)regs->r14,
			(void*)regs->rsp, "\t", (void*)regs->r15,
			(void*)regs->rip, "\t", (void*)regs->eflags);
}

void
__ctest_raise_parent_error(struct ctest_result* result,
                           struct user_regs_struct* regs,
                           const char* fmt,
                           ...)
{
	fprintf(stderr, " --> Ctest caught an error <--\n");
	print_registers(STDERR_FILENO, regs);
	va_list args;

	

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}
