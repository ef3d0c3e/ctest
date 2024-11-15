#include "syscall.h"
#include "capstone/x86.h"
#include "result.h"
#include "buffer.h"
#include <asm/unistd_64.h>
#include <unistd.h>

static ssize_t
read_hook(int fd, struct ctest_result* result, size_t len)
{
	const ssize_t n = read(fd, (void*)result->message_out.syscall.regs.rsi, len);
	result->message_in.syscall.read.n = n;
	result->message_in.syscall.read.buf = result->message_out.syscall.regs.rsi;
	result->in_hook = 0;

	return n;
}

int
__ctest_syscall_insn_hook(struct ctest_result* result, struct user_regs_struct* regs, cs_insn* insn)
{
	if (insn[0].id != X86_INS_SYSCALL)
		return 1;

	result->message = CTEST_MSG_SYSCALL;
	switch (regs->rax)
	{
		case __NR_read:
			result->in_hook = 1;
			result->message_out.syscall.regs = *regs;
			// TODO: Add buffer checks (rsi)
			__ctest_buffer_at_least(result, regs, regs->rsi, regs->rdx, "syscall read()");
			regs->rip = (uintptr_t)read_hook;
			regs->rsi = result->child_result;
			break;
		default:
			result->message = CTEST_MSG_NONE;
			break;
	}
	return 1;
}

void
__ctest_syscall_process_result(struct ctest_result* result)
{
	switch (result->message_out.syscall.regs.rax)
	{
		case __NR_read:
			// MARK memory as written
			break;
		default:
			break;
	}
}
