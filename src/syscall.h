#ifndef CTEST_SYSCALLS_H
#define CTEST_SYSCALLS_H

#include <capstone/capstone.h>
#include <sys/user.h>
struct ctest_result;

union ctest_syscall_msg_out
{
	struct user_regs_struct regs;
};

union ctest_syscall_msg_in
{
	struct {
		uintptr_t buf;
		ssize_t n;
	} read;
};

/**
 * @brief Process syscall insn
 *
 * @param result The result structure
 * @param regs The registers
 * @param insn The call insn
 *
 * @returns 1 on success, 0 on failure
 */
int
__ctest_syscall_insn_hook(struct ctest_result* result,
                        struct user_regs_struct* regs,
                        cs_insn* insn);

/**
 * @brief Process the result of a hooked syscall
 *
 * @param Result the result from which the syscall is retrieved
 */
void
__ctest_syscall_process_result(struct ctest_result* result);

#endif // CTEST_SYSCALLS_H
